#![no_std]
#![no_main]
#![feature(abi_efiapi)]
#![feature(default_alloc_error_handler)]
#![feature(slice_pattern)]
#![allow(dead_code)]
#![allow(unused_imports)]

#[macro_use]
extern crate alloc;

use acpi::AcpiTables;
use alloc::boxed::Box;
use alloc::vec::*;
use core::arch::global_asm;
use core::borrow::{Borrow, BorrowMut};
use core::fmt::Write;
use core::mem::transmute;
use core::ops::DerefMut;
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::slice::SlicePattern;
use core::time::Duration;
use cortex_a::registers::CurrentEL;
use cortex_a::registers::*;
use irsa::{RsaPublicKey, Sha256};
use log::*;
use rayboot::arch::aarch64::entry::{start_qemu, start_raspi4};
use rayboot::arch::aarch64::{
    config::*,
    entry::{
        init_mmu, init_qemu_boot_page_table, init_raspi4_boot_page_table, switch_to_el1, uptime,
        STACK,
    },
};
use rayboot::boot_info::{MemoryRegions, Optional};
use rayboot::{Aarch64BootInfo, FirmwareType};
use rsdp::Rsdp;
use serde_json;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use uefi::prelude::*;
use uefi::proto::console::serial::Serial;
use uefi::proto::device_path::DevicePath;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode, RegularFile};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{
    AllocateType, MemoryDescriptor, MemoryType, OpenProtocolAttributes, OpenProtocolParams,
};
use uefi::table::Runtime;
use uefi::{
    prelude::{entry, Boot, SystemTable},
    CStr16, Handle, ResultExt, Status,
};
use uefi_test_runner::poweron_check;
use xmas_elf::program::Type;
use xmas_elf::sections::SectionData::SymbolTable64;
use xmas_elf::symbol_table::Entry;

static mut IS_RASPI4: bool = true;

#[entry]
fn efi_main(image: Handle, mut st: SystemTable<Boot>) -> Status {
    // Initialize utilities (logging, memory allocation...)
    uefi_services::init(&mut st).expect("Failed to initialize utilities");

    // Set and detect firmware environment
    st.stdout().clear().expect("unable to clear screen");

    info!("Current EL: {}", CurrentEL.get() >> 2);

    // Locale ACPI table info
    let rsdp_addr = {
        use uefi::table::cfg;
        let mut config_entries = st.config_table().iter();
        // look for an ACPI2 RSDP first
        let acpi2_rsdp = config_entries.find(|entry| matches!(entry.guid, cfg::ACPI2_GUID));
        // if no ACPI2 RSDP is found, look for a ACPI1 RSDP
        let rsdp = acpi2_rsdp
            .or_else(|| config_entries.find(|entry| matches!(entry.guid, cfg::ACPI_GUID)));
        rsdp.map(|entry| entry.address as u64)
    }
    .expect("rsdp not found");
    info!("rsdp_addr: 0x{:x}", rsdp_addr);

    detect_device_type(st.boot_services());

    // Load and verify kernel
    let kernel_entry: extern "C" fn(&Aarch64BootInfo) = {
        let fs = st
            .boot_services()
            .get_image_file_system(image.clone())
            .expect("cannot get image file system");
        let fs = unsafe { fs.interface.get().as_mut().unwrap() };
        let kernel_elf = verify_kernel(fs);
        info!("loading kernel to memory...");
        let kernel_entry = load_kernel(st.boot_services(), kernel_elf);
        info!("kernel entry: 0x{:x}", kernel_entry);
        unsafe { transmute(kernel_entry) }
    };

    let fs = {
        let fs = st
            .boot_services()
            .get_image_file_system(image.clone())
            .expect("cannot get image file system");
        unsafe { fs.interface.get().as_mut().unwrap() }
    };

    let mut file = open_file(
        fs,
        "\\EFI\\Boot\\Boot.json",
        FileMode::Read,
        FileAttribute::READ_ONLY,
    );
    let file_info: Box<FileInfo> = file.get_boxed_info().unwrap();
    let mut buf = vec![0 as u8; file_info.file_size() as usize];
    let buf = buf.as_mut_slice();
    assert_eq!(file_info.file_size() as usize, file.read(buf).unwrap());
    let info = serde_json::from_slice(buf).unwrap();
    info!("Boot info from json: {:#x?}", info);

    // check memory mapping info
    let max_mmap_size = st.boot_services().memory_map_size().map_size;
    let mmap_storage = Box::leak(vec![0; max_mmap_size].into_boxed_slice());
    // exit boot service and switch to kernel
    info!("exit boot services");
    let (_system_table, _memory_map) = st
        .exit_boot_services(image, mmap_storage)
        .expect("Failed to exit boot services");

    unsafe {
        switch_to_kernel(kernel_entry, &info);
    }

    Status::SUCCESS
}

unsafe fn switch_to_kernel(kernel_entry: extern "C" fn(&Aarch64BootInfo), _info: &Aarch64BootInfo) {
    use rayboot::arch::aarch64::bsp::Pl011Uart;
    let uart = Pl011Uart::new(if IS_RASPI4 { 0xfe20_1000 } else { 0x0900_0000 });
    uart.write(format_args!("\n########## jump to kernel ##########\n\n"));
    let mut index = 0;
    for i in (kernel_entry as usize).to_le_bytes() {
        STACK.0[index] = i;
        index += 1;
    }
    for i in (_info as *const Aarch64BootInfo as usize).to_le_bytes() {
        STACK.0[index] = i;
        index += 1;
    }
    if IS_RASPI4 {
        start_raspi4();
    } else {
        start_qemu();
    }
}

fn load_kernel(boot_services: &BootServices, kernel_elf: Vec<u8>) -> u64 {
    let kernel_elf = xmas_elf::ElfFile::new(kernel_elf.as_slice()).unwrap();
    let elf_header = kernel_elf.header;
    assert_eq!(elf_header.pt1.magic, [0x7f, 0x45, 0x4c, 0x46]);

    for ph in kernel_elf.program_iter() {
        if ph.get_type().unwrap() == Type::Load {
            let start_va = ph.virtual_addr() as usize & 0x0000ffffffffffff;
            let end_va = (ph.virtual_addr() + ph.mem_size()) as usize & 0x0000ffffffffffff;
            let pages = (end_va >> ARM64_PAGE_SIZE_BITS) - (start_va >> ARM64_PAGE_SIZE_BITS) + 1;
            info!("load header to address: 0x{:x}", start_va);
            boot_services
                .allocate_pages(
                    AllocateType::Address(start_va),
                    MemoryType::CONVENTIONAL,
                    pages,
                )
                .ok();
            let dst = unsafe {
                core::slice::from_raw_parts_mut(start_va as *mut u8, ph.file_size() as usize)
            };
            let src =
                &kernel_elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize];
            dst.copy_from_slice(src);
        }
    }

    kernel_elf.header.pt2.entry_point()
}

fn verify_kernel(fs: &mut SimpleFileSystem) -> Vec<u8> {
    // load packaged kernel and hashed public key from disk and reset cursor to use behind
    let mut kernel_img = open_file(
        fs,
        KERNEL_LOCATION,
        FileMode::Read,
        FileAttribute::READ_ONLY,
    );
    let kernel_info: Box<FileInfo> = kernel_img.get_boxed_info().unwrap();
    let mut kernel_data = vec![0 as u8; kernel_info.file_size() as usize];
    let kernel_data = kernel_data.as_mut_slice();
    kernel_img.read(kernel_data).expect("failed to read kernel");

    match option_env!("SECURE_BOOT") {
        Some("ON") => {
            info!("running kernel integrity check...");
            info!("start integrity check at: {:?}", uptime());
            let mut pk_hash_data =
                open_file(fs, "pk_hash", FileMode::Read, FileAttribute::READ_ONLY);
            let mut pk_hash = vec![0 as u8; 32];
            let pk_hash = pk_hash.as_mut_slice();
            assert_eq!(pk_hash_data.read(pk_hash).unwrap(), 32);

            // Split the signed kernel image
            let header = unsafe {
                (kernel_data.as_ptr() as *const KernelHeader)
                    .as_ref()
                    .unwrap()
            };
            let header_size = core::mem::size_of::<KernelHeader>();
            let pk_from_image = &kernel_data[header_size..(header_size + header.pk_size)];
            let sign_from_image = &kernel_data
                [(header_size + header.pk_size)..(header_size + header.pk_size + header.sign_size)];
            let kernel_from_image =
                &kernel_data[(header_size + header.pk_size + header.sign_size)..];

            // verify public key
            let mut pk_hasher = Sha256::new();
            pk_hasher
                .input(pk_from_image)
                .expect("failed to input public key to hasher");
            assert_eq!(
                pk_hasher
                    .finalize()
                    .expect("hash pub key failed")
                    .as_slice(),
                pk_hash,
                "verify pub key failed"
            );
            info!("public key verification pass!");

            // verify signature, hash kernel data and verify kernel
            let pk = RsaPublicKey::from_raw(pk_from_image.to_vec());
            let hashed_kernel_from_sign = pk
                .verify(sign_from_image.as_slice())
                .expect("failed to verify signature");
            let mut kernel_hasher = Sha256::new();
            kernel_hasher
                .input(kernel_from_image)
                .expect("fail to input kernel to hasher");
            assert_eq!(
                kernel_hasher.finalize().expect("hash kernel data failed"),
                hashed_kernel_from_sign.as_slice(),
                "verify kernel failed"
            );
            info!("kernel verification pass!");
            info!("end integrity check at: {:?}", uptime());
            return kernel_from_image.to_vec();
        }
        _ => {}
    }

    kernel_data.to_vec()
}

fn open_file(
    fs: &mut SimpleFileSystem,
    name: &str,
    mode: FileMode,
    attribute: FileAttribute,
) -> RegularFile {
    let mut root_dir = fs.open_volume().expect("cannot get root dir");
    use uefi::CStr16;
    let mut name_buf: [u16; 100] = [0; 100];
    let kernel_img = root_dir
        .open(
            CStr16::from_str_with_buf(name, &mut name_buf).unwrap(),
            mode,
            attribute,
        )
        .expect(format!("open file {} failed", name).as_str());
    unsafe { RegularFile::new(kernel_img) }
}

fn detect_device_type(bt: &BootServices) {
    if let Ok(serial) = bt.locate_protocol::<Serial>() {
        let serial = unsafe { &*serial.get() };
        unsafe {
            match serial.io_mode().baud_rate {
                115200 => {
                    info!("Detect raspi4 device");
                    IS_RASPI4 = true;
                }
                38400 => {
                    info!("Detect QEMU device");
                    IS_RASPI4 = false;
                }
                _ => {
                    panic!("Unknown device");
                }
            }
        }
    } else {
        panic!("Get serial info failed");
    }
}
