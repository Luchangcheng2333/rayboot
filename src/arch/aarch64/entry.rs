use super::page_table::{MemFlags, PageTableEntry};
use core::time::Duration;
use cortex_a::{asm, asm::barrier, registers::*};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

#[repr(align(4096))]
struct PageTable([PageTableEntry; 512]);

#[repr(align(4096))]
pub struct NormalMem(pub [u8; 0x4000]);

#[no_mangle]
pub static mut STACK: NormalMem = NormalMem([0; 0x4000]);
#[no_mangle]
static mut BOOT_PT0: PageTable = PageTable([PageTableEntry::empty(); 512]);
#[no_mangle]
static mut BOOT_PT1: PageTable = PageTable([PageTableEntry::empty(); 512]);

/*
   函数：uptime
   传入参数：无
   返回值类型：时间Duration
   作用：获取从上电到现在经历的时间
*/
pub fn uptime() -> Duration {
    unsafe { barrier::isb(barrier::SY) }
    let cur_cnt = CNTPCT_EL0.get() * 1_000_000_000;
    let freq = CNTFRQ_EL0.get() as u64;
    Duration::from_nanos(cur_cnt / freq)
}

/*
   函数:switch_to_el1
   传入参数：无
   返回值类型：无
   作用：切换到EL1特权级
*/
pub unsafe fn switch_to_el1() {
    SPSel.write(SPSel::SP::ELx);
    let current_el = CurrentEL.read(CurrentEL::EL);
    if current_el >= 2 {
        if current_el == 3 {
            // Set EL2 to 64bit and enable the HVC instruction.
            SCR_EL3.write(
                SCR_EL3::NS::NonSecure + SCR_EL3::HCE::HvcEnabled + SCR_EL3::RW::NextELIsAarch64,
            );
            // Set the return address and exception level.
            SPSR_EL3.write(
                SPSR_EL3::M::EL1h
                    + SPSR_EL3::D::Masked
                    + SPSR_EL3::A::Masked
                    + SPSR_EL3::I::Masked
                    + SPSR_EL3::F::Masked,
            );
            ELR_EL3.set(LR.get());
        }
        // Disable EL1 timer traps and the timer offset.
        CNTHCTL_EL2.modify(CNTHCTL_EL2::EL1PCEN::SET + CNTHCTL_EL2::EL1PCTEN::SET);
        CNTVOFF_EL2.set(0);
        // Set EL1 to 64bit.
        HCR_EL2.write(HCR_EL2::RW::EL1IsAarch64);
        // Set the return address and exception level.
        SPSR_EL2.write(
            SPSR_EL2::M::EL1h
                + SPSR_EL2::D::Masked
                + SPSR_EL2::A::Masked
                + SPSR_EL2::I::Masked
                + SPSR_EL2::F::Masked,
        );
        SP_EL1.set(STACK.0.as_ptr_range().end as u64);
        ELR_EL2.set(LR.get());
        asm::eret();
    }
}

/*
   函数：init_mmu
   传入参数：无
   返回值类型：无
   作用：初始化MMU
*/
pub unsafe fn init_mmu() {
    // Device-nGnRE memory
    let attr0 = MAIR_EL1::Attr0_Device::nonGathering_nonReordering_EarlyWriteAck;
    // Normal memory
    let attr1 = MAIR_EL1::Attr1_Normal_Inner::WriteBack_NonTransient_ReadWriteAlloc
        + MAIR_EL1::Attr1_Normal_Outer::WriteBack_NonTransient_ReadWriteAlloc;
    MAIR_EL1.write(attr0 + attr1); // 0xff_04

    // Enable TTBR0 and TTBR1 walks, page size = 4K, vaddr size = 48 bits, paddr size = 40 bits.
    let tcr_flags0 = TCR_EL1::EPD0::EnableTTBR0Walks
        + TCR_EL1::TG0::KiB_4
        + TCR_EL1::SH0::Inner
        + TCR_EL1::ORGN0::WriteBack_ReadAlloc_WriteAlloc_Cacheable
        + TCR_EL1::IRGN0::WriteBack_ReadAlloc_WriteAlloc_Cacheable
        + TCR_EL1::T0SZ.val(16);
    let tcr_flags1 = TCR_EL1::EPD1::EnableTTBR1Walks
        + TCR_EL1::TG1::KiB_4
        + TCR_EL1::SH1::Inner
        + TCR_EL1::ORGN1::WriteBack_ReadAlloc_WriteAlloc_Cacheable
        + TCR_EL1::IRGN1::WriteBack_ReadAlloc_WriteAlloc_Cacheable
        + TCR_EL1::T1SZ.val(16);
    TCR_EL1.write(TCR_EL1::IPS::Bits_40 + tcr_flags0 + tcr_flags1);
    barrier::isb(barrier::SY);

    // Set both TTBR0 and TTBR1
    let root_paddr = BOOT_PT0.0.as_ptr() as u64;
    TTBR0_EL1.set(root_paddr);
    TTBR1_EL1.set(root_paddr);
    core::arch::asm!("tlbi vmalle1; dsb sy; isb"); // flush tlb all
                                                   // Enable the MMU and turn on I-cache and D-cache
    SCTLR_EL1.modify(SCTLR_EL1::M::Enable + SCTLR_EL1::I::Cacheable + SCTLR_EL1::C::Cacheable);
    barrier::isb(barrier::SY);
}

/*
   函数：init_qemu_boot_page_table
   传入参数：无
   返回值类型：无
   作用：初始化qemu启动时页表
*/
pub unsafe fn init_qemu_boot_page_table() {
    // 0x0000_0000_0000 ~ 0x0080_0000_0000, table
    BOOT_PT0.0[0] = PageTableEntry::new_table(BOOT_PT1.0.as_ptr() as u64);
    // 0x0000_0000_0000..0x0000_4000_0000, block, device memory
    BOOT_PT1.0[0] =
        PageTableEntry::new_page(0, MemFlags::READ | MemFlags::WRITE | MemFlags::DEVICE, true);
    // 0x0000_4000_0000..0x0000_8000_0000, block, normal memory
    BOOT_PT1.0[1] = PageTableEntry::new_page(
        0x4000_0000,
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
        true,
    );
}

/*
   函数：init_raspi4_boot_page_table
   传入参数：无
   返回值类型：无
   作用：初始化树莓派4b启动时页表
*/
pub unsafe fn init_raspi4_boot_page_table() {
    // 0x0000_0000_0000 ~ 0x0080_0000_0000, table
    BOOT_PT0.0[0] = PageTableEntry::new_table(BOOT_PT1.0.as_ptr() as u64);

    // 0x0000_0000_0000..0x0000_4000_0000, block, normal memory
    BOOT_PT1.0[0] = PageTableEntry::new_page(
        0,
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
        true,
    );
    // 0x0000_4000_0000..0x0000_8000_0000, block, normal memory
    BOOT_PT1.0[1] = PageTableEntry::new_page(
        0x4000_0000,
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
        true,
    );
    // 0x0000_8000_0000..0x0000_c000_0000, block, normal memory
    BOOT_PT1.0[2] = PageTableEntry::new_page(
        0x8000_0000,
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
        true,
    );
    // 0x0000_c000_0000..0x0001_0000_0000, block, device
    BOOT_PT1.0[3] = PageTableEntry::new_page(
        0xc000_0000,
        // 在树莓派4b平台上uart输出会乱码
        // MemFlags::READ | MemFlags::WRITE | MemFlags::DEVICE
        // 改成下面的就不会
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE | MemFlags::DEVICE,
        true,
    );
}

/*
   函数：start_raspi4
   传入参数：无
   返回值类型：!
   作用：初始化树莓派4b内存环境
*/
#[naked]
#[no_mangle]
pub unsafe extern "C" fn start_raspi4() -> ! {
    // PC = 0x4008_0000
    core::arch::asm!("
        adrp    x8, BOOT_PT0
        mov     sp, x8
        bl      {switch_to_el1}
        bl      {init_boot_page_table}
        bl      {init_mmu}
        adrp    x8, BOOT_PT0
        mov     sp, x8
        adrp    x9, STACK
        ldr     x10, [x9]
        ldr     x0, [x9, #8]
        br      x10
        ",
        switch_to_el1 = sym switch_to_el1,
        init_boot_page_table = sym init_raspi4_boot_page_table,
        init_mmu = sym init_mmu,
        options(noreturn),
    )
}

/*
   函数：start_qemu
   传入参数：无
   返回值类型：!
   作用：初始化qemu内存环境
*/
#[naked]
#[no_mangle]
pub unsafe extern "C" fn start_qemu() -> ! {
    // PC = 0x4008_0000
    core::arch::asm!("
        adrp    x8, BOOT_PT0
        mov     sp, x8
        bl      {switch_to_el1}
        bl      {init_boot_page_table}
        bl      {init_mmu}
        adrp    x8, BOOT_PT0
        mov     sp, x8
        adrp    x9, STACK
        ldr     x10, [x9]
        ldr     x0, [x9, #8]
        br      x10
        ",
    switch_to_el1 = sym switch_to_el1,
    init_boot_page_table = sym init_qemu_boot_page_table,
    init_mmu = sym init_mmu,
    options(noreturn),
    )
}
