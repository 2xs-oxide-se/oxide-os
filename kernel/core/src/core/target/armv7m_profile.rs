//! ARMv7-M CPU profile: PMSAv7 MPU, external stack guard and Mainline exceptions.
pub use super::common_arm_m_profile::mainline::{
    install_syscall_handler, isolated_app_gate_region, last_mem_manage_fault,
    request_syscall_thread_redirect, run_isolated_app, syscall_handler_debug_addr,
    syscall_initialize, syscall_table_debug_addr,
};
pub use super::common_arm_m_profile::{
    disable_interrupts, enable_interrupts, interrupts_restore, interrupts_save_and_disable,
};
use crate::core::mpu::{MpuAccess, MpuError, MpuPrivilege, MpuRegion, MpuRegionConfig, MpuResult};
use core::ptr::{addr_of_mut, read_volatile, write_volatile};

const MPU_TYPE: *const u32 = 0xE000_ED90 as *const u32;
const MPU_CTRL: *mut u32 = 0xE000_ED94 as *mut u32;
const MPU_RNR: *mut u32 = 0xE000_ED98 as *mut u32;
const MPU_RBAR: *mut u32 = 0xE000_ED9C as *mut u32;
const MPU_RASR: *mut u32 = 0xE000_EDA0 as *mut u32;

const MPU_CTRL_ENABLE: u32 = 1 << 0;
const MPU_CTRL_PRIVDEFENA: u32 = 1 << 2;
const MPU_RASR_ENABLE: u32 = 1 << 0;
const MPU_RASR_SIZE_SHIFT: u32 = 1;
const MPU_RASR_AP_SHIFT: u32 = 24;
const MPU_RASR_XN: u32 = 1 << 28;

const MPU_AP_NO_ACCESS: u32 = 0b000;
const MPU_AP_PRIVILEGED_RW: u32 = 0b001;
const MPU_AP_PRIVILEGED_RW_UNPRIVILEGED_RW: u32 = 0b011;
const MPU_AP_PRIVILEGED_RO: u32 = 0b101;
const MPU_AP_PRIVILEGED_RO_UNPRIVILEGED_RO: u32 = 0b110;

const MPU_MIN_REGION_SIZE: usize = 32;
const MPU_REGION_COUNT_MASK: u32 = 0xff;
const MPU_REGION_COUNT_SHIFT: u32 = 8;
const KERNEL_STACK_GUARD_REGION: MpuRegion = 7;
const KERNEL_STACK_GUARD_SIZE: usize = MPU_MIN_REGION_SIZE;
pub fn mpu_enable() -> MpuResult<()> {
    if mpu_region_count() == 0 {
        return Err(MpuError::Unsupported);
    }

    program_kernel_nx_regions()?;

    unsafe {
        write_volatile(MPU_CTRL, MPU_CTRL_ENABLE | MPU_CTRL_PRIVDEFENA);
        mpu_sync();
    }
    Ok(())
}

fn program_kernel_nx_regions() -> MpuResult<()> {
    super::common_arm_m_profile::program_kernel_nx_regions(
        &super::kernel_ram_execute_never_windows(),
        mpu_region_count(),
        mpu_set_region,
    )
}

pub fn mpu_disable() -> MpuResult<()> {
    if mpu_region_count() == 0 {
        return Err(MpuError::Unsupported);
    }

    unsafe {
        write_volatile(MPU_CTRL, 0);
        mpu_sync();
    }
    Ok(())
}

pub fn mpu_set_region(region: MpuRegion, config: &MpuRegionConfig) -> MpuResult<()> {
    validate_region(region)?;
    validate_region_config(config)?;

    let region_size_encoding = encode_region_size(config.size)?;
    let access_bits = encode_access_bits(config.access, config.privilege);

    let mut rasr = MPU_RASR_ENABLE | (region_size_encoding << MPU_RASR_SIZE_SHIFT);
    rasr |= access_bits << MPU_RASR_AP_SHIFT;

    if !config.executable {
        rasr |= MPU_RASR_XN;
    }

    // RNR selects the bank subsequently accessed through RBAR/RASR. Treat
    // the complete selector/data sequence as one transaction: SysTick also
    // changes MPU regions and must not retarget an interrupted update.
    let primask = interrupts_save_and_disable();
    unsafe {
        write_volatile(MPU_RNR, region as u32);
        write_volatile(MPU_RBAR, config.base_addr as u32);
        // The generic facade does not expose memory type tuning yet, so we
        // keep TEX/C/B/S and SRD at zero and only program the protection bits.
        write_volatile(MPU_RASR, rasr);
        mpu_sync();
    }
    interrupts_restore(primask);
    Ok(())
}

pub fn mpu_unset_region(region: MpuRegion) -> MpuResult<()> {
    validate_region(region)?;

    let primask = interrupts_save_and_disable();
    unsafe {
        write_volatile(MPU_RNR, region as u32);
        write_volatile(MPU_RBAR, 0);
        write_volatile(MPU_RASR, 0);
        mpu_sync();
    }
    interrupts_restore(primask);
    Ok(())
}

pub fn protect_kernel_nx(enabled: bool) {
    let unset_kernel_nx_regions = || -> MpuResult<()> {
        for window in crate::core::target::kernel_ram_execute_never_windows()
            .iter()
            .flatten()
        {
            if mpu_region_count() > window.region {
                mpu_unset_region(window.region)?;
            }
        }
        Ok(())
    };
    let result = if enabled {
        program_kernel_nx_regions()
    } else {
        unset_kernel_nx_regions()
    };

    if result.is_err() {
        crate::consoleln!("kernel NX update failed: enabled={}", enabled);
    }
}

#[inline(always)]
pub unsafe fn mpu_set_region_executable_unchecked(region: MpuRegion, executable: bool) {
    let primask = interrupts_save_and_disable();
    write_volatile(MPU_RNR, region as u32);
    let mut rasr = read_volatile(MPU_RASR);
    if executable {
        rasr &= !MPU_RASR_XN;
    } else {
        rasr |= MPU_RASR_XN;
    }
    write_volatile(MPU_RASR, rasr);
    mpu_sync();
    interrupts_restore(primask);
}

pub fn kernel_stack_guard_initialize() {
    if mpu_region_count() <= KERNEL_STACK_GUARD_REGION {
        return;
    }

    let guard_base = kernel_stack_guard_base();
    let result = mpu_set_region(
        KERNEL_STACK_GUARD_REGION,
        &MpuRegionConfig {
            base_addr: guard_base,
            size: KERNEL_STACK_GUARD_SIZE,
            access: MpuAccess::NoAccess,
            privilege: MpuPrivilege::PrivilegedOnly,
            executable: false,
        },
    )
    .and_then(|_| mpu_enable());

    if result.is_err() {
        crate::consoleln!(
            "kernel stack guard setup failed: base=0x{:08x} size={}",
            guard_base,
            KERNEL_STACK_GUARD_SIZE
        );
    }
}

/// ARMv7-M uses MPU guards; it has no MSPLIM register.
pub fn kernel_stack_overflow_protection(_stack: crate::core::isolation::AppMemoryWindow) {}
/// ARMv7-M relies on the application's MPU window for stack bounds.
pub fn app_stack_overflow_protection(_stack: Option<crate::core::isolation::AppMemoryWindow>) {}

#[inline(never)]
pub fn kernel_stack_guard_test_touch() {
    unsafe {
        write_volatile(kernel_stack_guard_base() as *mut u8, 0x5a);
    }
    crate::consoleln!("kernel stack guard test did not fault");
    crate::core::shutdown(1)
}

#[inline(never)]
pub fn kernel_ram_execute_never_test_touch() -> bool {
    if crate::core::target::kernel_ram_execute_never_windows()
        .iter()
        .all(Option::is_none)
    {
        return false;
    }

    #[repr(align(4))]
    struct RamCode([u16; 1]);

    static mut RAM_CODE: RamCode = RamCode([0]);

    // Invariant: this test runs in kernel phase, after MPU initialization, so
    // region 6 must carry the privileged RAM-XN mapping where the target
    // declares one. Executing this RAM-resident `BX LR` must fault.
    let addr = unsafe { addr_of_mut!(RAM_CODE.0) as usize | 1 };
    unsafe {
        write_volatile((addr & !1) as *mut u16, 0x4770);
        mpu_sync();
    }
    let f: extern "C" fn() = unsafe { core::mem::transmute(addr) };
    f();
    true
}

fn mpu_region_count() -> u8 {
    unsafe { ((read_volatile(MPU_TYPE) >> MPU_REGION_COUNT_SHIFT) & MPU_REGION_COUNT_MASK) as u8 }
}

fn validate_region(region: MpuRegion) -> MpuResult<()> {
    if mpu_region_count() == 0 {
        return Err(MpuError::Unsupported);
    }
    if region >= mpu_region_count() {
        return Err(MpuError::InvalidRegion);
    }
    Ok(())
}

fn validate_region_config(config: &MpuRegionConfig) -> MpuResult<()> {
    if config.size < MPU_MIN_REGION_SIZE {
        return Err(MpuError::InvalidSize);
    }
    if !config.size.is_power_of_two() {
        return Err(MpuError::InvalidSize);
    }
    if config.base_addr & (config.size - 1) != 0 {
        return Err(MpuError::UnalignedAddress);
    }
    if config.base_addr > u32::MAX as usize {
        return Err(MpuError::InvalidAddress);
    }
    Ok(())
}

fn encode_region_size(size: usize) -> MpuResult<u32> {
    if size < MPU_MIN_REGION_SIZE || !size.is_power_of_two() {
        return Err(MpuError::InvalidSize);
    }

    Ok((usize::BITS - size.leading_zeros()) - 2)
}

fn encode_access_bits(access: MpuAccess, privilege: MpuPrivilege) -> u32 {
    match (access, privilege) {
        (MpuAccess::NoAccess, _) => MPU_AP_NO_ACCESS,
        (MpuAccess::ReadOnly, MpuPrivilege::PrivilegedOnly) => MPU_AP_PRIVILEGED_RO,
        (MpuAccess::ReadOnly, MpuPrivilege::Unprivileged) => MPU_AP_PRIVILEGED_RO_UNPRIVILEGED_RO,
        (MpuAccess::ReadWrite, MpuPrivilege::PrivilegedOnly) => MPU_AP_PRIVILEGED_RW,
        (MpuAccess::ReadWrite, MpuPrivilege::Unprivileged) => MPU_AP_PRIVILEGED_RW_UNPRIVILEGED_RW,
    }
}

fn kernel_stack_guard_base() -> usize {
    crate::core::target::kernel_stack_guard_window()
        .map(|(base, _)| base)
        .unwrap_or(0)
}

fn mpu_sync() {
    super::common_arm_m_profile::synchronize();
}
