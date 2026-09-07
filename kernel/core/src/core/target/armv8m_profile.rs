//! ARMv8-M Mainline CPU profile: PMSAv8 MPU and architectural stack limits.
pub use super::common_arm_m_profile::mainline::{
    install_syscall_handler, isolated_app_gate_region, last_mem_manage_fault,
    request_syscall_thread_redirect, run_isolated_app, syscall_handler_debug_addr,
    syscall_initialize, syscall_table_debug_addr,
};
pub use super::common_arm_m_profile::{
    disable_interrupts, enable_interrupts, interrupts_restore, interrupts_save_and_disable,
};
use super::MmioRegister32;
use crate::core::mpu::{MpuError, MpuRegion, MpuRegionConfig, MpuResult};
use core::ptr::{addr_of_mut, write_volatile};

const MPU_BASE: usize = 0xE000ED90;

const MPU_TYPE: MmioRegister32 = MmioRegister32::new(MPU_BASE + 0x000);
const MPU_CTRL: MmioRegister32 = MmioRegister32::new(MPU_BASE + 0x004);
const MPU_RNR: MmioRegister32 = MmioRegister32::new(MPU_BASE + 0x008);
const MPU_RBAR: MmioRegister32 = MmioRegister32::new(MPU_BASE + 0x00C);
const MPU_RLAR: MmioRegister32 = MmioRegister32::new(MPU_BASE + 0x010);
const MPU_MAIR0: MmioRegister32 = MmioRegister32::new(MPU_BASE + 0x030);

const MPU_RBAR_XN: u32 = super::armv8m_mpu::XN;
const MPU_REGION_COUNT_SHIFT: u32 = 8;
const MPU_REGION_COUNT_MASK: u32 = 0xff;

// Invariant: only serialized kernel MPU transitions change this flag. User RAM
// mappings remain in the isolation plan, never in a second register snapshot.
static mut KERNEL_NX_ACTIVE: bool = false;

fn overlaps_kernel_ram(base: usize, end: usize) -> bool {
    super::kernel_ram_execute_never_windows()
        .iter()
        .flatten()
        .any(|window| base < window.base_addr + window.size && end > window.base_addr)
}

pub fn mpu_enable() -> MpuResult<()> {
    if mpu_region_count() == 0 {
        return Err(MpuError::Unsupported);
    }

    MPU_MAIR0.write(0x44); // Attribute 0: normal, non-cacheable memory.

    program_kernel_nx_regions()?;

    MPU_CTRL.write(super::armv8m_mpu::ENABLE_WITH_PRIVILEGED_BACKGROUND);

    mpu_sync();
    Ok(())
}

fn program_kernel_nx_regions() -> MpuResult<()> {
    if mpu_region_count() <= 6 {
        return Err(MpuError::Unsupported);
    }
    // PMSAv8 has no highest-region-wins rule. Remove every enabled overlapping
    // user window before installing NX, including the executable RAM gate.
    for region in 0..mpu_region_count() {
        let (base, limit) = read_region(region);
        if limit & 1 != 0
            && overlaps_kernel_ram((base & !31) as usize, ((limit & !31) as usize) + 32)
        {
            mpu_unset_region(region)?;
        }
    }
    unsafe {
        core::ptr::write_volatile(&raw mut KERNEL_NX_ACTIVE, true);
    }
    super::common_arm_m_profile::program_kernel_nx_regions(
        &super::kernel_ram_execute_never_windows(),
        mpu_region_count(),
        |region, config| {
            validate_region(region)?;
            let (rbar, rlar) = super::armv8m_mpu::encode(config)?;
            write_region(region, rbar, rlar);
            Ok(())
        },
    )
}

pub fn mpu_disable() -> MpuResult<()> {
    if mpu_region_count() == 0 {
        return Err(MpuError::Unsupported);
    }

    MPU_CTRL.write(0);
    mpu_sync();
    Ok(())
}

/// Programs one PMSAv8 window after validating its complete address range.
pub fn mpu_set_region(region: MpuRegion, config: &MpuRegionConfig) -> MpuResult<()> {
    validate_region(region)?;
    let (rbar, rlar) = super::armv8m_mpu::encode(config)?;
    if unsafe { core::ptr::read_volatile(&raw const KERNEL_NX_ACTIVE) }
        && (region == 6 || overlaps_kernel_ram(config.base_addr, config.base_addr + config.size))
    {
        // The isolation plan will install this window immediately before user
        // entry. Installing it now would overlap the privileged NX window.
        if region != 6 {
            mpu_unset_region(region)?;
        }
        return Ok(());
    }
    write_region(region, rbar, rlar);
    Ok(())
}

fn write_region(region: MpuRegion, rbar: u32, rlar: u32) {
    let primask = interrupts_save_and_disable();
    MPU_RNR.write(region as u32);
    MPU_RLAR.write(0);
    MPU_RBAR.write(rbar);
    MPU_RLAR.write(rlar);
    mpu_sync();
    interrupts_restore(primask);
}

fn read_region(region: MpuRegion) -> (u32, u32) {
    let primask = interrupts_save_and_disable();
    MPU_RNR.write(region as u32);
    let base = MPU_RBAR.read();
    let limit = MPU_RLAR.read();
    interrupts_restore(primask);
    (base, limit)
}

pub fn mpu_unset_region(region: MpuRegion) -> MpuResult<()> {
    validate_region(region)?;

    let primask = interrupts_save_and_disable();
    MPU_RNR.write(region as u32);
    MPU_RLAR.write(0);
    MPU_RBAR.write(0);
    mpu_sync();
    interrupts_restore(primask);
    Ok(())
}

pub fn protect_kernel_nx(enabled: bool) {
    if !enabled {
        unsafe {
            core::ptr::write_volatile(&raw mut KERNEL_NX_ACTIVE, false);
        }
    }
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
        crate::core::shutdown(1);
    }
}

#[inline(always)]
pub unsafe fn mpu_set_region_executable_unchecked(region: MpuRegion, executable: bool) {
    let primask = interrupts_save_and_disable();
    MPU_RNR.write(region as u32);
    let mut rbar = MPU_RBAR.read();
    if executable {
        rbar &= !MPU_RBAR_XN;
    } else {
        rbar |= MPU_RBAR_XN;
    }
    MPU_RBAR.write(rbar);
    mpu_sync();
    interrupts_restore(primask);
}

/// Enables protection; MSPLIM is configured from the actual kernel stack window.
pub fn kernel_stack_guard_initialize() {
    if mpu_enable().is_err() {
        crate::consoleln!("kernel MPU setup failed");
        crate::core::shutdown(1);
    }
}

/// Programs MSPLIM from the board's kernel stack window, not a guessed RAM base.
pub fn kernel_stack_overflow_protection(stack: crate::core::isolation::AppMemoryWindow) {
    #[cfg(oxide_se_target_has_stack_limits)]
    unsafe {
        core::arch::asm!(
            "msr MSPLIM, {limit}",
            limit = in(reg) stack.start,
            options(nomem, nostack, preserves_flags),
        );
    }

    #[cfg(not(oxide_se_target_has_stack_limits))]
    let _ = stack;
}

/// Programs, or clears, the Process Stack Pointer lower limit on ARMv8-M.
pub fn app_stack_overflow_protection(stack: Option<crate::core::isolation::AppMemoryWindow>) {
    #[cfg(oxide_se_target_has_stack_limits)]
    unsafe {
        let limit = stack.map_or(0, |window| window.start);
        core::arch::asm!(
            "msr PSPLIM, {limit}",
            limit = in(reg) limit,
            options(nomem, nostack, preserves_flags),
        );
    }

    #[cfg(not(oxide_se_target_has_stack_limits))]
    let _ = stack;
}

/// Exercises MSPLIM with an actual PUSH, rather than an unrelated RAM write.
/// The diagnostic temporarily raises the limit to the current MSP. Hardware
/// observation must stop at UsageFault entry, before its handler uses the
/// exhausted stack; this is a fatal kernel fault, not an application recovery.
#[inline(never)]
pub fn kernel_stack_guard_test_touch() {
    // Invariant: a PMSAv8 NoAccess region cannot be used as a stack guard.
    // r2 preserves the boot-configured limit for the external diagnostic.
    unsafe {
        core::arch::asm!(
            "mrs r2, MSPLIM",
            "mrs r0, msp",
            "msr MSPLIM, r0",
            "push {{r0, r1}}",
            "pop {{r0, r1}}",
            "msr MSPLIM, r2",
            out("r0") _, out("r1") _, out("r2") _,
        );
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
    ((MPU_TYPE.read() >> MPU_REGION_COUNT_SHIFT) & MPU_REGION_COUNT_MASK) as u8
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

fn mpu_sync() {
    super::common_arm_m_profile::synchronize();
}
