//! Mechanisms identical across the supported ARM M-profile CPUs.
//! No board addresses or peripherals belong here. Layout-dependent helpers
//! receive their windows explicitly; the facade selects the board layout.
use crate::core::mpu::{MpuAccess, MpuPrivilege, MpuRegionConfig, MpuResult};

#[cfg(not(oxide_se_target_armv6m))]
pub(super) mod mainline;

#[repr(C)]
/// Register-sized arguments consumed at fixed offsets by exception-entry assembly.
pub(super) struct TargetAppEntry {
    pub(super) entry_pc: u32,
    pub(super) app_gp: u32,
    pub(super) arg0: u32,
    pub(super) arg1: u32,
    pub(super) arg2: u32,
    pub(super) arg3: u32,
    pub(super) stack_top: u32,
    pub(super) entry_gate_pc: u32,
}

#[repr(C)]
/// Basic hardware exception frame (without an optional floating-point extension).
pub(super) struct ExceptionFrame {
    pub(super) r0: u32,
    pub(super) r1: u32,
    pub(super) r2: u32,
    pub(super) r3: u32,
    pub(super) r12: u32,
    pub(super) lr: u32,
    pub(super) pc: u32,
    pub(super) xpsr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Register values used to resume the kernel after a normal or faulty Rustlet exit.
pub(super) struct RedirectState {
    pub(super) r0: u32,
    pub(super) r1: u32,
    pub(super) pc: u32,
}

// Invariant: assembly consumes these layouts by literal offsets, never Rust field order.
const _: () = {
    assert!(core::mem::size_of::<TargetAppEntry>() == 32);
    assert!(core::mem::offset_of!(TargetAppEntry, stack_top) == 24);
    assert!(core::mem::offset_of!(TargetAppEntry, entry_gate_pc) == 28);
    assert!(core::mem::size_of::<ExceptionFrame>() == 32);
    assert!(core::mem::offset_of!(ExceptionFrame, lr) == 20);
    assert!(core::mem::offset_of!(ExceptionFrame, pc) == 24);
    assert!(core::mem::size_of::<RedirectState>() == 12);
};

/// Reads the SVC immediate preceding a validated hardware-stacked return PC.
/// The exception profile must establish that this frame came from executable code.
#[inline]
pub(super) fn decode_svc_immediate(stacked_pc: usize) -> crate::core::syscall::SyscallNumber {
    unsafe { core::ptr::read_volatile(stacked_pc.wrapping_sub(2) as *const u8) }
}

/// Orders MPU changes before subsequent data accesses and instruction fetch.
#[inline(always)]
pub(super) fn synchronize() {
    unsafe {
        core::arch::asm!("dsb", "isb", options(nostack, preserves_flags));
    }
}

/// Enables maskable interrupts after vectors and exception state are initialized.
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("cpsie i", "isb", options(nostack, preserves_flags));
    }
}

/// Masks maskable interrupts for a short kernel top-half critical section.
#[inline(always)]
pub fn disable_interrupts() {
    unsafe {
        core::arch::asm!("cpsid i", "isb", options(nostack, preserves_flags));
    }
}

/// Saves PRIMASK and masks interrupts for a target critical section.
#[inline(always)]
pub fn interrupts_save_and_disable() -> u32 {
    let primask: u32;
    unsafe {
        core::arch::asm!(
            "mrs {primask}, PRIMASK",
            "cpsid i",
            "isb",
            primask = out(reg) primask,
            options(nostack, preserves_flags)
        );
    }
    primask
}

/// Restores the exact interrupt mask captured before a critical section.
#[inline(always)]
pub fn interrupts_restore(primask: u32) {
    unsafe {
        core::arch::asm!(
            "msr PRIMASK, {primask}",
            "isb",
            primask = in(reg) primask,
            options(nostack, preserves_flags)
        );
    }
}

const SYST_CSR: super::MmioRegister32 = super::MmioRegister32::new(0xe000_e010);
const SYST_RVR: super::MmioRegister32 = super::MmioRegister32::new(0xe000_e014);
const SYST_CVR: super::MmioRegister32 = super::MmioRegister32::new(0xe000_e018);
const SCB_SHPR3: super::MmioRegister32 = super::MmioRegister32::new(0xe000_ed20);
const SYST_CSR_ENABLE: u32 = 1 << 0;
const SYST_CSR_TICKINT: u32 = 1 << 1;
const SYST_CSR_CLKSOURCE_CORE: u32 = 1 << 2;
const SYST_RVR_MAX: u32 = 0x00ff_ffff;
const SYSTICK_PRIORITY_SHIFT: u32 = 24;
const SYSTICK_PRIORITY_MASK: u32 = 0xff << SYSTICK_PRIORITY_SHIFT;

/// Configures architectural SysTick at `tick_hz` from the selected core clock.
pub fn periodic_timer_initialize(core_clock_hz: u32, tick_hz: u32) -> bool {
    if tick_hz == 0 || core_clock_hz < tick_hz {
        return false;
    }
    let cycles = core_clock_hz / tick_hz;
    if cycles == 0 || cycles - 1 > SYST_RVR_MAX {
        return false;
    }

    SYST_CSR.write(0);
    SCB_SHPR3.update(|value| (value & !SYSTICK_PRIORITY_MASK) | (0xff << SYSTICK_PRIORITY_SHIFT));
    SYST_RVR.write(cycles - 1);
    SYST_CVR.write(0);
    SYST_CSR.write(SYST_CSR_ENABLE | SYST_CSR_TICKINT | SYST_CSR_CLKSOURCE_CORE);
    true
}

/// Stops SysTick before replacing or removing the kernel callback.
pub fn periodic_timer_disable() {
    SYST_CSR.write(0);
    SYST_CVR.write(0);
}

/// Restores board-supplied kernel RAM-XN windows with statically selected MPU operations.
#[inline]
pub(super) fn program_kernel_nx_regions(
    windows: &[Option<super::KernelNxWindow>],
    region_count: u8,
    mut set_region: impl FnMut(u8, &MpuRegionConfig) -> MpuResult<()>,
) -> MpuResult<()> {
    for window in windows.iter().flatten() {
        if region_count <= window.region {
            continue;
        }
        // Invariant: these slots are kernel RW/NX only during kernel execution;
        // user entry replaces them with the application's own MPU windows.
        set_region(
            window.region,
            &MpuRegionConfig {
                base_addr: window.base_addr,
                size: window.size,
                access: MpuAccess::ReadWrite,
                privilege: MpuPrivilege::PrivilegedOnly,
                executable: false,
            },
        )?;
    }
    Ok(())
}
