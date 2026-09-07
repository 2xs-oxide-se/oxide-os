//! Single periodic kernel timer backed by the selected target interrupt source.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use core::time::Duration;

const HARDWARE_TICK_HZ: u32 = 1_000;

static HANDLER: AtomicUsize = AtomicUsize::new(0);
static PERIOD_TICKS: AtomicU32 = AtomicU32::new(0);
static REMAINING_TICKS: AtomicU32 = AtomicU32::new(0);
static TOP_HALF_COUNT: AtomicU32 = AtomicU32::new(0);
static BOTTOM_HALF_COUNT: AtomicU32 = AtomicU32::new(0);

pub type PeriodicHandler = fn();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerError {
    InvalidPeriod,
    Unsupported,
}

pub type TimerResult<T> = Result<T, TimerError>;

/// Installs the kernel's single periodic callback and starts its target timer.
///
/// The period is expressed as an integral number of milliseconds. Reinstalling
/// a callback atomically replaces the previous callback and restarts its period.
/// The callback runs in interrupt context: it must not allocate, block, or use
/// services whose code or data become unavailable during a flash operation.
/// A flash backend that suspends execute-in-place access must preserve and mask
/// interrupts around that window unless the complete interrupt path is resident
/// in RAM.
pub fn set_periodic_handler(handler: PeriodicHandler, period: Duration) -> TimerResult<()> {
    let period_millis = period.as_millis();
    if period_millis == 0 || !period.subsec_nanos().is_multiple_of(1_000_000) {
        return Err(TimerError::InvalidPeriod);
    }
    let ticks = u32::try_from(period_millis).map_err(|_| TimerError::InvalidPeriod)?;

    crate::core::target::periodic_timer_disable();
    PERIOD_TICKS.store(ticks, Ordering::Relaxed);
    REMAINING_TICKS.store(ticks, Ordering::Relaxed);
    HANDLER.store(handler as usize, Ordering::Release);
    TOP_HALF_COUNT.store(0, Ordering::Relaxed);
    BOTTOM_HALF_COUNT.store(0, Ordering::Relaxed);
    if !crate::core::target::periodic_timer_initialize(HARDWARE_TICK_HZ) {
        HANDLER.store(0, Ordering::Release);
        PERIOD_TICKS.store(0, Ordering::Relaxed);
        REMAINING_TICKS.store(0, Ordering::Relaxed);
        return Err(TimerError::Unsupported);
    }
    Ok(())
}

/// Returns saturating counts around completed periodic callback dispatches.
pub fn interrupt_counts() -> (u32, u32) {
    (
        TOP_HALF_COUNT.load(Ordering::Acquire),
        BOTTOM_HALF_COUNT.load(Ordering::Acquire),
    )
}

/// Stops the periodic source and removes the installed callback.
pub fn clear_periodic_handler() {
    crate::core::target::periodic_timer_disable();
    HANDLER.store(0, Ordering::Release);
    PERIOD_TICKS.store(0, Ordering::Relaxed);
    REMAINING_TICKS.store(0, Ordering::Relaxed);
}

/// Marks the transition from the non-preemptible top-half to interruptible work.
///
/// Higher-priority interrupts may preempt after this call. The currently active
/// timer exception cannot recursively preempt itself on Cortex-M. This marker
/// does not defer work onto another stack or create a scheduler bottom-half.
#[inline(always)]
pub fn begin_bottom_half() {
    crate::core::target::enable_interrupts();
}

fn dispatch_tick() {
    let remaining = REMAINING_TICKS.load(Ordering::Relaxed);
    if remaining > 1 {
        REMAINING_TICKS.store(remaining - 1, Ordering::Relaxed);
        return;
    }

    let period = PERIOD_TICKS.load(Ordering::Relaxed);
    if period == 0 {
        return;
    }
    REMAINING_TICKS.store(period, Ordering::Relaxed);

    let address = HANDLER.load(Ordering::Acquire);
    if address != 0 {
        let top = TOP_HALF_COUNT.load(Ordering::Relaxed);
        TOP_HALF_COUNT.store(top.saturating_add(1), Ordering::Relaxed);
        // Invariant: HANDLER is zero or a `PeriodicHandler` installed above.
        let handler: PeriodicHandler = unsafe { core::mem::transmute(address) };
        handler();
        let bottom = BOTTOM_HALF_COUNT.load(Ordering::Relaxed);
        BOTTOM_HALF_COUNT.store(bottom.saturating_add(1), Ordering::Release);
    }
}

/// Architectural SysTick vector target shared by every ARM M-profile board.
#[unsafe(no_mangle)]
pub extern "C" fn gpos_core_periodic_timer_interrupt_dispatch() {
    // Keep the top-half non-preemptible until the callback explicitly opts in.
    crate::core::target::disable_interrupts();
    dispatch_tick();
    // Invariant: an early or top-half-only callback must not leave IRQs masked.
    crate::core::target::enable_interrupts();
}
