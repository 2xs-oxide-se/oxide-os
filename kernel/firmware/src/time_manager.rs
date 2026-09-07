//! Kernel time services driven by the shared 100 ms periodic interrupt.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

const TIMER_PERIOD: Duration = Duration::from_millis(100);
const NULL_PERIOD_TICKS: u32 = 10;
const NULL_PROCEDURE_BYTE: u8 = 0x60;

// Zero means disabled; otherwise the value is the next saturating tick count.
static NULL_TICKS: AtomicU32 = AtomicU32::new(0);
static NULL_BYTES_SENT: AtomicU32 = AtomicU32::new(0);

pub(crate) fn initialize() {
    NULL_TICKS.store(0, Ordering::Relaxed);
    NULL_BYTES_SENT.store(0, Ordering::Relaxed);
    crate::core::timer::set_periodic_handler(periodic_tick, TIMER_PERIOD)
        .expect("periodic kernel time services are unavailable");
}

#[allow(dead_code)]
pub(crate) fn null_bytes_sent() -> u32 {
    NULL_BYTES_SENT.load(Ordering::Acquire)
}

/// Arms NULL emission; the timer, never this caller, emits the first byte.
pub(crate) fn arm_null_bytes() {
    NULL_TICKS.store(1, Ordering::Release);
}

/// Disarms NULL emission immediately before a real response byte is written.
#[inline(always)]
pub(crate) fn before_response_byte() {
    NULL_TICKS.store(0, Ordering::Release);
}

fn periodic_tick() {
    tick_null_bytes();
    crate::core::isolation::watchdog_tick();
}

fn tick_null_bytes() {
    let ticks = NULL_TICKS.load(Ordering::Acquire);
    if ticks == 0 {
        return;
    }
    if ticks >= NULL_PERIOD_TICKS {
        if !crate::core::serial::try_send_byte(NULL_PROCEDURE_BYTE) {
            NULL_TICKS.store(NULL_PERIOD_TICKS, Ordering::Release);
            return;
        }
        NULL_TICKS.store(1, Ordering::Release);
        let sent = NULL_BYTES_SENT.load(Ordering::Relaxed);
        NULL_BYTES_SENT.store(sent.saturating_add(1), Ordering::Release);
        // Invariant: the main T=0 path clears NULL_TICKS immediately before
        // every real byte, so this byte cannot split a response transmission.
    } else {
        NULL_TICKS.store(ticks.saturating_add(1), Ordering::Release);
    }
}
