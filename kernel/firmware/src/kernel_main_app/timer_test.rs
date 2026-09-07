use super::{ApduFilter, KernelAppModule};
use crate::apdu_manager::ApduStatus;
use rustlet_runtime::SEApdu;

const INS_KERNEL_TIMER: u8 = 0x0a;

pub(crate) struct Module;

impl KernelAppModule for Module {
    fn initialize() {}
}

pub(crate) const APDU_FILTER: ApduFilter = ApduFilter {
    matches: matches,
    process: process,
};

fn matches(apdu: &dyn SEApdu) -> bool {
    apdu.ins() == INS_KERNEL_TIMER
}

/// P1=1 waits twelve ticks; P1=2 waits thirty-two ticks for three NULL periods.
fn process(apdu: &mut dyn SEApdu) -> ApduStatus {
    let available = apdu.set_outgoing();
    if available < 12 {
        return ApduStatus::wrong_length();
    }

    let wait_ticks = match apdu.p1() {
        0 => 0,
        1 => 12,
        2 => 32,
        _ => return ApduStatus::incorrect_p1_p2(),
    };
    if wait_ticks != 0 {
        let start = crate::core::timer::interrupt_counts().0;
        while crate::core::timer::interrupt_counts()
            .0
            .saturating_sub(start)
            < wait_ticks
        {
            core::hint::spin_loop();
        }
    }

    let (top, bottom) = crate::core::timer::interrupt_counts();
    let top = top.to_be_bytes();
    let bottom = bottom.to_be_bytes();
    let nulls = crate::time_manager::null_bytes_sent().to_be_bytes();
    apdu.buffer_mut()[..4].copy_from_slice(&top);
    apdu.buffer_mut()[4..8].copy_from_slice(&bottom);
    apdu.buffer_mut()[8..12].copy_from_slice(&nulls);
    apdu.set_outgoing_length(12);
    ApduStatus::success()
}
