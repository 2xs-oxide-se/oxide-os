use super::{ApduFilter, KernelAppModule};
use crate::apdu_manager::ApduStatus;
use rustlet_runtime::SEApdu;

const INS_KERNEL_PING: u8 = 0xfe;

pub(crate) struct Module;

impl KernelAppModule for Module {
    fn initialize() {}
}

pub(crate) const APDU_FILTER: ApduFilter = ApduFilter {
    matches: matches,
    process: process,
};

fn matches(apdu: &dyn SEApdu) -> bool {
    apdu.ins() == INS_KERNEL_PING
}

/// P1=0 echoes incoming bytes through GET RESPONSE; P1=1 emits the
/// sequence 00, 01, ... directly, with its length taken from short Le.
/// P1=2 is a separate no-data probe: absent Le must not be confused with
/// Le=00 (256 bytes), which exceeds the current 255-byte payload limit.
fn process(apdu: &mut dyn SEApdu) -> ApduStatus {
    match apdu.p1() {
        0 => {}
        1 => {
            let len = apdu.set_outgoing();
            if len == 0 {
                return ApduStatus::wrong_length();
            }
            // Invariant: generate in shared storage, without a stack copy.
            for (index, byte) in apdu.buffer_mut()[..len].iter_mut().enumerate() {
                *byte = index as u8;
            }
            apdu.set_outgoing_length(len);
            return ApduStatus::success();
        }
        2 => return ApduStatus::success(),
        _ => return ApduStatus::incorrect_p1_p2(),
    }
    let incoming_len = apdu.set_incoming_and_receive();
    let _ = apdu.set_outgoing();
    apdu.set_outgoing_length(incoming_len);
    ApduStatus::success()
}
