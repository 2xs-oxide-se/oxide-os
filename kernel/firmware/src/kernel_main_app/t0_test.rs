use super::{ApduFilter, KernelAppModule};
use crate::apdu_manager::ApduStatus;
use rustlet_runtime::SEApdu;

const INS_CASE_EMPTY: u8 = 0x00;
const INS_CASE_IN: u8 = 0x02;
const INS_CASE_OUT: u8 = 0x04;
const INS_CASE_IN_OUT: u8 = 0x06;

pub(crate) struct Module;

impl KernelAppModule for Module {
    fn initialize() {}
}

pub(crate) const APDU_FILTER: ApduFilter = ApduFilter {
    matches: matches,
    process: process,
};

fn matches(apdu: &dyn SEApdu) -> bool {
    matches!(
        apdu.ins(),
        INS_CASE_EMPTY | INS_CASE_IN | INS_CASE_OUT | INS_CASE_IN_OUT
    )
}

fn process(apdu: &mut dyn SEApdu) -> ApduStatus {
    match apdu.ins() {
        INS_CASE_EMPTY => ApduStatus::success(),
        INS_CASE_IN => process_case_in(apdu),
        INS_CASE_OUT => process_case_out(apdu),
        INS_CASE_IN_OUT => process_case_in_out(apdu),
        _ => ApduStatus::instruction_not_supported(),
    }
}

fn process_case_in(apdu: &mut dyn SEApdu) -> ApduStatus {
    let _incoming_len = apdu.set_incoming_and_receive();
    for (index, &byte) in apdu.incoming_data().iter().enumerate() {
        if byte != index as u8 {
            return ApduStatus::wrong_data();
        }
    }
    ApduStatus::success()
}

fn process_case_out(apdu: &mut dyn SEApdu) -> ApduStatus {
    let _ = apdu.set_outgoing();
    apdu.set_outgoing_length(3);
    for (index, byte) in apdu.buffer_mut().iter_mut().take(3).enumerate() {
        *byte = index as u8;
    }
    ApduStatus::success()
}

fn process_case_in_out(apdu: &mut dyn SEApdu) -> ApduStatus {
    let incoming_len = apdu.set_incoming_and_receive();
    reverse_prefix(apdu.buffer_mut(), incoming_len);
    let _ = apdu.set_outgoing();
    apdu.set_outgoing_length(incoming_len);
    ApduStatus::success()
}

fn reverse_prefix(buffer: &mut [u8], len: usize) {
    let mut left = 0;
    let mut right = len.saturating_sub(1);
    while left < right {
        buffer.swap(left, right);
        left += 1;
        right -= 1;
    }
}
