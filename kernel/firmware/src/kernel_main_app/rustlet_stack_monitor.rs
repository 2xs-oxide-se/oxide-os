use super::{ApduFilter, KernelAppModule};
use crate::apdu_layer::ApduCommand;
use crate::apdu_manager::ApduStatus;
use crate::core::isolation::AppMemoryWindow;
use rustlet_runtime::SEApdu;

const STACK_MAGIC: u32 = 0x600D_FACE;
const INS_GET_DATA: u8 = 0xca;
const STACK_HIGH_WATERMARK_TAG: u16 = 0xdf72;

pub(crate) struct Module;

impl KernelAppModule for Module {
    fn initialize() {
        unsafe {
            MAX_HIGH_WATERMARK_BYTES = 0;
        }
    }
}

pub(crate) const APDU_FILTER: ApduFilter = ApduFilter {
    matches: matches_apdu,
    process: process_apdu,
};

pub(crate) fn before_rustlet(stack: AppMemoryWindow) {
    let mut cursor = aligned_start(stack);
    let end = aligned_end(stack);
    while cursor + core::mem::size_of::<u32>() <= end {
        unsafe {
            core::ptr::write_volatile(cursor as *mut u32, STACK_MAGIC);
        }
        cursor += core::mem::size_of::<u32>();
    }
}

pub(crate) fn after_rustlet(stack: AppMemoryWindow) {
    let start = aligned_start(stack);
    let end = aligned_end(stack);
    let mut cursor = start;
    while cursor + core::mem::size_of::<u32>() <= end {
        let word = unsafe { core::ptr::read_volatile(cursor as *const u32) };
        if word != STACK_MAGIC {
            break;
        }
        cursor += core::mem::size_of::<u32>();
    }
    let high_watermark = end.saturating_sub(cursor);
    unsafe {
        if high_watermark > MAX_HIGH_WATERMARK_BYTES {
            MAX_HIGH_WATERMARK_BYTES = high_watermark;
        }
    }
}

pub(crate) fn preserves_clear_apdu_session(command: &ApduCommand) -> bool {
    command.ins() == INS_GET_DATA
        && u16::from_be_bytes([command.p1(), command.p2()]) == STACK_HIGH_WATERMARK_TAG
}

fn matches_apdu(apdu: &dyn SEApdu) -> bool {
    apdu.ins() == INS_GET_DATA
        && u16::from_be_bytes([apdu.p1(), apdu.p2()]) == STACK_HIGH_WATERMARK_TAG
}

fn process_apdu(apdu: &mut dyn SEApdu) -> ApduStatus {
    let high_watermark = unsafe { MAX_HIGH_WATERMARK_BYTES as u32 };
    let _ = apdu.set_outgoing();
    apdu.buffer_mut()[..4].copy_from_slice(&high_watermark.to_be_bytes());
    apdu.set_outgoing_length(4);
    ApduStatus::success()
}

fn aligned_start(stack: AppMemoryWindow) -> usize {
    let align = core::mem::align_of::<u32>();
    (stack.start + align - 1) & !(align - 1)
}

fn aligned_end(stack: AppMemoryWindow) -> usize {
    stack.end() & !(core::mem::align_of::<u32>() - 1)
}

static mut MAX_HIGH_WATERMARK_BYTES: usize = 0;
