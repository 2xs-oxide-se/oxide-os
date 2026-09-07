use super::{ApduFilter, KernelAppModule};
use crate::apdu_manager::ApduStatus;
use rustlet_runtime::SEApdu;

const INS_FLASH_PERSISTENCE_PROBE: u8 = 0x8e;
const FLASH_PROBE_PAGE_SIZE: usize = 256;
// Explicit test allocation, excluded from the registry before it initializes.
// Only boards with this erase geometry are accepted; never fall back to the
// registry's first sector when reservation fails.
const FLASH_PROBE_BLOCK_SIZE: usize = 4096;
static mut PROBE_AREA: crate::core::flash::FlashPersistenceArea =
    crate::core::flash::FlashPersistenceArea {
        start: 0,
        page_count: 0,
    };
const FLASH_PROBE_RESPONSE_LEN: usize = 16;
const FLASH_PROBE_MAGIC: [u8; 8] = *b"RLOSFLSH";
const SW2_FLASH_ERASE_FAILED: u8 = 0x01;
const SW2_FLASH_WRITE_FAILED: u8 = 0x02;

static mut FLASH_PROBE_PAGE: [u8; FLASH_PROBE_PAGE_SIZE] = [0xFF; FLASH_PROBE_PAGE_SIZE];

pub(crate) struct Module;

impl KernelAppModule for Module {
    fn initialize() {
        if crate::core::flash::logical_page_size() == FLASH_PROBE_PAGE_SIZE
            && crate::core::flash::erase_sector_size() == FLASH_PROBE_BLOCK_SIZE
        {
            if let Ok(area) = crate::core::flash::reserve_persistence_tail(FLASH_PROBE_BLOCK_SIZE) {
                unsafe {
                    PROBE_AREA = area;
                }
            }
        }
    }
}

fn probe_area() -> crate::core::flash::FlashPersistenceArea {
    unsafe { PROBE_AREA }
}

pub(crate) const APDU_FILTER: ApduFilter = ApduFilter {
    matches: matches,
    process: process,
};

fn matches(apdu: &dyn SEApdu) -> bool {
    apdu.ins() == INS_FLASH_PERSISTENCE_PROBE
}

fn process(apdu: &mut dyn SEApdu) -> ApduStatus {
    // P1 selects one operation in this private diagnostic command family;
    // P2 remains available as the caller-controlled persistence marker.
    match apdu.p1() {
        0x00 => process_info(apdu),
        0x01 => process_write_probe(apdu),
        0x02 => process_read_probe(apdu),
        _ => ApduStatus::wrong_data(),
    }
}

fn process_info(apdu: &mut dyn SEApdu) -> ApduStatus {
    let area = probe_area();
    let page_size = crate::core::flash::logical_page_size();
    let _ = apdu.set_outgoing();
    let out = apdu.buffer_mut();
    out[..4].copy_from_slice(&(area.start as u32).to_le_bytes());
    out[4..8].copy_from_slice(&(area.page_count as u32).to_le_bytes());
    out[8..12].copy_from_slice(&(page_size as u32).to_le_bytes());
    apdu.set_outgoing_length(12);
    ApduStatus::success()
}

fn process_write_probe(apdu: &mut dyn SEApdu) -> ApduStatus {
    let area = probe_area();
    if area.page_count == 0
        || area.page_count > u16::MAX as usize
        || crate::core::flash::logical_page_size() != FLASH_PROBE_PAGE_SIZE
    {
        return ApduStatus::conditions_not_satisfied();
    }
    if crate::core::flash::erase_sector(area.start).is_err() {
        return diagnostic_failure(SW2_FLASH_ERASE_FAILED);
    }

    let page = unsafe { &mut *core::ptr::addr_of_mut!(FLASH_PROBE_PAGE) };
    page.fill(0xFF);
    page[..FLASH_PROBE_MAGIC.len()].copy_from_slice(&FLASH_PROBE_MAGIC);
    page[FLASH_PROBE_MAGIC.len()] = apdu.p2();
    page[FLASH_PROBE_MAGIC.len() + 1] = apdu.ins();
    // Invariant: the persistent probe encodes a checked little-endian u16.
    page[FLASH_PROBE_MAGIC.len() + 2..FLASH_PROBE_MAGIC.len() + 4]
        .copy_from_slice(&(area.page_count as u16).to_le_bytes());
    page[FLASH_PROBE_MAGIC.len() + 4] = 0xA5;

    if crate::core::flash::write_page(area.start, page).is_err() {
        return diagnostic_failure(SW2_FLASH_WRITE_FAILED);
    }
    process_read_probe(apdu)
}

fn process_read_probe(apdu: &mut dyn SEApdu) -> ApduStatus {
    let area = probe_area();
    if area.page_count == 0 {
        return ApduStatus::conditions_not_satisfied();
    }
    let persisted =
        unsafe { core::slice::from_raw_parts(area.start as *const u8, FLASH_PROBE_RESPONSE_LEN) };
    let _ = apdu.set_outgoing();
    apdu.buffer_mut()[..FLASH_PROBE_RESPONSE_LEN].copy_from_slice(persisted);
    apdu.set_outgoing_length(FLASH_PROBE_RESPONSE_LEN);
    ApduStatus::success()
}

/// Returns a private flash-probe diagnostic status.
///
/// These `6Fxx` values belong to the bring-up module and are not advertised as
/// general ISO/IEC 7816 status words.
const fn diagnostic_failure(detail: u8) -> ApduStatus {
    ApduStatus {
        sw1: 0x6f,
        sw2: detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_status_distinguishes_erase_and_write_failures() {
        assert_eq!(
            diagnostic_failure(SW2_FLASH_ERASE_FAILED),
            ApduStatus {
                sw1: 0x6f,
                sw2: 0x01
            }
        );
        assert_eq!(
            diagnostic_failure(SW2_FLASH_WRITE_FAILED),
            ApduStatus {
                sw1: 0x6f,
                sw2: 0x02
            }
        );
    }
}
