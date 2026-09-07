use ::core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashError {
    InvalidPageAddress,
    InvalidBufferSize,
    OutOfRange,
    Busy,
    Unsupported,
    Io,
    VerifyFailed,
    CorruptedState,
}

pub type FlashResult<T> = Result<T, FlashError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashPersistenceArea {
    pub start: usize,
    pub page_count: usize,
}

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static RESERVED_TAIL_PAGES: AtomicUsize = AtomicUsize::new(0);
static PERSISTENCE_EXPOSED: AtomicBool = AtomicBool::new(false);

pub(crate) fn initialize() {
    if INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    INITIALIZED.store(true, Ordering::Release);
    crate::core::target::flash_initialize();
}

pub fn logical_page_size() -> usize {
    crate::core::target::flash_logical_page_size()
}

pub fn erase_sector_size() -> usize {
    crate::core::target::flash_erase_sector_size()
}

pub fn persistence_area() -> FlashPersistenceArea {
    PERSISTENCE_EXPOSED.store(true, Ordering::Release);
    let mut area = crate::core::target::flash_persistence_area();
    area.page_count = area
        .page_count
        .saturating_sub(RESERVED_TAIL_PAGES.load(Ordering::Acquire));
    area
}

/// Reserve a sector-aligned diagnostic tail before the registry sees its area.
/// Called only from the single-threaded module boot sequence. The target's raw
/// flash bounds remain unchanged; the registry receives only the remaining
/// prefix. A test image using this API changes the on-flash layout and must
/// start on explicitly disposable storage.
pub fn reserve_persistence_tail(bytes: usize) -> FlashResult<FlashPersistenceArea> {
    if PERSISTENCE_EXPOSED.load(Ordering::Acquire)
        || RESERVED_TAIL_PAGES.load(Ordering::Acquire) != 0
    {
        return Err(FlashError::Busy);
    }
    let area = crate::core::target::flash_persistence_area();
    let reserved = split_persistence_tail(area, logical_page_size(), erase_sector_size(), bytes)?;
    RESERVED_TAIL_PAGES.store(reserved.page_count, Ordering::Release);
    Ok(reserved)
}

fn split_persistence_tail(
    area: FlashPersistenceArea,
    page: usize,
    sector: usize,
    bytes: usize,
) -> FlashResult<FlashPersistenceArea> {
    if page == 0
        || sector == 0
        || !sector.is_multiple_of(page)
        || bytes == 0
        || !bytes.is_multiple_of(sector)
        || !area.start.is_multiple_of(sector)
    {
        return Err(FlashError::InvalidPageAddress);
    }
    let total = area
        .page_count
        .checked_mul(page)
        .ok_or(FlashError::OutOfRange)?;
    let end = area
        .start
        .checked_add(total)
        .ok_or(FlashError::OutOfRange)?;
    if bytes >= total || end % sector != 0 {
        return Err(FlashError::OutOfRange);
    }
    Ok(FlashPersistenceArea {
        start: end - bytes,
        page_count: bytes / page,
    })
}

#[cfg(test)]
// These focused tests intentionally stay next to the private geometry helper.
#[allow(clippy::items_after_test_module)]
mod reservation_tests {
    use super::*;
    #[test]
    fn diagnostic_sector_is_outside_registry_prefix() {
        let area = FlashPersistenceArea {
            start: 0x103c0000,
            page_count: 1024,
        };
        let tail = split_persistence_tail(area, 256, 4096, 4096).unwrap();
        assert_eq!(tail.start, 0x103ff000);
        assert_eq!(tail.page_count, 16);
        assert_eq!(
            area.start + (area.page_count - tail.page_count) * 256,
            tail.start
        );
    }
    #[test]
    fn invalid_or_exhausted_geometry_is_rejected() {
        let area = FlashPersistenceArea {
            start: 0x1000,
            page_count: 32,
        };
        for (page, sector, bytes) in [
            (0, 4096, 4096),
            (256, 0, 4096),
            (256, 4096, 0),
            (256, 4096, 256),
            (256, 4096, 8192),
        ] {
            assert!(split_persistence_tail(area, page, sector, bytes).is_err());
        }
        assert!(split_persistence_tail(
            FlashPersistenceArea {
                start: usize::MAX - 4095,
                page_count: 32
            },
            256,
            4096,
            4096
        )
        .is_err());
    }
}

pub fn erase_sector(sector_addr: usize) -> FlashResult<()> {
    initialize();
    validate_sector_address(sector_addr)?;
    crate::core::target::flash_erase_sector(sector_addr)
}

pub fn write_page(page_addr: usize, page_buf: &[u8]) -> FlashResult<()> {
    initialize();
    validate_page_buffer(page_addr, page_buf)?;
    crate::core::target::flash_write_page(page_addr, page_buf)
}

pub fn flush_page(page_addr: usize) -> FlashResult<()> {
    initialize();
    validate_page_address(page_addr)?;
    crate::core::target::flash_flush_page(page_addr)
}

pub fn write_page_atomic(page_addr: usize, page_buf: &[u8]) -> FlashResult<()> {
    initialize();
    validate_page_buffer(page_addr, page_buf)?;
    crate::core::target::flash_write_page_atomic(page_addr, page_buf)
}

fn validate_page_address(page_addr: usize) -> FlashResult<()> {
    let page_size = logical_page_size();
    if !page_addr.is_multiple_of(page_size) {
        return Err(FlashError::InvalidPageAddress);
    }
    Ok(())
}

fn validate_page_buffer(page_addr: usize, page_buf: &[u8]) -> FlashResult<()> {
    validate_page_address(page_addr)?;
    if page_buf.len() != logical_page_size() {
        return Err(FlashError::InvalidBufferSize);
    }
    Ok(())
}

fn validate_sector_address(sector_addr: usize) -> FlashResult<()> {
    let sector_size = erase_sector_size();
    if sector_size == 0 || !sector_addr.is_multiple_of(sector_size) {
        return Err(FlashError::InvalidPageAddress);
    }
    Ok(())
}
