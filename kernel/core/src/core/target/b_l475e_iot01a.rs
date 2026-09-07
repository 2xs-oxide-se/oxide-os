/// CPU primitives selected at compile time; peripheral code stays in this board.
#[cfg(oxide_se_board_b_l475e_iot01a)]
pub(crate) use super::armv7m_profile as cpu;

use ::core::slice;
use ::core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::MmioRegister32;

pub fn timer_clock_hz() -> u32 {
    16_000_000
}

pub const MEMORY_LAYOUT: crate::core::target::layout::TargetMemoryLayout =
    crate::core::target::layout::TargetMemoryLayout {
        name: "b-l475e-iot01a",
        ram_base: 0x2000_0000usize,
        ram_size: 96 * 1024usize,
        flash_base: 0x0800_0000usize,
        flash_size: 1024 * 1024usize,
        kernel_heap_min_size: 6 * 1024usize,
        kernel_stack_size: 0x4000usize,
    };

// Target MPU alignment model:
// - strict alignment
// - region size must be a power of two and at least 32 bytes
// - region base address must be aligned to the region size
//
// This board is currently driven through the shared classic ARM
// M-profile MPU backend.

const SYS_EXIT_EXTENDED: u32 = 0x20;
const SYS_WRITEC: u32 = 0x03;
const ADP_STOPPED_APPLICATION_EXIT: u32 = 0x20026;

const RCC_BASE: usize = 0x4002_1000;
const RCC_AHB2ENR: MmioRegister32 = MmioRegister32::new(RCC_BASE + 0x4c);
const RCC_APB2ENR: MmioRegister32 = MmioRegister32::new(RCC_BASE + 0x60);
const RCC_CCIPR: MmioRegister32 = MmioRegister32::new(RCC_BASE + 0x88);
const RCC_CRRCR: MmioRegister32 = MmioRegister32::new(RCC_BASE + 0x98);

const GPIOB_BASE: usize = 0x4800_0400;
const GPIOB_MODER: MmioRegister32 = MmioRegister32::new(GPIOB_BASE);
const GPIOB_AFRL: MmioRegister32 = MmioRegister32::new(GPIOB_BASE + 0x20);

const USART1_BASE: usize = 0x4001_3800;
const USART1_CR1: MmioRegister32 = MmioRegister32::new(USART1_BASE);
const USART1_BRR: MmioRegister32 = MmioRegister32::new(USART1_BASE + 0x0c);
const USART1_ISR: MmioRegister32 = MmioRegister32::new(USART1_BASE + 0x1c);
const USART1_ICR: MmioRegister32 = MmioRegister32::new(USART1_BASE + 0x20);
const USART1_RDR: MmioRegister32 = MmioRegister32::new(USART1_BASE + 0x24);
const USART1_TDR: MmioRegister32 = MmioRegister32::new(USART1_BASE + 0x28);

const RNG_BASE: usize = 0x5006_0800;
const RNG_CR: MmioRegister32 = MmioRegister32::new(RNG_BASE);
const RNG_SR: MmioRegister32 = MmioRegister32::new(RNG_BASE + 0x04);
const RNG_DR: MmioRegister32 = MmioRegister32::new(RNG_BASE + 0x08);

const FLASH_BASE: usize = 0x4002_2000;
const FLASH_KEYR: MmioRegister32 = MmioRegister32::new(FLASH_BASE + 0x08);
const FLASH_SR: MmioRegister32 = MmioRegister32::new(FLASH_BASE + 0x10);
const FLASH_CR: MmioRegister32 = MmioRegister32::new(FLASH_BASE + 0x14);

const GPIOB_EN: u32 = 1 << 1;
const RNG_EN: u32 = 1 << 18;
const USART1_EN: u32 = 1 << 14;
const USART_ENABLE: u32 = 1 << 0;
const TRANSMIT_ENABLE: u32 = 1 << 3;
const RECEIVE_ENABLE: u32 = 1 << 2;
const STATUS_RX_NOT_EMPTY: u32 = 1 << 5;
const STATUS_TX_EMPTY: u32 = 1 << 7;
const STATUS_TRANSMIT_ENABLE_ACK: u32 = 1 << 21;
const STATUS_RECEIVE_ENABLE_ACK: u32 = 1 << 22;
const STATUS_PARITY_ERROR: u32 = 1 << 0;
const STATUS_FRAMING_ERROR: u32 = 1 << 1;
const STATUS_NOISE_ERROR: u32 = 1 << 2;
const STATUS_OVERRUN_ERROR: u32 = 1 << 3;
const STATUS_RX_ERROR_MASK: u32 =
    STATUS_PARITY_ERROR | STATUS_FRAMING_ERROR | STATUS_NOISE_ERROR | STATUS_OVERRUN_ERROR;
const ICR_PARITY_ERROR_CLEAR: u32 = 1 << 0;
const ICR_FRAMING_ERROR_CLEAR: u32 = 1 << 1;
const ICR_NOISE_ERROR_CLEAR: u32 = 1 << 2;
const ICR_OVERRUN_ERROR_CLEAR: u32 = 1 << 3;
const ICR_RX_ERROR_CLEAR_MASK: u32 = ICR_PARITY_ERROR_CLEAR
    | ICR_FRAMING_ERROR_CLEAR
    | ICR_NOISE_ERROR_CLEAR
    | ICR_OVERRUN_ERROR_CLEAR;
const RCC_CRRCR_HSI48ON: u32 = 1 << 0;
const RCC_CRRCR_HSI48RDY: u32 = 1 << 1;
const RCC_CCIPR_CLK48SEL_SHIFT: u32 = 26;
const RCC_CCIPR_CLK48SEL_MASK: u32 = 0b11 << RCC_CCIPR_CLK48SEL_SHIFT;
const RCC_CCIPR_CLK48SEL_HSI48: u32 = 0b11 << RCC_CCIPR_CLK48SEL_SHIFT;
const RNG_CR_RNGEN: u32 = 1 << 2;
const RNG_SR_DRDY: u32 = 1 << 0;
const RNG_SR_CECS: u32 = 1 << 1;
const RNG_SR_SECS: u32 = 1 << 2;
const RNG_INIT_ATTEMPTS: usize = 3;

const FLASH_KEY1: u32 = 0x4567_0123;
const FLASH_KEY2: u32 = 0xcdef_89ab;
const FLASH_CR_PG: u32 = 1 << 0;
const FLASH_CR_PER: u32 = 1 << 1;
const FLASH_CR_PNB_SHIFT: u32 = 3;
const FLASH_CR_PNB_MASK: u32 = 0xff << FLASH_CR_PNB_SHIFT;
const FLASH_CR_BKER: u32 = 1 << 11;
const FLASH_CR_START: u32 = 1 << 16;
const FLASH_CR_LOCK: u32 = 1 << 31;
const FLASH_SR_EOP: u32 = 1 << 0;
const FLASH_SR_OPERR: u32 = 1 << 1;
const FLASH_SR_PROGERR: u32 = 1 << 3;
const FLASH_SR_WRPERR: u32 = 1 << 4;
const FLASH_SR_PGAERR: u32 = 1 << 5;
const FLASH_SR_SIZERR: u32 = 1 << 6;
const FLASH_SR_PGSERR: u32 = 1 << 7;
const FLASH_SR_MISERR: u32 = 1 << 8;
const FLASH_SR_FASTERR: u32 = 1 << 9;
const FLASH_SR_RDERR: u32 = 1 << 14;
const FLASH_SR_OPTVERR: u32 = 1 << 15;
const FLASH_SR_BSY: u32 = 1 << 16;
const FLASH_SR_CFGBSY: u32 = 1 << 18;
const FLASH_SR_ERROR_MASK: u32 = FLASH_SR_OPERR
    | FLASH_SR_PROGERR
    | FLASH_SR_WRPERR
    | FLASH_SR_PGAERR
    | FLASH_SR_SIZERR
    | FLASH_SR_PGSERR
    | FLASH_SR_MISERR
    | FLASH_SR_FASTERR
    | FLASH_SR_RDERR
    | FLASH_SR_OPTVERR;
const FLASH_SR_CLEAR_MASK: u32 = FLASH_SR_EOP | FLASH_SR_ERROR_MASK;

const FLASH_BANK2_BASE: usize = 0x0808_0000;
const FLASH_BANK2_SIZE: usize = 512 * 1024;
const FLASH_BANK2_END: usize = FLASH_BANK2_BASE + FLASH_BANK2_SIZE;
const LOGICAL_PAGE_SIZE: usize = 2048;
const MANAGED_PAGE_COUNT: usize = 240;
const RESERVED_SLOT_COUNT: usize = 8;
const MANAGED_FLASH_END: usize = FLASH_BANK2_BASE + (MANAGED_PAGE_COUNT * LOGICAL_PAGE_SIZE);
const EMPTY_WORD: u32 = 0xffff_ffff;
const METADATA_MAGIC: u32 = 0x4750_4f53;

static RNG_PREFETCH: AtomicU32 = AtomicU32::new(0);
static RNG_PREFETCH_VALID: AtomicBool = AtomicBool::new(false);

#[repr(C)]
#[derive(Clone, Copy)]
struct MetadataHeader {
    magic: u32,
    logical_page_addr: u32,
    shadow_crc: u32,
    sequence_number: u32,
}

impl MetadataHeader {
    const fn empty(sequence_number: u32) -> Self {
        Self {
            magic: METADATA_MAGIC,
            logical_page_addr: EMPTY_WORD,
            shadow_crc: EMPTY_WORD,
            sequence_number,
        }
    }

    fn has_target(self) -> bool {
        self.magic == METADATA_MAGIC && self.logical_page_addr != EMPTY_WORD
    }
}

pub fn initialize() {
    RCC_AHB2ENR.update(|ahb2| ahb2 | GPIOB_EN);
    RCC_APB2ENR.update(|apb2| apb2 | USART1_EN);

    GPIOB_MODER
        .update(|moder| (moder & !((0b11 << 12) | (0b11 << 14))) | (0b10 << 12) | (0b10 << 14));
    GPIOB_AFRL.update(|afrl| {
        (afrl & !((0b1111 << 24) | (0b1111 << 28))) | (0b0111 << 24) | (0b0111 << 28)
    });

    USART1_BRR.write(139);
    USART1_CR1.write(USART_ENABLE | TRANSMIT_ENABLE | RECEIVE_ENABLE);
    while USART1_ISR.read() & (STATUS_TRANSMIT_ENABLE_ACK | STATUS_RECEIVE_ENABLE_ACK)
        != (STATUS_TRANSMIT_ENABLE_ACK | STATUS_RECEIVE_ENABLE_ACK)
    {
        ::core::hint::spin_loop();
    }
}

pub fn send_byte(byte: u8) {
    while USART1_ISR.read() & STATUS_TX_EMPTY == 0 {
        ::core::hint::spin_loop();
    }

    USART1_TDR.write(byte as u32);
}

pub fn try_send_byte(byte: u8) -> bool {
    if USART1_ISR.read() & STATUS_TX_EMPTY == 0 {
        return false;
    }
    USART1_TDR.write(byte as u32);
    true
}

pub fn receive_byte() -> u8 {
    while USART1_ISR.read() & STATUS_RX_NOT_EMPTY == 0 {
        let isr = USART1_ISR.read();
        if isr & STATUS_RX_ERROR_MASK != 0 {
            USART1_ICR.write(ICR_RX_ERROR_CLEAR_MASK);
        }
        ::core::hint::spin_loop();
    }

    USART1_RDR.read() as u8
}

pub fn debug_write_byte(byte: u8) {
    semihost_write_byte(byte);
}

pub fn shutdown(exit_code: i32) -> ! {
    semihost_exit(exit_code);
}

pub fn flash_initialize() {
    if let Err(error) = flash_initialize_inner() {
        panic!("flash init failed: {:?}", error);
    }
}

pub fn flash_logical_page_size() -> usize {
    LOGICAL_PAGE_SIZE
}

pub fn flash_erase_sector_size() -> usize {
    LOGICAL_PAGE_SIZE
}

pub fn flash_persistence_area() -> crate::core::flash::FlashPersistenceArea {
    crate::core::flash::FlashPersistenceArea {
        start: MEMORY_LAYOUT.flash_base,
        page_count: 0,
    }
}

pub fn flash_erase_sector(sector_addr: usize) -> crate::core::flash::FlashResult<()> {
    erase_page_raw(sector_addr)
}

pub fn flash_write_page(page_addr: usize, page_buf: &[u8]) -> crate::core::flash::FlashResult<()> {
    validate_public_page_address(page_addr)?;
    write_page_raw(page_addr, page_buf)
}

pub fn flash_flush_page(page_addr: usize) -> crate::core::flash::FlashResult<()> {
    validate_public_page_address(page_addr)?;
    Ok(())
}

pub fn flash_write_page_atomic(
    page_addr: usize,
    page_buf: &[u8],
) -> crate::core::flash::FlashResult<()> {
    validate_public_page_address(page_addr)?;

    let (slot, next_sequence) = select_metadata_slot()?;
    let metadata_addr = metadata_slot_addr(slot);
    let shadow_addr = shadow_slot_addr(slot);

    erase_page_raw(metadata_addr)?;
    write_page_raw(shadow_addr, page_buf)?;

    let shadow_page = flash_page_slice(shadow_addr);
    let shadow_crc = crc32(page_buf);
    if shadow_page != page_buf || crc32(shadow_page) != shadow_crc {
        return Err(crate::core::flash::FlashError::VerifyFailed);
    }

    program_metadata_header(
        metadata_addr,
        MetadataHeader {
            magic: METADATA_MAGIC,
            logical_page_addr: page_addr as u32,
            shadow_crc,
            sequence_number: next_sequence,
        },
    )?;

    flash_write_page(page_addr, page_buf)?;
    flash_flush_page(page_addr)?;
    Ok(())
}

pub fn crypto_initialize() {
    // TODO: STM32L475 exposes a hardware AES peripheral, but the current
    // core::crypto target backend only wires the RNG path on this board.
    RCC_CRRCR.update(|crrcr| crrcr | RCC_CRRCR_HSI48ON);
    while RCC_CRRCR.read() & RCC_CRRCR_HSI48RDY == 0 {
        ::core::hint::spin_loop();
    }

    RCC_CCIPR.update(|ccipr| (ccipr & !RCC_CCIPR_CLK48SEL_MASK) | RCC_CCIPR_CLK48SEL_HSI48);
    RCC_AHB2ENR.update(|ahb2| ahb2 | RNG_EN);
    RNG_CR.update(|cr| cr | RNG_CR_RNGEN);

    RNG_PREFETCH_VALID.store(false, Ordering::Release);
    RNG_PREFETCH.store(
        rng_prime_prefetch().expect("rng init failed"),
        Ordering::Release,
    );
    RNG_PREFETCH_VALID.store(true, Ordering::Release);
}

pub fn crypto_fill_random(buf: &mut [u8]) -> crate::core::crypto::CryptoResult<()> {
    if buf.is_empty() {
        return Ok(());
    }

    let mut offset = 0usize;
    while offset < buf.len() {
        let word = take_rng_word()?;
        let bytes = word.to_le_bytes();
        let chunk_len = usize::min(4, buf.len() - offset);
        buf[offset..offset + chunk_len].copy_from_slice(&bytes[..chunk_len]);
        offset += chunk_len;
    }

    Ok(())
}

fn flash_initialize_inner() -> crate::core::flash::FlashResult<()> {
    initialize_metadata_pages()?;
    recover_interrupted_atomic_writes()
}

fn initialize_metadata_pages() -> crate::core::flash::FlashResult<()> {
    for slot in 0..RESERVED_SLOT_COUNT {
        let metadata_addr = metadata_slot_addr(slot);
        let header = read_metadata_header(metadata_addr);
        if header.magic == METADATA_MAGIC {
            continue;
        }

        erase_page_raw(metadata_addr)?;
        program_metadata_header(metadata_addr, MetadataHeader::empty(slot as u32))?;
    }

    Ok(())
}

fn recover_interrupted_atomic_writes() -> crate::core::flash::FlashResult<()> {
    let (slot, header) = latest_metadata_slot()?;
    if !header.has_target() {
        return Ok(());
    }

    let page_addr = header.logical_page_addr as usize;
    validate_public_page_address(page_addr)?;

    let shadow_addr = shadow_slot_addr(slot);
    let shadow_page = flash_page_slice(shadow_addr);
    if crc32(shadow_page) != header.shadow_crc {
        return Err(crate::core::flash::FlashError::CorruptedState);
    }

    if flash_page_slice(page_addr) != shadow_page {
        write_page_raw(page_addr, shadow_page)?;
    }

    Ok(())
}

fn select_metadata_slot() -> crate::core::flash::FlashResult<(usize, u32)> {
    let mut selected_slot = 0;
    let mut smallest_sequence = u32::MAX;
    let mut greatest_sequence = 0u32;

    for slot in 0..RESERVED_SLOT_COUNT {
        let header = read_metadata_header(metadata_slot_addr(slot));
        if header.magic != METADATA_MAGIC {
            return Err(crate::core::flash::FlashError::CorruptedState);
        }
        if header.sequence_number < smallest_sequence {
            smallest_sequence = header.sequence_number;
            selected_slot = slot;
        }
        if header.sequence_number > greatest_sequence {
            greatest_sequence = header.sequence_number;
        }
    }

    Ok((selected_slot, greatest_sequence.wrapping_add(1)))
}

fn latest_metadata_slot() -> crate::core::flash::FlashResult<(usize, MetadataHeader)> {
    let mut selected_slot = 0usize;
    let mut selected_header = MetadataHeader::empty(0);
    let mut initialized = false;

    for slot in 0..RESERVED_SLOT_COUNT {
        let header = read_metadata_header(metadata_slot_addr(slot));
        if header.magic != METADATA_MAGIC {
            return Err(crate::core::flash::FlashError::CorruptedState);
        }

        if !initialized || header.sequence_number > selected_header.sequence_number {
            selected_slot = slot;
            selected_header = header;
            initialized = true;
        }
    }

    if !initialized {
        return Err(crate::core::flash::FlashError::CorruptedState);
    }

    Ok((selected_slot, selected_header))
}

fn validate_public_page_address(page_addr: usize) -> crate::core::flash::FlashResult<()> {
    if page_addr % LOGICAL_PAGE_SIZE != 0 {
        return Err(crate::core::flash::FlashError::InvalidPageAddress);
    }
    if !(FLASH_BANK2_BASE..MANAGED_FLASH_END).contains(&page_addr) {
        return Err(crate::core::flash::FlashError::OutOfRange);
    }
    Ok(())
}

fn validate_internal_page_address(page_addr: usize) -> crate::core::flash::FlashResult<()> {
    if page_addr % LOGICAL_PAGE_SIZE != 0 {
        return Err(crate::core::flash::FlashError::InvalidPageAddress);
    }
    if !(FLASH_BANK2_BASE..FLASH_BANK2_END).contains(&page_addr) {
        return Err(crate::core::flash::FlashError::OutOfRange);
    }
    Ok(())
}

fn metadata_slot_addr(slot: usize) -> usize {
    FLASH_BANK2_END - ((slot + 1) * LOGICAL_PAGE_SIZE)
}

fn take_rng_word() -> crate::core::crypto::CryptoResult<u32> {
    if !RNG_PREFETCH_VALID.load(Ordering::Acquire) {
        RNG_PREFETCH.store(rng_read_word_blocking()?, Ordering::Release);
        RNG_PREFETCH_VALID.store(true, Ordering::Release);
    }

    let word = RNG_PREFETCH.load(Ordering::Acquire);
    match rng_read_word_blocking() {
        Ok(next_word) => {
            RNG_PREFETCH.store(next_word, Ordering::Release);
            RNG_PREFETCH_VALID.store(true, Ordering::Release);
        }
        Err(_) => {
            RNG_PREFETCH_VALID.store(false, Ordering::Release);
        }
    }
    Ok(word)
}

fn rng_read_word_blocking() -> crate::core::crypto::CryptoResult<u32> {
    loop {
        let status = RNG_SR.read();
        if status & (RNG_SR_CECS | RNG_SR_SECS) != 0 {
            return Err(crate::core::crypto::CryptoError::EntropyUnavailable);
        }
        if status & RNG_SR_DRDY != 0 {
            return Ok(RNG_DR.read());
        }
        ::core::hint::spin_loop();
    }
}

fn rng_prime_prefetch() -> crate::core::crypto::CryptoResult<u32> {
    let mut last_error = crate::core::crypto::CryptoError::EntropyUnavailable;

    for _ in 0..RNG_INIT_ATTEMPTS {
        match rng_read_word_blocking() {
            Ok(word) => return Ok(word),
            Err(error) => last_error = error,
        }
    }

    Err(last_error)
}

fn shadow_slot_addr(slot: usize) -> usize {
    FLASH_BANK2_END - ((slot + 1 + RESERVED_SLOT_COUNT) * LOGICAL_PAGE_SIZE)
}

fn read_metadata_header(page_addr: usize) -> MetadataHeader {
    // Invariant: callers pass addresses inside the managed flash metadata area.
    unsafe {
        MetadataHeader {
            magic: core::ptr::read_volatile(page_addr as *const u32),
            logical_page_addr: core::ptr::read_volatile((page_addr + 4) as *const u32),
            shadow_crc: core::ptr::read_volatile((page_addr + 8) as *const u32),
            sequence_number: core::ptr::read_volatile((page_addr + 12) as *const u32),
        }
    }
}

fn program_metadata_header(
    page_addr: usize,
    header: MetadataHeader,
) -> crate::core::flash::FlashResult<()> {
    program_double_word(page_addr, header.magic, header.logical_page_addr)?;
    program_double_word(page_addr + 8, header.shadow_crc, header.sequence_number)
}

fn write_page_raw(page_addr: usize, page_buf: &[u8]) -> crate::core::flash::FlashResult<()> {
    validate_internal_page_address(page_addr)?;
    if page_buf.len() != LOGICAL_PAGE_SIZE {
        return Err(crate::core::flash::FlashError::InvalidBufferSize);
    }

    erase_page_raw(page_addr)?;

    for (offset, chunk) in page_buf.chunks_exact(8).enumerate() {
        let offset = offset * 8;
        let low = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let high = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        program_double_word(page_addr + offset, low, high)?;
    }

    if flash_page_slice(page_addr) != page_buf {
        return Err(crate::core::flash::FlashError::VerifyFailed);
    }

    Ok(())
}

fn erase_page_raw(page_addr: usize) -> crate::core::flash::FlashResult<()> {
    validate_internal_page_address(page_addr)?;
    let page_index = (page_addr - FLASH_BANK2_BASE) / LOGICAL_PAGE_SIZE;
    let page_index = u32::try_from(page_index).map_err(|_| crate::core::flash::FlashError::Io)?;

    flash_unlock();
    flash_wait_ready()?;
    flash_clear_status();

    let mut control = FLASH_CR.read();
    control &= !(FLASH_CR_PNB_MASK | FLASH_CR_PER | FLASH_CR_PG | FLASH_CR_START);
    control |= FLASH_CR_PER | FLASH_CR_BKER | (page_index << FLASH_CR_PNB_SHIFT);
    FLASH_CR.write(control);
    FLASH_CR.write(control | FLASH_CR_START);

    let result = flash_wait_ready();

    let control = FLASH_CR.read() & !(FLASH_CR_PER | FLASH_CR_PNB_MASK | FLASH_CR_START);
    FLASH_CR.write(control);

    result?;
    flash_verify_page_erased(page_addr)
}

fn program_double_word(
    page_addr: usize,
    low: u32,
    high: u32,
) -> crate::core::flash::FlashResult<()> {
    flash_unlock();
    flash_wait_ready()?;
    flash_clear_status();

    FLASH_CR.write(FLASH_CR.read() | FLASH_CR_PG);
    // Invariant: `page_addr` was validated as an internal flash page address.
    unsafe {
        core::ptr::write_volatile(page_addr as *mut u32, low);
        core::ptr::write_volatile((page_addr + 4) as *mut u32, high);
    }

    let result = flash_wait_ready();

    FLASH_CR.write(FLASH_CR.read() & !FLASH_CR_PG);

    result?;

    // Invariant: same validated flash double-word as above.
    let verified_low = unsafe { core::ptr::read_volatile(page_addr as *const u32) };
    let verified_high = unsafe { core::ptr::read_volatile((page_addr + 4) as *const u32) };
    if verified_low != low || verified_high != high {
        return Err(crate::core::flash::FlashError::VerifyFailed);
    }

    Ok(())
}

fn flash_page_slice(page_addr: usize) -> &'static [u8] {
    // Invariant: callers validate that `page_addr` is inside the managed flash
    // bank and aligned to LOGICAL_PAGE_SIZE before exposing this read-only view.
    unsafe { slice::from_raw_parts(page_addr as *const u8, LOGICAL_PAGE_SIZE) }
}

fn flash_unlock() {
    if FLASH_CR.read() & FLASH_CR_LOCK != 0 {
        FLASH_KEYR.write(FLASH_KEY1);
        FLASH_KEYR.write(FLASH_KEY2);
    }
}

fn flash_wait_ready() -> crate::core::flash::FlashResult<()> {
    loop {
        let status = FLASH_SR.read();
        if status & (FLASH_SR_BSY | FLASH_SR_CFGBSY) == 0 {
            if status & FLASH_SR_ERROR_MASK != 0 {
                flash_clear_status();
                return Err(crate::core::flash::FlashError::Io);
            }
            if status & FLASH_SR_EOP != 0 {
                flash_clear_status();
            }
            return Ok(());
        }
        ::core::hint::spin_loop();
    }
}

fn flash_clear_status() {
    FLASH_SR.write(FLASH_SR_CLEAR_MASK);
}

fn flash_verify_page_erased(page_addr: usize) -> crate::core::flash::FlashResult<()> {
    for offset in (0..LOGICAL_PAGE_SIZE).step_by(4) {
        // Invariant: `page_addr` was validated as a managed flash page base.
        let value = unsafe { core::ptr::read_volatile((page_addr + offset) as *const u32) };
        if value != EMPTY_WORD {
            return Err(crate::core::flash::FlashError::VerifyFailed);
        }
    }
    Ok(())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = EMPTY_WORD;
    for &byte in bytes {
        let mut word = (crc ^ u32::from(byte)) & 0xff;
        for _ in 0..8 {
            if word & 1 != 0 {
                word = (word >> 1) ^ 0xedb8_8320;
            } else {
                word >>= 1;
            }
        }
        crc = (crc >> 8) ^ word;
    }
    !crc
}

fn semihost_exit(exit_code: i32) -> ! {
    #[repr(C)]
    struct ExitBlock {
        reason: u32,
        subcode: u32,
    }

    let block = ExitBlock {
        reason: ADP_STOPPED_APPLICATION_EXIT,
        subcode: exit_code as u32,
    };

    unsafe {
        ::core::arch::asm!(
            "bkpt 0xab",
            in("r0") SYS_EXIT_EXTENDED,
            in("r1") &block,
            options(noreturn)
        );
    }
}

fn semihost_write_byte(byte: u8) {
    let value = byte;

    unsafe {
        ::core::arch::asm!(
            "bkpt 0xab",
            inlateout("r0") SYS_WRITEC => _,
            inlateout("r1") &value => _,
            options(nostack, preserves_flags),
        );
    }
}
