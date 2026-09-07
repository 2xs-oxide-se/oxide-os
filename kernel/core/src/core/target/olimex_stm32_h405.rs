/// CPU primitives selected at compile time; peripheral code stays in this board.
#[cfg(oxide_se_board_olimex_stm32_h405)]
pub(crate) use super::armv7m_profile as cpu;

use ::core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::MmioRegister32;

pub const MEMORY_LAYOUT: crate::core::target::layout::TargetMemoryLayout =
    crate::core::target::layout::TargetMemoryLayout {
        name: "olimex-stm32-h405",
        ram_base: 0x2000_0000usize,
        ram_size: 128 * 1024usize,
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

const RCC_BASE: usize = 0x4002_3800;
const RCC_AHB1ENR: MmioRegister32 = MmioRegister32::new(RCC_BASE + 0x30);
const RCC_AHB2ENR: MmioRegister32 = MmioRegister32::new(RCC_BASE + 0x34);
const RCC_APB2ENR: MmioRegister32 = MmioRegister32::new(RCC_BASE + 0x44);

const GPIOA_BASE: usize = 0x4002_0000;
const GPIOA_MODER: MmioRegister32 = MmioRegister32::new(GPIOA_BASE);
const GPIOA_AFRL: MmioRegister32 = MmioRegister32::new(GPIOA_BASE + 0x20);
const GPIOA_AFRH: MmioRegister32 = MmioRegister32::new(GPIOA_BASE + 0x24);

const USART1_BASE: usize = 0x4001_1000;
const USART1_SR: MmioRegister32 = MmioRegister32::new(USART1_BASE);
const USART1_DR: MmioRegister32 = MmioRegister32::new(USART1_BASE + 0x04);
const USART1_BRR: MmioRegister32 = MmioRegister32::new(USART1_BASE + 0x08);
const USART1_CR1: MmioRegister32 = MmioRegister32::new(USART1_BASE + 0x0c);

const RNG_BASE: usize = 0x5006_0800;
const RNG_CR: MmioRegister32 = MmioRegister32::new(RNG_BASE);
const RNG_SR: MmioRegister32 = MmioRegister32::new(RNG_BASE + 0x04);
const RNG_DR: MmioRegister32 = MmioRegister32::new(RNG_BASE + 0x08);

const GPIOA_EN: u32 = 1 << 0;
const RNG_EN: u32 = 1 << 6;
const USART1_EN: u32 = 1 << 4;
const USART_ENABLE: u32 = 1 << 13;
const TRANSMIT_ENABLE: u32 = 1 << 3;
const RECEIVE_ENABLE: u32 = 1 << 2;
const STATUS_RX_NOT_EMPTY: u32 = 1 << 5;
const STATUS_TX_EMPTY: u32 = 1 << 7;
const RNG_CR_RNGEN: u32 = 1 << 2;
const RNG_SR_DRDY: u32 = 1 << 0;
const RNG_SR_CECS: u32 = 1 << 1;
const RNG_SR_SECS: u32 = 1 << 2;
const RNG_INIT_ATTEMPTS: usize = 3;

pub fn timer_clock_hz() -> u32 {
    168_000_000
}

static RNG_PREFETCH: AtomicU32 = AtomicU32::new(0);
static RNG_PREFETCH_VALID: AtomicBool = AtomicBool::new(false);

pub fn initialize() {
    RCC_AHB1ENR.update(|ahb1| ahb1 | GPIOA_EN);
    RCC_APB2ENR.update(|apb2| apb2 | USART1_EN);

    GPIOA_MODER
        .update(|moder| (moder & !((0b11 << 18) | (0b11 << 20))) | (0b10 << 18) | (0b10 << 20));
    let afrl = GPIOA_AFRL.read();
    GPIOA_AFRL.write(afrl);
    GPIOA_AFRH
        .update(|afrh| (afrh & !((0b1111 << 4) | (0b1111 << 8))) | (0b0111 << 4) | (0b0111 << 8));

    USART1_BRR.write(139);
    USART1_CR1.write(USART_ENABLE | TRANSMIT_ENABLE | RECEIVE_ENABLE);
}

pub fn send_byte(byte: u8) {
    while USART1_SR.read() & STATUS_TX_EMPTY == 0 {
        ::core::hint::spin_loop();
    }

    USART1_DR.write(byte as u32);
}

pub fn try_send_byte(byte: u8) -> bool {
    if USART1_SR.read() & STATUS_TX_EMPTY == 0 {
        return false;
    }
    USART1_DR.write(byte as u32);
    true
}

pub fn receive_byte() -> u8 {
    while USART1_SR.read() & STATUS_RX_NOT_EMPTY == 0 {
        ::core::hint::spin_loop();
    }

    USART1_DR.read() as u8
}

pub fn debug_write_byte(byte: u8) {
    semihost_write_byte(byte);
}

pub fn shutdown(exit_code: i32) -> ! {
    semihost_exit(exit_code);
}

pub fn flash_initialize() {}

pub fn flash_logical_page_size() -> usize {
    2048
}

pub fn flash_erase_sector_size() -> usize {
    flash_logical_page_size()
}

pub fn flash_persistence_area() -> crate::core::flash::FlashPersistenceArea {
    crate::core::flash::FlashPersistenceArea {
        start: MEMORY_LAYOUT.flash_base,
        page_count: 0,
    }
}

pub fn flash_erase_sector(_sector_addr: usize) -> crate::core::flash::FlashResult<()> {
    Err(crate::core::flash::FlashError::Unsupported)
}

pub fn flash_write_page(
    _page_addr: usize,
    _page_buf: &[u8],
) -> crate::core::flash::FlashResult<()> {
    Err(crate::core::flash::FlashError::Unsupported)
}

pub fn flash_flush_page(_page_addr: usize) -> crate::core::flash::FlashResult<()> {
    Err(crate::core::flash::FlashError::Unsupported)
}

pub fn flash_write_page_atomic(
    _page_addr: usize,
    _page_buf: &[u8],
) -> crate::core::flash::FlashResult<()> {
    Err(crate::core::flash::FlashError::Unsupported)
}

pub fn crypto_initialize() {
    // STM32F405 gives us a hardware RNG, but AES operations still go through
    // the software fallback in the current core::crypto integration.
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
