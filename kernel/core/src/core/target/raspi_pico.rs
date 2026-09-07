/// CPU primitives selected at compile time; peripheral code stays in this board.
#[cfg(oxide_se_board_raspi_pico)]
pub(crate) use super::armv6m_profile as cpu;

use super::MmioRegister32;

pub const MEMORY_LAYOUT: crate::core::target::layout::TargetMemoryLayout =
    crate::core::target::layout::TargetMemoryLayout {
        name: "raspi-pico1",
        ram_base: 0x2000_0000usize,
        ram_size: 264 * 1024usize,
        flash_base: 0x1000_0000usize,
        flash_size: 2 * 1024 * 1024usize,
        kernel_heap_min_size: 15_872usize,
        kernel_stack_size: 7 * 1024usize,
    };

unsafe extern "C" {
    static __registry_persistence_start: u8;
    static __registry_persistence_page_count: u8;
}

const XIP_FLASH_BASE: usize = 0x1000_0000;
const FLASH_PAGE_SIZE: usize = 256;
const FLASH_SECTOR_SIZE: usize = 4096;
const ROM_FUNC_TABLE_PTR_ADDR: usize = 0x0000_0014;
const ROM_TABLE_LOOKUP_PTR_ADDR: usize = 0x0000_0018;
const FLASH_ERASE_CMD_4K: u8 = 0x20;

// Target MPU alignment model:
// - RP2040/Cortex-M0+ is currently brought up as a minimal APDU board;
// - Rustlet isolation and kernel stack guard MPU programming are not wired yet.

const IOBANK0_BASE: usize = 0x4001_4000;
const GPIO0_CTRL: MmioRegister32 = MmioRegister32::new(IOBANK0_BASE + 0x04);
const GPIO1_CTRL: MmioRegister32 = MmioRegister32::new(IOBANK0_BASE + 0x0c);
const GPIO_FUNCSEL_UART: u32 = 2;

const PADS_BANK0_BASE: usize = 0x4001_c000;
const PADS_BANK0_GPIO0: MmioRegister32 = MmioRegister32::new(PADS_BANK0_BASE + 0x04);
const PADS_BANK0_GPIO1: MmioRegister32 = MmioRegister32::new(PADS_BANK0_BASE + 0x08);
const PAD_IE: u32 = 1 << 6;

const RESETS_BASE: usize = 0x4000_c000;
const RESETS_RESET: MmioRegister32 = MmioRegister32::new(RESETS_BASE);
const RESETS_RESET_DONE: MmioRegister32 = MmioRegister32::new(RESETS_BASE + 0x08);
const RESETS_RESET_IO_BANK0: u32 = 1 << 5;
const RESETS_RESET_PADS_BANK0: u32 = 1 << 8;
const RESETS_RESET_UART0: u32 = 1 << 22;

const CLOCKS_BASE: usize = 0x4000_8000;
const CLOCKS_CLK_REF_CTRL: MmioRegister32 = MmioRegister32::new(CLOCKS_BASE + 0x30);
const CLOCKS_CLK_REF_DIV: MmioRegister32 = MmioRegister32::new(CLOCKS_BASE + 0x34);
const CLOCKS_CLK_REF_SELECTED: MmioRegister32 = MmioRegister32::new(CLOCKS_BASE + 0x38);
const CLOCKS_CLK_SYS_CTRL: MmioRegister32 = MmioRegister32::new(CLOCKS_BASE + 0x3c);
const CLOCKS_CLK_SYS_DIV: MmioRegister32 = MmioRegister32::new(CLOCKS_BASE + 0x40);
const CLOCKS_CLK_SYS_SELECTED: MmioRegister32 = MmioRegister32::new(CLOCKS_BASE + 0x44);
const CLOCKS_CLK_PERI_CTRL: MmioRegister32 = MmioRegister32::new(CLOCKS_BASE + 0x48);
const CLOCKS_CLK_PERI_DIV: MmioRegister32 = MmioRegister32::new(CLOCKS_BASE + 0x4c);
const CLOCKS_CLK_PERI_CTRL_ENABLE: u32 = 1 << 11;
const CLOCKS_CLK_PERI_CTRL_AUXSRC_CLK_SYS: u32 = 0 << 5;
const CLOCKS_CLK_REF_CTRL_SRC_XOSC: u32 = 2;
const CLOCKS_CLK_SYS_CTRL_SRC_CLK_REF: u32 = 0;
const CLOCKS_DIV_1: u32 = 1 << 8;

pub fn timer_clock_hz() -> u32 {
    12_000_000
}

const XOSC_BASE: usize = 0x4002_4000;
const XOSC_CTRL: MmioRegister32 = MmioRegister32::new(XOSC_BASE);
const XOSC_STATUS: MmioRegister32 = MmioRegister32::new(XOSC_BASE + 0x04);
const XOSC_STARTUP: MmioRegister32 = MmioRegister32::new(XOSC_BASE + 0x0c);
const XOSC_CTRL_FREQ_1_15MHZ: u32 = 0xaa0;
const XOSC_CTRL_ENABLE: u32 = 0xfab << 12;
const XOSC_STATUS_STABLE: u32 = 1 << 31;

const ROSC_BASE: usize = 0x4006_0000;
const ROSC_CTRL: MmioRegister32 = MmioRegister32::new(ROSC_BASE);
const ROSC_DORMANT: MmioRegister32 = MmioRegister32::new(ROSC_BASE + 0x0c);
const ROSC_STATUS: MmioRegister32 = MmioRegister32::new(ROSC_BASE + 0x18);
const ROSC_RANDOMBIT: MmioRegister32 = MmioRegister32::new(ROSC_BASE + 0x1c);
const ROSC_CTRL_ENABLE_MASK: u32 = 0xfff << 12;
const ROSC_CTRL_ENABLE: u32 = 0xfab << 12;
const ROSC_WAKE: u32 = 0x7761_6b65;
const ROSC_STATUS_READY: u32 = (1 << 31) | (1 << 12);
const ROSC_READY_POLL_LIMIT: usize = 100_000;

const UART0_BASE: usize = 0x4003_4000;
const UARTDR: MmioRegister32 = MmioRegister32::new(UART0_BASE);
const UARTFR: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x18);
const UARTIBRD: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x24);
const UARTFBRD: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x28);
const UARTLCR_H: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x2c);
const UARTCR: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x30);
const UARTIMSC: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x38);
const UARTICR: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x44);

const UARTFR_TXFF: u32 = 1 << 5;
const UARTFR_RXFE: u32 = 1 << 4;
const UARTFR_BUSY: u32 = 1 << 3;
const UARTLCR_H_FEN: u32 = 1 << 4;
const UARTLCR_H_WLEN_8: u32 = 0b11 << 5;
const UARTCR_UARTEN: u32 = 1 << 0;
const UARTCR_TXE: u32 = 1 << 8;
const UARTCR_RXE: u32 = 1 << 9;
const UARTICR_ALL: u32 = 0x07ff;

const SYNTHETIC_ROM_DBG_BASE: usize = 0x5fff_0000;
const SYNTHETIC_ROM_DBG_CMD: MmioRegister32 = MmioRegister32::new(SYNTHETIC_ROM_DBG_BASE);
const SYNTHETIC_ROM_DBG_ARG0: MmioRegister32 = MmioRegister32::new(SYNTHETIC_ROM_DBG_BASE + 0x04);
const SYNTHETIC_ROM_DBG_CMD_EXIT: u32 = u32::from_le_bytes(*b"EXIT");

pub fn initialize() {
    initialize_xosc_12mhz();

    let gpio_reset_mask = RESETS_RESET_IO_BANK0 | RESETS_RESET_PADS_BANK0;
    RESETS_RESET.write(RESETS_RESET.read() & !gpio_reset_mask);
    while RESETS_RESET_DONE.read() & gpio_reset_mask != gpio_reset_mask {
        ::core::hint::spin_loop();
    }

    RESETS_RESET.write(RESETS_RESET.read() & !RESETS_RESET_UART0);
    while RESETS_RESET_DONE.read() & RESETS_RESET_UART0 != RESETS_RESET_UART0 {
        ::core::hint::spin_loop();
    }

    // Invariant: qemu-rp2040-pico defaults to strict UART pins, so GPIO0 and
    // GPIO1 must be switched to FUNCSEL=UART before UART0 reaches -serial.
    PADS_BANK0_GPIO0.write(PAD_IE);
    PADS_BANK0_GPIO1.write(PAD_IE);
    GPIO0_CTRL.write(GPIO_FUNCSEL_UART);
    GPIO1_CTRL.write(GPIO_FUNCSEL_UART);

    UARTCR.write(0);
    while UARTFR.read() & UARTFR_BUSY != 0 {
        ::core::hint::spin_loop();
    }

    // 115200 bauds from the explicitly selected 12 MHz clk_peri.
    UARTIBRD.write(6);
    UARTFBRD.write(33);
    UARTLCR_H.write(UARTLCR_H_WLEN_8 | UARTLCR_H_FEN);
    UARTICR.write(UARTICR_ALL);
    UARTIMSC.write(0);
    UARTCR.write(UARTCR_UARTEN | UARTCR_TXE | UARTCR_RXE);
}

fn initialize_xosc_12mhz() {
    XOSC_STARTUP.write(0x00c4);
    XOSC_CTRL.write(XOSC_CTRL_ENABLE | XOSC_CTRL_FREQ_1_15MHZ);
    while XOSC_STATUS.read() & XOSC_STATUS_STABLE == 0 {
        ::core::hint::spin_loop();
    }

    CLOCKS_CLK_REF_DIV.write(CLOCKS_DIV_1);
    CLOCKS_CLK_REF_CTRL.write(CLOCKS_CLK_REF_CTRL_SRC_XOSC);
    while CLOCKS_CLK_REF_SELECTED.read() & (1 << CLOCKS_CLK_REF_CTRL_SRC_XOSC) == 0 {
        ::core::hint::spin_loop();
    }

    CLOCKS_CLK_SYS_DIV.write(CLOCKS_DIV_1);
    CLOCKS_CLK_SYS_CTRL.write(CLOCKS_CLK_SYS_CTRL_SRC_CLK_REF);
    while CLOCKS_CLK_SYS_SELECTED.read() & (1 << CLOCKS_CLK_SYS_CTRL_SRC_CLK_REF) == 0 {
        ::core::hint::spin_loop();
    }

    CLOCKS_CLK_PERI_DIV.write(CLOCKS_DIV_1);
    CLOCKS_CLK_PERI_CTRL.write(CLOCKS_CLK_PERI_CTRL_ENABLE | CLOCKS_CLK_PERI_CTRL_AUXSRC_CLK_SYS);
}

pub fn send_byte(byte: u8) {
    while UARTFR.read() & UARTFR_TXFF != 0 {
        ::core::hint::spin_loop();
    }

    UARTDR.write(byte as u32);
}

pub fn try_send_byte(byte: u8) -> bool {
    if UARTFR.read() & UARTFR_TXFF != 0 {
        return false;
    }
    UARTDR.write(byte as u32);
    true
}

pub fn receive_byte() -> u8 {
    while UARTFR.read() & UARTFR_RXFE != 0 {
        ::core::hint::spin_loop();
    }

    UARTDR.read() as u8
}

pub fn debug_write_byte(byte: u8) {
    crate::core::semihosting::write_byte(byte);
}

pub fn shutdown(exit_code: i32) -> ! {
    SYNTHETIC_ROM_DBG_ARG0.write(exit_code as u32);
    SYNTHETIC_ROM_DBG_CMD.write(SYNTHETIC_ROM_DBG_CMD_EXIT);
    loop {
        ::core::hint::spin_loop();
    }
}

pub fn flash_initialize() {}

pub fn flash_logical_page_size() -> usize {
    FLASH_PAGE_SIZE
}

pub fn flash_erase_sector_size() -> usize {
    FLASH_SECTOR_SIZE
}

pub fn flash_persistence_area() -> crate::core::flash::FlashPersistenceArea {
    let start = &raw const __registry_persistence_start as usize;
    let page_count = &raw const __registry_persistence_page_count as usize;
    crate::core::flash::FlashPersistenceArea { start, page_count }
}

pub fn flash_erase_sector(sector_addr: usize) -> crate::core::flash::FlashResult<()> {
    validate_persistence_sector_address(sector_addr)?;
    flash_erase_persistence_sector(sector_addr)
}

pub fn flash_write_page(page_addr: usize, page_buf: &[u8]) -> crate::core::flash::FlashResult<()> {
    validate_persistence_page(page_addr, page_buf)?;
    flash_write_persistence_page(page_addr, page_buf)
}

pub fn flash_flush_page(page_addr: usize) -> crate::core::flash::FlashResult<()> {
    validate_persistence_page_address(page_addr)?;
    Ok(())
}

pub fn flash_write_page_atomic(
    page_addr: usize,
    page_buf: &[u8],
) -> crate::core::flash::FlashResult<()> {
    // Invariant: RP2040 flash programming is not power-fail atomic at sector
    // level. This is the strongest board-local operation we expose; the
    // registry persistence layer obtains transaction safety through append-only
    // object writes and final CRC validation.
    flash_write_page(page_addr, page_buf)
}

fn validate_persistence_page(
    page_addr: usize,
    page_buf: &[u8],
) -> crate::core::flash::FlashResult<()> {
    if page_buf.len() != FLASH_PAGE_SIZE {
        return Err(crate::core::flash::FlashError::InvalidBufferSize);
    }
    validate_persistence_page_address(page_addr)
}

fn validate_persistence_page_address(page_addr: usize) -> crate::core::flash::FlashResult<()> {
    if page_addr % FLASH_PAGE_SIZE != 0 {
        return Err(crate::core::flash::FlashError::InvalidPageAddress);
    }
    let area = flash_persistence_area();
    let area_len = area
        .page_count
        .checked_mul(FLASH_PAGE_SIZE)
        .ok_or(crate::core::flash::FlashError::OutOfRange)?;
    let area_end = area
        .start
        .checked_add(area_len)
        .ok_or(crate::core::flash::FlashError::OutOfRange)?;
    let page_end = page_addr
        .checked_add(FLASH_PAGE_SIZE)
        .ok_or(crate::core::flash::FlashError::OutOfRange)?;
    if page_addr < area.start || page_end > area_end {
        return Err(crate::core::flash::FlashError::OutOfRange);
    }
    Ok(())
}

fn validate_persistence_sector_address(sector_addr: usize) -> crate::core::flash::FlashResult<()> {
    if sector_addr % FLASH_SECTOR_SIZE != 0 {
        return Err(crate::core::flash::FlashError::InvalidPageAddress);
    }
    let area = flash_persistence_area();
    let area_len = area
        .page_count
        .checked_mul(FLASH_PAGE_SIZE)
        .ok_or(crate::core::flash::FlashError::OutOfRange)?;
    let area_end = area
        .start
        .checked_add(area_len)
        .ok_or(crate::core::flash::FlashError::OutOfRange)?;
    let sector_end = sector_addr
        .checked_add(FLASH_SECTOR_SIZE)
        .ok_or(crate::core::flash::FlashError::OutOfRange)?;
    if sector_addr < area.start || sector_end > area_end {
        return Err(crate::core::flash::FlashError::OutOfRange);
    }
    Ok(())
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
// Invariant: section placement alone does not prevent inlining into XIP code.
// Keep the entire XIP-disabled interval in this SRAM-resident function.
#[inline(never)]
fn flash_write_persistence_page(
    page_addr: usize,
    page_buf: &[u8],
) -> crate::core::flash::FlashResult<()> {
    let flash_offs = page_addr
        .checked_sub(XIP_FLASH_BASE)
        .ok_or(crate::core::flash::FlashError::OutOfRange)?;
    if flash_offs > u32::MAX as usize {
        return Err(crate::core::flash::FlashError::OutOfRange);
    }

    let current = unsafe { ::core::slice::from_raw_parts(page_addr as *const u8, FLASH_PAGE_SIZE) };
    if current
        .iter()
        .zip(page_buf.iter())
        .any(|(old, new)| (*old & *new) != *new)
    {
        return Err(crate::core::flash::FlashError::CorruptedState);
    }

    // Invariant: all code after `flash_exit_xip()` and before
    // `flash_enter_cmd_xip()` must execute from SRAM or ROM, not from XIP.
    unsafe {
        let connect_internal_flash = rom_func_noarg(b'I', b'F')?;
        let flash_exit_xip = rom_func_noarg(b'E', b'X')?;
        let flash_flush_cache = rom_func_noarg(b'F', b'C')?;
        let flash_enter_cmd_xip = rom_func_noarg(b'C', b'X')?;
        let flash_range_program = rom_func_program()?;

        // No flash-resident exception path may run while XIP is unavailable.
        // Restore the caller's exact PRIMASK state after command mode ends.
        let primask = super::app_target_profile::interrupts_save_and_disable();
        connect_internal_flash();
        flash_exit_xip();
        flash_range_program(flash_offs as u32, page_buf.as_ptr(), FLASH_PAGE_SIZE as u32);
        flash_flush_cache();
        flash_enter_cmd_xip();
        super::app_target_profile::interrupts_restore(primask);
    }

    let programmed =
        unsafe { ::core::slice::from_raw_parts(page_addr as *const u8, page_buf.len()) };
    if programmed != page_buf {
        return Err(crate::core::flash::FlashError::VerifyFailed);
    }
    Ok(())
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
// Invariant: a caller in flash must not inline the XIP-disabled erase sequence.
#[inline(never)]
fn flash_erase_persistence_sector(sector_addr: usize) -> crate::core::flash::FlashResult<()> {
    let flash_offs = sector_addr
        .checked_sub(XIP_FLASH_BASE)
        .ok_or(crate::core::flash::FlashError::OutOfRange)?;
    if flash_offs > u32::MAX as usize {
        return Err(crate::core::flash::FlashError::OutOfRange);
    }

    // Invariant: erase is explicit and sector-sized. The persistent registry
    // allocator calls this only for sectors outside the latest valid BOSS graph.
    unsafe {
        let connect_internal_flash = rom_func_noarg(b'I', b'F')?;
        let flash_exit_xip = rom_func_noarg(b'E', b'X')?;
        let flash_flush_cache = rom_func_noarg(b'F', b'C')?;
        let flash_enter_cmd_xip = rom_func_noarg(b'C', b'X')?;
        let flash_range_erase = rom_func_erase()?;

        // Erase has the same XIP exclusion requirement as page programming.
        let primask = super::app_target_profile::interrupts_save_and_disable();
        connect_internal_flash();
        flash_exit_xip();
        flash_range_erase(
            flash_offs as u32,
            FLASH_SECTOR_SIZE as u32,
            FLASH_SECTOR_SIZE as u32,
            FLASH_ERASE_CMD_4K,
        );
        flash_flush_cache();
        flash_enter_cmd_xip();
        super::app_target_profile::interrupts_restore(primask);
    }

    let erased =
        unsafe { ::core::slice::from_raw_parts(sector_addr as *const u8, FLASH_SECTOR_SIZE) };
    if erased.iter().any(|byte| *byte != 0xFF) {
        return Err(crate::core::flash::FlashError::VerifyFailed);
    }
    Ok(())
}

type RomNoArgFn = unsafe extern "C" fn();
type RomFlashEraseFn = unsafe extern "C" fn(u32, u32, u32, u8);
type RomFlashProgramFn = unsafe extern "C" fn(u32, *const u8, u32);
type RomTableLookupFn = unsafe extern "C" fn(*const u16, u32) -> usize;

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
unsafe fn rom_func_noarg(first: u8, second: u8) -> crate::core::flash::FlashResult<RomNoArgFn> {
    let addr = rom_lookup(first, second)?;
    Ok(::core::mem::transmute::<usize, RomNoArgFn>(addr))
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
unsafe fn rom_func_erase() -> crate::core::flash::FlashResult<RomFlashEraseFn> {
    let addr = rom_lookup(b'R', b'E')?;
    Ok(::core::mem::transmute::<usize, RomFlashEraseFn>(addr))
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
unsafe fn rom_func_program() -> crate::core::flash::FlashResult<RomFlashProgramFn> {
    let addr = rom_lookup(b'R', b'P')?;
    Ok(::core::mem::transmute::<usize, RomFlashProgramFn>(addr))
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
unsafe fn rom_lookup(first: u8, second: u8) -> crate::core::flash::FlashResult<usize> {
    let table = (*(ROM_FUNC_TABLE_PTR_ADDR as *const u16)) as *const u16;
    let lookup_addr = (*(ROM_TABLE_LOOKUP_PTR_ADDR as *const u16)) as usize;
    let lookup = ::core::mem::transmute::<usize, RomTableLookupFn>(lookup_addr);
    let code = (first as u32) | ((second as u32) << 8);
    let addr = lookup(table, code);
    if addr == 0 {
        return Err(crate::core::flash::FlashError::Unsupported);
    }
    Ok(addr)
}

/// Enables the ROSC source used for development-only random sampling.
pub fn crypto_initialize() {
    // Invariant: initialize_xosc_12mhz() has selected XOSC, not ROSC, for the
    // CPU clock. Sampling a ROSC-clocked CPU's oscillator would be correlated.
    ROSC_CTRL.write((ROSC_CTRL.read() & !ROSC_CTRL_ENABLE_MASK) | ROSC_CTRL_ENABLE);
    ROSC_DORMANT.write(ROSC_WAKE);
}

/// Fills the caller's buffer directly with raw RP2040 ROSC RANDOMBIT samples.
///
/// # Warning: not cryptographically secure on physical hardware
/// RP2040 datasheet section 2.17.5 explicitly states that this source does not
/// meet security-system randomness requirements and can be compromised. This
/// backend is for development and functional tests, not production keys or
/// secure-channel freshness guarantees. It provides no entropy conditioning or
/// health certification; passing a crypto test does not establish either.
///
/// QEMU emulates the same register with guest entropy (or a seeded test stream).
/// No semihosting or deterministic software fallback is used by this driver.
pub fn crypto_fill_random(buf: &mut [u8]) -> crate::core::crypto::CryptoResult<()> {
    if buf.is_empty() {
        return Ok(());
    }

    // Invariant: an unavailable oscillator must fail rather than hang or be
    // replaced by predictable bytes. Ready status is not an entropy health test.
    let ready = (0..ROSC_READY_POLL_LIMIT)
        .any(|_| ROSC_STATUS.read() & ROSC_STATUS_READY == ROSC_STATUS_READY);
    if !ready {
        return Err(crate::core::crypto::CryptoError::EntropyUnavailable);
    }

    // Invariant: only the provided output buffer is written; there is no
    // staging array, heap allocation, or persistent software PRNG state.
    for byte in buf {
        let mut sample = 0u8;
        for _ in 0..8 {
            sample = (sample << 1) | (ROSC_RANDOMBIT.read() as u8 & 1);
        }
        *byte = sample;
    }
    Ok(())
}
