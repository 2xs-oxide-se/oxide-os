/// CPU primitives selected at compile time; peripheral code stays in this board.
#[cfg(oxide_se_board_raspi_pico2)]
pub(crate) use super::armv8m_profile as cpu;

use super::MmioRegister32;

/// Static memory contract for the Pico2 board.
///
/// The kernel uses this layout to derive its heap, stack, boot ABI, MPU guard
/// windows, xtask layout checks, and generated board linker wrappers.
pub const MEMORY_LAYOUT: crate::core::target::layout::TargetMemoryLayout =
    crate::core::target::layout::TargetMemoryLayout {
        name: "raspi-pico2",
        ram_base: 0x2000_0000usize,
        ram_size: 520 * 1024usize,
        flash_base: 0x1000_0000usize,
        flash_size: 4 * 1024 * 1024usize,
        kernel_heap_min_size: 16 * 1024usize,
        kernel_stack_size: 8 * 1024usize,
    };

unsafe extern "C" {
    static __registry_persistence_start: u8;
    static __registry_persistence_page_count: u8;
}

const IO_BANK0_BASE: usize = 0x4002_8000;
const IO_BANK0_GPIO0_CTRL: MmioRegister32 = MmioRegister32::new(IO_BANK0_BASE + 0x04);
const IO_BANK0_GPIO1_CTRL: MmioRegister32 = MmioRegister32::new(IO_BANK0_BASE + 0x0c);
const GPIO_FUNCSEL_UART: u32 = 2;

const PADS_BANK0_BASE: usize = 0x4003_8000;
const PADS_BANK0_GPIO0: MmioRegister32 = MmioRegister32::new(PADS_BANK0_BASE + 0x04);
const PADS_BANK0_GPIO1: MmioRegister32 = MmioRegister32::new(PADS_BANK0_BASE + 0x08);

const RESETS_BASE: usize = 0x4002_0000;
const RESETS_RESET: usize = RESETS_BASE;
const RESETS_RESET_DONE: MmioRegister32 = MmioRegister32::new(RESETS_BASE + 0x08);

const REG_ALIAS_SET_BITS: usize = 0x2000;
const REG_ALIAS_CLR_BITS: usize = 0x3000;

const RESETS_RESET_SET_ALIAS: MmioRegister32 =
    MmioRegister32::new(RESETS_RESET + REG_ALIAS_SET_BITS);
const RESETS_RESET_CLR_ALIAS: MmioRegister32 =
    MmioRegister32::new(RESETS_RESET + REG_ALIAS_CLR_BITS);

const RESETS_UART0_BIT: u32 = 1 << 26;
const RESETS_PLL_BIT: u32 = 1 << 14;

const CLOCKS_BASE: usize = 0x4001_0000;
const CLOCKS_CLK_SYS_CTRL: MmioRegister32 = MmioRegister32::new(CLOCKS_BASE + 0x3c);
const CLOCKS_CLK_SYS_SELECTED: MmioRegister32 = MmioRegister32::new(CLOCKS_BASE + 0x44);
const CLOCKS_CLK_PERI_CTRL: MmioRegister32 = MmioRegister32::new(CLOCKS_BASE + 0x48);

const PLL_SYS_BASE: usize = 0x4005_0000;
const PLL_SYS_CS: MmioRegister32 = MmioRegister32::new(PLL_SYS_BASE);
const PLL_SYS_FBDIV_INT: MmioRegister32 = MmioRegister32::new(PLL_SYS_BASE + 0x08);
const PLL_SYS_PWR: MmioRegister32 = MmioRegister32::new(PLL_SYS_BASE + 0x04);
const PLL_SYS_PRIM: MmioRegister32 = MmioRegister32::new(PLL_SYS_BASE + 0x0c);

const PLL_PWR_PD_BITS: u32 = 1 << 0;
const PLL_PWR_VCOPD_BITS: u32 = 1 << 5;
const PLL_CS_LOCK_BITS: u32 = 1 << 31;
const PLL_PWR_POSTDIVPD_BITS: u32 = 1 << 3;

const PLL_PRIM_POSTDIV1_LSB: u32 = 16;
const PLL_PRIM_POSTDIV2_LSB: u32 = 12;

const XOSC_BASE: usize = 0x4004_8000;
const XOSC_CTRL: MmioRegister32 = MmioRegister32::new(XOSC_BASE);
const XOSC_STATUS: MmioRegister32 = MmioRegister32::new(XOSC_BASE + 0x04);
const XOSC_STARTUP: MmioRegister32 = MmioRegister32::new(XOSC_BASE + 0x0c);

const XOSC_CTRL_FREQ_RANGE_VALUE_1_15MHZ: u32 = 0xaa0;
const XOSC_CTRL_ENABLE: u32 = 0xfab << 12;
const XOSC_STATUS_STABLE_BITS: u32 = 1 << 31;
const XOSC_HZ: u32 = 12000000;
const STARTUP_DELAY: u32 = ((XOSC_HZ / 1000) + 128) / 256; // ~47

const UART0_BASE: usize = 0x4007_0000;
const UART0_UARTDR: MmioRegister32 = MmioRegister32::new(UART0_BASE);
const UART0_UARTFR: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x18);
const UART0_UARTIBRD: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x24);
const UART0_UARTFBRD: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x28);
const UART0_UARTLCR_H: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x2c);
const UART0_UARTCR: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x30);

// RP2350 UARTFR: TXFF is bit 5; bit 6 is RXFF, not transmit backpressure.
const UART_UARTFR_TXFF_BITS: u32 = 1 << 5;
const UART_UARTFR_RXFE_BITS: u32 = 1 << 4;
const UART_UARTFR_BUSY_BITS: u32 = 1 << 3;

const UART_UARTCR_TXE_BITS: u32 = 1 << 8;
const UART_UARTCR_RXE_BITS: u32 = 1 << 9;
const UART_UARTCR_UARTEN_BITS: u32 = 0x1;

const XIP_FLASH_BASE: usize = 0x1000_0000;

const FLASH_PAGE_SIZE: usize = 1 << 8;
const FLASH_SECTOR_SIZE: usize = 1 << 12;

const BOOTROM_FUNC_TABLE_OFFSET: usize = 0x14;
const BOOTROM_WELL_KNOWN_PTR_SIZE: usize = 2;
const BOOTROM_TABLE_LOOKUP: usize = BOOTROM_FUNC_TABLE_OFFSET + BOOTROM_WELL_KNOWN_PTR_SIZE;

const RT_FLAG_FUNC_ARM_SEC: u32 = 0x0004;

const BAUD_RATE: u32 = 115200;
const CLK_PERI_HZ: u32 = 150000000;

pub fn timer_clock_hz() -> u32 {
    CLK_PERI_HZ
}

/// Initializes the board services needed before the kernel APDU loop starts.
///
/// Configure clocks, pins, UART, and any target-local state required by the
/// other functions in this module. Keep this function small and deterministic:
/// the kernel calls it once during early boot.
pub fn initialize() {
    // Invariant: after this function returns, `send_byte()` and
    // `receive_byte()` must be safe to call from the kernel APDU transport.

    clk_init();

    uart_reset();
    uart_unreset();

    uart_set_baudrate(BAUD_RATE);

    uart_init();
}

fn clk_init() {
    CLOCKS_CLK_SYS_CTRL.write(CLOCKS_CLK_SYS_CTRL.read() & !1);
    while (CLOCKS_CLK_SYS_SELECTED.read() & (1 << 0)) == 0 {
        ::core::hint::spin_loop();
    }

    xosc_init();

    pll_init();

    CLOCKS_CLK_SYS_CTRL.write(CLOCKS_CLK_SYS_CTRL.read() & !(0x7 << 5));
    CLOCKS_CLK_SYS_CTRL.write(CLOCKS_CLK_SYS_CTRL.read() | 1);
    while (CLOCKS_CLK_SYS_SELECTED.read() & (1 << 1)) == 0 {
        ::core::hint::spin_loop();
    }

    CLOCKS_CLK_PERI_CTRL.write((0 << 5) | (1 << 11));
}

fn xosc_init() {
    XOSC_CTRL.write(XOSC_CTRL_FREQ_RANGE_VALUE_1_15MHZ);
    XOSC_STARTUP.write(STARTUP_DELAY);
    XOSC_CTRL.write(XOSC_CTRL.read() | XOSC_CTRL_ENABLE);

    while (XOSC_STATUS.read() & XOSC_STATUS_STABLE_BITS) == 0 {
        ::core::hint::spin_loop();
    }
}

fn pll_init() {
    RESETS_RESET_SET_ALIAS.write(RESETS_PLL_BIT);
    RESETS_RESET_CLR_ALIAS.write(RESETS_PLL_BIT);
    while (RESETS_RESET_DONE.read() & RESETS_PLL_BIT) == 0 {
        ::core::hint::spin_loop();
    }

    PLL_SYS_CS.write(1);
    PLL_SYS_FBDIV_INT.write(125);

    PLL_SYS_PWR.write(PLL_SYS_PWR.read() & !(PLL_PWR_PD_BITS | PLL_PWR_VCOPD_BITS));
    while (PLL_SYS_CS.read() & PLL_CS_LOCK_BITS) == 0 {
        ::core::hint::spin_loop();
    }

    PLL_SYS_PRIM.write((5 << PLL_PRIM_POSTDIV1_LSB) | (2 << PLL_PRIM_POSTDIV2_LSB));
    PLL_SYS_PWR.write(PLL_SYS_PWR.read() & !PLL_PWR_POSTDIVPD_BITS);
}

fn get_clk_sys() -> u32 {
    return CLK_PERI_HZ;
}

fn uart_init() {
    UART0_UARTLCR_H.write(0x70);
    UART0_UARTCR.write(UART_UARTCR_UARTEN_BITS | UART_UARTCR_TXE_BITS | UART_UARTCR_RXE_BITS); // 0x301

    IO_BANK0_GPIO0_CTRL.write(GPIO_FUNCSEL_UART);
    PADS_BANK0_GPIO0.write(0x40);

    IO_BANK0_GPIO1_CTRL.write(GPIO_FUNCSEL_UART);
    PADS_BANK0_GPIO1.write(0x40);
}

fn uart_set_baudrate(baud_rate: u32) {
    let baud_rate_div: u32 = ((8 * get_clk_sys()) / baud_rate) + 1;
    let mut baud_ibrd: u32 = baud_rate_div >> 7;
    let baud_fbrd;

    if baud_ibrd == 0 {
        baud_ibrd = 1;
        baud_fbrd = 0;
    } else if baud_ibrd >= 65535 {
        baud_ibrd = 65535;
        baud_fbrd = 0;
    } else {
        baud_fbrd = (baud_rate_div & 0x7f) >> 1;
    }

    UART0_UARTIBRD.write(baud_ibrd);
    UART0_UARTFBRD.write(baud_fbrd);
}

fn uart_reset() {
    RESETS_RESET_SET_ALIAS.write(RESETS_UART0_BIT);
}

fn uart_unreset() {
    RESETS_RESET_CLR_ALIAS.write(RESETS_UART0_BIT);

    while (RESETS_RESET_DONE.read() & RESETS_UART0_BIT) == 0 {
        ::core::hint::spin_loop();
    }
}

fn uart_is_writable() -> bool {
    (UART0_UARTFR.read() & UART_UARTFR_TXFF_BITS) == 0
}

fn uart_is_readable() -> bool {
    (UART0_UARTFR.read() & UART_UARTFR_RXFE_BITS) == 0
}

// Invariant: only the synchronous kernel UART path calls send_byte. Drain the
// transmitter before every 32nd byte, without imposing an artificial delay.
static mut PACED_BYTE_COUNT: u8 = 0;
/// Waits for both the FIFO and shift register to finish transmitting.
/// TXFE alone is insufficient: the last byte can still be on the wire.
fn uart_wait_tx_idle() {
    // Invariant: no concurrent writer refills UARTDR while draining it.
    // BUSY clears only after the final stop bit is sent.
    while UART0_UARTFR.read() & UART_UARTFR_BUSY_BITS != 0 {
        ::core::hint::spin_loop();
    }
}

/// Sends one byte on the kernel APDU transport.
///
/// This function may block until the byte can be accepted by the target UART.
/// It must not allocate and must not depend on interrupts unless the board
/// initialization enables them before the APDU loop starts.
pub fn send_byte(byte: u8) {
    while !uart_is_writable() {
        ::core::hint::spin_loop();
    }
    unsafe {
        PACED_BYTE_COUNT += 1;
        if PACED_BYTE_COUNT == 32 {
            PACED_BYTE_COUNT = 0;
            uart_wait_tx_idle();
        }
    }
    UART0_UARTDR.write(byte.into());
}

pub fn try_send_byte(byte: u8) -> bool {
    if !uart_is_writable() {
        return false;
    }
    UART0_UARTDR.write(byte.into());
    true
}

/// Receives one byte from the kernel APDU transport.
///
/// This function may block until a byte is available. The T=0/APDU layer uses
/// it as a byte stream, so it must return bytes exactly in receive order.
pub fn receive_byte() -> u8 {
    while !uart_is_readable() {
        ::core::hint::spin_loop();
    }

    UART0_UARTDR.read() as u8
}

#[repr(C)]
struct SemihostArgs {
    fd: u32,
    buf: *const u8,
    len: u32,
}

const SYS_WRITE: u32 = 0x05;
fn semihost_write(buf: &[u8]) {
    let args = SemihostArgs {
        fd: 1,
        buf: buf.as_ptr(),
        len: buf.len() as u32,
    };

    unsafe {
        core::arch::asm!(
            "bkpt #0xab",
            in("r0") SYS_WRITE,
            in("r1") &args,
            options(nostack, preserves_flags),
        );
    }
}

fn semihost_write_byte(byte: u8) {
    let buf = [byte];
    semihost_write(&buf);
}

/// Writes one diagnostic byte for debug traces.
///
/// This path is separate from the APDU transport. QEMU ports often implement
/// it with semihosting; real boards may route it to a debug UART, ITM, or a
/// no-op if no diagnostic channel exists.
pub fn debug_write_byte(byte: u8) {
    semihost_write_byte(byte);
}

/// Terminates the board or QEMU process with the provided exit code.
///
/// QEMU targets should use the platform-specific exit mechanism so xtask can
/// observe success/failure. Hardware targets can spin forever after reporting
/// the error through `debug_write_byte()`.
pub fn shutdown(exit_code: i32) -> ! {
    let _ = exit_code;
    loop {
        ::core::hint::spin_loop();
    }
}

/// Initializes the target flash backend.
///
/// Return successfully even when flash persistence is unsupported; unsupported
/// operations are reported by the write/flush functions below.
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
    // Invariant: RP2350 flash programming is not power-fail atomic at sector
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
    all(not(test), oxide_se_board_raspi_pico2),
    unsafe(link_section = ".critical.kernel.fct")
)]
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
        let flash_range_program = rom_func_program()?;

        // RP2350 ROM temporarily suspends XIP inside these calls. Keep every
        // flash-resident exception path masked until the ROM restored XIP.
        let primask = super::app_target_profile::interrupts_save_and_disable();
        connect_internal_flash();
        flash_exit_xip();
        flash_range_program(flash_offs as u32, page_buf.as_ptr(), FLASH_PAGE_SIZE as u32);
        flash_flush_cache();

        // Invariant: in RP2350 rom_flash_exit_xip() routine leaves basic XIP enabled
        // thus it is redundant to use flash_enter_cmd_xip() or flash_enable_xip_via_boot2()
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
    all(not(test), oxide_se_board_raspi_pico2),
    unsafe(link_section = ".critical.kernel.fct")
)]
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
        let flash_range_erase = rom_func_erase()?;

        let primask = super::app_target_profile::interrupts_save_and_disable();
        connect_internal_flash();
        flash_exit_xip();
        flash_range_erase(flash_offs as u32, FLASH_SECTOR_SIZE as u32, 0, 0);
        flash_flush_cache();
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
type RomTableLookupFn = unsafe extern "C" fn(u32, u32) -> usize;

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico2),
    unsafe(link_section = ".critical.kernel.fct")
)]
unsafe fn rom_func_noarg(first: u8, second: u8) -> crate::core::flash::FlashResult<RomNoArgFn> {
    let addr = rom_lookup(first, second)?;
    Ok(::core::mem::transmute::<usize, RomNoArgFn>(addr))
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico2),
    unsafe(link_section = ".critical.kernel.fct")
)]
unsafe fn rom_func_erase() -> crate::core::flash::FlashResult<RomFlashEraseFn> {
    let addr = rom_lookup(b'R', b'E')?;
    Ok(::core::mem::transmute::<usize, RomFlashEraseFn>(addr))
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico2),
    unsafe(link_section = ".critical.kernel.fct")
)]
unsafe fn rom_func_program() -> crate::core::flash::FlashResult<RomFlashProgramFn> {
    let addr = rom_lookup(b'R', b'P')?;
    Ok(::core::mem::transmute::<usize, RomFlashProgramFn>(addr))
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico2),
    unsafe(link_section = ".critical.kernel.fct")
)]
unsafe fn rom_lookup(first: u8, second: u8) -> crate::core::flash::FlashResult<usize> {
    let lookup_addr = (*(BOOTROM_TABLE_LOOKUP as *const u16)) as usize;
    let lookup = ::core::mem::transmute::<usize, RomTableLookupFn>(lookup_addr);
    let code = (first as u32) | ((second as u32) << 8);
    let addr = lookup(code, RT_FLAG_FUNC_ARM_SEC);
    if addr == 0 {
        return Err(crate::core::flash::FlashError::Unsupported);
    }
    Ok(addr)
}

/// Initializes target cryptographic peripherals.
///
/// Use this for RNG, AES, ECC, or accelerator clocks. It is skipped under the
/// QEMU execution environment when `target/mod.rs` deliberately routes entropy
/// through semihosting.
pub fn crypto_initialize() {
    #[cfg(oxide_se_board_raspi_pico2)]
    super::raspi_pico2_random::initialize();
}

/// Fills `buf` with target-provided random bytes.
///
/// Return `EntropyUnavailable` if the target has no usable hardware entropy
/// source. Under QEMU, `target/mod.rs` currently substitutes host randomness
/// before this function is called.
pub fn crypto_fill_random(buf: &mut [u8]) -> crate::core::crypto::CryptoResult<()> {
    #[cfg(oxide_se_board_raspi_pico2)]
    {
        super::raspi_pico2_random::fill(buf)
    }
    #[cfg(not(oxide_se_board_raspi_pico2))]
    {
        let _ = buf;
        Err(crate::core::crypto::CryptoError::EntropyUnavailable)
    }
}
