//! Documentation-only template for adding a new Oxide SE board target.
//!
//! This file is intentionally not referenced from `target/mod.rs` and is never
//! compiled. Copy it to `kernel/core/src/core/target/<board_name>.rs`, replace
//! the placeholders, then wire the copied module into `target/mod.rs`,
//! `kernel/core/build.rs`, and the BoardCatalog in `xtask/src/lib.rs`.

use super::MmioRegister32;

/// Select an existing CPU profile, not a copy of its MPU/exception implementation.
/// Use armv6m_profile for Cortex-M0+, armv7m_profile for Cortex-M3/M4,
/// or armv8m_profile for Cortex-M33. Keep this alias consistent with the
/// oxide_se_target_armvXm cfg emitted by kernel/core/build.rs for the board.
/// target/mod.rs selects this board's cpu alias as app_target_profile.
#[cfg(oxide_se_board_replace_me)]
pub(crate) use super::armv8m_profile as cpu;

/// Static memory contract for the target board.
///
/// The kernel uses this layout to derive its heap, stack, boot ABI, MPU guard
/// windows, xtask layout checks, and generated board linker wrappers.
pub const MEMORY_LAYOUT: crate::core::target::layout::TargetMemoryLayout =
    crate::core::target::layout::TargetMemoryLayout {
        name: "<board-name>",
        ram_base: 0x0000_0000usize,
        ram_size: 0usize,
        flash_base: 0x0000_0000usize,
        flash_size: 0usize,
        kernel_heap_min_size: 6 * 1024usize,
        // Invariant: xtask copies this value into __STACK_SIZE_CPU0 when it
        // generates the native and bootable board linker wrappers.
        // The boot ABI starts immediately after this stack.
        kernel_stack_size: 0usize,
    };

// Invariant: target/mod.rs::mpu_region_policy() must match the selected CPU.
// v6-M/v7-M require power-of-two sizes and size-aligned bases. v8-M accepts
// 32-byte-aligned bases and sizes. Stack and RAM-XN windows come from the
// board layout through the target facade, never board names in the CPU code.

const UART_BASE: usize = 0x0000_0000;
const UART_STATUS: MmioRegister32 = MmioRegister32::new(UART_BASE);
const UART_DATA: MmioRegister32 = MmioRegister32::new(UART_BASE + 0x04);

const UART_STATUS_TX_READY: u32 = 1 << 0;
const UART_STATUS_RX_READY: u32 = 1 << 1;

/// Initializes the board services needed before the kernel APDU loop starts.
///
/// Configure clocks, pins, UART, and any target-local state required by the
/// other functions in this module. Keep this function small and deterministic:
/// the kernel calls it once during early boot.
pub fn initialize() {
    // Invariant: after this function returns, `send_byte()` and
    // `receive_byte()` must be safe to call from the kernel APDU transport.
    let _ = UART_STATUS.read();
}

/// Returns the core clock consumed by architectural SysTick, in hertz.
///
/// Keep this value synchronized with the clock tree established by
/// `initialize()`. An incorrect value changes every requested kernel period.
pub fn timer_clock_hz() -> u32 {
    0
}

/// Sends one byte on the kernel APDU transport.
///
/// This function may block until the byte can be accepted by the target UART.
/// It must not allocate and must not depend on interrupts unless the board
/// initialization enables them before the APDU loop starts.
pub fn send_byte(byte: u8) {
    while UART_STATUS.read() & UART_STATUS_TX_READY == 0 {
        ::core::hint::spin_loop();
    }

    UART_DATA.write(byte as u32);
}

/// Attempts to enqueue one byte without blocking; required by timer ISRs.
pub fn try_send_byte(_byte: u8) -> bool {
    false
}

/// Receives one byte from the kernel APDU transport.
///
/// This function may block until a byte is available. The T=0/APDU layer uses
/// it as a byte stream, so it must return bytes exactly in receive order.
pub fn receive_byte() -> u8 {
    while UART_STATUS.read() & UART_STATUS_RX_READY == 0 {
        ::core::hint::spin_loop();
    }

    UART_DATA.read() as u8
}

/// Writes one diagnostic byte for debug traces.
///
/// This path is separate from the APDU transport. QEMU ports often implement
/// it with semihosting; real boards may route it to a debug UART, ITM, or a
/// no-op if no diagnostic channel exists.
pub fn debug_write_byte(byte: u8) {
    let _ = byte;
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

/// Returns the logical flash page size exposed to the kernel persistence layer.
///
/// Use the smallest page/granule that the backend can program from 1 to 0
/// without erasing.
pub fn flash_logical_page_size() -> usize {
    2048
}

/// Returns the target flash erase-sector size.
///
/// This may be larger than `flash_logical_page_size()`. For example, a board
/// can expose 256-byte programmable pages while requiring 4 KiB sector erase.
pub fn flash_erase_sector_size() -> usize {
    flash_logical_page_size()
}

/// Erases one flash sector in the persistence area.
///
/// `sector_addr` is an absolute flash address aligned to
/// `flash_erase_sector_size()`. The registry writer calls this only when every
/// page in the sector is obsolete or erased.
pub fn flash_erase_sector(sector_addr: usize) -> crate::core::flash::FlashResult<()> {
    let _ = sector_addr;
    Err(crate::core::flash::FlashError::Unsupported)
}

/// Stages or writes one logical flash page.
///
/// `page_addr` is an absolute address in the target flash address space and
/// `page_buf.len()` is expected to match `flash_logical_page_size()`.
/// This must only program bits from 1 to 0; it must not erase implicitly.
pub fn flash_write_page(page_addr: usize, page_buf: &[u8]) -> crate::core::flash::FlashResult<()> {
    let _ = (page_addr, page_buf);
    Err(crate::core::flash::FlashError::Unsupported)
}

/// Flushes a page previously passed to `flash_write_page()`.
///
/// Backends that write synchronously can return `Ok(())` here once
/// `flash_write_page()` succeeds.
pub fn flash_flush_page(page_addr: usize) -> crate::core::flash::FlashResult<()> {
    let _ = page_addr;
    Err(crate::core::flash::FlashError::Unsupported)
}

/// Writes one logical flash page with the strongest atomicity the board offers.
///
/// The kernel persistence layer calls this when it needs the page update to be
/// either fully committed or detectably absent after reset.
pub fn flash_write_page_atomic(
    page_addr: usize,
    page_buf: &[u8],
) -> crate::core::flash::FlashResult<()> {
    let _ = (page_addr, page_buf);
    Err(crate::core::flash::FlashError::Unsupported)
}

/// Initializes target cryptographic peripherals.
///
/// Use this for RNG, AES, ECC, or accelerator clocks. It is skipped under the
/// QEMU execution environment when `target/mod.rs` deliberately routes entropy
/// through semihosting.
pub fn crypto_initialize() {}

/// Fills `buf` with target-provided random bytes.
///
/// Return `EntropyUnavailable` if the target has no usable hardware entropy
/// source. Under QEMU, `target/mod.rs` currently substitutes host randomness
/// before this function is called.
pub fn crypto_fill_random(buf: &mut [u8]) -> crate::core::crypto::CryptoResult<()> {
    let _ = buf;
    Err(crate::core::crypto::CryptoError::EntropyUnavailable)
}
