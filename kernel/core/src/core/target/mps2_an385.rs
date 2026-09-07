/// CPU primitives selected at compile time; peripheral code stays in this board.
#[cfg(oxide_se_board_mps2_an385)]
pub(crate) use super::armv7m_profile as cpu;

use super::MmioRegister32;

pub const MEMORY_LAYOUT: crate::core::target::layout::TargetMemoryLayout =
    crate::core::target::layout::TargetMemoryLayout {
        name: "mps2-an385",
        ram_base: 0x2000_0000usize,
        ram_size: 32 * 1024usize,
        flash_base: 0x0000_0000usize,
        flash_size: 512 * 1024usize,
        kernel_heap_min_size: 7 * 1024usize,
        // Keep this synchronized with __STACK_SIZE_CPU0 in the board link scripts.
        // The boot ABI is placed immediately after the kernel stack.
        kernel_stack_size: 6 * 1024usize,
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

const UART0_BASE: usize = 0x4000_4000;
const UART_DATA: MmioRegister32 = MmioRegister32::new(UART0_BASE);
const UART_STATE: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x04);
const UART_CTRL: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x08);
const UART_BAUDDIV: MmioRegister32 = MmioRegister32::new(UART0_BASE + 0x10);

const STATE_TX_FULL: u32 = 1 << 0;
const STATE_RX_FULL: u32 = 1 << 1;
const CTRL_TX_ENABLE: u32 = 1 << 0;
const CTRL_RX_ENABLE: u32 = 1 << 1;

pub fn timer_clock_hz() -> u32 {
    16_000_000
}

pub fn initialize() {
    UART_BAUDDIV.write(139);
    UART_CTRL.write(CTRL_TX_ENABLE | CTRL_RX_ENABLE);
}

pub fn send_byte(byte: u8) {
    while UART_STATE.read() & STATE_TX_FULL != 0 {
        ::core::hint::spin_loop();
    }

    UART_DATA.write(byte as u32);
}

pub fn try_send_byte(byte: u8) -> bool {
    if UART_STATE.read() & STATE_TX_FULL != 0 {
        return false;
    }
    UART_DATA.write(byte as u32);
    true
}

pub fn receive_byte() -> u8 {
    while UART_STATE.read() & STATE_RX_FULL == 0 {
        ::core::hint::spin_loop();
    }

    UART_DATA.read() as u8
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
    // This board does not expose a target AES backend in core.
    // Callers are expected to rely on the software fallback for AES services.
}

pub fn crypto_fill_random(_buf: &mut [u8]) -> crate::core::crypto::CryptoResult<()> {
    Err(crate::core::crypto::CryptoError::EntropyUnavailable)
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
