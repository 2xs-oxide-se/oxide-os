// Target MPU alignment model:
// - no target MPU backend
// - MPU region programming is currently unsupported on this fallback path

pub fn initialize() {}

#[allow(dead_code)]
pub fn syscall_initialize() {}

#[allow(dead_code)]
pub fn enable_interrupts() {}

#[allow(dead_code)]
pub fn disable_interrupts() {}

#[allow(dead_code)]
pub fn timer_clock_hz() -> u32 {
    0
}

#[allow(dead_code)]
pub fn install_syscall_handler(
    _number: crate::core::syscall::SyscallNumber,
    _handler: crate::core::syscall::SyscallHandler,
) {
    panic!("syscall backend is only implemented for ARM targets")
}

#[allow(dead_code)]
pub fn request_syscall_thread_redirect(_pc: usize, _r0: usize, _r1: usize) {
    panic!("syscall redirect is only implemented for ARM targets")
}

#[allow(dead_code)]
pub fn syscall_table_debug_addr() -> usize {
    0
}

#[allow(dead_code)]
pub fn syscall_handler_debug_addr(_number: crate::core::syscall::SyscallNumber) -> usize {
    0
}

#[allow(dead_code)]
pub fn kernel_stack_guard_initialize() {}

#[allow(dead_code)]
pub fn kernel_stack_overflow_protection(_stack: crate::core::isolation::AppMemoryWindow) {}

#[allow(dead_code)]
pub fn app_stack_overflow_protection(_stack: Option<crate::core::isolation::AppMemoryWindow>) {}

#[allow(dead_code)]
pub fn kernel_stack_guard_test_touch() {
    loop {
        ::core::hint::spin_loop();
    }
}

#[allow(dead_code)]
pub fn kernel_ram_execute_never_test_touch() -> bool {
    false
}

#[allow(dead_code)]
pub const MEMORY_LAYOUT: crate::core::target::layout::TargetMemoryLayout =
    crate::core::target::layout::TargetMemoryLayout {
        name: "generic",
        ram_base: 0,
        ram_size: 0,
        flash_base: 0,
        flash_size: 0,
        kernel_heap_min_size: 0,
        kernel_stack_size: 0,
    };

#[allow(dead_code)]
pub fn run_isolated_app(
    _entry_pc: usize,
    _app_gp: usize,
    _arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
    _stack_top: usize,
) -> Option<crate::core::isolation::AppReturnRegisters> {
    None
}

#[allow(dead_code)]
pub fn isolated_app_gate_region() -> Option<crate::core::target::AppGateRegion> {
    None
}

#[allow(dead_code)]
pub fn kernel_stack_guard_window() -> Option<(usize, usize)> {
    None
}

#[allow(dead_code)]
pub fn boot_abi_region() -> Option<crate::core::target::BootAbiRegion> {
    None
}

#[allow(dead_code)]
pub fn last_mem_manage_fault() -> Option<crate::core::isolation::MemoryFaultInfo> {
    None
}

#[allow(dead_code)]
pub fn mpu_enable() -> crate::core::mpu::MpuResult<()> {
    Err(crate::core::mpu::MpuError::Unsupported)
}

#[allow(dead_code)]
pub fn mpu_disable() -> crate::core::mpu::MpuResult<()> {
    Err(crate::core::mpu::MpuError::Unsupported)
}

#[allow(dead_code)]
pub fn mpu_set_region(
    _region: crate::core::mpu::MpuRegion,
    _config: &crate::core::mpu::MpuRegionConfig,
) -> crate::core::mpu::MpuResult<()> {
    Err(crate::core::mpu::MpuError::Unsupported)
}

#[allow(dead_code)]
pub fn mpu_unset_region(_region: crate::core::mpu::MpuRegion) -> crate::core::mpu::MpuResult<()> {
    Err(crate::core::mpu::MpuError::Unsupported)
}

#[allow(dead_code)]
pub fn protect_kernel_nx(_enabled: bool) {}

#[allow(dead_code)]
#[inline(always)]
pub unsafe fn mpu_set_region_executable_unchecked(
    _region: crate::core::mpu::MpuRegion,
    _executable: bool,
) {
}

pub fn send_byte(_byte: u8) {}

pub fn try_send_byte(byte: u8) -> bool {
    send_byte(byte);
    true
}

pub fn debug_write_byte(byte: u8) {
    send_byte(byte);
}

pub fn receive_byte() -> u8 {
    loop {
        ::core::hint::spin_loop();
    }
}

pub fn shutdown(_exit_code: i32) -> ! {
    crate::core::serial::write_line("tbd");
    loop {
        ::core::hint::spin_loop();
    }
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

pub fn crypto_initialize() {}

#[cfg(feature = "host-test")]
pub fn crypto_fill_random(buf: &mut [u8]) -> crate::core::crypto::CryptoResult<()> {
    // Host-side firmware tests need a deterministic entropy source so the
    // software P-256 path can exercise SCP11c establishment without hardware.
    // Invariant: this path exists only for `host-test` and must never be used
    // as production entropy.
    for (index, byte) in buf.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_add(1);
    }
    Ok(())
}

#[cfg(not(feature = "host-test"))]
pub fn crypto_fill_random(_buf: &mut [u8]) -> crate::core::crypto::CryptoResult<()> {
    Err(crate::core::crypto::CryptoError::EntropyUnavailable)
}

pub fn crypto_aes_cbc_encrypt_in_place(
    _key: &crate::core::crypto::AesKey,
    _iv: &[u8; crate::core::crypto::AES_BLOCK_SIZE],
    _buf: &mut [u8],
) -> crate::core::crypto::CryptoResult<()> {
    Err(crate::core::crypto::CryptoError::Unsupported)
}

pub fn crypto_aes_cbc_decrypt_in_place(
    _key: &crate::core::crypto::AesKey,
    _iv: &[u8; crate::core::crypto::AES_BLOCK_SIZE],
    _buf: &mut [u8],
) -> crate::core::crypto::CryptoResult<()> {
    Err(crate::core::crypto::CryptoError::Unsupported)
}

pub fn crypto_aes_cmac(
    _key: &crate::core::crypto::AesKey,
    _input: &[u8],
    _out: &mut [u8; crate::core::crypto::AES_CMAC_SIZE],
) -> crate::core::crypto::CryptoResult<()> {
    Err(crate::core::crypto::CryptoError::Unsupported)
}

pub fn crypto_scp03_kdf(
    _key: &crate::core::crypto::AesKey,
    _derivation_constant: u8,
    _context: &[u8],
    _out: &mut [u8],
) -> crate::core::crypto::CryptoResult<()> {
    Err(crate::core::crypto::CryptoError::Unsupported)
}

pub fn crypto_p256_generate_keypair(
    _private_out: &mut [u8],
    _public_out: &mut [u8],
) -> crate::core::crypto::CryptoResult<()> {
    Err(crate::core::crypto::CryptoError::Unsupported)
}

pub fn crypto_p256_ecdh(
    _private_key: &[u8],
    _peer_public: &[u8],
    _out: &mut [u8],
) -> crate::core::crypto::CryptoResult<()> {
    Err(crate::core::crypto::CryptoError::Unsupported)
}
