use ::core::panic::PanicInfo;
use ::core::ptr::{copy_nonoverlapping, write_bytes};
use ::core::sync::atomic::{AtomicBool, Ordering};

static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn initialize() {
    if INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    INITIALIZED.store(true, Ordering::Release);

    crate::core::target::initialize();
    initialize_runtime_services();
    crate::core::target::enable_interrupts();
}

pub fn core_shutdown(exit_code: i32) -> ! {
    crate::core::target::shutdown(exit_code)
}

fn initialize_runtime_services() {
    crate::core::allocator::initialize();
    crate::core::crypto::initialize();
    crate::core::syscall::initialize();
    crate::core::target::kernel_stack_guard_initialize();
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    crate::consoleln!("panic: {info}");
    core_shutdown(1)
}

#[unsafe(no_mangle)]
pub extern "C" fn __aeabi_unwind_cpp_pr0() {}

#[unsafe(no_mangle)]
pub extern "C" fn __aeabi_unwind_cpp_pr1() {}

#[unsafe(no_mangle)]
pub extern "C" fn abort() -> ! {
    core_shutdown(1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    copy_nonoverlapping(src, dest, len);
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut u8, byte: i32, len: usize) -> *mut u8 {
    write_bytes(dest, byte as u8, len);
    dest
}
