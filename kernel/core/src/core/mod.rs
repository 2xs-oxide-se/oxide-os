// Host tools can reuse pure protocol helpers without exercising bare-metal
// allocator initialization, crypto initialization, or trace output.
#[cfg_attr(feature = "host-test", allow(dead_code))]
mod allocator;
#[cfg_attr(feature = "host-test", allow(dead_code))]
pub mod crypto;
pub mod flash;
pub mod gp_sm;
pub mod isolation;
pub mod mpu;
#[cfg(all(not(test), not(feature = "host-test")))]
mod runtime;
pub mod scp03;
pub mod scp11;
pub mod scp11c;
#[cfg_attr(feature = "host-test", allow(dead_code))]
mod semihosting;
pub mod serial;
pub mod syscall;
pub mod target;
pub mod timer;

pub use allocator::{
    alloc, alloc_from_heap, dealloc, dealloc_from_heap, kernel_heap_debug_window,
    kernel_heap_metadata_debug_window, metadata_size_for_heap_size, partition_kernel_heap,
    reset_heap, HeapAllocatorState, KernelHeapPartition, ALLOCATION_GRANULE,
};

/// Overwrites sensitive memory with zeroes using volatile stores.
///
/// Invariant: callers invoke this at the last point where the bytes may be
/// observed. The compiler fence and volatile stores prevent dead-store
/// elimination from removing the scrub.
pub fn secure_zero(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { ::core::ptr::write_volatile(byte, 0) };
    }
    ::core::sync::atomic::compiler_fence(::core::sync::atomic::Ordering::SeqCst);
}

/// Raw-pointer form of [`secure_zero`] for allocator-owned regions.
///
/// # Safety
///
/// `ptr..ptr + len` must denote one live, writable allocation.
pub unsafe fn secure_zero_raw(ptr: *mut u8, len: usize) {
    let bytes = unsafe { ::core::slice::from_raw_parts_mut(ptr, len) };
    secure_zero(bytes);
}

#[cfg(any(oxide_se_trace_semihosting, oxide_se_trace_jtag))]
pub use semihosting::write_buffer;

#[cfg(not(any(oxide_se_trace_semihosting, oxide_se_trace_jtag)))]
#[doc(hidden)]
pub fn write_buffer(_buf: &[u8]) {}

#[doc(hidden)]
#[cfg(any(oxide_se_trace_semihosting, oxide_se_trace_jtag))]
pub fn log(args: ::core::fmt::Arguments<'_>) {
    semihosting::log(args);
}

#[doc(hidden)]
#[cfg(not(any(oxide_se_trace_semihosting, oxide_se_trace_jtag)))]
pub fn log(_args: ::core::fmt::Arguments<'_>) {}

#[macro_export]
macro_rules! consoleln {
    () => {
        $crate::core::write_buffer(b"\n")
    };
    ($($arg:tt)*) => {{
        $crate::core::log(::core::format_args!($($arg)*));
        $crate::core::write_buffer(b"\n");
    }};
}

#[cfg(all(not(test), not(feature = "host-test")))]
pub fn initialize() {
    runtime::initialize();
}

#[cfg(any(test, feature = "host-test"))]
pub fn initialize() {}

/// Enables the strongest kernel-stack lower-bound protection implemented by
/// the selected CPU profile. Profiles without hardware stack-limit registers
/// intentionally implement this hook as a no-op.
pub fn kernel_stack_overflow_protection() {
    target::kernel_stack_overflow_protection();
}

#[cfg(all(not(test), not(feature = "host-test")))]
pub fn shutdown(exit_code: i32) -> ! {
    runtime::core_shutdown(exit_code)
}

#[cfg(any(test, feature = "host-test"))]
pub fn shutdown(_exit_code: i32) -> ! {
    panic!("shutdown is not available in host-side unit tests")
}

#[cfg(all(not(test), not(feature = "host-test")))]
pub use runtime::abort;

#[cfg(any(test, feature = "host-test"))]
pub extern "C" fn abort() -> ! {
    panic!("abort is not available in host-side unit tests")
}

#[cfg(test)]
mod memory_tests {
    #[test]
    fn secure_zero_scrubs_the_complete_region() {
        let mut bytes = [0xa5; 37];
        super::secure_zero(&mut bytes);
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}
