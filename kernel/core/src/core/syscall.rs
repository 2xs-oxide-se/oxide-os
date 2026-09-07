pub type SyscallNumber = rustlet_runtime::syscall_abi::SyscallNumber;
pub type SyscallWord = rustlet_runtime::syscall_abi::SyscallWord;
use core::alloc::Layout;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

pub type SyscallHandler =
    unsafe extern "C" fn(SyscallWord, SyscallWord, SyscallWord, SyscallWord) -> SyscallWord;

static CURRENT_APP_ALLOCATOR: AtomicPtr<crate::core::HeapAllocatorState> =
    AtomicPtr::new(null_mut());

#[derive(Clone, Copy)]
pub struct SyscallBinding {
    pub number: SyscallNumber,
    pub handler: SyscallHandler,
}

pub fn initialize() {
    crate::core::target::syscall_initialize();
    install_bindings(&BUILTIN_BINDINGS);
}

pub fn install_handler(number: SyscallNumber, handler: SyscallHandler) {
    crate::core::target::install_syscall_handler(number, handler);
}

pub fn install_bindings(bindings: &[SyscallBinding]) {
    for binding in bindings {
        install_handler(binding.number, binding.handler);
    }
}

pub fn request_thread_redirect(pc: usize, r0: SyscallWord, r1: SyscallWord) {
    crate::core::target::request_syscall_thread_redirect(pc, r0, r1);
}

pub fn set_current_app_allocator(state: *mut crate::core::HeapAllocatorState) {
    CURRENT_APP_ALLOCATOR.store(state, Ordering::Release);
}

pub fn clear_current_app_allocator() {
    CURRENT_APP_ALLOCATOR.store(null_mut(), Ordering::Release);
}

pub fn syscall_table_debug_addr() -> usize {
    crate::core::target::syscall_table_debug_addr()
}

pub fn syscall_handler_debug_addr(number: SyscallNumber) -> usize {
    crate::core::target::syscall_handler_debug_addr(number)
}

unsafe extern "C" fn enter_app_handler(
    _arg0: SyscallWord,
    _arg1: SyscallWord,
    _arg2: SyscallWord,
    _arg3: SyscallWord,
) -> SyscallWord {
    0
}

unsafe extern "C" fn alloc_handler(
    arg0: SyscallWord,
    arg1: SyscallWord,
    _arg2: SyscallWord,
    _arg3: SyscallWord,
) -> SyscallWord {
    let Some((allocator, layout)) = active_allocator_and_layout(arg0, arg1) else {
        return 0;
    };
    // Invariant: the active allocator pointer is installed by the kernel while
    // an isolated Rustlet call is active.
    unsafe { crate::core::allocator::alloc_from_heap(allocator, layout) as SyscallWord }
}

unsafe extern "C" fn dealloc_handler(
    arg0: SyscallWord,
    arg1: SyscallWord,
    arg2: SyscallWord,
    _arg3: SyscallWord,
) -> SyscallWord {
    if let Some((allocator, layout)) = active_allocator_and_layout(arg1, arg2) {
        // Invariant: the active allocator pointer is installed by the kernel
        // while an isolated Rustlet call is active.
        unsafe {
            let _ = crate::core::allocator::dealloc_from_heap(allocator, arg0 as *mut u8, layout);
        }
    }
    0
}

#[inline(always)]
fn active_allocator_and_layout(
    size: SyscallWord,
    align: SyscallWord,
) -> Option<(*mut crate::core::HeapAllocatorState, Layout)> {
    let allocator = CURRENT_APP_ALLOCATOR.load(Ordering::Acquire);
    if allocator.is_null() {
        return None;
    }
    let layout = Layout::from_size_align(size, align).ok()?;
    Some((allocator, layout))
}

const BUILTIN_BINDINGS: [SyscallBinding; 3] = [
    SyscallBinding {
        number: rustlet_runtime::syscall_abi::ENTER_APP,
        handler: enter_app_handler,
    },
    SyscallBinding {
        number: rustlet_runtime::syscall_abi::ALLOC,
        handler: alloc_handler,
    },
    SyscallBinding {
        number: rustlet_runtime::syscall_abi::DEALLOC,
        handler: dealloc_handler,
    },
];
