#![no_std]
#![no_main]

// Track the external startup object: Cargo must relink when its contents change.
const _: Option<&str> = option_env!("OXIDE_SE_NATIVE_STARTUP_FINGERPRINT");

use core::alloc::Layout;
#[cfg(target_arch = "arm")]
use core::arch::asm;
use oxi_core::core::crypto::{self, AesKey};
use oxi_core::core::{
    alloc_from_heap, dealloc_from_heap, metadata_size_for_heap_size, reset_heap,
    HeapAllocatorState, ALLOCATION_GRANULE,
};

#[repr(align(8))]
struct AlignedHeap<const N: usize>([u8; N]);

const LOCAL_RAW_HEAP_SIZE: usize = 72;
const LOCAL_USABLE_HEAP_SIZE: usize = 64;
const LOCAL_METADATA_LEN: usize = metadata_size_for_heap_size(LOCAL_USABLE_HEAP_SIZE);
const ALIGN_RAW_HEAP_SIZE: usize = 2056;
const ALIGN_USABLE_HEAP_SIZE: usize = 2048;
const ALIGN_METADATA_LEN: usize = metadata_size_for_heap_size(ALIGN_USABLE_HEAP_SIZE * 4);
const FAE_HEAP_SIZE: usize = 4 * 1024;
const FAE_HEAP_RAW_SIZE: usize = FAE_HEAP_SIZE * 2 - 1;
const FAE_STACK_SIZE: usize = 2 * 1024;
const FAE_HEAP_METADATA_LEN: usize = metadata_size_for_heap_size(FAE_HEAP_SIZE);

static mut LOCAL_HEAP: AlignedHeap<LOCAL_RAW_HEAP_SIZE> = AlignedHeap([0; LOCAL_RAW_HEAP_SIZE]);
static mut LOCAL_METADATA: [u8; LOCAL_METADATA_LEN] = [0; LOCAL_METADATA_LEN];
static mut ALIGN_HEAP: AlignedHeap<ALIGN_RAW_HEAP_SIZE> = AlignedHeap([0; ALIGN_RAW_HEAP_SIZE]);
static mut ALIGN_METADATA: [u8; ALIGN_METADATA_LEN] = [0; ALIGN_METADATA_LEN];
static mut FAE_HEAP: AlignedHeap<FAE_HEAP_RAW_SIZE> = AlignedHeap([0; FAE_HEAP_RAW_SIZE]);
static mut FAE_METADATA: [u8; FAE_HEAP_METADATA_LEN] = [0; FAE_HEAP_METADATA_LEN];

fn test_main() -> i32 {
    let mut failed = 0usize;

    write_line(b"TEST-BEGIN kernel-svc-roundtrip");
    if test_kernel_svc_roundtrip() {
        write_line(b"TEST-PASS kernel-svc-roundtrip");
    } else {
        write_line(b"TEST-FAIL kernel-svc-roundtrip svc-path-failed");
        failed += 1;
    }

    write_line(b"TEST-BEGIN scp03-kdf-card-cryptogram");
    if test_scp03_kdf_card_cryptogram() {
        write_line(b"TEST-PASS scp03-kdf-card-cryptogram");
    } else {
        write_line(b"TEST-FAIL scp03-kdf-card-cryptogram unexpected-kdf-output");
        failed += 1;
    }

    write_line(b"TEST-BEGIN scp03-kdf-session-key");
    if test_scp03_kdf_session_key() {
        write_line(b"TEST-PASS scp03-kdf-session-key");
    } else {
        write_line(b"TEST-FAIL scp03-kdf-session-key unexpected-session-key");
        failed += 1;
    }

    write_line(b"TEST-BEGIN fill-random-qemu");
    if test_fill_random() {
        write_line(b"TEST-PASS fill-random-qemu");
    } else {
        write_line(b"TEST-FAIL fill-random-qemu fill-random-failed");
        failed += 1;
    }

    write_line(b"TEST-BEGIN allocator-local-state");
    if test_allocator_local_state() {
        write_line(b"TEST-PASS allocator-local-state");
    } else {
        write_line(b"TEST-FAIL allocator-local-state allocator-contract-broken");
        failed += 1;
    }

    write_line(b"TEST-BEGIN allocator-requested-alignments");
    if test_allocator_requested_alignments() {
        write_line(b"TEST-PASS allocator-requested-alignments");
    } else {
        write_line(b"TEST-FAIL allocator-requested-alignments allocator-alignment-broken");
        failed += 1;
    }

    write_line(b"TEST-BEGIN allocator-fae-reload-pattern");
    if test_allocator_fae_reload_pattern() {
        write_line(b"TEST-PASS allocator-fae-reload-pattern");
    } else {
        write_line(b"TEST-FAIL allocator-fae-reload-pattern allocator-reload-pattern-broken");
        failed += 1;
    }

    write_line(b"TEST-BEGIN allocator-kernel-rustlet-layout");
    if test_allocator_kernel_rustlet_layout() {
        write_line(b"TEST-PASS allocator-kernel-rustlet-layout");
    } else {
        write_line(b"TEST-FAIL allocator-kernel-rustlet-layout allocator-kernel-layout-broken");
        failed += 1;
    }

    match failed {
        0 => write_line(b"TEST-DONE total=8 failed=0"),
        1 => write_line(b"TEST-DONE total=8 failed=1"),
        2 => write_line(b"TEST-DONE total=8 failed=2"),
        3 => write_line(b"TEST-DONE total=8 failed=3"),
        4 => write_line(b"TEST-DONE total=8 failed=4"),
        5 => write_line(b"TEST-DONE total=8 failed=5"),
        6 => write_line(b"TEST-DONE total=8 failed=6"),
        7 => write_line(b"TEST-DONE total=8 failed=7"),
        _ => write_line(b"TEST-DONE total=8 failed=8"),
    }

    if failed == 0 {
        0
    } else {
        1
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn start() -> ! {
    // Use the firmware's stack-limit setup before exercising its protection.
    oxi_core::core::kernel_stack_overflow_protection();
    oxi_core::core::initialize();
    if option_env!("OXIDE_SE_KERNEL_STACK_GUARD_TEST") == Some("1") {
        let touch: fn() = oxi_core::core::target::kernel_stack_guard_test_touch;
        let touch = unsafe { core::ptr::read_volatile(&touch) };
        touch();
    }
    if option_env!("OXIDE_SE_KERNEL_RAM_NX_TEST") == Some("1") {
        let touch: fn() -> bool = oxi_core::core::target::kernel_ram_execute_never_test_touch;
        let touch = unsafe { core::ptr::read_volatile(&touch) };
        if !touch() {
            write_line(b"TEST-UNSUPPORTED kernel-ram-nx");
            oxi_core::core::shutdown(2);
        }
        write_line(b"TEST-FAIL kernel-ram-nx ram-execution-returned");
        oxi_core::core::shutdown(1);
    }

    let exit_code = test_main();
    oxi_core::core::shutdown(exit_code)
}

fn test_scp03_kdf_card_cryptogram() -> bool {
    let key = match AesKey::from_bytes(&hex_16("00112233445566778899AABBCCDDEEFF")) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let context = hex_16("112233445566778899AABBCCDDEEFF00");
    let mut out = [0u8; 8];

    crypto::scp03_kdf(&key, 0x00, &context, &mut out).is_ok() && out == hex_8("524A020867FB4974")
}

const KERNEL_SVC_TEST_NUMBER: u8 = 0x7e;

fn test_kernel_svc_roundtrip() -> bool {
    oxi_core::core::syscall::install_handler(KERNEL_SVC_TEST_NUMBER, kernel_svc_test_handler);
    (unsafe { kernel_svc_roundtrip(0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00) })
        == 0x5a17_c0de
}

unsafe extern "C" fn kernel_svc_test_handler(
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> usize {
    if arg0 != 0x1122_3344 || arg1 != 0x5566_7788 || arg2 != 0x99aa_bbcc || arg3 != 0xddee_ff00 {
        return 0;
    }

    0x5a17_c0de
}

#[cfg(target_arch = "arm")]
unsafe fn kernel_svc_roundtrip(arg0: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc 0x7e",
            inlateout("r0") arg0 => ret,
            in("r1") arg1,
            in("r2") arg2,
            in("r3") arg3,
            options(nostack),
        );
    }
    ret
}

#[cfg(not(target_arch = "arm"))]
unsafe fn kernel_svc_roundtrip(_arg0: usize, _arg1: usize, _arg2: usize, _arg3: usize) -> usize {
    0
}

fn test_scp03_kdf_session_key() -> bool {
    let key = match AesKey::from_bytes(&hex_16("00112233445566778899AABBCCDDEEFF")) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let context = hex_16("112233445566778899AABBCCDDEEFF00");
    let mut out = [0u8; 16];

    crypto::scp03_kdf(&key, 0x04, &context, &mut out).is_ok()
        && out == hex_16("62A911BE75B984BB7A6D3DE46F3B127E")
}

fn test_fill_random() -> bool {
    let mut buf = [0u8; 16];
    crypto::fill_random(&mut buf).is_ok() && buf != [0u8; 16]
}

fn test_allocator_local_state() -> bool {
    let mut state = HeapAllocatorState::new();
    let heap = core::ptr::addr_of_mut!(LOCAL_HEAP);
    let heap_start = heap.cast::<u8>();
    let metadata = core::ptr::addr_of_mut!(LOCAL_METADATA).cast::<u8>();

    // Exercise the explicit heap contract used by Rustlet allocator syscalls:
    // the heap base is granule-aligned and allocations below one granule are
    // rounded up internally, not rejected.
    let reset_ok = unsafe {
        reset_heap(
            &mut state,
            align_ptr_to_granule(heap_start),
            LOCAL_USABLE_HEAP_SIZE,
            metadata,
            LOCAL_METADATA_LEN,
        )
    };
    if !reset_ok {
        oxi_core::consoleln!(
            "allocator-local reset-failed heap=0x{:08x} size={} meta_len={}",
            align_ptr_to_granule(heap_start) as usize,
            LOCAL_USABLE_HEAP_SIZE,
            LOCAL_METADATA_LEN
        );
        return false;
    }

    let tiny_layout = Layout::from_size_align(1, 1).unwrap();
    let first = unsafe { alloc_from_heap(&mut state, tiny_layout) };
    if first.is_null() || !(first as usize).is_multiple_of(ALLOCATION_GRANULE) {
        oxi_core::consoleln!(
            "allocator-local first-failed ptr=0x{:08x} heap=0x{:08x}",
            first as usize,
            align_ptr_to_granule(heap_start) as usize
        );
        return false;
    }

    let second_layout = Layout::from_size_align(16, 16).unwrap();
    let second = unsafe { alloc_from_heap(&mut state, second_layout) };
    if second.is_null() || !(second as usize).is_multiple_of(16) {
        oxi_core::consoleln!(
            "allocator-local second-failed ptr=0x{:08x}",
            second as usize
        );
        return false;
    }

    if first == second {
        return false;
    }

    let third_layout = Layout::from_size_align(48, 8).unwrap();
    let third = unsafe { alloc_from_heap(&mut state, third_layout) };
    if !third.is_null() {
        oxi_core::consoleln!(
            "allocator-local third-unexpected ptr=0x{:08x}",
            third as usize
        );
        return false;
    }

    let freed_first = unsafe { dealloc_from_heap(&mut state, first, tiny_layout) };
    let freed_second = unsafe { dealloc_from_heap(&mut state, second, second_layout) };
    if !freed_first || !freed_second {
        oxi_core::consoleln!(
            "allocator-local free-failed first={} second={}",
            freed_first,
            freed_second
        );
        return false;
    }

    let recycled_layout = Layout::from_size_align(24, 8).unwrap();
    let recycled = unsafe { alloc_from_heap(&mut state, recycled_layout) };
    if recycled.is_null() || !(recycled as usize).is_multiple_of(8) {
        oxi_core::consoleln!(
            "allocator-local recycled-failed ptr=0x{:08x}",
            recycled as usize
        );
        return false;
    }

    if !unsafe { dealloc_from_heap(&mut state, recycled, recycled_layout) } {
        oxi_core::consoleln!("allocator-local recycled-free-failed");
        return false;
    }

    let probe = unsafe { alloc_from_heap(&mut state, tiny_layout) };
    if probe.is_null() {
        return false;
    }
    unsafe { dealloc_from_heap(&mut state, probe, tiny_layout) }
}

fn test_allocator_requested_alignments() -> bool {
    const ALIGNMENTS: [usize; 9] = [1, 8, 16, 32, 64, 128, 256, 512, 1024];

    let mut state = HeapAllocatorState::new();
    let heap = core::ptr::addr_of_mut!(ALIGN_HEAP);
    let heap_start = heap.cast::<u8>();
    let metadata = core::ptr::addr_of_mut!(ALIGN_METADATA).cast::<u8>();

    let reset_ok = unsafe {
        reset_heap(
            &mut state,
            align_ptr_to_granule(heap_start),
            ALIGN_USABLE_HEAP_SIZE,
            metadata,
            ALIGN_METADATA_LEN,
        )
    };
    if !reset_ok {
        oxi_core::consoleln!("allocator-align reset-failed");
        return false;
    }

    for requested_align in ALIGNMENTS {
        let expected_align = requested_align.max(ALLOCATION_GRANULE);
        let layout = Layout::from_size_align(1, requested_align).unwrap();
        let ptr = unsafe { alloc_from_heap(&mut state, layout) };
        if ptr.is_null() || !(ptr as usize).is_multiple_of(expected_align) {
            oxi_core::consoleln!(
                "allocator-align failed align={} ptr=0x{:08x}",
                requested_align,
                ptr as usize
            );
            return false;
        }
        if !unsafe { dealloc_from_heap(&mut state, ptr, layout) } {
            oxi_core::consoleln!(
                "allocator-align dealloc-failed align={} ptr=0x{:08x}",
                requested_align,
                ptr as usize
            );
            return false;
        }
    }

    true
}

fn test_allocator_fae_reload_pattern() -> bool {
    let mut state = HeapAllocatorState::new();
    let heap = core::ptr::addr_of_mut!(FAE_HEAP);
    let heap_start = align_ptr(heap.cast::<u8>(), FAE_HEAP_SIZE);
    let metadata = core::ptr::addr_of_mut!(FAE_METADATA).cast::<u8>();

    let reset_ok = unsafe {
        reset_heap(
            &mut state,
            heap_start,
            FAE_HEAP_SIZE,
            metadata,
            FAE_HEAP_METADATA_LEN,
        )
    };
    if !reset_ok {
        oxi_core::consoleln!(
            "allocator-fae reset-failed heap=0x{:08x} size={} metadata=0x{:08x}+{}",
            heap_start as usize,
            FAE_HEAP_SIZE,
            metadata as usize,
            FAE_HEAP_METADATA_LEN
        );
        return false;
    }

    let app_layout = Layout::from_size_align(FAE_HEAP_SIZE, FAE_HEAP_SIZE).unwrap();
    let block = unsafe { alloc_from_heap(&mut state, app_layout) };
    if block.is_null() {
        oxi_core::consoleln!(
            "allocator-fae first-load-failed block=0x{:08x}",
            block as usize
        );
        return false;
    }

    let stack_start = block as usize;
    let data_start = stack_start + FAE_STACK_SIZE;
    if !stack_start.is_multiple_of(FAE_HEAP_SIZE) || data_start >= stack_start + FAE_HEAP_SIZE {
        oxi_core::consoleln!(
            "allocator-fae bad-layout block=0x{:08x} stack=0x{:08x} data=0x{:08x}",
            block as usize,
            stack_start,
            data_start
        );
        return false;
    }

    if !unsafe { dealloc_from_heap(&mut state, block, app_layout) } {
        oxi_core::consoleln!("allocator-fae block-free-failed");
        return false;
    }

    let reloaded = unsafe { alloc_from_heap(&mut state, app_layout) };
    if reloaded.is_null() || !(reloaded as usize).is_multiple_of(FAE_HEAP_SIZE) {
        oxi_core::consoleln!(
            "allocator-fae reload-failed ptr=0x{:08x}",
            reloaded as usize
        );
        return false;
    }

    unsafe { dealloc_from_heap(&mut state, reloaded, app_layout) }
}

fn test_allocator_kernel_rustlet_layout() -> bool {
    let app_layout = Layout::from_size_align(FAE_HEAP_SIZE, FAE_HEAP_SIZE).unwrap();
    let block = oxi_core::core::alloc(app_layout);
    if block.is_null() {
        let (heap, heap_len, virtual_start, virtual_len) =
            oxi_core::core::kernel_heap_debug_window();
        oxi_core::consoleln!(
            "allocator-kernel-layout failed block=0x{:08x} heap=0x{:08x}+{} virtual=0x{:08x}+{}",
            block as usize,
            heap,
            heap_len,
            virtual_start,
            virtual_len
        );
        return false;
    }

    let stack_start = block as usize;
    let data_start = stack_start + FAE_STACK_SIZE;
    if !stack_start.is_multiple_of(FAE_HEAP_SIZE) || data_start >= stack_start + FAE_HEAP_SIZE {
        oxi_core::consoleln!(
            "allocator-kernel-layout bad-placement block=0x{:08x} stack=0x{:08x} data=0x{:08x}",
            block as usize,
            stack_start,
            data_start
        );
        unsafe { oxi_core::core::dealloc(block, app_layout) };
        return false;
    }

    unsafe { oxi_core::core::dealloc(block, app_layout) };
    true
}

fn align_ptr_to_granule(ptr: *mut u8) -> *mut u8 {
    align_ptr(ptr, ALLOCATION_GRANULE)
}

fn align_ptr(ptr: *mut u8, align: usize) -> *mut u8 {
    let value = ptr as usize;
    let mask = align - 1;
    ((value + mask) & !mask) as *mut u8
}

fn write_line(line: &[u8]) {
    oxi_core::core::write_buffer(line);
    oxi_core::core::write_buffer(b"\n");
}

fn hex_8(input: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    decode_hex_into(input, &mut out);
    out
}

fn hex_16(input: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    decode_hex_into(input, &mut out);
    out
}

fn decode_hex_into(input: &str, out: &mut [u8]) {
    let bytes = input.as_bytes();
    if bytes.len() != out.len() * 2 {
        panic!("invalid hex test vector length");
    }

    let mut index = 0usize;
    while index < out.len() {
        out[index] = (nibble(bytes[index * 2]) << 4) | nibble(bytes[index * 2 + 1]);
        index += 1;
    }
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}
