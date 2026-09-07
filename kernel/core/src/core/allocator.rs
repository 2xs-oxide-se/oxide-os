use ::core::alloc::{GlobalAlloc, Layout};
use ::core::cell::UnsafeCell;
use ::core::ptr::null_mut;

/// # Buddy Allocator with External Bit-Tree (V2: Arbitrary Size Support)
///
/// ### (1) Operating Principle
/// This allocator manages memory using a binary tree represented as a flat bit-table stored **outside**
/// the heap. To support arbitrary heap sizes and alignments:
/// - The physical heap is mapped onto a "virtual" power-of-two space.
/// - The tree is "pruned" at initialization: nodes representing addresses outside the physical
///   storage boundaries are marked as `Unavailable`.
/// - Each node in the tree is represented by 2 bits, encoding 4 states:
///   `00` (Free), `01` (Unavailable), `10` (Partial/Split), `11` (Full/Allocated).
///
/// ### (2) Motivations
/// - **Performance**: Fast power-of-two allocations and coalescing in $O(\log n)$.
/// - **MPU Alignment**: Guaranteed alignment on power-of-two boundaries, essential for MPU region protection.
/// - **Integrity**: Metadata is isolated from the managed heap. User-space memory corruption
///   cannot overwrite the allocator's internal state.
/// - **Flexibility**: Supports non-power-of-two heap sizes through the `Unavailable` state marking.
///
/// ### (3) Constraints & Overhead
/// - **Memory Footprint**: Metadata size is $(4 \times g) / 8$ bytes, where $g$ is the number
///   of granules in the virtual power-of-two space.
/// - **Complexity**: All operations are $O(\log n)$.
pub const ALLOCATION_GRANULE: usize = 8;

#[derive(PartialEq, Copy, Clone)]
#[repr(u8)]
enum NodeState {
    Free = 0b00,
    Unavailable = 0b01,
    Partial = 0b10,
    Full = 0b11,
}

/// Header for the allocator state.
/// All control state lives in kernel-owned memory, protecting it from user-space heap corruption.
#[repr(C)]
pub struct HeapAllocatorState {
    storage_start: *mut u8,
    storage_len: usize,
    virtual_start: *mut u8,
    virtual_len: usize,
    metadata_start: *mut u8,
    metadata_len: usize,
    initialized: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelHeapPartition {
    pub metadata_start: usize,
    pub metadata_len: usize,
    pub heap_start: usize,
    pub heap_len: usize,
}

impl HeapAllocatorState {
    pub const fn new() -> Self {
        Self {
            storage_start: null_mut(),
            storage_len: 0,
            virtual_start: null_mut(),
            virtual_len: 0,
            metadata_start: null_mut(),
            metadata_len: 0,
            initialized: false,
        }
    }

    /// Retrieves the 2-bit state of a specific node in the bit-table.
    #[inline]
    fn get_state(&self, node_idx: usize) -> NodeState {
        // Invariant: node_idx * 2 / 8 must be less than metadata_len.
        let bit_pos = node_idx * 2;
        if bit_pos / 8 >= self.metadata_len {
            panic!("allocator metadata read out of bounds");
        }
        // Invariant: reset_heap() installs a valid metadata buffer covering
        // metadata_len bytes before any allocator operation can reach here.
        let byte = unsafe { *self.metadata_start.add(bit_pos / 8) };
        match (byte >> (bit_pos % 8)) & 0b11 {
            0b00 => NodeState::Free,
            0b01 => NodeState::Unavailable,
            0b10 => NodeState::Partial,
            _ => NodeState::Full,
        }
    }

    /// Sets the 2-bit state of a specific node in the bit-table.
    #[inline]
    fn set_state(&mut self, node_idx: usize, state: NodeState) {
        let bit_pos = node_idx * 2;
        if bit_pos / 8 >= self.metadata_len {
            panic!("allocator metadata write out of bounds");
        }
        // Invariant: reset_heap() installs a valid metadata buffer covering
        // metadata_len bytes before any allocator operation can reach here.
        let byte_ptr = unsafe { self.metadata_start.add(bit_pos / 8) };
        let offset = bit_pos % 8;
        let mask = 0b11 << offset;
        // Invariant: byte_ptr targets one byte inside the metadata buffer.
        unsafe {
            *byte_ptr = (*byte_ptr & !mask) | ((state as u8) << offset);
        }
    }
}

impl Default for HeapAllocatorState {
    fn default() -> Self {
        Self::new()
    }
}

// --- Internal Helper Functions ---

const fn virtual_len_capacity_for_heap_size(heap_size: usize) -> usize {
    // We over-provision the virtual tree so any granule-aligned physical base
    // can be represented without losing allocator metadata coverage.
    let base = if heap_size <= ALLOCATION_GRANULE {
        ALLOCATION_GRANULE
    } else {
        heap_size.next_power_of_two()
    };
    base * 4
}

pub const fn metadata_size_for_heap_size(heap_size: usize) -> usize {
    let v_size = virtual_len_capacity_for_heap_size(heap_size);
    let granules = v_size / ALLOCATION_GRANULE;
    let total_bits = (2 * granules - 1) * 2;
    total_bits.div_ceil(8)
}

fn exact_metadata_size_for_heap(storage_addr: usize, size: usize) -> Option<usize> {
    if size < ALLOCATION_GRANULE || !size.is_multiple_of(ALLOCATION_GRANULE) {
        return None;
    }

    let mut v_len = if size <= ALLOCATION_GRANULE {
        ALLOCATION_GRANULE
    } else {
        size.checked_next_power_of_two()?
    };
    let mut v_start = align_down(storage_addr, v_len);
    while storage_addr.checked_add(size)? > v_start.checked_add(v_len)? {
        v_len = v_len.checked_mul(2)?;
        v_start = align_down(storage_addr, v_len);
    }

    let granules = v_len / ALLOCATION_GRANULE;
    let total_bits = (2 * granules - 1) * 2;
    Some(total_bits.div_ceil(8))
}

pub fn partition_kernel_heap(free_start: usize, ram_end: usize) -> Option<KernelHeapPartition> {
    let metadata_start = align_up(free_start, ALLOCATION_GRANULE);
    let ram_end = align_down(ram_end, ALLOCATION_GRANULE);
    if metadata_start >= ram_end {
        return None;
    }

    let mut metadata_len = 0usize;
    for _ in 0..32 {
        let heap_start = align_up(
            metadata_start.checked_add(metadata_len)?,
            ALLOCATION_GRANULE,
        );
        if heap_start >= ram_end {
            return None;
        }
        let heap_len = ram_end - heap_start;
        let required_metadata_len = align_up(
            exact_metadata_size_for_heap(heap_start, heap_len)?,
            ALLOCATION_GRANULE,
        );

        if required_metadata_len <= metadata_len {
            return Some(KernelHeapPartition {
                metadata_start,
                metadata_len,
                heap_start,
                heap_len,
            });
        }
        metadata_len = required_metadata_len;
    }

    None
}

const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

// --- Allocator Implementation ---

struct KernelAllocator;

struct KernelHeapStateCell {
    state: UnsafeCell<HeapAllocatorState>,
}

// Invariant: the kernel allocator is initialized during single-core early boot,
// and later accesses are serialized by the current kernel execution model.
unsafe impl Sync for KernelHeapStateCell {}

impl KernelHeapStateCell {
    const fn new() -> Self {
        Self {
            state: UnsafeCell::new(HeapAllocatorState::new()),
        }
    }

    fn as_mut_ptr(&self) -> *mut HeapAllocatorState {
        self.state.get()
    }
}

static KERNEL_HEAP_STATE: KernelHeapStateCell = KernelHeapStateCell::new();

#[cfg(all(not(test), not(feature = "host-test")))]
#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(any(test, feature = "host-test"))]
#[global_allocator]
static ALLOCATOR: std::alloc::System = std::alloc::System;

impl KernelAllocator {
    /// Marks nodes as Unavailable if they are outside physical memory bounds.
    ///
    /// Invariant: node_offset is always relative to virtual_start.
    fn prune_tree(
        &self,
        state: &mut HeapAllocatorState,
        node_idx: usize,
        node_offset: usize,
        node_size: usize,
    ) -> NodeState {
        let node_end = node_offset + node_size;
        let storage_offset = state.storage_start as usize - state.virtual_start as usize;
        let storage_end = storage_offset + state.storage_len;

        // Node is entirely outside the physical storage
        if node_end <= storage_offset || node_offset >= storage_end {
            state.set_state(node_idx, NodeState::Unavailable);
            return NodeState::Unavailable;
        }

        // Node straddles the boundary: recurse if not a leaf
        if node_offset < storage_offset || node_end > storage_end {
            if node_size > ALLOCATION_GRANULE {
                let left = self.prune_tree(state, node_idx * 2 + 1, node_offset, node_size / 2);
                let right = self.prune_tree(
                    state,
                    node_idx * 2 + 2,
                    node_offset + node_size / 2,
                    node_size / 2,
                );

                let s = if left == NodeState::Unavailable && right == NodeState::Unavailable {
                    NodeState::Unavailable
                } else {
                    NodeState::Partial
                };
                state.set_state(node_idx, s);
                return s;
            } else {
                state.set_state(node_idx, NodeState::Unavailable);
                return NodeState::Unavailable;
            }
        }

        // Node is entirely inside
        state.set_state(node_idx, NodeState::Free);
        NodeState::Free
    }

    /// Recursively finds and allocates a block.
    fn alloc_node(
        &self,
        state: &mut HeapAllocatorState,
        node_idx: usize,
        node_offset: usize,
        node_size: usize,
        target_size: usize,
    ) -> Option<usize> {
        let current = state.get_state(node_idx);

        // Invariant: Unavailable and Full nodes are terminal during search.
        match current {
            NodeState::Unavailable | NodeState::Full => return None,
            NodeState::Partial if node_size == target_size => return None,
            _ => {}
        }

        if node_size == target_size {
            // Final safety check: ensure the candidate block is physically within storage
            let candidate_abs = state.virtual_start as usize + node_offset;
            let storage_start = state.storage_start as usize;
            let storage_end = storage_start + state.storage_len;

            if candidate_abs >= storage_start && (candidate_abs + target_size) <= storage_end {
                state.set_state(node_idx, NodeState::Full);
                return Some(node_offset);
            }
            return None;
        }

        let child_size = node_size / 2;

        if current == NodeState::Free {
            // Invariant: splitting a Free node must rebuild child states from physical bounds.
            // This clears stale descendants after coalescing without erasing pruned holes.
            self.prune_tree(state, node_idx * 2 + 1, node_offset, child_size);
            self.prune_tree(
                state,
                node_idx * 2 + 2,
                node_offset + child_size,
                child_size,
            );
        }

        // Search Left
        if let Some(offset) = self.alloc_node(
            state,
            node_idx * 2 + 1,
            node_offset,
            child_size,
            target_size,
        ) {
            state.set_state(node_idx, NodeState::Partial);
            return Some(offset);
        }
        // Search Right
        if let Some(offset) = self.alloc_node(
            state,
            node_idx * 2 + 2,
            node_offset + child_size,
            child_size,
            target_size,
        ) {
            state.set_state(node_idx, NodeState::Partial);
            return Some(offset);
        }

        None
    }

    /// Recursively frees a block and coalesces buddies.
    fn dealloc_node(
        &self,
        state: &mut HeapAllocatorState,
        node_idx: usize,
        node_size: usize,
        target_offset: usize,
        target_size: usize,
    ) {
        if node_size == target_size {
            state.set_state(node_idx, NodeState::Free);
            return;
        }

        let child_size = node_size / 2;
        let left_idx = node_idx * 2 + 1;
        let right_idx = node_idx * 2 + 2;

        if target_offset < child_size {
            self.dealloc_node(state, left_idx, child_size, target_offset, target_size);
        } else {
            self.dealloc_node(
                state,
                right_idx,
                child_size,
                target_offset - child_size,
                target_size,
            );
        }

        let left = state.get_state(left_idx);
        let right = state.get_state(right_idx);

        // Invariant: Coalescing only happens if both buddies are purely Free.
        // Invariant: If one buddy is Unavailable, parent stays Partial to protect the hole.
        if left == NodeState::Free && right == NodeState::Free {
            state.set_state(node_idx, NodeState::Free);
        } else {
            state.set_state(node_idx, NodeState::Partial);
        }
    }
}

// --- Public Interface ---

/// Initializes the heap state.
///
/// Invariant: `storage` must be aligned to `ALLOCATION_GRANULE`.
/// Invariant: `metadata` must be cleared before calling `prune_tree`.
///
/// # Safety
/// `state`, `storage`, and `metadata` must point to writable, non-overlapping
/// memory ranges owned by the kernel for the complete lifetime of the heap.
pub unsafe fn reset_heap(
    state: *mut HeapAllocatorState,
    storage: *mut u8,
    size: usize,
    metadata: *mut u8,
    meta_size: usize,
) -> bool {
    if state.is_null() || storage.is_null() || metadata.is_null() {
        return false;
    }
    if size < ALLOCATION_GRANULE || !size.is_multiple_of(ALLOCATION_GRANULE) {
        return false;
    }
    if !(storage as usize).is_multiple_of(ALLOCATION_GRANULE) {
        return false;
    }

    let storage_addr = storage as usize;
    let mut v_len = if size <= ALLOCATION_GRANULE {
        ALLOCATION_GRANULE
    } else {
        size.next_power_of_two()
    };
    let mut v_start = align_down(storage_addr, v_len);
    while storage_addr + size > v_start + v_len {
        v_len *= 2;
        v_start = align_down(storage_addr, v_len);
    }

    // Verify metadata buffer is large enough for the calculated virtual tree
    let granules = v_len / ALLOCATION_GRANULE;
    let total_bits = (2 * granules - 1) * 2;
    let required_metadata_len = total_bits.div_ceil(8);
    if meta_size < required_metadata_len {
        return false;
    }

    // Invariant: null was rejected above and the caller owns this state object.
    let s = unsafe { &mut *state };
    s.storage_start = storage;
    s.storage_len = size;
    s.virtual_start = v_start as *mut u8;
    s.virtual_len = v_len;
    s.metadata_start = metadata;
    s.metadata_len = meta_size;

    // Clear metadata
    // Invariant: null was rejected above and the caller promised meta_size
    // writable bytes of kernel-owned metadata storage.
    unsafe {
        ::core::ptr::write_bytes(metadata, 0, meta_size);
    }

    // Build the pruned tree
    KernelAllocator.prune_tree(s, 0, 0, v_len);

    s.initialized = true;
    true
}

/// Allocates one block from an explicitly supplied heap state.
///
/// # Safety
///
/// `state` must point to a live, exclusively accessible allocator state whose
/// backing storage and metadata remain valid for the complete call.
pub unsafe fn alloc_from_heap(state: *mut HeapAllocatorState, layout: Layout) -> *mut u8 {
    // Invariant: callers pass an allocator state pointer owned by the kernel.
    let Some(s) = (unsafe { state.as_mut() }) else {
        return null_mut();
    };
    alloc_from_heap_state(s, layout)
}

fn alloc_from_heap_state(s: &mut HeapAllocatorState, layout: Layout) -> *mut u8 {
    if !s.initialized {
        return null_mut();
    }

    let Some(size) = allocation_size(layout) else {
        return null_mut();
    };
    if size > s.virtual_len {
        return null_mut();
    }

    match KernelAllocator.alloc_node(s, 0, 0, s.virtual_len, size) {
        Some(offset) => (s.virtual_start as usize + offset) as *mut u8,
        None => null_mut(),
    }
}

/// Returns one allocation to an explicitly supplied heap state.
///
/// # Safety
///
/// `state` must identify the allocator that produced `ptr`, and `ptr` with
/// `layout` must describe a currently live allocation from that allocator.
pub unsafe fn dealloc_from_heap(
    state: *mut HeapAllocatorState,
    ptr: *mut u8,
    layout: Layout,
) -> bool {
    // Invariant: callers pass an allocator state pointer owned by the kernel.
    let Some(s) = (unsafe { state.as_mut() }) else {
        return false;
    };
    dealloc_from_heap_state(s, ptr, layout)
}

fn dealloc_from_heap_state(s: &mut HeapAllocatorState, ptr: *mut u8, layout: Layout) -> bool {
    if !s.initialized || ptr.is_null() {
        return false;
    }

    let Some(size) = allocation_size(layout) else {
        return false;
    };
    let ptr_addr = ptr as usize;

    // Invariant: The pointer must be within the physical heap.
    if ptr_addr < s.storage_start as usize || ptr_addr >= (s.storage_start as usize + s.storage_len)
    {
        return false;
    }

    let offset = ptr_addr - s.virtual_start as usize;
    // Invariant: Offset must be aligned to the power-of-two size.
    if !offset.is_multiple_of(size) {
        return false;
    }

    KernelAllocator.dealloc_node(s, 0, s.virtual_len, offset, size);
    true
}

fn allocation_size(layout: Layout) -> Option<usize> {
    layout
        .size()
        .max(layout.align())
        .max(ALLOCATION_GRANULE)
        .checked_next_power_of_two()
}

/// Allocates from the kernel heap using the standard Rust allocation layout.
pub fn alloc(layout: Layout) -> *mut u8 {
    // Invariant: KERNEL_HEAP_STATE is the singleton kernel heap state.
    unsafe { alloc_from_heap(KERNEL_HEAP_STATE.as_mut_ptr(), layout) }
}

/// Deallocates from the kernel heap using the original Rust allocation layout.
///
/// # Safety
/// `ptr` and `layout` must describe a live allocation returned by [`alloc`].
pub unsafe fn dealloc(ptr: *mut u8, layout: Layout) {
    // Invariant: KERNEL_HEAP_STATE is the singleton kernel heap state.
    let _ = unsafe { dealloc_from_heap(KERNEL_HEAP_STATE.as_mut_ptr(), ptr, layout) };
}

pub fn kernel_heap_debug_window() -> (usize, usize, usize, usize) {
    // Invariant: debug readers only snapshot scalar fields from the singleton
    // allocator state.
    unsafe {
        let state = &*KERNEL_HEAP_STATE.as_mut_ptr();
        (
            state.storage_start as usize,
            state.storage_len,
            state.virtual_start as usize,
            state.virtual_len,
        )
    }
}

pub fn kernel_heap_metadata_debug_window() -> (usize, usize) {
    // Invariant: debug readers only snapshot scalar fields from the singleton
    // allocator state.
    unsafe {
        let state = &*KERNEL_HEAP_STATE.as_mut_ptr();
        (state.metadata_start as usize, state.metadata_len)
    }
}

// --- GlobalAlloc Glue ---

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        crate::core::allocator::alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        crate::core::allocator::dealloc(ptr, layout);
    }
}

/// Public API to initialize the kernel allocator.
///
/// This function sets up the physical storage, cleans up the alignment,
/// and triggers the tree pruning to lock out-of-bounds memory nodes.
#[cfg_attr(test, allow(dead_code))]
pub fn initialize() {
    unsafe {
        unsafe extern "C" {
            static __ram_end: u8;
        }

        let free_start = ::core::ptr::addr_of!(__ram_end) as usize;
        let Some(ram_end) = crate::core::target::kernel_heap_end() else {
            panic!("missing kernel heap end for target");
        };
        let Some(partition) = partition_kernel_heap(free_start, ram_end) else {
            panic!("failed to partition kernel heap");
        };

        let success = reset_heap(
            KERNEL_HEAP_STATE.as_mut_ptr(),
            partition.heap_start as *mut u8,
            partition.heap_len,
            partition.metadata_start as *mut u8,
            partition.metadata_len,
        );

        if !success {
            crate::consoleln!(
                "allocator init failed free=0x{:08x} meta=0x{:08x}+{} heap=0x{:08x}+{} granule={}",
                free_start,
                partition.metadata_start,
                partition.metadata_len,
                partition.heap_start,
                partition.heap_len,
                ALLOCATION_GRANULE
            );
            // Optional: Panic or Log. In a micro-system, an init failure
            // of the global allocator is usually fatal.
            panic!("Failed to initialize Kernel Buddy Allocator");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_state_allocates_power_of_two_blocks_inside_storage() {
        let mut state = HeapAllocatorState::new();
        let mut storage = [0u8; 256];
        let mut metadata = [0u8; metadata_size_for_heap_size(256)];

        let initialized = unsafe {
            reset_heap(
                &mut state,
                storage.as_mut_ptr(),
                storage.len(),
                metadata.as_mut_ptr(),
                metadata.len(),
            )
        };
        assert!(initialized);

        let layout = Layout::from_size_align(24, 16).unwrap();
        let ptr = alloc_from_heap_state(&mut state, layout);
        assert!(!ptr.is_null());

        let start = storage.as_ptr() as usize;
        let end = start + storage.len();
        let ptr_addr = ptr as usize;
        assert!((start..end).contains(&ptr_addr));
        assert_eq!(ptr_addr % 32, 0);
    }

    #[test]
    fn heap_state_reuses_deallocated_block() {
        let mut state = HeapAllocatorState::new();
        let mut storage = [0u8; 256];
        let mut metadata = [0u8; metadata_size_for_heap_size(256)];

        let initialized = unsafe {
            reset_heap(
                &mut state,
                storage.as_mut_ptr(),
                storage.len(),
                metadata.as_mut_ptr(),
                metadata.len(),
            )
        };
        assert!(initialized);

        let layout = Layout::from_size_align(32, 8).unwrap();
        let first = alloc_from_heap_state(&mut state, layout);
        assert!(!first.is_null());
        assert!(dealloc_from_heap_state(&mut state, first, layout));

        let second = alloc_from_heap_state(&mut state, layout);
        assert_eq!(second, first);
    }

    #[test]
    fn heap_state_rejects_foreign_deallocation() {
        let mut state = HeapAllocatorState::new();
        let mut storage = [0u8; 256];
        let mut metadata = [0u8; metadata_size_for_heap_size(256)];
        let mut foreign = [0u8; 32];

        let initialized = unsafe {
            reset_heap(
                &mut state,
                storage.as_mut_ptr(),
                storage.len(),
                metadata.as_mut_ptr(),
                metadata.len(),
            )
        };
        assert!(initialized);

        let layout = Layout::from_size_align(16, 8).unwrap();
        assert!(!dealloc_from_heap_state(
            &mut state,
            foreign.as_mut_ptr(),
            layout
        ));
    }
}
