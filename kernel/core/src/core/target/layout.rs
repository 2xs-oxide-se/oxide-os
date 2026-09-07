/// Static RAM and flash layout for one supported target.
///
/// These values describe the board-level memory budget used by the kernel
/// runtime, bootable startup linker scripts, and host-side layout diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetMemoryLayout {
    pub name: &'static str,
    pub ram_base: usize,
    pub ram_size: usize,
    pub flash_base: usize,
    pub flash_size: usize,
    pub kernel_heap_min_size: usize,
    pub kernel_stack_size: usize,
}
