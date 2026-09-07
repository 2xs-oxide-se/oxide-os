// Only one CPU profile and one exception implementation are compiled.
#[cfg(all(not(test), target_arch = "arm", oxide_se_target_armv6m))]
pub(crate) mod armv6m_profile;
#[cfg(all(not(test), target_arch = "arm", oxide_se_target_armv7m))]
pub(crate) mod armv7m_profile;
#[cfg(any(test, all(target_arch = "arm", oxide_se_target_armv8m)))]
mod armv8m_mpu;
#[cfg(all(not(test), target_arch = "arm", oxide_se_target_armv8m))]
pub(crate) mod armv8m_profile;
#[cfg(all(not(test), target_arch = "arm"))]
mod common_arm_m_profile;
mod generic;
pub mod layout;

#[cfg(all(not(test), target_arch = "arm", oxide_se_board_b_l475e_iot01a))]
use b_l475e_iot01a::cpu as app_target_profile;
#[cfg(any(test, not(target_arch = "arm")))]
use generic as app_target_profile;
#[cfg(all(not(test), target_arch = "arm", oxide_se_board_mps2_an385))]
use mps2_an385::cpu as app_target_profile;
#[cfg(all(not(test), target_arch = "arm", oxide_se_board_olimex_stm32_h405))]
use olimex_stm32_h405::cpu as app_target_profile;
#[cfg(all(not(test), target_arch = "arm", oxide_se_board_raspi_pico))]
use raspi_pico::cpu as app_target_profile;
#[cfg(all(not(test), target_arch = "arm", oxide_se_board_raspi_pico2))]
use raspi_pico2::cpu as app_target_profile;

/// Memory-mapped 32-bit register helper for board target code.
///
/// This wrapper keeps volatile MMIO access centralized without allocating,
/// copying, or hiding the fact that board modules are touching hardware.
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct MmioRegister32 {
    address: usize,
}

#[allow(dead_code)]
impl MmioRegister32 {
    /// Creates a register descriptor for a board-owned MMIO address.
    pub(crate) const fn new(address: usize) -> Self {
        Self { address }
    }

    /// Reads the register with volatile semantics.
    pub(crate) fn read(self) -> u32 {
        // Invariant: callers define constants only for valid 32-bit MMIO
        // registers of the selected board.
        unsafe { core::ptr::read_volatile(self.address as *const u32) }
    }

    /// Writes the register with volatile semantics.
    pub(crate) fn write(self, value: u32) {
        // Invariant: callers define constants only for valid writable 32-bit
        // MMIO registers of the selected board.
        unsafe { core::ptr::write_volatile(self.address as *mut u32, value) }
    }

    /// Applies a read-modify-write update with volatile register accesses.
    pub(crate) fn update(self, f: impl FnOnce(u32) -> u32) {
        self.write(f(self.read()));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppGateRegion {
    pub base: usize,
    pub size: usize,
    pub entry_pc: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootAbiRegion {
    pub base: usize,
    pub size: usize,
    pub svc_forward: usize,
    pub memmanage_forward: usize,
    pub usagefault_forward: usize,
    pub periodic_timer_forward: usize,
}

const BOOT_ABI_SIZE: usize = 0x20;
#[allow(dead_code)]
const RASPI_PICO_KERNEL_MUTABLE_RAM_SIZE: usize = 48 * 1024;
#[allow(dead_code)]
const RASPI_PICO_KERNEL_MUTABLE_RAM_LOW_SIZE: usize = 32 * 1024;
#[allow(dead_code)]
const RASPI_PICO_KERNEL_MUTABLE_RAM_HIGH_SIZE: usize = 16 * 1024;
// Invariant: matches the executable tail reserved by native/raspi-pico2/link.ld.
const PICO2_EXECUTABLE_RAM_SIZE: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct KernelNxWindow {
    pub region: crate::core::mpu::MpuRegion,
    pub base_addr: usize,
    pub size: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MpuAlignmentModel {
    Unsupported,
    StrictPowerOfTwo,
    Relaxed32Byte,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpuRegionPolicy {
    pub model: MpuAlignmentModel,
    pub min_region_granule: usize,
}

impl MpuRegionPolicy {
    pub const fn unsupported() -> Self {
        Self {
            model: MpuAlignmentModel::Unsupported,
            min_region_granule: 32,
        }
    }

    pub const fn strict_power_of_two() -> Self {
        Self {
            model: MpuAlignmentModel::StrictPowerOfTwo,
            min_region_granule: 32,
        }
    }

    #[allow(dead_code)]
    pub const fn relaxed_32_byte() -> Self {
        Self {
            model: MpuAlignmentModel::Relaxed32Byte,
            min_region_granule: 32,
        }
    }
}

#[cfg(all(not(test), target_arch = "arm"))]
pub mod b_l475e_iot01a;
#[cfg(any(test, not(target_arch = "arm")))]
mod b_l475e_iot01a {
    pub use super::generic::*;
}

#[cfg(all(not(test), target_arch = "arm"))]
pub mod mps2_an385;
#[cfg(any(test, not(target_arch = "arm")))]
mod mps2_an385 {
    pub use super::generic::*;
}

#[cfg(all(not(test), target_arch = "arm"))]
pub mod olimex_stm32_h405;
#[cfg(any(test, not(target_arch = "arm")))]
mod olimex_stm32_h405 {
    pub use super::generic::*;
}

#[cfg(all(not(test), target_arch = "arm"))]
pub mod raspi_pico;
#[cfg(any(test, not(target_arch = "arm")))]
mod raspi_pico {
    pub use super::generic::*;
}

#[cfg(all(not(test), target_arch = "arm"))]
pub mod raspi_pico2;
#[cfg(any(test, oxide_se_board_raspi_pico2))]
#[cfg_attr(test, allow(dead_code))]
mod raspi_pico2_random;
#[cfg(any(test, not(target_arch = "arm")))]
mod raspi_pico2 {
    pub use super::generic::*;
}

fn board() -> &'static str {
    match option_env!("OXIDE_SE_BOARD") {
        Some(board) => board,
        None => "mps2-an385",
    }
}

// Invariant: keep this board-to-module table synchronized with the real target
// modules declared above and with `kernel/core/build.rs`.
macro_rules! dispatch_target_board {
    ($function:ident ( $($arg:expr),* $(,)? ), $fallback:expr) => {{
        match board() {
            "mps2-an385" => mps2_an385::$function($($arg),*),
            "olimex-stm32-h405" => olimex_stm32_h405::$function($($arg),*),
            "b-l475e-iot01a" => b_l475e_iot01a::$function($($arg),*),
            "raspi-pico1" => raspi_pico::$function($($arg),*),
            "raspi-pico2" =>  raspi_pico2::$function($($arg),*),
            _ => $fallback,
        }
    }};
}

// Invariant: every concrete board module must expose a MEMORY_LAYOUT constant.
macro_rules! target_board_memory_layout {
    () => {{
        match board() {
            "mps2-an385" => Some(mps2_an385::MEMORY_LAYOUT),
            "olimex-stm32-h405" => Some(olimex_stm32_h405::MEMORY_LAYOUT),
            "b-l475e-iot01a" => Some(b_l475e_iot01a::MEMORY_LAYOUT),
            "raspi-pico1" => Some(raspi_pico::MEMORY_LAYOUT),
            "raspi-pico2" => Some(raspi_pico2::MEMORY_LAYOUT),
            _ => None,
        }
    }};
}

pub fn execution_env() -> &'static str {
    match option_env!("OXIDE_SE_EXECUTION_ENV") {
        Some(execution_env) => execution_env,
        None => "hardware",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultSecurityDomainKind {
    NullSecurityDomain,
    KernelSecurityDomain,
    RustletSecurityDomainProxy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelScp03Profile {
    S8,
    S16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelScp11Profiles {
    bits: u8,
}

impl KernelScp11Profiles {
    const A: u8 = 0b001;
    const B: u8 = 0b010;
    const C: u8 = 0b100;

    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    pub const fn supports(self, profile: crate::core::scp11::Scp11Profile) -> bool {
        let bit = match profile {
            crate::core::scp11::Scp11Profile::A => Self::A,
            crate::core::scp11::Scp11Profile::B => Self::B,
            crate::core::scp11::Scp11Profile::C => Self::C,
        };
        (self.bits & bit) != 0 && scp11_profile_compiled(profile)
    }

    pub const fn supports_pso_certificate(self) -> bool {
        self.supports(crate::core::scp11::Scp11Profile::A)
            || self.supports(crate::core::scp11::Scp11Profile::C)
    }

    pub const fn mutual_authenticate_profile(self) -> Option<crate::core::scp11::Scp11Profile> {
        match (
            self.supports(crate::core::scp11::Scp11Profile::A),
            self.supports(crate::core::scp11::Scp11Profile::C),
        ) {
            (true, false) => Some(crate::core::scp11::Scp11Profile::A),
            (false, true) => Some(crate::core::scp11::Scp11Profile::C),
            _ => None,
        }
    }

    pub const fn internal_authenticate_profile(self) -> Option<crate::core::scp11::Scp11Profile> {
        if self.supports(crate::core::scp11::Scp11Profile::B) {
            Some(crate::core::scp11::Scp11Profile::B)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureChannelMode {
    None,
    Identity,
    Scp03Only,
    Scp11Only,
    Scp03AndScp11,
}

impl SecureChannelMode {
    pub const fn supports_scp03(self) -> bool {
        matches!(self, Self::Scp03Only | Self::Scp03AndScp11)
    }

    pub const fn supports_scp11(self) -> bool {
        matches!(self, Self::Scp11Only | Self::Scp03AndScp11)
    }

    pub const fn is_identity(self) -> bool {
        matches!(self, Self::Identity)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildAid {
    pub bytes: [u8; 16],
    pub len: u8,
}

pub const DEFAULT_ROOT_SECURITY_DOMAIN_AID: BuildAid = BuildAid {
    bytes: [
        0xa0, 0x00, 0x00, 0x47, 0x50, 0x4f, 0x53, 0x01, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    len: 8,
};

pub fn default_security_domain_kind() -> DefaultSecurityDomainKind {
    match option_env!("OXIDE_SE_DEFAULT_SECURITY_DOMAIN") {
        Some("KernelSecurityDomain") => DefaultSecurityDomainKind::KernelSecurityDomain,
        Some("RustletSecurityDomainProxy") => DefaultSecurityDomainKind::RustletSecurityDomainProxy,
        Some("NullSecurityDomain") | None => DefaultSecurityDomainKind::NullSecurityDomain,
        Some(_) => {
            // core/build.rs rejects unknown values before normal builds reach
            // this fallback.
            DefaultSecurityDomainKind::NullSecurityDomain
        }
    }
}

pub const fn kernel_scp03_profile() -> KernelScp03Profile {
    if cfg!(oxide_se_scp03_profile_s16) {
        KernelScp03Profile::S16
    } else {
        KernelScp03Profile::S8
    }
}

pub fn root_security_domain_aid() -> BuildAid {
    match option_env!("OXIDE_SE_ROOT_SECURITY_DOMAIN_AID") {
        Some(hex) => parse_hex_aid(hex).unwrap_or(DEFAULT_ROOT_SECURITY_DOMAIN_AID),
        None => DEFAULT_ROOT_SECURITY_DOMAIN_AID,
    }
}

#[inline(always)]
pub fn secure_channel_mode() -> SecureChannelMode {
    match option_env!("OXIDE_SE_SECURE_CHANNEL_MODE") {
        Some("None") => SecureChannelMode::None,
        Some("Identity") => SecureChannelMode::Identity,
        Some("Scp03Only") => SecureChannelMode::Scp03Only,
        Some("Scp11Only" | "Scp11cOnly") => SecureChannelMode::Scp11Only,
        Some("Scp03AndScp11" | "Scp03AndScp11c") => SecureChannelMode::Scp03AndScp11,
        Some(_) => match default_security_domain_kind() {
            DefaultSecurityDomainKind::NullSecurityDomain => SecureChannelMode::None,
            DefaultSecurityDomainKind::KernelSecurityDomain
            | DefaultSecurityDomainKind::RustletSecurityDomainProxy => SecureChannelMode::Scp03Only,
        },
        None => match default_security_domain_kind() {
            DefaultSecurityDomainKind::NullSecurityDomain => SecureChannelMode::None,
            DefaultSecurityDomainKind::KernelSecurityDomain
            | DefaultSecurityDomainKind::RustletSecurityDomainProxy => SecureChannelMode::Scp03Only,
        },
    }
}

pub const fn scp11_profile_compiled(profile: crate::core::scp11::Scp11Profile) -> bool {
    match profile {
        crate::core::scp11::Scp11Profile::A => cfg!(oxide_se_scp11_profile_a),
        crate::core::scp11::Scp11Profile::B => cfg!(oxide_se_scp11_profile_b),
        crate::core::scp11::Scp11Profile::C => cfg!(oxide_se_scp11_profile_c),
    }
}

pub fn scp11_profiles() -> KernelScp11Profiles {
    let mut profiles = KernelScp11Profiles::empty();
    let mut bytes = option_env!("OXIDE_SE_SCP11_PROFILES")
        .unwrap_or("C")
        .as_bytes();
    while !bytes.is_empty() {
        match bytes[0] {
            b'A' => profiles.bits |= KernelScp11Profiles::A,
            b'B' => profiles.bits |= KernelScp11Profiles::B,
            b'C' => profiles.bits |= KernelScp11Profiles::C,
            _ => {}
        }
        bytes = &bytes[1..];
    }
    profiles
}

fn parse_hex_aid(hex: &str) -> Option<BuildAid> {
    let bytes = hex.as_bytes();
    if bytes.len() < 10 || bytes.len() > 32 || !bytes.len().is_multiple_of(2) {
        return None;
    }

    let mut aid = BuildAid {
        bytes: [0; 16],
        len: (bytes.len() / 2) as u8,
    };
    let mut index = 0;
    while index < aid.len as usize {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        aid.bytes[index] = (high << 4) | low;
        index += 1;
    }
    Some(aid)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn mpu_region_policy() -> MpuRegionPolicy {
    match board() {
        "mps2-an385" => MpuRegionPolicy::strict_power_of_two(),
        "olimex-stm32-h405" => MpuRegionPolicy::strict_power_of_two(),
        "b-l475e-iot01a" => MpuRegionPolicy::strict_power_of_two(),
        "raspi-pico1" => MpuRegionPolicy::strict_power_of_two(),
        "raspi-pico2" => MpuRegionPolicy::relaxed_32_byte(),
        _ => MpuRegionPolicy::unsupported(),
    }
}

/// Static base used by the kernel FAE payload.
#[cfg(oxide_se_board_mps2_an385)]
pub const FAE_STATIC_BASE: usize = mps2_an385::MEMORY_LAYOUT.ram_base
    + mps2_an385::MEMORY_LAYOUT.kernel_stack_size
    + BOOT_ABI_SIZE;

/// Static base used by the kernel FAE payload.
#[cfg(oxide_se_board_olimex_stm32_h405)]
pub const FAE_STATIC_BASE: usize = olimex_stm32_h405::MEMORY_LAYOUT.ram_base
    + olimex_stm32_h405::MEMORY_LAYOUT.kernel_stack_size
    + BOOT_ABI_SIZE;

/// Static base used by the kernel FAE payload.
#[cfg(oxide_se_board_b_l475e_iot01a)]
pub const FAE_STATIC_BASE: usize = b_l475e_iot01a::MEMORY_LAYOUT.ram_base
    + b_l475e_iot01a::MEMORY_LAYOUT.kernel_stack_size
    + BOOT_ABI_SIZE;

/// Static base used by the kernel FAE payload.
#[cfg(oxide_se_board_raspi_pico)]
pub const FAE_STATIC_BASE: usize = raspi_pico::MEMORY_LAYOUT.ram_base
    + raspi_pico::MEMORY_LAYOUT.kernel_stack_size
    + BOOT_ABI_SIZE;

/// Static base used by the kernel FAE payload.
#[cfg(oxide_se_board_raspi_pico2)]
pub const FAE_STATIC_BASE: usize = raspi_pico2::MEMORY_LAYOUT.ram_base
    + raspi_pico2::MEMORY_LAYOUT.kernel_stack_size
    + BOOT_ABI_SIZE;

pub fn initialize() {
    dispatch_target_board!(initialize(), generic::initialize())
}

pub fn syscall_initialize() {
    app_target_profile::syscall_initialize();
}

pub fn install_syscall_handler(
    number: crate::core::syscall::SyscallNumber,
    handler: crate::core::syscall::SyscallHandler,
) {
    app_target_profile::install_syscall_handler(number, handler);
}

pub fn syscall_table_debug_addr() -> usize {
    app_target_profile::syscall_table_debug_addr()
}

pub fn syscall_handler_debug_addr(number: crate::core::syscall::SyscallNumber) -> usize {
    app_target_profile::syscall_handler_debug_addr(number)
}

pub fn enable_interrupts() {
    app_target_profile::enable_interrupts();
}

pub fn disable_interrupts() {
    app_target_profile::disable_interrupts();
}

pub fn periodic_timer_initialize(tick_hz: u32) -> bool {
    #[cfg(all(not(test), target_arch = "arm"))]
    {
        return common_arm_m_profile::periodic_timer_initialize(
            dispatch_target_board!(timer_clock_hz(), generic::timer_clock_hz()),
            tick_hz,
        );
    }
    #[cfg(any(test, not(target_arch = "arm")))]
    {
        let _ = tick_hz;
        false
    }
}

pub fn periodic_timer_disable() {
    #[cfg(all(not(test), target_arch = "arm"))]
    common_arm_m_profile::periodic_timer_disable();
}

pub fn request_syscall_thread_redirect(pc: usize, r0: usize, r1: usize) {
    app_target_profile::request_syscall_thread_redirect(pc, r0, r1);
}

pub fn kernel_stack_guard_initialize() {
    app_target_profile::kernel_stack_guard_initialize();
}

pub fn kernel_stack_overflow_protection() {
    let Some(layout) = ram_layout() else {
        return;
    };
    app_target_profile::kernel_stack_overflow_protection(crate::core::isolation::AppMemoryWindow {
        start: layout.ram_base,
        len: layout.kernel_stack_size,
    });
}

pub fn app_stack_overflow_protection(stack: Option<crate::core::isolation::AppMemoryWindow>) {
    app_target_profile::app_stack_overflow_protection(stack);
}

pub fn kernel_stack_guard_test_touch() {
    app_target_profile::kernel_stack_guard_test_touch()
}

pub fn kernel_ram_execute_never_test_touch() -> bool {
    app_target_profile::kernel_ram_execute_never_test_touch()
}

pub fn mpu_enable() -> crate::core::mpu::MpuResult<()> {
    app_target_profile::mpu_enable()
}

pub fn mpu_disable() -> crate::core::mpu::MpuResult<()> {
    app_target_profile::mpu_disable()
}

pub fn mpu_set_region(
    region: crate::core::mpu::MpuRegion,
    config: &crate::core::mpu::MpuRegionConfig,
) -> crate::core::mpu::MpuResult<()> {
    app_target_profile::mpu_set_region(region, config)
}

pub fn mpu_unset_region(region: crate::core::mpu::MpuRegion) -> crate::core::mpu::MpuResult<()> {
    app_target_profile::mpu_unset_region(region)
}

pub(crate) fn protect_kernel_nx(enabled: bool) {
    app_target_profile::protect_kernel_nx(enabled)
}

#[inline(always)]
pub(crate) unsafe fn mpu_set_region_executable_unchecked(
    region: crate::core::mpu::MpuRegion,
    executable: bool,
) {
    app_target_profile::mpu_set_region_executable_unchecked(region, executable)
}

pub fn run_isolated_app(
    entry_pc: usize,
    app_gp: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    stack_top: usize,
) -> Option<crate::core::isolation::AppReturnRegisters> {
    app_target_profile::run_isolated_app(entry_pc, app_gp, arg0, arg1, arg2, arg3, stack_top)
}

pub fn isolated_app_gate_region() -> Option<AppGateRegion> {
    app_target_profile::isolated_app_gate_region()
}

fn ram_layout() -> Option<layout::TargetMemoryLayout> {
    target_board_memory_layout!()
}

pub fn kernel_stack_guard_window() -> Option<(usize, usize)> {
    let layout = ram_layout()?;
    const GUARD_SIZE: usize = 1024 * 1024;
    Some((layout.ram_base - GUARD_SIZE, GUARD_SIZE))
}

#[allow(dead_code)]
pub(crate) fn kernel_ram_execute_never_windows() -> [Option<KernelNxWindow>; 2] {
    let Some(layout) = ram_layout() else {
        return [None, None];
    };
    kernel_ram_execute_never_windows_for_layout(layout)
}

#[allow(dead_code)]
fn kernel_ram_execute_never_windows_for_layout(
    layout: layout::TargetMemoryLayout,
) -> [Option<KernelNxWindow>; 2] {
    if layout.name == "raspi-pico2" {
        return [
            None,
            Some(KernelNxWindow {
                region: 6,
                base_addr: layout.ram_base,
                size: layout.ram_size - PICO2_EXECUTABLE_RAM_SIZE,
            }),
        ];
    }
    if layout.name == "raspi-pico1" {
        return [
            Some(KernelNxWindow {
                region: 5,
                base_addr: layout.ram_base,
                size: RASPI_PICO_KERNEL_MUTABLE_RAM_LOW_SIZE,
            }),
            Some(KernelNxWindow {
                region: 6,
                base_addr: layout.ram_base + RASPI_PICO_KERNEL_MUTABLE_RAM_LOW_SIZE,
                size: RASPI_PICO_KERNEL_MUTABLE_RAM_HIGH_SIZE,
            }),
        ];
    }

    if !layout.ram_size.is_power_of_two() || !layout.ram_base.is_multiple_of(layout.ram_size) {
        return [None, None];
    }

    [
        None,
        Some(KernelNxWindow {
            region: 6,
            base_addr: layout.ram_base,
            size: layout.ram_size,
        }),
    ]
}

#[cfg(test)]
// Layout policy tests stay adjacent to the private policy function they cover.
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::{kernel_ram_execute_never_windows_for_layout, layout::TargetMemoryLayout};

    #[test]
    fn pico2_nx_excludes_the_executable_tail_without_power_of_two_rounding() {
        let windows = kernel_ram_execute_never_windows_for_layout(TargetMemoryLayout {
            name: "raspi-pico2",
            ram_base: 0x2000_0000,
            ram_size: 520 * 1024,
            flash_base: 0x1000_0000,
            flash_size: 4 * 1024 * 1024,
            kernel_heap_min_size: 16 * 1024,
            kernel_stack_size: 8 * 1024,
        });
        assert_eq!(windows[0], None);
        let window = windows[1].unwrap();
        assert_eq!(window.region, 6);
        assert_eq!(window.base_addr, 0x2000_0000);
        assert_eq!(window.size, 504 * 1024);
        assert_eq!(window.base_addr + window.size, 0x2007_e000);
        assert_eq!(window.size % 32, 0);
    }

    #[test]
    fn kernel_ram_xn_window_accepts_one_strict_power_of_two_ram_region() {
        let layout = TargetMemoryLayout {
            name: "test-board",
            ram_base: 0x2000_0000,
            ram_size: 128 * 1024,
            flash_base: 0,
            flash_size: 0,
            kernel_heap_min_size: 0,
            kernel_stack_size: 0,
        };

        assert_eq!(
            kernel_ram_execute_never_windows_for_layout(layout),
            [
                None,
                Some(super::KernelNxWindow {
                    region: 6,
                    base_addr: 0x2000_0000,
                    size: 128 * 1024,
                }),
            ]
        );
    }

    #[test]
    fn kernel_ram_xn_window_opts_out_when_one_strict_region_cannot_cover_ram() {
        let layout = TargetMemoryLayout {
            name: "odd-sized-board",
            ram_base: 0x2000_0000,
            ram_size: 96 * 1024,
            flash_base: 0,
            flash_size: 0,
            kernel_heap_min_size: 0,
            kernel_stack_size: 0,
        };

        assert_eq!(
            kernel_ram_execute_never_windows_for_layout(layout),
            [None, None]
        );
    }

    #[test]
    fn kernel_ram_xn_windows_cover_pico_mutable_ram_below_critical_code() {
        let layout = TargetMemoryLayout {
            name: "raspi-pico1",
            ram_base: 0x2000_0000,
            ram_size: 264 * 1024,
            flash_base: 0x1000_0000,
            flash_size: 2 * 1024 * 1024,
            kernel_heap_min_size: 15 * 1024 + 512,
            kernel_stack_size: 7 * 1024,
        };

        assert_eq!(
            kernel_ram_execute_never_windows_for_layout(layout),
            [
                Some(super::KernelNxWindow {
                    region: 5,
                    base_addr: 0x2000_0000,
                    size: 32 * 1024,
                }),
                Some(super::KernelNxWindow {
                    region: 6,
                    base_addr: 0x2000_8000,
                    size: 16 * 1024,
                }),
            ]
        );
    }
}

pub fn boot_abi_region() -> Option<BootAbiRegion> {
    let layout = ram_layout()?;

    let base = layout.ram_base + layout.kernel_stack_size;
    Some(BootAbiRegion {
        base,
        size: BOOT_ABI_SIZE,
        svc_forward: base,
        memmanage_forward: base + 4,
        usagefault_forward: base + 8,
        periodic_timer_forward: base + 12,
    })
}

pub fn kernel_heap_end() -> Option<usize> {
    let layout = ram_layout()?;
    if layout.name == "raspi-pico2" {
        return Some(layout.ram_base + layout.ram_size - PICO2_EXECUTABLE_RAM_SIZE);
    }
    if layout.name == "raspi-pico1" {
        return Some(layout.ram_base + RASPI_PICO_KERNEL_MUTABLE_RAM_SIZE);
    }
    Some(layout.ram_base + layout.ram_size)
}

pub fn last_mem_manage_fault() -> Option<crate::core::isolation::MemoryFaultInfo> {
    app_target_profile::last_mem_manage_fault()
}

pub fn send_byte(byte: u8) {
    dispatch_target_board!(send_byte(byte), generic::send_byte(byte))
}

pub fn try_send_byte(byte: u8) -> bool {
    dispatch_target_board!(try_send_byte(byte), generic::try_send_byte(byte))
}

pub fn debug_write_byte(byte: u8) {
    dispatch_target_board!(debug_write_byte(byte), generic::debug_write_byte(byte))
}

pub fn receive_byte() -> u8 {
    dispatch_target_board!(receive_byte(), generic::receive_byte())
}

pub fn shutdown(exit_code: i32) -> ! {
    dispatch_target_board!(shutdown(exit_code), generic::shutdown(exit_code))
}

pub fn flash_initialize() {
    dispatch_target_board!(flash_initialize(), generic::flash_initialize())
}

pub fn flash_logical_page_size() -> usize {
    dispatch_target_board!(
        flash_logical_page_size(),
        generic::flash_logical_page_size()
    )
}

pub fn flash_erase_sector_size() -> usize {
    dispatch_target_board!(
        flash_erase_sector_size(),
        generic::flash_erase_sector_size()
    )
}

pub fn flash_persistence_area() -> crate::core::flash::FlashPersistenceArea {
    dispatch_target_board!(flash_persistence_area(), generic::flash_persistence_area())
}

pub fn flash_erase_sector(sector_addr: usize) -> crate::core::flash::FlashResult<()> {
    dispatch_target_board!(
        flash_erase_sector(sector_addr),
        generic::flash_erase_sector(sector_addr)
    )
}

pub fn flash_write_page(page_addr: usize, page_buf: &[u8]) -> crate::core::flash::FlashResult<()> {
    dispatch_target_board!(
        flash_write_page(page_addr, page_buf),
        generic::flash_write_page(page_addr, page_buf)
    )
}

pub fn flash_flush_page(page_addr: usize) -> crate::core::flash::FlashResult<()> {
    dispatch_target_board!(
        flash_flush_page(page_addr),
        generic::flash_flush_page(page_addr)
    )
}

pub fn flash_write_page_atomic(
    page_addr: usize,
    page_buf: &[u8],
) -> crate::core::flash::FlashResult<()> {
    dispatch_target_board!(
        flash_write_page_atomic(page_addr, page_buf),
        generic::flash_write_page_atomic(page_addr, page_buf)
    )
}

pub fn crypto_initialize() {
    if execution_env() == "qemu" {
        return;
    }

    dispatch_target_board!(crypto_initialize(), generic::crypto_initialize())
}

pub fn crypto_fill_random(buf: &mut [u8]) -> crate::core::crypto::CryptoResult<()> {
    if execution_env() == "qemu" && board() != "raspi-pico1" {
        return crate::core::semihosting::fill_random(buf);
    }

    dispatch_target_board!(crypto_fill_random(buf), generic::crypto_fill_random(buf))
}

pub fn crypto_aes_cbc_encrypt_in_place(
    key: &crate::core::crypto::AesKey,
    iv: &[u8; crate::core::crypto::AES_BLOCK_SIZE],
    buf: &mut [u8],
) -> crate::core::crypto::CryptoResult<()> {
    // Software AES fallback is currently intentional on mps2-an385 and
    // olimex-stm32-h405. b-l475e-iot01a still routes here until its hardware
    // AES block is wired into the target backend.
    generic::crypto_aes_cbc_encrypt_in_place(key, iv, buf)
}

pub fn crypto_aes_cbc_decrypt_in_place(
    key: &crate::core::crypto::AesKey,
    iv: &[u8; crate::core::crypto::AES_BLOCK_SIZE],
    buf: &mut [u8],
) -> crate::core::crypto::CryptoResult<()> {
    // See the note above: AES decryption currently shares the same software
    // fallback path on every target.
    generic::crypto_aes_cbc_decrypt_in_place(key, iv, buf)
}

pub fn crypto_aes_cmac(
    key: &crate::core::crypto::AesKey,
    input: &[u8],
    out: &mut [u8; crate::core::crypto::AES_CMAC_SIZE],
) -> crate::core::crypto::CryptoResult<()> {
    // CMAC follows the same backend policy as AES-CBC for now.
    generic::crypto_aes_cmac(key, input, out)
}

pub fn crypto_scp03_kdf(
    key: &crate::core::crypto::AesKey,
    derivation_constant: u8,
    context: &[u8],
    out: &mut [u8],
) -> crate::core::crypto::CryptoResult<()> {
    generic::crypto_scp03_kdf(key, derivation_constant, context, out)
}

pub fn crypto_p256_generate_keypair(
    private_out: &mut [u8],
    public_out: &mut [u8],
) -> crate::core::crypto::CryptoResult<()> {
    generic::crypto_p256_generate_keypair(private_out, public_out)
}

pub fn crypto_p256_ecdh(
    private_key: &[u8],
    peer_public: &[u8],
    out: &mut [u8],
) -> crate::core::crypto::CryptoResult<()> {
    generic::crypto_p256_ecdh(private_key, peer_public, out)
}
