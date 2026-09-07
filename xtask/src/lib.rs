use std::env;
use std::error::Error;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use apdu_tool::{OwnedT0Command, T0Response};
use hkdf::Hkdf;
use oxi_core::core::gp_sm;
use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use testing::scenarios::*;
use testing::{BuildContext, TestContext};

pub const DEFAULT_BOARD: &str = "mps2-an385";
const QEMU_TEST_TIMEOUT: Duration = Duration::from_secs(15);
const TARGET_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
// First boot may install instances and commit flash before emitting ATR.
// This is a host wall-clock initialization allowance, not an ISO ATR timing claim.
const TARGET_INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(120);
const APDU_RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);
const APDU_FRAME_TIMEOUT: Duration = Duration::from_millis(200);
const APDU_BYTE_PACING: Duration = Duration::from_millis(1);
const KERNEL_CRYPTO_BENCH_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const BOOT_ABI_SIZE: usize = 0x20;
const ALLOCATION_GRANULE: usize = 8;
const STACK_HIGH_WATERMARK_UNKNOWN: usize = usize::MAX;
const KERNEL_STACK_HIGH_WATERMARK_BUDGET_BYTES: usize = 6 * 1024;
const STACK_BASELINES_PATH: &str = "xtask/stack-baselines.toml";
const STACK_MONITOR_PROFILE: &str = "apdu-observer-v2";
const LEGACY_STACK_MONITOR_PROFILE: &str = "kernel-only-v1";
static SELECTED_TRACE_MODE: AtomicUsize = AtomicUsize::new(TraceMode::None as usize);

#[derive(Clone, Debug, PartialEq, Eq)]
struct StackObservation {
    label: String,
    high_watermark: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceMode {
    None = 0,
    Semihosting = 1,
    Jtag = 2,
}

impl TraceMode {
    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "none" => Ok(Self::None),
            "semihosting" => Ok(Self::Semihosting),
            "jtag" => Ok(Self::Jtag),
            _ => Err(format!(
                "unknown --trace mode `{value}`; expected none, semihosting, or jtag"
            )
            .into()),
        }
    }

    fn env_value(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Semihosting => "semihosting",
            Self::Jtag => "jtag",
        }
    }

    fn from_usize(value: usize) -> Self {
        match value {
            1 => Self::Semihosting,
            2 => Self::Jtag,
            _ => Self::None,
        }
    }
}

mod testing;
const SCP03_TEST_ENC_KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];
const SCP03_TEST_MAC_KEY: [u8; 16] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
];
const SCP03_ROTATED_ENC_KEY: [u8; 16] = [
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
];
const SCP03_ROTATED_MAC_KEY: [u8; 16] = [
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
];
const SECURITY_DOMAIN_INSTALL_PRIVILEGES: [u8; 3] = [0xFF, 0xFF, 0xF0];
const SCP03_KDF_CARD_CRYPTOGRAM: u8 = 0x00;
const SCP03_KDF_HOST_CRYPTOGRAM: u8 = 0x01;
const SCP03_KDF_S_ENC: u8 = 0x04;
const SCP03_KDF_S_MAC: u8 = 0x06;
const SCP03_KDF_S_RMAC: u8 = 0x07;
const SCP11C_DEV_CA_PRIVATE_KEY: [u8; 32] = [
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
];
const SCP11_DEV_CARD_STATIC_PRIVATE_KEY: [u8; 32] = [
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
];
const SCP11C_KEY_USAGE_FULL: u8 = 0x3C;
const SCP11_KEY_USAGE_MACS: u8 = 0x34;
const SCP11C_KEY_USAGE_COMMAND_ONLY: u8 = 0x1C;
const SCP11C_KEY_USAGE_COMMAND_ENC_RESPONSE_MAC: u8 = 0x74;
const SCP11C_KEY_TYPE_AES: u8 = 0x88;
const SCP11C_KEY_LENGTH_AES_128: u8 = 0x10;
const OXIDE_SE_SCP11C_HOST_ID: &[u8] = b"oxide-se-host";
const OXIDE_SE_SCP11_SIN: &[u8] = b"oxide-se-sin";
const OXIDE_SE_SCP11_SDIN: &[u8] = b"oxide-se-sdin";
const OXIDE_SE_SCP11_CARD_GROUP_ID: &[u8] = b"oxide-se-card";
const SCP11_IDENTIFIER_FAMILY: u8 = 0x11;
const SCP11A_IDENTIFIER_PARAM: u8 = 0x05;
const SCP11B_IDENTIFIER_PARAM: u8 = 0x04;
const SCP11C_IDENTIFIER_PARAM: u8 = 0x07;
const ATR_PREFIX: [u8; 4] = [0x3B, 0x1C, 0x11, 0x80];
const ATR_OXIDE_SE_COMPACT_TLV_HEADER: u8 = 0x56;
const ATR_OXIDE_SE_MARKER: [u8; 4] = [0x09, 0xC1, 0xDE, 0x5E];
const ATR_OXIDE_SE_VERSION: u8 = 0x09;
const ATR_CARD_CAPABILITIES_COMPACT_TLV: [u8; 4] = [0x73, 0x80, 0x00, 0x00];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostScp03Profile {
    S8,
    S16,
}

#[derive(Clone, Copy, Debug)]
pub enum HostScp03Selection {
    Single(HostScp03Profile),
    All,
}

impl HostScp03Selection {
    fn from_cli(value: &str) -> Result<Self, Box<dyn Error>> {
        match value.to_ascii_lowercase().as_str() {
            "s8" => Ok(Self::Single(HostScp03Profile::S8)),
            "s16" => Ok(Self::Single(HostScp03Profile::S16)),
            "all" => Ok(Self::All),
            _ => Err(
                format!("unsupported SCP03 selection `{value}`; expected s8, s16 or all").into(),
            ),
        }
    }

    fn is_cli_value(value: &str) -> bool {
        matches!(value.to_ascii_lowercase().as_str(), "s8" | "s16" | "all")
    }

    fn stack_scenario(self) -> &'static str {
        match self {
            Self::Single(HostScp03Profile::S8) => "s8",
            Self::Single(HostScp03Profile::S16) => "s16",
            Self::All => "all",
        }
    }
}

impl HostScp03Profile {
    fn log_suffix(self) -> &'static str {
        match self {
            Self::S8 => "s8",
            Self::S16 => "s16",
        }
    }

    fn challenge(self) -> &'static [u8] {
        match self {
            Self::S8 => &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            Self::S16 => &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                0x17, 0x18,
            ],
        }
    }

    fn cryptogram_len(self) -> usize {
        match self {
            Self::S8 => 8,
            Self::S16 => 16,
        }
    }

    fn mac_len(self) -> usize {
        match self {
            Self::S8 => 8,
            Self::S16 => 16,
        }
    }
}

pub fn main_entry() -> Result<(), Box<dyn Error>> {
    let (mode, explicit_config) = parse_cli(env::args().skip(1))?;
    match mode {
        Mode::Test(invocation) => {
            if invocation.update_stack_baseline {
                ensure_clean_git_worktree(&repo_root()?)?;
            }
            let config = match explicit_config {
                Some(path) => Some(path),
                None => resolve_predeployment_config_for_scenario(&invocation.scenario)?,
            };
            let ctx = TestContext {
                build: BuildContext {
                    config,
                    trace: invocation.trace,
                    check_stack: scenario_checks_stack(&invocation.scenario),
                    without_rustlets: invocation.without_rustlets,
                    ..BuildContext::default()
                },
                target: invocation.target,
                update_stack_baseline: invocation.update_stack_baseline,
                apdu_observer: None,
            };
            testing::run(&ctx, invocation.scenario)
        }
        Mode::Help(command) => {
            print_help(command.as_deref());
            Ok(())
        }
        Mode::Clean => clean_repo_build_outputs(),
        Mode::Build {
            image_format,
            board,
        } => match image_format {
            LayoutImageFormat::Elf => build_firmware(
                &BuildContext {
                    config: explicit_config,
                    trace: selected_trace_mode(),
                    ..BuildContext::default()
                },
                FirmwareKind::GpKernel,
                None,
                &board,
                "hardware",
            ),
            LayoutImageFormat::Fae => build_firmware(
                &BuildContext {
                    config: explicit_config,
                    trace: selected_trace_mode(),
                    ..BuildContext::default()
                },
                FirmwareKind::GpKernel,
                Some(Packaging::Bootable(board_spec(&board)?)),
                &board,
                "hardware",
            ),
        },
        Mode::DumpKernelLayout {
            image_format,
            board,
            profile,
        } => dump_kernel_layout(
            &BuildContext {
                config: explicit_config,
                trace: selected_trace_mode(),
                ..BuildContext::default()
            },
            image_format,
            &board,
            profile.as_deref(),
        ),
    }
}

fn scenario_checks_stack(scenario: &Scenario) -> bool {
    match scenario {
        Scenario::KernelPing { check_stack, .. }
        | Scenario::GpScp03 { check_stack, .. }
        | Scenario::GpScp11c { check_stack, .. }
        | Scenario::GpScp11a { check_stack, .. }
        | Scenario::GpScp11b { check_stack, .. }
        | Scenario::GpRustletSecurityDomainScp03 { check_stack, .. }
        | Scenario::GpRustletSecurityDomainDelegatedScp03 { check_stack, .. }
        | Scenario::GpRustletSecurityDomainScp11a { check_stack, .. }
        | Scenario::GpRustletSecurityDomainScp11b { check_stack, .. }
        | Scenario::GpRustletSecurityDomainScp11c { check_stack, .. }
        | Scenario::RustletSingle { check_stack, .. }
        | Scenario::RustletAll { check_stack, .. } => *check_stack,
        _ => false,
    }
}

fn generate_stack_monitor_config(source: Option<&Path>) -> Result<PathBuf, Box<dyn Error>> {
    const STACK_MONITOR_MODULES: &[&str] = &["kernel-stack-monitor", "rustlet-stack-monitor"];

    let repo_root = repo_root()?;
    let source = source
        .map(Path::to_path_buf)
        .unwrap_or_else(|| repo_root.join(default_predeployment_config_relpath(&repo_root)));
    let source = if source.is_absolute() {
        source
    } else {
        repo_root.join(source)
    };
    let input = fs::read_to_string(&source).map_err(|err| {
        format!(
            "failed to read stack-monitor source manifest {}: {err}",
            source.display()
        )
    })?;
    let mut manifest: toml::Value = toml::from_str(&input).map_err(|err| {
        format!(
            "failed to parse stack-monitor source manifest {}: {err}",
            source.display()
        )
    })?;
    let root = manifest
        .as_table_mut()
        .ok_or("stack-monitor source manifest must be a TOML table")?;
    let kernel_image = root
        .entry("kernel-image")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or("kernel-image must be a TOML table")?;
    let modules = kernel_image
        .entry("kernel-app-modules")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or("kernel-image.kernel-app-modules must be an array")?;
    for module in STACK_MONITOR_MODULES {
        if !modules.iter().any(|value| value.as_str() == Some(module)) {
            modules.push(toml::Value::String((*module).to_owned()));
        }
    }

    let output_dir = repo_root.join("target/xtask/generated-configs");
    fs::create_dir_all(&output_dir)?;
    let stem = source
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("config");
    let output = output_dir.join(format!("{stem}_stack_monitor.toml"));
    fs::write(&output, toml::to_string_pretty(&manifest)?)?;
    Ok(output)
}

fn resolve_predeployment_config_for_scenario(
    scenario: &Scenario,
) -> Result<Option<PathBuf>, Box<dyn Error>> {
    if let Some(path) = testing::config_for_scenario(scenario) {
        return Ok(Some(path));
    }
    match scenario {
        Scenario::RustletSingle { rustlet, .. } => {
            Ok(Some(generate_single_rustlet_config(rustlet)?))
        }
        _ => Ok(None),
    }
}

#[derive(Debug, Clone)]
enum Mode {
    Test(testing::TestInvocation),
    Help(Option<String>),
    Clean,
    Build {
        image_format: LayoutImageFormat,
        board: String,
    },
    DumpKernelLayout {
        image_format: LayoutImageFormat,
        board: String,
        profile: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum Scenario {
    KernelStackGuard(String),
    KernelRamNx(String),
    KernelPing {
        board: String,
        check_stack: bool,
    },
    KernelT0(String),
    KernelTimer(String),
    KernelNullByte(String),
    KernelFlash(String),
    KernelRegistry(String),
    KernelCrypto {
        board: String,
        bench: Option<KernelCryptoBench>,
    },
    GpNoScp {
        image_format: LayoutImageFormat,
        board: String,
    },
    GpScp03 {
        image_format: LayoutImageFormat,
        board: String,
        scp03_selection: HostScp03Selection,
        check_stack: bool,
    },
    GpScp11c {
        image_format: LayoutImageFormat,
        board: String,
        check_stack: bool,
    },
    GpScp11a {
        image_format: LayoutImageFormat,
        board: String,
        check_stack: bool,
    },
    GpScp11b {
        image_format: LayoutImageFormat,
        board: String,
        check_stack: bool,
    },
    GpSecurityDomain {
        image_format: LayoutImageFormat,
        board: String,
    },
    GpPredeployment {
        image_format: LayoutImageFormat,
        board: String,
    },
    GpRegistry {
        image_format: LayoutImageFormat,
        board: String,
    },
    GpPersistence {
        board: String,
    },
    GpAll {
        image_format: LayoutImageFormat,
        board: String,
    },
    GpScp03InstallLoad {
        board: String,
    },
    GpScp11aInstallLoad {
        board: String,
    },
    GpRustletSecurityDomainScp03 {
        image_format: LayoutImageFormat,
        board: String,
        check_stack: bool,
    },
    GpRustletSecurityDomainDelegatedScp03 {
        image_format: LayoutImageFormat,
        board: String,
        check_stack: bool,
    },
    GpRustletSecurityDomainScp11a {
        image_format: LayoutImageFormat,
        board: String,
        check_stack: bool,
    },
    GpRustletSecurityDomainScp11b {
        image_format: LayoutImageFormat,
        board: String,
        check_stack: bool,
    },
    GpRustletSecurityDomainScp11c {
        image_format: LayoutImageFormat,
        board: String,
        check_stack: bool,
    },
    RustletIsolation(String),
    RustletWatchdog(String),
    RustletSingle {
        image_format: LayoutImageFormat,
        board: String,
        rustlet: String,
        check_stack: bool,
    },
    RustletAll {
        image_format: LayoutImageFormat,
        board_filter: Option<String>,
        check_stack: bool,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum FirmwareKind {
    GpKernel,
    CoreTest,
}

#[derive(Debug, Clone, Copy)]
struct BoardSpec {
    machine: &'static str,
    env_name: &'static str,
    startup_dir: &'static str,
    rust_target: &'static str,
    target_source: &'static str,
    compiler_flags: &'static [&'static str],
}

struct DynamicLoadPayload {
    fae: Vec<u8>,
    hash: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
enum BoardSupportLevel {
    BuildOnly,
    KernelApdu,
    GlobalPlatformApdu,
    Rustlet,
}

impl BoardSupportLevel {
    fn label(self) -> &'static str {
        match self {
            Self::BuildOnly => "build-only",
            Self::KernelApdu => "kernel-apdu",
            Self::GlobalPlatformApdu => "global-platform-apdu",
            Self::Rustlet => "rustlet",
        }
    }

    fn supports_rustlets(self) -> bool {
        self >= Self::Rustlet
    }
}

#[derive(Debug, Clone, Copy)]
struct BoardCatalogEntry {
    spec: BoardSpec,
    support_level: BoardSupportLevel,
    qemu_support: bool,
    board_support: bool,
    /// OpenOCD target script, not a claim of completed hardware validation.
    openocd_target: Option<&'static str>,
}

const BOARD_CATALOG: &[BoardCatalogEntry] = &[
    BoardCatalogEntry {
        spec: BoardSpec {
            machine: "mps2-an385",
            env_name: "mps2-an385",
            startup_dir: "mps2-an385",
            rust_target: "thumbv7m-none-eabi",
            target_source: "kernel/core/src/core/target/mps2_an385.rs",
            compiler_flags: &["-c", "-mcpu=cortex-m3", "-mthumb"],
        },
        support_level: BoardSupportLevel::Rustlet,
        qemu_support: true,
        board_support: false,
        openocd_target: None,
    },
    BoardCatalogEntry {
        spec: BoardSpec {
            machine: "raspi-pico2",
            env_name: "raspi-pico2",
            startup_dir: "raspi-pico2",
            rust_target: "thumbv8m.main-none-eabihf",
            target_source: "kernel/core/src/core/target/raspi_pico2.rs",
            compiler_flags: &[
                "-c",
                "-mcpu=cortex-m33",
                "-mthumb",
                "-mfloat-abi=hard",
                "-mfpu=fpv5-sp-d16",
            ],
        },
        support_level: BoardSupportLevel::KernelApdu,
        qemu_support: false,
        board_support: true,
        openocd_target: Some("target/rp2350.cfg"),
    },
    BoardCatalogEntry {
        spec: BoardSpec {
            machine: "olimex-stm32-h405",
            env_name: "olimex-stm32-h405",
            startup_dir: "olimex-stm32-h405",
            rust_target: "thumbv7em-none-eabi",
            target_source: "kernel/core/src/core/target/olimex_stm32_h405.rs",
            compiler_flags: &["-c", "-mcpu=cortex-m4", "-mthumb"],
        },
        support_level: BoardSupportLevel::Rustlet,
        qemu_support: true,
        board_support: false,
        openocd_target: None,
    },
    BoardCatalogEntry {
        spec: BoardSpec {
            machine: "b-l475e-iot01a",
            env_name: "b-l475e-iot01a",
            startup_dir: "b-l475e-iot01a",
            rust_target: "thumbv7em-none-eabi",
            target_source: "kernel/core/src/core/target/b_l475e_iot01a.rs",
            compiler_flags: &["-c", "-mcpu=cortex-m4", "-mthumb"],
        },
        support_level: BoardSupportLevel::BuildOnly,
        qemu_support: false,
        board_support: false,
        openocd_target: None,
    },
    BoardCatalogEntry {
        spec: BoardSpec {
            machine: "raspi-pico",
            env_name: "raspi-pico1",
            startup_dir: "raspi-pico",
            rust_target: "thumbv6m-none-eabi",
            target_source: "kernel/core/src/core/target/raspi_pico.rs",
            compiler_flags: &["-c", "-mcpu=cortex-m0plus", "-mthumb"],
        },
        support_level: BoardSupportLevel::Rustlet,
        qemu_support: true,
        board_support: false,
        openocd_target: Some("target/rp2040.cfg"),
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TargetMemoryLayout {
    name: &'static str,
    ram_base: usize,
    ram_size: usize,
    flash_base: usize,
    flash_size: usize,
    kernel_heap_min_size: usize,
    kernel_stack_size: usize,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinkerMemoryLayout {
    ram_base: usize,
    ram_size: usize,
    flash_base: usize,
    flash_size: usize,
    kernel_stack_size: usize,
}

#[derive(Debug, Clone, Copy)]
enum Packaging {
    Fae,
    Bootable(BoardSpec),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutImageFormat {
    Fae,
    Elf,
}

impl LayoutImageFormat {
    fn name_upper(self) -> &'static str {
        match self {
            Self::Fae => "FAE",
            Self::Elf => "ELF",
        }
    }

    fn name_lower(self) -> &'static str {
        match self {
            Self::Fae => "fae",
            Self::Elf => "elf",
        }
    }
}

#[derive(Debug, Clone)]
struct FirmwareSpec {
    manifest: PathBuf,
    bin_name: &'static str,
}

#[derive(Debug, Clone)]
pub struct TestReport {
    pub total: usize,
    pub failed: usize,
    pub stdout: String,
    pub stderr: String,
}

impl TestReport {
    pub fn passed(total: usize) -> Self {
        Self {
            total,
            failed: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum KernelCryptoBench {
    FillRandom {
        len: u8,
    },
    AesCbc {
        key: Vec<u8>,
        iv: [u8; 16],
        data: Vec<u8>,
    },
    AesEcb {
        key: Vec<u8>,
        data: Vec<u8>,
    },
    AesIso9797M2 {
        key: Vec<u8>,
        iv: [u8; 16],
        data: Vec<u8>,
    },
    Cmac {
        key: Vec<u8>,
        data: Vec<u8>,
    },
    Hkdf {
        ikm: Vec<u8>,
        salt: Vec<u8>,
        len: u8,
    },
    X963 {
        shared_secret: Vec<u8>,
        shared_info: Vec<u8>,
        len: u8,
    },
    P256GenerateKeypair,
    P256Ecdh {
        private_key: [u8; 32],
        peer_public: [u8; 65],
    },
}

impl KernelCryptoBench {
    const INS_FILL_RANDOM: u8 = 0x85;
    const INS_AES_CBC: u8 = 0x86;
    const INS_AES_ECB: u8 = 0x87;
    const INS_AES_ISO9797_M2: u8 = 0x88;
    const INS_CMAC: u8 = 0x89;
    const INS_HKDF: u8 = 0x8a;
    const INS_X963: u8 = 0x8b;
    const INS_P256_GENERATE_KEYPAIR: u8 = 0x8c;
    const INS_P256_ECDH: u8 = 0x8d;

    fn parse(op: &str, args: &[String]) -> Result<Self, Box<dyn Error>> {
        match normalize_bench_op(op).as_str() {
            "fill_random" | "random" => {
                let len = parse_optional_u8_arg(args, 0, 16, "fill_random length")?;
                Ok(Self::FillRandom { len })
            }
            "aes_cbc" | "aes_cbc_encrypt" | "cbc" => {
                let key = parse_optional_hex_arg(args, 0, &default_aes256_key(), "AES key")?;
                let iv = parse_optional_hex_array_arg(args, 1, &default_aes_iv(), "AES-CBC IV")?;
                let data =
                    parse_optional_hex_arg(args, 2, &default_aes_plaintext(), "AES-CBC input")?;
                validate_aes_key_len(&key)?;
                validate_block_aligned_len(data.len(), "AES-CBC input")?;
                Ok(Self::AesCbc { key, iv, data })
            }
            "aes_ecb" | "aes_ecb_encrypt" | "ecb" => {
                let key = parse_optional_hex_arg(args, 0, &default_aes256_key(), "AES key")?;
                let data =
                    parse_optional_hex_arg(args, 1, &default_aes_plaintext(), "AES-ECB input")?;
                validate_aes_key_len(&key)?;
                validate_block_aligned_len(data.len(), "AES-ECB input")?;
                Ok(Self::AesEcb { key, data })
            }
            "aes_iso9797_m2" | "aes_cbc_iso9797_m2" | "iso9797_m2" | "iso" => {
                let key = parse_optional_hex_arg(args, 0, &default_aes256_key(), "AES key")?;
                let iv =
                    parse_optional_hex_array_arg(args, 1, &default_aes_iv(), "AES ISO9797-M2 IV")?;
                let data = parse_optional_hex_arg(
                    args,
                    2,
                    &default_unaligned_payload(),
                    "AES ISO9797-M2 input",
                )?;
                validate_aes_key_len(&key)?;
                Ok(Self::AesIso9797M2 { key, iv, data })
            }
            "cmac" | "aes_cmac" => {
                let key = parse_optional_hex_arg(args, 0, &default_aes256_key(), "CMAC key")?;
                let data = parse_optional_hex_arg(args, 1, &default_cmac_payload(), "CMAC input")?;
                validate_aes_key_len(&key)?;
                Ok(Self::Cmac { key, data })
            }
            "hkdf" | "hkdf_sha256" => {
                let ikm = parse_optional_hex_arg(args, 0, &default_kdf_secret(), "HKDF IKM")?;
                let salt = parse_optional_hex_arg(args, 1, &default_kdf_info(), "HKDF salt")?;
                let len = parse_optional_u8_arg(args, 2, 32, "HKDF output length")?;
                validate_kdf_bench_len(ikm.len(), "HKDF IKM")?;
                validate_kdf_bench_len(salt.len(), "HKDF salt")?;
                validate_kdf_output_len(len)?;
                Ok(Self::Hkdf { ikm, salt, len })
            }
            "x963" | "x963_sha256" | "x9_63" | "x9.63" => {
                let shared_secret =
                    parse_optional_hex_arg(args, 0, &default_kdf_secret(), "X9.63 shared secret")?;
                let shared_info =
                    parse_optional_hex_arg(args, 1, &default_kdf_info(), "X9.63 shared info")?;
                let len = parse_optional_u8_arg(args, 2, 32, "X9.63 output length")?;
                validate_kdf_bench_len(shared_secret.len(), "X9.63 shared secret")?;
                validate_kdf_bench_len(shared_info.len(), "X9.63 shared info")?;
                validate_kdf_output_len(len)?;
                Ok(Self::X963 {
                    shared_secret,
                    shared_info,
                    len,
                })
            }
            "p256_generate_keypair" | "p256_keygen" | "keygen" => {
                if !args.is_empty() {
                    return Err("p256_generate_keypair does not take arguments yet".into());
                }
                Ok(Self::P256GenerateKeypair)
            }
            "p256_ecdh" | "ecdh" => {
                let private_key =
                    parse_optional_hex_array_arg(args, 0, &default_p256_private_key(), "P-256 private key")?;
                let peer_public = match args.get(1) {
                    Some(value) => parse_hex_array::<65>(value, "P-256 peer public key")?,
                    None => default_p256_peer_public_key()?,
                };
                Ok(Self::P256Ecdh {
                    private_key,
                    peer_public,
                })
            }
            _ => Err(format!(
                "unknown test kernel_crypto --bench operation: {op}; expected fill_random, aes_cbc, aes_ecb, aes_iso9797_m2, cmac, hkdf, x963, p256_generate_keypair, or p256_ecdh"
            )
            .into()),
        }
    }

    fn op_name(&self) -> &'static str {
        match self {
            Self::FillRandom { .. } => "fill_random",
            Self::AesCbc { .. } => "aes_cbc",
            Self::AesEcb { .. } => "aes_ecb",
            Self::AesIso9797M2 { .. } => "aes_iso9797_m2",
            Self::Cmac { .. } => "cmac",
            Self::Hkdf { .. } => "hkdf",
            Self::X963 { .. } => "x963",
            Self::P256GenerateKeypair => "p256_generate_keypair",
            Self::P256Ecdh { .. } => "p256_ecdh",
        }
    }

    fn command(&self) -> OwnedT0Command {
        match self {
            Self::FillRandom { len } => {
                CommandBuilder::process_no_data_with_p1_and_le(Self::INS_FILL_RANDOM, *len, *len)
            }
            Self::AesCbc { key, iv, data } => {
                let mut payload = Vec::with_capacity(key.len() + iv.len() + data.len());
                payload.extend_from_slice(key);
                payload.extend_from_slice(iv);
                payload.extend_from_slice(data);
                CommandBuilder::process_with_p1_data_and_le(
                    Self::INS_AES_CBC,
                    key.len() as u8,
                    &payload,
                    data.len() as u8,
                )
            }
            Self::AesEcb { key, data } => {
                let mut payload = Vec::with_capacity(key.len() + data.len());
                payload.extend_from_slice(key);
                payload.extend_from_slice(data);
                CommandBuilder::process_with_p1_data_and_le(
                    Self::INS_AES_ECB,
                    key.len() as u8,
                    &payload,
                    data.len() as u8,
                )
            }
            Self::AesIso9797M2 { key, iv, data } => {
                let mut payload = Vec::with_capacity(key.len() + iv.len() + data.len());
                payload.extend_from_slice(key);
                payload.extend_from_slice(iv);
                payload.extend_from_slice(data);
                let le = (data.len() + 16) as u8;
                CommandBuilder::process_with_p1_data_and_le(
                    Self::INS_AES_ISO9797_M2,
                    key.len() as u8,
                    &payload,
                    le,
                )
            }
            Self::Cmac { key, data } => {
                let mut payload = Vec::with_capacity(key.len() + data.len());
                payload.extend_from_slice(key);
                payload.extend_from_slice(data);
                CommandBuilder::process_with_p1_data_and_le(
                    Self::INS_CMAC,
                    key.len() as u8,
                    &payload,
                    16,
                )
            }
            Self::Hkdf { ikm, salt, len } => {
                let mut payload = Vec::with_capacity(2 + ikm.len() + salt.len());
                push_lv(&mut payload, ikm);
                push_lv(&mut payload, salt);
                CommandBuilder::process_with_p1_data_and_le(Self::INS_HKDF, *len, &payload, *len)
            }
            Self::X963 {
                shared_secret,
                shared_info,
                len,
            } => {
                let mut payload = Vec::with_capacity(2 + shared_secret.len() + shared_info.len());
                push_lv(&mut payload, shared_secret);
                push_lv(&mut payload, shared_info);
                CommandBuilder::process_with_p1_data_and_le(Self::INS_X963, *len, &payload, *len)
            }
            Self::P256GenerateKeypair => {
                CommandBuilder::process_no_data_with_le(Self::INS_P256_GENERATE_KEYPAIR, 97)
            }
            Self::P256Ecdh {
                private_key,
                peer_public,
            } => {
                let mut payload = Vec::with_capacity(private_key.len() + peer_public.len());
                payload.extend_from_slice(private_key);
                payload.extend_from_slice(peer_public);
                CommandBuilder::process_with_data_and_le(Self::INS_P256_ECDH, &payload, 32)
            }
        }
    }

    fn verify_response(&self, response: &T0Response) -> Result<(), Box<dyn Error>> {
        if response.status != (0x90, 0x00) {
            return Err(format!(
                "{}: expected status 9000, got {:02X?}",
                self.op_name(),
                response.status
            )
            .into());
        }

        let expected = match self {
            Self::FillRandom { len } => {
                if response.data.len() != *len as usize {
                    return Err(format!(
                        "fill_random: expected {} bytes, got {}",
                        len,
                        response.data.len()
                    )
                    .into());
                }
                return Ok(());
            }
            Self::AesCbc { key, iv, data } => {
                host_aes_cbc_encrypt(key, iv, data, HostCbcPadding::None)?
            }
            Self::AesEcb { key, data } => host_aes_ecb_encrypt(key, data)?,
            Self::AesIso9797M2 { key, iv, data } => {
                host_aes_cbc_encrypt(key, iv, data, HostCbcPadding::Iso9797M2)?
            }
            Self::Cmac { key, data } => host_aes_cmac(key, data)?,
            Self::Hkdf { ikm, salt, len } => {
                let mut out = vec![0u8; *len as usize];
                host_hkdf_sha256(ikm, salt, &[], &mut out, "kernel crypto bench HKDF")?;
                out
            }
            Self::X963 {
                shared_secret,
                shared_info,
                len,
            } => {
                let mut out = vec![0u8; *len as usize];
                host_x963_sha256_kdf(
                    shared_secret,
                    shared_info,
                    &mut out,
                    "kernel crypto bench X9.63",
                )?;
                out
            }
            Self::P256GenerateKeypair => {
                return verify_p256_keypair_bench_response(&response.data);
            }
            Self::P256Ecdh {
                private_key,
                peer_public,
            } => {
                let secret = SecretKey::from_slice(private_key)
                    .map_err(|_| "kernel crypto bench P-256 ECDH invalid private key")?;
                host_p256_shared_secret(&secret, peer_public, "kernel crypto bench P-256 ECDH")?
                    .to_vec()
            }
        };

        if response.data != expected {
            return Err(format!(
                "{}: expected {}, got {}",
                self.op_name(),
                hex_bytes_upper(&expected),
                hex_bytes_upper(&response.data)
            )
            .into());
        }
        Ok(())
    }
}

fn normalize_bench_op(op: &str) -> String {
    op.trim().to_ascii_lowercase().replace('-', "_")
}

fn parse_optional_u8_arg(
    args: &[String],
    index: usize,
    default: u8,
    label: &str,
) -> Result<u8, Box<dyn Error>> {
    let Some(value) = args.get(index) else {
        return Ok(default);
    };
    if value.len() > 2 && value[..2].eq_ignore_ascii_case("0x") {
        return u8::from_str_radix(&value[2..], 16)
            .map_err(|err| format!("{label}: invalid hex byte {value}: {err}").into());
    }
    value
        .parse::<u8>()
        .map_err(|err| format!("{label}: invalid decimal byte {value}: {err}").into())
}

fn parse_optional_hex_arg(
    args: &[String],
    index: usize,
    default: &[u8],
    label: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    match args.get(index) {
        Some(value) => parse_hex_bytes(value, label),
        None => Ok(default.to_vec()),
    }
}

fn parse_optional_hex_array_arg<const N: usize>(
    args: &[String],
    index: usize,
    default: &[u8; N],
    label: &str,
) -> Result<[u8; N], Box<dyn Error>> {
    match args.get(index) {
        Some(value) => parse_hex_array(value, label),
        None => Ok(*default),
    }
}

fn parse_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], Box<dyn Error>> {
    let bytes = parse_hex_bytes(value, label)?;
    if bytes.len() != N {
        return Err(format!("{label}: expected {N} bytes, got {}", bytes.len()).into());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_bytes(value: &str, label: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut text = value.trim();
    if text.len() > 2 && text[..2].eq_ignore_ascii_case("0x") {
        text = &text[2..];
    }
    let cleaned = text
        .chars()
        .filter(|ch| !matches!(ch, ':' | '_' | '-'))
        .collect::<String>();
    if cleaned.len() % 2 != 0 {
        return Err(format!("{label}: hex input has an odd number of digits").into());
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for index in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[index..index + 2], 16)
            .map_err(|err| format!("{label}: invalid hex byte: {err}"))?;
        out.push(byte);
    }
    Ok(out)
}

fn validate_aes_key_len(key: &[u8]) -> Result<(), Box<dyn Error>> {
    match key.len() {
        16 | 32 => Ok(()),
        len => Err(format!("AES key must be 16 or 32 bytes, got {len}").into()),
    }
}

fn validate_block_aligned_len(len: usize, label: &str) -> Result<(), Box<dyn Error>> {
    if len != 0 && len.is_multiple_of(16) {
        Ok(())
    } else {
        Err(format!("{label} must be a non-empty multiple of 16 bytes, got {len}").into())
    }
}

fn validate_kdf_bench_len(len: usize, label: &str) -> Result<(), Box<dyn Error>> {
    if len <= 64 {
        Ok(())
    } else {
        Err(format!("{label} must be at most 64 bytes, got {len}").into())
    }
}

fn validate_kdf_output_len(len: u8) -> Result<(), Box<dyn Error>> {
    if (1..=64).contains(&len) {
        Ok(())
    } else {
        Err(format!("KDF output length must be between 1 and 64 bytes, got {len}").into())
    }
}

fn default_aes256_key() -> Vec<u8> {
    vec![
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ]
}

fn default_aes_iv() -> [u8; 16] {
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ]
}

fn default_aes_plaintext() -> Vec<u8> {
    vec![
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ]
}

fn default_unaligned_payload() -> Vec<u8> {
    b"Oxide SE kernel crypto bench".to_vec()
}

fn default_cmac_payload() -> Vec<u8> {
    b"Oxide SE CMAC bench".to_vec()
}

fn default_kdf_secret() -> Vec<u8> {
    (0x10u8..0x30).collect()
}

fn default_kdf_info() -> Vec<u8> {
    b"Oxide SE-KDF".to_vec()
}

fn default_p256_private_key() -> [u8; 32] {
    [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ]
}

fn default_p256_peer_public_key() -> Result<[u8; 65], Box<dyn Error>> {
    let peer_private = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40,
    ];
    let secret =
        SecretKey::from_slice(&peer_private).map_err(|_| "invalid default P-256 peer key")?;
    let public = secret.public_key().to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(public.as_bytes());
    Ok(out)
}

fn verify_p256_keypair_bench_response(data: &[u8]) -> Result<(), Box<dyn Error>> {
    if data.len() != 97 {
        return Err(format!(
            "p256_generate_keypair: expected 97 bytes private||public, got {}",
            data.len()
        )
        .into());
    }
    let secret = SecretKey::from_slice(&data[..32])
        .map_err(|_| "p256_generate_keypair: invalid returned private key")?;
    let public = secret.public_key().to_encoded_point(false);
    if public.as_bytes() != &data[32..] {
        return Err("p256_generate_keypair: returned public key does not match private key".into());
    }
    Ok(())
}

fn hex_bytes_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02X}");
    }
    out
}

fn parse_mode(mut args: impl Iterator<Item = String>) -> Result<Mode, Box<dyn Error>> {
    let command = args.next();
    let rest: Vec<String> = args.collect();
    if command.as_deref() == Some("test") {
        return testing::parse(rest);
    }
    if command
        .as_deref()
        .is_some_and(|name| name.starts_with("qemu_"))
    {
        return Err("test commands use cargo run test <name>; run cargo run test --help".into());
    }
    if matches!(command.as_deref(), None | Some("--help" | "-h")) {
        return Ok(Mode::Help(None));
    }
    if rest.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Mode::Help(command.clone()));
    }

    let (trace_mode, rest) = parse_trace_options(rest)?;
    SELECTED_TRACE_MODE.store(trace_mode as usize, Ordering::Relaxed);

    let mut args = rest.into_iter();
    let mode = match command.as_deref() {
        Some("build") => {
            let (image_format, board, extra) = parse_dump_kernel_layout_args(&mut args)?;
            if let Some(extra) = extra {
                return Err(format!("unexpected extra argument for build: {extra}").into());
            }
            Mode::Build {
                image_format,
                board,
            }
        }
        Some("clean") => Mode::Clean,
        Some("dump_kernel_layout") => {
            let (image_format, board, profile) = parse_dump_kernel_layout_args(&mut args)?;
            Mode::DumpKernelLayout {
                image_format,
                board,
                profile,
            }
        }
        Some(other) => {
            return Err(format!(
                "unknown xtask command: {other} (run `cargo run -- --help` for the command list)"
            )
            .into())
        }
        None => unreachable!("missing command is handled before command dispatch"),
    };

    Ok(mode)
}

fn parse_trace_options(args: Vec<String>) -> Result<(TraceMode, Vec<String>), Box<dyn Error>> {
    let mut trace_mode = TraceMode::None;
    let mut out = Vec::with_capacity(args.len());
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix("--trace=") {
            trace_mode = TraceMode::parse(value)?;
        } else if arg == "--trace" {
            let value = iter
                .next()
                .ok_or("--trace requires one of: none, semihosting, jtag")?;
            trace_mode = TraceMode::parse(&value)?;
        } else {
            out.push(arg);
        }
    }
    Ok((trace_mode, out))
}

fn selected_trace_mode() -> TraceMode {
    TraceMode::from_usize(SELECTED_TRACE_MODE.load(Ordering::Relaxed))
}

fn parse_cli(
    args: impl Iterator<Item = String>,
) -> Result<(Mode, Option<PathBuf>), Box<dyn Error>> {
    let mut filtered = Vec::new();
    let mut config = None;
    let mut iter = args.peekable();
    while let Some(arg) = iter.next() {
        if let Some(path) = arg.strip_prefix("--config=") {
            if path.is_empty() || config.is_some() {
                return Err("--config requires one non-empty path and cannot be repeated".into());
            }
            config = Some(PathBuf::from(path));
            continue;
        }
        if arg == "--config" {
            let path = iter.next().ok_or("missing path after --config")?;
            if path.is_empty() || path.starts_with('-') || config.is_some() {
                return Err("--config requires one non-empty path and cannot be repeated".into());
            }
            config = Some(PathBuf::from(path));
            continue;
        }
        filtered.push(arg);
    }
    Ok((parse_mode(filtered.into_iter())?, config))
}

fn generate_single_rustlet_config(rustlet: &str) -> Result<PathBuf, Box<dyn Error>> {
    let repo_root = repo_root()?;
    let build_entry = embedded_rustlet_build_entry(rustlet)?;
    let config_dir = repo_root.join("target/xtask/generated-configs");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join(format!("config_rustlet_single_test_{rustlet}.toml"));
    let config = format!(
        "[root.package]\nname = \"NullSecurityDomain\"\naid = \"A0:00:00:47:50:4F:53:01\"\n\n[root.instance]\naid = \"A0:00:00:47:50:4F:53:01\"\ninstall_bytes = \"FF:FF:FF\"\n\n[[root.packages]]\npath = \"./{}\"\n",
        build_entry.crate_dir
    );
    fs::write(&config_path, config)?;
    Ok(config_path)
}

fn parse_dump_kernel_layout_args(
    args: &mut impl Iterator<Item = String>,
) -> Result<(LayoutImageFormat, String, Option<String>), Box<dyn Error>> {
    let options = parse_common_options(args)?;
    let (board, profile) = match options.positional.as_slice() {
        [] => (DEFAULT_BOARD.to_owned(), None),
        [board] => (board.to_owned(), None),
        [board, profile] => (board.to_owned(), Some(profile.to_owned())),
        [_, _, extra, ..] => {
            return Err(format!("unexpected extra argument for kernel layout: {extra}").into())
        }
    };
    Ok((options.image_format, board, profile))
}

struct ParsedCommandOptions {
    image_format: LayoutImageFormat,
    positional: Vec<String>,
}

fn parse_common_options(
    args: &mut impl Iterator<Item = String>,
) -> Result<ParsedCommandOptions, Box<dyn Error>> {
    let mut image_format = LayoutImageFormat::Elf;
    let mut image_seen = false;
    let mut positional = Vec::new();

    for arg in args {
        match arg.as_str() {
            "--fae" | "--elf" => {
                if image_seen {
                    return Err("duplicate or conflicting image format option".into());
                }
                image_seen = true;
                image_format = if arg == "--fae" {
                    LayoutImageFormat::Fae
                } else {
                    LayoutImageFormat::Elf
                };
            }
            "--check_stack" => return Err("--check_stack is not supported by this command".into()),
            "--update_stack_baseline" => {
                return Err("--update_stack_baseline is not supported by this command".into())
            }
            value if value.starts_with("--") => {
                return Err(format!("unknown option: {value}").into())
            }
            _ => positional.push(arg),
        }
    }

    Ok(ParsedCommandOptions {
        image_format,
        positional,
    })
}

fn print_help(command: Option<&str>) {
    match command {
        None => print_general_help(),
        Some("clean") => print_clean_help(),
        Some("build") => print_build_help(),
        Some("test") => print!("{}", testing::help(None)),
        Some("dump_kernel_layout") => print_dump_kernel_layout_help(),
        Some(other) if other.starts_with("test ") => {
            print!("{}", testing::help(other.strip_prefix("test ")));
        }
        Some(other) => {
            println!("Unknown xtask command `{other}`.\n");
            print_general_help();
        }
    }
}

fn print_general_help() {
    println!(
        "Oxide SE xtask\n\n\
Usage:\n  cargo run <command> [options]\n\n\
Build commands:\n  clean\n  build [--elf|--fae] [board]\n  dump_kernel_layout [--elf|--fae] [board] [profile]\n\n\
Target tests:\n  test <name> [board] [--on qemu|openocd] [options] [test arguments]\n  test --help\n  test <name> --help\n\n\
Global options:\n  --config <path>       Explicit predeployment manifest\n  --trace=none|semihosting|jtag\n                        Debug trace output (default: none)\n  -h, --help            Show help\n\n{}",
        board_help_footer()
    );
}

fn print_clean_help() {
    println!(
        "Usage:\n  cargo run clean\n\n\
Description:\n  Remove Oxide SE build outputs managed by xtask."
    );
}

fn print_build_help() {
    println!(
        "Usage:\n  cargo run build [--elf|--fae] [board]\n\n\
Options:\n  --elf                 Build the native fixed-address kernel ELF (default)\n  --fae                 Build the board-aware bootable kernel FAE\n  -h, --help            Show this help\n\n\
Global options:\n  --config <path>       Use an explicit predeployment manifest\n\n\
{}",
        board_help_footer()
    );
}

fn board_help_footer() -> String {
    format!(
        "Default board: {DEFAULT_BOARD}\n\
Trace modes: none (default), semihosting (QEMU/debug), jtag (raspi-pico1 only)\n{}",
        board_matrix_help()
    )
}

fn board_matrix_help() -> String {
    format!(
        "Known boards: {}\n\
Rustlet QEMU boards: {}\n\
Board support: {}",
        known_board_names().join(", "),
        rustlet_qemu_board_names().join(", "),
        board_support_level_summary().join(", ")
    )
}

fn print_dump_kernel_layout_help() {
    println!(
        "Usage:\n  cargo run dump_kernel_layout [--elf|--fae] [board] [profile]\n\n\
Description:\n  Build and report the selected kernel image memory layout without launching QEMU.\n\n\
Options:\n  --elf                 Report the native fixed-address kernel ELF layout (default)\n  --fae                 Report the board-aware bootable kernel FAE layout\n  -h, --help            Show this help\n\n\
{}",
        board_help_footer()
    );
}

fn clean_repo_build_outputs() -> Result<(), Box<dyn Error>> {
    let repo_root = repo_root()?;
    let paths = [
        repo_root.join("target"),
        repo_root.join("xtask/target"),
        repo_root.join("tools/apdu-tool/target"),
        repo_root.join("tooling/build-fae/target"),
        repo_root.join("tooling/build-fae/build"),
        repo_root.join("kernel/core/target"),
        repo_root.join("kernel/core/build"),
        repo_root.join("kernel/firmware/target"),
        repo_root.join("kernel/firmware/build"),
        repo_root.join("core_test/target"),
        repo_root.join("core_test/build"),
        repo_root.join("rustlets/complete_security_domain/target"),
        repo_root.join("rustlets/complete_security_domain/build"),
        repo_root.join("rustlets/tests/alloc_free_test/target"),
        repo_root.join("rustlets/tests/alloc_free_test/build"),
        repo_root.join("rustlets/tests/apdus_test/target"),
        repo_root.join("rustlets/tests/apdus_test/build"),
        repo_root.join("rustlets/tests/crypto_test/target"),
        repo_root.join("rustlets/tests/crypto_test/build"),
        repo_root.join("rustlets/tests/declare_macro_forms/target"),
        repo_root.join("rustlets/tests/declare_macro_forms/build"),
        repo_root.join("rustlets/tests/ecdh_test/target"),
        repo_root.join("rustlets/tests/ecdh_test/build"),
        repo_root.join("rustlets/tests/heap_form_test/target"),
        repo_root.join("rustlets/tests/heap_form_test/build"),
        repo_root.join("rustlets/tests/isolation_fault_test/target"),
        repo_root.join("rustlets/tests/isolation_fault_test/build"),
        repo_root.join("rustlets/tests/minimal_valid_test/target"),
        repo_root.join("rustlets/tests/minimal_valid_test/build"),
        repo_root.join("rustlets/tests/getting_started_test/target"),
        repo_root.join("rustlets/tests/getting_started_test/build"),
        repo_root.join("rustlets/tests/serialization_test/target"),
        repo_root.join("rustlets/tests/serialization_test/build"),
        repo_root.join("rustlets/tests/stack_overflow_test/target"),
        repo_root.join("rustlets/tests/stack_overflow_test/build"),
        repo_root.join("rustlets/tests/state_test/target"),
        repo_root.join("rustlets/tests/state_test/build"),
        repo_root.join("rustlets/tests/string_test/target"),
        repo_root.join("rustlets/tests/string_test/build"),
        repo_root.join("rustlets/tests/termination_test/target"),
        repo_root.join("rustlets/tests/termination_test/build"),
        repo_root.join("rustlets/tests/trampoline_return_test/target"),
        repo_root.join("rustlets/tests/trampoline_return_test/build"),
    ];
    for path in paths {
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
    }
    Ok(())
}

fn kernel_ram_nx_qemu_supported(board: BoardSpec) -> bool {
    matches!(board.env_name, "mps2-an385" | "raspi-pico1")
}

#[derive(Clone, Copy)]
struct SingleRustletSpec {
    name: &'static str,
    total: usize,
}

#[derive(Clone, Copy)]
struct EmbeddedRustletBuildEntry {
    crate_dir: &'static str,
    bin_name: &'static str,
    fae_abi: RustletFaeAbi,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RustletFaeAbi {
    Application,
    SecurityDomain,
}

impl RustletFaeAbi {
    const fn cli_name(self) -> &'static str {
        match self {
            Self::Application => "rustlet",
            Self::SecurityDomain => "rustlet-security-domain",
        }
    }
}

#[derive(Deserialize)]
struct PredeploymentManifestConfig {
    #[serde(default, rename = "kernel-image")]
    kernel_image: KernelImageManifestConfig,
    #[serde(default)]
    secure_channel: SecureChannelManifestConfig,
    root: Option<PredeploymentRootConfig>,
    #[serde(default)]
    security_domains: Vec<PredeploymentSecurityDomainConfig>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct KernelImageManifestConfig {
    mode: Option<String>,
    #[serde(default)]
    kernel_app_modules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedKernelImageManifest {
    mode: &'static str,
    modules: Vec<String>,
}

const KERNEL_IMAGE_MODE_GLOBAL_PLATFORM: &str = "global-platform";
const KERNEL_IMAGE_MODE_KERNEL_ONLY: &str = "kernel-only";
fn valid_kernel_app_module_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn resolve_kernel_image_manifest(
    manifest: &PredeploymentManifestConfig,
) -> Result<ResolvedKernelImageManifest, Box<dyn Error>> {
    let mode = match manifest.kernel_image.mode.as_deref() {
        None | Some(KERNEL_IMAGE_MODE_GLOBAL_PLATFORM) => KERNEL_IMAGE_MODE_GLOBAL_PLATFORM,
        Some(KERNEL_IMAGE_MODE_KERNEL_ONLY) => KERNEL_IMAGE_MODE_KERNEL_ONLY,
        Some(other) => {
            return Err(format!(
                "unsupported kernel-image.mode `{other}`; expected global-platform or kernel-only"
            )
            .into())
        }
    };

    let mut modules = Vec::new();
    for requested in &manifest.kernel_image.kernel_app_modules {
        if !valid_kernel_app_module_name(requested) {
            return Err(format!(
                "invalid kernel app module name `{requested}`; expected lower-case kebab-case"
            )
            .into());
        }
        if modules.contains(requested) {
            return Err(format!("duplicate kernel app module `{requested}`").into());
        }
        modules.push(requested.clone());
    }

    if mode == KERNEL_IMAGE_MODE_KERNEL_ONLY {
        if modules.is_empty() {
            return Err("kernel-only images require at least one kernel-app-modules entry".into());
        }
        if manifest.root.is_some() || !manifest.security_domains.is_empty() {
            return Err(
                "kernel-only images must not declare root or security_domains predeployment".into(),
            );
        }
        if !manifest.secure_channel.protocols.is_empty()
            || manifest.secure_channel.scp03_profile.is_some()
            || !manifest.secure_channel.scp11_profiles.is_empty()
        {
            return Err("kernel-only images must not configure secure channels".into());
        }
    }

    Ok(ResolvedKernelImageManifest { mode, modules })
}

#[derive(Default, Deserialize)]
struct SecureChannelManifestConfig {
    #[serde(default)]
    protocols: Vec<String>,
    scp03_profile: Option<String>,
    #[serde(default)]
    scp11_profiles: Vec<String>,
}

#[derive(Deserialize)]
struct PredeploymentRootConfig {
    package: PredeploymentSecurityDomainPackageConfig,
    instance: PredeploymentSecurityDomainInstanceConfig,
    #[serde(default)]
    keys: Vec<PredeploymentKeyConfig>,
    #[serde(default)]
    packages: Vec<PredeploymentRustletPackageConfig>,
}

#[derive(Deserialize)]
struct PredeploymentSecurityDomainConfig {
    package: PredeploymentSecurityDomainPackageConfig,
    instance: PredeploymentSecurityDomainInstanceConfig,
    #[serde(default)]
    keys: Vec<PredeploymentKeyConfig>,
    #[serde(default)]
    packages: Vec<PredeploymentRustletPackageConfig>,
}

#[derive(Deserialize)]
struct PredeploymentKeyConfig {
    #[serde(rename = "type")]
    key_type: String,
    version: u8,
    id: u8,
    usage: String,
    material: String,
}

#[derive(Deserialize)]
struct PredeploymentRustletPackageConfig {
    #[serde(alias = "crate_dir")]
    path: String,
}

#[derive(Deserialize)]
struct PredeploymentSecurityDomainPackageConfig {
    #[serde(default)]
    name: String,
    #[serde(default)]
    path: String,
}

#[derive(Deserialize)]
struct PredeploymentSecurityDomainInstanceConfig {
    aid: String,
}

#[derive(Deserialize)]
struct WorkspaceManifestConfig {
    #[serde(default)]
    workspace: WorkspaceConfigSection,
}

#[derive(Default, Deserialize)]
struct WorkspaceConfigSection {
    #[serde(default)]
    metadata: WorkspaceMetadataSection,
}

#[derive(Default, Deserialize)]
struct WorkspaceMetadataSection {
    #[serde(default)]
    oxide_se: WorkspaceOxideSeMetadata,
}

#[derive(Default, Deserialize)]
struct WorkspaceOxideSeMetadata {
    default_config_toml: Option<String>,
}

#[derive(Clone, Copy)]
struct RustletScenarioAids {
    package_aid: &'static [u8],
    applet_aid: &'static [u8],
    instance_aid: &'static [u8],
    alternate_instance_aid: Option<&'static [u8]>,
}

impl RustletScenarioAids {
    fn same(aid: &'static [u8]) -> Self {
        Self {
            package_aid: aid,
            applet_aid: aid,
            instance_aid: aid,
            alternate_instance_aid: None,
        }
    }
}

fn single_rustlet_spec(name: &str) -> Result<SingleRustletSpec, Box<dyn Error>> {
    match name {
        "minimal" | "minimal_valid" | "minimal_valid_test" | "rustlet_minimal_valid_test" => {
            Ok(SingleRustletSpec {
                name: "minimal_valid_test",
                total: 6,
            })
        }
        "getting_started" | "getting_started_test" | "rustlet_getting_started_test" => {
            Ok(SingleRustletSpec {
                name: "getting_started_test",
                total: 7,
            })
        }
        "apdu" | "apdus" | "apdus_test" | "rustlet_apdus_test" => Ok(SingleRustletSpec {
            name: "apdus_test",
            total: 8,
        }),
        "crypto" | "crypto_test" | "rustlet_crypto_test" => Ok(SingleRustletSpec {
            name: "crypto_test",
            total: 30,
        }),
        "ecdh" | "ecdh_test" | "rustlet_ecdh_test" => Ok(SingleRustletSpec {
            name: "ecdh_test",
            total: 5,
        }),
        "state" | "state_test" | "rustlet_state_test" => Ok(SingleRustletSpec {
            name: "state_test",
            total: 11,
        }),
        "serialization" | "serialization_test" | "rustlet_serialization_test" => {
            Ok(SingleRustletSpec {
                name: "serialization_test",
                total: 20,
            })
        }
        "stack" | "stack_overflow" | "stack_overflow_test" | "rustlet_stack_overflow_test" => {
            Ok(SingleRustletSpec {
                name: "stack_overflow_test",
                total: 7,
            })
        }
        "stack_overflow_recursive" | "stack_overflow_recursive_test" => Ok(SingleRustletSpec {
            name: "stack_overflow_recursive_test",
            total: 4,
        }),
        "alloc" | "alloc_free" | "alloc_free_test" | "rustlet_alloc_free_test" => {
            Ok(SingleRustletSpec {
                name: "alloc_free_test",
                total: 5,
            })
        }
        "heap" | "heap_form" | "heap_form_test" | "rustlet_heap_form_test" => {
            Ok(SingleRustletSpec {
                name: "heap_form_test",
                total: 3,
            })
        }
        "string" | "string_test" | "rustlet_string_test" => Ok(SingleRustletSpec {
            name: "string_test",
            total: 3,
        }),
        "termination" | "termination_test" | "rustlet_termination_test" => Ok(SingleRustletSpec {
            name: "termination_test",
            total: 7,
        }),
        "isolation_fault" | "isolation_fault_test" | "rustlet_isolation_fault_test" => {
            Ok(SingleRustletSpec {
                name: "isolation_fault_test",
                total: 11,
            })
        }
        "complete_security_domain" | "security_domain" | "sd" => Ok(SingleRustletSpec {
            name: "complete_security_domain",
            total: 3,
        }),
        other => Err(format!(
            "unknown single Rustlet '{other}' (expected one of: {})",
            canonical_single_rustlet_names()
        )
        .into()),
    }
}

fn canonical_single_rustlet_names() -> &'static str {
    "minimal_valid_test, getting_started_test, apdus_test, crypto_test, ecdh_test, state_test, serialization_test, stack_overflow_test, stack_overflow_recursive_test, alloc_free_test, heap_form_test, string_test, termination_test, isolation_fault_test, complete_security_domain"
}

fn embedded_only_name_for_single_scenario(name: &str) -> &str {
    match name {
        "stack_overflow_recursive_test" => "stack_overflow_test",
        other => other,
    }
}

fn embedded_rustlet_build_entry(name: &str) -> Result<EmbeddedRustletBuildEntry, Box<dyn Error>> {
    let application = |crate_dir, bin_name| EmbeddedRustletBuildEntry {
        crate_dir,
        bin_name,
        fae_abi: RustletFaeAbi::Application,
    };
    match embedded_only_name_for_single_scenario(single_rustlet_spec(name)?.name) {
        "minimal_valid_test" => Ok(application(
            "rustlets/tests/minimal_valid_test",
            "rustlet_minimal_valid_test",
        )),
        "getting_started_test" => Ok(application(
            "rustlets/tests/getting_started_test",
            "rustlet_getting_started_test",
        )),
        "apdus_test" => Ok(application(
            "rustlets/tests/apdus_test",
            "rustlet_apdus_test",
        )),
        "crypto_test" => Ok(application(
            "rustlets/tests/crypto_test",
            "rustlet_crypto_test",
        )),
        "ecdh_test" => Ok(application("rustlets/tests/ecdh_test", "rustlet_ecdh_test")),
        "state_test" => Ok(application(
            "rustlets/tests/state_test",
            "rustlet_state_test",
        )),
        "serialization_test" => Ok(application(
            "rustlets/tests/serialization_test",
            "rustlet_serialization_test",
        )),
        "stack_overflow_test" => Ok(application(
            "rustlets/tests/stack_overflow_test",
            "rustlet_stack_overflow_test",
        )),
        "alloc_free_test" => Ok(application(
            "rustlets/tests/alloc_free_test",
            "rustlet_alloc_free_test",
        )),
        "heap_form_test" => Ok(application(
            "rustlets/tests/heap_form_test",
            "rustlet_heap_form_test",
        )),
        "string_test" => Ok(application(
            "rustlets/tests/string_test",
            "rustlet_string_test",
        )),
        "termination_test" => Ok(application(
            "rustlets/tests/termination_test",
            "rustlet_termination_test",
        )),
        "isolation_fault_test" => Ok(application(
            "rustlets/tests/isolation_fault_test",
            "rustlet_isolation_fault_test",
        )),
        "complete_security_domain" => Ok(EmbeddedRustletBuildEntry {
            crate_dir: "rustlets/complete_security_domain",
            bin_name: "complete_security_domain",
            fae_abi: RustletFaeAbi::SecurityDomain,
        }),
        other => Err(format!("missing embedded build entry for {other}").into()),
    }
}

fn embedded_rustlet_build_entry_from_crate_dir(
    crate_dir: &str,
) -> Result<EmbeddedRustletBuildEntry, Box<dyn Error>> {
    let normalized = crate_dir
        .strip_prefix("./")
        .or_else(|| crate_dir.strip_prefix('/'))
        .unwrap_or(crate_dir);
    match normalized {
        "rustlets/tests/minimal_valid_test" => embedded_rustlet_build_entry("minimal_valid_test"),
        "rustlets/tests/getting_started_test" => {
            embedded_rustlet_build_entry("getting_started_test")
        }
        "rustlets/tests/apdus_test" => embedded_rustlet_build_entry("apdus_test"),
        "rustlets/tests/crypto_test" => embedded_rustlet_build_entry("crypto_test"),
        "rustlets/tests/ecdh_test" => embedded_rustlet_build_entry("ecdh_test"),
        "rustlets/tests/state_test" => embedded_rustlet_build_entry("state_test"),
        "rustlets/tests/serialization_test" => embedded_rustlet_build_entry("serialization_test"),
        "rustlets/tests/stack_overflow_test" => embedded_rustlet_build_entry("stack_overflow_test"),
        "rustlets/tests/alloc_free_test" => embedded_rustlet_build_entry("alloc_free_test"),
        "rustlets/tests/heap_form_test" => embedded_rustlet_build_entry("heap_form_test"),
        "rustlets/tests/string_test" => embedded_rustlet_build_entry("string_test"),
        "rustlets/tests/termination_test" => embedded_rustlet_build_entry("termination_test"),
        "rustlets/tests/isolation_fault_test" => {
            embedded_rustlet_build_entry("isolation_fault_test")
        }
        "rustlets/complete_security_domain" => {
            embedded_rustlet_build_entry("complete_security_domain")
        }
        other => Err(format!("unknown embedded rustlet crate_dir in config: {other}").into()),
    }
}

fn rustlet_functional_specs() -> Result<Vec<SingleRustletSpec>, Box<dyn Error>> {
    [
        "minimal_valid_test",
        "apdus_test",
        "crypto_test",
        "state_test",
        "serialization_test",
        "stack_overflow_test",
        "alloc_free_test",
        "heap_form_test",
        "string_test",
        "termination_test",
    ]
    .iter()
    .map(|name| single_rustlet_spec(name))
    .collect()
}

fn rustlet_scenario_aids(name: &str) -> Result<RustletScenarioAids, Box<dyn Error>> {
    match name {
        "minimal_valid_test" => Ok(RustletScenarioAids::same(
            crate_rustlet_minimal_valid_test_aid(),
        )),
        "getting_started_test" => Ok(RustletScenarioAids::same(
            crate_rustlet_getting_started_test_aid(),
        )),
        "apdus_test" => Ok(RustletScenarioAids::same(crate_rustlet_apdus_test_aid())),
        "crypto_test" => Ok(RustletScenarioAids::same(crate_rustlet_crypto_test_aid())),
        "ecdh_test" => Ok(RustletScenarioAids::same(crate_rustlet_ecdh_test_aid())),
        "state_test" => Ok(RustletScenarioAids {
            package_aid: crate_rustlet_state_test_aid(),
            applet_aid: crate_rustlet_state_test_aid(),
            instance_aid: crate_rustlet_state_test_aid(),
            alternate_instance_aid: Some(crate_rustlet_state_test_instance_b_aid()),
        }),
        "serialization_test" => Ok(RustletScenarioAids {
            package_aid: crate_rustlet_serialization_test_aid(),
            applet_aid: crate_rustlet_serialization_test_aid(),
            instance_aid: crate_rustlet_serialization_test_aid(),
            alternate_instance_aid: Some(crate_rustlet_serialization_test_instance_b_aid()),
        }),
        "stack_overflow_test" => Ok(RustletScenarioAids::same(
            crate_rustlet_stack_overflow_test_aid(),
        )),
        "stack_overflow_recursive_test" => Ok(RustletScenarioAids::same(
            crate_rustlet_stack_overflow_test_aid(),
        )),
        "alloc_free_test" => Ok(RustletScenarioAids::same(
            crate_rustlet_alloc_free_test_aid(),
        )),
        "heap_form_test" => Ok(RustletScenarioAids::same(crate_rustlet_heap_form_test_aid())),
        "string_test" => Ok(RustletScenarioAids::same(crate_rustlet_string_test_aid())),
        "termination_test" => Ok(RustletScenarioAids::same(
            crate_rustlet_termination_test_aid(),
        )),
        "isolation_fault_test" => Ok(RustletScenarioAids::same(
            crate_rustlet_isolation_fault_test_aid(),
        )),
        "complete_security_domain" => Ok(RustletScenarioAids::same(complete_security_domain_aid())),
        other => Err(format!("missing Rustlet AID scenario for {other}").into()),
    }
}

fn run_with_build_config<T>(
    ctx: &TestContext,
    config: &str,
    f: impl FnOnce(&TestContext) -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    f(&ctx.with_config(config))
}

fn build_getting_started_dynamic_load_payload(
    ctx: &BuildContext,
    board: BoardSpec,
) -> Result<DynamicLoadPayload, Box<dyn Error>> {
    let repo_root = repo_root()?;
    let tool_manifest = repo_root.join("tooling/build-fae/Cargo.toml");
    let dynamic_entry = embedded_rustlet_build_entry("getting_started_test")?;
    build_embedded_app(
        ctx,
        &tool_manifest,
        dynamic_entry.crate_dir,
        dynamic_entry.bin_name,
        dynamic_entry.fae_abi,
        board,
        "qemu",
    )?;
    let dynamic_fae_path =
        embedded_app_fae_path(&repo_root, dynamic_entry.crate_dir, dynamic_entry.bin_name);
    let fae = fs::read(&dynamic_fae_path).map_err(|err| {
        format!(
            "failed to read dynamic LOAD FAE {}: {err}",
            dynamic_fae_path.display()
        )
    })?;
    let hash = Sha256::digest(&fae).to_vec();
    Ok(DynamicLoadPayload { fae, hash })
}

fn scp03_key_object_aid(key_version: u8, key_id: u8, usage: u8) -> [u8; 6] {
    [0x4B, 0x45, 0x59, key_version, key_id, usage]
}

fn gp_data_object_aid(tag: u16) -> [u8; 6] {
    [0x44, 0x41, 0x54, 0x41, (tag >> 8) as u8, tag as u8]
}

fn send_gp_load_sequence(client: &mut ApduClient, payload: &[u8]) -> Result<usize, Box<dyn Error>> {
    const GP_LOAD_CLEAR_CHUNK_LEN: usize = u8::MAX as usize;
    let load_file = apdu_tool::gp::encode_load_file_data_block(payload)?;
    let mut block_number = 0u8;
    let mut offset = 0usize;
    let mut total = 0usize;
    while offset < load_file.len() {
        let end = (offset + GP_LOAD_CLEAR_CHUNK_LEN).min(load_file.len());
        let is_last = end == load_file.len();
        eprintln!("persistence: LOAD block {block_number}");
        expect_status(
            client.exchange(&CommandBuilder::gp_load_block(
                block_number,
                is_last,
                &load_file[offset..end],
            ))?,
            (0x90, 0x00),
            "dynamic LOAD block",
        )?;
        offset = end;
        block_number = block_number.wrapping_add(1);
        total += 1;
    }
    Ok(total)
}

fn send_gp_load_sequence_protected_scp03(
    client: &mut ApduClient,
    session: &mut HostScp03Session,
    payload: &[u8],
    label: &str,
) -> Result<usize, Box<dyn Error>> {
    let chunk_len = protected_load_chunk_len(session.profile.mac_len())?;
    let load_file = apdu_tool::gp::encode_load_file_data_block(payload)?;
    let mut block_number = 0u8;
    let mut offset = 0usize;
    let mut total = 0usize;
    while offset < load_file.len() {
        let end = (offset + chunk_len).min(load_file.len());
        let is_last = end == load_file.len();
        exchange_protected_scp03_status(
            client,
            session,
            CommandBuilder::gp_load_block(block_number, is_last, &load_file[offset..end]),
            &format!("{label} LOAD block {block_number}"),
        )?;
        offset = end;
        block_number = block_number.wrapping_add(1);
        total += 1;
    }
    Ok(total)
}

fn send_gp_load_sequence_protected_scp11(
    client: &mut ApduClient,
    session: &mut HostScp11Session,
    payload: &[u8],
    label: &str,
) -> Result<usize, Box<dyn Error>> {
    let chunk_len = protected_load_chunk_len(16)?;
    let load_file = apdu_tool::gp::encode_load_file_data_block(payload)?;
    let mut block_number = 0u8;
    let mut offset = 0usize;
    let mut total = 0usize;
    while offset < load_file.len() {
        let end = (offset + chunk_len).min(load_file.len());
        let is_last = end == load_file.len();
        exchange_protected_scp11_status(
            client,
            session,
            CommandBuilder::gp_load_block(block_number, is_last, &load_file[offset..end]),
            &format!("{label} LOAD block {block_number}"),
        )?;
        offset = end;
        block_number = block_number.wrapping_add(1);
        total += 1;
    }
    Ok(total)
}

fn protected_load_chunk_len(mac_len: usize) -> Result<usize, Box<dyn Error>> {
    gp_sm::encrypted_short_apdu_payload_budget(mac_len)
        .ok_or_else(|| format!("no protected LOAD payload budget for MAC length {mac_len}").into())
}

fn select_complete_security_domain(
    client: &mut ApduClient,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    eprintln!("{label}: select complete_security_domain");
    expect_response(
        client.exchange(&CommandBuilder::select(
            complete_security_domain_instance_aid(),
        ))?,
        complete_security_domain_select_fci(),
        (0x90, 0x00),
        &format!("{label} select complete_security_domain"),
    )
}

struct HostScp03Session {
    profile: HostScp03Profile,
    session_enc_key: Vec<u8>,
    session_mac_key: Vec<u8>,
    command_mac_chain: [u8; 16],
    command_enc_counter: u32,
}

struct HostScp11Session {
    keys: HostScp11cSessionKeys,
    command_mac_chain: [u8; 16],
    response_mac_chain: [u8; 16],
    command_enc_counter: u32,
}

fn open_host_scp03_session(
    client: &mut ApduClient,
    profile: HostScp03Profile,
    key_version: u8,
    key_id: u8,
    static_enc_key: &[u8],
    static_mac_key: &[u8],
    label: &str,
) -> Result<HostScp03Session, Box<dyn Error>> {
    eprintln!("{label}: INITIALIZE UPDATE");
    let host_challenge = profile.challenge();
    let expected = exchange_scp03_initialize_update(
        client,
        profile,
        host_challenge,
        static_enc_key,
        static_mac_key,
        key_version,
        key_id,
        label,
    )?;
    let host_cryptogram = expected.host_cryptogram.clone();

    eprintln!("{label}: EXTERNAL AUTHENTICATE");
    let (external_authenticate, initial_mac_chain) = CommandBuilder::scp03_external_authenticate(
        0x03,
        &host_cryptogram,
        &expected.session_mac_key,
        profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&external_authenticate)?,
        (0x90, 0x00),
        &format!("{label} EXTERNAL AUTHENTICATE"),
    )?;

    Ok(HostScp03Session {
        profile,
        session_enc_key: expected.session_enc_key,
        session_mac_key: expected.session_mac_key,
        command_mac_chain: initial_mac_chain,
        command_enc_counter: 0,
    })
}

/// Opens an owner-authenticated channel for mutable registry operations.
fn open_host_scp11a_session(
    client: &mut ApduClient,
    label: &str,
) -> Result<HostScp11Session, Box<dyn Error>> {
    let host_ephemeral_secret_bytes = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x41,
    ];
    let host_static_secret_bytes: [u8; 32] = std::array::from_fn(|i| 0x31 + i as u8);
    let host_static_secret = SecretKey::from_slice(&host_static_secret_bytes)
        .map_err(|_| "scp11a: invalid host static private key")?;
    let host_static_public = host_static_secret.public_key().to_encoded_point(false);
    let certificate = build_dev_oce_certificate(host_static_public.as_bytes())?;
    let split = certificate.len() / 2;
    for (p1, block) in [(0x80, &certificate[..split]), (0x00, &certificate[split..])] {
        expect_status(
            client.exchange(&CommandBuilder::scp11c_perform_security_operation(
                p1, 0, block,
            ))?,
            (0x90, 0x00),
            &format!("{label} SCP11a PSO certificate"),
        )?;
    }
    let host_ephemeral_secret = SecretKey::from_slice(&host_ephemeral_secret_bytes)
        .map_err(|_| "scp11a: invalid host ephemeral private key")?;
    let host_ephemeral_public = host_ephemeral_secret.public_key().to_encoded_point(false);

    eprintln!("{label}: SCP11a MUTUAL AUTHENTICATE");
    let response = client.exchange(&CommandBuilder::scp11a_mutual_authenticate(
        0x00,
        0x01,
        host_ephemeral_public.as_bytes(),
    ))?;
    let response = expect_scp11c_mutual_authenticate_response(
        &response,
        &format!("{label} SCP11a mutual authenticate"),
    )?;
    let keys = derive_host_scp11a_session_keys(
        &host_static_secret,
        &host_ephemeral_secret,
        response.public_key,
        &format!("{label} SCP11a mutual authenticate"),
    )?;
    if !keys.all_distinct() {
        return Err(format!("{label}: SCP11a derived session keys should remain distinct").into());
    }
    let receipt = host_scp11c_mutual_authenticate_receipt(
        &keys,
        &CommandBuilder::scp11a_mutual_authenticate(0x00, 0x01, host_ephemeral_public.as_bytes())
            .data,
        response.public_key,
        &format!("{label} SCP11a mutual authenticate"),
    )?;
    if response.receipt != receipt {
        return Err(format!("{label}: SCP11a receipt mismatch").into());
    }

    Ok(HostScp11Session {
        keys,
        command_mac_chain: receipt,
        response_mac_chain: receipt,
        command_enc_counter: 0,
    })
}

fn exchange_protected_scp03_status(
    client: &mut ApduClient,
    session: &mut HostScp03Session,
    command: OwnedT0Command,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    exchange_protected_scp03_expected_status(client, session, command, (0x90, 0x00), label)
}

fn exchange_protected_scp03_expected_status(
    client: &mut ApduClient,
    session: &mut HostScp03Session,
    command: OwnedT0Command,
    expected_status: (u8, u8),
    label: &str,
) -> Result<(), Box<dyn Error>> {
    eprintln!("{label}");
    let protected = scp03_encrypt_command_data(
        command,
        &session.session_enc_key,
        &session.session_mac_key,
        &mut session.command_mac_chain,
        &mut session.command_enc_counter,
        session.profile.mac_len(),
    )?;
    expect_status(client.exchange(&protected)?, expected_status, label)
}

fn exchange_protected_scp11_status(
    client: &mut ApduClient,
    session: &mut HostScp11Session,
    command: OwnedT0Command,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    eprintln!("{label}");
    let protected = scp11c_encrypt_command_data(
        command,
        &session.keys,
        &mut session.command_mac_chain,
        &mut session.command_enc_counter,
    )?;
    let expected_rmac = host_chained_truncated_aes_cmac(
        &session.keys.s_rmac,
        &mut session.response_mac_chain,
        &[0x90, 0x00],
        16,
    )?;
    expect_protected_status(
        client.exchange(&protected)?,
        (0x90, 0x00),
        &expected_rmac,
        label,
    )
}

fn validate_gp_discovery(
    client: &mut ApduClient,
    log_prefix: &str,
    capabilities: rustlet_runtime::gp::SecurityDomainCapabilities,
) -> Result<usize, Box<dyn Error>> {
    validate_gp_discovery_with_issuer(client, log_prefix, capabilities, None)
}

fn validate_gp_discovery_with_issuer(
    client: &mut ApduClient,
    log_prefix: &str,
    capabilities: rustlet_runtime::gp::SecurityDomainCapabilities,
    expected_issuer_aid: Option<&[u8]>,
) -> Result<usize, Box<dyn Error>> {
    let mut expected = [0u8; rustlet_runtime::APDU_BUFFER_CAPACITY];
    let card_data_len =
        rustlet_runtime::gp::write_card_recognition_data(capabilities, &mut expected)
            .map_err(|_| "failed to encode expected GP Card Recognition Data")?;
    eprintln!("{log_prefix}: GET DATA Card Recognition Data");
    expect_response(
        client.exchange(&CommandBuilder::gp_get_data(
            0x0066,
            u8::try_from(card_data_len)?,
        ))?,
        &expected[..card_data_len],
        (0x90, 0x00),
        "GET DATA Card Recognition Data",
    )?;

    eprintln!("{log_prefix}: GET DATA Card Capability Information");
    if capabilities.has_secure_channel() {
        let card_capabilities_len =
            rustlet_runtime::gp::write_card_capability_information(capabilities, &mut expected)
                .map_err(|_| "failed to encode expected GP Card Capability Information")?;
        expect_response(
            client.exchange(&CommandBuilder::gp_get_data(
                0x0067,
                u8::try_from(card_capabilities_len)?,
            ))?,
            &expected[..card_capabilities_len],
            (0x90, 0x00),
            "GET DATA Card Capability Information",
        )?;
    } else {
        expect_status(
            client.exchange(&CommandBuilder::gp_get_data(0x0067, 0x01))?,
            (0x6a, 0x88),
            "GET DATA absent Card Capability Information",
        )?;
    }

    eprintln!("{log_prefix}: GET STATUS Issuer Security Domain");
    let response = client.exchange(&CommandBuilder::gp_get_status(0x80, false, &[]))?;
    if let Some(expected_issuer_aid) = expected_issuer_aid {
        expect_get_status_record(
            &response,
            expected_issuer_aid,
            true,
            "GET STATUS Issuer Security Domain",
        )?;
    } else {
        expect_status(
            response,
            (0x6a, 0x88),
            "GET STATUS absent Issuer Security Domain",
        )?;
    }
    Ok(3)
}

fn expect_get_status_record(
    response: &T0Response,
    expected_aid: &[u8],
    expect_privileges: bool,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    if response.status != (0x90, 0x00) {
        return Err(format!(
            "{label}: unexpected status {:02X}{:02X}",
            response.status.0, response.status.1
        )
        .into());
    }
    let records = apdu_tool::gp::decode_status(&response.data)
        .map_err(|error| format!("{label}: {error}"))?;
    let record = records
        .first()
        .ok_or_else(|| format!("{label}: missing E3 record"))?;
    let aid_seen = record.aid == expected_aid;
    let lifecycle_seen = record.lifecycle.is_some();
    let privileges_seen = record.privileges.len() == 3;
    if !aid_seen || !lifecycle_seen || (expect_privileges && !privileges_seen) {
        return Err(format!(
            "{label}: incomplete E3 record (AID={aid_seen}, lifecycle={lifecycle_seen}, privileges={privileges_seen})"
        )
        .into());
    }
    Ok(())
}

fn build_firmware(
    ctx: &BuildContext,
    kind: FirmwareKind,
    packaging: Option<Packaging>,
    board: &str,
    execution_env: &str,
) -> Result<(), Box<dyn Error>> {
    let repo_root = repo_root()?;
    let tool_manifest = repo_root.join("tooling/build-fae/Cargo.toml");
    let firmware = firmware_spec(kind)?;
    let board = board_spec(board)?;
    let selected_predeployment_config = Some(ctx.manifest_path(&repo_root));
    let build_env = BuildManifestEnv::resolve(ctx, &repo_root, board.env_name, execution_env)?;

    if matches!(kind, FirmwareKind::GpKernel)
        && build_env.get("OXIDE_SE_KERNEL_IMAGE_MODE") != KERNEL_IMAGE_MODE_KERNEL_ONLY
    {
        build_embedded_rustlets(ctx, &tool_manifest, board, execution_env)?;
    }

    if let Some(Packaging::Bootable(packaging_board)) = packaging {
        let output = firmware_image_path(kind)?;
        let stamp_path = firmware_fae_stamp_path(&output);
        let stamp = firmware_fae_stamp(
            ctx,
            kind,
            packaging_board,
            execution_env,
            selected_predeployment_config.as_deref(),
        );
        if firmware_fae_is_fresh(
            kind,
            &firmware,
            packaging_board,
            execution_env,
            &output,
            &stamp_path,
            &stamp,
            selected_predeployment_config.as_deref(),
        )? {
            eprintln!("xtask: reuse firmware FAE {}", output.display());
            validate_firmware_layout(ctx, kind, packaging_board, None)?;
            return Ok(());
        }
    }

    match packaging {
        None => build_native_firmware_elf(
            ctx,
            &firmware,
            board,
            execution_env,
            selected_predeployment_config.as_deref(),
        ),
        Some(Packaging::Bootable(packaging_board)) => {
            run_build_fae(
                ctx,
                &tool_manifest,
                &firmware.manifest,
                firmware.bin_name,
                None,
                None,
                board,
                execution_env,
                Some(&kernel_firmware_work_dir()?),
                Some(&kernel_target_dir()?.join("build-fae")),
            )?;
            let startup_elf = build_oxide_se_bootable_startup(packaging_board)?;
            let firmware_elf = firmware_elf_path_from_spec(&firmware)?;
            build_bootable_fae(&startup_elf, &firmware_elf)?;
            validate_firmware_layout(ctx, kind, packaging_board, None)?;
            fs::write(
                firmware_fae_stamp_path(&firmware_image_path(kind)?),
                firmware_fae_stamp(
                    ctx,
                    kind,
                    packaging_board,
                    execution_env,
                    selected_predeployment_config.as_deref(),
                ),
            )?;
            Ok(())
        }
        Some(Packaging::Fae) => run_build_fae(
            ctx,
            &tool_manifest,
            &firmware.manifest,
            firmware.bin_name,
            packaging,
            None,
            board,
            execution_env,
            Some(&kernel_firmware_work_dir()?),
            Some(&kernel_target_dir()?.join("build-fae")),
        ),
    }
}

fn build_native_firmware_elf(
    ctx: &BuildContext,
    firmware: &FirmwareSpec,
    board: BoardSpec,
    execution_env: &str,
    predeployment_config: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let toolchain = preferred_nightly_toolchain()?;
    let rust_lld = rust_lld_path(&toolchain)?;
    let startup_object = build_oxide_se_native_startup(board)?;
    let startup_fingerprint = file_fingerprint(&startup_object)?;
    let linker_script = write_board_linker_script(board, "native")?;
    let target_dir = kernel_target_dir()?.join("native-elf");
    let built_elf = target_dir
        .join(board.rust_target)
        .join("release")
        .join(firmware.bin_name);
    let output_elf = firmware_elf_path_from_spec(firmware)?;

    let rustflags = toml_array(&[
        "-Z".to_owned(),
        "function-sections=yes".to_owned(),
        "-C".to_owned(),
        "panic=abort".to_owned(),
        "-C".to_owned(),
        "link-arg=--gc-sections".to_owned(),
        "-C".to_owned(),
        "link-arg=--no-undefined".to_owned(),
        "-Z".to_owned(),
        format!("pre-link-arg=-T{}", linker_script.display()),
        "-C".to_owned(),
        format!("link-arg={}", startup_object.display()),
    ]);

    let mut cargo = Command::new("cargo");
    cargo
        .arg(format!("+{toolchain}"))
        .arg("build")
        .arg("-Z")
        .arg("build-std=core,alloc,compiler_builtins")
        .arg("-Z")
        .arg("build-std-features=compiler-builtins-mem")
        .arg("--manifest-path")
        .arg(&firmware.manifest)
        .arg("--release")
        .arg("--target")
        .arg(board.rust_target)
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--config")
        .arg(format!(
            "target.{}.linker=\"{}\"",
            board.rust_target, rust_lld
        ))
        .arg("--config")
        .arg(format!(
            "target.{}.rustflags={rustflags}",
            board.rust_target
        ))
        .env("OXIDE_SE_BOARD", board.env_name)
        .env("OXIDE_SE_EXECUTION_ENV", execution_env)
        .env("OXIDE_SE_TRACE", ctx.trace.env_value())
        .env("OXIDE_SE_NATIVE_STARTUP_FINGERPRINT", startup_fingerprint);
    if let Some(config) = predeployment_config {
        cargo.env("OXIDE_SE_BUILD_CONFIG", config);
    }
    BuildManifestEnv::resolve(ctx, &repo_root()?, board.env_name, execution_env)?.apply(&mut cargo);
    run_checked(&mut cargo, "cargo build native firmware ELF")?;

    fs::create_dir_all(
        output_elf
            .parent()
            .ok_or("native firmware output has no parent")?,
    )?;
    fs::copy(&built_elf, &output_elf).map_err(|err| {
        format!(
            "failed to copy native ELF from {} to {}: {err}",
            built_elf.display(),
            output_elf.display()
        )
    })?;
    println!("Generated {}", output_elf.display());
    Ok(())
}

fn file_fingerprint(path: &Path) -> Result<String, Box<dyn Error>> {
    let metadata = fs::metadata(path)?;
    let modified = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(format!("{}:{modified}", metadata.len()))
}

fn build_oxide_se_native_startup(board: BoardSpec) -> Result<PathBuf, Box<dyn Error>> {
    let repo_root = repo_root()?;
    let build_dir = kernel_target_dir()?.join("support");
    fs::create_dir_all(&build_dir)?;

    let source = repo_root
        .join("kernel/native")
        .join(board.startup_dir)
        .join("native_rt0.s");
    let object = build_dir.join(format!("native-{}.o", board.env_name));

    let mut compile = Command::new("arm-none-eabi-gcc");
    compile.current_dir(&repo_root);
    compile.args(board.compiler_flags);
    compile.arg("-I").arg(&repo_root);
    compile.arg(&source);
    compile.arg("-o").arg(&object);
    run_checked(&mut compile, "compile Oxide SE native startup")?;

    Ok(object)
}

fn build_oxide_se_bootable_startup(board: BoardSpec) -> Result<PathBuf, Box<dyn Error>> {
    let repo_root = repo_root()?;
    let build_dir = kernel_target_dir()?.join("support");
    std::fs::create_dir_all(&build_dir)?;

    let source = repo_root
        .join("kernel/bootable")
        .join(board.startup_dir)
        .join("boot_rt0.s");
    let linker_script = write_board_linker_script(board, "bootable")?;
    let object = build_dir.join(format!("boot-{}.o", board.env_name));
    let elf = build_dir.join(format!("boot-{}.elf", board.env_name));

    let mut compile = Command::new("arm-none-eabi-gcc");
    compile.current_dir(&repo_root);
    compile.args(board.compiler_flags);
    compile.arg("-Wa,--defsym,FAE1_FOOTER=1");
    compile.arg("-I").arg(&repo_root);
    compile.arg(&source);
    compile.arg("-o").arg(&object);
    run_checked(&mut compile, "compile Oxide SE bootable startup")?;

    let mut link = Command::new("arm-none-eabi-ld");
    link.current_dir(&repo_root);
    link.arg("-T").arg(&linker_script);
    link.arg(&object);
    link.arg("-o").arg(&elf);
    run_checked(&mut link, "link Oxide SE bootable startup")?;

    Ok(elf)
}

fn build_bootable_fae(startup_elf: &Path, firmware_elf: &Path) -> Result<(), Box<dyn Error>> {
    let repo_root = repo_root()?;
    let mut cargo = Command::new("cargo");
    cargo
        .arg("run")
        .arg("--manifest-path")
        .arg(repo_root.join("tooling/build-fae/Cargo.toml"))
        .arg("--bin")
        .arg("build_fae")
        .arg("--")
        .arg("--rt0")
        .arg(startup_elf)
        .arg("--align_payload")
        .arg("2048")
        .arg("--align_size")
        .arg("2048")
        .arg(firmware_elf);
    run_checked(&mut cargo, "build_fae --rt0")
}

fn firmware_fae_stamp_path(output: &Path) -> PathBuf {
    output.with_extension("fae.stamp")
}

fn firmware_fae_stamp(
    ctx: &BuildContext,
    kind: FirmwareKind,
    board: BoardSpec,
    execution_env: &str,
    predeployment_config: Option<&Path>,
) -> String {
    format!(
        "format=fae1-custom-startup-v2\nkind={}\nboard={}\nenv={}\ntrace={:?}\nfault={:?}\nstack={}\nconfig={}\n",
        firmware_kind_name(kind),
        board.env_name,
        execution_env,
        ctx.trace,
        ctx.fault_test,
        ctx.check_stack,
        predeployment_config
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    )
}

fn firmware_kind_name(kind: FirmwareKind) -> &'static str {
    match kind {
        FirmwareKind::GpKernel => "kernel",
        FirmwareKind::CoreTest => "core_test",
    }
}

fn firmware_fae_is_fresh(
    kind: FirmwareKind,
    firmware: &FirmwareSpec,
    board: BoardSpec,
    _execution_env: &str,
    output: &Path,
    stamp_path: &Path,
    expected_stamp: &str,
    predeployment_config: Option<&Path>,
) -> Result<bool, Box<dyn Error>> {
    if !output.is_file() || !stamp_path.is_file() {
        return Ok(false);
    }
    if fs::read_to_string(stamp_path)? != expected_stamp {
        return Ok(false);
    }

    let repo_root = repo_root()?;
    let output_mtime = file_mtime(output)?;
    let firmware_dir = firmware
        .manifest
        .parent()
        .ok_or("firmware manifest has no parent directory")?;

    let mut dependencies = vec![
        firmware.manifest.clone(),
        firmware_dir.join("src"),
        firmware_dir.join("build.rs"),
        repo_root.join("Cargo.lock"),
        repo_root.join("rust-toolchain.toml"),
        repo_root.join("kernel/core/Cargo.toml"),
        repo_root.join("kernel/core/src"),
        repo_root.join("kernel/bootable").join(board.startup_dir),
        repo_root.join("tooling/build-fae/Cargo.toml"),
        repo_root.join("tooling/build-fae/Cargo.lock"),
        repo_root.join("tooling/build-fae/crates"),
        repo_root.join("tooling/build-fae/rt0"),
        repo_root.join("tooling/build-fae/crates/build-fae-rust/Cargo.toml"),
        repo_root.join("tooling/build-fae/crates/build-fae-rust/src"),
        repo_root.join("config.toml"),
        repo_root.join("configs"),
    ];

    if let Some(path) = predeployment_config {
        dependencies.push(path.to_path_buf());
    }

    if matches!(kind, FirmwareKind::GpKernel) {
        dependencies.extend([
            repo_root.join("rustlets"),
            repo_root.join("rustlets/rustlet_runtime/Cargo.toml"),
            repo_root.join("rustlets/rustlet_runtime/src"),
        ]);
    }

    for dependency in dependencies {
        if path_has_file_newer_than_with_policy(&dependency, output_mtime, false)? {
            eprintln!(
                "xtask: rebuild firmware FAE {} because {} changed",
                firmware.bin_name,
                dependency.display()
            );
            return Ok(false);
        }
    }

    Ok(true)
}

/// Child-process build settings. Resolving them never mutates xtask's environment.
struct BuildManifestEnv {
    values: std::collections::BTreeMap<&'static str, Option<String>>,
}
impl BuildManifestEnv {
    fn resolve(
        ctx: &BuildContext,
        root: &Path,
        board: &str,
        execution_env: &str,
    ) -> Result<Self, Box<dyn Error>> {
        if ctx.trace == TraceMode::Jtag && board != "raspi-pico1" {
            return Err(format!("--trace=jtag is unsupported on {board}").into());
        }
        let path = ctx.effective_config(root)?;
        let manifest: PredeploymentManifestConfig = toml::from_str(&fs::read_to_string(&path)?)?;
        let image = resolve_kernel_image_manifest(&manifest)?;
        let mut out = Self {
            values: BUILD_MANIFEST_ENV
                .iter()
                .map(|name| (*name, None))
                .collect(),
        };
        out.set("OXIDE_SE_BUILD_CONFIG", path.display().to_string());
        out.set("OXIDE_SE_BOARD", board);
        out.set("OXIDE_SE_EXECUTION_ENV", execution_env);
        out.set("OXIDE_SE_TRACE", ctx.trace.env_value());
        out.set("OXIDE_SE_KERNEL_IMAGE_MODE", image.mode);
        out.set("OXIDE_SE_KERNEL_APP_MODULES", image.modules.join(","));
        if image.mode == KERNEL_IMAGE_MODE_KERNEL_ONLY {
            out.set("OXIDE_SE_DEFAULT_SECURITY_DOMAIN", "NullSecurityDomain");
            out.set(
                "OXIDE_SE_ROOT_SECURITY_DOMAIN_AID",
                "A0:00:00:47:50:4F:53:01",
            );
            out.set("OXIDE_SE_SCP11_PROFILES", "");
            out.set("OXIDE_SE_SECURE_CHANNEL_MODE", "None");
        } else {
            let sd = manifest
                .root
                .as_ref()
                .ok_or("global-platform images require [root]")?;
            let sc = resolve_secure_channel_manifest(&manifest.secure_channel)?;
            validate_predeployment_keys(&manifest)?;
            out.set(
                "OXIDE_SE_DEFAULT_SECURITY_DOMAIN",
                root_security_domain_kind(&sd.package),
            );
            out.set("OXIDE_SE_ROOT_SECURITY_DOMAIN_AID", &sd.instance.aid);
            if let Some(p) = sc.scp03_profile {
                out.set("OXIDE_SE_SCP03_PROFILE", p);
            }
            out.set(
                "OXIDE_SE_SCP11_PROFILES",
                sc.scp11_profiles.as_deref().unwrap_or(""),
            );
            out.set("OXIDE_SE_SECURE_CHANNEL_MODE", sc.mode);
        }
        if let Some(fault) = ctx.fault_test {
            out.set(fault, "1");
        }
        Ok(out)
    }
    fn set(&mut self, key: &'static str, value: impl Into<String>) {
        self.values.insert(key, Some(value.into()));
    }
    /// Clear inherited values for disabled protocols and fault modes as well.
    fn apply(&self, command: &mut Command) {
        for (name, value) in &self.values {
            match value {
                Some(value) => {
                    command.env(name, value);
                }
                None => {
                    command.env_remove(name);
                }
            }
        }
    }
    fn get(&self, name: &str) -> &str {
        self.values
            .get(name)
            .and_then(|v| v.as_deref())
            .unwrap_or("")
    }
}

fn validate_predeployment_keys(
    manifest: &PredeploymentManifestConfig,
) -> Result<(), Box<dyn Error>> {
    let root = manifest
        .root
        .as_ref()
        .ok_or("predeployment key validation requires a [root] configuration")?;
    let mut identities = std::collections::BTreeSet::new();
    validate_security_domain_keys(&root.instance.aid, &root.keys, "root.keys", &mut identities)?;
    for (index, security_domain) in manifest.security_domains.iter().enumerate() {
        validate_security_domain_keys(
            &security_domain.instance.aid,
            &security_domain.keys,
            &format!("security_domains[{index}].keys"),
            &mut identities,
        )?;
    }
    Ok(())
}

fn validate_security_domain_keys(
    owner: &str,
    keys: &[PredeploymentKeyConfig],
    field_name: &str,
    identities: &mut std::collections::BTreeSet<(String, u8, u8, u8)>,
) -> Result<(), Box<dyn Error>> {
    for key in keys {
        if key.key_type != "Scp03Static" {
            return Err(format!(
                "unsupported {field_name}.type '{}'; expected Scp03Static",
                key.key_type
            )
            .into());
        }
        let usage = match key.usage.as_str() {
            "Enc" => 0x01,
            "Mac" => 0x02,
            other => {
                return Err(format!(
                    "unsupported {field_name}.usage '{other}'; expected Enc or Mac"
                )
                .into())
            }
        };
        let material = parse_manifest_hex_bytes(&key.material, &format!("{field_name}.material"))?;
        if material.len() != 16 {
            return Err(format!(
                "{field_name}.material must contain exactly 16 bytes for Scp03Static, got {}",
                material.len()
            )
            .into());
        }
        if !identities.insert((owner.to_owned(), key.version, key.id, usage)) {
            return Err(format!(
                "duplicate {field_name} entry for version {}, id {}, usage {}",
                key.version, key.id, key.usage
            )
            .into());
        }
    }
    Ok(())
}

fn parse_manifest_hex_bytes(value: &str, field_name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let compact: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if !compact.len().is_multiple_of(2) {
        return Err(format!("{field_name} must contain an even number of hex digits").into());
    }
    let mut bytes = Vec::with_capacity(compact.len() / 2);
    for index in 0..(compact.len() / 2) {
        let start = index * 2;
        bytes.push(
            u8::from_str_radix(&compact[start..start + 2], 16)
                .map_err(|_| format!("{field_name} contains invalid hex"))?,
        );
    }
    Ok(bytes)
}

const BUILD_MANIFEST_ENV: &[&str] = &[
    "OXIDE_SE_BUILD_CONFIG",
    "OXIDE_SE_KERNEL_STACK_GUARD_TEST",
    "OXIDE_SE_KERNEL_RAM_NX_TEST",
    "OXIDE_SE_BOARD",
    "OXIDE_SE_EXECUTION_ENV",
    "OXIDE_SE_TRACE",
    "OXIDE_SE_DEFAULT_SECURITY_DOMAIN",
    "OXIDE_SE_ROOT_SECURITY_DOMAIN_AID",
    "OXIDE_SE_SCP03_PROFILE",
    "OXIDE_SE_SCP11_PROFILES",
    "OXIDE_SE_SECURE_CHANNEL_MODE",
    "OXIDE_SE_KERNEL_IMAGE_MODE",
    "OXIDE_SE_KERNEL_APP_MODULES",
];

struct ResolvedSecureChannelManifest {
    mode: &'static str,
    scp03_profile: Option<&'static str>,
    scp11_profiles: Option<String>,
}

fn resolve_secure_channel_manifest(
    manifest: &SecureChannelManifestConfig,
) -> Result<ResolvedSecureChannelManifest, Box<dyn Error>> {
    let supports_scp03 = manifest
        .protocols
        .iter()
        .any(|protocol| protocol.eq_ignore_ascii_case("SCP03"));
    let supports_scp11 = manifest
        .protocols
        .iter()
        .any(|protocol| protocol.eq_ignore_ascii_case("SCP11"));
    for protocol in &manifest.protocols {
        if !protocol.eq_ignore_ascii_case("SCP03") && !protocol.eq_ignore_ascii_case("SCP11") {
            return Err(format!(
                "unsupported secure_channel protocol {protocol}; expected SCP03 or SCP11"
            )
            .into());
        }
    }

    let scp03_profile = match manifest.scp03_profile.as_deref() {
        Some(_) if !supports_scp03 => {
            return Err("secure_channel.scp03_profile requires protocols = [\"SCP03\", ...]".into())
        }
        Some("S8") => Some("S8"),
        Some("S16") => Some("S16"),
        Some(profile) => {
            return Err(format!("unsupported secure_channel.scp03_profile {profile}").into())
        }
        None if supports_scp03 => Some("S8"),
        None => None,
    };

    if !supports_scp11 && !manifest.scp11_profiles.is_empty() {
        return Err("secure_channel.scp11_profiles requires protocols = [\"SCP11\", ...]".into());
    }
    if supports_scp11 && manifest.scp11_profiles.is_empty() {
        return Err("secure_channel.scp11_profiles is required when SCP11 is enabled".into());
    }

    let mut scp11_profiles = String::new();
    for profile in &manifest.scp11_profiles {
        let normalized = match profile.as_str() {
            "A" | "a" => "A",
            "B" | "b" => "B",
            "C" | "c" => "C",
            _ => {
                return Err(format!(
                    "unsupported secure_channel.scp11_profiles entry {profile}; expected A, B, or C"
                )
                .into())
            }
        };
        if !scp11_profiles.split(',').any(|entry| entry == normalized) {
            if !scp11_profiles.is_empty() {
                scp11_profiles.push(',');
            }
            scp11_profiles.push_str(normalized);
        }
    }

    let mode = match (supports_scp03, supports_scp11) {
        (false, false) => "None",
        (true, false) => "Scp03Only",
        (false, true) => "Scp11Only",
        (true, true) => "Scp03AndScp11",
    };

    Ok(ResolvedSecureChannelManifest {
        mode,
        scp03_profile,
        scp11_profiles: supports_scp11.then_some(scp11_profiles),
    })
}

fn root_security_domain_kind(package: &PredeploymentSecurityDomainPackageConfig) -> &'static str {
    match package.name.as_str() {
        "KernelSecurityDomain" => "KernelSecurityDomain",
        "NullSecurityDomain" | "" if package.path.is_empty() => "NullSecurityDomain",
        _ => "RustletSecurityDomainProxy",
    }
}

fn predeployment_embedded_rustlets(
    ctx: &BuildContext,
    repo_root: &Path,
) -> Result<Vec<EmbeddedRustletBuildEntry>, Box<dyn Error>> {
    let config_path = ctx.manifest_path(repo_root);
    let source = fs::read_to_string(&config_path).map_err(|err| {
        format!(
            "failed to read predeployment config {}: {err}",
            config_path.display()
        )
    })?;
    let manifest: PredeploymentManifestConfig = toml::from_str(&source).map_err(|err| {
        format!(
            "failed to parse predeployment config {}: {err}",
            config_path.display()
        )
    })?;

    let kernel_image = resolve_kernel_image_manifest(&manifest)?;
    if kernel_image.mode == KERNEL_IMAGE_MODE_KERNEL_ONLY {
        return Ok(Vec::new());
    }

    let root = manifest
        .root
        .ok_or("global-platform images require a [root] configuration")?;

    let mut entries = Vec::new();
    push_embedded_security_domain_package_entry(&mut entries, &root.package)?;
    for package in root.packages {
        push_embedded_rustlet_entry(&mut entries, &package.path, None)?;
    }
    for security_domain in manifest.security_domains {
        push_embedded_security_domain_package_entry(&mut entries, &security_domain.package)?;
        for package in security_domain.packages {
            push_embedded_rustlet_entry(&mut entries, &package.path, None)?;
        }
    }
    Ok(entries)
}

fn push_embedded_security_domain_package_entry(
    entries: &mut Vec<EmbeddedRustletBuildEntry>,
    package: &PredeploymentSecurityDomainPackageConfig,
) -> Result<(), Box<dyn Error>> {
    if package.path.is_empty() {
        return Ok(());
    }
    push_embedded_rustlet_entry(entries, &package.path, Some(RustletFaeAbi::SecurityDomain))
}

fn push_embedded_rustlet_entry(
    entries: &mut Vec<EmbeddedRustletBuildEntry>,
    crate_dir: &str,
    fae_abi: Option<RustletFaeAbi>,
) -> Result<(), Box<dyn Error>> {
    let mut entry = embedded_rustlet_build_entry_from_crate_dir(crate_dir)?;
    // A package can preload SD code without preinstalling an SD instance.
    // Its placement in `packages` must not override the code's declared ABI.
    if let Some(fae_abi) = fae_abi {
        entry.fae_abi = fae_abi;
    }
    if let Some(existing) = entries.iter().find(|existing| {
        existing.crate_dir == entry.crate_dir && existing.bin_name == entry.bin_name
    }) {
        if existing.fae_abi != entry.fae_abi {
            return Err(format!(
                "{} cannot be predeployed as both a Rustlet application and a Security Domain",
                entry.crate_dir
            )
            .into());
        }
        return Ok(());
    }
    entries.push(entry);
    Ok(())
}

fn default_predeployment_config_relpath(repo_root: &Path) -> String {
    let workspace_manifest = repo_root.join("Cargo.toml");
    let source = fs::read_to_string(&workspace_manifest).unwrap_or_default();
    toml::from_str::<WorkspaceManifestConfig>(&source)
        .ok()
        .and_then(|manifest| manifest.workspace.metadata.oxide_se.default_config_toml)
        .unwrap_or_else(|| "config.toml".to_owned())
}

fn build_embedded_rustlets(
    ctx: &BuildContext,
    tool_manifest: &Path,
    board: BoardSpec,
    execution_env: &str,
) -> Result<(), Box<dyn Error>> {
    let repo_root = repo_root()?;
    let mut requested_test_names = Vec::new();
    for entry in predeployment_embedded_rustlets(ctx, &repo_root)? {
        if let Some(test_name) = test_name_from_crate_dir(entry.crate_dir) {
            if !requested_test_names
                .iter()
                .any(|existing| existing == test_name)
            {
                requested_test_names.push(test_name.to_owned());
            }
            continue;
        }

        build_embedded_app(
            ctx,
            tool_manifest,
            entry.crate_dir,
            entry.bin_name,
            entry.fae_abi,
            board,
            execution_env,
        )?;
    }

    if !requested_test_names.is_empty() {
        build_test_rustlets(&repo_root, board, &requested_test_names)?;
    }

    Ok(())
}

fn build_embedded_app(
    ctx: &BuildContext,
    tool_manifest: &Path,
    crate_dir: &str,
    bin_name: &str,
    fae_abi: RustletFaeAbi,
    board: BoardSpec,
    execution_env: &str,
) -> Result<(), Box<dyn Error>> {
    let repo_root = repo_root()?;
    if let Some(test_name) = test_name_from_crate_dir(crate_dir) {
        if test_name != "declare_macro_forms" {
            return build_test_rustlets(&repo_root, board, &[test_name.to_owned()]);
        }
    }
    let app_manifest = repo_root.join(crate_dir).join("Cargo.toml");
    let fae_path = embedded_app_fae_path(&repo_root, crate_dir, bin_name);
    let stamp_path = embedded_app_fae_stamp_path(&repo_root, crate_dir, bin_name);
    let stamp = embedded_app_fae_stamp(board, execution_env, fae_abi.cli_name());

    if embedded_app_fae_is_fresh(
        &repo_root,
        crate_dir,
        bin_name,
        &fae_path,
        &stamp_path,
        &stamp,
    )? {
        eprintln!("xtask: reuse embedded FAE {}", fae_path.display());
        return Ok(());
    }

    run_build_fae(
        ctx,
        tool_manifest,
        &app_manifest,
        bin_name,
        Some(Packaging::Fae),
        Some(fae_abi.cli_name()),
        board,
        execution_env,
        None,
        None,
    )?;

    fs::write(&stamp_path, stamp)?;
    Ok(())
}

fn test_name_from_crate_dir(crate_dir: &str) -> Option<&str> {
    crate_dir.strip_prefix("rustlets/tests/")
}

fn build_test_rustlets(
    repo_root: &Path,
    board: BoardSpec,
    requested_tests: &[String],
) -> Result<(), Box<dyn Error>> {
    let tests_manifest = repo_root.join("rustlets/tests/Cargo.toml");
    let mut command = Command::new("cargo");
    command
        .arg("run")
        .arg("--manifest-path")
        .arg(tests_manifest)
        .arg("--")
        .arg("build-fae");

    for test_name in requested_tests {
        command.arg(test_name);
    }

    command.env("RUSTLET_TARGET", board.rust_target);

    run_checked(&mut command, "cargo run rustlets/tests build-fae")
}

fn embedded_app_fae_path(repo_root: &Path, crate_dir: &str, bin_name: &str) -> PathBuf {
    repo_root
        .join(crate_dir)
        .join("build")
        .join(format!("{bin_name}.fae"))
}

fn embedded_app_fae_stamp_path(repo_root: &Path, crate_dir: &str, bin_name: &str) -> PathBuf {
    repo_root
        .join(crate_dir)
        .join("build")
        .join(format!("{bin_name}.fae.stamp"))
}

fn embedded_app_fae_stamp(board: BoardSpec, execution_env: &str, fae_abi: &str) -> String {
    format!(
        "board={}\nrust_target={}\nruntime_startup={}\nexecution_env={}\nabi={}\nalign_size=2048\nalign_payload=0\n",
        board.env_name,
        board.rust_target,
        runtime_startup_for_target(board.rust_target),
        execution_env,
        fae_abi
    )
}

fn runtime_startup_for_target(target: &str) -> &'static str {
    if target.starts_with("thumbv6m") {
        "thumbv6m-v2"
    } else {
        "default"
    }
}

fn embedded_app_fae_is_fresh(
    repo_root: &Path,
    crate_dir: &str,
    bin_name: &str,
    fae_path: &Path,
    stamp_path: &Path,
    expected_stamp: &str,
) -> Result<bool, Box<dyn Error>> {
    if !fae_path.is_file() || !stamp_path.is_file() {
        return Ok(false);
    }
    if fs::read_to_string(stamp_path)? != expected_stamp {
        return Ok(false);
    }

    let fae_mtime = file_mtime(fae_path)?;
    let app_dir = repo_root.join(crate_dir);
    let dependencies = [
        app_dir.join("Cargo.toml"),
        app_dir.join("src"),
        repo_root.join("Cargo.lock"),
        repo_root.join("rust-toolchain.toml"),
        repo_root.join("rustlets/rustlet_runtime/Cargo.toml"),
        repo_root.join("rustlets/rustlet_runtime/src"),
        repo_root.join("tooling/build-fae/Cargo.toml"),
        repo_root.join("tooling/build-fae/Cargo.lock"),
        repo_root.join("tooling/build-fae/crates"),
        repo_root.join("tooling/build-fae/rt0"),
        repo_root.join("tooling/build-fae/crates/build-fae-rust/Cargo.toml"),
        repo_root.join("tooling/build-fae/crates/build-fae-rust/src"),
    ];

    for dependency in dependencies {
        if path_has_file_newer_than(&dependency, fae_mtime)? {
            eprintln!(
                "xtask: rebuild embedded FAE {} because {} changed",
                bin_name,
                dependency.display()
            );
            return Ok(false);
        }
    }

    Ok(true)
}

fn file_mtime(path: &Path) -> Result<SystemTime, Box<dyn Error>> {
    Ok(fs::metadata(path)?.modified()?)
}

fn path_has_file_newer_than(path: &Path, reference: SystemTime) -> Result<bool, Box<dyn Error>> {
    path_has_file_newer_than_with_policy(path, reference, true)
}

fn path_has_file_newer_than_with_policy(
    path: &Path,
    reference: SystemTime,
    skip_build_dirs: bool,
) -> Result<bool, Box<dyn Error>> {
    if !path.exists() {
        return Ok(false);
    }

    if path.is_file() {
        return Ok(file_mtime(path)? > reference);
    }

    if is_cache_dir(path, skip_build_dirs) {
        return Ok(false);
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if is_cache_dir(&entry_path, skip_build_dirs) {
            continue;
        }
        if path_has_file_newer_than_with_policy(&entry_path, reference, skip_build_dirs)? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn is_cache_dir(path: &Path, skip_build_dirs: bool) -> bool {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("target") | Some(".git") => true,
        Some("build") => skip_build_dirs,
        _ => false,
    }
}

// This boundary deliberately mirrors the build-fae CLI. Keeping each option
// named here makes command construction auditable and avoids an opaque bag of
// arguments shared with unrelated build phases.
#[allow(clippy::too_many_arguments)]
fn run_build_fae(
    ctx: &BuildContext,
    tool_manifest: &Path,
    app_manifest: &Path,
    bin_name: &str,
    packaging: Option<Packaging>,
    fae_abi: Option<&str>,
    board: BoardSpec,
    execution_env: &str,
    output_dir: Option<&Path>,
    target_dir: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let mut cargo = Command::new("cargo");
    cargo
        .arg("run")
        .arg("--manifest-path")
        .arg(tool_manifest)
        .arg("--bin")
        .arg("build_fae_rust")
        .arg("--")
        .arg("--manifest-path")
        .arg(app_manifest)
        .arg("--bin")
        .arg(bin_name)
        .arg("--target")
        .arg(board.rust_target)
        .arg("--align_size")
        .arg("2048")
        .env("OXIDE_SE_BOARD", board.env_name)
        .env("OXIDE_SE_EXECUTION_ENV", execution_env)
        .env("OXIDE_SE_TRACE", ctx.trace.env_value());
    if let Some(fae_abi) = fae_abi {
        match fae_abi {
            "rustlet" => {
                cargo.arg("--rustlet");
            }
            "rustlet-security-domain" => {
                cargo.arg("--securitydomain");
            }
            other => return Err(format!("unsupported Rustlet FAE profile: {other}").into()),
        }
    }
    if let Some(dir) = output_dir {
        cargo.env("BUILD_FAE_BUILD_DIR", dir);
    }
    if let Some(dir) = target_dir {
        cargo.env("BUILD_FAE_TARGET_DIR", dir);
    }

    match packaging {
        None => {
            cargo.arg("--elf");
        }
        Some(Packaging::Fae) => {
            cargo.arg("--fae");
        }
        Some(Packaging::Bootable(board)) => {
            cargo.arg("bootable").arg(board.machine);
        }
    }

    BuildManifestEnv::resolve(ctx, &repo_root()?, board.env_name, execution_env)?.apply(&mut cargo);
    run_checked(&mut cargo, "xiprfs build-fae-rust")
}

fn parse_core_test_output(stdout: &str, stderr: &str) -> Result<TestReport, Box<dyn Error>> {
    let combined = if stdout.is_empty() {
        stderr.to_owned()
    } else if stderr.is_empty() {
        stdout.to_owned()
    } else {
        format!("{stdout}\n{stderr}")
    };

    let mut begin_count = 0usize;
    let mut pass_count = 0usize;
    let mut fail_count = 0usize;
    let mut done = None;

    for line in combined.lines() {
        if line.starts_with("TEST-BEGIN ") {
            begin_count += 1;
        } else if line.starts_with("TEST-PASS ") {
            pass_count += 1;
        } else if line.starts_with("TEST-FAIL ") {
            fail_count += 1;
        } else if let Some(fields) = line.strip_prefix("TEST-DONE ") {
            let mut total = None;
            let mut failed = None;
            for field in fields.split_whitespace() {
                if let Some(value) = field.strip_prefix("total=") {
                    total = Some(value.parse::<usize>()?);
                } else if let Some(value) = field.strip_prefix("failed=") {
                    failed = Some(value.parse::<usize>()?);
                }
            }
            done = Some((
                total.ok_or("missing total in TEST-DONE")?,
                failed.ok_or("missing failed in TEST-DONE")?,
            ));
        }
    }

    let (total, failed) = done
        .ok_or_else(|| format!("missing TEST-DONE marker\nstdout:\n{stdout}\nstderr:\n{stderr}"))?;

    if begin_count != total || pass_count + fail_count != total || fail_count != failed {
        return Err(format!(
            "inconsistent test trace (begin={begin_count}, pass={pass_count}, fail={fail_count}, total={total}, failed={failed})\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )
        .into());
    }

    Ok(TestReport {
        total,
        failed,
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
    })
}

fn firmware_spec(kind: FirmwareKind) -> Result<FirmwareSpec, Box<dyn Error>> {
    let repo_root = repo_root()?;
    let (manifest_rel, bin_name) = match kind {
        FirmwareKind::GpKernel => ("kernel/firmware/Cargo.toml", "kernel"),
        FirmwareKind::CoreTest => ("core_test/Cargo.toml", "core_test"),
    };

    Ok(FirmwareSpec {
        manifest: repo_root.join(manifest_rel),
        bin_name,
    })
}

fn firmware_image_path(kind: FirmwareKind) -> Result<PathBuf, Box<dyn Error>> {
    let firmware = firmware_spec(kind)?;
    Ok(kernel_firmware_work_dir()?.join(format!("{}.fae", firmware.bin_name)))
}

fn firmware_elf_path(kind: FirmwareKind) -> Result<PathBuf, Box<dyn Error>> {
    let firmware = firmware_spec(kind)?;
    firmware_elf_path_from_spec(&firmware)
}

fn firmware_elf_path_from_spec(firmware: &FirmwareSpec) -> Result<PathBuf, Box<dyn Error>> {
    Ok(kernel_firmware_work_dir()?.join(format!("{}.elf", firmware.bin_name)))
}

fn kernel_target_dir() -> Result<PathBuf, Box<dyn Error>> {
    Ok(repo_root()?.join("target").join("kernel"))
}

fn kernel_firmware_work_dir() -> Result<PathBuf, Box<dyn Error>> {
    Ok(kernel_target_dir()?.join("firmware"))
}

fn write_board_linker_script(
    board: BoardSpec,
    image_kind: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let path = kernel_target_dir()?
        .join("support")
        .join(format!("{image_kind}-{}.ld", board.env_name));
    fs::create_dir_all(
        path.parent()
            .ok_or("generated linker script has no parent")?,
    )?;
    fs::write(&path, render_board_linker_script(board, image_kind)?)?;
    Ok(path)
}

fn render_board_linker_script(
    board: BoardSpec,
    image_kind: &str,
) -> Result<String, Box<dyn Error>> {
    let layout = read_target_memory_layout(board)?;
    let linker_include = linker_script_include(board, image_kind);
    Ok(format!(
        "/* Generated by xtask from {}. Do not edit. */\n\
ENTRY(_start)\n\n\
PROVIDE(__STACK_SIZE_CPU0 = {:#010x});\n\n\
MEMORY\n\
{{\n\
  FLASH (rx) : ORIGIN = {:#010x}, LENGTH = {:#x}\n\
  RAM   (rwx): ORIGIN = {:#010x}, LENGTH = {:#x}\n\
}}\n\n\
INCLUDE {linker_include}\n",
        board.target_source,
        layout.kernel_stack_size,
        layout.flash_base,
        layout.flash_size,
        layout.ram_base,
        layout.ram_size
    ))
}

fn linker_script_include(board: BoardSpec, image_kind: &str) -> String {
    if image_kind == "native" && board.env_name == "raspi-pico1" {
        return "kernel/native/raspi-pico/link.ld".to_owned();
    }
    if image_kind == "native" && board.env_name == "raspi-pico2" {
        return "kernel/native/raspi-pico2/link.ld".to_owned();
    }

    format!("kernel/{image_kind}/generic-cortex-m/link.ld")
}

fn board_catalog() -> &'static [BoardCatalogEntry] {
    BOARD_CATALOG
}

fn board_spec(name: &str) -> Result<BoardSpec, Box<dyn Error>> {
    board_catalog()
        .iter()
        .find(|entry| entry.spec.env_name == name)
        .map(|entry| entry.spec)
        .ok_or_else(|| {
            format!(
                "unsupported board '{name}' (expected one of: {})",
                known_board_names().join(", ")
            )
            .into()
        })
}

fn is_rustlet_qemu_board(name: &str) -> bool {
    board_catalog()
        .iter()
        .find(|entry| entry.spec.env_name == name)
        .is_some_and(|entry| entry.qemu_support && entry.support_level.supports_rustlets())
}

fn known_board_names() -> Vec<&'static str> {
    board_catalog()
        .iter()
        .map(|entry| entry.spec.env_name)
        .collect()
}

fn rustlet_qemu_board_names() -> Vec<&'static str> {
    board_catalog()
        .iter()
        .filter(|entry| entry.qemu_support && entry.support_level.supports_rustlets())
        .map(|entry| entry.spec.env_name)
        .collect()
}

fn board_support_level_summary() -> Vec<String> {
    board_catalog()
        .iter()
        .map(|entry| {
            let validation = validation_environment_label(entry.qemu_support, entry.board_support);
            format!(
                "{}={}[{}]",
                entry.spec.env_name,
                entry.support_level.label(),
                validation
            )
        })
        .collect()
}

fn validation_environment_label(qemu_support: bool, board_support: bool) -> &'static str {
    match (qemu_support, board_support) {
        (false, false) => "none",
        (true, false) => "qemu",
        (false, true) => "hardware",
        (true, true) => "qemu+hardware",
    }
}

#[derive(Clone, Copy, Debug)]
struct FaeFootprint {
    file_size: usize,
    startup_size: usize,
    got_size: usize,
    rom_size: usize,
    rom_ram_size: usize,
    ram_size: usize,
    entrypoint: usize,
    magic: u32,
}

impl FaeFootprint {
    fn loader_ram(self) -> usize {
        self.got_size + self.rom_ram_size + self.ram_size
    }

    fn required_ram(self) -> usize {
        self.loader_ram()
    }
}

#[derive(Clone, Debug)]
struct ElfSectionFootprint {
    name: String,
    size: usize,
    flags: u32,
    section_type: u32,
}

#[derive(Clone, Debug)]
struct ElfFootprint {
    file_size: usize,
    flash_size: usize,
    ram_size: usize,
    entrypoint: usize,
    sections: Vec<ElfSectionFootprint>,
}

#[derive(Clone, Debug)]
enum FirmwareFootprint {
    Fae(FaeFootprint),
    Elf(ElfFootprint),
}

impl FirmwareFootprint {
    fn required_ram(&self) -> usize {
        match self {
            Self::Fae(footprint) => footprint.required_ram(),
            Self::Elf(footprint) => footprint.ram_size,
        }
    }

    fn flash_used(&self) -> usize {
        match self {
            Self::Fae(footprint) => footprint.file_size,
            Self::Elf(footprint) => footprint.flash_size,
        }
    }
}

#[derive(Debug)]
struct EmbeddedFaeReport {
    bin_name: &'static str,
    footprint: FaeFootprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelHeapPartitionReport {
    metadata_start: usize,
    metadata_len: usize,
    heap_start: usize,
    heap_len: usize,
}

#[derive(Debug)]
struct FirmwareLayoutReport {
    kind: FirmwareKind,
    image_format: LayoutImageFormat,
    board: BoardSpec,
    profile: String,
    target: TargetMemoryLayout,
    firmware: FirmwareFootprint,
    embedded: Vec<EmbeddedFaeReport>,
}

impl FirmwareLayoutReport {
    fn stack_base(&self) -> usize {
        self.target.ram_base
    }

    fn stack_top(&self) -> usize {
        self.stack_base() + self.target.kernel_stack_size
    }

    fn boot_abi_base(&self) -> usize {
        self.stack_top()
    }

    fn fae_ram_start(&self) -> usize {
        self.boot_abi_base() + BOOT_ABI_SIZE
    }

    fn ram_end(&self) -> usize {
        self.target.ram_base + self.target.ram_size
    }

    fn kernel_heap_limit(&self) -> usize {
        if self.board.env_name == "raspi-pico1" {
            self.target.ram_base + 48 * 1024
        } else {
            self.ram_end()
        }
    }

    fn fae_ram_budget(&self) -> usize {
        self.ram_end() - self.fae_ram_start()
    }

    fn kernel_heap_free_start(&self) -> usize {
        align_up(
            self.fae_ram_start() + self.firmware.required_ram(),
            ALLOCATION_GRANULE,
        )
    }

    fn kernel_heap_partition(&self) -> Option<KernelHeapPartitionReport> {
        partition_kernel_heap(self.kernel_heap_free_start(), self.kernel_heap_limit())
    }

    fn kernel_heap_size(&self) -> usize {
        self.kernel_heap_partition()
            .map(|partition| partition.heap_len)
            .unwrap_or_default()
    }

    fn ram_overflow(&self) -> Option<usize> {
        self.firmware
            .required_ram()
            .checked_sub(self.fae_ram_budget())
            .filter(|missing| *missing > 0)
    }

    fn flash_overflow(&self) -> Option<usize> {
        self.firmware
            .flash_used()
            .checked_sub(self.target.flash_size)
            .filter(|missing| *missing > 0)
    }

    fn heap_underflow(&self) -> Option<usize> {
        self.target
            .kernel_heap_min_size
            .checked_sub(self.kernel_heap_size())
            .filter(|missing| *missing > 0)
    }

    fn heap_partition_missing(&self) -> bool {
        self.ram_overflow().is_none() && self.kernel_heap_partition().is_none()
    }

    fn constraints_satisfied(&self) -> bool {
        self.ram_overflow().is_none()
            && self.flash_overflow().is_none()
            && self.heap_underflow().is_none()
            && !self.heap_partition_missing()
    }

    fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{} layout for {}",
            firmware_kind_name(self.kind),
            self.board.env_name
        );
        let _ = writeln!(out, "profile: {}", self.profile);
        let _ = writeln!(out);
        let _ = writeln!(out, "Target memory");
        let _ = writeln!(
            out,
            "  RAM   0x{:08x}..0x{:08x} {}",
            self.target.ram_base,
            self.target.ram_base + self.target.ram_size,
            format_bytes(self.target.ram_size)
        );
        let _ = writeln!(
            out,
            "  FLASH 0x{:08x}..0x{:08x} {}",
            self.target.flash_base,
            self.target.flash_base + self.target.flash_size,
            format_bytes(self.target.flash_size)
        );
        let _ = writeln!(out);

        let _ = writeln!(out, "RAM plan");
        let _ = writeln!(
            out,
            "  kernel stack       0x{:08x}..0x{:08x} {}",
            self.stack_base(),
            self.stack_top(),
            format_bytes(self.target.kernel_stack_size)
        );
        let _ = writeln!(
            out,
            "  boot ABI           0x{:08x}..0x{:08x} {}",
            self.boot_abi_base(),
            self.fae_ram_start(),
            format_bytes(BOOT_ABI_SIZE)
        );
        let ram_window_label = match self.image_format {
            LayoutImageFormat::Fae => "FAE runtime window",
            LayoutImageFormat::Elf => "ELF runtime window",
        };
        let _ = writeln!(
            out,
            "  {ram_window_label:<18} 0x{:08x}..0x{:08x} {}",
            self.fae_ram_start(),
            self.kernel_heap_free_start().min(self.ram_end()),
            format_bytes(self.firmware.required_ram().min(self.fae_ram_budget()))
        );
        if let Some(partition) = self.kernel_heap_partition() {
            if self.kernel_heap_limit() != self.ram_end() {
                let _ = writeln!(
                    out,
                    "  kernel heap limit  0x{:08x}           board-specific",
                    self.kernel_heap_limit()
                );
            }
            let _ = writeln!(
                out,
                "  kernel heap meta   0x{:08x}..0x{:08x} {}",
                partition.metadata_start,
                partition.metadata_start + partition.metadata_len,
                format_bytes(partition.metadata_len)
            );
            let _ = writeln!(
                out,
                "  kernel heap        0x{:08x}..0x{:08x} {}",
                partition.heap_start,
                partition.heap_start + partition.heap_len,
                format_bytes(partition.heap_len)
            );
        } else {
            let _ = writeln!(
                out,
                "  kernel heap meta   unavailable after 0x{:08x}",
                self.kernel_heap_free_start()
            );
            let _ = writeln!(out, "  kernel heap        unavailable");
        }
        let _ = writeln!(
            out,
            "  kernel heap min    {}",
            format_bytes(self.target.kernel_heap_min_size)
        );
        let _ = writeln!(out);

        let _ = writeln!(out, "Firmware {}", self.image_format.name_upper());
        render_firmware_footprint(&mut out, "  image", &self.firmware);
        let _ = writeln!(
            out,
            "  required RAM       {} / {}",
            format_bytes(self.firmware.required_ram()),
            format_bytes(self.fae_ram_budget())
        );
        let _ = writeln!(
            out,
            "  flash used         {} / {}",
            format_bytes(self.firmware.flash_used()),
            format_bytes(self.target.flash_size)
        );

        if let Some(missing) = self.ram_overflow() {
            let _ = writeln!(
                out,
                "  RAM OVERFLOW       needs {} more",
                format_bytes(missing)
            );
        }
        if let Some(missing) = self.flash_overflow() {
            let _ = writeln!(
                out,
                "  ROM OVERFLOW       needs {} more",
                format_bytes(missing)
            );
        }
        if let Some(missing) = self.heap_underflow() {
            let _ = writeln!(
                out,
                "  HEAP UNDERFLOW     needs {} more",
                format_bytes(missing)
            );
        }
        if self.heap_partition_missing() {
            let _ = writeln!(out, "  HEAP PARTITION     unavailable after FAE RAM usage");
        }
        if self.constraints_satisfied() {
            let _ = writeln!(out, "  status             OK");
        }
        let _ = writeln!(out);

        let _ = writeln!(out, "Embedded Rustlets");
        if self.embedded.is_empty() {
            let _ = writeln!(out, "  none");
        } else {
            let mut total_file_size = 0usize;
            let mut total_loader_ram = 0usize;
            for entry in &self.embedded {
                total_file_size += entry.footprint.file_size;
                total_loader_ram += entry.footprint.loader_ram();
                let _ = writeln!(
                    out,
                    "  {:32} flash={} loader_ram={}",
                    entry.bin_name,
                    format_bytes(entry.footprint.file_size),
                    format_bytes(entry.footprint.loader_ram())
                );
            }
            let _ = writeln!(
                out,
                "  embedded subtotal              flash={} loader_ram={}",
                format_bytes(total_file_size),
                format_bytes(total_loader_ram)
            );
        }

        out
    }
}

fn firmware_layout_report(
    ctx: &BuildContext,
    kind: FirmwareKind,
    image_format: LayoutImageFormat,
    board: BoardSpec,
    profile: Option<String>,
) -> Result<FirmwareLayoutReport, Box<dyn Error>> {
    let target = read_target_memory_layout(board)?;
    let firmware = match image_format {
        LayoutImageFormat::Fae => {
            FirmwareFootprint::Fae(read_fae_footprint(&firmware_image_path(kind)?)?)
        }
        LayoutImageFormat::Elf => {
            FirmwareFootprint::Elf(read_elf_footprint(&firmware_elf_path(kind)?)?)
        }
    };
    let embedded = if matches!(kind, FirmwareKind::GpKernel) {
        embedded_fae_reports(ctx)?
    } else {
        Vec::new()
    };

    Ok(FirmwareLayoutReport {
        kind,
        image_format,
        board,
        profile: profile.unwrap_or_else(|| "current environment".to_owned()),
        target,
        firmware,
        embedded,
    })
}

fn read_target_memory_layout(board: BoardSpec) -> Result<TargetMemoryLayout, Box<dyn Error>> {
    let repo_root = repo_root()?;
    let source_path = repo_root.join(board.target_source);
    let source = fs::read_to_string(&source_path)?;
    let block = source
        .split("pub const MEMORY_LAYOUT")
        .nth(1)
        .ok_or_else(|| format!("missing MEMORY_LAYOUT in {}", source_path.display()))?;

    let layout = TargetMemoryLayout {
        name: parse_layout_str(block, "name")?,
        ram_base: parse_layout_usize(block, "ram_base")?,
        ram_size: parse_layout_usize(block, "ram_size")?,
        flash_base: parse_layout_usize(block, "flash_base")?,
        flash_size: parse_layout_usize(block, "flash_size")?,
        kernel_heap_min_size: parse_layout_usize(block, "kernel_heap_min_size")?,
        kernel_stack_size: parse_layout_usize(block, "kernel_stack_size")?,
    };

    if layout.name != board.env_name {
        return Err(format!(
            "target MEMORY_LAYOUT name mismatch in {}: expected {}, got {}",
            source_path.display(),
            board.env_name,
            layout.name
        )
        .into());
    }

    Ok(layout)
}

#[cfg(test)]
fn validate_board_linker_layouts(
    _repo_root: &Path,
    board: BoardSpec,
) -> Result<(), Box<dyn Error>> {
    let target = read_target_memory_layout(board)?;
    let native = read_generated_board_linker_memory_layout(board, "native")?;
    let bootable = read_generated_board_linker_memory_layout(board, "bootable")?;

    if native != bootable {
        return Err(format!(
            "{} native and bootable linker memory layouts differ: native={native:?}, bootable={bootable:?}",
            board.env_name
        )
        .into());
    }

    let expected = LinkerMemoryLayout {
        ram_base: target.ram_base,
        ram_size: target.ram_size,
        flash_base: target.flash_base,
        flash_size: target.flash_size,
        kernel_stack_size: target.kernel_stack_size,
    };
    if native != expected {
        return Err(format!(
            "{} linker memory layout does not match {}: linker={native:?}, MEMORY_LAYOUT={expected:?}",
            board.env_name, board.target_source
        )
        .into());
    }

    Ok(())
}

#[cfg(test)]
fn read_generated_board_linker_memory_layout(
    board: BoardSpec,
    image_kind: &str,
) -> Result<LinkerMemoryLayout, Box<dyn Error>> {
    let source = render_board_linker_script(board, image_kind)?;
    let expected_include = format!("INCLUDE {}", linker_script_include(board, image_kind));
    if !source.lines().any(|line| line.trim() == expected_include) {
        return Err(
            format!("generated {image_kind} linker must include {expected_include}").into(),
        );
    }

    let path = PathBuf::from(format!(
        "generated {image_kind} linker for {}",
        board.env_name
    ));
    let (flash_base, flash_size) = parse_linker_memory_region(&source, "FLASH", &path)?;
    let (ram_base, ram_size) = parse_linker_memory_region(&source, "RAM", &path)?;
    let stack_value = source
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("PROVIDE(__STACK_SIZE_CPU0 =")
                .and_then(|value| value.strip_suffix(");"))
        })
        .ok_or_else(|| {
            format!(
                "missing PROVIDE(__STACK_SIZE_CPU0 = ...) in {}",
                path.display()
            )
        })?;

    Ok(LinkerMemoryLayout {
        ram_base,
        ram_size,
        flash_base,
        flash_size,
        kernel_stack_size: parse_linker_number(stack_value).ok_or_else(|| {
            format!(
                "invalid __STACK_SIZE_CPU0 value '{stack_value}' in {}",
                path.display()
            )
        })?,
    })
}

#[cfg(test)]
fn parse_linker_memory_region(
    source: &str,
    region: &str,
    path: &Path,
) -> Result<(usize, usize), Box<dyn Error>> {
    let line = source
        .lines()
        .find(|line| line.trim_start().starts_with(region))
        .ok_or_else(|| format!("missing {region} memory region in {}", path.display()))?;
    let origin_marker = "ORIGIN =";
    let length_marker = "LENGTH =";
    let origin_start = line
        .find(origin_marker)
        .ok_or_else(|| format!("missing ORIGIN for {region} in {}", path.display()))?
        + origin_marker.len();
    let length_start = line
        .find(length_marker)
        .ok_or_else(|| format!("missing LENGTH for {region} in {}", path.display()))?
        + length_marker.len();
    let origin = line[origin_start..]
        .split(',')
        .next()
        .and_then(parse_linker_number)
        .ok_or_else(|| format!("invalid {region} ORIGIN in {}", path.display()))?;
    let length = parse_linker_number(&line[length_start..])
        .ok_or_else(|| format!("invalid {region} LENGTH in {}", path.display()))?;
    Ok((origin, length))
}

#[cfg(test)]
fn parse_linker_number(value: &str) -> Option<usize> {
    let value = value.trim().replace('_', "");
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b'K') | Some(b'k') => (&value[..value.len() - 1], 1024usize),
        Some(b'M') | Some(b'm') => (&value[..value.len() - 1], 1024usize * 1024),
        _ => (value.as_str(), 1usize),
    };
    let parsed = if let Some(hex) = number.strip_prefix("0x") {
        usize::from_str_radix(hex, 16).ok()?
    } else {
        number.parse::<usize>().ok()?
    };
    parsed.checked_mul(multiplier)
}

#[cfg(test)]
fn validate_generic_linker_layout_contract(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let required_statements = [
        "__OXIDE_SE_BOOT_ABI_SIZE=0x20;",
        "__StackLimit=ORIGIN(RAM);",
        "__StackTop=__StackLimit+__STACK_SIZE_CPU0;",
        "__oxide_se_boot_abi_start=__StackTop;",
        "__fae_ram_start=__oxide_se_boot_abi_start+__OXIDE_SE_BOOT_ABI_SIZE;",
        "__fae_ram_end=ORIGIN(RAM)+LENGTH(RAM);",
    ];

    for image_kind in ["native", "bootable"] {
        let path = repo_root
            .join("kernel")
            .join(image_kind)
            .join("generic-cortex-m")
            .join("link.ld");
        let compact_source: String = fs::read_to_string(&path)?
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();
        for statement in required_statements {
            if !compact_source.contains(statement) {
                return Err(format!(
                    "{} no longer defines the required linker layout invariant '{statement}'",
                    path.display()
                )
                .into());
            }
        }
    }

    Ok(())
}

fn parse_layout_str(source: &str, field: &str) -> Result<&'static str, Box<dyn Error>> {
    let raw = parse_layout_value(source, field)?;
    let value = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| format!("layout field {field} must be a string literal"))?;
    Ok(Box::leak(value.to_owned().into_boxed_str()))
}

fn parse_layout_usize(source: &str, field: &str) -> Result<usize, Box<dyn Error>> {
    eval_usize_expr(parse_layout_value(source, field)?)
        .ok_or_else(|| format!("could not parse layout field {field}").into())
}

fn parse_layout_value<'a>(source: &'a str, field: &str) -> Result<&'a str, Box<dyn Error>> {
    let marker = format!("{field}:");
    let start = source
        .find(&marker)
        .ok_or_else(|| format!("missing layout field {field}"))?
        + marker.len();
    let tail = &source[start..];
    let end = tail
        .find(',')
        .ok_or_else(|| format!("missing trailing comma for layout field {field}"))?;
    Ok(tail[..end].trim())
}

fn eval_usize_expr(expr: &str) -> Option<usize> {
    let mut product = 1usize;
    for factor in expr.split('*') {
        let factor = factor.trim().trim_end_matches("usize");
        let value = if let Some(hex) = factor.strip_prefix("0x") {
            usize::from_str_radix(&hex.replace('_', ""), 16).ok()?
        } else {
            factor.replace('_', "").parse::<usize>().ok()?
        };
        product = product.checked_mul(value)?;
    }
    Some(product)
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

fn exact_allocator_metadata_size(storage_addr: usize, size: usize) -> Option<usize> {
    if size < ALLOCATION_GRANULE || !size.is_multiple_of(ALLOCATION_GRANULE) {
        return None;
    }

    let mut virtual_len = if size <= ALLOCATION_GRANULE {
        ALLOCATION_GRANULE
    } else {
        size.checked_next_power_of_two()?
    };
    let mut virtual_start = align_down(storage_addr, virtual_len);
    while storage_addr.checked_add(size)? > virtual_start.checked_add(virtual_len)? {
        virtual_len = virtual_len.checked_mul(2)?;
        virtual_start = align_down(storage_addr, virtual_len);
    }

    let granules = virtual_len / ALLOCATION_GRANULE;
    let total_bits = (2 * granules - 1) * 2;
    Some(total_bits.div_ceil(8))
}

fn partition_kernel_heap(free_start: usize, ram_end: usize) -> Option<KernelHeapPartitionReport> {
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
            exact_allocator_metadata_size(heap_start, heap_len)?,
            ALLOCATION_GRANULE,
        );
        if required_metadata_len <= metadata_len {
            return Some(KernelHeapPartitionReport {
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

fn validate_firmware_layout(
    ctx: &BuildContext,
    kind: FirmwareKind,
    board: BoardSpec,
    profile: Option<String>,
) -> Result<bool, Box<dyn Error>> {
    let report = firmware_layout_report(ctx, kind, LayoutImageFormat::Fae, board, profile)?;
    if report.constraints_satisfied() {
        return Ok(true);
    }

    Err(format!("target memory constraints violated\n{}", report.render()).into())
}

fn embedded_fae_reports(ctx: &BuildContext) -> Result<Vec<EmbeddedFaeReport>, Box<dyn Error>> {
    let repo_root = repo_root()?;
    let mut reports = Vec::new();
    for entry in predeployment_embedded_rustlets(ctx, &repo_root)? {
        let path = embedded_app_fae_path(&repo_root, entry.crate_dir, entry.bin_name);
        if !path.is_file() {
            return Err(format!("missing embedded FAE {}", path.display()).into());
        }
        reports.push(EmbeddedFaeReport {
            bin_name: entry.bin_name,
            footprint: read_fae_footprint(&path)?,
        });
    }
    Ok(reports)
}

fn dump_kernel_layout(
    ctx: &BuildContext,
    image_format: LayoutImageFormat,
    board: &str,
    profile: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let board = board_spec(board)?;
    let owned_ctx = layout_context(ctx, profile)?;
    let ctx = &owned_ctx;

    let packaging = match image_format {
        LayoutImageFormat::Fae => Some(Packaging::Bootable(board)),
        LayoutImageFormat::Elf => None,
    };
    build_firmware(
        ctx,
        FirmwareKind::GpKernel,
        packaging,
        board.env_name,
        "qemu",
    )?;

    let report = firmware_layout_report(
        ctx,
        FirmwareKind::GpKernel,
        image_format,
        board,
        Some(profile.unwrap_or("selected config").to_owned()),
    )?;
    print!("{}", report.render());
    Ok(())
}

fn layout_context(
    ctx: &BuildContext,
    profile: Option<&str>,
) -> Result<BuildContext, Box<dyn Error>> {
    Ok(match profile {
        None | Some("default" | "all") => ctx.clone(),
        Some("minimal") => ctx.with_config("configs/config_rustlet_smoke_test.toml"),
        Some("kernel-main" | "kernel_main" | "kernel_main_app") => {
            ctx.with_config("configs/config_kernel_ping.toml")
        }
        Some(rustlet) => ctx.with_config(generate_single_rustlet_config(
            single_rustlet_spec(rustlet)?.name,
        )?),
    })
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct StackBaselineFile {
    version: u8,
    #[serde(default)]
    campaigns: Vec<StackBaselineCampaign>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct StackBaselineCampaign {
    command: String,
    board: String,
    image: String,
    #[serde(default = "legacy_stack_execution_environment")]
    execution_environment: String,
    #[serde(default)]
    scenario: String,
    #[serde(default = "legacy_stack_monitor_profile")]
    monitor_profile: String,
    measured_commit: String,
    checkpoints: Vec<StackBaselineCheckpoint>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct StackBaselineCheckpoint {
    label: String,
    high_watermark: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StackBaselineKey {
    command: String,
    board: String,
    image: String,
    execution_environment: String,
    scenario: String,
    monitor_profile: String,
}

fn legacy_stack_monitor_profile() -> String {
    LEGACY_STACK_MONITOR_PROFILE.to_owned()
}

fn legacy_stack_execution_environment() -> String {
    "qemu".to_owned()
}

impl StackBaselineKey {
    fn new(
        command: &str,
        board: &str,
        image_format: LayoutImageFormat,
        scenario: Option<&str>,
    ) -> Self {
        Self {
            command: command.to_owned(),
            board: board.to_owned(),
            image: image_format.name_lower().to_owned(),
            execution_environment: legacy_stack_execution_environment(),
            scenario: scenario.unwrap_or_default().to_owned(),
            monitor_profile: STACK_MONITOR_PROFILE.to_owned(),
        }
    }

    fn with_execution_environment(mut self, execution_environment: &str) -> Self {
        self.execution_environment = execution_environment.to_owned();
        self
    }

    fn matches(&self, campaign: &StackBaselineCampaign) -> bool {
        self.command == campaign.command
            && self.board == campaign.board
            && self.image == campaign.image
            && self.execution_environment == campaign.execution_environment
            && self.scenario == campaign.scenario
            && self.monitor_profile == campaign.monitor_profile
    }

    fn display_name(&self) -> String {
        if self.scenario.is_empty() {
            format!(
                "{} {} --{} --on {} ({})",
                self.command,
                self.board,
                self.image,
                self.execution_environment,
                self.monitor_profile
            )
        } else {
            format!(
                "{} {} {} --{} --on {} ({})",
                self.command,
                self.board,
                self.scenario,
                self.image,
                self.execution_environment,
                self.monitor_profile
            )
        }
    }
}

#[derive(Debug)]
struct StackObserver {
    started: Instant,
    backend: &'static str,
    baseline_key: StackBaselineKey,
    expect_rustlet_measurement: bool,
    update_baseline: bool,
    kernel_high_watermark: usize,
    rustlet_high_watermark: usize,
    observations: Vec<StackObservation>,
    command_occurrences: std::collections::BTreeMap<[u8; 4], usize>,
}

impl StackObserver {
    fn new(
        backend: &'static str,
        baseline_key: StackBaselineKey,
        expect_rustlet_measurement: bool,
        update_baseline: bool,
    ) -> Self {
        Self {
            started: Instant::now(),
            backend,
            baseline_key,
            expect_rustlet_measurement,
            update_baseline,
            kernel_high_watermark: STACK_HIGH_WATERMARK_UNKNOWN,
            rustlet_high_watermark: 0,
            observations: Vec::new(),
            command_occurrences: std::collections::BTreeMap::new(),
        }
    }

    fn observe(
        &mut self,
        command: &OwnedT0Command,
        kernel_high_watermark: Option<usize>,
        rustlet_high_watermark: Option<usize>,
    ) {
        let Some(kernel_high_watermark) = kernel_high_watermark else {
            return;
        };
        self.kernel_high_watermark = if self.kernel_high_watermark == STACK_HIGH_WATERMARK_UNKNOWN {
            kernel_high_watermark
        } else {
            self.kernel_high_watermark.max(kernel_high_watermark)
        };
        if let Some(rustlet) = rustlet_high_watermark {
            self.rustlet_high_watermark = self.rustlet_high_watermark.max(rustlet);
        }
        let identity = [command.cla, command.ins, command.p1, command.p2];
        let occurrence = self.command_occurrences.entry(identity).or_default();
        *occurrence += 1;
        let label = format!(
            "APDU {:02X} {:02X} {:02X} {:02X} #{}",
            identity[0], identity[1], identity[2], identity[3], occurrence
        );
        self.observations.push(StackObservation {
            label: label.clone(),
            high_watermark: kernel_high_watermark,
        });
        std::eprintln!(
            "stack-observer: {label}: kernel={kernel_high_watermark} rustlet={}",
            self.rustlet_high_watermark
        );
    }

    fn finish(&self) -> Result<(), Box<dyn Error>> {
        self.finish_observations().map_err(|error| {
            format!(
                "test={} board={} backend={} stage=stack-check elapsed={:.3}s: {error}",
                self.baseline_key.command,
                self.baseline_key.board,
                self.backend,
                self.started.elapsed().as_secs_f64()
            )
            .into()
        })
    }

    fn finish_observations(&self) -> Result<(), Box<dyn Error>> {
        let high_watermark = self.kernel_high_watermark;
        validate_kernel_stack_high_watermark(
            high_watermark,
            read_target_memory_layout(board_spec(&self.baseline_key.board)?)?.kernel_stack_size,
        )?;
        let rustlet_high_watermark = self.rustlet_high_watermark;
        if self.expect_rustlet_measurement && rustlet_high_watermark == 0 {
            return Err("Rustlet stack monitor produced no measurement".into());
        }
        let checkpoints = stack_high_watermark_checkpoints(&self.observations);
        if checkpoints.is_empty() {
            return Err("kernel stack monitor produced no labeled checkpoints".into());
        }

        let repo_root = repo_root()?;
        let baseline_path = repo_root.join(STACK_BASELINES_PATH);
        if self.update_baseline {
            update_stack_baseline(
                &repo_root,
                &baseline_path,
                &self.baseline_key,
                &self.observations,
                &checkpoints,
            )?;
        } else {
            compare_stack_baseline(&baseline_path, &self.baseline_key, &self.observations)?;
        }

        std::eprintln!("stack-check: maximum stack high-watermark = {high_watermark} bytes");
        if rustlet_high_watermark != 0 {
            std::eprintln!(
                "stack-check: maximum Rustlet stack high-watermark = {rustlet_high_watermark} bytes"
            );
        }
        Ok(())
    }
}

fn validate_kernel_stack_high_watermark(
    high_watermark: usize,
    stack_size: usize,
) -> Result<(), String> {
    if high_watermark == STACK_HIGH_WATERMARK_UNKNOWN {
        return Err("kernel stack monitor produced no measurement".to_owned());
    }
    let maximum = stack_size.min(KERNEL_STACK_HIGH_WATERMARK_BUDGET_BYTES);
    if high_watermark > maximum {
        return Err(format!(
            "kernel stack regression: {high_watermark} bytes used, maximum is {maximum} bytes \
             (physical stack is {stack_size} bytes, global budget is \
             {KERNEL_STACK_HIGH_WATERMARK_BUDGET_BYTES} bytes)"
        ));
    }
    Ok(())
}

fn stack_high_watermark_checkpoints(
    observations: &[StackObservation],
) -> Vec<StackBaselineCheckpoint> {
    let mut checkpoints = Vec::new();
    let mut previous = 0;
    for observation in observations {
        if observation.high_watermark > previous {
            checkpoints.push(StackBaselineCheckpoint {
                label: observation.label.clone(),
                high_watermark: observation.high_watermark,
            });
            previous = observation.high_watermark;
        }
    }
    checkpoints
}

fn compare_stack_baseline(
    baseline_path: &Path,
    key: &StackBaselineKey,
    observations: &[StackObservation],
) -> Result<(), Box<dyn Error>> {
    let baselines = read_stack_baselines(baseline_path)?;
    let Some(campaign) = baselines
        .campaigns
        .iter()
        .find(|campaign| key.matches(campaign))
    else {
        std::eprintln!(
            "stack-check: no versioned baseline for {}; run again with \
             --update_stack_baseline on a clean worktree",
            key.display_name()
        );
        return Ok(());
    };
    validate_stack_campaign(campaign, key, observations)
}

fn validate_stack_campaign(
    campaign: &StackBaselineCampaign,
    key: &StackBaselineKey,
    observations: &[StackObservation],
) -> Result<(), Box<dyn Error>> {
    for expected in &campaign.checkpoints {
        let Some(current) = observations
            .iter()
            .filter(|observation| observation.label == expected.label)
            .map(|observation| observation.high_watermark)
            .max()
        else {
            return Err(format!(
                "stack baseline checkpoint '{}' is missing from {}",
                expected.label,
                key.display_name()
            )
            .into());
        };
        if current > expected.high_watermark {
            return Err(format!(
                "kernel stack regression in '{}': {current} bytes used, baseline is {} bytes \
                 (measured at commit {})",
                expected.label, expected.high_watermark, campaign.measured_commit
            )
            .into());
        }
        if current < expected.high_watermark {
            std::eprintln!(
                "stack-check: gain in '{}': {current} bytes used, baseline is {} bytes; \
                 update explicitly with --update_stack_baseline",
                expected.label,
                expected.high_watermark
            );
        }
    }

    let current_max = observations
        .iter()
        .max_by_key(|observation| observation.high_watermark)
        .expect("observations checked non-empty");
    let baseline_max = campaign
        .checkpoints
        .iter()
        .map(|checkpoint| checkpoint.high_watermark)
        .max()
        .ok_or("stack baseline has no checkpoints")?;
    if current_max.high_watermark > baseline_max {
        return Err(format!(
            "kernel stack regression at new checkpoint '{}': {} bytes used, campaign baseline \
             maximum is {baseline_max} bytes (measured at commit {})",
            current_max.label, current_max.high_watermark, campaign.measured_commit
        )
        .into());
    }
    Ok(())
}

fn update_stack_baseline(
    repo_root: &Path,
    baseline_path: &Path,
    key: &StackBaselineKey,
    _observations: &[StackObservation],
    checkpoints: &[StackBaselineCheckpoint],
) -> Result<(), Box<dyn Error>> {
    ensure_clean_git_worktree(repo_root)?;
    let measured_commit = git_output(repo_root, &["rev-parse", "--short=12", "HEAD"])?;
    let mut baselines = read_stack_baselines(baseline_path)?;
    let campaign = StackBaselineCampaign {
        command: key.command.clone(),
        board: key.board.clone(),
        image: key.image.clone(),
        execution_environment: key.execution_environment.clone(),
        scenario: key.scenario.clone(),
        monitor_profile: key.monitor_profile.clone(),
        measured_commit,
        checkpoints: checkpoints.to_vec(),
    };
    if let Some(existing) = baselines
        .campaigns
        .iter_mut()
        .find(|existing| key.matches(existing))
    {
        *existing = campaign;
    } else {
        baselines.campaigns.push(campaign);
    }
    baselines.campaigns.sort_by(|left, right| {
        (
            left.command.as_str(),
            left.board.as_str(),
            left.image.as_str(),
            left.execution_environment.as_str(),
            left.scenario.as_str(),
            left.monitor_profile.as_str(),
        )
            .cmp(&(
                right.command.as_str(),
                right.board.as_str(),
                right.image.as_str(),
                right.execution_environment.as_str(),
                right.scenario.as_str(),
                right.monitor_profile.as_str(),
            ))
    });
    fs::write(baseline_path, render_stack_baselines(&baselines))?;
    std::eprintln!(
        "stack-check: updated {} at commit {}",
        key.display_name(),
        baselines
            .campaigns
            .iter()
            .find(|campaign| key.matches(campaign))
            .expect("updated campaign exists")
            .measured_commit
    );
    Ok(())
}

fn read_stack_baselines(path: &Path) -> Result<StackBaselineFile, Box<dyn Error>> {
    if !path.exists() {
        return Ok(StackBaselineFile {
            version: 2,
            campaigns: Vec::new(),
        });
    }
    let source = fs::read_to_string(path)?;
    let baselines: StackBaselineFile = toml::from_str(&source)?;
    if baselines.version != 2 {
        return Err(format!(
            "unsupported stack baseline format version {} in {}",
            baselines.version,
            path.display()
        )
        .into());
    }
    Ok(baselines)
}

fn render_stack_baselines(baselines: &StackBaselineFile) -> String {
    let mut out = String::from(
        "# Kernel stack high-watermark baselines.\n\
         # Update only through `cargo run test <name> --update_stack_baseline ...`.\n\
         version = 2\n",
    );
    for campaign in &baselines.campaigns {
        out.push_str("\n[[campaigns]]\n");
        writeln!(out, "command = {:?}", campaign.command).unwrap();
        writeln!(out, "board = {:?}", campaign.board).unwrap();
        writeln!(out, "image = {:?}", campaign.image).unwrap();
        writeln!(
            out,
            "execution_environment = {:?}",
            campaign.execution_environment
        )
        .unwrap();
        if !campaign.scenario.is_empty() {
            writeln!(out, "scenario = {:?}", campaign.scenario).unwrap();
        }
        writeln!(out, "monitor_profile = {:?}", campaign.monitor_profile).unwrap();
        writeln!(out, "measured_commit = {:?}", campaign.measured_commit).unwrap();
        for checkpoint in &campaign.checkpoints {
            out.push_str("\n[[campaigns.checkpoints]]\n");
            writeln!(out, "label = {:?}", checkpoint.label).unwrap();
            writeln!(out, "high_watermark = {}", checkpoint.high_watermark).unwrap();
        }
    }
    out
}

fn ensure_clean_git_worktree(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let status = git_output(
        repo_root,
        &["status", "--porcelain", "--untracked-files=no"],
    )?;
    if stack_baseline_update_has_source_changes(&status) {
        return Err(
            "--update_stack_baseline requires clean tracked sources so the recorded commit \
             identifies the measured code; only the baseline file itself may already be modified"
                .into(),
        );
    }
    Ok(())
}

fn stack_baseline_update_has_source_changes(status: &str) -> bool {
    status.lines().any(|line| {
        line.split_ascii_whitespace()
            .last()
            .is_none_or(|path| path != STACK_BASELINES_PATH)
    })
}

fn git_output(repo_root: &Path, args: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .output()?;
    if !output.status.success() {
        return Err(format!("git {} failed with {}", args.join(" "), output.status).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn read_fae_footprint(path: &Path) -> Result<FaeFootprint, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if bytes.len() < 28 {
        return Err(format!("{} is too small to contain a FAE footer", path.display()).into());
    }

    Ok(FaeFootprint {
        file_size: bytes.len(),
        startup_size: read_footer_u32(&bytes, 8)?,
        got_size: read_footer_u32(&bytes, 24)?,
        rom_size: read_footer_u32(&bytes, 20)?,
        rom_ram_size: read_footer_u32(&bytes, 16)?,
        ram_size: read_footer_u32(&bytes, 28)?,
        entrypoint: read_footer_u32(&bytes, 12)?,
        magic: read_footer_u32(&bytes, 4)? as u32,
    })
}

fn read_elf_footprint(path: &Path) -> Result<ElfFootprint, Box<dyn Error>> {
    const EI_CLASS: usize = 4;
    const EI_DATA: usize = 5;
    const ELFCLASS32: u8 = 1;
    const ELFDATA2LSB: u8 = 1;
    const SHT_NOBITS: u32 = 8;
    const SHF_WRITE: u32 = 0x1;
    const SHF_ALLOC: u32 = 0x2;

    let bytes = fs::read(path)?;
    if bytes.get(0..4) != Some(b"\x7fELF") {
        return Err(format!("{} is not an ELF file", path.display()).into());
    }
    if bytes.get(EI_CLASS) != Some(&ELFCLASS32) || bytes.get(EI_DATA) != Some(&ELFDATA2LSB) {
        return Err(format!("{} is not a 32-bit little-endian ELF", path.display()).into());
    }

    let entrypoint = read_elf_u32(&bytes, 0x18)? as usize;
    let shoff = read_elf_u32(&bytes, 0x20)? as usize;
    let shentsize = read_elf_u16(&bytes, 0x2e)? as usize;
    let shnum = read_elf_u16(&bytes, 0x30)? as usize;
    let shstrndx = read_elf_u16(&bytes, 0x32)? as usize;

    if shentsize < 40 {
        return Err(format!("{} has invalid ELF32 section headers", path.display()).into());
    }
    let shstr = section_header(&bytes, shoff, shentsize, shnum, shstrndx)?;
    let shstr_start = shstr.offset;
    let shstr_end = shstr_start
        .checked_add(shstr.size)
        .ok_or("ELF string table overflow")?;
    let shstrtab = bytes
        .get(shstr_start..shstr_end)
        .ok_or("ELF string table is outside the file")?;

    let mut flash_size = 0usize;
    let mut ram_size = 0usize;
    let mut sections = Vec::new();
    for index in 0..shnum {
        let section = section_header(&bytes, shoff, shentsize, shnum, index)?;
        if section.flags & SHF_ALLOC == 0 || section.size == 0 {
            continue;
        }

        let name = elf_section_name(shstrtab, section.name_offset).to_owned();
        if section.flags & SHF_WRITE != 0 {
            ram_size = ram_size
                .checked_add(section.size)
                .ok_or("ELF RAM footprint overflow")?;
        }
        if section.section_type != SHT_NOBITS {
            flash_size = flash_size
                .checked_add(section.size)
                .ok_or("ELF flash footprint overflow")?;
        }
        sections.push(ElfSectionFootprint {
            name,
            size: section.size,
            flags: section.flags,
            section_type: section.section_type,
        });
    }

    Ok(ElfFootprint {
        file_size: bytes.len(),
        flash_size,
        ram_size,
        entrypoint,
        sections,
    })
}

#[derive(Clone, Copy)]
struct ElfSectionHeader {
    name_offset: usize,
    section_type: u32,
    flags: u32,
    offset: usize,
    size: usize,
}

fn section_header(
    bytes: &[u8],
    shoff: usize,
    shentsize: usize,
    shnum: usize,
    index: usize,
) -> Result<ElfSectionHeader, Box<dyn Error>> {
    if index >= shnum {
        return Err(format!("ELF section index {index} is out of range").into());
    }
    let start = shoff
        .checked_add(
            index
                .checked_mul(shentsize)
                .ok_or("ELF section offset overflow")?,
        )
        .ok_or("ELF section offset overflow")?;
    Ok(ElfSectionHeader {
        name_offset: read_elf_u32(bytes, start)? as usize,
        section_type: read_elf_u32(bytes, start + 4)?,
        flags: read_elf_u32(bytes, start + 8)?,
        offset: read_elf_u32(bytes, start + 16)? as usize,
        size: read_elf_u32(bytes, start + 20)? as usize,
    })
}

fn elf_section_name(shstrtab: &[u8], offset: usize) -> &str {
    let Some(tail) = shstrtab.get(offset..) else {
        return "<invalid>";
    };
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(tail.len());
    std::str::from_utf8(&tail[..end]).unwrap_or("<non-utf8>")
}

fn read_elf_u16(bytes: &[u8], offset: usize) -> Result<u16, Box<dyn Error>> {
    let word = bytes
        .get(offset..offset + 2)
        .ok_or("invalid ELF u16 offset")?;
    Ok(u16::from_le_bytes([word[0], word[1]]))
}

fn read_elf_u32(bytes: &[u8], offset: usize) -> Result<u32, Box<dyn Error>> {
    let word = bytes
        .get(offset..offset + 4)
        .ok_or("invalid ELF u32 offset")?;
    Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}

fn read_footer_u32(bytes: &[u8], distance_from_end: usize) -> Result<usize, Box<dyn Error>> {
    let start = bytes
        .len()
        .checked_sub(distance_from_end)
        .ok_or("invalid FAE footer offset")?;
    let word = bytes
        .get(start..start + 4)
        .ok_or("invalid FAE footer word")?;
    Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]) as usize)
}

fn render_fae(out: &mut String, label: &str, fae: &FaeFootprint) {
    let _ = writeln!(out, "{} {}", label, format_bytes(fae.file_size));
    let _ = writeln!(out, "    startup   {}", format_bytes(fae.startup_size));
    let _ = writeln!(out, "    rom       {}", format_bytes(fae.rom_size));
    let _ = writeln!(out, "    got       {}", format_bytes(fae.got_size));
    let _ = writeln!(out, "    rom.ram   {}", format_bytes(fae.rom_ram_size));
    let _ = writeln!(out, "    ram       {}", format_bytes(fae.ram_size));
    let _ = writeln!(out, "    entry     0x{:08x}", fae.entrypoint);
    let _ = writeln!(out, "    magic     0x{:08x}", fae.magic);
}

fn render_firmware_footprint(out: &mut String, label: &str, footprint: &FirmwareFootprint) {
    match footprint {
        FirmwareFootprint::Fae(fae) => render_fae(out, label, fae),
        FirmwareFootprint::Elf(elf) => render_elf(out, label, elf),
    }
}

fn render_elf(out: &mut String, label: &str, elf: &ElfFootprint) {
    let _ = writeln!(out, "{} {}", label, format_bytes(elf.file_size));
    let _ = writeln!(out, "    load      {}", format_bytes(elf.flash_size));
    let _ = writeln!(out, "    ram       {}", format_bytes(elf.ram_size));
    let _ = writeln!(out, "    entry     0x{:08x}", elf.entrypoint);
    for section in &elf.sections {
        let location = if section.flags & 0x1 != 0 {
            "ram"
        } else {
            "rom"
        };
        let kind = if section.section_type == 8 {
            "nobits"
        } else {
            "load"
        };
        let _ = writeln!(
            out,
            "    section {:18} {:6} {:6} {}",
            section.name,
            location,
            kind,
            format_bytes(section.size)
        );
    }
}

fn format_bytes(size: usize) -> String {
    if size >= 1024 && size.is_multiple_of(1024) {
        format!("{} KiB", size / 1024)
    } else {
        format!("{size} B")
    }
}

fn run_checked(cmd: &mut Command, label: &str) -> Result<(), Box<dyn Error>> {
    let status = cmd.status()?;
    if !status.success() {
        return Err(format!("{label} failed with status {status}").into());
    }
    Ok(())
}

fn run_checked_output(cmd: &mut Command, label: &str) -> Result<String, Box<dyn Error>> {
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(format!(
            "{label} failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn host_target() -> Result<String, Box<dyn Error>> {
    let stdout = run_checked_output(Command::new("rustc").arg("-vV"), "rustc -vV")?;
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "rustc -vV did not report a host target".into())
}

fn preferred_nightly_toolchain() -> Result<String, Box<dyn Error>> {
    let host = host_target()?;
    let preferred = format!("nightly-{host}");
    let list = run_checked_output(
        Command::new("rustup").arg("toolchain").arg("list"),
        "rustup toolchain list",
    )?;
    if list
        .lines()
        .any(|line| line.split_whitespace().next() == Some(preferred.as_str()))
    {
        return Ok(preferred);
    }
    if list
        .lines()
        .any(|line| line.split_whitespace().next() == Some("nightly"))
    {
        return Ok("nightly".to_owned());
    }
    Err("no nightly Rust toolchain is installed".into())
}

fn rust_lld_path(toolchain: &str) -> Result<String, Box<dyn Error>> {
    let host = host_target()?;
    let sysroot = run_checked_output(
        Command::new("rustc")
            .arg(format!("+{toolchain}"))
            .arg("--print")
            .arg("sysroot"),
        "rustc --print sysroot",
    )?;
    Ok(Path::new(sysroot.trim())
        .join("lib")
        .join("rustlib")
        .join(host)
        .join("bin")
        .join("rust-lld")
        .display()
        .to_string())
}

fn toml_array(items: &[String]) -> String {
    let mut out = String::from("[");
    for (index, item) in items.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push('"');
        for ch in item.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                _ => out.push(ch),
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

fn repo_root() -> Result<PathBuf, Box<dyn Error>> {
    let mut dir = env::current_dir()?;

    loop {
        if dir.join("Cargo.toml").is_file() && dir.join("xtask/Cargo.toml").is_file() {
            return Ok(dir);
        }

        if !dir.pop() {
            break;
        }
    }

    Err("failed to locate Oxide SE workspace root from current directory".into())
}

fn complete_security_domain_select_fci() -> &'static [u8] {
    &[
        0x6F, 0x10, 0x84, 0x08, 0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x06, 0xA5, 0x04, 0x9F,
        0x65, 0x01, 0x01,
    ]
}

fn complete_security_domain_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x06]
}

fn kernel_security_domain_package_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x01]
}

fn root_security_domain_aid() -> &'static [u8] {
    kernel_security_domain_package_aid()
}

fn complete_security_domain_instance_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x04]
}

fn kernel_security_domain_limited_instance_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x03]
}

fn predeployed_child_security_domain_instance_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x03]
}

fn crate_rustlet_state_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x10]
}

fn crate_rustlet_state_test_instance_b_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x18]
}

fn crate_rustlet_apdus_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x1B]
}

fn crate_rustlet_crypto_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x1C]
}

fn crate_rustlet_ecdh_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x1E]
}

fn crate_rustlet_serialization_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x19]
}

fn crate_rustlet_serialization_test_instance_b_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x1A]
}

fn crate_rustlet_stack_overflow_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x1D]
}

fn crate_rustlet_alloc_free_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x13]
}

fn crate_rustlet_heap_form_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x12]
}

fn crate_rustlet_isolation_fault_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x17]
}

fn crate_rustlet_minimal_valid_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x16]
}

fn crate_rustlet_getting_started_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x20]
}

fn crate_rustlet_minimal_valid_test_instance_b_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x26]
}

fn crate_rustlet_minimal_valid_test_instance_c_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x27]
}

fn crate_rustlet_string_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x14]
}

fn crate_rustlet_termination_test_aid() -> &'static [u8] {
    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x11]
}

struct CommandBuilder;

impl CommandBuilder {
    fn gp_command(ins: u8, p1: u8, p2: u8, data: &[u8], le: u8) -> OwnedT0Command {
        apdu_tool::gp::command(ins, p1, p2, data, le)
            .expect("short GP APDU command data must fit in Lc")
    }

    fn gp_get_data(tag: u16, le: u8) -> OwnedT0Command {
        apdu_tool::gp::get_data(tag, le).expect("valid GP GET DATA command")
    }

    fn gp_get_status(p1: u8, next_occurrence: bool, aid_filter: &[u8]) -> OwnedT0Command {
        apdu_tool::gp::get_status_with_p1(p1, next_occurrence, aid_filter)
            .expect("valid GP GET STATUS command")
    }

    fn gp_store_data_with_tag(tag: u16, data: &[u8]) -> OwnedT0Command {
        apdu_tool::gp::store_data(tag, data).expect("valid GP STORE DATA command")
    }

    fn gp_install_for_load(
        package_aid: &[u8],
        security_domain_aid: &[u8],
        total_len: u32,
        load_file_hash: &[u8],
    ) -> OwnedT0Command {
        apdu_tool::gp::install_for_load(package_aid, security_domain_aid, total_len, load_file_hash)
            .expect("valid GP INSTALL [for load] command")
    }

    fn gp_load_block(block_number: u8, is_last_block: bool, data: &[u8]) -> OwnedT0Command {
        apdu_tool::gp::load_block(block_number, is_last_block, data).expect("valid GP LOAD command")
    }

    fn gp_put_key(key_version: u8, key_id: u8, entries: &[(&[u8], u8)]) -> OwnedT0Command {
        let entries = entries
            .iter()
            .map(|(material, usage)| apdu_tool::gp::KeyEntry {
                usage: match usage {
                    0x01 => apdu_tool::gp::KeyUsage::Scp03Enc,
                    0x02 => apdu_tool::gp::KeyUsage::Scp03Mac,
                    0x11 => apdu_tool::gp::KeyUsage::Scp11SdEcka,
                    0x12 => apdu_tool::gp::KeyUsage::Scp11CaKloc,
                    _ => panic!("unsupported GP key usage {usage:02X}"),
                },
                material: material.to_vec(),
            })
            .collect::<Vec<_>>();
        apdu_tool::gp::put_key(key_version, key_id, &entries).expect("valid GP PUT KEY command")
    }

    fn gp_delete_aid(aid: &[u8]) -> OwnedT0Command {
        let mut data = Vec::with_capacity(2 + aid.len());
        data.push(0x4F);
        data.push(aid.len() as u8);
        data.extend_from_slice(aid);
        Self::gp_command(apdu_tool::gp::INS_DELETE, 0x00, 0x00, &data, 0x00)
    }

    fn gp_set_status(kind: u8, state: u8, aid: &[u8]) -> OwnedT0Command {
        let mut data = Vec::with_capacity(2 + aid.len());
        data.push(0x4F);
        data.push(aid.len() as u8);
        data.extend_from_slice(aid);
        Self::gp_command(apdu_tool::gp::INS_SET_STATUS, kind, state, &data, 0x00)
    }

    fn initialize_update(host_challenge: &[u8]) -> OwnedT0Command {
        Self::initialize_update_with_keyset(0x00, 0x00, host_challenge)
    }

    fn initialize_update_with_keyset(
        key_version: u8,
        _key_id: u8,
        host_challenge: &[u8],
    ) -> OwnedT0Command {
        let le = match host_challenge.len() {
            16 => 0x2C,
            _ => 0x1C,
        };
        Self::gp_command(
            apdu_tool::gp::INS_INITIALIZE_UPDATE,
            key_version,
            0x00,
            host_challenge,
            le,
        )
    }

    fn scp03_external_authenticate(
        security_level: u8,
        host_cryptogram: &[u8],
        session_mac_key: &[u8],
        mac_len: usize,
    ) -> Result<(OwnedT0Command, [u8; 16]), Box<dyn Error>> {
        if host_cryptogram.len() != mac_len || !matches!(mac_len, 8 | 16) {
            return Err("SCP03 EXTERNAL AUTHENTICATE profile lengths do not match".into());
        }
        let lc = host_cryptogram
            .len()
            .checked_add(mac_len)
            .and_then(|len| u8::try_from(len).ok())
            .ok_or("SCP03 EXTERNAL AUTHENTICATE data is too large")?;
        let header = [0x84, 0x82, security_level, 0x00, lc];
        let mut authenticated = Vec::from(header);
        authenticated.extend_from_slice(host_cryptogram);
        let mut initial_mac_chain = [0u8; 16];
        let command_mac = host_chained_truncated_aes_cmac(
            session_mac_key,
            &mut initial_mac_chain,
            &authenticated,
            mac_len,
        )?;
        let mut data = Vec::from(host_cryptogram);
        data.extend_from_slice(&command_mac);
        Ok((
            OwnedT0Command {
                cla: 0x84,
                ins: 0x82,
                p1: security_level,
                p2: 0x00,
                lc,
                le: 0x00,
                data,
            },
            initial_mac_chain,
        ))
    }

    fn scp11c_perform_security_operation(
        ca_key_version: u8,
        ca_key_id: u8,
        certificate_or_key: &[u8],
    ) -> OwnedT0Command {
        Self::gp_command(0x2A, ca_key_version, ca_key_id, certificate_or_key, 0x00)
    }

    fn scp11a_mutual_authenticate(
        key_version: u8,
        key_id: u8,
        host_public: &[u8],
    ) -> OwnedT0Command {
        Self::scp11_mutual_authenticate(key_version, key_id, SCP11A_IDENTIFIER_PARAM, host_public)
    }

    fn scp11c_mutual_authenticate(
        key_version: u8,
        key_id: u8,
        host_public: &[u8],
    ) -> OwnedT0Command {
        Self::scp11_mutual_authenticate(key_version, key_id, SCP11C_IDENTIFIER_PARAM, host_public)
    }

    fn scp11_mutual_authenticate(
        key_version: u8,
        key_id: u8,
        scp11_param: u8,
        host_public: &[u8],
    ) -> OwnedT0Command {
        Self::scp11_mutual_authenticate_with_host_tag(
            key_version,
            key_id,
            scp11_param,
            true,
            host_public,
        )
    }

    fn scp11_mutual_authenticate_with_host_tag(
        key_version: u8,
        key_id: u8,
        scp11_param: u8,
        include_host_tag: bool,
        host_public: &[u8],
    ) -> OwnedT0Command {
        Self::scp11_mutual_authenticate_with_options(
            key_version,
            key_id,
            scp11_param,
            SCP11C_KEY_USAGE_FULL,
            include_host_tag,
            host_public,
        )
    }

    fn scp11_mutual_authenticate_with_usage(
        key_version: u8,
        key_id: u8,
        scp11_param: u8,
        key_usage: u8,
        host_public: &[u8],
    ) -> OwnedT0Command {
        Self::scp11_mutual_authenticate_with_options(
            key_version,
            key_id,
            scp11_param,
            key_usage,
            true,
            host_public,
        )
    }

    fn scp11_mutual_authenticate_with_options(
        key_version: u8,
        key_id: u8,
        scp11_param: u8,
        key_usage: u8,
        include_host_tag: bool,
        host_public: &[u8],
    ) -> OwnedT0Command {
        let mut crt = Vec::new();
        crt.extend_from_slice(&tlv(&[0x90], &[SCP11_IDENTIFIER_FAMILY, scp11_param]));
        crt.extend_from_slice(&tlv(&[0x95], &[key_usage]));
        crt.extend_from_slice(&tlv(&[0x80], &[SCP11C_KEY_TYPE_AES]));
        crt.extend_from_slice(&tlv(&[0x81], &[SCP11C_KEY_LENGTH_AES_128]));
        if include_host_tag {
            crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
        }
        let mut data = tlv(&[0xA6], &crt);
        data.extend_from_slice(&tlv(&[0x5F, 0x49], host_public));
        Self::gp_command(0x82, key_version, key_id, &data, 0x56)
    }

    fn scp11b_internal_authenticate(
        key_version: u8,
        key_id: u8,
        host_public: &[u8],
    ) -> OwnedT0Command {
        Self::scp11b_internal_authenticate_with_usage(
            key_version,
            key_id,
            SCP11C_KEY_USAGE_FULL,
            host_public,
        )
    }

    fn scp11b_internal_authenticate_with_usage(
        key_version: u8,
        key_id: u8,
        key_usage: u8,
        host_public: &[u8],
    ) -> OwnedT0Command {
        let mut crt = Vec::new();
        crt.extend_from_slice(&tlv(
            &[0x90],
            &[SCP11_IDENTIFIER_FAMILY, SCP11B_IDENTIFIER_PARAM],
        ));
        crt.extend_from_slice(&tlv(&[0x95], &[key_usage]));
        crt.extend_from_slice(&tlv(&[0x80], &[SCP11C_KEY_TYPE_AES]));
        crt.extend_from_slice(&tlv(&[0x81], &[SCP11C_KEY_LENGTH_AES_128]));
        crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
        let mut data = tlv(&[0xA6], &crt);
        data.extend_from_slice(&tlv(&[0x5F, 0x49], host_public));
        Self::gp_command(0x88, key_version, key_id, &data, 0x56)
    }

    fn scp11c_mutual_authenticate_raw(key_version: u8, key_id: u8, data: &[u8]) -> OwnedT0Command {
        Self::gp_command(0x82, key_version, key_id, data, 0x56)
    }

    fn protected_gp_get_data_with_mac(tag: u16, command_mac: &[u8], le: u8) -> OwnedT0Command {
        let data = command_mac.to_vec();
        OwnedT0Command {
            cla: 0x84,
            ins: 0xCA,
            p1: (tag >> 8) as u8,
            p2: tag as u8,
            lc: data.len() as u8,
            le,
            data,
        }
    }

    fn protected_gp_get_data(
        tag: u16,
        mac_key: &[u8],
        command_mac_chain: &mut [u8; 16],
        mac_len: usize,
        le: u8,
    ) -> Result<OwnedT0Command, Box<dyn Error>> {
        let mut data = Vec::new();
        let lc = data
            .len()
            .checked_add(mac_len)
            .and_then(|len| u8::try_from(len).ok())
            .ok_or("protected GP GET DATA command too large")?;
        let header = [0x84, 0xCA, (tag >> 8) as u8, tag as u8, lc];
        let mut authenticated = Vec::from(header);
        authenticated.extend_from_slice(&data);
        let command_mac =
            host_chained_truncated_aes_cmac(mac_key, command_mac_chain, &authenticated, mac_len)?;
        data.extend_from_slice(&command_mac);
        Ok(OwnedT0Command {
            cla: 0x84,
            ins: 0xCA,
            p1: (tag >> 8) as u8,
            p2: tag as u8,
            lc,
            le,
            data,
        })
    }

    fn kernel_ping(data: &[u8]) -> OwnedT0Command {
        OwnedT0Command {
            cla: 0x80,
            ins: 0xFE,
            p1: 0x00,
            p2: 0x00,
            lc: data.len() as u8,
            le: data.len() as u8,
            data: data.to_vec(),
        }
    }

    fn kernel_timer(p1: u8) -> OwnedT0Command {
        OwnedT0Command {
            cla: 0x80,
            ins: 0x0a,
            p1,
            p2: 0,
            lc: 0,
            le: 12,
            data: Vec::new(),
        }
    }

    fn gp_rmac_session(ins: u8, p1: u8, p2: u8) -> OwnedT0Command {
        OwnedT0Command {
            cla: 0x80,
            ins,
            p1,
            p2,
            lc: 0,
            le: 0,
            data: Vec::new(),
        }
    }

    fn select(aid: &[u8]) -> OwnedT0Command {
        OwnedT0Command {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            lc: aid.len() as u8,
            le: 0x00,
            data: aid.to_vec(),
        }
    }

    fn install(aid: &[u8]) -> OwnedT0Command {
        Self::install_with_data(aid, &[])
    }

    fn install_with_data(aid: &[u8], install_parameters: &[u8]) -> OwnedT0Command {
        Self::install_with_aids_and_data(aid, aid, aid, install_parameters)
    }

    fn install_with_aids_and_data(
        package_applet_aid: &[u8],
        applet_aid: &[u8],
        instance_aid: &[u8],
        install_parameters: &[u8],
    ) -> OwnedT0Command {
        Self::install_with_aids_privileges_and_data(
            package_applet_aid,
            applet_aid,
            instance_aid,
            &[0x00],
            install_parameters,
        )
    }

    fn install_with_aids_privileges_and_data(
        package_applet_aid: &[u8],
        applet_aid: &[u8],
        instance_aid: &[u8],
        privileges: &[u8],
        install_parameters: &[u8],
    ) -> OwnedT0Command {
        let mut data = Vec::with_capacity(
            6 + package_applet_aid.len()
                + applet_aid.len()
                + instance_aid.len()
                + privileges.len()
                + install_parameters.len(),
        );
        push_lv(&mut data, package_applet_aid);
        push_lv(&mut data, applet_aid);
        push_lv(&mut data, instance_aid);
        push_lv(&mut data, privileges);
        push_lv(&mut data, install_parameters);
        push_lv(&mut data, &[]);

        OwnedT0Command {
            cla: 0x80,
            ins: rustlet_runtime::INS_INSTALL,
            p1: 0x0c,
            p2: 0x00,
            lc: data.len() as u8,
            le: 0,
            data,
        }
    }

    fn process_no_data(ins: u8) -> OwnedT0Command {
        OwnedT0Command {
            cla: 0x00,
            ins,
            p1: 0x00,
            p2: 0x00,
            lc: 0,
            le: 0,
            data: Vec::new(),
        }
    }

    fn process_with_data(ins: u8, data: &[u8]) -> OwnedT0Command {
        OwnedT0Command {
            cla: 0x00,
            ins,
            p1: 0x00,
            p2: 0x00,
            lc: data.len() as u8,
            le: 0,
            data: data.to_vec(),
        }
    }

    fn process_no_data_with_le(ins: u8, le: u8) -> OwnedT0Command {
        OwnedT0Command {
            cla: 0x00,
            ins,
            p1: 0x00,
            p2: 0x00,
            lc: 0,
            le,
            data: Vec::new(),
        }
    }

    fn process_no_data_with_p1_and_le(ins: u8, p1: u8, le: u8) -> OwnedT0Command {
        OwnedT0Command {
            cla: 0x00,
            ins,
            p1,
            p2: 0x00,
            lc: 0,
            le,
            data: Vec::new(),
        }
    }

    fn process_with_data_and_le(ins: u8, data: &[u8], le: u8) -> OwnedT0Command {
        OwnedT0Command {
            cla: 0x00,
            ins,
            p1: 0x00,
            p2: 0x00,
            lc: data.len() as u8,
            le,
            data: data.to_vec(),
        }
    }

    fn process_with_p1_data_and_le(ins: u8, p1: u8, data: &[u8], le: u8) -> OwnedT0Command {
        OwnedT0Command {
            cla: 0x00,
            ins,
            p1,
            p2: 0x00,
            lc: data.len() as u8,
            le,
            data: data.to_vec(),
        }
    }
}

fn command_header(command: &OwnedT0Command) -> [u8; 5] {
    let p3 = if command.lc != 0 {
        command.lc
    } else {
        command.le
    };
    [command.cla, command.ins, command.p1, command.p2, p3]
}

fn push_lv(buffer: &mut Vec<u8>, value: &[u8]) {
    apdu_tool::gp::push_lv(buffer, value).expect("GP LV value must fit one byte");
}

#[derive(Clone, Copy)]
enum HostCbcPadding {
    None,
    Iso9797M2,
}

fn host_aes_cbc_encrypt(
    key: &[u8],
    iv: &[u8; 16],
    input: &[u8],
    padding: HostCbcPadding,
) -> Result<Vec<u8>, Box<dyn Error>> {
    use aes::cipher::{
        block_padding::{Iso7816, NoPadding},
        BlockEncryptMut, KeyIvInit,
    };

    let extra = match padding {
        HostCbcPadding::None => 0,
        HostCbcPadding::Iso9797M2 => 16,
    };
    let mut buffer = input.to_vec();
    buffer.resize(input.len() + extra, 0);
    let out = match key.len() {
        16 => match padding {
            HostCbcPadding::None => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| "invalid AES-128-CBC host key/iv length")?
                .encrypt_padded_mut::<NoPadding>(&mut buffer, input.len())
                .map_err(|_| "AES-128-CBC host encryption failed")?,
            HostCbcPadding::Iso9797M2 => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| "invalid AES-128-CBC host key/iv length")?
                .encrypt_padded_mut::<Iso7816>(&mut buffer, input.len())
                .map_err(|_| "AES-128-CBC ISO9797-M2 host encryption failed")?,
        },
        32 => match padding {
            HostCbcPadding::None => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| "invalid AES-256-CBC host key/iv length")?
                .encrypt_padded_mut::<NoPadding>(&mut buffer, input.len())
                .map_err(|_| "AES-256-CBC host encryption failed")?,
            HostCbcPadding::Iso9797M2 => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| "invalid AES-256-CBC host key/iv length")?
                .encrypt_padded_mut::<Iso7816>(&mut buffer, input.len())
                .map_err(|_| "AES-256-CBC ISO9797-M2 host encryption failed")?,
        },
        _ => return Err("unsupported AES key length".into()),
    };
    Ok(out.to_vec())
}

fn host_aes_cbc_decrypt(
    key: &[u8],
    iv: &[u8; 16],
    input: &[u8],
    padding: HostCbcPadding,
) -> Result<Vec<u8>, Box<dyn Error>> {
    use aes::cipher::{
        block_padding::{Iso7816, NoPadding},
        BlockDecryptMut, KeyIvInit,
    };

    let mut buffer = input.to_vec();
    let out = match key.len() {
        16 => match padding {
            HostCbcPadding::None => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| "invalid AES-128-CBC host key/iv length")?
                .decrypt_padded_mut::<NoPadding>(&mut buffer)
                .map_err(|_| "AES-128-CBC host decryption failed")?,
            HostCbcPadding::Iso9797M2 => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| "invalid AES-128-CBC host key/iv length")?
                .decrypt_padded_mut::<Iso7816>(&mut buffer)
                .map_err(|_| "AES-128-CBC ISO9797-M2 host decryption failed")?,
        },
        32 => match padding {
            HostCbcPadding::None => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| "invalid AES-256-CBC host key/iv length")?
                .decrypt_padded_mut::<NoPadding>(&mut buffer)
                .map_err(|_| "AES-256-CBC host decryption failed")?,
            HostCbcPadding::Iso9797M2 => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| "invalid AES-256-CBC host key/iv length")?
                .decrypt_padded_mut::<Iso7816>(&mut buffer)
                .map_err(|_| "AES-256-CBC ISO9797-M2 host decryption failed")?,
        },
        _ => return Err("unsupported AES key length".into()),
    };
    Ok(out.to_vec())
}

fn expect_cbc_encrypted_response(
    response: T0Response,
    key: &[u8],
    expected_plaintext: &[u8],
    padding: HostCbcPadding,
    label: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if response.status != (0x90, 0x00) || response.data.len() < 16 {
        return Err(format!(
            "{}: expected IV-prefixed ciphertext and status 9000, got data {:02X?} and status {:02X?}",
            label, response.data, response.status
        )
        .into());
    }

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&response.data[..16]);
    let plaintext = host_aes_cbc_decrypt(key, &iv, &response.data[16..], padding)?;
    if plaintext != expected_plaintext {
        return Err(format!(
            "{}: expected plaintext {:02X?}, got {:02X?} after host decrypt",
            label, expected_plaintext, plaintext
        )
        .into());
    }

    Ok(response.data)
}

fn host_aes_cmac_for_command(
    key: &[u8],
    command: &OwnedT0Command,
) -> Result<Vec<u8>, Box<dyn Error>> {
    host_aes_cmac_for_header_and_payload(key, command.ins, &command.data)
}

fn host_aes_cmac_for_header_and_payload(
    key: &[u8],
    ins: u8,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut input = vec![0x00, ins, 0x00, 0x00];
    input.extend_from_slice(payload);
    host_aes_cmac(key, &input)
}

fn host_aes_cmac(key: &[u8], input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    use cmac::{Cmac, Mac};

    match key.len() {
        16 => {
            let mut mac = <Cmac<aes::Aes128> as Mac>::new_from_slice(key)
                .map_err(|_| "invalid AES-128-CMAC host key length")?;
            mac.update(input);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        32 => {
            let mut mac = <Cmac<aes::Aes256> as Mac>::new_from_slice(key)
                .map_err(|_| "invalid AES-256-CMAC host key length")?;
            mac.update(input);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err("unsupported AES-CMAC key length".into()),
    }
}

fn host_chained_truncated_aes_cmac(
    key: &[u8],
    chain: &mut [u8; 16],
    input: &[u8],
    mac_len: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if mac_len > 16 {
        return Err("unsupported SCP03 host MAC length".into());
    }
    let mut chained = Vec::with_capacity(chain.len() + input.len());
    chained.extend_from_slice(chain);
    chained.extend_from_slice(input);
    let mac = host_aes_cmac(key, &chained)?;
    chain.copy_from_slice(&mac[..16]);
    Ok(mac[..mac_len].to_vec())
}

fn scp03_encrypt_command_data(
    command: OwnedT0Command,
    session_enc_key: &[u8],
    session_mac_key: &[u8],
    command_mac_chain: &mut [u8; 16],
    command_enc_counter: &mut u32,
    mac_len: usize,
) -> Result<OwnedT0Command, Box<dyn Error>> {
    let mut command = command;
    let body = if command.data.is_empty() {
        Vec::new()
    } else {
        let iv = host_scp03_encryption_iv(session_enc_key, command_enc_counter, 0x01)?;

        host_aes_cbc_encrypt(
            session_enc_key,
            &iv,
            &command.data,
            HostCbcPadding::Iso9797M2,
        )?
    };
    command.cla = 0x84;
    command.lc = body
        .len()
        .checked_add(mac_len)
        .and_then(|len| u8::try_from(len).ok())
        .ok_or("protected SCP03 command too large")?;

    let mut authenticated = Vec::from(command_header(&command));
    authenticated.extend_from_slice(&body);
    let command_mac = host_chained_truncated_aes_cmac(
        session_mac_key,
        command_mac_chain,
        &authenticated,
        mac_len,
    )?;
    command.data = body;
    command.data.extend_from_slice(&command_mac);
    Ok(command)
}

fn host_scp03_encryption_iv(
    key: &[u8],
    counter: &mut u32,
    direction: u8,
) -> Result<[u8; 16], Box<dyn Error>> {
    *counter = counter
        .checked_add(1)
        .ok_or("SCP03 encryption counter overflow")?;
    let mut block = [0u8; 16];
    block[0] = direction;
    block[12..16].copy_from_slice(&counter.to_be_bytes());
    let iv = host_aes_ecb_encrypt(key, &block)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&iv);
    Ok(out)
}

fn host_scp11c_encryption_iv(
    key: &[u8],
    counter: &mut u32,
    direction: u8,
) -> Result<[u8; 16], Box<dyn Error>> {
    *counter = counter
        .checked_add(1)
        .ok_or("SCP11c encryption counter overflow")?;
    let mut block = [0u8; 16];
    block[0] = direction;
    block[12..16].copy_from_slice(&counter.to_be_bytes());
    let iv = host_aes_ecb_encrypt(key, &block)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&iv);
    Ok(out)
}

fn scp11c_encrypt_command_data(
    mut command: OwnedT0Command,
    keys: &HostScp11cSessionKeys,
    command_mac_chain: &mut [u8; 16],
    command_enc_counter: &mut u32,
) -> Result<OwnedT0Command, Box<dyn Error>> {
    let iv = host_scp11c_encryption_iv(&keys.s_enc, command_enc_counter, 0x11)?;
    let encrypted =
        host_aes_cbc_encrypt(&keys.s_enc, &iv, &command.data, HostCbcPadding::Iso9797M2)?;
    command.cla = 0x84;
    command.data = encrypted;
    command.lc = command
        .data
        .len()
        .checked_add(16)
        .and_then(|len| u8::try_from(len).ok())
        .ok_or("protected SCP11c command too large")?;

    let mut authenticated = Vec::from(command_header(&command));
    authenticated.extend_from_slice(&command.data);
    let command_mac =
        host_chained_truncated_aes_cmac(&keys.s_mac, command_mac_chain, &authenticated, 16)?;
    command.data.extend_from_slice(&command_mac);
    Ok(command)
}

fn scp03_context(host_challenge: &[u8], card_challenge: &[u8]) -> Vec<u8> {
    let mut context = Vec::with_capacity(host_challenge.len() + card_challenge.len());
    context.extend_from_slice(host_challenge);
    context.extend_from_slice(card_challenge);
    context
}

struct HostScp03Expectations {
    expected_initialize_update: Vec<u8>,
    host_cryptogram: Vec<u8>,
    session_enc_key: Vec<u8>,
    session_mac_key: Vec<u8>,
    session_rmac_key: Vec<u8>,
}

fn host_scp03_expectations(
    profile: HostScp03Profile,
    host_challenge: &[u8],
    card_challenge: &[u8],
    static_enc_key: &[u8],
    static_mac_key: &[u8],
    key_version: u8,
    _key_id: u8,
) -> Result<HostScp03Expectations, Box<dyn Error>> {
    let scp03_context = scp03_context(host_challenge, card_challenge);
    let session_enc_key = host_scp03_kdf(static_enc_key, SCP03_KDF_S_ENC, &scp03_context, 16)?;
    let session_mac_key = host_scp03_kdf(static_mac_key, SCP03_KDF_S_MAC, &scp03_context, 16)?;
    let session_rmac_key = host_scp03_kdf(static_mac_key, SCP03_KDF_S_RMAC, &scp03_context, 16)?;
    let card_cryptogram = host_scp03_kdf(
        &session_mac_key,
        SCP03_KDF_CARD_CRYPTOGRAM,
        &scp03_context,
        profile.cryptogram_len(),
    )?;
    let host_cryptogram = host_scp03_kdf(
        &session_mac_key,
        SCP03_KDF_HOST_CRYPTOGRAM,
        &scp03_context,
        profile.cryptogram_len(),
    )?;
    let mut expected_initialize_update =
        vec![0u8; 12 + card_challenge.len() + card_cryptogram.len()];
    expected_initialize_update[10] = key_version;
    expected_initialize_update[11] = 0x03;
    expected_initialize_update[12..12 + card_challenge.len()].copy_from_slice(card_challenge);
    expected_initialize_update[12 + card_challenge.len()..].copy_from_slice(&card_cryptogram);
    Ok(HostScp03Expectations {
        expected_initialize_update,
        host_cryptogram,
        session_enc_key,
        session_mac_key,
        session_rmac_key,
    })
}

fn exchange_scp03_initialize_update(
    client: &mut ApduClient,
    profile: HostScp03Profile,
    host_challenge: &[u8],
    static_enc_key: &[u8],
    static_mac_key: &[u8],
    key_version: u8,
    key_id: u8,
    label: &str,
) -> Result<HostScp03Expectations, Box<dyn Error>> {
    let response = client.exchange(&CommandBuilder::initialize_update_with_keyset(
        key_version,
        key_id,
        host_challenge,
    ))?;
    if response.status != (0x90, 0x00) {
        return Err(format!(
            "{label} INITIALIZE UPDATE: expected 9000, got {:02X}{:02X}",
            response.status.0, response.status.1
        )
        .into());
    }
    let expected_len = 12 + profile.challenge().len() + profile.cryptogram_len();
    if response.data.len() != expected_len
        || response.data[10] != key_version
        || response.data[11] != 0x03
    {
        return Err(format!("{label} INITIALIZE UPDATE: malformed SCP03 response").into());
    }
    let challenge_end = 12 + profile.challenge().len();
    let expected = host_scp03_expectations(
        profile,
        host_challenge,
        &response.data[12..challenge_end],
        static_enc_key,
        static_mac_key,
        key_version,
        key_id,
    )?;
    if response.data != expected.expected_initialize_update {
        return Err(format!("{label} INITIALIZE UPDATE: card cryptogram mismatch").into());
    }
    Ok(expected)
}

fn host_scp03_kdf(
    key: &[u8],
    derivation_constant: u8,
    context: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if !matches!(out_len, 8 | 16 | 24 | 32) {
        return Err(format!("unsupported SCP03 KDF output length: {out_len}").into());
    }

    let output_len_bits = ((out_len as u16) * 8).to_be_bytes();
    let mut generated = Vec::with_capacity(out_len);
    let mut counter = 1u8;
    while generated.len() < out_len {
        let mut input = vec![0u8; 11];
        input.push(derivation_constant);
        input.push(0x00);
        input.extend_from_slice(&output_len_bits);
        input.push(counter);
        input.extend_from_slice(context);
        let block = host_aes_cmac(key, &input)?;
        let take_len = usize::min(block.len(), out_len - generated.len());
        generated.extend_from_slice(&block[..take_len]);
        counter = counter.checked_add(1).ok_or("SCP03 KDF counter overflow")?;
    }
    Ok(generated)
}

fn host_aes_ecb_encrypt(key: &[u8], input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    use aes::cipher::{BlockEncrypt, KeyInit};

    let mut buffer = input.to_vec();
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(key)
                .map_err(|_| "invalid AES-128-ECB host key length")?;
            for block in buffer.chunks_exact_mut(16) {
                cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
                    block,
                ));
            }
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(key)
                .map_err(|_| "invalid AES-256-ECB host key length")?;
            for block in buffer.chunks_exact_mut(16) {
                cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
                    block,
                ));
            }
        }
        _ => return Err("unsupported AES key length".into()),
    }
    Ok(buffer)
}

struct HostEcdhResponse<'a> {
    public_key: &'a [u8],
    payload: &'a [u8],
}

struct HostScp11cMutualAuthenticateResponse<'a> {
    public_key: &'a [u8],
    receipt: &'a [u8],
}

struct HostProtectedResponseDo {
    encrypted_data: Vec<u8>,
    status: (u8, u8),
    mac: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostScp11cSessionKeys {
    s_enc: [u8; 16],
    s_mac: [u8; 16],
    s_rmac: [u8; 16],
    dek: [u8; 16],
    receipt_key: [u8; 16],
}

impl HostScp11cSessionKeys {
    fn from_bytes(payload: &[u8], label: &str) -> Result<Self, Box<dyn Error>> {
        if payload.len() != 80 {
            return Err(format!(
                "{label}: expected 80 bytes of SCP11c session material, got {}",
                payload.len()
            )
            .into());
        }

        let mut s_enc = [0u8; 16];
        let mut s_mac = [0u8; 16];
        let mut s_rmac = [0u8; 16];
        let mut dek = [0u8; 16];
        let mut receipt_key = [0u8; 16];
        receipt_key.copy_from_slice(&payload[..16]);
        s_enc.copy_from_slice(&payload[16..32]);
        s_mac.copy_from_slice(&payload[32..48]);
        s_rmac.copy_from_slice(&payload[48..64]);
        dek.copy_from_slice(&payload[64..80]);
        Ok(Self {
            s_enc,
            s_mac,
            s_rmac,
            dek,
            receipt_key,
        })
    }

    fn all_distinct(&self) -> bool {
        self.s_enc != self.s_mac
            && self.s_enc != self.s_rmac
            && self.s_enc != self.dek
            && self.s_enc != self.receipt_key
            && self.s_mac != self.s_rmac
            && self.s_mac != self.dek
            && self.s_mac != self.receipt_key
            && self.s_rmac != self.dek
            && self.s_rmac != self.receipt_key
            && self.dek != self.receipt_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostEcdhDerivedTriplet {
    first: [u8; 16],
    second: [u8; 16],
    third: [u8; 16],
}

impl HostEcdhDerivedTriplet {
    fn from_bytes(payload: &[u8], label: &str) -> Result<Self, Box<dyn Error>> {
        if payload.len() != 48 {
            return Err(format!(
                "{label}: expected 48 bytes of ECDH/HKDF material, got {}",
                payload.len()
            )
            .into());
        }
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        let mut third = [0u8; 16];
        first.copy_from_slice(&payload[..16]);
        second.copy_from_slice(&payload[16..32]);
        third.copy_from_slice(&payload[32..48]);
        Ok(Self {
            first,
            second,
            third,
        })
    }

    fn all_distinct(&self) -> bool {
        self.first != self.second && self.first != self.third && self.second != self.third
    }
}

struct ApduClient {
    protocol: apdu_tool::T0Client,
    observer: Option<std::rc::Rc<std::cell::RefCell<StackObserver>>>,
}

impl ApduClient {
    fn connect_with_timeout(
        socket_path: &Path,
        byte_timeout: Duration,
    ) -> Result<Self, Box<dyn Error>> {
        let stream = UnixStream::connect(socket_path)?;
        stream.set_nonblocking(true)?;
        Ok(Self {
            protocol: apdu_tool::T0Client::new(
                Box::new(stream),
                Self::protocol_config(byte_timeout),
            ),
            observer: None,
        })
    }

    fn connect_link(
        link: &apdu_tool::LinkSpec,
        byte_timeout: Duration,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            protocol: apdu_tool::T0Client::connect(link, Self::protocol_config(byte_timeout))?,
            observer: None,
        })
    }

    fn set_observer(&mut self, observer: Option<std::rc::Rc<std::cell::RefCell<StackObserver>>>) {
        self.observer = observer;
    }

    fn protocol_config(silence_timeout: Duration) -> apdu_tool::T0ClientConfig {
        apdu_tool::T0ClientConfig {
            silence_timeout,
            frame_idle_timeout: APDU_FRAME_TIMEOUT,
            byte_pacing: APDU_BYTE_PACING,
        }
    }

    /// Only called while the target is halted, before the reset which emits ATR.
    fn discard_stale_input(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(self.protocol.discard_stale_input()?)
    }

    fn exchange(&mut self, command: &OwnedT0Command) -> Result<T0Response, Box<dyn Error>> {
        let result = self
            .exchange_without_stack_probe(command)
            .map_err(|error| {
                format!(
                    "APDU {:02X} {:02X} {:02X} {:02X} Lc={} Le={}: {error}",
                    command.cla, command.ins, command.p1, command.p2, command.lc, command.le
                )
            })?;
        if let Some(observer) = self.observer.clone() {
            let kernel = self.read_kernel_stack_high_watermark().ok();
            let rustlet = self.read_rustlet_stack_high_watermark().ok();
            observer.borrow_mut().observe(command, kernel, rustlet);
        }
        Ok(result)
    }

    fn exchange_without_stack_probe(
        &mut self,
        command: &OwnedT0Command,
    ) -> Result<T0Response, Box<dyn Error>> {
        self.exchange_with_response_chunk_limit(command, 255)
    }

    fn exchange_with_response_chunk_limit(
        &mut self,
        command: &OwnedT0Command,
        response_chunk_limit: usize,
    ) -> Result<T0Response, Box<dyn Error>> {
        let response = self
            .protocol
            .exchange_with_response_chunk_limit(command.as_borrowed(), response_chunk_limit)?;
        Ok(response)
    }

    fn read_kernel_stack_high_watermark(&mut self) -> Result<usize, Box<dyn Error>> {
        let response =
            self.exchange_without_stack_probe(&CommandBuilder::gp_get_data(0xDF71, 4))?;
        if response.status != (0x90, 0x00) || response.data.len() != 4 {
            return Err("kernel stack monitor GET DATA failed".into());
        }
        Ok(u32::from_be_bytes([
            response.data[0],
            response.data[1],
            response.data[2],
            response.data[3],
        ]) as usize)
    }

    fn read_rustlet_stack_high_watermark(&mut self) -> Result<usize, Box<dyn Error>> {
        let response =
            self.exchange_without_stack_probe(&CommandBuilder::gp_get_data(0xDF72, 4))?;
        if response.status != (0x90, 0x00) || response.data.len() != 4 {
            return Err("Rustlet stack monitor GET DATA failed".into());
        }
        Ok(u32::from_be_bytes([
            response.data[0],
            response.data[1],
            response.data[2],
            response.data[3],
        ]) as usize)
    }

    fn read_frame(&mut self, first_byte_timeout: Duration) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.protocol.read_frame(first_byte_timeout)?)
    }
}

fn read_expected_atr(
    ctx: &BuildContext,
    client: &mut ApduClient,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let expected_yy = expected_atr_capability_byte(ctx)?;
    read_expected_atr_with_capability(client, label, expected_yy)
}

fn read_expected_atr_with_capability(
    client: &mut ApduClient,
    label: &str,
    expected_yy: u8,
) -> Result<(), Box<dyn Error>> {
    eprintln!("{label}: read ATR");
    let started = Instant::now();
    let atr = client.read_frame(TARGET_INITIALIZATION_TIMEOUT)?;
    let expected_atr = [
        ATR_PREFIX[0],
        ATR_PREFIX[1],
        ATR_PREFIX[2],
        ATR_PREFIX[3],
        ATR_OXIDE_SE_COMPACT_TLV_HEADER,
        ATR_OXIDE_SE_MARKER[0],
        ATR_OXIDE_SE_MARKER[1],
        ATR_OXIDE_SE_MARKER[2],
        ATR_OXIDE_SE_MARKER[3],
        ATR_OXIDE_SE_VERSION,
        expected_yy,
        ATR_CARD_CAPABILITIES_COMPACT_TLV[0],
        ATR_CARD_CAPABILITIES_COMPACT_TLV[1],
        ATR_CARD_CAPABILITIES_COMPACT_TLV[2],
        ATR_CARD_CAPABILITIES_COMPACT_TLV[3],
    ];
    if atr != expected_atr {
        return Err(format!(
            "{label}: unexpected ATR: got {:02X?}, expected {:02X?}",
            atr, expected_atr
        )
        .into());
    }
    eprintln!(
        "{label}: ATR validated after {:.3}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn expected_atr_capability_byte(ctx: &BuildContext) -> Result<u8, Box<dyn Error>> {
    let repo_root = repo_root()?;
    let config_path = ctx.manifest_path(&repo_root);
    let source = fs::read_to_string(&config_path).map_err(|err| {
        format!(
            "failed to read build config {} for ATR check: {err}",
            config_path.display()
        )
    })?;
    let manifest: PredeploymentManifestConfig = toml::from_str(&source).map_err(|err| {
        format!(
            "failed to parse build config {} for ATR check: {err}",
            config_path.display()
        )
    })?;
    let kernel_image = resolve_kernel_image_manifest(&manifest)?;
    if kernel_image.mode == KERNEL_IMAGE_MODE_KERNEL_ONLY {
        return Ok(0);
    }
    let secure_channel = resolve_secure_channel_manifest(&manifest.secure_channel)?;
    let root = manifest
        .root
        .as_ref()
        .ok_or("global-platform images require a [root] configuration")?;

    let mut yy = 0u8;
    if root_security_domain_kind(&root.package) != "NullSecurityDomain" {
        yy |= 0x80;
    }
    if let Some(profiles) = secure_channel.scp11_profiles.as_deref() {
        for profile in profiles.split(',') {
            yy |= match profile {
                "A" => 0x40,
                "B" => 0x20,
                "C" => 0x10,
                "" => 0x00,
                other => return Err(format!("unsupported resolved SCP11 profile {other}").into()),
            };
        }
    }
    if secure_channel.mode == "Scp03Only" || secure_channel.mode == "Scp03AndScp11" {
        yy |= match secure_channel.scp03_profile {
            Some("S8") => 0b10,
            Some("S16") => 0b11,
            Some(other) => return Err(format!("unsupported resolved SCP03 profile {other}").into()),
            None => 0b00,
        };
    }

    Ok(yy)
}

fn expect_status(
    response: T0Response,
    expected_status: (u8, u8),
    label: &str,
) -> Result<(), Box<dyn Error>> {
    expect_response(response, &[], expected_status, label)
}

fn expect_response(
    response: T0Response,
    expected_data: &[u8],
    expected_status: (u8, u8),
    label: &str,
) -> Result<(), Box<dyn Error>> {
    if response.data != expected_data || response.status != expected_status {
        return Err(format!(
            "{}: expected data {:02X?} and status {:02X?}, got data {:02X?} and status {:02X?}",
            label, expected_data, expected_status, response.data, response.status
        )
        .into());
    }

    Ok(())
}

fn expect_host_ecdh_response<'a>(
    response: &'a T0Response,
    expected_len: usize,
    label: &str,
) -> Result<HostEcdhResponse<'a>, Box<dyn Error>> {
    if response.status != (0x90, 0x00) {
        return Err(format!(
            "{label}: expected status (90, 00), got ({:02X}, {:02X})",
            response.status.0, response.status.1
        )
        .into());
    }
    if response.data.len() != expected_len {
        return Err(format!(
            "{label}: expected {expected_len} response bytes, got {}",
            response.data.len()
        )
        .into());
    }
    Ok(HostEcdhResponse {
        public_key: &response.data[..65],
        payload: &response.data[65..],
    })
}

fn expect_scp11c_mutual_authenticate_response<'a>(
    response: &'a T0Response,
    label: &str,
) -> Result<HostScp11cMutualAuthenticateResponse<'a>, Box<dyn Error>> {
    if response.status != (0x90, 0x00) {
        return Err(format!(
            "{label}: expected status (90, 00), got ({:02X}, {:02X})",
            response.status.0, response.status.1
        )
        .into());
    }
    if response.data.len() != 86 {
        return Err(format!(
            "{label}: expected 86 TLV response bytes, got {}",
            response.data.len()
        )
        .into());
    }
    if response.data[0] != 0x5F || response.data[1] != 0x49 || response.data[2] != 65 {
        return Err(format!("{label}: missing 5F49 card ephemeral public key").into());
    }
    if response.data[68] != 0x86 || response.data[69] != 16 {
        return Err(format!("{label}: missing 86 receipt").into());
    }
    Ok(HostScp11cMutualAuthenticateResponse {
        public_key: &response.data[3..68],
        receipt: &response.data[70..86],
    })
}

fn parse_protected_response(
    response: T0Response,
    label: &str,
) -> Result<HostProtectedResponseDo, Box<dyn Error>> {
    let mac_offset = response
        .data
        .len()
        .checked_sub(16)
        .ok_or_else(|| format!("{label}: protected response is missing its 16-byte R-MAC"))?;
    Ok(HostProtectedResponseDo {
        encrypted_data: response.data[..mac_offset].to_vec(),
        status: response.status,
        mac: response.data[mac_offset..].to_vec(),
    })
}

fn expect_protected_status(
    response: T0Response,
    expected_status: (u8, u8),
    expected_mac: &[u8],
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let parsed = parse_protected_response(response, label)?;
    if !parsed.encrypted_data.is_empty()
        || parsed.status != expected_status
        || parsed.mac != expected_mac
    {
        return Err(format!(
            "{label}: expected empty protected data, status {:02X?}, mac {:02X?}; got data {:02X?}, status {:02X?}, mac {:02X?}",
            expected_status, expected_mac, parsed.encrypted_data, parsed.status, parsed.mac
        )
        .into());
    }
    Ok(())
}

fn host_p256_shared_secret(
    host_secret: &SecretKey,
    peer_public_bytes: &[u8],
    label: &str,
) -> Result<[u8; 32], Box<dyn Error>> {
    let peer_public = PublicKey::from_sec1_bytes(peer_public_bytes)
        .map_err(|_| format!("{label}: invalid peer public key encoding"))?;
    let shared = diffie_hellman(host_secret.to_nonzero_scalar(), peer_public.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    Ok(out)
}

fn host_hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out: &mut [u8],
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    hkdf.expand(info, out)
        .map_err(|_| format!("{label}: host expand failed").into())
}

fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 2 + value.len());
    apdu_tool::gp::push_tlv(&mut out, tag, value).expect("host BER-TLV value must fit");
    out
}

fn build_dev_oce_certificate(host_public: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if host_public.len() != 65 {
        return Err("scp11c certificate: expected uncompressed P-256 public key".into());
    }
    let signing_key = SigningKey::from_slice(&SCP11C_DEV_CA_PRIVATE_KEY)
        .map_err(|_| "scp11c certificate: invalid dev CA private key")?;

    let mut body = Vec::new();
    body.extend_from_slice(&tlv(&[0x93], &[0x01]));
    body.extend_from_slice(&tlv(&[0x42], b"RLOS"));
    body.extend_from_slice(&tlv(&[0x5F, 0x20], b"oce-debug"));
    body.extend_from_slice(&tlv(&[0x95], &[0x00, 0x80]));
    body.extend_from_slice(&tlv(&[0x5F, 0x25], &[0x20, 0x24, 0x01, 0x01]));
    body.extend_from_slice(&tlv(&[0x5F, 0x24], &[0x20, 0x34, 0x01, 0x01]));
    body.extend_from_slice(&tlv(&[0xBF, 0x20], b"oxide-se-oce"));

    let mut key_template = Vec::new();
    key_template.extend_from_slice(&tlv(&[0xB0], host_public));
    key_template.extend_from_slice(&tlv(&[0xF0], &[0x00]));
    body.extend_from_slice(&tlv(&[0x7F, 0x49], &key_template));

    let signature: Signature = signing_key.sign(&body);
    body.extend_from_slice(&tlv(&[0x5F, 0x37], &signature.to_bytes()));
    Ok(tlv(&[0x7F, 0x21], &body))
}

fn derive_host_scp11c_session_keys(
    host_static_secret: &SecretKey,
    host_ephemeral_secret: &SecretKey,
    card_static_public: &[u8],
    label: &str,
) -> Result<HostScp11cSessionKeys, Box<dyn Error>> {
    let ephemeral_shared =
        host_p256_shared_secret(host_ephemeral_secret, card_static_public, label)?;
    let static_shared = host_p256_shared_secret(host_static_secret, card_static_public, label)?;
    // Invariant: GP SCP11c feeds ShSes || ShSss to the X9.63 KDF.
    let mut shared = Vec::with_capacity(64);
    shared.extend_from_slice(&ephemeral_shared);
    shared.extend_from_slice(&static_shared);
    let mut info = Vec::with_capacity(3 + 1 + OXIDE_SE_SCP11C_HOST_ID.len() + 1);
    info.extend_from_slice(&[
        SCP11C_KEY_USAGE_FULL,
        SCP11C_KEY_TYPE_AES,
        SCP11C_KEY_LENGTH_AES_128,
    ]);
    info.push(OXIDE_SE_SCP11C_HOST_ID.len() as u8);
    info.extend_from_slice(OXIDE_SE_SCP11C_HOST_ID);
    info.push(OXIDE_SE_SCP11_CARD_GROUP_ID.len() as u8);
    info.extend_from_slice(OXIDE_SE_SCP11_CARD_GROUP_ID);
    let mut derived = [0u8; 80];
    host_x963_sha256_kdf(&shared, &info, &mut derived, label)?;
    HostScp11cSessionKeys::from_bytes(&derived, label)
}

fn derive_host_scp11a_session_keys(
    host_static_secret: &SecretKey,
    host_ephemeral_secret: &SecretKey,
    card_ephemeral_public: &[u8],
    label: &str,
) -> Result<HostScp11cSessionKeys, Box<dyn Error>> {
    let card_static_secret = SecretKey::from_slice(&SCP11_DEV_CARD_STATIC_PRIVATE_KEY)
        .map_err(|_| "scp11a: invalid card static private key")?;
    let card_static_public = card_static_secret.public_key().to_encoded_point(false);
    let ephemeral_shared =
        host_p256_shared_secret(host_ephemeral_secret, card_ephemeral_public, label)?;
    let static_shared =
        host_p256_shared_secret(host_static_secret, card_static_public.as_bytes(), label)?;
    let mut secret = Vec::with_capacity(64);
    secret.extend_from_slice(&ephemeral_shared);
    secret.extend_from_slice(&static_shared);

    let mut info = Vec::with_capacity(3 + 1 + OXIDE_SE_SCP11C_HOST_ID.len() + 1 + 1);
    info.extend_from_slice(&[
        SCP11C_KEY_USAGE_FULL,
        SCP11C_KEY_TYPE_AES,
        SCP11C_KEY_LENGTH_AES_128,
    ]);
    info.push(OXIDE_SE_SCP11C_HOST_ID.len() as u8);
    info.extend_from_slice(OXIDE_SE_SCP11C_HOST_ID);
    info.push(OXIDE_SE_SCP11_SIN.len() as u8);
    info.extend_from_slice(OXIDE_SE_SCP11_SIN);
    info.push(OXIDE_SE_SCP11_SDIN.len() as u8);
    info.extend_from_slice(OXIDE_SE_SCP11_SDIN);

    let mut derived = [0u8; 80];
    host_x963_sha256_kdf(&secret, &info, &mut derived, label)?;
    HostScp11cSessionKeys::from_bytes(&derived, label)
}

fn derive_host_scp11b_session_keys(
    host_ephemeral_secret: &SecretKey,
    card_ephemeral_public: &[u8],
    label: &str,
) -> Result<HostScp11cSessionKeys, Box<dyn Error>> {
    let card_static_secret = SecretKey::from_slice(&SCP11_DEV_CARD_STATIC_PRIVATE_KEY)
        .map_err(|_| "scp11b: invalid card static private key")?;
    let card_static_public = card_static_secret.public_key().to_encoded_point(false);
    let ephemeral_shared =
        host_p256_shared_secret(host_ephemeral_secret, card_ephemeral_public, label)?;
    let static_shared =
        host_p256_shared_secret(host_ephemeral_secret, card_static_public.as_bytes(), label)?;
    let mut secret = Vec::with_capacity(64);
    secret.extend_from_slice(&ephemeral_shared);
    secret.extend_from_slice(&static_shared);

    let mut info = Vec::with_capacity(3 + 1 + OXIDE_SE_SCP11C_HOST_ID.len() + 1 + 1);
    info.extend_from_slice(&[
        SCP11C_KEY_USAGE_FULL,
        SCP11C_KEY_TYPE_AES,
        SCP11C_KEY_LENGTH_AES_128,
    ]);
    info.push(OXIDE_SE_SCP11C_HOST_ID.len() as u8);
    info.extend_from_slice(OXIDE_SE_SCP11C_HOST_ID);
    info.push(OXIDE_SE_SCP11_SIN.len() as u8);
    info.extend_from_slice(OXIDE_SE_SCP11_SIN);
    info.push(OXIDE_SE_SCP11_SDIN.len() as u8);
    info.extend_from_slice(OXIDE_SE_SCP11_SDIN);

    let mut derived = [0u8; 80];
    host_x963_sha256_kdf(&secret, &info, &mut derived, label)?;
    HostScp11cSessionKeys::from_bytes(&derived, label)
}

fn derive_host_ecdh_hkdf_triplet(
    host_secret: &SecretKey,
    host_public: &[u8],
    card_public: &[u8],
    label: &str,
) -> Result<HostEcdhDerivedTriplet, Box<dyn Error>> {
    let shared = host_p256_shared_secret(host_secret, card_public, label)?;
    let mut info = Vec::with_capacity(b"oxide-se-scp11c-session".len() + 130);
    info.extend_from_slice(b"oxide-se-scp11c-session");
    info.extend_from_slice(host_public);
    info.extend_from_slice(card_public);
    let mut derived = [0u8; 48];
    host_hkdf_sha256(
        &shared,
        b"oxide-se-scp11c-session-salt",
        &info,
        &mut derived,
        label,
    )?;
    HostEcdhDerivedTriplet::from_bytes(&derived, label)
}

fn append_scp11c_crt_identifier(crt: &mut Vec<u8>) {
    crt.extend_from_slice(&tlv(
        &[0x90],
        &[SCP11_IDENTIFIER_FAMILY, SCP11C_IDENTIFIER_PARAM],
    ));
}

fn host_scp11c_mutual_authenticate_receipt(
    keys: &HostScp11cSessionKeys,
    command_data: &[u8],
    card_public: &[u8],
    _label: &str,
) -> Result<[u8; 16], Box<dyn Error>> {
    let mut message = Vec::with_capacity(command_data.len() + 68);
    message.extend_from_slice(command_data);
    message.extend_from_slice(&tlv(&[0x5F, 0x49], card_public));
    let mac = host_aes_cmac(&keys.receipt_key, &message)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac[..16]);
    Ok(out)
}

fn host_x963_sha256_kdf(
    shared_secret: &[u8],
    shared_info: &[u8],
    out: &mut [u8],
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let mut counter = 1u32;
    let mut offset = 0usize;
    while offset < out.len() {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(counter.to_be_bytes());
        hasher.update(shared_info);
        let block = hasher.finalize();
        let take_len = usize::min(block.len(), out.len() - offset);
        out[offset..offset + take_len].copy_from_slice(&block[..take_len]);
        offset += take_len;
        counter = counter
            .checked_add(1)
            .ok_or_else(|| format!("{label}: X9.63 counter overflow"))?;
    }
    Ok(())
}

fn parse_ecdh_derived_triplet(
    payload: &[u8],
    label: &str,
) -> Result<HostEcdhDerivedTriplet, Box<dyn Error>> {
    HostEcdhDerivedTriplet::from_bytes(payload, label)
}

#[cfg(test)]
mod tests {
    use super::{
        board_catalog, board_spec, gp_sm, is_rustlet_qemu_board, protected_load_chunk_len,
        render_stack_baselines, repo_root, resolve_kernel_image_manifest,
        stack_baseline_update_has_source_changes, stack_high_watermark_checkpoints,
        validate_board_linker_layouts, validate_generic_linker_layout_contract,
        validate_kernel_stack_high_watermark, validate_security_domain_keys,
        validate_stack_campaign, validation_environment_label, BoardSupportLevel,
        LayoutImageFormat, OwnedT0Command, PredeploymentKeyConfig, PredeploymentManifestConfig,
        StackBaselineCampaign, StackBaselineCheckpoint, StackBaselineFile, StackBaselineKey,
        StackObservation, StackObserver, KERNEL_STACK_HIGH_WATERMARK_BUDGET_BYTES,
        LEGACY_STACK_MONITOR_PROFILE, STACK_HIGH_WATERMARK_UNKNOWN, STACK_MONITOR_PROFILE,
    };
    use apdu_tool::validate_t0_instruction;
    use std::collections::BTreeSet;

    #[test]
    fn board_linker_scripts_match_target_memory_layouts() {
        let root = repo_root().expect("locate workspace root");
        for entry in board_catalog() {
            let board_name = entry.spec.env_name;
            let board = board_spec(board_name).expect("known board");
            validate_board_linker_layouts(&root, board)
                .unwrap_or_else(|error| panic!("{board_name}: {error}"));
        }
        validate_generic_linker_layout_contract(&root)
            .expect("generic native and bootable linker layout contract");
    }

    #[test]
    fn kernel_only_manifest_accepts_multiple_known_modules_without_predeployment() {
        let manifest: PredeploymentManifestConfig = toml::from_str(
            r#"
                [kernel-image]
                mode = "kernel-only"
                kernel-app-modules = ["ping", "t0-test", "kernel-stack-monitor"]
            "#,
        )
        .expect("parse kernel-only manifest");

        let resolved =
            resolve_kernel_image_manifest(&manifest).expect("resolve kernel-only manifest");
        assert_eq!(resolved.mode, "kernel-only");
        assert_eq!(
            resolved.modules,
            vec!["ping", "t0-test", "kernel-stack-monitor"]
        );
    }

    #[test]
    fn kernel_only_manifest_rejects_global_platform_predeployment() {
        let manifest: PredeploymentManifestConfig = toml::from_str(
            r#"
                [kernel-image]
                mode = "kernel-only"
                kernel-app-modules = ["ping"]

                [root.package]
                name = "NullSecurityDomain"
                aid = "A0:00:00:47:50:4F:53:01"

                [root.instance]
                aid = "A0:00:00:47:50:4F:53:01"
                install_bytes = "FF:FF:FF"
            "#,
        )
        .expect("parse mixed manifest");

        assert!(resolve_kernel_image_manifest(&manifest).is_err());
    }

    #[test]
    fn validation_environment_flags_cover_none_qemu_hardware_and_both() {
        assert_eq!(validation_environment_label(false, false), "none");
        assert_eq!(validation_environment_label(true, false), "qemu");
        assert_eq!(validation_environment_label(false, true), "hardware");
        assert_eq!(validation_environment_label(true, true), "qemu+hardware");
    }

    #[test]
    fn stack_regression_guard_accepts_the_global_budget_floor() {
        assert!(validate_kernel_stack_high_watermark(
            KERNEL_STACK_HIGH_WATERMARK_BUDGET_BYTES,
            8192
        )
        .is_ok());
    }

    #[test]
    fn stack_regression_guard_rejects_above_the_global_budget() {
        assert!(validate_kernel_stack_high_watermark(
            KERNEL_STACK_HIGH_WATERMARK_BUDGET_BYTES + 1,
            8192
        )
        .is_err());
    }

    #[test]
    fn stack_regression_guard_accepts_the_physical_stack_limit() {
        assert!(validate_kernel_stack_high_watermark(4096, 4096).is_ok());
    }

    #[test]
    fn stack_regression_guard_rejects_above_the_physical_stack_limit() {
        assert!(validate_kernel_stack_high_watermark(4097, 4096).is_err());
    }

    #[test]
    fn stack_regression_guard_requires_a_measurement() {
        assert!(validate_kernel_stack_high_watermark(STACK_HIGH_WATERMARK_UNKNOWN, 8192).is_err());
    }

    #[test]
    fn t0_instruction_validation_rejects_status_byte_classes() {
        for ins in 0x60..=0x6f {
            assert!(validate_t0_instruction(ins).is_err());
        }
        for ins in 0x90..=0x9f {
            assert!(validate_t0_instruction(ins).is_err());
        }
        assert!(validate_t0_instruction(0x52).is_ok());
        assert!(validate_t0_instruction(0xca).is_ok());
    }

    #[test]
    fn rustlet_qemu_matrix_requires_maturity_and_qemu_support() {
        assert!(is_rustlet_qemu_board("mps2-an385"));
        assert!(is_rustlet_qemu_board("olimex-stm32-h405"));
        assert!(!is_rustlet_qemu_board("raspi-pico2"));
        assert!(!is_rustlet_qemu_board("b-l475e-iot01a"));
        let build_only = board_catalog()
            .iter()
            .find(|entry| entry.spec.env_name == "b-l475e-iot01a")
            .expect("b-l475e-iot01a is catalogued");
        assert_eq!(build_only.support_level, BoardSupportLevel::BuildOnly);
        assert!(!build_only.qemu_support);
        assert!(!build_only.board_support);

        let pico2 = board_catalog()
            .iter()
            .find(|entry| entry.spec.env_name == "raspi-pico2")
            .expect("raspi-pico2 is catalogued");
        assert_eq!(pico2.support_level, BoardSupportLevel::KernelApdu);
        assert!(!pico2.qemu_support);
        assert!(pico2.board_support);
    }

    #[test]
    fn protected_load_chunk_budget_tracks_amendment_d_encryption_and_mac_overhead() {
        assert_eq!(gp_sm::scp03_s8_short_apdu_payload_budget(), 239);
        assert_eq!(protected_load_chunk_len(8).unwrap(), 239);
        assert_eq!(gp_sm::encrypted_command_data_field_len(239, 8), Some(248));
        assert_eq!(gp_sm::encrypted_command_data_field_len(240, 8), None);

        assert_eq!(gp_sm::scp03_s16_short_apdu_payload_budget(), 223);
        assert_eq!(gp_sm::scp11_short_apdu_payload_budget(), 223);
        assert_eq!(protected_load_chunk_len(16).unwrap(), 223);
        assert_eq!(gp_sm::encrypted_command_data_field_len(223, 16), Some(240));
        assert_eq!(gp_sm::encrypted_command_data_field_len(224, 16), None);
    }

    #[test]
    fn stack_baseline_keeps_only_increasing_high_watermarks() {
        let observations = [
            StackObservation {
                label: "first".to_owned(),
                high_watermark: 2000,
            },
            StackObservation {
                label: "plateau".to_owned(),
                high_watermark: 2000,
            },
            StackObservation {
                label: "second".to_owned(),
                high_watermark: 4000,
            },
        ];
        assert_eq!(
            stack_high_watermark_checkpoints(&observations),
            vec![
                StackBaselineCheckpoint {
                    label: "first".to_owned(),
                    high_watermark: 2000,
                },
                StackBaselineCheckpoint {
                    label: "second".to_owned(),
                    high_watermark: 4000,
                },
            ]
        );
    }

    #[test]
    fn stack_observer_uses_apdu_identity_and_occurrence_without_global_state() {
        let key = StackBaselineKey::new("rustlet", "mps2-an385", LayoutImageFormat::Elf, None);
        let mut observer = StackObserver::new("qemu", key, true, false);
        let command = OwnedT0Command::from_wire_fields(0x80, 0xCA, 0xDF, 0x71, 0, 4, vec![])
            .expect("valid GET DATA command");

        observer.observe(&command, Some(512), Some(128));
        observer.observe(&command, Some(480), Some(96));

        assert_eq!(observer.kernel_high_watermark, 512);
        assert_eq!(observer.rustlet_high_watermark, 128);
        assert_eq!(observer.observations[0].label, "APDU 80 CA DF 71 #1");
        assert_eq!(observer.observations[1].label, "APDU 80 CA DF 71 #2");
    }

    #[test]
    fn stack_baseline_rejects_a_local_regression_above_the_global_floor() {
        let key = StackBaselineKey::new("rustlet_all", "mps2-an385", LayoutImageFormat::Elf, None);
        let campaign = StackBaselineCampaign {
            command: key.command.clone(),
            board: key.board.clone(),
            image: key.image.clone(),
            execution_environment: key.execution_environment.clone(),
            scenario: String::new(),
            monitor_profile: key.monitor_profile.clone(),
            measured_commit: "abc123".to_owned(),
            checkpoints: vec![
                StackBaselineCheckpoint {
                    label: "crypto".to_owned(),
                    high_watermark: 6200,
                },
                StackBaselineCheckpoint {
                    label: "later".to_owned(),
                    high_watermark: 7200,
                },
            ],
        };
        let observations = [
            StackObservation {
                label: "crypto".to_owned(),
                high_watermark: 6300,
            },
            StackObservation {
                label: "later".to_owned(),
                high_watermark: 7200,
            },
        ];
        assert!(validate_stack_campaign(&campaign, &key, &observations).is_err());
    }

    #[test]
    fn stack_baseline_identity_separates_qemu_and_hardware() {
        let qemu =
            StackBaselineKey::new("kernel_ping", "raspi-pico2", LayoutImageFormat::Elf, None);
        let hardware = qemu.clone().with_execution_environment("hardware");
        let campaign = StackBaselineCampaign {
            command: qemu.command.clone(),
            board: qemu.board.clone(),
            image: qemu.image.clone(),
            execution_environment: qemu.execution_environment.clone(),
            scenario: qemu.scenario.clone(),
            monitor_profile: qemu.monitor_profile.clone(),
            measured_commit: "abc123".to_owned(),
            checkpoints: Vec::new(),
        };

        assert!(qemu.matches(&campaign));
        assert!(!hardware.matches(&campaign));
    }

    #[test]
    fn stack_baseline_toml_roundtrip_preserves_commit_and_checkpoints() {
        let baseline = StackBaselineFile {
            version: 2,
            campaigns: vec![StackBaselineCampaign {
                command: "rustlet".to_owned(),
                board: "mps2-an385".to_owned(),
                image: "elf".to_owned(),
                execution_environment: "qemu".to_owned(),
                scenario: "state_test".to_owned(),
                monitor_profile: STACK_MONITOR_PROFILE.to_owned(),
                measured_commit: "d76cc05".to_owned(),
                checkpoints: vec![StackBaselineCheckpoint {
                    label: "state A counter 1".to_owned(),
                    high_watermark: 4096,
                }],
            }],
        };
        let rendered = render_stack_baselines(&baseline);
        let decoded: StackBaselineFile =
            toml::from_str(&rendered).expect("parse rendered baseline");
        assert_eq!(decoded, baseline);
    }

    #[test]
    fn historical_stack_baselines_keep_the_kernel_only_monitor_profile() {
        let decoded: StackBaselineFile = toml::from_str(
            r#"
                version = 2

                [[campaigns]]
                command = "gp_scp03"
                board = "mps2-an385"
                image = "elf"
                measured_commit = "abc123"
                checkpoints = []
            "#,
        )
        .expect("parse historical baseline");

        assert_eq!(
            decoded.campaigns[0].monitor_profile,
            LEGACY_STACK_MONITOR_PROFILE
        );
        assert_eq!(decoded.campaigns[0].execution_environment, "qemu");
    }

    #[test]
    fn stack_baseline_batch_update_allows_only_the_baseline_file_to_be_dirty() {
        assert!(!stack_baseline_update_has_source_changes(""));
        assert!(!stack_baseline_update_has_source_changes(
            " M xtask/stack-baselines.toml"
        ));
        assert!(!stack_baseline_update_has_source_changes(
            "M xtask/stack-baselines.toml"
        ));
        assert!(!stack_baseline_update_has_source_changes(
            "M  xtask/stack-baselines.toml"
        ));
        assert!(stack_baseline_update_has_source_changes(
            " M kernel/firmware/src/selected_app.rs"
        ));
        assert!(stack_baseline_update_has_source_changes(
            " M xtask/stack-baselines.toml\n M kernel/firmware/src/selected_app.rs"
        ));
    }

    #[test]
    fn predeployment_scp03_key_requires_aes128_material() {
        let keys = [PredeploymentKeyConfig {
            key_type: "Scp03Static".to_owned(),
            version: 1,
            id: 3,
            usage: "Enc".to_owned(),
            material: "00:01".to_owned(),
        }];
        assert!(validate_security_domain_keys(
            "A0:00:00:47:50:4F:53:01",
            &keys,
            "root.keys",
            &mut BTreeSet::new(),
        )
        .is_err());
    }

    #[test]
    fn predeployment_scp03_key_identity_is_unique_per_owner() {
        let key = || PredeploymentKeyConfig {
            key_type: "Scp03Static".to_owned(),
            version: 1,
            id: 3,
            usage: "Mac".to_owned(),
            material: "50:51:52:53:54:55:56:57:58:59:5A:5B:5C:5D:5E:5F".to_owned(),
        };
        let keys = [key(), key()];
        assert!(validate_security_domain_keys(
            "A0:00:00:47:50:4F:53:01",
            &keys,
            "root.keys",
            &mut BTreeSet::new(),
        )
        .is_err());
    }
}

/// Runs the standalone embedded core regression for the Cargo integration test.
pub fn run_qemu_test_for_board(board: &str) -> Result<TestReport, Box<dyn Error>> {
    run_core_test_with_context(&TestContext::default(), board)
}

/// Builds the public Rustlet declaration fixtures for Cargo integration tests.
pub fn run_rustlet_macro_build_tests() -> Result<TestReport, Box<dyn Error>> {
    run_rustlet_macro_build_tests_with_context(&TestContext::default())
}

#[cfg(test)]
mod atr_initialization_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{self, ErrorKind};

    struct ScriptedLink(VecDeque<io::Result<Vec<u8>>>);

    impl Read for ScriptedLink {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let bytes = self
                .0
                .pop_front()
                .unwrap_or_else(|| Err(ErrorKind::WouldBlock.into()))?;
            output[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }

    impl Write for ScriptedLink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn client(reads: Vec<io::Result<Vec<u8>>>) -> ApduClient {
        ApduClient {
            protocol: apdu_tool::T0Client::new(
                Box::new(ScriptedLink(reads.into())),
                ApduClient::protocol_config(Duration::from_millis(1)),
            ),
            observer: None,
        }
    }

    #[test]
    fn initialization_wait_is_independent_of_apdu_byte_timeout() {
        let mut link = client(vec![
            Err(ErrorKind::WouldBlock.into()),
            Err(ErrorKind::TimedOut.into()),
            Ok(vec![0x3b, 0x1b]),
            Ok(Vec::new()),
        ]);
        assert_eq!(
            link.read_frame(Duration::from_secs(1)).unwrap(),
            [0x3b, 0x1b]
        );
        assert_eq!(
            link.protocol.config().silence_timeout,
            Duration::from_millis(1)
        );
    }

    #[test]
    fn get_response_reassembles_small_chunks_without_losing_status_like_data() {
        let expected: Vec<u8> = (0..65).map(|i| 0x60u8.wrapping_add(i)).collect();
        let mut wire = vec![0x84, 0x61, 65]; // ACK input, pending response
        let mut remaining = expected.len();
        for chunk in expected.chunks(24) {
            wire.push(0xc0);
            wire.extend_from_slice(chunk);
            remaining -= chunk.len();
            let status = if remaining == 0 {
                [0x90, 0]
            } else {
                [0x61, remaining as u8]
            };
            wire.extend_from_slice(&status);
        }
        let mut link = client(wire.into_iter().map(|b| Ok(vec![b])).collect());
        let response = link
            .exchange_with_response_chunk_limit(
                &CommandBuilder::process_with_data_and_le(0x84, &[0], 65),
                24,
            )
            .unwrap();
        assert_eq!(response.data, expected);
        assert_eq!(response.status, (0x90, 0));
        assert!(client(vec![])
            .exchange_with_response_chunk_limit(&CommandBuilder::process_no_data(0x84), 0)
            .is_err());
    }

    #[test]
    fn fragmented_atr_is_collected_after_the_first_byte() {
        let mut link = client(vec![
            Ok(vec![0x3b]),
            Err(ErrorKind::WouldBlock.into()),
            Ok(vec![0x1b, 0x11]),
            Ok(Vec::new()),
        ]);
        assert_eq!(link.read_frame(Duration::ZERO).unwrap(), [0x3b, 0x1b, 0x11]);
    }

    #[test]
    fn absent_atr_still_has_a_finite_deadline() {
        assert!(client(vec![])
            .read_frame(Duration::ZERO)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn initialization_does_not_swallow_transport_errors() {
        let error = client(vec![Err(ErrorKind::ConnectionReset.into())])
            .read_frame(Duration::from_secs(1))
            .unwrap_err();
        let error = error.downcast_ref::<apdu_tool::ApduToolError>().unwrap();
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap()
                .kind(),
            ErrorKind::ConnectionReset
        );
    }
}
