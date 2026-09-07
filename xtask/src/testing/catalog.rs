//! Static scenario catalogue, configuration selection and generated help.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arguments {
    Standard,
    Scp03,
    Rustlet,
    Crypto,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Boards {
    Default,
    AllRustlet,
    PicoPersistence,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetConstraint {
    Any,
    /// QEMU needs its persistent Pico1 flash file; hardware uses board flash.
    PersistentFlash,
    /// The OpenOCD fault-observation scripts currently describe RP2350 state.
    Pico2HardwareFault,
}

#[derive(Clone, Copy)]
pub(crate) struct TestCapabilities {
    pub(crate) fae: bool,
    pub(crate) stack_observer: bool,
    pub(crate) without_rustlets: bool,
    pub(crate) target: TargetConstraint,
}

/// A scenario's advertised options must agree with what its runner consumes.
pub(crate) struct TestSpec {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    pub(crate) config: Option<&'static str>,
    pub(crate) capabilities: TestCapabilities,
    pub(crate) boards: Boards,
    pub(crate) arguments: Arguments,
    pub(crate) support: BoardSupportLevel,
    pub(crate) mode: fn(TestOptions) -> Scenario,
}

/// The catalogue owns naming, help, configuration and the CLI-to-runner mapping.
/// No runtime registration or second catalogue of command aliases is needed.
pub(crate) struct TestCatalog;

macro_rules! test_catalog {
    ($(($name:literal, $pattern:pat, $description:literal, $config:expr,
        $fae:literal, $stack:literal, $without_rustlets:literal, $target:ident,
        $boards:ident, $arguments:ident,
        $support:ident, $mode:expr)),* $(,)?) => {
        pub(crate) const TESTS: &[TestSpec] = &[
            $(TestSpec { name: $name, description: $description, config: $config,
                capabilities: TestCapabilities { fae: $fae,
                    stack_observer: $stack, without_rustlets: $without_rustlets,
                    target: TargetConstraint::$target }, boards: Boards::$boards,
                arguments: Arguments::$arguments, support: BoardSupportLevel::$support,
                mode: $mode }),*
        ];
        impl TestCatalog {
            pub(crate) fn for_scenario(scenario: &Scenario) -> &'static TestSpec {
                let name = match scenario {
                    $($pattern => $name,)*
                };
                Self::find(name).expect("every Scenario is declared in TestCatalog")
            }
        }
    };
}

test_catalog! {
    ("kernel_stack_guard", Scenario::KernelStackGuard(_), "Kernel stack guard fault and diagnostic.", None,
        false, false, false, Pico2HardwareFault, Default, Standard, KernelApdu, |o| Scenario::KernelStackGuard(o.board())),
    ("kernel_ram_nx", Scenario::KernelRamNx(_), "Kernel RAM execute-never fault and diagnostic.", None,
        false, false, false, Pico2HardwareFault, Default, Standard, KernelApdu, |o| Scenario::KernelRamNx(o.board())),
    ("kernel_ping", Scenario::KernelPing { .. }, "Kernel-local APDU ping.", Some("configs/config_kernel_ping.toml"),
        false, true, false, Any, Default, Standard, KernelApdu, |o| Scenario::KernelPing { board: o.board(), check_stack: o.check_stack }),
    ("kernel_t0", Scenario::KernelT0(_), "Kernel-local T=0 transcript.", Some("configs/config_kernel_t0_test.toml"),
        false, false, false, Any, Default, Standard, KernelApdu, |o| Scenario::KernelT0(o.board())),
    ("kernel_timer", Scenario::KernelTimer(_), "Periodic kernel interrupt and top/bottom-half transition.", Some("configs/config_kernel_timer_test.toml"),
        false, false, false, Any, Default, Standard, KernelApdu, |o| Scenario::KernelTimer(o.board())),
    ("kernel_null_byte", Scenario::KernelNullByte(_), "Periodic T=0 NULL byte emission while a command remains in progress.", Some("configs/config_kernel_timer_test.toml"),
        false, false, false, Any, Default, Standard, KernelApdu, |o| Scenario::KernelNullByte(o.board())),
    ("kernel_registry", Scenario::KernelRegistry(_), "Registry data persistence across reboots (QEMU: Pico1; OpenOCD: flash-capable boards, validated on Pico2).", Some("configs/config_kernel_registry_test.toml"),
        false, false, false, PersistentFlash, Default, Standard, KernelApdu, |o| Scenario::KernelRegistry(o.board())),
    ("kernel_flash", Scenario::KernelFlash(_), "Reserved flash block write/read across kernel reboots (QEMU: Pico1; OpenOCD: flash-capable boards, validated on Pico2).", Some("configs/config_kernel_flash_probe.toml"),
        false, false, false, PersistentFlash, Default, Standard, KernelApdu, |o| Scenario::KernelFlash(o.board())),
    ("kernel_crypto", Scenario::KernelCrypto { .. }, "Kernel crypto API regression or one benchmark.", Some("configs/config_kernel_crypto_self_test.toml"),
        false, false, false, Any, Default, Crypto, KernelApdu, |o| Scenario::KernelCrypto { board: o.board(), bench: o.bench, }),
    ("gp_noscp", Scenario::GpNoScp { .. }, "Clear-channel GP management policy.", Some("configs/config_noscp_test.toml"),
        true, false, false, Any, Default, Standard, GlobalPlatformApdu, |o| Scenario::GpNoScp { board: o.board(), image_format: o.image_format,  }),
    ("gp_scp03", Scenario::GpScp03 { .. }, "SCP03 S8, S16, or both profiles.", Some("configs/config_scp03_test.toml"),
        true, true, true, Any, Default, Scp03, GlobalPlatformApdu, |o| Scenario::GpScp03 { board: o.board(), image_format: o.image_format, check_stack: o.check_stack, scp03_selection: o.scp03.expect("validated SCP03 selection"), }),
    ("gp_scp11a", Scenario::GpScp11a { .. }, "SCP11a establishment and management.", Some("configs/config_scp11a_test.toml"),
        true, true, true, Any, Default, Standard, GlobalPlatformApdu, |o| Scenario::GpScp11a { board: o.board(), image_format: o.image_format, check_stack: o.check_stack,  }),
    ("gp_scp11b", Scenario::GpScp11b { .. }, "SCP11b establishment and management.", Some("configs/config_scp11b_test.toml"),
        true, true, true, Any, Default, Standard, GlobalPlatformApdu, |o| Scenario::GpScp11b { board: o.board(), image_format: o.image_format, check_stack: o.check_stack,  }),
    ("gp_scp11c", Scenario::GpScp11c { .. }, "SCP11c establishment and management.", Some("configs/config_scp11c_test.toml"),
        true, true, true, Any, Default, Standard, GlobalPlatformApdu, |o| Scenario::GpScp11c { board: o.board(), image_format: o.image_format, check_stack: o.check_stack,  }),
    ("gp_security_domain", Scenario::GpSecurityDomain { .. }, "Kernel Security Domain management and discovery.", None,
        true, false, false, Any, Default, Standard, GlobalPlatformApdu, |o| Scenario::GpSecurityDomain { board: o.board(), image_format: o.image_format,  }),
    ("gp_predeployment", Scenario::GpPredeployment { .. }, "Declarative Security Domain hierarchy.", Some("configs/config_predeployment_test.toml"),
        true, false, false, Any, Default, Standard, GlobalPlatformApdu, |o| Scenario::GpPredeployment { board: o.board(), image_format: o.image_format,  }),
    ("gp_registry", Scenario::GpRegistry { .. }, "Clear APDU registry access without SCP.", Some("configs/config_gp_registry_test.toml"),
        true, false, false, Any, Default, Standard, GlobalPlatformApdu, |o| Scenario::GpRegistry { board: o.board(), image_format: o.image_format,  }),
    ("gp_persistence", Scenario::GpPersistence { .. }, "Persistent registry across boots.", Some("configs/config_gp_persistence_test.toml"),
        false, false, false, PersistentFlash, PicoPersistence, Standard, GlobalPlatformApdu, |o| Scenario::GpPersistence { board: o.board(),  }),
    ("gp_all", Scenario::GpAll { .. }, "Aggregate GP regression campaign.", None,
        true, false, false, Any, Default, Standard, Rustlet, |o| Scenario::GpAll { board: o.board(), image_format: o.image_format,  }),
    ("gp_scp03_install_load", Scenario::GpScp03InstallLoad { .. }, "Focused SCP03 INSTALL for load / LOAD.", Some("configs/config_scp03_test.toml"),
        false, false, false, PersistentFlash, PicoPersistence, Standard, GlobalPlatformApdu, |o| Scenario::GpScp03InstallLoad { board: o.board(),  }),
    ("gp_scp11a_install_load", Scenario::GpScp11aInstallLoad { .. }, "Owner-authenticated SCP11a INSTALL for load / LOAD across reboots.", Some("configs/config_scp11a_test.toml"),
        false, false, false, PersistentFlash, PicoPersistence, Standard, GlobalPlatformApdu, |o| Scenario::GpScp11aInstallLoad { board: o.board(),  }),
    ("gp_rustlet_security_domain_scp03", Scenario::GpRustletSecurityDomainScp03 { .. }, "Rustlet Security Domain scp03 management.", Some("configs/config_rustlet_security_domain_scp03_test.toml"),
        true, true, false, Any, Default, Standard, Rustlet, |o| Scenario::GpRustletSecurityDomainScp03 { board: o.board(), image_format: o.image_format, check_stack: o.check_stack,  }),
    ("gp_rustlet_security_domain_delegated_scp03", Scenario::GpRustletSecurityDomainDelegatedScp03 { .. }, "Rustlet Security Domain delegated scp03 management.", Some("configs/config_rustlet_security_domain_delegated_scp03_test.toml"),
        true, true, false, Any, Default, Standard, Rustlet, |o| Scenario::GpRustletSecurityDomainDelegatedScp03 { board: o.board(), image_format: o.image_format, check_stack: o.check_stack,  }),
    ("gp_rustlet_security_domain_scp11a", Scenario::GpRustletSecurityDomainScp11a { .. }, "Rustlet Security Domain scp11a management.", Some("configs/config_rustlet_security_domain_scp11a_test.toml"),
        true, true, false, Any, Default, Standard, Rustlet, |o| Scenario::GpRustletSecurityDomainScp11a { board: o.board(), image_format: o.image_format, check_stack: o.check_stack,  }),
    ("gp_rustlet_security_domain_scp11b", Scenario::GpRustletSecurityDomainScp11b { .. }, "Rustlet Security Domain scp11b management.", Some("configs/config_rustlet_security_domain_scp11b_test.toml"),
        true, true, false, Any, Default, Standard, Rustlet, |o| Scenario::GpRustletSecurityDomainScp11b { board: o.board(), image_format: o.image_format, check_stack: o.check_stack,  }),
    ("gp_rustlet_security_domain_scp11c", Scenario::GpRustletSecurityDomainScp11c { .. }, "Rustlet Security Domain scp11c management.", Some("configs/config_rustlet_security_domain_scp11c_test.toml"),
        true, true, false, Any, Default, Standard, Rustlet, |o| Scenario::GpRustletSecurityDomainScp11c { board: o.board(), image_format: o.image_format, check_stack: o.check_stack,  }),
    ("rustlet_isolation", Scenario::RustletIsolation(_), "Cross-Rustlet isolation, faults and liveness.", Some("configs/config_rustlet_isolation_test.toml"),
        false, false, false, Any, Default, Standard, Rustlet, |o| Scenario::RustletIsolation(o.board())),
    ("rustlet_watchdog", Scenario::RustletWatchdog(_), "Watchdog termination of a non-returning Rustlet and kernel liveness.", Some("configs/config_rustlet_watchdog_test.toml"),
        false, false, false, Any, Default, Standard, Rustlet, |o| Scenario::RustletWatchdog(o.board())),
    ("rustlet", Scenario::RustletSingle { .. }, "Canonical APDU scenario for one Rustlet.", None,
        true, true, false, Any, Default, Rustlet, Rustlet, |o| Scenario::RustletSingle { board: o.board(), image_format: o.image_format, check_stack: o.check_stack, rustlet: o.rustlet.expect("validated Rustlet name"), }),
    ("rustlet_all", Scenario::RustletAll { .. }, "All canonical Rustlet functional scenarios.", Some("configs/config_rustlet_test_all.toml"),
        true, true, false, Any, AllRustlet, Standard, Rustlet, |o| Scenario::RustletAll { board_filter: o.board.clone(), image_format: o.image_format, check_stack: o.check_stack }),
}

impl TestCatalog {
    pub(crate) fn find(name: &str) -> Option<&'static TestSpec> {
        TESTS.iter().find(|test| test.name == name)
    }
}

/// Returns the configured manifest without building or starting a target.
pub(crate) fn config_for_scenario(scenario: &Scenario) -> Option<PathBuf> {
    let root = repo_root().ok()?;
    if let Scenario::RustletSingle { rustlet, .. } = scenario {
        return [
            root.join(format!("configs/config_rustlet_{rustlet}.toml")),
            root.join(format!("configs/config_rustlet_single_test_{rustlet}.toml")),
        ]
        .into_iter()
        .find(|path| path.is_file());
    }
    TestCatalog::for_scenario(scenario)
        .config
        .map(|path| root.join(path))
        .filter(|path| path.is_file())
}

/// Formats both catalogue and per-scenario help from the same descriptors.
pub(crate) fn help(name: Option<&str>) -> String {
    let mut out = String::new();
    let Some(name) = name else {
        out.push_str(
            "Usage:\n  cargo run test <test> [board] [options] [test arguments]\n\nTests:\n",
        );
        for test in TESTS {
            writeln!(out, "  {:44} {}", test.name, test.description).unwrap();
        }
        out.push_str("\nUse cargo run test <test> --help for supported options and defaults.\n");
        out.push_str(
            "Backend: --on qemu by default; --on openocd for an explicit board.\nAPDU scenarios use the same build, deployment, reboot and reporting pipeline on both backends.\nA run above the board's validated support level is reported as a bring-up attempt.\nUnique USB serial link auto-detected, erase consent required.\n",
        );
        out.push_str(&board_matrix_help());
        return out;
    };
    let Some(test) = TestCatalog::find(name) else {
        return format!("Unknown test: {name}\nUse cargo run test --help.");
    };
    writeln!(
        out,
        "Usage:\n  cargo run test {} [board] [options]{}\n\n{}\n",
        test.name,
        match test.arguments {
            Arguments::Rustlet => " <rustlet>",
            Arguments::Scp03 => " --scp03=s8|s16|all",
            Arguments::Crypto => " [--bench <operation> [args...]]",
            Arguments::Standard => "",
        },
        test.description
    )
    .unwrap();
    out.push_str("Options:\n  --on qemu|openocd    QEMU by default, OpenOCD if the board has no QEMU support\n  --elf               Native kernel ELF (default)\n");
    out.push_str("  --serial ENDPOINT   APDU link override: /dev/tty...:115200, COM3:115200, HOST:PORT or /path/socket\n                      Defaults to the unique USB serial port at 115200; lists choices if ambiguous\n  --probe-serial ID   Optional CMSIS-DAP adapter selector (not the APDU port)\n  --allow-destructive Explicitly authorize erasing the board FLASH, including registry data\nOpenOCD requires ELF. Stack baselines are kept separately for QEMU and hardware.\nRuns above the board's validated support level are explicit bring-up attempts.\n");
    if test.capabilities.fae {
        out.push_str("  --fae               Bootable kernel FAE\n");
    }
    if test.capabilities.stack_observer {
        out.push_str("  --check_stack       Measure stack high-watermarks and check baselines\n  --update_stack_baseline  Measure/update baselines on a clean worktree\n");
    }
    if test.capabilities.without_rustlets {
        out.push_str("  --without-rustlets  Kernel SCP bring-up: no Rustlet payloads or execution\n                      Cannot be combined with stack baseline checks/updates\n");
    }
    out.push_str("  --config <path>     Override the predeployment manifest\n  --trace=none|semihosting|jtag  Debug trace output (default: none)\n  -h, --help          Show this help\n");
    match test.arguments {
        Arguments::Scp03 => out.push_str("\n--scp03=s8|s16|all (or positional s8/s16/all) is required.\nWithout a profile, show help without running tests.\n"),
        Arguments::Rustlet => { writeln!(out, "\nRustlets: {}", canonical_single_rustlet_names()).unwrap(); }
        Arguments::Crypto => out.push_str("\nBench operations (omit operands for defaults):\n  fill_random [len]\n  aes_cbc [key_hex] [iv_hex] [data_hex]\n  aes_ecb [key_hex] [data_hex]\n  aes_iso9797_m2 [key_hex] [iv_hex] [data_hex]\n  cmac [key_hex] [data_hex]\n  hkdf [ikm_hex] [salt_hex] [out_len]\n  x963 [shared_secret_hex] [shared_info_hex] [out_len]\n  p256_generate_keypair\n  p256_ecdh [private_key_hex] [peer_public_key_hex]\n"),
        Arguments::Standard => {}
    }
    match test.boards {
        Boards::Default => {
            writeln!(out, "\nDefault board: {DEFAULT_BOARD}").unwrap();
        }
        Boards::AllRustlet => {
            out.push_str("\nNo board: all functional Rustlet/QEMU boards from BoardCatalog.\n")
        }
        Boards::PicoPersistence => out.push_str(
            "\nDefault board: raspi-pico1. QEMU requires Pico1 persistent flash; hardware requires a supported OpenOCD scenario and flash-capable board.\n",
        ),
    }
    if let Some(config) = test.config {
        writeln!(out, "Default config: {config}").unwrap();
    }
    writeln!(out, "Required board level: {}", test.support.label()).unwrap();
    out.push_str(&board_matrix_help());
    out
}
