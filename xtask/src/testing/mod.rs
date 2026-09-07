//! Target test orchestration. Scenarios and target lifetimes are separate.
use super::*;

pub(crate) fn with_stack_observer(
    ctx: &TestContext,
    enabled: bool,
    key: StackBaselineKey,
    expect_rustlet_measurement: bool,
    run: impl FnOnce(&TestContext) -> Result<TestReport, Box<dyn Error>>,
) -> Result<TestReport, Box<dyn Error>> {
    if !enabled {
        return run(ctx);
    }
    let observer = std::rc::Rc::new(std::cell::RefCell::new(StackObserver::new(
        ctx.execution_env(),
        key.with_execution_environment(ctx.execution_env()),
        expect_rustlet_measurement,
        ctx.update_stack_baseline,
    )));
    let observed = ctx.with_apdu_observer(observer.clone());
    let report = run(&observed)?;
    observer.borrow().finish()?;
    Ok(report)
}

pub(crate) fn run(ctx: &TestContext, scenario: Scenario) -> Result<(), Box<dyn Error>> {
    match scenario {
        Scenario::KernelStackGuard(board) => {
            run_kernel_stack_guard_test_for_board(ctx, &board)?;
            println!("KERNEL-STACK-GUARD-DONE board={} total=1", board);
        }
        Scenario::KernelRamNx(board) => {
            run_kernel_ram_nx_test_for_board(ctx, &board)?;
            println!("KERNEL-RAM-NX-DONE board={} total=1", board);
        }
        Scenario::KernelPing { board, check_stack } => {
            let summary = with_stack_observer(
                ctx,
                check_stack,
                StackBaselineKey::new("kernel_ping", &board, LayoutImageFormat::Elf, None),
                false,
                |ctx| run_kernel_ping_test_for_board(ctx, &board),
            )?;
            println!("KERNEL-PING-DONE board={} total={}", board, summary.total);
        }
        Scenario::KernelFlash(board) => {
            run_kernel_flash_test_for_board(ctx, &board)?;
            println!("KERNEL-FLASH-DONE board={} total=5", board);
        }
        Scenario::KernelRegistry(board) => {
            let total = run_kernel_registry_test_for_board(ctx, &board)?;
            println!("KERNEL-REGISTRY-DONE board={} total={}", board, total);
        }
        Scenario::KernelT0(board) => {
            let summary = run_kernel_t0_test_for_board(ctx, &board)?;
            println!("KERNEL-T0-DONE board={} total={}", board, summary.total);
        }
        Scenario::KernelTimer(board) => {
            let summary = run_kernel_timer_test_for_board(ctx, &board)?;
            println!("KERNEL-TIMER-DONE board={} total={}", board, summary.total);
        }
        Scenario::KernelNullByte(board) => {
            let summary = run_kernel_null_byte_test_for_board(ctx, &board)?;
            println!(
                "KERNEL-NULL-BYTE-DONE board={} total={}",
                board, summary.total
            );
        }
        Scenario::KernelCrypto { board, bench } => {
            let summary = run_kernel_crypto_test_for_board(ctx, &board, bench.as_ref())?;
            println!("KERNEL-CRYPTO-DONE board={} total={}", board, summary.total);
        }
        Scenario::GpNoScp {
            image_format,
            board,
        } => {
            let summary = run_noscp_test_for_board(ctx, image_format, &board)?;
            println!("NO-SCP-DONE board={} total={}", board, summary.total);
        }
        Scenario::GpScp03 {
            image_format,
            board,
            scp03_selection,
            check_stack,
        } => {
            let summary = with_stack_observer(
                ctx,
                check_stack,
                StackBaselineKey::new(
                    "gp_scp03",
                    &board,
                    image_format,
                    Some(scp03_selection.stack_scenario()),
                ),
                false,
                |ctx| run_scp03_test_for_board(ctx, image_format, &board, scp03_selection),
            )?;
            println!("SCP03-DONE board={} total={}", board, summary.total);
        }
        Scenario::GpScp11c {
            image_format,
            board,
            check_stack,
        } => {
            let summary = with_stack_observer(
                ctx,
                check_stack,
                StackBaselineKey::new("gp_scp11c", &board, image_format, None),
                false,
                |ctx| run_scp11c_test_for_board(ctx, image_format, &board),
            )?;
            println!("SCP11C-DONE board={} total={}", board, summary.total);
        }
        Scenario::GpScp11a {
            image_format,
            board,
            check_stack,
        } => {
            let summary = with_stack_observer(
                ctx,
                check_stack,
                StackBaselineKey::new("gp_scp11a", &board, image_format, None),
                false,
                |ctx| run_scp11a_test_for_board(ctx, image_format, &board),
            )?;
            println!("SCP11A-DONE board={} total={}", board, summary.total);
        }
        Scenario::GpScp11b {
            image_format,
            board,
            check_stack,
        } => {
            let summary = with_stack_observer(
                ctx,
                check_stack,
                StackBaselineKey::new("gp_scp11b", &board, image_format, None),
                false,
                |ctx| run_scp11b_test_for_board(ctx, image_format, &board),
            )?;
            println!("SCP11B-DONE board={} total={}", board, summary.total);
        }
        Scenario::GpSecurityDomain {
            image_format,
            board,
        } => {
            let summary = run_security_domain_test_for_board(ctx, image_format, &board)?;
            println!(
                "SECURITY-DOMAIN-DONE board={} total={}",
                board, summary.total
            );
        }
        Scenario::GpPredeployment {
            image_format,
            board,
        } => {
            let summary = run_predeployment_test_for_board(ctx, image_format, &board)?;
            println!("PREDEPLOYMENT-DONE board={} total={}", board, summary.total);
        }
        Scenario::GpRegistry {
            image_format,
            board,
        } => {
            let summary = run_registry_test_for_board(ctx, image_format, &board)?;
            println!("REGISTRY-DONE board={} total={}", board, summary.total);
        }
        Scenario::GpPersistence { board } => {
            let summary = run_persistence_test_for_board(ctx, &board)?;
            println!("PERSISTENCE-DONE board={} total={}", board, summary.total);
        }
        Scenario::GpAll {
            image_format,
            board,
        } => {
            let summary = run_gp_all_test_for_board(ctx, image_format, &board)?;
            println!("GP-ALL-DONE board={} total={}", board, summary.total);
        }
        Scenario::GpScp03InstallLoad { board } => {
            let summary = run_with_build_config(ctx, "configs/config_scp03_test.toml", |ctx| {
                run_scp03_install_load_test_for_board(ctx, &board)
            })?;
            println!(
                "SCP03-INSTALL-LOAD-DONE board={} total={}",
                board, summary.total
            );
        }
        Scenario::GpScp11aInstallLoad { board } => {
            let total = run_with_build_config(ctx, "configs/config_scp11a_test.toml", |ctx| {
                run_kernel_security_domain_scp11_load_persistence_test_for_board(ctx, &board)
            })?;
            println!("SCP11A-INSTALL-LOAD-DONE board={} total={}", board, total);
        }
        Scenario::GpRustletSecurityDomainScp03 {
            image_format,
            board,
            check_stack,
        } => {
            let summary = with_stack_observer(
                ctx,
                check_stack,
                StackBaselineKey::new(
                    "gp_rustlet_security_domain_scp03",
                    &board,
                    image_format,
                    None,
                ),
                true,
                |ctx| run_rustlet_security_domain_test_for_board(ctx, image_format, &board),
            )?;
            println!(
                "RUSTLET-SECURITY-DOMAIN-DONE board={} total={}",
                board, summary.total
            );
        }
        Scenario::GpRustletSecurityDomainDelegatedScp03 {
            image_format,
            board,
            check_stack,
        } => {
            let summary = with_stack_observer(
                ctx,
                check_stack,
                StackBaselineKey::new(
                    "gp_rustlet_security_domain_delegated_scp03",
                    &board,
                    image_format,
                    None,
                ),
                true,
                |ctx| run_rustlet_security_domain_test_for_board(ctx, image_format, &board),
            )?;
            println!(
                "RUSTLET-SECURITY-DOMAIN-DELEGATED-SCP03-DONE board={} total={}",
                board, summary.total
            );
        }
        Scenario::GpRustletSecurityDomainScp11a {
            image_format,
            board,
            check_stack,
        } => {
            let summary = with_stack_observer(
                ctx,
                check_stack,
                StackBaselineKey::new(
                    "gp_rustlet_security_domain_scp11a",
                    &board,
                    image_format,
                    None,
                ),
                true,
                |ctx| run_rustlet_security_domain_scp11a_test_for_board(ctx, image_format, &board),
            )?;
            println!(
                "RUSTLET-SECURITY-DOMAIN-SCP11A-DONE board={} total={}",
                board, summary.total
            );
        }
        Scenario::GpRustletSecurityDomainScp11b {
            image_format,
            board,
            check_stack,
        } => {
            let summary = with_stack_observer(
                ctx,
                check_stack,
                StackBaselineKey::new(
                    "gp_rustlet_security_domain_scp11b",
                    &board,
                    image_format,
                    None,
                ),
                true,
                |ctx| run_rustlet_security_domain_scp11b_test_for_board(ctx, image_format, &board),
            )?;
            println!(
                "RUSTLET-SECURITY-DOMAIN-SCP11B-DONE board={} total={}",
                board, summary.total
            );
        }
        Scenario::GpRustletSecurityDomainScp11c {
            image_format,
            board,
            check_stack,
        } => {
            let summary = with_stack_observer(
                ctx,
                check_stack,
                StackBaselineKey::new(
                    "gp_rustlet_security_domain_scp11c",
                    &board,
                    image_format,
                    None,
                ),
                true,
                |ctx| run_rustlet_security_domain_scp11c_test_for_board(ctx, image_format, &board),
            )?;
            println!(
                "RUSTLET-SECURITY-DOMAIN-SCP11C-DONE board={} total={}",
                board, summary.total
            );
        }
        Scenario::RustletIsolation(board) => {
            let summary = run_rustlet_isolation_test_for_board(ctx, &board)?;
            println!(
                "RUSTLET-ISOLATION-DONE board={} total={}",
                board, summary.total
            );
        }
        Scenario::RustletWatchdog(board) => {
            let summary = run_rustlet_watchdog_test_for_board(ctx, &board)?;
            println!(
                "RUSTLET-WATCHDOG-DONE board={} total={}",
                board, summary.total
            );
        }
        Scenario::RustletSingle {
            image_format,
            board,
            rustlet,
            check_stack,
        } => {
            let summary = run_rustlet_single_test_for_board(
                ctx,
                image_format,
                &board,
                &rustlet,
                check_stack,
            )?;
            println!(
                "RUSTLET-SINGLE-DONE board={} rustlet={} total={}",
                board, rustlet, summary.total
            );
        }
        Scenario::RustletAll {
            image_format,
            board_filter,
            check_stack,
        } => {
            let boards = match board_filter.as_deref() {
                Some(board) if ctx.openocd().is_some() => vec![board],
                Some(board) if is_rustlet_qemu_board(board) => vec![board],
                Some(board) => {
                    return Err(format!(
                        "board `{board}` is not a Rustlet/QEMU target; \
                         expected one of: {}",
                        rustlet_qemu_board_names().join(", ")
                    )
                    .into())
                }
                None => rustlet_qemu_board_names(),
            };
            for board in boards {
                let summary =
                    run_rustlet_functional_test_for_board(ctx, image_format, board, check_stack)?;
                println!("RUSTLET-TEST-DONE board={} total={}", board, summary.total);
            }
        }
    }

    Ok(())
}
mod catalog;
mod context;
pub(crate) mod openocd;
mod options;
pub(crate) mod scenarios;
pub(crate) mod target;
use catalog::*;
pub(crate) use catalog::{config_for_scenario, help};
pub(crate) use context::{BuildContext, TargetOptions, TestContext};
pub(crate) use options::parse;
pub(crate) use options::TestInvocation;
use options::TestOptions;

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Result<Mode, Box<dyn Error>> {
        parse_mode(args.iter().map(|s| (*s).to_owned()))
    }

    fn invocation(mode: &Mode) -> &TestInvocation {
        let Mode::Test(invocation) = mode else {
            panic!("expected test invocation, got {mode:?}")
        };
        invocation
    }

    fn scenario(mode: &Mode) -> &Scenario {
        &invocation(mode).scenario
    }

    #[test]
    fn empty_test_command_and_help_never_run_a_scenario() {
        for args in [vec!["test"], vec!["test", "-h"], vec!["test", "--help"]] {
            assert!(matches!(cli(&args).unwrap(), Mode::Help(Some(name)) if name == "test"));
        }
        for spec in TESTS {
            assert!(matches!(
                cli(&["test", spec.name, "--help"]).unwrap(),
                Mode::Help(_)
            ));
            assert!(help(Some(spec.name)).contains(spec.description));
        }
    }

    #[test]
    fn catalogue_names_are_unique_and_configs_exist() {
        let mut names = std::collections::BTreeSet::new();
        for spec in TESTS {
            assert!(names.insert(spec.name));
            assert!(!spec.name.starts_with("qemu_"));
            if let Some(config) = spec.config {
                assert!(repo_root().unwrap().join(config).is_file(), "{config}");
            }
        }
    }

    #[test]
    fn every_catalogue_entry_selects_its_own_runner() {
        for spec in TESTS {
            let mut args = vec!["test", spec.name];
            if matches!(spec.name, "kernel_flash" | "kernel_registry") {
                args.push("raspi-pico1");
            }
            match spec.arguments {
                Arguments::Scp03 => args.push("--scp03=s8"),
                Arguments::Rustlet => args.push("minimal_valid_test"),
                _ => {}
            }
            let mode = cli(&args).unwrap();
            assert_eq!(TestCatalog::for_scenario(scenario(&mode)).name, spec.name);
        }
    }

    #[test]
    fn old_commands_and_ambiguous_alias_are_rejected_even_with_help() {
        for name in [
            "qemu_kernel_ping",
            "qemu_rustlet_single",
            "qemu_test_scp03_install_load",
        ] {
            assert!(cli(&[name]).is_err());
            assert!(cli(&[name, "--help"]).is_err());
        }
        assert!(cli(&["test", "gp_rustlet_security_domain"]).is_err());
        assert!(cli(&["test", "no_such_test", "--help"]).is_err());
    }

    #[test]
    fn explicit_elf_is_accepted_by_fixed_elf_runners() {
        assert!(
            matches!(cli(&["test", "kernel_ping", "--elf", "--on=qemu"]).unwrap(),
            Mode::Test(TestInvocation { scenario: Scenario::KernelPing { board, .. }, .. }) if board == DEFAULT_BOARD)
        );
        assert!(cli(&["test", "kernel_ping", "--fae"]).is_err());
    }

    #[test]
    fn unsupported_options_and_conflicts_are_not_silently_ignored() {
        for tail in [
            vec!["--elf", "--fae"],
            vec!["--on=qemu", "--on=qemu"],
            vec!["--trace=none", "--trace=semihosting"],
            vec!["--check_stack", "--update_stack_baseline"],
            vec!["--scp03=s8"],
            vec!["--bench", "fill_random"],
            vec!["mps2-an385", "mps2-an385"],
            vec!["--unknown"],
        ] {
            let mut args = vec!["test", "kernel_ping"];
            args.extend(tail);
            assert!(cli(&args).is_err(), "{args:?}");
        }
        assert!(cli(&["test", "gp_scp03", "--scp03=s8", "s16"]).is_err());
    }

    #[test]
    fn backends_are_checked_before_running_anything() {
        assert!(cli(&["test", "kernel_ping", "--on"]).is_err());
        assert!(cli(&["test", "kernel_ping", "--on=unknown"]).is_err());
        let missing = cli(&["test", "kernel_ping", "--on=openocd"])
            .unwrap_err()
            .to_string();
        assert!(missing.contains("explicit board"));
        let unsupported = cli(&["test", "kernel_ping", "raspi-pico2", "--on=openocd"])
            .unwrap_err()
            .to_string();
        assert!(unsupported.contains("--allow-destructive"));
        assert!(cli(&["test", "kernel_ping", "-on", "qemu"]).is_ok());
    }

    #[test]
    fn boards_are_validated_against_catalogue_capabilities() {
        assert!(cli(&["test", "kernel_ping", "typo"]).is_err());
        assert!(cli(&["test", "kernel_ping", "raspi-pico2"]).is_err());
        assert!(cli(&["test", "gp_persistence", "mps2-an385"]).is_err());
        assert!(cli(&["test", "kernel_ping", "mps2-an385", "--trace=jtag"]).is_err());
    }

    #[test]
    fn hardware_defaults_and_consent_are_explicit_and_fail_closed() {
        let tail = ["--serial", "127.0.0.1:4444", "--allow-destructive"];
        for (board, backend) in [("raspi-pico1", Some("openocd")), ("raspi-pico2", None)] {
            let mut args = vec!["test", "kernel_ping", board];
            if let Some(backend) = backend {
                args.extend(["--on", backend]);
            }
            args.extend(tail);
            assert!(matches!(
                invocation(&cli(&args).unwrap()).target,
                TargetOptions::OpenOcd(_)
            ));
        }
        assert!(matches!(
            cli(&["test", "kernel_ping", "raspi-pico1"]).unwrap(),
            Mode::Test(TestInvocation {
                scenario: Scenario::KernelPing { .. },
                target: TargetOptions::Qemu,
                ..
            })
        ));
        let denied = cli(&[
            "test",
            "kernel_ping",
            "raspi-pico2",
            "--serial",
            "COM3:115200",
        ])
        .unwrap_err()
        .to_string();
        assert!(denied.contains("--allow-destructive"));
        assert!(denied.contains("FLASH 0x"));
        assert!(cli(&["test", "kernel_ping", "raspi-pico2", "--on=qemu"]).is_err());
        for name in ["kernel_stack_guard", "kernel_ram_nx"] {
            let mut args = vec!["test", name, "raspi-pico1", "--on=openocd"];
            args.extend(tail);
            assert!(cli(&args).is_err(), "{name}");
        }
        let mut aggregate = vec!["test", "gp_all", "raspi-pico1", "--on=openocd"];
        aggregate.extend(tail);
        assert!(matches!(
            invocation(&cli(&aggregate).unwrap()).target,
            TargetOptions::OpenOcd(_)
        ));
        let mut persistence = vec!["test", "gp_persistence", "raspi-pico1", "--on=openocd"];
        persistence.extend(tail);
        assert!(matches!(
            invocation(&cli(&persistence).unwrap()).target,
            TargetOptions::OpenOcd(_)
        ));
        for rustlet in ["crypto_test", "isolation_fault_test"] {
            let mut args = vec!["test", "rustlet", "raspi-pico1", rustlet, "--on=openocd"];
            args.extend(tail);
            assert!(matches!(
                invocation(&cli(&args).unwrap()).target,
                TargetOptions::OpenOcd(_)
            ));
        }
        for name in [
            "rustlet_all",
            "rustlet_isolation",
            "rustlet_watchdog",
            "gp_security_domain",
            "gp_predeployment",
            "gp_rustlet_security_domain_scp03",
            "gp_rustlet_security_domain_delegated_scp03",
            "gp_rustlet_security_domain_scp11a",
            "gp_rustlet_security_domain_scp11b",
            "gp_rustlet_security_domain_scp11c",
        ] {
            let mut args = vec!["test", name, "raspi-pico1", "--on=openocd"];
            args.extend(tail);
            assert!(
                matches!(
                    invocation(&cli(&args).unwrap()).target,
                    TargetOptions::OpenOcd(_)
                ),
                "{name}"
            );
        }
        let mut args = vec![
            "test",
            "rustlet",
            "raspi-pico1",
            "minimal_valid_test",
            "--on=openocd",
        ];
        args.extend(tail);
        assert!(matches!(
            invocation(&cli(&args).unwrap()).target,
            TargetOptions::OpenOcd(_)
        ));
        args.push("--check_stack");
        assert!(matches!(
            invocation(&cli(&args).unwrap()).target,
            TargetOptions::OpenOcd(_)
        ));
    }

    #[test]
    fn kernel_scp_scope_is_explicit_and_keeps_full_baselines_separate() {
        for name in ["gp_scp03", "gp_scp11a", "gp_scp11b", "gp_scp11c"] {
            let mut args = vec!["test", name, "mps2-an385", "--without-rustlets"];
            if name == "gp_scp03" {
                args.push("--scp03=all");
            }
            assert!(invocation(&cli(&args).unwrap()).without_rustlets);
            for option in [
                "--check_stack",
                "--update_stack_baseline",
                "--without-rustlets",
            ] {
                let mut invalid = args.clone();
                invalid.push(option);
                assert!(cli(&invalid).is_err());
            }
        }
        for name in [
            "kernel_ping",
            "gp_noscp",
            "gp_all",
            "gp_rustlet_security_domain_scp03",
        ] {
            assert!(cli(&["test", name, "--without-rustlets"]).is_err());
        }
        let hardware = cli(&[
            "test",
            "gp_scp11b",
            "raspi-pico2",
            "--without-rustlets",
            "--on=openocd",
            "--serial=COM3:115200",
            "--allow-destructive",
        ])
        .unwrap();
        assert!(matches!(
            invocation(&hardware).target,
            TargetOptions::OpenOcd(_)
        ));
        assert!(invocation(&hardware).without_rustlets);
    }

    #[test]
    fn openocd_accepts_catalogue_scenarios_without_a_name_allowlist() {
        for (name, rustlet) in [
            ("gp_noscp", None),
            ("gp_scp03", None),
            ("gp_scp11a", None),
            ("gp_scp11b", None),
            ("gp_scp11c", None),
            ("gp_security_domain", None),
            ("gp_predeployment", None),
            ("gp_registry", None),
            ("gp_persistence", None),
            ("gp_all", None),
            ("gp_scp11a_install_load", None),
            ("rustlet", Some("minimal_valid_test")),
            ("rustlet", Some("apdus_test")),
            ("rustlet", Some("crypto_test")),
            ("rustlet", Some("ecdh_test")),
            ("rustlet", Some("state_test")),
            ("rustlet", Some("serialization_test")),
            ("rustlet", Some("stack_overflow_test")),
            ("rustlet", Some("stack_overflow_recursive_test")),
            ("rustlet", Some("isolation_fault_test")),
            ("rustlet", Some("termination_test")),
            ("rustlet_all", None),
            ("rustlet_isolation", None),
        ] {
            let mut args = vec![
                "test",
                name,
                "raspi-pico2",
                "--on=openocd",
                "--serial=COM3:115200",
                "--allow-destructive",
            ];
            if let Some(rustlet) = rustlet {
                args.push(rustlet);
            }
            if name == "gp_scp03" {
                args.push("--scp03=all");
            }
            assert!(matches!(
                invocation(&cli(&args).unwrap()).target,
                TargetOptions::OpenOcd(_)
            ));
        }
        assert!(cli(&["test", "gp_scp11b_install_load", "raspi-pico1"]).is_err());
        let pico2 = board_catalog()
            .iter()
            .find(|b| b.spec.env_name == "raspi-pico2")
            .unwrap();
        assert_eq!(pico2.support_level, BoardSupportLevel::KernelApdu);
    }

    #[test]
    fn kernel_diagnostics_accept_openocd_without_changing_the_scenario() {
        for name in [
            "kernel_t0",
            "kernel_timer",
            "kernel_null_byte",
            "kernel_stack_guard",
            "kernel_ram_nx",
            "kernel_crypto",
            "kernel_flash",
            "kernel_registry",
        ] {
            let args = [
                "test",
                name,
                "raspi-pico2",
                "--on",
                "openocd",
                "--serial",
                "COM3:115200",
                "--allow-destructive",
            ];
            let mode = cli(&args).unwrap();
            assert!(matches!(
                invocation(&mode).target,
                TargetOptions::OpenOcd(_)
            ));
            assert_eq!(TestCatalog::for_scenario(scenario(&mode)).name, name);
            assert!(cli(&args[..args.len() - 1])
                .unwrap_err()
                .to_string()
                .contains("--allow-destructive"));
            let mut unsupported = args.to_vec();
            unsupported.push("--check_stack");
            assert!(cli(&unsupported).is_err());
            assert!(catalog::help(Some(name)).contains("--serial ENDPOINT"));
        }
    }

    #[test]
    fn persistence_diagnostics_require_a_persistent_qemu_backend() {
        for name in ["kernel_flash", "kernel_registry"] {
            assert!(cli(&["test", name, "raspi-pico1", "--on", "qemu"]).is_ok());
            assert!(cli(&["test", name, "mps2-an385", "--on", "qemu"]).is_err());
        }
    }

    #[test]
    fn rustlet_defaults_and_common_options_are_order_independent() {
        assert!(matches!(cli(&["test", "rustlet", "crypto_test"]).unwrap(),
            Mode::Test(TestInvocation { scenario: Scenario::RustletSingle { board, rustlet, .. }, .. })
                if board == DEFAULT_BOARD && rustlet == "crypto_test"));
        assert!(matches!(cli(&["test", "rustlet", "--elf", "raspi-pico1",
            "--on", "qemu", "crypto_test", "--check_stack"]).unwrap(),
            Mode::Test(TestInvocation { scenario: Scenario::RustletSingle { board, check_stack: true, .. }, .. }) if board == "raspi-pico1"));
        assert!(cli(&["test", "rustlet"]).is_err());
        assert!(cli(&["test", "rustlet", "mps2-an385", "unknown"]).is_err());
    }

    #[test]
    fn aggregate_and_persistence_keep_their_board_defaults() {
        assert!(matches!(
            cli(&["test", "rustlet_all"]).unwrap(),
            Mode::Test(TestInvocation {
                scenario: Scenario::RustletAll {
                    board_filter: None,
                    ..
                },
                ..
            })
        ));
        assert!(matches!(cli(&["test", "gp_persistence"]).unwrap(),
            Mode::Test(TestInvocation { scenario: Scenario::GpPersistence { board }, .. }) if board == "raspi-pico1"));
    }

    #[test]
    fn scp03_requires_an_explicit_profile() {
        assert!(matches!(cli(&["test", "gp_scp03"]).unwrap(), Mode::Help(_)));
        for profile in ["s8", "s16", "all"] {
            assert!(matches!(
                cli(&[
                    "test",
                    "gp_scp03",
                    "mps2-an385",
                    "--scp03",
                    profile,
                    "--check_stack"
                ])
                .unwrap(),
                Mode::Test(TestInvocation {
                    scenario: Scenario::GpScp03 {
                        check_stack: true,
                        ..
                    },
                    ..
                })
            ));
            assert!(cli(&["test", "gp_scp03", profile, "mps2-an385"]).is_ok());
        }
    }

    #[test]
    fn bench_operands_do_not_swallow_common_options() {
        assert!(matches!(
            cli(&[
                "test",
                "kernel_crypto",
                "raspi-pico1",
                "--bench",
                "fill_random",
                "16",
                "--on=qemu",
                "--elf"
            ])
            .unwrap(),
            Mode::Test(TestInvocation {
                scenario: Scenario::KernelCrypto {
                    bench: Some(KernelCryptoBench::FillRandom { len: 16 }),
                    ..
                },
                ..
            })
        ));
        assert!(cli(&["test", "kernel_crypto", "--bench=p256_ecdh", "--trace=none"]).is_ok());
        assert!(cli(&[
            "test",
            "kernel_crypto",
            "--bench=p256_generate_keypair",
            "extra"
        ])
        .is_err());
    }

    #[test]
    fn config_override_is_preserved_and_duplicates_are_rejected() {
        let (mode, config) = parse_cli(
            ["test", "kernel_ping", "--config", "custom.toml"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert!(matches!(
            mode,
            Mode::Test(TestInvocation {
                scenario: Scenario::KernelPing { .. },
                ..
            })
        ));
        assert_eq!(config, Some(PathBuf::from("custom.toml")));
        for args in [
            vec!["test", "kernel_ping", "--config="],
            vec!["test", "kernel_ping", "--config", "--elf"],
            vec!["test", "kernel_ping", "--config=a", "--config=b"],
        ] {
            assert!(parse_cli(args.into_iter().map(str::to_owned)).is_err());
        }
    }

    #[test]
    fn selected_manifest_matches_existing_runner_defaults() {
        let mode = cli(&["test", "kernel_ping"]).unwrap();
        assert!(config_for_scenario(scenario(&mode))
            .unwrap()
            .ends_with("configs/config_kernel_ping.toml"));
        let mode = cli(&["test", "rustlet", "minimal_valid_test"]).unwrap();
        assert!(config_for_scenario(scenario(&mode)).unwrap().is_file());
    }

    #[test]
    fn profile_config_changes_keep_stack_monitors() {
        for config in [
            "configs/config_scp03_test.toml",
            "configs/config_scp03_s16_test.toml",
        ] {
            let root = repo_root().unwrap();
            let mut ctx = TestContext::default().with_config(config);
            assert_eq!(
                ctx.build.effective_config(&root).unwrap(),
                root.join(config)
            );
            ctx.build.check_stack = true;
            let instrumented = ctx.build.effective_config(&root).unwrap();
            let before: toml::Value =
                toml::from_str(&fs::read_to_string(repo_root().unwrap().join(config)).unwrap())
                    .unwrap();
            let after: toml::Value =
                toml::from_str(&fs::read_to_string(&instrumented).unwrap()).unwrap();
            assert_eq!(before["secure_channel"], after["secure_channel"]);
            assert_eq!(before["root"], after["root"]);
            let modules = after["kernel-image"]["kernel-app-modules"]
                .as_array()
                .unwrap();
            for name in ["kernel-stack-monitor", "rustlet-stack-monitor"] {
                assert_eq!(
                    modules.iter().filter(|m| m.as_str() == Some(name)).count(),
                    1
                );
            }
            let twice = ctx
                .with_config(&instrumented)
                .build
                .effective_config(&root)
                .unwrap();
            let repeated: toml::Value =
                toml::from_str(&fs::read_to_string(twice).unwrap()).unwrap();
            assert_eq!(after, repeated);
        }
    }
}
