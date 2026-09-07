//! Common CLI parsing and capability validation.
use super::*;

/// Parsed once, before any build or target-side operation is allowed.
pub(crate) struct TestOptions {
    pub(crate) board: Option<String>,
    pub(crate) image_format: LayoutImageFormat,
    pub(crate) check_stack: bool,
    pub(crate) scp03: Option<HostScp03Selection>,
    pub(crate) rustlet: Option<String>,
    pub(crate) bench: Option<KernelCryptoBench>,
}

#[derive(Clone, Debug)]
pub(crate) struct TestInvocation {
    pub(crate) scenario: Scenario,
    pub(crate) target: TargetOptions,
    pub(crate) trace: TraceMode,
    pub(crate) without_rustlets: bool,
    pub(crate) update_stack_baseline: bool,
}

impl TestOptions {
    pub(crate) fn board(&self) -> String {
        self.board
            .clone()
            .unwrap_or_else(|| DEFAULT_BOARD.to_owned())
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), Box<dyn Error>> {
    if slot.is_some() {
        return Err(format!("duplicate or conflicting {option} option").into());
    }
    *slot = Some(value);
    Ok(())
}

/// Validate capabilities and consent before building or touching a target.
pub(crate) fn parse(args: Vec<String>) -> Result<Mode, Box<dyn Error>> {
    let mut args = args.into_iter();
    let Some(name) = args.next() else {
        return Ok(Mode::Help(Some("test".into())));
    };
    if matches!(name.as_str(), "--help" | "-h") {
        return Ok(Mode::Help(Some("test".into())));
    }
    let test = TestCatalog::find(&name)
        .ok_or_else(|| format!("unknown test: {name}; run cargo run test --help"))?;
    let args: Vec<_> = args.collect();
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Ok(Mode::Help(Some(format!("test {name}"))));
    }

    let mut backend = None;
    let mut serial = None;
    let mut probe_serial = None;
    let mut allow_destructive = None;
    let mut image = None;
    let mut stack = None;
    let mut without_rustlets = None;
    let mut trace = None;
    let mut scp03 = None;
    let mut bench_op = None;
    let mut positions = Vec::new();
    let mut bench_args = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--serial" => {
                let value = args.next().ok_or("--serial requires an endpoint")?;
                set_once(&mut serial, apdu_tool::parse_link_spec(&value)?, "--serial")?;
            }
            "--probe-serial" => {
                set_once(
                    &mut probe_serial,
                    args.next()
                        .ok_or("--probe-serial requires an adapter serial number")?,
                    "--probe-serial",
                )?;
            }
            "--allow-destructive" => set_once(&mut allow_destructive, true, "--allow-destructive")?,
            "--without-rustlets" if test.capabilities.without_rustlets => {
                set_once(&mut without_rustlets, true, "--without-rustlets")?;
            }
            value if value.starts_with("--serial=") => {
                set_once(
                    &mut serial,
                    apdu_tool::parse_link_spec(&value["--serial=".len()..])?,
                    "--serial",
                )?;
            }
            value if value.starts_with("--probe-serial=") => {
                set_once(
                    &mut probe_serial,
                    value["--probe-serial=".len()..].to_owned(),
                    "--probe-serial",
                )?;
            }
            "--on" | "-on" => {
                let value = args.next().ok_or("--on requires qemu or openocd")?;
                set_once(&mut backend, value, "--on")?;
            }
            "--elf" => set_once(&mut image, LayoutImageFormat::Elf, "image format")?,
            "--fae" => set_once(&mut image, LayoutImageFormat::Fae, "image format")?,
            "--check_stack" => set_once(&mut stack, false, "stack check")?,
            "--update_stack_baseline" => set_once(&mut stack, true, "stack check")?,
            "--trace" => {
                let value = args.next().ok_or("--trace requires a mode")?;
                set_once(&mut trace, TraceMode::parse(&value)?, "--trace")?;
            }
            "--scp03" if test.arguments == Arguments::Scp03 => {
                let value = args.next().ok_or("--scp03 requires s8, s16 or all")?;
                set_once(&mut scp03, HostScp03Selection::from_cli(&value)?, "--scp03")?;
            }
            "--bench" if test.arguments == Arguments::Crypto => {
                let value = args.next().ok_or("--bench requires an operation")?;
                set_once(&mut bench_op, value, "--bench")?;
            }
            value if value.starts_with("--on=") => {
                set_once(&mut backend, value["--on=".len()..].to_owned(), "--on")?;
            }
            value if value.starts_with("--trace=") => {
                set_once(
                    &mut trace,
                    TraceMode::parse(&value["--trace=".len()..])?,
                    "--trace",
                )?;
            }
            value if value.starts_with("--scp03=") && test.arguments == Arguments::Scp03 => {
                set_once(
                    &mut scp03,
                    HostScp03Selection::from_cli(&value["--scp03=".len()..])?,
                    "--scp03",
                )?;
            }
            value if value.starts_with("--bench=") && test.arguments == Arguments::Crypto => {
                set_once(
                    &mut bench_op,
                    value["--bench=".len()..].to_owned(),
                    "--bench",
                )?;
            }
            value if value.starts_with('-') => {
                return Err(format!("unsupported option for {name}: {value}").into());
            }
            value if bench_op.is_some() => bench_args.push(value.to_owned()),
            value
                if test.arguments == Arguments::Scp03
                    && HostScp03Selection::is_cli_value(value) =>
            {
                set_once(&mut scp03, HostScp03Selection::from_cli(value)?, "--scp03")?;
            }
            _ => positions.push(arg),
        }
    }
    let image_format = image.unwrap_or(LayoutImageFormat::Elf);
    if without_rustlets.is_some() && stack.is_some() {
        return Err("--without-rustlets has a different workload; do not compare/update full-scenario stack baselines".into());
    }
    if image_format == LayoutImageFormat::Fae && !test.capabilities.fae {
        return Err(format!("{name} currently supports only --elf").into());
    }
    if stack.is_some() && !test.capabilities.stack_observer {
        return Err(
            format!("{name} does not support --check_stack/--update_stack_baseline").into(),
        );
    }
    let mut board = None;
    if positions.first().is_some_and(|value| {
        board_catalog()
            .iter()
            .any(|entry| entry.spec.env_name == value)
    }) {
        board = Some(positions.remove(0));
    }
    let rustlet = if test.arguments == Arguments::Rustlet && positions.len() == 1 {
        Some(single_rustlet_spec(&positions.remove(0))?.name.to_owned())
    } else {
        None
    };
    if !positions.is_empty() {
        return Err(format!(
            "unknown board or unexpected argument for {name}: {}",
            positions.join(" ")
        )
        .into());
    }
    if test.arguments == Arguments::Rustlet && rustlet.is_none() {
        return Err("missing Rustlet name; run cargo run test rustlet --help".into());
    }
    let default_backend = board
        .as_deref()
        .and_then(|name| board_catalog().iter().find(|e| e.spec.env_name == name))
        .map_or("qemu", |entry| {
            if entry.qemu_support {
                "qemu"
            } else {
                "openocd"
            }
        });
    let hardware = match backend.as_deref().unwrap_or(default_backend) {
        "qemu" => false,
        "openocd" => true,
        other => return Err(format!("unknown backend: {other}; expected qemu or openocd").into()),
    };
    let openocd = if hardware {
        let name_board = board
            .as_deref()
            .ok_or("--on openocd requires an explicit board; no hardware is selected implicitly")?;
        let entry = board_catalog()
            .iter()
            .find(|e| e.spec.env_name == name_board)
            .unwrap();
        if entry.openocd_target.is_none() {
            return Err(format!(
                "OpenOCD is unavailable on {name_board}: no target script in BoardCatalog"
            )
            .into());
        }
        if test.capabilities.target == TargetConstraint::Pico2HardwareFault
            && name_board != "raspi-pico2"
        {
            return Err("OpenOCD kernel fault observation is available only on raspi-pico2".into());
        }
        if entry.support_level < test.support {
            eprintln!(
                "OpenOCD: running {name} above the validated {} level of {name_board}; this is a bring-up attempt and does not promote board support",
                entry.support_level.label()
            );
        }
        if image_format != LayoutImageFormat::Elf {
            return Err("OpenOCD currently requires ELF".into());
        }
        if trace == Some(TraceMode::Semihosting) {
            return Err(
                "hardware uses --trace=none or --trace=jtag (Pico1 only), not --trace=semihosting"
                    .into(),
            );
        }
        if allow_destructive != Some(true) {
            let layout = read_target_memory_layout(entry.spec)?;
            return Err(format!("OpenOCD will erase FLASH 0x{:08X}..0x{:08X}, including persistent registry data. Add --allow-destructive to authorize this test; no device was touched.",
                layout.flash_base, layout.flash_base + layout.flash_size).into());
        }
        let serial = match serial {
            Some(serial) => serial,
            None => {
                let target = match rustlet.as_deref() {
                    Some(rustlet) => format!("{name_board} {rustlet}"),
                    None => name_board.to_owned(),
                };
                openocd::detect_serial(&name, &target)?
            }
        };
        let options = openocd::Options {
            serial,
            probe_serial,
            allow_destructive: true,
        };
        options.validate()?;
        Some(options)
    } else {
        if serial.is_some() || probe_serial.is_some() || allow_destructive.is_some() {
            return Err(
                "--serial, --probe-serial and --allow-destructive require the OpenOCD backend"
                    .into(),
            );
        }
        None
    };
    if board.is_none() {
        board = match test.boards {
            Boards::Default => Some(DEFAULT_BOARD.to_owned()),
            Boards::PicoPersistence => Some("raspi-pico1".to_owned()),
            Boards::AllRustlet => None,
        };
    }
    let selected_boards: Vec<_> = match board.as_deref() {
        Some(board) => vec![board],
        None => rustlet_qemu_board_names(),
    };
    for board in selected_boards {
        if test.capabilities.target == TargetConstraint::PersistentFlash
            && !hardware
            && board != "raspi-pico1"
        {
            return Err(format!("{} requires raspi-pico1 under QEMU (persistent flash-file), or --on openocd with a flash-capable board", test.name).into());
        }
        let entry = board_catalog()
            .iter()
            .find(|entry| entry.spec.env_name == board)
            .ok_or_else(|| format!("unknown board: {board}"))?;
        if !hardware && (!entry.qemu_support || entry.support_level < test.support) {
            return Err(format!(
                "{name} is unavailable on {board} under QEMU (board support: {})",
                entry.support_level.label()
            )
            .into());
        }
        if test.boards == Boards::PicoPersistence && !hardware && board != "raspi-pico1" {
            return Err(format!("{name} requires raspi-pico1 persistent QEMU flash").into());
        }
        if matches!(trace, Some(TraceMode::Jtag)) && board != "raspi-pico1" {
            return Err(format!("--trace=jtag is unsupported on {board}").into());
        }
    }
    let bench = bench_op
        .map(|op| KernelCryptoBench::parse(&op, &bench_args))
        .transpose()?;
    if test.arguments == Arguments::Scp03 && scp03.is_none() {
        return Ok(Mode::Help(Some(format!("test {name}"))));
    }
    let scenario = (test.mode)(TestOptions {
        board,
        image_format,
        check_stack: stack.is_some(),
        scp03,
        rustlet,
        bench,
    });
    Ok(Mode::Test(TestInvocation {
        scenario,
        target: openocd.map_or(TargetOptions::Qemu, TargetOptions::OpenOcd),
        trace: trace.unwrap_or(TraceMode::None),
        without_rustlets: without_rustlets == Some(true),
        update_stack_baseline: stack == Some(true),
    }))
}
