//! Hardware control only. APDUs use the same client and links as QEMU/apdu_tool.
//! The runner owns its OpenOCD process; it never attaches to an existing server.
use super::*;
use std::net::{TcpListener, TcpStream};
use std::process::Child;
use std::thread::JoinHandle;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(120);

/// Auto-select only an unambiguous USB serial link. Never open candidate ports
/// to probe them: opening a serial device can itself have hardware side effects.
pub(crate) fn detect_serial(
    test: &str,
    board: &str,
) -> Result<apdu_tool::LinkSpec, Box<dyn Error>> {
    let ports = apdu_tool::available_serial_ports().map_err(|error| {
        format!("cannot enumerate serial ports: {error}; specify --serial ENDPOINT")
    })?;
    let link = select_serial(&ports, test, board)?;
    if let apdu_tool::LinkSpec::SerialPort { path, baud } = &link {
        eprintln!("OpenOCD: auto-selected APDU serial link {path}:{baud} (override with --serial)");
    }
    Ok(link)
}

fn select_serial(
    ports: &[apdu_tool::SerialPortInfo],
    test: &str,
    board: &str,
) -> Result<apdu_tool::LinkSpec, Box<dyn Error>> {
    // macOS may expose tty.* and cu.* names for the same USB interface.
    // Prefer its callout name, without merging distinct USB interfaces.
    let mut ports: Vec<_> = ports
        .iter()
        .filter(|port| {
            let Some(suffix) = port.port_name.strip_prefix("/dev/tty.") else {
                return true;
            };
            !ports
                .iter()
                .any(|other| other.port_name == format!("/dev/cu.{suffix}"))
        })
        .collect();
    ports.sort_by(|a, b| a.port_name.cmp(&b.port_name));
    ports.dedup_by(|a, b| a.port_name == b.port_name);
    let usb: Vec<_> = ports
        .iter()
        .filter(|port| matches!(port.port_type, apdu_tool::SerialPortType::UsbPort(_)))
        .collect();
    if let [port] = usb.as_slice() {
        return Ok(apdu_tool::LinkSpec::SerialPort {
            path: port.port_name.clone(),
            baud: apdu_tool::DEFAULT_SERIAL_BAUD,
        });
    }
    let mut message = if usb.is_empty() {
        "No unambiguous USB APDU serial link found. Connect the UART bridge or specify --serial ENDPOINT.".to_owned()
    } else {
        "Multiple USB serial links found; specify --serial to choose the APDU UART bridge."
            .to_owned()
    };
    for port in &ports {
        let detail = match &port.port_type {
            apdu_tool::SerialPortType::UsbPort(info) => format!(
                "USB {:04x}:{:04x}, {}, serial={}",
                info.vid,
                info.pid,
                info.product.as_deref().unwrap_or("unknown product"),
                info.serial_number.as_deref().unwrap_or("unknown")
            ),
            other => format!("{other:?}"),
        };
        writeln!(message, "\n  {} ({detail})", port.port_name)?;
        // POSIX quoting keeps spaces and shell metacharacters literal.
        let endpoint =
            format!("{}:{}", port.port_name, apdu_tool::DEFAULT_SERIAL_BAUD).replace('\'', "'\\''");
        writeln!(message, "    cargo run test {test} {board} --on openocd --serial '{endpoint}' --allow-destructive")?;
    }
    if ports.is_empty() {
        message.push_str("\nNo serial ports reported by the operating system.");
    }
    message.push_str("\n--probe-serial selects the SWD adapter separately; --serial selects the APDU link. No device was opened.");
    Err(message.into())
}

#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub(crate) serial: apdu_tool::LinkSpec,
    pub(crate) probe_serial: Option<String>,
    pub(crate) allow_destructive: bool,
}

impl Options {
    pub(crate) fn validate(&self) -> Result<(), Box<dyn Error>> {
        if let Some(serial) = &self.probe_serial {
            if serial.is_empty() {
                return Err("empty --probe-serial".into());
            }
            tcl_word(serial)?;
        }
        Ok(())
    }
}

/// Uses vector catch, not a timeout or semihosting message, as fault evidence.
/// The CPU must stop at MemManage entry with an instruction-access violation
/// and the stacked PC pointing at the diagnostic BX LR in mutable RAM.
pub(crate) fn run_ram_nx(
    ctx: &TestContext,
    board: BoardSpec,
    image: &Path,
) -> Result<(), Box<dyn Error>> {
    run_fault_probe(ctx, board, image, false)
}

/// Requires an ARMv8-M stack-limit fault, not merely a halted processor.
pub(crate) fn run_stack_guard(
    ctx: &TestContext,
    board: BoardSpec,
    image: &Path,
) -> Result<(), Box<dyn Error>> {
    run_fault_probe(ctx, board, image, true)
}

fn run_fault_probe(
    ctx: &TestContext,
    board: BoardSpec,
    image: &Path,
    stack_guard: bool,
) -> Result<(), Box<dyn Error>> {
    let name = if stack_guard {
        "kernel-stack-guard"
    } else {
        "kernel-ram-nx"
    };
    let options = ctx.openocd().ok_or("missing hardware options")?;
    let layout = read_target_memory_layout(board)?;
    eprintln!(
        "DESTRUCTIVE test={name} board={} FLASH 0x{:08X}..0x{:08X}: erase, program and verify {}",
        board.env_name,
        layout.flash_base,
        layout.flash_base + layout.flash_size,
        image.display()
    );
    let mut target = Process::launch(board, options)?;
    let start = Instant::now();
    let result = (|| {
        let rpc = target.rpc.as_mut().ok_or("OpenOCD RPC unavailable")?;
        prepare(
            rpc,
            Some(image),
            layout.flash_base,
            layout.flash_size,
            options.allow_destructive,
        )?;
        if stack_guard {
            return rpc.execute(&stack_guard_observation_script(
                layout.flash_base,
                layout.ram_base,
            ));
        }
        rpc.execute(&ram_nx_observation_script(
            layout.ram_base,
            layout.ram_base + layout.ram_size - 16 * 1024,
        ))
    })();
    if let Some(rpc) = target.rpc.as_mut() {
        if stack_guard {
            let _ = rpc.execute("if {[info exists handler]} {catch {rbp $handler}}");
        }
        let _ = rpc.execute("cortex_m vector_catch none");
    }
    let logs = target.finish();
    if let Err(error) = result {
        return Err(format!(
            "test={name} board={} backend=openocd result=FAIL: {error}\n{logs}",
            board.env_name
        )
        .into());
    }
    if logs.starts_with("cleanup:") {
        return Err(logs.into());
    }
    eprintln!("{logs}");
    eprintln!(
        "test={name} board={} backend=openocd result=PASS elapsed={:.3}s",
        board.env_name,
        start.elapsed().as_secs_f64()
    );
    Ok(())
}

fn stack_guard_observation_script(flash_base: usize, ram_base: usize) -> String {
    // STKOF has no dedicated vector-catch bit. Stop before the UsageFault
    // handler needs stack space: this diagnostic deliberately exhausted MSP.
    let setup = format!(
        "set handler [expr {{[lindex [read_memory {} 32 1] 0] & ~1}}]\n\
         if {{$handler == 0}} {{ error \"missing UsageFault vector\" }}\n\
         bp $handler 2 hw\n",
        flash_base + 6 * 4,
    );
    setup + r#"
cortex_m vector_catch chk_err hard_err
arm semihosting enable
mww 0xE000ED28 0xffffffff
mww 0xE000ED2C 0xffffffff
resume
wait_halt 5000
rbp $handler
set cfsr [lindex [read_memory 0xE000ED28 32 1] 0]
set hfsr [lindex [read_memory 0xE000ED2C 32 1] 0]
set regs [get_reg -force {xpsr msp lr control r0 r2 pc}]
if {$cfsr != 0x100000 || $hfsr != 0 || ([dict get $regs xpsr] & 0x1ff) != 6} { error "expected UsageFault STKOF only: CFSR=$cfsr HFSR=$hfsr regs=$regs" }
if {([dict get $regs control] & 1) || ([dict get $regs lr] & 4)} { error "expected privileged kernel MSP fault: $regs" }
if {[dict get $regs pc] != $handler} { error "did not stop at UsageFault entry" }
echo [format "STACK-GUARD-EVIDENCE CFSR=%08x HFSR=%08x MSP=%08x" $cfsr $hfsr [dict get $regs msp]]
"# + &format!(
        "if {{[dict get $regs r2] != {ram_base}}} {{ error \"initial MSPLIM does not match kernel stack base: $regs\" }}\n"
    )
}

fn ram_nx_observation_script(ram_start: usize, ram_end: usize) -> String {
    format!(
        r#"
cortex_m vector_catch mm_err hard_err
arm semihosting enable
mww 0xE000ED28 0xffffffff
mww 0xE000ED2C 0xffffffff
resume
wait_halt 5000
set cfsr [lindex [read_memory 0xE000ED28 32 1] 0]
set hfsr [lindex [read_memory 0xE000ED2C 32 1] 0]
set regs [get_reg -force {{xpsr msp lr control}}]
if {{($cfsr != 1) || ($hfsr != 0) || (([dict get $regs xpsr] & 0x1ff) != 4)}} {{ error "expected MemManage IACCVIOL only: CFSR=$cfsr HFSR=$hfsr regs=$regs" }}
if {{([dict get $regs control] & 1) || ([dict get $regs lr] & 4) || !([dict get $regs lr] & 16)}} {{ error "expected privileged MSP basic exception frame: $regs" }}
set sp [dict get $regs msp]
if {{$sp < {ram_start} || $sp + 32 > {ram_end}}} {{ error "exception frame outside mutable RAM" }}
set pc [lindex [read_memory [expr {{$sp + 24}}] 32 1] 0]
set caller [lindex [read_memory [expr {{$sp + 20}}] 32 1] 0]
if {{$pc < {ram_start} || $pc + 2 > {ram_end} || ($pc & 1)}} {{ error "fault PC outside mutable RAM: $pc" }}
if {{[lindex [read_memory $pc 16 1] 0] != 0x4770}} {{ error "fault PC does not point at diagnostic BX LR" }}
echo [format "RAM-NX-EVIDENCE CFSR=%08x HFSR=%08x stacked_PC=%08x stacked_LR=%08x" $cfsr $hfsr $pc $caller]
"#
    )
}

/// Quote one Tcl word, without allowing substitutions or an RPC frame delimiter.
fn tcl_word(value: &str) -> Result<String, Box<dyn Error>> {
    if value.chars().any(char::is_control) {
        return Err("control characters are not allowed in OpenOCD arguments".into());
    }
    let mut quoted = String::from("\"");
    for c in value.chars() {
        if matches!(c, '\\' | '"' | '$' | '[' | ']' | '{' | '}') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    Ok(quoted)
}

/// Small test seam for ordering reset/program/connect/resume, not an APDU engine.
trait Control {
    fn execute(&mut self, script: &str) -> Result<(), Box<dyn Error>>;
}

struct Rpc(TcpStream);

impl Control for Rpc {
    fn execute(&mut self, script: &str) -> Result<(), Box<dyn Error>> {
        // catch preserves command failures: a nonempty Tcl string is not success.
        let request =
            format!("set code [catch {{{script}}} result]; format \"%d:%s\" $code $result\x1a");
        self.0.write_all(request.as_bytes())?;
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        let mut reply = Vec::new();
        loop {
            let mut byte = [0];
            self.0.read_exact(&mut byte)?;
            if byte[0] == 0x1a {
                break;
            }
            reply.push(byte[0]);
            if reply.len() > 1024 * 1024 || Instant::now() >= deadline {
                return Err("OpenOCD RPC reply exceeded time/size limit".into());
            }
        }
        let reply = String::from_utf8(reply)?;
        if !reply.starts_with("0:") {
            return Err(format!("OpenOCD command failed ({script}): {reply}").into());
        }
        Ok(())
    }
}

struct Process {
    child: Option<Child>,
    logs: Vec<JoinHandle<std::io::Result<Vec<u8>>>>,
    rpc: Option<Rpc>,
}

impl Process {
    fn launch(board: BoardSpec, options: &Options) -> Result<Self, Box<dyn Error>> {
        options.validate()?;
        let target = board_catalog()
            .iter()
            .find(|entry| entry.spec.env_name == board.env_name)
            .and_then(|entry| entry.openocd_target)
            .ok_or("board has no OpenOCD target script")?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let mut command = Command::new("openocd");
        command
            .arg("-c")
            .arg("bindto 127.0.0.1")
            .arg("-c")
            .arg(format!("tcl_port {port}"))
            .arg("-c")
            .arg("gdb_port disabled")
            .arg("-c")
            .arg("telnet_port disabled")
            .arg("-f")
            .arg("interface/cmsis-dap.cfg");
        if let Some(serial) = &options.probe_serial {
            command
                .arg("-c")
                .arg(format!("adapter serial {}", tcl_word(serial)?));
        }
        // Oxide SE boots core 0; core 1 is not a second test execution context.
        command
            .arg("-c")
            .arg("set USE_CORE 0")
            .arg("-f")
            .arg(target)
            .arg("-c")
            .arg("adapter speed 1000")
            .arg("-c")
            .arg("init")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let mut logs = Vec::new();
        if let Some(pipe) = child.stdout.take() {
            logs.push(target::drain(pipe));
        }
        if let Some(pipe) = child.stderr.take() {
            logs.push(target::drain(pipe));
        }
        let mut process = Self {
            child: Some(child),
            logs,
            rpc: None,
        };
        let result = (|| {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = process
                    .child
                    .as_mut()
                    .ok_or("OpenOCD stopped")?
                    .try_wait()?
                {
                    return Err(format!("OpenOCD exited during initialization: {status}").into());
                }
                match TcpStream::connect_timeout(
                    &format!("127.0.0.1:{port}").parse()?,
                    Duration::from_millis(100),
                ) {
                    Ok(stream) => {
                        stream.set_nodelay(true)?;
                        stream.set_read_timeout(Some(CONTROL_TIMEOUT))?;
                        stream.set_write_timeout(Some(CONTROL_TIMEOUT))?;
                        process.rpc = Some(Rpc(stream));
                        return Ok(());
                    }
                    Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                    Err(e) => return Err(Box::<dyn Error>::from(e)),
                }
            }
        })();
        if let Err(e) = result {
            let log = process.finish();
            return Err(format!("{e}\n{log}").into());
        }
        Ok(process)
    }

    fn finish(&mut self) -> String {
        let mut log = String::new();
        if let Some(mut rpc) = self.rpc.take() {
            let _ = rpc.0.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = rpc.0.set_write_timeout(Some(Duration::from_secs(2)));
            // Leave the tested firmware halted, including on ATR/APDU failure.
            if let Err(e) = rpc.execute("halt") {
                log.push_str(&format!("cleanup: {e}\n"));
            }
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        for thread in self.logs.drain(..) {
            if let Ok(Ok(bytes)) = thread.join() {
                log.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
        log
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

/// No image means reset-only. It must never erase or program persistent data.
fn prepare(
    control: &mut impl Control,
    image: Option<&Path>,
    flash_base: usize,
    flash_size: usize,
    authorized: bool,
) -> Result<(), Box<dyn Error>> {
    if image.is_some()
        && (!authorized || flash_size == 0 || flash_base.checked_add(flash_size).is_none())
    {
        return Err("initial hardware programming requires consent and a valid FLASH range".into());
    }
    if let Some(image) = image {
        let image = tcl_word(image.to_str().ok_or("non-UTF8 ELF path")?)?;
        control.execute("reset init")?;
        control.execute(&format!(
            "flash erase_address 0x{flash_base:X} 0x{flash_size:X}"
        ))?;
        control.execute(&format!("flash write_image {image}"))?;
        control.execute(&format!("verify_image {image}"))?;
    }
    control.execute("reset halt")
}

/// The link is opened and stale input drained while halted. No purge is allowed
/// after reset run: the first received bytes already belong to the new ATR.
fn connect_then_run<T>(
    control: &mut impl Control,
    connect: impl FnOnce() -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    let client = connect()?;
    control.execute("reset run")?;
    Ok(client)
}

pub(crate) struct Connection {
    target: Process,
}

impl Connection {
    pub(crate) fn finish(&mut self) -> Result<String, Box<dyn Error>> {
        let logs = self.target.finish();
        if logs.starts_with("cleanup:") {
            Err(logs.into())
        } else {
            Ok(logs)
        }
    }
}

pub(crate) fn connect(
    board: BoardSpec,
    options: &Options,
    image: Option<&Path>,
    trace: TraceMode,
    timeout: Duration,
) -> Result<(ApduClient, Connection), Box<dyn Error>> {
    let layout = read_target_memory_layout(board)?;
    if let Some(image) = image {
        std::eprintln!("DESTRUCTIVE board={} FLASH 0x{:08X}..0x{:08X}: erase firmware and persistent registry, program and verify {}",
            board.env_name, layout.flash_base, layout.flash_base + layout.flash_size, image.display());
    }
    let mut target = Process::launch(board, options)?;
    let client = (|| {
        let rpc = target.rpc.as_mut().ok_or("OpenOCD RPC unavailable")?;
        prepare(
            rpc,
            image,
            layout.flash_base,
            layout.flash_size,
            options.allow_destructive,
        )?;
        if trace == TraceMode::Jtag {
            rpc.execute("arm semihosting enable")?;
        }
        connect_then_run(rpc, || {
            let mut client = ApduClient::connect_link(&options.serial, timeout)?;
            client.discard_stale_input()?;
            Ok(client)
        })
    })()?;
    Ok((client, Connection { target }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn usb_port(path: &str) -> apdu_tool::SerialPortInfo {
        apdu_tool::SerialPortInfo {
            port_name: path.into(),
            port_type: apdu_tool::SerialPortType::UsbPort(apdu_tool::UsbPortInfo {
                vid: 0x2e8a,
                pid: 0x000c,
                serial_number: Some("test-probe".into()),
                manufacturer: None,
                product: Some("Debugprobe".into()),
            }),
        }
    }

    #[test]
    fn serial_detection_selects_unique_usb_not_bluetooth_or_console() {
        let ports = [
            usb_port("/dev/cu.usbmodem1102"),
            apdu_tool::SerialPortInfo {
                port_name: "/dev/cu.Bluetooth".into(),
                port_type: apdu_tool::SerialPortType::BluetoothPort,
            },
            apdu_tool::SerialPortInfo {
                port_name: "/dev/cu.debug-console".into(),
                port_type: apdu_tool::SerialPortType::Unknown,
            },
        ];
        assert_eq!(
            select_serial(&ports, "kernel_ping", "raspi-pico2").unwrap(),
            apdu_tool::LinkSpec::SerialPort {
                path: "/dev/cu.usbmodem1102".into(),
                baud: 115200,
            }
        );
    }

    #[test]
    fn serial_detection_prefers_callout_alias_without_merging_interfaces() {
        let ports = [
            usb_port("/dev/tty.usbmodem1"),
            usb_port("/dev/cu.usbmodem1"),
        ];
        assert_eq!(
            select_serial(&ports, "kernel_ping", "raspi-pico2").unwrap(),
            apdu_tool::LinkSpec::SerialPort {
                path: "/dev/cu.usbmodem1".into(),
                baud: 115200,
            }
        );
        let mut ports = ports.to_vec();
        ports.push(usb_port("/dev/cu.usbmodem2"));
        assert!(select_serial(&ports, "kernel_ping", "raspi-pico2").is_err());
    }

    #[test]
    fn serial_detection_lists_multiple_ports_and_exact_commands() {
        let ports = [usb_port("COM4"), usb_port("COM3")];
        let error = select_serial(&ports, "kernel_ping", "raspi-pico2")
            .unwrap_err()
            .to_string();
        assert!(error.contains("Multiple USB serial links"));
        for port in ["COM3", "COM4"] {
            assert!(error.contains(&format!("cargo run test kernel_ping raspi-pico2 --on openocd --serial '{port}:115200' --allow-destructive")));
        }
        assert!(error.contains("USB 2e8a:000c"));
        let error = select_serial(&ports, "rustlet", "raspi-pico1 minimal_valid_test")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("cargo run test rustlet raspi-pico1 minimal_valid_test --on openocd")
        );
    }

    #[test]
    fn serial_detection_does_not_guess_unknown_ports_or_missing_devices() {
        for ports in [
            vec![],
            vec![apdu_tool::SerialPortInfo {
                port_name: "/dev/ttyS0".into(),
                port_type: apdu_tool::SerialPortType::Unknown,
            }],
        ] {
            let error = select_serial(&ports, "kernel_ping", "raspi-pico2")
                .unwrap_err()
                .to_string();
            assert!(error.contains("specify --serial"));
            assert!(error.contains("No device was opened"));
        }
    }

    #[derive(Default)]
    struct Fake {
        calls: Rc<RefCell<Vec<String>>>,
        fail: Option<&'static str>,
    }
    impl Control for Fake {
        fn execute(&mut self, command: &str) -> Result<(), Box<dyn Error>> {
            self.calls.borrow_mut().push(command.to_owned());
            if self.fail.is_some_and(|word| command.starts_with(word)) {
                Err("injected debugger failure".into())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn initial_boot_verifies_then_connects_before_releasing_reset() {
        let mut control = Fake::default();
        prepare(
            &mut control,
            Some(Path::new("kernel.elf")),
            0x10000000,
            0x200000,
            true,
        )
        .unwrap();
        let calls = control.calls.clone();
        connect_then_run(&mut control, || {
            calls.borrow_mut().push("serial open + drain".into());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            &*control.calls.borrow(),
            &[
                "reset init",
                "flash erase_address 0x10000000 0x200000",
                "flash write_image \"kernel.elf\"",
                "verify_image \"kernel.elf\"",
                "reset halt",
                "serial open + drain",
                "reset run",
            ]
        );
    }

    #[test]
    fn reset_only_never_erases_or_programs_flash() {
        let mut control = Fake::default();
        prepare(&mut control, None, 0x10000000, 0x200000, false).unwrap();
        connect_then_run(&mut control, || Ok(())).unwrap();
        assert_eq!(&*control.calls.borrow(), &["reset halt", "reset run"]);
    }

    #[test]
    fn missing_consent_does_not_even_reset_the_device() {
        let mut control = Fake::default();
        assert!(prepare(
            &mut control,
            Some(Path::new("kernel.elf")),
            0x10000000,
            0x200000,
            false
        )
        .is_err());
        assert!(control.calls.borrow().is_empty());
    }

    #[test]
    fn failed_serial_connection_does_not_resume() {
        let mut control = Fake::default();
        let result: Result<(), _> =
            connect_then_run(&mut control, || Err("serial unavailable".into()));
        assert!(result.is_err());
        assert!(control.calls.borrow().is_empty());
    }

    #[test]
    fn failed_write_or_verify_does_not_proceed_to_reset() {
        for fail in ["flash erase", "flash write", "verify_image"] {
            let mut control = Fake {
                fail: Some(fail),
                ..Fake::default()
            };
            assert!(prepare(
                &mut control,
                Some(Path::new("kernel.elf")),
                0x10000000,
                0x200000,
                true
            )
            .is_err());
            assert!(!control
                .calls
                .borrow()
                .iter()
                .any(|c| c == "reset halt" || c == "reset run"));
        }
    }

    #[test]
    fn tcl_paths_are_words_not_executable_scripts() {
        assert_eq!(
            tcl_word("a b;$[cmd]{x}\\\"").unwrap(),
            "\"a b;\\$\\[cmd\\]\\{x\\}\\\\\\\"\""
        );
        for value in ["bad\x1a", "bad\n", "bad\0"] {
            assert!(tcl_word(value).is_err());
        }
    }

    #[test]
    fn rpc_uses_delimiter_and_propagates_tcl_errors() {
        for response in ["0:done\x1a", "1:erase failed\x1a"] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let addr = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                loop {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    if byte[0] == 0x1a {
                        break;
                    }
                    request.push(byte[0]);
                }
                assert!(String::from_utf8(request)
                    .unwrap()
                    .contains("catch {reset halt}"));
                stream.write_all(response.as_bytes()).unwrap();
            });
            let mut rpc = Rpc(TcpStream::connect(addr).unwrap());
            assert_eq!(
                rpc.execute("reset halt").is_ok(),
                response.starts_with("0:")
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn teardown_halts_then_reaps_the_owned_process_and_is_idempotent() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut b = [0];
                stream.read_exact(&mut b).unwrap();
                if b[0] == 0x1a {
                    break;
                }
                request.push(b[0]);
            }
            assert!(String::from_utf8(request).unwrap().contains("catch {halt}"));
            stream.write_all(b"0:\x1a").unwrap();
        });
        let mut target = Process {
            child: Some(Command::new("sleep").arg("30").spawn().unwrap()),
            logs: Vec::new(),
            rpc: Some(Rpc(TcpStream::connect(addr).unwrap())),
        };
        assert_eq!(target.finish(), "");
        assert!(target.child.is_none());
        assert!(target.rpc.is_none());
        assert_eq!(target.finish(), "");
        server.join().unwrap();
    }

    #[test]
    fn hardware_configuration_does_not_change_derived_builds_to_qemu() {
        let ctx = TestContext {
            target: TargetOptions::OpenOcd(Options {
                serial: apdu_tool::default_link_spec(),
                probe_serial: None,
                allow_destructive: true,
            }),
            ..TestContext::default()
        };
        assert_eq!(ctx.with_config("config.toml").execution_env(), "hardware");
        assert_eq!(TestContext::default().execution_env(), "qemu");
        let ctx = ctx.with_config("configs/config_kernel_ping.toml");
        let env = BuildManifestEnv::resolve(
            &ctx.build,
            &repo_root().unwrap(),
            "raspi-pico1",
            ctx.execution_env(),
        )
        .unwrap();
        assert_eq!(env.get("OXIDE_SE_EXECUTION_ENV"), "hardware");
        assert_eq!(env.get("OXIDE_SE_TRACE"), "none");
    }

    #[test]
    fn shared_transport_discards_old_bytes_but_keeps_atr_emitted_at_resume() {
        let ctx = TestContext::default().with_config("configs/config_kernel_ping.toml");
        let mut atr = ATR_PREFIX.to_vec();
        atr.push(ATR_OXIDE_SE_COMPACT_TLV_HEADER);
        atr.extend_from_slice(&ATR_OXIDE_SE_MARKER);
        atr.push(ATR_OXIDE_SE_VERSION);
        atr.push(expected_atr_capability_byte(&ctx.build).unwrap());
        atr.extend_from_slice(&ATR_CARD_CAPABILITIES_COMPACT_TLV);
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (resumed, wait_resume) = std::sync::mpsc::channel();
        let (stale_sent, wait_stale) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream.write_all(b"old boot bytes").unwrap();
            stale_sent.send(()).unwrap();
            wait_resume.recv_timeout(Duration::from_secs(2)).unwrap();
            stream.write_all(&atr).unwrap();
            let mut header = [0; 5];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header, [0; 5]);
            stream.write_all(&[0x60, 0x90, 0x00]).unwrap();
        });
        struct Resume(std::sync::mpsc::Sender<()>);
        impl Control for Resume {
            fn execute(&mut self, script: &str) -> Result<(), Box<dyn Error>> {
                assert_eq!(script, "reset run");
                self.0.send(())?;
                Ok(())
            }
        }
        let link = apdu_tool::LinkSpec::Tcp {
            host: "127.0.0.1".into(),
            port,
        };
        let mut client = connect_then_run(&mut Resume(resumed), || {
            let mut client = ApduClient::connect_link(&link, Duration::from_secs(2))?;
            wait_stale.recv_timeout(Duration::from_secs(2))?;
            client.discard_stale_input()?;
            Ok(client)
        })
        .unwrap();
        read_expected_atr(&ctx.build, &mut client, "hardware-mock").unwrap();
        expect_status(
            client
                .exchange(&CommandBuilder::process_no_data(0))
                .unwrap(),
            (0x90, 0),
            "post-ATR APDU",
        )
        .unwrap();
        server.join().unwrap();
    }
}
