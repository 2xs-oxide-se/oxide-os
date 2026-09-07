//! Builds images and owns target sessions, synchronization and error reporting.
//! Protocol assertions live in scenarios and are independent of the backend.
use super::*;
use std::process::Child;
use std::thread::JoinHandle;

/// Every successful spawn immediately acquires an owner. Drop also handles
/// connection failures, early returns and unwinding, not just successful APDUs.
struct QemuProcess {
    child: Option<Child>,
    stdout: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    socket: PathBuf,
}

pub(super) fn drain(mut pipe: impl Read + Send + 'static) -> JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

impl QemuProcess {
    fn new(mut child: Child, socket: PathBuf) -> Self {
        let stdout = child.stdout.take().map(drain);
        let stderr = child.stderr.take().map(drain);
        Self {
            child: Some(child),
            stdout,
            stderr,
            socket,
        }
    }

    fn connect(&mut self, timeout: Duration) -> Result<ApduClient, Box<dyn Error>> {
        self.connect_until(timeout, Instant::now() + TARGET_CONNECTION_TIMEOUT)
    }

    fn connect_until(
        &mut self,
        timeout: Duration,
        deadline: Instant,
    ) -> Result<ApduClient, Box<dyn Error>> {
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .ok_or("QEMU already stopped")?
                .try_wait()?
            {
                return Err(format!("QEMU exited before serial connection: {status}").into());
            }
            if self.socket.exists() {
                match ApduClient::connect_with_timeout(&self.socket, timeout) {
                    Ok(client) => return Ok(client),
                    Err(err) if Instant::now() >= deadline => return Err(err),
                    Err(_) => {}
                }
            }
            if Instant::now() >= deadline {
                return Err(
                    format!("serial connection timed out: {}", self.socket.display()).into(),
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn finish(&mut self) -> Result<(String, String), Box<dyn Error>> {
        let mut wait_error = None;
        if let Some(mut child) = self.child.take() {
            // Reap even if termination or process-status inspection fails.
            let _ = child.kill();
            if let Err(err) = child.wait() {
                wait_error = Some(err);
            }
        }
        let read = |thread: &mut Option<JoinHandle<std::io::Result<Vec<u8>>>>| -> String {
            match thread.take().map(|t| t.join()) {
                Some(Ok(Ok(bytes))) => String::from_utf8_lossy(&bytes).into_owned(),
                Some(_) => "<could not collect target output>".to_owned(),
                None => String::new(),
            }
        };
        let stdout = read(&mut self.stdout);
        let stderr = read(&mut self.stderr);
        match fs::remove_file(&self.socket) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        if let Some(err) = wait_error {
            return Err(err.into());
        }
        Ok((stdout, stderr))
    }
}

impl Drop for QemuProcess {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

fn failure(
    label: &str,
    board: BoardSpec,
    backend: &str,
    stage: &str,
    start: Instant,
    error: impl std::fmt::Display,
    stdout: &str,
    stderr: &str,
) -> Box<dyn Error> {
    format!("test={label} board={} backend={backend} stage={stage} elapsed={:.3}s: {error}\nbackend stdout:\n{stdout}\nbackend stderr:\n{stderr}",
        board.env_name, start.elapsed().as_secs_f64()).into()
}

/// Build once for an effective image, then always start a fresh target session.
pub(crate) fn run_apdu<T>(
    ctx: &TestContext,
    board: BoardSpec,
    image_format: LayoutImageFormat,
    label: &str,
    timeout: Duration,
    scenario: impl FnOnce(&mut ApduClient) -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    prepare_apdu_session(ctx, board, image_format, false)?.boot(label, timeout, scenario)
}

/// The backend boundary used by every APDU scenario. Implementations own
/// deployment details; scenarios only request a boot and exchange APDUs.
trait DeploymentBackend {
    fn name(&self) -> &'static str;
    fn board(&self) -> BoardSpec;
    fn connect(
        &mut self,
        image: Option<&Path>,
        trace: TraceMode,
        timeout: Duration,
    ) -> Result<ConnectedTarget, Box<dyn Error>>;
}

struct QemuBackend {
    board: BoardSpec,
    flash: Option<FlashFile>,
}

impl DeploymentBackend for QemuBackend {
    fn name(&self) -> &'static str {
        "qemu"
    }

    fn board(&self) -> BoardSpec {
        self.board
    }

    fn connect(
        &mut self,
        image: Option<&Path>,
        _trace: TraceMode,
        timeout: Duration,
    ) -> Result<ConnectedTarget, Box<dyn Error>> {
        let socket = qemu_serial_socket_path(self.board.env_name)?;
        let child = spawn_qemu_serial_with_optional_kernel(
            self.board,
            image,
            &socket,
            self.flash.as_deref(),
        )?;
        let mut owner = QemuProcess::new(child, socket);
        let client = owner.connect(timeout)?;
        Ok(ConnectedTarget {
            client,
            owner: ConnectionOwner::Qemu(owner),
        })
    }
}

struct OpenOcdBackend {
    board: BoardSpec,
    options: openocd::Options,
}

impl DeploymentBackend for OpenOcdBackend {
    fn name(&self) -> &'static str {
        "openocd"
    }

    fn board(&self) -> BoardSpec {
        self.board
    }

    fn connect(
        &mut self,
        image: Option<&Path>,
        trace: TraceMode,
        timeout: Duration,
    ) -> Result<ConnectedTarget, Box<dyn Error>> {
        let (client, owner) = openocd::connect(self.board, &self.options, image, trace, timeout)?;
        Ok(ConnectedTarget {
            client,
            owner: ConnectionOwner::OpenOcd(owner),
        })
    }
}

enum ConnectionOwner {
    Qemu(QemuProcess),
    OpenOcd(openocd::Connection),
}

struct ConnectedTarget {
    client: ApduClient,
    owner: ConnectionOwner,
}

impl ConnectedTarget {
    fn check_alive(&mut self) -> Result<(), Box<dyn Error>> {
        if let ConnectionOwner::Qemu(target) = &mut self.owner {
            if let Some(status) = target.child.as_mut().ok_or("QEMU stopped")?.try_wait()? {
                return Err(format!("target exited during the scenario: {status}").into());
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(String, String), Box<dyn Error>> {
        match &mut self.owner {
            ConnectionOwner::Qemu(target) => target.finish(),
            ConnectionOwner::OpenOcd(target) => Ok((String::new(), target.finish()?)),
        }
    }
}

/// A built image and its selected deployment backend. The first boot deploys
/// the image; subsequent boots preserve target flash and only reset the target.
pub(crate) struct TargetSession<'a> {
    build: &'a BuildContext,
    image: PreparedImage,
    deployed: bool,
    backend: Box<dyn DeploymentBackend>,
    observer: Option<std::rc::Rc<std::cell::RefCell<StackObserver>>>,
}

impl TargetSession<'_> {
    pub(crate) fn boot<T>(
        &mut self,
        label: &str,
        timeout: Duration,
        scenario: impl FnOnce(&mut ApduClient) -> Result<T, Box<dyn Error>>,
    ) -> Result<T, Box<dyn Error>> {
        let start = Instant::now();
        let backend = self.backend.name();
        let board = self.backend.board();
        let image = (!self.deployed).then_some(self.image.path());
        let mut stage = "deploy/connect";
        let mut target = self
            .backend
            .connect(image, self.build.trace, timeout)
            .map_err(|err| failure(label, board, backend, stage, start, err, "", ""))?;
        target.client.set_observer(self.observer.clone());
        let result: Result<T, Box<dyn Error>> = (|| {
            stage = "ATR";
            read_expected_atr(self.build, &mut target.client, label)?;
            stage = "APDU";
            let value = scenario(&mut target.client)?;
            target.check_alive()?;
            Ok(value)
        })();
        let diagnostics = target.finish();
        self.deployed = true;
        match (result, diagnostics) {
            (Ok(value), Ok(_)) => {
                std::eprintln!(
                    "test={label} board={} backend={backend} image_format={} result=PASS elapsed={:.3}s",
                    board.env_name,
                    self.image.format.name_lower(),
                    start.elapsed().as_secs_f64()
                );
                Ok(value)
            }
            (Err(err), Ok((stdout, stderr))) => Err(failure(
                label, board, backend, stage, start, err, &stdout, &stderr,
            )),
            (Ok(_), Err(err)) => Err(failure(
                label, board, backend, "cleanup", start, err, "", "",
            )),
            (Err(primary), Err(cleanup)) => Err(failure(
                label,
                board,
                backend,
                stage,
                start,
                format!("{primary}; additionally cleanup failed: {cleanup}"),
                "",
                "",
            )),
        }
    }

    pub(crate) fn reboot<T>(
        &mut self,
        label: &str,
        timeout: Duration,
        scenario: impl FnOnce(&mut ApduClient) -> Result<T, Box<dyn Error>>,
    ) -> Result<T, Box<dyn Error>> {
        if !self.deployed {
            return Err("cannot reboot a target before its initial boot".into());
        }
        self.boot(label, timeout, scenario)
    }
}

/// Build once, then construct the backend selected by the parsed CLI options.
pub(crate) fn prepare_apdu_session(
    ctx: &TestContext,
    board: BoardSpec,
    image_format: LayoutImageFormat,
    persistent: bool,
) -> Result<TargetSession<'_>, Box<dyn Error>> {
    let start = Instant::now();
    let image = prepare_image(ctx, board, image_format).map_err(|err| -> Box<dyn Error> {
        format!(
            "board={} backend={} stage=build elapsed={:.3}s: {err}",
            board.env_name,
            ctx.execution_env(),
            start.elapsed().as_secs_f64()
        )
        .into()
    })?;
    let backend: Box<dyn DeploymentBackend> = match &ctx.target {
        TargetOptions::OpenOcd(options) => Box::new(OpenOcdBackend {
            board,
            options: options.clone(),
        }),
        TargetOptions::Qemu => {
            let flash = if persistent {
                let layout = read_target_memory_layout(board)?;
                Some(FlashFile::erased(board, layout.flash_size)?)
            } else {
                None
            };
            Box::new(QemuBackend { board, flash })
        }
    };
    Ok(TargetSession {
        build: &ctx.build,
        image,
        deployed: false,
        backend,
        observer: ctx.apdu_observer.clone(),
    })
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedImage {
    path: PathBuf,
    pub(crate) format: LayoutImageFormat,
}

impl PreparedImage {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for PreparedImage {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

pub(crate) fn prepare_image(
    ctx: &TestContext,
    board: BoardSpec,
    image_format: LayoutImageFormat,
) -> Result<PreparedImage, Box<dyn Error>> {
    // Include the path as well as content: relative payload paths can depend on it.
    let config = ctx.build.effective_config(&repo_root()?)?;
    let key = format!(
        "{}|{:?}|{:?}|{:?}|{}|{}|{}",
        board.env_name,
        image_format,
        ctx.build.trace,
        ctx.build.fault_test,
        ctx.execution_env(),
        config.display(),
        fs::read_to_string(&config)?
    );
    if let Some(path) = ctx.build.images.borrow().images.get(&key) {
        eprintln!("test image reuse: {}", path.display());
        return Ok(PreparedImage {
            path: path.clone(),
            format: image_format,
        });
    }
    // Payload discovery and build.rs must see the same reduced manifest.
    // Merely overriding build.rs would still compile the original Rustlets.
    let build_ctx = if ctx.build.without_rustlets {
        eprintln!(
            "test scope=kernel-scp without Rustlets; config={}",
            config.display()
        );
        BuildContext {
            without_rustlets: false,
            ..ctx.build.with_config(&config)
        }
    } else {
        ctx.build.clone()
    };
    build_firmware(
        &build_ctx,
        FirmwareKind::GpKernel,
        if image_format == LayoutImageFormat::Fae {
            Some(Packaging::Bootable(board))
        } else {
            None
        },
        board.env_name,
        ctx.execution_env(),
    )?;
    let built = match image_format {
        LayoutImageFormat::Elf => firmware_elf_path(FirmwareKind::GpKernel),
        LayoutImageFormat::Fae => firmware_image_path(FirmwareKind::GpKernel),
    }?;
    if !built.is_file() {
        return Err(format!("build completed without producing {}", built.display()).into());
    }
    Ok(PreparedImage {
        path: ctx.build.images.borrow_mut().remember(key, &built)?,
        format: image_format,
    })
}

/// Immutable image snapshots prevent a later profile build from overwriting an
/// earlier campaign image. Source/configuration inputs must stay unchanged during
/// one campaign, just as during one Cargo build. Nothing is reused across runs.
#[derive(Debug, Default)]
pub(crate) struct ImageCache {
    images: std::collections::BTreeMap<String, PathBuf>,
    directory: Option<PathBuf>,
}

impl ImageCache {
    fn remember(&mut self, key: String, built: &Path) -> Result<PathBuf, Box<dyn Error>> {
        if self.directory.is_none() {
            let base = qemu_serial_socket_path("images")?.with_extension("images");
            fs::create_dir(&base)?;
            self.directory = Some(base);
        }
        let path = self.directory.as_ref().unwrap().join(format!(
            "{}.{}",
            self.images.len(),
            built.extension().unwrap_or_default().to_string_lossy()
        ));
        fs::copy(built, &path)?;
        self.images.insert(key, path.clone());
        Ok(path)
    }
}

impl Drop for ImageCache {
    fn drop(&mut self) {
        if let Some(directory) = &self.directory {
            let _ = fs::remove_dir_all(directory);
        }
    }
}

/// A campaign owns its flash backing file across resets. Dropping the owner
/// removes only this invocation's file, including on an early assertion error.
struct FlashFile(PathBuf);

impl FlashFile {
    fn erased(board: BoardSpec, size: usize) -> Result<Self, Box<dyn Error>> {
        let path = qemu_serial_socket_path(board.env_name)?.with_extension("flash");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let owner = Self(path);
        let page = [0xff; 4096];
        for _ in 0..size / page.len() {
            file.write_all(&page)?;
        }
        file.write_all(&page[..size % page.len()])?;
        Ok(owner)
    }
}

impl std::ops::Deref for FlashFile {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for FlashFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Core diagnostics terminate through semihosting instead of an APDU response.
pub(crate) fn run_core<T>(
    ctx: &TestContext,
    board: BoardSpec,
    execution_env: &str,
    label: &str,
    scenario: impl FnOnce(Output) -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    let build_ctx = BuildContext {
        trace: TraceMode::Semihosting,
        ..ctx.build.clone()
    };
    let start = Instant::now();
    build_firmware(
        &build_ctx,
        FirmwareKind::CoreTest,
        None,
        board.env_name,
        execution_env,
    )
    .map_err(|e| failure(label, board, "qemu", "build", start, e, "", ""))?;
    let image = firmware_elf_path(FirmwareKind::CoreTest)?;
    let output = run_qemu_capture(board, &image)
        .map_err(|e| failure(label, board, "qemu", "capture", start, e, "", ""))?;
    let value = scenario(output)
        .map_err(|e| failure(label, board, "qemu", "assertion", start, e, "", ""))?;
    std::eprintln!(
        "test={label} board={} backend=qemu result=PASS elapsed={:.3}s",
        board.env_name,
        start.elapsed().as_secs_f64()
    );
    Ok(value)
}

fn run_qemu_capture(board: BoardSpec, image: &Path) -> Result<Output, Box<dyn Error>> {
    let mut command = qemu_system_arm_command(board)?;
    command.arg("-machine").arg(board.machine);
    add_qemu_headless_display_args(&mut command, board);
    command
        .arg("-monitor")
        .arg("none")
        .arg("-serial")
        .arg("none");
    command
        .arg("-semihosting-config")
        .arg("enable=on,target=native");
    let start = Instant::now();
    let child = command
        .arg("-kernel")
        .arg(image)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut target = QemuProcess::new(child, qemu_serial_socket_path("capture")?);
    loop {
        if let Some(status) = target.child.as_mut().ok_or("QEMU stopped")?.try_wait()? {
            let (stdout, stderr) = target.finish()?;
            return Ok(Output {
                status,
                stdout: stdout.into_bytes(),
                stderr: stderr.into_bytes(),
            });
        }
        if start.elapsed() > QEMU_TEST_TIMEOUT {
            let (stdout, stderr) = target.finish()?;
            return Err(failure(
                "kernel-capture",
                board,
                "qemu",
                "completion",
                start,
                "target did not terminate",
                &stdout,
                &stderr,
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

pub(crate) fn spawn_qemu_serial_with_optional_kernel(
    board: BoardSpec,
    image: Option<&Path>,
    socket_path: &Path,
    flash_path: Option<&Path>,
) -> Result<std::process::Child, Box<dyn Error>> {
    Ok(serial_command(board, image, socket_path, flash_path)?
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?)
}

fn serial_command(
    board: BoardSpec,
    image: Option<&Path>,
    socket_path: &Path,
    flash_path: Option<&Path>,
) -> Result<Command, Box<dyn Error>> {
    let mut command = qemu_system_arm_command(board)?;
    let machine = if let Some(flash_path) = flash_path {
        format!("{},flash-file={}", board.machine, flash_path.display())
    } else {
        board.machine.to_owned()
    };
    command.arg("-machine").arg(machine);
    add_qemu_headless_display_args(&mut command, board);
    command.arg("-monitor").arg("none");
    if board.env_name == "raspi-pico1" {
        command
            .arg("-chardev")
            .arg(format!(
                "socket,id=serial0,path={},server=on,wait=on",
                socket_path.display()
            ))
            .arg("-serial")
            .arg("chardev:serial0");
    } else {
        command
            .arg("-serial")
            .arg(format!("unix:{},server=on,wait=on", socket_path.display()));
    }
    command
        .arg("-semihosting-config")
        .arg("enable=on,target=native");
    if let Some(image) = image {
        command.arg("-kernel").arg(image);
    }
    Ok(command)
}

pub(crate) fn add_qemu_headless_display_args(command: &mut Command, board: BoardSpec) {
    if board.env_name == "raspi-pico1" {
        command.arg("-display").arg("none");
    } else {
        command.arg("-nographic");
    }
}

pub(crate) fn qemu_system_arm_command(board: BoardSpec) -> Result<Command, Box<dyn Error>> {
    if board.env_name != "raspi-pico1" {
        return Ok(Command::new("qemu-system-arm"));
    }

    let bundled = repo_root()?.join("tooling/qemu-rp2040-pico/build/qemu-system-arm");
    if bundled.is_file() {
        return Ok(Command::new(bundled));
    }

    Ok(Command::new("qemu-system-arm"))
}

pub(crate) fn qemu_serial_socket_path(board: &str) -> Result<PathBuf, Box<dyn Error>> {
    static NEXT_SOCKET: AtomicUsize = AtomicUsize::new(0);
    let pid = std::process::id();
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    // macOS TMPDIR can exceed sockaddr_un.sun_path once the test name is added.
    // The Unix backend keeps short paths, unique to this process and session.
    Ok(PathBuf::from("/tmp").join(format!("oxide-se-{board}-{pid}-{sequence}.sock")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn sleeper(socket: PathBuf) -> QemuProcess {
        QemuProcess::new(
            Command::new("sleep")
                .arg("30")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
            socket,
        )
    }

    struct SocketBackend {
        board: BoardSpec,
        socket: PathBuf,
    }

    impl DeploymentBackend for SocketBackend {
        fn name(&self) -> &'static str {
            "test"
        }

        fn board(&self) -> BoardSpec {
            self.board
        }

        fn connect(
            &mut self,
            _image: Option<&Path>,
            _trace: TraceMode,
            timeout: Duration,
        ) -> Result<ConnectedTarget, Box<dyn Error>> {
            let mut owner = sleeper(self.socket.clone());
            let client = owner.connect(timeout)?;
            Ok(ConnectedTarget {
                client,
                owner: ConnectionOwner::Qemu(owner),
            })
        }
    }

    fn socket_session<'a>(ctx: &'a TestContext, socket: PathBuf) -> TargetSession<'a> {
        let board = board_spec("mps2-an385").unwrap();
        TargetSession {
            build: &ctx.build,
            image: PreparedImage {
                path: PathBuf::from("unused-test-image.elf"),
                format: LayoutImageFormat::Elf,
            },
            deployed: false,
            backend: Box::new(SocketBackend { board, socket }),
            observer: ctx.apdu_observer.clone(),
        }
    }

    #[test]
    fn missing_socket_times_out_and_process_is_reaped() {
        let socket = qemu_serial_socket_path("missing").unwrap();
        let mut target = sleeper(socket.clone());
        let error = target
            .connect_until(
                Duration::from_millis(20),
                Instant::now() + Duration::from_millis(30),
            )
            .err()
            .unwrap();
        assert!(error.to_string().contains("timed out"));
        target.finish().unwrap();
        assert!(target.child.is_none());
        assert!(!socket.exists());
    }

    #[test]
    fn exited_target_is_detected_before_connection() {
        let socket = qemu_serial_socket_path("exited").unwrap();
        let child = Command::new("true")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut target = QemuProcess::new(child, socket);
        let error = target
            .connect_until(
                Duration::from_millis(20),
                Instant::now() + Duration::from_secs(2),
            )
            .err()
            .unwrap();
        assert!(error.to_string().contains("exited before serial"));
        target.finish().unwrap();
        assert!(target.child.is_none());
    }

    #[test]
    fn incorrect_atr_fails_before_scenario_and_removes_socket() {
        let socket = qemu_serial_socket_path("bad-atr").unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&[0x3b, 0x00]).unwrap();
        });
        let ctx = TestContext::default();
        let error = socket_session(&ctx, socket.clone())
            .boot(
                "bad-atr",
                Duration::from_millis(100),
                |_| -> Result<(), Box<dyn Error>> { panic!("scenario must not start") },
            )
            .unwrap_err()
            .to_string();
        server.join().unwrap();
        assert!(error.contains("stage=ATR"), "{error}");
        assert!(error.contains("board=mps2-an385"));
        assert!(!socket.exists());
    }

    #[test]
    fn drop_cleans_socket_on_unwind() {
        let socket = qemu_serial_socket_path("unwind").unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let path = socket.clone();
        let result = std::panic::catch_unwind(|| {
            let _target = sleeper(path);
            panic!("simulated assertion panic");
        });
        drop(listener);
        assert!(result.is_err());
        assert!(!socket.exists());
    }

    #[test]
    fn persistence_reset_keeps_flash_without_reloading_kernel() {
        let board = board_spec("raspi-pico1").unwrap();
        let flash = FlashFile::erased(board, 1024).unwrap();
        let path = flash.to_path_buf();
        assert_eq!(fs::read(&path).unwrap(), vec![0xff; 1024]);
        let image = Path::new("kernel.elf");
        let socket = Path::new("/tmp/test.sock");
        let initial = serial_command(board, Some(image), socket, Some(&flash)).unwrap();
        let reset = serial_command(board, None, socket, Some(&flash)).unwrap();
        let args = |c: &Command| {
            c.get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert!(args(&initial).contains(&"-kernel".to_owned()));
        assert!(!args(&reset).contains(&"-kernel".to_owned()));
        assert!(args(&reset)
            .iter()
            .any(|a| a.contains(&format!("flash-file={}", path.display()))));
        drop(flash);
        assert!(!path.exists());
    }

    #[test]
    fn scenario_failure_keeps_its_diagnostic_and_cleans_target() {
        let ctx = TestContext::default();
        let mut atr = ATR_PREFIX.to_vec();
        atr.push(ATR_OXIDE_SE_COMPACT_TLV_HEADER);
        atr.extend_from_slice(&ATR_OXIDE_SE_MARKER);
        atr.push(ATR_OXIDE_SE_VERSION);
        atr.push(expected_atr_capability_byte(&ctx.build).unwrap());
        atr.extend_from_slice(&ATR_CARD_CAPABILITIES_COMPACT_TLV);
        let socket = qemu_serial_socket_path("apdu-error").unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&atr).unwrap();
        });
        let error = socket_session(&ctx, socket.clone())
            .boot(
                "assertion-test",
                Duration::from_millis(100),
                |_| -> Result<(), Box<dyn Error>> { Err("incorrect SELECT response".into()) },
            )
            .unwrap_err()
            .to_string();
        server.join().unwrap();
        assert!(error.contains("stage=APDU"), "{error}");
        assert!(error.contains("incorrect SELECT response"));
        assert!(!socket.exists());
    }

    #[test]
    fn image_snapshots_survive_other_profile_builds_and_are_removed_on_drop() {
        let source = qemu_serial_socket_path("image-source").unwrap();
        fs::write(&source, b"profile-a").unwrap();
        let mut cache = ImageCache::default();
        let first = cache.remember("a".to_owned(), &source).unwrap();
        fs::write(&source, b"profile-b").unwrap();
        let second = cache.remember("b".to_owned(), &source).unwrap();
        assert_eq!(fs::read(&first).unwrap(), b"profile-a");
        assert_eq!(fs::read(&second).unwrap(), b"profile-b");
        let dir = cache.directory.clone().unwrap();
        drop(cache);
        assert!(!dir.exists());
        fs::remove_file(source).unwrap();
    }
}
