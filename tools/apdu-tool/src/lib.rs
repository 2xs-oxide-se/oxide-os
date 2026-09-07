//! Shared APDU links: TCP, Unix sockets and physical serial ports (115200 8N1).
pub mod fae;
pub mod gp;
pub mod scp03;
pub mod scp11;
pub mod secure_channel;
pub mod session;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 4444;
pub const DEFAULT_SERIAL_BAUD: u32 = 115_200;
pub const APDU_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
pub const T0_NULL_PROCEDURE_BYTE: u8 = 0x60;
pub const ATR_PROGRESS_INTERVAL: Duration = Duration::from_millis(500);
const LINK_POLL_TIMEOUT: Duration = Duration::from_millis(20);

/// Stable error categories shared by transports, T=0 and future protocol layers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// The link could not be opened or configured.
    Connection,
    /// The link is open but the Secure Element did not answer before the deadline.
    SecureElementSilent,
    /// Bytes were received, but not at a valid boundary for the requested exchange.
    Desynchronization,
    /// The T=0 byte stream violates the protocol or ended mid-response.
    T0Protocol,
    /// Secure Channel establishment or secure messaging failed.
    SecureChannel,
    /// The card returned a status word classified as an operation failure.
    StatusWord,
    /// The command, endpoint or local option is invalid.
    InvalidInput,
}

/// An error with a machine-testable category and a human-readable message.
#[derive(Debug)]
pub struct ApduToolError {
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl ApduToolError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(
        kind: ErrorKind,
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for ApduToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ApduToolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

pub type ToolResult<T> = std::result::Result<T, ApduToolError>;

/// Runtime policy for a T=0 client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct T0ClientConfig {
    /// Maximum silence between two bytes. Every received NULL restarts this delay.
    pub silence_timeout: Duration,
    /// Idle period which terminates ATR or diagnostic frame collection.
    pub frame_idle_timeout: Duration,
    /// Optional pacing between bytes written by host-side test runners.
    pub byte_pacing: Duration,
}

impl Default for T0ClientConfig {
    fn default() -> Self {
        Self {
            silence_timeout: APDU_RESPONSE_TIMEOUT,
            frame_idle_timeout: Duration::from_millis(200),
            byte_pacing: Duration::ZERO,
        }
    }
}

/// A short APDU command represented as T=0 header fields and command data.
#[derive(Clone, Copy, Debug)]
pub struct T0Command<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub lc: u8,
    pub le: u8,
    pub data: &'a [u8],
}

/// An owned logical short APDU, independent from CLI parsing and rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedT0Command {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub lc: u8,
    pub le: u8,
    pub data: Vec<u8>,
}

/// A logical short APDU whose `Lc` is derived from its data when encoded for T=0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: u8,
}

impl LogicalApdu {
    /// Encode the logical command as an owned T=0 command.
    pub fn to_t0(&self) -> ToolResult<OwnedT0Command> {
        let lc = u8::try_from(self.data.len()).map_err(|_| {
            ApduToolError::new(
                ErrorKind::InvalidInput,
                format!(
                    "short APDU data is {} bytes; the maximum is 255",
                    self.data.len()
                ),
            )
        })?;
        validate_t0_instruction(self.ins)?;
        Ok(OwnedT0Command {
            cla: self.cla,
            ins: self.ins,
            p1: self.p1,
            p2: self.p2,
            lc,
            le: self.le,
            data: self.data.clone(),
        })
    }
}

impl OwnedT0Command {
    /// Build a strict wire command and reject inconsistent `Lc`.
    pub fn from_wire_fields(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        lc: u8,
        le: u8,
        data: Vec<u8>,
    ) -> ToolResult<Self> {
        validate_t0_instruction(ins)?;
        if data.len() != usize::from(lc) {
            return Err(ApduToolError::new(
                ErrorKind::InvalidInput,
                format!(
                    "DATA length mismatch: LC is {lc:02X} but {} data bytes were provided",
                    data.len()
                ),
            ));
        }
        Ok(Self {
            cla,
            ins,
            p1,
            p2,
            lc,
            le,
            data,
        })
    }

    pub fn as_borrowed(&self) -> T0Command<'_> {
        T0Command {
            cla: self.cla,
            ins: self.ins,
            p1: self.p1,
            p2: self.p2,
            lc: self.lc,
            le: self.le,
            data: &self.data,
        }
    }

    /// Bytes in CLI wire order, including the separate `Lc` and `Le`.
    pub fn display_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(6 + self.data.len());
        bytes.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2, self.lc, self.le]);
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

impl T0Command<'_> {
    fn header_bytes(self) -> [u8; 5] {
        let p3 = if self.lc != 0 { self.lc } else { self.le };
        [self.cla, self.ins, self.p1, self.p2, p3]
    }
}

/// Data and status returned by one complete T=0 exchange, including GET RESPONSE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct T0Response {
    pub data: Vec<u8>,
    pub status: (u8, u8),
}

/// Shared T=0 client used by the command-line tool and target test runner.
pub struct T0Client {
    stream: Box<dyn ReadWrite>,
    config: T0ClientConfig,
}

impl T0Client {
    /// Open a physical link and apply the supplied protocol timing policy.
    pub fn connect(link: &LinkSpec, config: T0ClientConfig) -> ToolResult<Self> {
        Ok(Self::new(
            open_link_with_timeout(link, LINK_POLL_TIMEOUT)?,
            config,
        ))
    }

    /// Wrap an already-open byte stream, notably a QEMU Unix socket or a test double.
    pub fn new(stream: Box<dyn ReadWrite>, config: T0ClientConfig) -> Self {
        Self { stream, config }
    }

    pub fn config(&self) -> T0ClientConfig {
        self.config
    }

    /// Drain bytes left by an earlier hardware run while the target is halted.
    pub fn discard_stale_input(&mut self) -> ToolResult<()> {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut buffer = [0; 256];
        while Instant::now() < deadline {
            match self.stream.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error) if is_retryable_io(&error) => return Ok(()),
                Err(error) => {
                    return Err(ApduToolError::with_source(
                        ErrorKind::T0Protocol,
                        "failed while draining stale input",
                        error,
                    ))
                }
            }
        }
        Err(ApduToolError::new(
            ErrorKind::Desynchronization,
            "serial input did not become idle while target was halted",
        ))
    }

    /// Collect an ATR or diagnostic frame until the stream becomes idle.
    pub fn read_frame(&mut self, first_byte_timeout: Duration) -> ToolResult<Vec<u8>> {
        self.read_frame_until(Some(first_byte_timeout))
    }

    /// Collect a frame with an optional infinite wait for its first byte.
    pub fn read_frame_until(
        &mut self,
        first_byte_timeout: Option<Duration>,
    ) -> ToolResult<Vec<u8>> {
        self.read_frame_until_with_progress(first_byte_timeout, || {})
    }

    /// Collect a frame and report twice per second while bytes are awaited.
    pub fn read_frame_until_with_progress(
        &mut self,
        first_byte_timeout: Option<Duration>,
        mut on_wait: impl FnMut(),
    ) -> ToolResult<Vec<u8>> {
        let mut frame = Vec::new();
        let mut buffer = [0u8; 256];
        let first_byte_deadline = match first_byte_timeout {
            Some(timeout) => Some(Instant::now().checked_add(timeout).ok_or_else(|| {
                ApduToolError::new(ErrorKind::InvalidInput, "ATR timeout is too large")
            })?),
            None => None,
        };
        let mut idle_since = None;
        let mut next_progress = Instant::now() + ATR_PROGRESS_INTERVAL;

        loop {
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    if !frame.is_empty() || deadline_expired(first_byte_deadline) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Ok(read_len) => {
                    frame.extend_from_slice(&buffer[..read_len]);
                    idle_since = Some(Instant::now());
                }
                Err(error) if is_retryable_io(&error) => {
                    if frame.is_empty() {
                        if deadline_expired(first_byte_deadline) {
                            break;
                        }
                    } else if idle_since
                        .is_some_and(|idle| idle.elapsed() >= self.config.frame_idle_timeout)
                    {
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => {
                    return Err(ApduToolError::with_source(
                        ErrorKind::T0Protocol,
                        "failed while reading an ATR or diagnostic frame",
                        error,
                    ))
                }
            }
            if Instant::now() >= next_progress {
                on_wait();
                next_progress = Instant::now() + ATR_PROGRESS_INTERVAL;
            }
        }
        Ok(frame)
    }

    /// Execute a complete short-APDU T=0 exchange.
    pub fn exchange(&mut self, command: T0Command<'_>) -> ToolResult<T0Response> {
        self.exchange_with_progress(command, || {})
    }

    /// Execute an exchange and notify the caller for every T=0 NULL procedure byte.
    pub fn exchange_with_progress(
        &mut self,
        command: T0Command<'_>,
        mut on_null: impl FnMut(),
    ) -> ToolResult<T0Response> {
        self.exchange_with_response_chunk_limit_and_progress(command, 255, &mut on_null)
    }

    /// Execute an exchange while limiting each GET RESPONSE request.
    pub fn exchange_with_response_chunk_limit(
        &mut self,
        command: T0Command<'_>,
        response_chunk_limit: usize,
    ) -> ToolResult<T0Response> {
        self.exchange_with_response_chunk_limit_and_progress(
            command,
            response_chunk_limit,
            &mut || {},
        )
    }

    fn exchange_with_response_chunk_limit_and_progress(
        &mut self,
        mut command: T0Command<'_>,
        response_chunk_limit: usize,
        on_null: &mut impl FnMut(),
    ) -> ToolResult<T0Response> {
        if !(1..=255).contains(&response_chunk_limit) {
            return Err(ApduToolError::new(
                ErrorKind::InvalidInput,
                "GET RESPONSE chunk size must be in 1..=255",
            ));
        }
        validate_t0_instruction(command.ins)?;
        if command.data.len() != command.lc as usize {
            return Err(ApduToolError::new(
                ErrorKind::InvalidInput,
                "T=0 command data length does not match Lc",
            ));
        }

        loop {
            self.write_bytes(&command.header_bytes())?;

            if command.lc != 0 {
                if let Some(status) = self.read_procedure_status(command.ins, on_null)? {
                    return Ok(T0Response {
                        data: Vec::new(),
                        status,
                    });
                }
                self.write_bytes(command.data)?;
            }

            if command.lc == 0 && command.le != 0 {
                let first = self.read_protocol_byte(on_null)?;
                if first == 0x6c {
                    command.le = self.read_byte()?;
                    continue;
                }
                self.require_bulk_ack_or_status(first, command.ins)?;
                if is_t0_status_byte(first) {
                    return Ok(T0Response {
                        data: Vec::new(),
                        status: (first, self.read_byte()?),
                    });
                }
                let data = self.read_exact_bytes(command.le as usize)?;
                return Ok(T0Response {
                    data,
                    status: self.read_status(on_null)?,
                });
            }

            let mut data = Vec::new();
            let mut status = self.read_status(on_null)?;
            if status.0 != 0x61 {
                return Ok(T0Response { data, status });
            }

            let mut remaining = (command.le != 0).then_some(command.le as usize);
            while status.0 == 0x61 {
                let hinted = hinted_len_from_status(status);
                let request_len = remaining
                    .map(|len| hinted.min(len).min(response_chunk_limit))
                    .unwrap_or_else(|| hinted.min(response_chunk_limit));
                self.write_bytes(&[0x00, 0xc0, 0x00, 0x00, request_len as u8])?;

                let procedure = self.read_protocol_byte(on_null)?;
                if procedure != 0xc0 {
                    if procedure == !0xc0 {
                        return Err(ApduToolError::new(
                            ErrorKind::T0Protocol,
                            "single-byte T=0 ACK is not supported by this client",
                        ));
                    }
                    if is_t0_status_byte(procedure) {
                        status = (procedure, self.read_byte()?);
                        break;
                    }
                    return Err(ApduToolError::new(
                        ErrorKind::T0Protocol,
                        format!("expected GET RESPONSE procedure byte C0, got {procedure:02X}"),
                    ));
                }

                data.extend_from_slice(&self.read_exact_bytes(request_len)?);
                if let Some(remaining_len) = remaining.as_mut() {
                    *remaining_len = remaining_len.saturating_sub(request_len);
                    if *remaining_len == 0 {
                        status = self.read_status(on_null)?;
                        break;
                    }
                }
                status = self.read_status(on_null)?;
            }
            return Ok(T0Response { data, status });
        }
    }

    fn read_procedure_status(
        &mut self,
        ins: u8,
        on_null: &mut impl FnMut(),
    ) -> ToolResult<Option<(u8, u8)>> {
        let first = self.read_protocol_byte(on_null)?;
        self.require_bulk_ack_or_status(first, ins)?;
        if is_t0_status_byte(first) {
            return Ok(Some((first, self.read_byte()?)));
        }
        Ok(None)
    }

    fn require_bulk_ack_or_status(&self, byte: u8, ins: u8) -> ToolResult<()> {
        reject_atr_start(byte)?;
        if byte == !ins {
            return Err(ApduToolError::new(
                ErrorKind::T0Protocol,
                "single-byte T=0 ACK is not supported by this client",
            ));
        }
        if byte != ins && !is_t0_status_byte(byte) {
            return Err(ApduToolError::new(
                ErrorKind::T0Protocol,
                format!("invalid T=0 procedure byte {byte:02X}"),
            ));
        }
        Ok(())
    }

    fn read_protocol_byte(&mut self, on_null: &mut impl FnMut()) -> ToolResult<u8> {
        loop {
            let byte = self.read_byte()?;
            if byte != T0_NULL_PROCEDURE_BYTE {
                return Ok(byte);
            }
            on_null();
            // Each NULL proves card liveness and starts a fresh silence interval.
        }
    }

    fn read_status(&mut self, on_null: &mut impl FnMut()) -> ToolResult<(u8, u8)> {
        let sw1 = self.read_protocol_byte(on_null)?;
        reject_atr_start(sw1)?;
        if !is_t0_status_byte(sw1) {
            return Err(ApduToolError::new(
                ErrorKind::T0Protocol,
                format!("invalid T=0 status byte {sw1:02X}"),
            ));
        }
        let sw2 = self.read_byte().map_err(|error| {
            ApduToolError::new(
                ErrorKind::T0Protocol,
                format!("truncated T=0 status after SW1 {sw1:02X}: {error}"),
            )
        })?;
        Ok((sw1, sw2))
    }

    fn read_exact_bytes(&mut self, len: usize) -> ToolResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(len);
        while bytes.len() < len {
            bytes.push(self.read_byte().map_err(|error| {
                ApduToolError::new(
                    ErrorKind::T0Protocol,
                    format!(
                        "APDU payload: received {}/{} bytes: {error}",
                        bytes.len(),
                        len
                    ),
                )
            })?);
        }
        Ok(bytes)
    }

    fn read_byte(&mut self) -> ToolResult<u8> {
        let deadline = Instant::now() + self.config.silence_timeout;
        let mut buffer = [0u8; 1];
        loop {
            match self.stream.read(&mut buffer) {
                Ok(1) => return Ok(buffer[0]),
                Ok(0) => {}
                Ok(_) => unreachable!(),
                Err(error) if is_retryable_io(&error) => {}
                Err(error) => {
                    return Err(ApduToolError::with_source(
                        ErrorKind::T0Protocol,
                        "I/O error while reading an APDU byte",
                        error,
                    ))
                }
            }
            if Instant::now() >= deadline {
                return Err(ApduToolError::new(
                    ErrorKind::SecureElementSilent,
                    "timed out waiting for APDU byte",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> ToolResult<()> {
        for &byte in bytes {
            self.stream.write_all(&[byte]).map_err(|error| {
                ApduToolError::with_source(
                    ErrorKind::T0Protocol,
                    "I/O error while writing an APDU byte",
                    error,
                )
            })?;
            self.stream.flush().map_err(|error| {
                ApduToolError::with_source(
                    ErrorKind::T0Protocol,
                    "I/O error while flushing an APDU byte",
                    error,
                )
            })?;
            if !self.config.byte_pacing.is_zero() {
                thread::sleep(self.config.byte_pacing);
            }
        }
        Ok(())
    }
}

fn is_retryable_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

fn reject_atr_start(byte: u8) -> ToolResult<()> {
    if matches!(byte, 0x3b | 0x3f) {
        return Err(ApduToolError::new(
            ErrorKind::Desynchronization,
            format!(
                "received ATR start byte {byte:02X} while waiting for an APDU response; run `apdu-tool atr` before sending the command"
            ),
        ));
    }
    Ok(())
}

pub fn is_t0_status_byte(byte: u8) -> bool {
    byte != T0_NULL_PROCEDURE_BYTE && matches!(byte & 0xf0, 0x60 | 0x90)
}

pub fn is_valid_t0_instruction(ins: u8) -> bool {
    !matches!(ins & 0xf0, 0x60 | 0x90)
}

pub fn validate_t0_instruction(ins: u8) -> ToolResult<()> {
    if is_valid_t0_instruction(ins) {
        return Ok(());
    }
    Err(ApduToolError::new(
        ErrorKind::InvalidInput,
        format!(
            "invalid T=0 INS {ins:02X}: 60-6F and 90-9F are reserved for procedure/status bytes"
        ),
    ))
}

fn hinted_len_from_status(status: (u8, u8)) -> usize {
    match status {
        (0x61, 0) => 256,
        (0x61, len) => len as usize,
        _ => 0,
    }
}

/// Common byte stream used by the APDU clients, independent of the physical link.
pub trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Parsed link description; parsing never opens or resets a device.
pub enum LinkSpec {
    Tcp { host: String, port: u16 },
    UnixSocket { path: PathBuf },
    SerialPort { path: String, baud: u32 },
}

/// Enumerate serial ports without opening them. USB metadata lets callers
/// distinguish external adapters from Bluetooth and platform debug consoles.
pub use serialport::{
    available_ports as available_serial_ports, SerialPortInfo, SerialPortType, UsbPortInfo,
};

/// Preserve the standalone tool's TCP default.
pub fn default_link_spec() -> LinkSpec {
    LinkSpec::Tcp {
        host: DEFAULT_HOST.to_owned(),
        port: DEFAULT_PORT,
    }
}

/// Decode HOST:PORT, an absolute socket path, /dev/device:BAUD or COMn[:BAUD].
pub fn parse_link_spec(value: &str) -> ToolResult<LinkSpec> {
    if value == "default" {
        return Ok(default_link_spec());
    }

    if looks_like_windows_com_port(value) {
        return parse_serial_port_spec(value);
    }

    let path = Path::new(value);
    if path.is_absolute() {
        if has_trailing_numeric_suffix(value) && value.starts_with("/dev/") {
            return parse_serial_port_spec(value);
        }
        return Ok(LinkSpec::UnixSocket {
            path: PathBuf::from(value),
        });
    }

    let (host, port) = split_endpoint(value)?;
    Ok(LinkSpec::Tcp { host, port })
}

fn parse_serial_port_spec(value: &str) -> ToolResult<LinkSpec> {
    let (path, baud) = match value.rsplit_once(':') {
        Some((path, baud)) if !path.is_empty() && baud.chars().all(|ch| ch.is_ascii_digit()) => (
            path.to_owned(),
            baud.parse().map_err(|error| {
                ApduToolError::with_source(
                    ErrorKind::InvalidInput,
                    format!("invalid serial baud rate `{baud}`"),
                    error,
                )
            })?,
        ),
        _ => (value.to_owned(), DEFAULT_SERIAL_BAUD),
    };
    Ok(LinkSpec::SerialPort { path, baud })
}

/// Open a link with the ordinary APDU tool timeout and physical serial 8N1.
pub fn open_link(link: &LinkSpec) -> ToolResult<Box<dyn ReadWrite>> {
    open_link_with_timeout(link, APDU_RESPONSE_TIMEOUT)
}

/// Set an I/O polling timeout without changing the caller's APDU deadline.
pub fn open_link_with_timeout(
    link: &LinkSpec,
    timeout: Duration,
) -> ToolResult<Box<dyn ReadWrite>> {
    match link {
        LinkSpec::Tcp { host, port } => {
            let endpoint = format!("{host}:{port}");
            let stream = TcpStream::connect(&endpoint).map_err(|error| {
                ApduToolError::with_source(
                    ErrorKind::Connection,
                    format!("could not connect to TCP endpoint {endpoint}"),
                    error,
                )
            })?;
            stream
                .set_nodelay(true)
                .map_err(connection_configuration_error)?;
            stream
                .set_read_timeout(Some(timeout))
                .map_err(connection_configuration_error)?;
            stream
                .set_write_timeout(Some(timeout))
                .map_err(connection_configuration_error)?;
            Ok(Box::new(stream))
        }
        LinkSpec::UnixSocket { path } => open_unix_socket(path, timeout),
        LinkSpec::SerialPort { path, baud } => {
            let mut stream = serialport::new(path, *baud)
                .data_bits(serialport::DataBits::Eight)
                .parity(serialport::Parity::None)
                .stop_bits(serialport::StopBits::One)
                .flow_control(serialport::FlowControl::None)
                .timeout(timeout)
                .open()
                .map_err(|error| {
                    ApduToolError::with_source(
                        ErrorKind::Connection,
                        format!("could not open serial port {path} at {baud} baud"),
                        error,
                    )
                })?;
            stream.write_data_terminal_ready(true).map_err(|error| {
                ApduToolError::with_source(
                    ErrorKind::Connection,
                    format!("could not configure DTR on serial port {path}"),
                    error,
                )
            })?;
            stream.write_request_to_send(true).map_err(|error| {
                ApduToolError::with_source(
                    ErrorKind::Connection,
                    format!("could not configure RTS on serial port {path}"),
                    error,
                )
            })?;
            Ok(Box::new(stream))
        }
    }
}

#[cfg(unix)]
fn open_unix_socket(path: &Path, timeout: Duration) -> ToolResult<Box<dyn ReadWrite>> {
    let stream = UnixStream::connect(path).map_err(|error| {
        ApduToolError::with_source(
            ErrorKind::Connection,
            format!("could not connect to Unix socket {}", path.display()),
            error,
        )
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(connection_configuration_error)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(connection_configuration_error)?;
    Ok(Box::new(stream))
}

#[cfg(not(unix))]
fn open_unix_socket(_path: &Path, _timeout: Duration) -> ToolResult<Box<dyn ReadWrite>> {
    Err(ApduToolError::new(
        ErrorKind::Connection,
        "Unix sockets are not supported on this platform",
    ))
}

fn connection_configuration_error(error: std::io::Error) -> ApduToolError {
    ApduToolError::with_source(
        ErrorKind::Connection,
        "could not configure link timeouts",
        error,
    )
}

pub fn looks_like_endpoint(value: &str) -> bool {
    value.contains(':')
}

fn looks_like_windows_com_port(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    let Some(rest) = upper.strip_prefix("COM") else {
        return false;
    };
    let port = rest.split_once(':').map(|(port, _)| port).unwrap_or(rest);
    !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit())
}

fn has_trailing_numeric_suffix(value: &str) -> bool {
    value
        .rsplit_once(':')
        .map(|(_, suffix)| !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit()))
        .unwrap_or(false)
}

pub fn split_endpoint(value: &str) -> ToolResult<(String, u16)> {
    let (host, port) = value.rsplit_once(':').ok_or_else(|| {
        ApduToolError::new(ErrorKind::InvalidInput, "endpoint must look like HOST:PORT")
    })?;
    let port = port.parse().map_err(|error| {
        ApduToolError::with_source(
            ErrorKind::InvalidInput,
            format!("invalid TCP port `{port}`"),
            error,
        )
    })?;
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io;
    use std::net::TcpListener;
    use std::rc::Rc;
    use std::sync::mpsc;

    enum ReadEvent {
        Byte(u8),
        Wait(Duration),
    }

    struct ScriptedLink {
        reads: VecDeque<ReadEvent>,
        writes: Rc<RefCell<Vec<u8>>>,
    }

    impl Read for ScriptedLink {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            match self.reads.pop_front() {
                Some(ReadEvent::Byte(byte)) => {
                    output[0] = byte;
                    Ok(1)
                }
                Some(ReadEvent::Wait(duration)) => {
                    thread::sleep(duration);
                    Err(io::ErrorKind::WouldBlock.into())
                }
                None => Err(io::ErrorKind::WouldBlock.into()),
            }
        }
    }

    impl Write for ScriptedLink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn client(events: impl IntoIterator<Item = ReadEvent>) -> (T0Client, Rc<RefCell<Vec<u8>>>) {
        let writes = Rc::new(RefCell::new(Vec::new()));
        let link = ScriptedLink {
            reads: events.into_iter().collect(),
            writes: writes.clone(),
        };
        let config = T0ClientConfig {
            silence_timeout: Duration::from_millis(20),
            frame_idle_timeout: Duration::ZERO,
            byte_pacing: Duration::ZERO,
        };
        (T0Client::new(Box::new(link), config), writes)
    }

    fn command<'a>(ins: u8, data: &'a [u8], le: u8) -> T0Command<'a> {
        T0Command {
            cla: 0x80,
            ins,
            p1: 0,
            p2: 0,
            lc: data.len() as u8,
            le,
            data,
        }
    }

    #[test]
    fn null_bytes_are_ignored_before_an_immediate_status() {
        let (mut client, writes) = client([
            ReadEvent::Byte(0x60),
            ReadEvent::Byte(0x60),
            ReadEvent::Byte(0x69),
            ReadEvent::Byte(0x85),
        ]);
        let response = client.exchange(command(0x06, &[0xaa], 0)).unwrap();
        assert_eq!(
            response,
            T0Response {
                data: vec![],
                status: (0x69, 0x85)
            }
        );
        assert_eq!(&*writes.borrow(), &[0x80, 0x06, 0, 0, 1]);
    }

    #[test]
    fn response_progress_is_driven_only_by_null_procedure_bytes() {
        let (mut client, _) = client([
            ReadEvent::Byte(0x60),
            ReadEvent::Byte(0x04),
            ReadEvent::Byte(0x60),
            ReadEvent::Byte(0x22),
            ReadEvent::Byte(0x90),
            ReadEvent::Byte(0x00),
        ]);
        let mut ticks = 0;
        let response = client
            .exchange_with_progress(command(0x04, &[], 2), || ticks += 1)
            .unwrap();
        assert_eq!(ticks, 1);
        assert_eq!(response.data, [0x60, 0x22]);
    }

    #[test]
    fn atr_progress_interval_is_twice_per_second() {
        assert_eq!(ATR_PROGRESS_INTERVAL, Duration::from_millis(500));
    }

    #[test]
    fn atr_wait_reports_progress_after_half_a_second() {
        let (mut client, _) = client([
            ReadEvent::Wait(Duration::from_millis(510)),
            ReadEvent::Byte(0x3b),
            ReadEvent::Byte(0x00),
        ]);
        let mut ticks = 0;
        let atr = client
            .read_frame_until_with_progress(Some(Duration::from_secs(1)), || ticks += 1)
            .unwrap();
        assert_eq!(atr, [0x3b, 0x00]);
        assert_eq!(ticks, 1);
    }

    #[test]
    fn every_null_starts_a_fresh_silence_timeout() {
        let (mut client, _) = client([
            ReadEvent::Wait(Duration::from_millis(12)),
            ReadEvent::Byte(0x60),
            ReadEvent::Wait(Duration::from_millis(12)),
            ReadEvent::Byte(0x90),
            ReadEvent::Byte(0x00),
        ]);
        assert_eq!(
            client.exchange(command(0x00, &[], 0)).unwrap().status,
            (0x90, 0x00)
        );
    }

    #[test]
    fn wrong_length_reissues_the_command_with_corrected_le() {
        let (mut client, writes) = client([
            ReadEvent::Byte(0x6c),
            ReadEvent::Byte(0x02),
            ReadEvent::Byte(0xca),
            ReadEvent::Byte(0x12),
            ReadEvent::Byte(0x34),
            ReadEvent::Byte(0x90),
            ReadEvent::Byte(0x00),
        ]);
        let response = client.exchange(command(0xca, &[], 4)).unwrap();
        assert_eq!(response.data, [0x12, 0x34]);
        assert_eq!(
            &*writes.borrow(),
            &[0x80, 0xca, 0, 0, 4, 0x80, 0xca, 0, 0, 2]
        );
    }

    #[test]
    fn get_response_preserves_null_valued_payload_bytes() {
        let (mut client, writes) = client([
            ReadEvent::Byte(0x84),
            ReadEvent::Byte(0x61),
            ReadEvent::Byte(0x03),
            ReadEvent::Byte(0xc0),
            ReadEvent::Byte(0x11),
            ReadEvent::Byte(0x60),
            ReadEvent::Byte(0x22),
            ReadEvent::Byte(0x90),
            ReadEvent::Byte(0x00),
        ]);
        let response = client.exchange(command(0x84, &[0xaa], 0)).unwrap();
        assert_eq!(response.data, [0x11, 0x60, 0x22]);
        assert_eq!(response.status, (0x90, 0x00));
        assert_eq!(
            &*writes.borrow(),
            &[0x80, 0x84, 0, 0, 1, 0xaa, 0, 0xc0, 0, 0, 3]
        );
    }

    #[test]
    fn invalid_instruction_is_rejected_before_any_write() {
        let (mut client, writes) = client([]);
        assert!(client.exchange(command(0x90, &[], 0)).is_err());
        assert!(writes.borrow().is_empty());
    }

    #[test]
    fn logical_apdu_derives_lc_and_wire_apdu_remains_strict() {
        let logical = LogicalApdu {
            cla: 0x80,
            ins: 0x02,
            p1: 0x01,
            p2: 0x02,
            data: vec![0xaa, 0xbb, 0xcc],
            le: 0x10,
        };
        let encoded = logical.to_t0().unwrap();
        assert_eq!(encoded.lc, 3);
        assert_eq!(encoded.data, [0xaa, 0xbb, 0xcc]);

        let error =
            OwnedT0Command::from_wire_fields(0x80, 0x02, 0, 0, 2, 0, vec![0xaa]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn logical_short_apdu_rejects_more_than_255_data_bytes() {
        let error = LogicalApdu {
            cla: 0x80,
            ins: 0x02,
            p1: 0,
            p2: 0,
            data: vec![0; 256],
            le: 0,
        }
        .to_t0()
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn t0_case_one_sends_header_and_reads_status() {
        let (mut client, writes) = client([ReadEvent::Byte(0x90), ReadEvent::Byte(0x00)]);
        let response = client.exchange(command(0x02, &[], 0)).unwrap();
        assert_eq!(
            response,
            T0Response {
                data: vec![],
                status: (0x90, 0x00)
            }
        );
        assert_eq!(&*writes.borrow(), &[0x80, 0x02, 0, 0, 0]);
    }

    #[test]
    fn t0_case_three_sends_data_after_ack() {
        let (mut client, writes) = client([
            ReadEvent::Byte(0x02),
            ReadEvent::Byte(0x90),
            ReadEvent::Byte(0x00),
        ]);
        let response = client.exchange(command(0x02, &[0x12, 0x34], 0)).unwrap();
        assert_eq!(response.status, (0x90, 0x00));
        assert_eq!(&*writes.borrow(), &[0x80, 0x02, 0, 0, 2, 0x12, 0x34]);
    }

    #[test]
    fn t0_case_two_reads_expected_data_after_ack() {
        let (mut client, writes) = client([
            ReadEvent::Byte(0x04),
            ReadEvent::Byte(0x12),
            ReadEvent::Byte(0x34),
            ReadEvent::Byte(0x90),
            ReadEvent::Byte(0x00),
        ]);
        let response = client.exchange(command(0x04, &[], 2)).unwrap();
        assert_eq!(response.data, [0x12, 0x34]);
        assert_eq!(&*writes.borrow(), &[0x80, 0x04, 0, 0, 2]);
    }

    #[test]
    fn t0_case_four_collects_output_through_get_response() {
        let (mut client, writes) = client([
            ReadEvent::Byte(0x06),
            ReadEvent::Byte(0x61),
            ReadEvent::Byte(0x02),
            ReadEvent::Byte(0xc0),
            ReadEvent::Byte(0xab),
            ReadEvent::Byte(0xcd),
            ReadEvent::Byte(0x90),
            ReadEvent::Byte(0x00),
        ]);
        let response = client.exchange(command(0x06, &[0x55], 2)).unwrap();
        assert_eq!(response.data, [0xab, 0xcd]);
        assert_eq!(
            &*writes.borrow(),
            &[0x80, 0x06, 0, 0, 1, 0x55, 0, 0xc0, 0, 0, 2]
        );
    }

    #[test]
    fn silence_and_truncation_have_distinct_error_categories() {
        let (mut silent_client, _) = client([]);
        let silent = silent_client.exchange(command(0x00, &[], 0)).unwrap_err();
        assert_eq!(silent.kind(), ErrorKind::SecureElementSilent);

        let (mut truncated_client, _) = client([ReadEvent::Byte(0x90)]);
        let truncated = truncated_client
            .exchange(command(0x00, &[], 0))
            .unwrap_err();
        assert_eq!(truncated.kind(), ErrorKind::T0Protocol);
        assert!(truncated.to_string().contains("truncated T=0 status"));
    }

    #[test]
    fn invalid_procedure_byte_is_a_t0_protocol_error() {
        let (mut client, _) = client([ReadEvent::Byte(0x42)]);
        let error = client.exchange(command(0x02, &[0xaa], 0)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::T0Protocol);
    }

    #[test]
    fn atr_start_while_waiting_for_response_is_desynchronization() {
        for atr_start in [0x3b, 0x3f] {
            let (mut client, _) = client([ReadEvent::Byte(atr_start)]);
            let error = client.exchange(command(0x02, &[], 0)).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Desynchronization);
            assert!(error.to_string().contains("apdu-tool atr"));
        }
    }

    #[test]
    fn tcp_link_opens_and_transfers_bytes() {
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("could not bind TCP test listener: {error}"),
        };
        let port = listener.local_addr().unwrap().port();
        let (sent, received) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut input = [0u8; 1];
            stream.read_exact(&mut input).unwrap();
            sent.send(input[0]).unwrap();
            stream.write_all(&[0x3b]).unwrap();
        });

        let mut link = open_link_with_timeout(
            &LinkSpec::Tcp {
                host: "127.0.0.1".to_owned(),
                port,
            },
            Duration::from_millis(200),
        )
        .unwrap();
        link.write_all(&[0xa5]).unwrap();
        let mut output = [0u8; 1];
        link.read_exact(&mut output).unwrap();
        assert_eq!(output, [0x3b]);
        assert_eq!(received.recv().unwrap(), 0xa5);
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_link_opens_and_transfers_bytes() {
        use std::os::unix::net::UnixListener;

        // Keep this below macOS' short sockaddr_un path limit.
        let socket_path = PathBuf::from(format!("/tmp/apdu-tool-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket_path);
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("could not bind Unix test listener: {error}"),
        };
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut input = [0u8; 1];
            stream.read_exact(&mut input).unwrap();
            assert_eq!(input, [0xa5]);
            stream.write_all(&[0x3b]).unwrap();
        });

        let mut link = open_link_with_timeout(
            &LinkSpec::UnixSocket {
                path: socket_path.clone(),
            },
            Duration::from_millis(200),
        )
        .unwrap();
        link.write_all(&[0xa5]).unwrap();
        let mut output = [0u8; 1];
        link.read_exact(&mut output).unwrap();
        assert_eq!(output, [0x3b]);
        server.join().unwrap();
        std::fs::remove_file(socket_path).unwrap();
    }

    #[test]
    fn unavailable_tcp_endpoint_is_a_connection_error() {
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("could not bind TCP test listener: {error}"),
        };
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let error = open_link_with_timeout(
            &LinkSpec::Tcp {
                host: "127.0.0.1".to_owned(),
                port,
            },
            Duration::from_millis(20),
        )
        .err()
        .expect("connection should fail");
        assert_eq!(error.kind(), ErrorKind::Connection);
    }
}
