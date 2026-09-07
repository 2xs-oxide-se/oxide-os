use apdu_tool::scp03::{Scp03Engine, Scp03Keyset, Scp03Profile};
use apdu_tool::scp11::{Scp11Credentials, Scp11Engine};
use apdu_tool::secure_channel::{
    CommandTransport, SecureChannelConfig, SecureChannelProtocol, SecureChannelSession,
    SecurityLevel,
};
use apdu_tool::session::{self, PersistedSecureChannel, SessionFile};
use apdu_tool::*;
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_ATR_TIMEOUT: Duration = APDU_RESPONSE_TIMEOUT;
const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const ENV_LINK: &str = "APDU_LINK";
const ENV_OUTPUT: &str = "APDU_OUTPUT";
const ENV_CONNECT_TIMEOUT: &str = "APDU_CONNECT_TIMEOUT";
const ENV_ATR_TIMEOUT: &str = "APDU_ATR_TIMEOUT";
const ENV_RESPONSE_TIMEOUT: &str = "APDU_RESPONSE_TIMEOUT";
const ENV_RETRY_INTERVAL: &str = "APDU_RETRY_INTERVAL";
const ENV_SECURE_CHANNEL: &str = "APDU_SECURE_CHANNEL";
const ENV_SECURITY_DOMAIN: &str = "APDU_SECURITY_DOMAIN";
const ENV_SECURITY_LEVEL: &str = "APDU_SECURITY_LEVEL";
const ENV_CREDENTIALS: &str = "APDU_CREDENTIALS";
const ENV_SCP03_PROFILE: &str = "APDU_SCP03_PROFILE";
const ENV_KEYSET: &str = "APDU_KEYSET";
const ANSI_RESET: &str = "\x1b[0m";
const ANSI_WHITE: &str = "\x1b[97m";
const ANSI_BLUE: &str = "\x1b[34m";
const ANSI_PINK: &str = "\x1b[95m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RED: &str = "\x1b[31m";
const FIELD_COLORS: [&str; 8] = [
    "\x1b[36m", // cyan
    "\x1b[33m", // yellow
    "\x1b[35m", // magenta
    "\x1b[32m", // green
    "\x1b[34m", // blue
    "\x1b[31m", // red
    "\x1b[96m", // bright cyan
    "\x1b[93m", // bright yellow
];

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    let error_output = requested_output_mode(&raw_args);
    let options = match parse_args(raw_args.into_iter()) {
        Ok(options) => options,
        Err(error) => {
            emit_error(error_output, &*error);
            std::process::exit(2);
        }
    };
    let output = options.output;
    match run(options) {
        Ok(outcome) if outcome.success() => {}
        Ok(_) => std::process::exit(15),
        Err(error) => {
            emit_error(output, &*error);
            let code = error
                .downcast_ref::<ApduToolError>()
                .map(error_exit_code)
                .unwrap_or(1);
            std::process::exit(code);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputMode {
    Human,
    Color,
    Json,
    Bin,
}

impl OutputMode {
    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "human" => Ok(Self::Human),
            "color" => Ok(Self::Color),
            "json" => Ok(Self::Json),
            "bin" => Ok(Self::Bin),
            _ => Err(
                format!("invalid output mode `{value}`; expected human, color, json or bin").into(),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RunOutcome {
    status: Option<(u8, u8)>,
}

impl RunOutcome {
    const fn success(self) -> bool {
        matches!(self.status, None | Some((0x90, 0x00)))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CliOptions {
    link: LinkSpec,
    verbose: u8,
    progress: bool,
    quiet: bool,
    output: OutputMode,
    connect_timeout: Duration,
    atr_timeout: Option<Duration>,
    response_timeout: Duration,
    retry_interval: Duration,
    secure_channel: SecureChannelConfig,
    scp03_profile: Option<Scp03Profile>,
    command: CliCommand,
}

#[derive(Debug, PartialEq, Eq)]
enum CliCommand {
    Atr,
    Close,
    Scp03Open,
    Scp03Inspect,
    Scp03Close,
    Select(Vec<u8>),
    Raw(OwnedT0Command),
    GpGetData(GpGetDataOptions),
    GpGetStatus(GpGetStatusOptions),
    GpMutation(OwnedT0Command),
    GpPutKey(GpPutKeyOptions),
    GpLoad(GpLoadOptions),
}

#[derive(Debug, PartialEq, Eq)]
struct GpLoadOptions {
    package_aid: Vec<u8>,
    instance_aid: Option<Vec<u8>>,
    install_parameters: Vec<u8>,
    fae: Vec<u8>,
    metadata: fae::FaeMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GpDataFormat {
    Hex,
    Binary,
    Tlv,
}

#[derive(Debug, PartialEq, Eq)]
struct GpGetDataOptions {
    tag: u16,
    format: GpDataFormat,
    output: Option<PathBuf>,
}

type GpStatusCategory = gp::StatusCategory;

#[derive(Debug, PartialEq, Eq)]
struct GpGetStatusOptions {
    category: GpStatusCategory,
    aid_filter: Vec<u8>,
}

#[derive(PartialEq, Eq)]
struct GpPutKeyOptions {
    command: OwnedT0Command,
    warnings: Vec<String>,
}

impl std::fmt::Debug for GpPutKeyOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GpPutKeyOptions")
            .field("cla", &self.command.cla)
            .field("ins", &self.command.ins)
            .field("p1", &self.command.p1)
            .field("p2", &self.command.p2)
            .field("key_payload", &"[REDACTED]")
            .field("warnings", &self.warnings)
            .finish()
    }
}

#[derive(Clone, Copy)]
struct ByteSpan {
    start: usize,
    len: usize,
}

struct DecodedField {
    name: &'static str,
    span: ByteSpan,
    value: String,
    description: String,
    color_index: usize,
}

struct Progress<'a> {
    enabled: bool,
    displayed: bool,
    frame: usize,
    writer: &'a mut dyn Write,
}

struct CliClient {
    transport: T0Client,
    scp03: Option<SecureChannelSession<Scp03Engine>>,
    scp11: Option<SecureChannelSession<Scp11Engine>>,
    persisted: Option<(PathBuf, SessionFile)>,
    persistent_claimed: bool,
}

impl CliClient {
    fn connect(
        link: &LinkSpec,
        transport_config: T0ClientConfig,
        secure_config: &SecureChannelConfig,
        profile_override: Option<Scp03Profile>,
        error_writer: &mut dyn Write,
    ) -> Result<Self, Box<dyn Error>> {
        Self::connect_internal(
            link,
            transport_config,
            secure_config,
            profile_override,
            error_writer,
            false,
        )
    }

    fn open_persistent_scp03(
        link: &LinkSpec,
        transport_config: T0ClientConfig,
        secure_config: &SecureChannelConfig,
        profile_override: Option<Scp03Profile>,
        error_writer: &mut dyn Write,
    ) -> Result<Self, Box<dyn Error>> {
        Self::connect_internal(
            link,
            transport_config,
            secure_config,
            profile_override,
            error_writer,
            true,
        )
    }

    fn connect_internal(
        link: &LinkSpec,
        transport_config: T0ClientConfig,
        secure_config: &SecureChannelConfig,
        profile_override: Option<Scp03Profile>,
        error_writer: &mut dyn Write,
        persist_new_channel: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let session_path = session::path_from_environment()?;
        let mut persisted = if session_path.exists() {
            let state = session::load(&session_path)?;
            Some((session_path, state))
        } else {
            None
        };
        let effective_link = persisted
            .as_ref()
            .map(|(_, state)| &state.link)
            .unwrap_or(link);
        let mut persistent_claimed = false;
        if persisted
            .as_ref()
            .is_some_and(|(_, state)| state.protocol() == SecureChannelProtocol::Scp03)
        {
            let path = &persisted.as_ref().expect("checked above").0;
            if !session::remove(path)? {
                return Err(ApduToolError::new(
                    ErrorKind::SecureChannel,
                    "persisted SCP03 state is already in use or was invalidated",
                )
                .into());
            }
            persistent_claimed = true;
        }
        let mut transport = T0Client::connect(effective_link, transport_config)?;
        let restored_scp03 = persisted
            .as_ref()
            .and_then(|(_, state)| state.secure_channel.as_ref())
            .filter(|channel| channel.protocol == SecureChannelProtocol::Scp03);
        let resuming_scp03 = restored_scp03.is_some();
        let scp03 = if let Some(channel) = restored_scp03 {
            let config = SecureChannelConfig {
                protocol: SecureChannelProtocol::Scp03,
                security_domain: channel.security_domain.clone(),
                security_level: channel.security_level,
                credentials: None,
            };
            Some(SecureChannelSession::from_established(
                config,
                Scp03Engine::from_snapshot(channel.scp03.clone()),
            ))
        } else if secure_config.protocol == SecureChannelProtocol::Scp03 {
            let path = secure_config
                .credentials
                .as_deref()
                .ok_or("SCP03 requires --keyset/--credentials or APDU_KEYSET")?;
            let (keyset, warnings) = Scp03Keyset::load(path)?;
            for warning in warnings {
                writeln!(error_writer, "{warning}")?;
            }
            let profile = profile_override
                .or(keyset.profile)
                .unwrap_or(Scp03Profile::S16);
            let engine = Scp03Engine::new(keyset, profile);
            let mut session = SecureChannelSession::new(secure_config.clone(), engine)?;
            session.establish(&mut transport)?;
            if persist_new_channel {
                let (path, state) = persisted
                    .as_mut()
                    .ok_or("`scp03 open` requires an APDU session; run `apdu-tool atr` first")?;
                state.secure_channel = Some(PersistedSecureChannel {
                    protocol: SecureChannelProtocol::Scp03,
                    security_domain: secure_config.security_domain.clone(),
                    security_level: secure_config.security_level,
                    scp03: session.engine().snapshot()?,
                });
                session::save(path, state)?;
            }
            Some(session)
        } else {
            None
        };
        let scp11 = if matches!(
            secure_config.protocol,
            SecureChannelProtocol::Scp11a
                | SecureChannelProtocol::Scp11b
                | SecureChannelProtocol::Scp11c
        ) {
            let path = secure_config
                .credentials
                .as_deref()
                .ok_or("SCP11 requires --credentials or APDU_CREDENTIALS")?;
            let (credentials, warnings) = Scp11Credentials::load(path)?;
            for warning in warnings {
                writeln!(error_writer, "{warning}")?;
            }
            let engine = Scp11Engine::new(secure_config.protocol, credentials)?;
            let mut session = SecureChannelSession::new(secure_config.clone(), engine)?;
            session.establish(&mut transport)?;
            Some(session)
        } else {
            None
        };
        if secure_config.protocol == SecureChannelProtocol::Scp03
            && !resuming_scp03
            && !persist_new_channel
        {
            // The legacy global option remains a one-shot channel. Only the
            // explicit `scp03 open` command creates resumable state.
            persisted = None;
        }
        Ok(Self {
            transport,
            scp03,
            scp11,
            persisted,
            persistent_claimed,
        })
    }

    fn exchange(
        &mut self,
        command: &OwnedT0Command,
        on_null: &mut dyn FnMut(),
    ) -> ToolResult<T0Response> {
        if let Some(session) = &mut self.scp03 {
            if let Some((path, _)) = &self.persisted {
                // Once protection advances a MAC chain, an old on-disk copy
                // would be unsafe to reuse if transport or verification fails.
                if !self.persistent_claimed && !session::remove(path)? {
                    return Err(ApduToolError::new(
                        ErrorKind::SecureChannel,
                        "persisted SCP03 state is already in use or was invalidated",
                    ));
                }
                self.persistent_claimed = true;
            }
            let mut transport = ProgressTransport {
                client: &mut self.transport,
                on_null,
            };
            let response = session.exchange(&mut transport, command);
            if let Ok(verified_response) = &response {
                if let Some((path, state)) = &mut self.persisted {
                    let channel = state.secure_channel.as_mut().ok_or_else(|| {
                        ApduToolError::new(
                            ErrorKind::SecureChannel,
                            "missing persisted SCP03 state",
                        )
                    })?;
                    channel.scp03 = session.engine().snapshot()?;
                    if command.ins == 0xa4 && verified_response.status == (0x90, 0x00) {
                        state.selected_aid = Some(command.data.clone());
                    }
                    session::save(path, state)?;
                    self.persistent_claimed = false;
                }
            }
            response
        } else if let Some(session) = &mut self.scp11 {
            let mut transport = ProgressTransport {
                client: &mut self.transport,
                on_null,
            };
            session.exchange(&mut transport, command)
        } else {
            let response = self
                .transport
                .exchange_with_progress(command.as_borrowed(), on_null)?;
            if command.ins == 0xa4 && response.status == (0x90, 0x00) {
                if let Some((path, state)) = &mut self.persisted {
                    state.selected_aid = Some(command.data.clone());
                    session::save(path, state)?;
                }
            }
            Ok(response)
        }
    }

    fn max_plaintext_data(&self) -> ToolResult<usize> {
        if let Some(session) = &self.scp03 {
            session.max_plaintext_data(u8::MAX as usize)
        } else if let Some(session) = &self.scp11 {
            session.max_plaintext_data(u8::MAX as usize)
        } else {
            Ok(u8::MAX as usize)
        }
    }
}

struct ProgressTransport<'a, 'b> {
    client: &'a mut T0Client,
    on_null: &'b mut dyn FnMut(),
}

impl CommandTransport for ProgressTransport<'_, '_> {
    fn exchange_command(&mut self, command: &OwnedT0Command) -> ToolResult<T0Response> {
        self.client
            .exchange_with_progress(command.as_borrowed(), &mut self.on_null)
    }
}

impl<'a> Progress<'a> {
    fn new(enabled: bool, writer: &'a mut dyn Write) -> Self {
        Self {
            enabled,
            displayed: false,
            frame: 0,
            writer,
        }
    }

    fn tick(&mut self, label: &str) {
        if !self.enabled {
            return;
        }
        const FRAMES: [char; 4] = ['-', '\\', '|', '/'];
        let _ = write!(
            self.writer,
            "{label}{}\r",
            FRAMES[self.frame % FRAMES.len()]
        );
        let _ = self.writer.flush();
        self.frame = self.frame.wrapping_add(1);
        self.displayed = true;
    }

    fn clear(&mut self) {
        if !self.displayed {
            return;
        }
        let _ = write!(self.writer, "\r\x1b[2K");
        let _ = self.writer.flush();
        self.displayed = false;
    }
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<CliOptions, Box<dyn Error>> {
    let mut link = match environment_value(ENV_LINK)? {
        Some(value) => parse_link_spec(&value)?,
        None => default_link_spec(),
    };
    let mut verbose = 0u8;
    let mut progress = false;
    let mut quiet = false;
    let mut output = match environment_value(ENV_OUTPUT)? {
        Some(value) => OutputMode::parse(&value)?,
        None => OutputMode::Human,
    };
    let mut connect_timeout = match environment_value(ENV_CONNECT_TIMEOUT)? {
        Some(value) => parse_duration(&value)?,
        None => DEFAULT_CONNECT_TIMEOUT,
    };
    let mut atr_timeout = match environment_value(ENV_ATR_TIMEOUT)? {
        Some(value) => parse_optional_duration(&value)?,
        None => Some(DEFAULT_ATR_TIMEOUT),
    };
    let mut response_timeout = match environment_value(ENV_RESPONSE_TIMEOUT)? {
        Some(value) => parse_nonzero_duration(&value, ENV_RESPONSE_TIMEOUT)?,
        None => APDU_RESPONSE_TIMEOUT,
    };
    let mut retry_interval = match environment_value(ENV_RETRY_INTERVAL)? {
        Some(value) => parse_nonzero_duration(&value, ENV_RETRY_INTERVAL)?,
        None => DEFAULT_RETRY_INTERVAL,
    };
    let mut secure_channel = SecureChannelConfig {
        protocol: match environment_value(ENV_SECURE_CHANNEL)? {
            Some(value) => SecureChannelProtocol::parse(&value)?,
            None => SecureChannelProtocol::None,
        },
        security_domain: environment_value(ENV_SECURITY_DOMAIN)?
            .map(|value| parse_hex_text(&value))
            .transpose()?,
        security_level: match environment_value(ENV_SECURITY_LEVEL)? {
            Some(value) => SecurityLevel::parse(&value)?,
            None => SecurityLevel::None,
        },
        credentials: environment_value(ENV_CREDENTIALS)?
            .or(environment_value(ENV_KEYSET)?)
            .map(PathBuf::from),
    };
    let mut scp03_profile = environment_value(ENV_SCP03_PROFILE)?
        .map(|value| Scp03Profile::parse(&value))
        .transpose()?;
    let mut explicit_command = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-?" => {
                print_usage();
                std::process::exit(0);
            }
            "--verbose" | "-v" => {
                verbose = verbose.saturating_add(1);
            }
            "-vv" => {
                verbose = verbose.saturating_add(2);
            }
            "--progress" => {
                progress = true;
            }
            "--quiet" | "-q" => {
                quiet = true;
            }
            "--output" => {
                output = OutputMode::parse(&next_value(&mut args, &arg)?)?;
            }
            "--connect-timeout" => {
                connect_timeout = parse_duration(&next_value(&mut args, &arg)?)?;
            }
            "--atr-timeout" => {
                atr_timeout = parse_optional_duration(&next_value(&mut args, &arg)?)?;
            }
            "--response-timeout" => {
                response_timeout = parse_nonzero_duration(&next_value(&mut args, &arg)?, &arg)?;
            }
            "--retry-interval" => {
                retry_interval = parse_nonzero_duration(&next_value(&mut args, &arg)?, &arg)?;
            }
            "--serial" | "-s" => {
                let value = args.next().ok_or("missing value after --serial/-s")?;
                link = parse_link_spec(&value)?;
            }
            "--secure-channel" => {
                secure_channel.protocol =
                    SecureChannelProtocol::parse(&next_value(&mut args, &arg)?)?;
            }
            "--security-domain" => {
                secure_channel.security_domain =
                    Some(parse_hex_text(&next_value(&mut args, &arg)?)?);
            }
            "--security-level" => {
                secure_channel.security_level =
                    SecurityLevel::parse(&next_value(&mut args, &arg)?)?;
            }
            "--credentials" => {
                secure_channel.credentials = Some(PathBuf::from(next_value(&mut args, &arg)?));
            }
            "--keyset" => {
                secure_channel.credentials = Some(PathBuf::from(next_value(&mut args, &arg)?));
            }
            "--scp03-profile" => {
                scp03_profile = Some(Scp03Profile::parse(&next_value(&mut args, &arg)?)?);
            }
            _ if arg.starts_with("--serial=") => {
                link = parse_link_spec(&arg["--serial=".len()..])?;
            }
            _ if arg.starts_with("--connect-timeout=") => {
                connect_timeout = parse_duration(&arg["--connect-timeout=".len()..])?;
            }
            _ if arg.starts_with("--atr-timeout=") => {
                atr_timeout = parse_optional_duration(&arg["--atr-timeout=".len()..])?;
            }
            _ if arg.starts_with("--response-timeout=") => {
                response_timeout = parse_nonzero_duration(
                    &arg["--response-timeout=".len()..],
                    "--response-timeout",
                )?;
            }
            _ if arg.starts_with("--retry-interval=") => {
                retry_interval =
                    parse_nonzero_duration(&arg["--retry-interval=".len()..], "--retry-interval")?;
            }
            _ if arg.starts_with("--output=") => {
                output = OutputMode::parse(&arg["--output=".len()..])?;
            }
            _ if arg.starts_with("--secure-channel=") => {
                secure_channel.protocol =
                    SecureChannelProtocol::parse(&arg["--secure-channel=".len()..])?;
            }
            _ if arg.starts_with("--security-domain=") => {
                secure_channel.security_domain =
                    Some(parse_hex_text(&arg["--security-domain=".len()..])?);
            }
            _ if arg.starts_with("--security-level=") => {
                secure_channel.security_level =
                    SecurityLevel::parse(&arg["--security-level=".len()..])?;
            }
            _ if arg.starts_with("--credentials=") => {
                secure_channel.credentials = Some(PathBuf::from(&arg["--credentials=".len()..]));
            }
            _ if arg.starts_with("--keyset=") => {
                secure_channel.credentials = Some(PathBuf::from(&arg["--keyset=".len()..]));
            }
            _ if arg.starts_with("--scp03-profile=") => {
                scp03_profile = Some(Scp03Profile::parse(&arg["--scp03-profile=".len()..])?);
            }
            "atr" if explicit_command.is_none() => {
                explicit_command = Some(CliCommand::Atr);
            }
            "close" if explicit_command.is_none() => {
                explicit_command = Some(CliCommand::Close);
            }
            "select" if explicit_command.is_none() => {
                let select_args: Vec<String> = args.collect();
                if select_args.len() != 1 {
                    return Err("select expects exactly one application AID".into());
                }
                let aid = parse_hex_text(&select_args[0])?;
                if !(5..=16).contains(&aid.len()) {
                    return Err("application AID length must be in 5..=16".into());
                }
                explicit_command = Some(CliCommand::Select(aid));
                break;
            }
            "scp03" if explicit_command.is_none() => {
                let subcommand_args: Vec<String> = args.collect();
                explicit_command = Some(parse_scp03_command(
                    &subcommand_args,
                    &mut secure_channel,
                    &mut scp03_profile,
                )?);
                break;
            }
            "raw" if explicit_command.is_none() => {
                let raw_args: Vec<String> = args.collect();
                if raw_args.iter().any(|arg| arg == "--help" || arg == "-?") {
                    print_raw_usage();
                    std::process::exit(0);
                }
                explicit_command = Some(CliCommand::Raw(parse_raw_command(raw_args)?));
                break;
            }
            "gp" if explicit_command.is_none() => {
                explicit_command = Some(parse_gp_command(args.collect())?);
                break;
            }
            _ if explicit_command.is_some() => {
                return Err(format!("unexpected argument after `atr`: {arg}").into());
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}").into()),
            _ => {
                return Err(
                    format!("unknown command `{arg}`; expected `atr`, `close`, `scp03`, `select`, `raw` or `gp`").into(),
                )
            }
        }
    }

    let command = explicit_command
        .ok_or("missing command; expected `atr`, `close`, `scp03`, `select`, `raw` or `gp`")?;
    secure_channel.validate()?;
    if scp03_profile.is_some() && secure_channel.protocol != SecureChannelProtocol::Scp03 {
        return Err("--scp03-profile/APDU_SCP03_PROFILE requires --secure-channel scp03".into());
    }

    Ok(CliOptions {
        link,
        verbose,
        progress,
        quiet,
        output,
        connect_timeout,
        atr_timeout,
        response_timeout,
        retry_interval,
        secure_channel,
        scp03_profile,
        command,
    })
}

fn parse_scp03_command(
    args: &[String],
    secure_channel: &mut SecureChannelConfig,
    profile: &mut Option<Scp03Profile>,
) -> Result<CliCommand, Box<dyn Error>> {
    let Some((name, options)) = args.split_first() else {
        return Err("scp03 expects `open`, `inspect` or `close`".into());
    };
    match name.as_str() {
        "inspect" if options.is_empty() => Ok(CliCommand::Scp03Inspect),
        "close" if options.is_empty() => Ok(CliCommand::Scp03Close),
        "inspect" | "close" => Err(format!("scp03 {name} takes no options").into()),
        "open" => {
            secure_channel.protocol = SecureChannelProtocol::Scp03;
            let mut index = 0;
            while index < options.len() {
                let option = &options[index];
                let value = |index: &mut usize| -> Result<&str, Box<dyn Error>> {
                    *index += 1;
                    options
                        .get(*index)
                        .map(String::as_str)
                        .ok_or_else(|| format!("missing value after {option}").into())
                };
                match option.as_str() {
                    "--security-domain" => {
                        secure_channel.security_domain = Some(parse_hex_text(value(&mut index)?)?);
                    }
                    "--security-level" => {
                        secure_channel.security_level = SecurityLevel::parse(value(&mut index)?)?;
                    }
                    "--credentials" | "--keyset" => {
                        secure_channel.credentials = Some(PathBuf::from(value(&mut index)?));
                    }
                    "--scp03-profile" => {
                        *profile = Some(Scp03Profile::parse(value(&mut index)?)?);
                    }
                    _ if option.starts_with("--security-domain=") => {
                        secure_channel.security_domain =
                            Some(parse_hex_text(&option["--security-domain=".len()..])?);
                    }
                    _ if option.starts_with("--security-level=") => {
                        secure_channel.security_level =
                            SecurityLevel::parse(&option["--security-level=".len()..])?;
                    }
                    _ if option.starts_with("--credentials=") => {
                        secure_channel.credentials =
                            Some(PathBuf::from(&option["--credentials=".len()..]));
                    }
                    _ if option.starts_with("--keyset=") => {
                        secure_channel.credentials =
                            Some(PathBuf::from(&option["--keyset=".len()..]));
                    }
                    _ if option.starts_with("--scp03-profile=") => {
                        *profile = Some(Scp03Profile::parse(&option["--scp03-profile=".len()..])?);
                    }
                    _ => return Err(format!("unknown scp03 open option: {option}").into()),
                }
                index += 1;
            }
            Ok(CliCommand::Scp03Open)
        }
        _ => Err(format!("unknown SCP03 command `{name}`").into()),
    }
}

fn environment_value(name: &str) -> Result<Option<String>, Box<dyn Error>> {
    let Some(value) = env::var_os(name) else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| format!("environment variable {name} is not valid UTF-8"))?;
    if value.is_empty() {
        return Err(format!("environment variable {name} must not be empty").into());
    }
    Ok(Some(value))
}

fn run(options: CliOptions) -> Result<RunOutcome, Box<dyn Error>> {
    let stdout = io::stdout();
    let stderr = io::stderr();
    run_with_writers(options, &mut stdout.lock(), &mut stderr.lock())
}

fn emit_session_action(
    writer: &mut dyn Write,
    output: OutputMode,
    quiet: bool,
    event: &str,
    message: &str,
) -> Result<(), Box<dyn Error>> {
    if quiet || output == OutputMode::Bin {
        return Ok(());
    }
    if output == OutputMode::Json {
        serde_json::to_writer(
            &mut *writer,
            &serde_json::json!({
                "type": "session",
                "event": event,
                "message": message,
            }),
        )?;
        writeln!(writer)?;
    } else {
        writeln!(writer, "{message}")?;
    }
    Ok(())
}

fn emit_session_inspection(
    writer: &mut dyn Write,
    output: OutputMode,
    quiet: bool,
    path: &std::path::Path,
    state: &SessionFile,
) -> Result<(), Box<dyn Error>> {
    if quiet || output == OutputMode::Bin {
        return Ok(());
    }
    let protocol = format!("{:?}", state.protocol()).to_ascii_lowercase();
    let selected = state.selected_aid.as_deref().map(format_hex);
    let security_level = state
        .secure_channel
        .as_ref()
        .map(|channel| format!("{:02X}", channel.security_level.bits()));
    if output == OutputMode::Json {
        serde_json::to_writer(
            &mut *writer,
            &serde_json::json!({
                "type": "session",
                "path": path,
                "link": state.link,
                "atr": format_hex(&state.atr),
                "secure_channel": protocol,
                "security_level": security_level,
                "selected_aid": selected,
            }),
        )?;
        writeln!(writer)?;
    } else {
        writeln!(writer, "Session file : {}", path.display())?;
        writeln!(writer, "Link : {:?}", state.link)?;
        writeln!(writer, "ATR : {}", format_hex(&state.atr))?;
        writeln!(writer, "Secure Channel : {protocol}")?;
        if let Some(level) = security_level {
            writeln!(writer, "Security level : {level}")?;
        }
        writeln!(
            writer,
            "Selected AID : {}",
            selected.as_deref().unwrap_or("none")
        )?;
    }
    Ok(())
}

fn run_with_writers(
    options: CliOptions,
    output_writer: &mut dyn Write,
    error_writer: &mut dyn Write,
) -> Result<RunOutcome, Box<dyn Error>> {
    let config = T0ClientConfig {
        silence_timeout: options.response_timeout,
        ..T0ClientConfig::default()
    };
    let show_progress = options.progress && !options.quiet && options.output != OutputMode::Bin;
    let secure_config = options.secure_channel.clone();
    let scp03_profile = options.scp03_profile;
    let command_spec = match options.command {
        CliCommand::Atr => {
            let mut client = connect_with_retry(
                &options.link,
                config,
                options.connect_timeout,
                options.retry_interval,
            )?;
            let atr_result = {
                let mut progress = Progress::new(show_progress, error_writer);
                let result = client.read_frame_until_with_progress(options.atr_timeout, || {
                    progress.tick("waiting ATR...");
                });
                progress.clear();
                result
            };
            let atr = atr_result?;
            if atr.is_empty() {
                return Err(ApduToolError::new(
                    ErrorKind::SecureElementSilent,
                    "link opened, but the Secure Element did not send an ATR before the timeout",
                )
                .into());
            }
            let session_path = session::path_from_environment()?;
            session::save(
                &session_path,
                &SessionFile::new(options.link.clone(), atr.clone()),
            )?;
            writeln!(
                error_writer,
                "WARNING: {} contains security-critical session state; keep it private and use `apdu-tool close` when finished",
                session_path.display()
            )?;
            emit_atr(output_writer, &atr, options.output, options.quiet)?;
            if options.verbose > 0 && !options.quiet && options.output == OutputMode::Human {
                for line in atr_verbose_lines(&atr) {
                    writeln!(error_writer, "{line}")?;
                }
            }
            return Ok(RunOutcome { status: None });
        }
        CliCommand::Close => {
            let path = session::path_from_environment()?;
            let removed = session::remove(&path)?;
            emit_session_action(
                output_writer,
                options.output,
                options.quiet,
                "session-closed",
                if removed {
                    "APDU session closed"
                } else {
                    "no APDU session was open"
                },
            )?;
            return Ok(RunOutcome { status: None });
        }
        CliCommand::Scp03Inspect => {
            let path = session::path_from_environment()?;
            let state = session::load(&path)?;
            emit_session_inspection(output_writer, options.output, options.quiet, &path, &state)?;
            return Ok(RunOutcome { status: None });
        }
        CliCommand::Scp03Close => {
            let path = session::path_from_environment()?;
            let mut state = session::load(&path)?;
            let had_channel = state.secure_channel.take().is_some();
            session::save(&path, &state)?;
            emit_session_action(
                output_writer,
                options.output,
                options.quiet,
                "scp03-closed",
                if had_channel {
                    "SCP03 host state erased; APDU session remains open"
                } else {
                    "no SCP03 channel was open"
                },
            )?;
            return Ok(RunOutcome { status: None });
        }
        CliCommand::Scp03Open => {
            let path = session::path_from_environment()?;
            let state = session::load(&path)?;
            if state.secure_channel.is_some() {
                return Err(
                    "a Secure Channel is already open; run `apdu-tool scp03 close` first".into(),
                );
            }
            drop(state);
            let client = CliClient::open_persistent_scp03(
                &options.link,
                config,
                &secure_config,
                scp03_profile,
                error_writer,
            )?;
            if client.scp03.is_none() {
                return Err("SCP03 establishment did not produce a session".into());
            }
            emit_session_action(
                output_writer,
                options.output,
                options.quiet,
                "scp03-opened",
                "SCP03 channel opened and persisted",
            )?;
            return Ok(RunOutcome { status: None });
        }
        CliCommand::Select(aid) => OwnedT0Command::from_wire_fields(
            0x00,
            0xa4,
            0x04,
            0x00,
            aid.len().try_into()?,
            0x00,
            aid,
        )?,
        CliCommand::Raw(command) => command,
        CliCommand::GpMutation(command) => command,
        CliCommand::GpGetData(gp_options) => {
            return run_gp_get_data(
                &gp_options,
                config,
                &options.link,
                options.output,
                options.quiet,
                show_progress,
                output_writer,
                error_writer,
                &secure_config,
                scp03_profile,
            );
        }
        CliCommand::GpGetStatus(gp_options) => {
            return run_gp_get_status(
                &gp_options,
                config,
                &options.link,
                options.output,
                options.quiet,
                show_progress,
                output_writer,
                error_writer,
                &secure_config,
                scp03_profile,
            );
        }
        CliCommand::GpPutKey(gp_options) => {
            return run_gp_put_key(
                &gp_options,
                config,
                &options.link,
                options.output,
                options.quiet,
                show_progress,
                output_writer,
                error_writer,
                &secure_config,
                scp03_profile,
            );
        }
        CliCommand::GpLoad(gp_options) => {
            return run_gp_load(
                &gp_options,
                config,
                &options.link,
                options.output,
                options.quiet,
                show_progress,
                output_writer,
                error_writer,
                &secure_config,
                scp03_profile,
            );
        }
    };

    // Command modes deliberately connect once and transmit without reading an ATR.
    let mut client = CliClient::connect(
        &options.link,
        config,
        &secure_config,
        scp03_profile,
        error_writer,
    )?;

    if !options.quiet && options.output == OutputMode::Human {
        emit_human_command(output_writer, &command_spec)?;
    }
    if options.verbose > 0 && !options.quiet && options.output == OutputMode::Human {
        for line in render_command(&command_spec, options.verbose) {
            writeln!(error_writer, "{line}")?;
        }
    }
    let response_result = {
        let mut progress = Progress::new(show_progress, error_writer);
        let result = client.exchange(&command_spec, &mut || progress.tick("waiting RESPONSE..."));
        progress.clear();
        result
    };
    let response = response_result?;
    emit_response(
        output_writer,
        error_writer,
        &command_spec,
        &response,
        options.output,
        options.quiet,
    )?;

    Ok(RunOutcome {
        status: Some(response.status),
    })
}

#[allow(clippy::too_many_arguments)]
fn run_gp_put_key(
    options: &GpPutKeyOptions,
    config: T0ClientConfig,
    link: &LinkSpec,
    output: OutputMode,
    quiet: bool,
    show_progress: bool,
    output_writer: &mut dyn Write,
    error_writer: &mut dyn Write,
    secure_config: &SecureChannelConfig,
    scp03_profile: Option<Scp03Profile>,
) -> Result<RunOutcome, Box<dyn Error>> {
    for warning in &options.warnings {
        writeln!(error_writer, "{warning}")?;
    }
    if !quiet && output == OutputMode::Human {
        for (name, byte, comment) in [
            ("CLA", options.command.cla, "GlobalPlatform command"),
            ("INS", options.command.ins, "GlobalPlatform PUT KEY"),
            ("P1", options.command.p1, "key version"),
            (
                "P2",
                options.command.p2,
                "first key identifier and multiple-key flag",
            ),
            ("LC", options.command.lc, "redacted key payload length"),
            ("LE", options.command.le, "expected response length"),
        ] {
            write_colored(output_writer, &[byte], ANSI_PINK)?;
            writeln!(output_writer, " # {name} : {comment}")?;
        }
        writeln!(output_writer, "[REDACTED] # Key material")?;
    }
    let mut client = CliClient::connect(link, config, secure_config, scp03_profile, error_writer)?;
    let response =
        exchange_with_cli_progress(&mut client, &options.command, show_progress, error_writer)?;
    let mut redacted = options.command.clone();
    redacted.data.clear();
    emit_response(
        output_writer,
        error_writer,
        &redacted,
        &response,
        output,
        quiet,
    )?;
    Ok(RunOutcome {
        status: Some(response.status),
    })
}

#[allow(clippy::too_many_arguments)]
fn run_gp_get_data(
    options: &GpGetDataOptions,
    config: T0ClientConfig,
    link: &LinkSpec,
    output: OutputMode,
    quiet: bool,
    show_progress: bool,
    output_writer: &mut dyn Write,
    error_writer: &mut dyn Write,
    secure_config: &SecureChannelConfig,
    scp03_profile: Option<Scp03Profile>,
) -> Result<RunOutcome, Box<dyn Error>> {
    let command = gp_get_data_command(options.tag);
    let mut client = CliClient::connect(link, config, secure_config, scp03_profile, error_writer)?;
    let data_only = options.format == GpDataFormat::Binary || options.output.is_some();
    if !quiet && !data_only && output == OutputMode::Human {
        emit_human_command(output_writer, &command)?;
    }
    let response = exchange_with_cli_progress(
        &mut client,
        &command,
        show_progress && options.format != GpDataFormat::Binary,
        error_writer,
    )?;
    if options.format == GpDataFormat::Tlv
        && !response.data.is_empty()
        && parse_tlv_lines(&response.data).is_none()
    {
        return Err(ApduToolError::new(
            ErrorKind::T0Protocol,
            "GET DATA response is not valid BER-TLV",
        )
        .into());
    }
    if let Some(path) = &options.output {
        std::fs::write(path, &response.data)?;
        if response.status != (0x90, 0x00) {
            writeln!(
                error_writer,
                "SW: {:02X} {:02X}",
                response.status.0, response.status.1
            )?;
        }
    } else {
        let effective_output = if options.format == GpDataFormat::Binary {
            OutputMode::Bin
        } else {
            output
        };
        if !quiet && effective_output == OutputMode::Human && options.format == GpDataFormat::Tlv {
            emit_gp_tlv_human(output_writer, &response.data, 0)?;
            write_colored(
                output_writer,
                &[response.status.0, response.status.1],
                if response.status == (0x90, 0x00) {
                    ANSI_GREEN
                } else {
                    ANSI_RED
                },
            )?;
            writeln!(
                output_writer,
                " # Status Word : {}",
                status_word_description(response.status)
            )?;
        } else {
            emit_response(
                output_writer,
                error_writer,
                &command,
                &response,
                effective_output,
                quiet,
            )?;
        }
    }
    Ok(RunOutcome {
        status: Some(response.status),
    })
}

#[allow(clippy::too_many_arguments)]
fn run_gp_get_status(
    options: &GpGetStatusOptions,
    config: T0ClientConfig,
    link: &LinkSpec,
    output: OutputMode,
    quiet: bool,
    show_progress: bool,
    output_writer: &mut dyn Write,
    error_writer: &mut dyn Write,
    secure_config: &SecureChannelConfig,
    scp03_profile: Option<Scp03Profile>,
) -> Result<RunOutcome, Box<dyn Error>> {
    let mut client = CliClient::connect(link, config, secure_config, scp03_profile, error_writer)?;
    let first_command = gp_get_status_command(options, false);
    let mut command = first_command.clone();
    let mut all_data = Vec::new();
    let final_status = loop {
        if !quiet && output == OutputMode::Human {
            emit_human_command(output_writer, &command)?;
        }
        let response =
            exchange_with_cli_progress(&mut client, &command, show_progress, error_writer)?;
        all_data.extend_from_slice(&response.data);
        if response.status != gp::SW_MORE_STATUS_DATA {
            break response.status;
        }
        command = gp_get_status_command(options, true);
    };
    let response = T0Response {
        data: all_data,
        status: final_status,
    };
    if !quiet && output == OutputMode::Human && final_status == (0x90, 0x00) {
        emit_gp_status_human(output_writer, options.category, &response.data)?;
        write_colored(output_writer, &[0x90, 0x00], ANSI_GREEN)?;
        writeln!(output_writer, " # Status Word : Success")?;
    } else if !quiet && output == OutputMode::Json && final_status == (0x90, 0x00) {
        emit_gp_status_json(
            output_writer,
            &first_command,
            options.category,
            &response.data,
        )?;
    } else {
        emit_response(
            output_writer,
            error_writer,
            &first_command,
            &response,
            output,
            quiet,
        )?;
    }
    Ok(RunOutcome {
        status: Some(final_status),
    })
}

#[allow(clippy::too_many_arguments)]
fn run_gp_load(
    options: &GpLoadOptions,
    config: T0ClientConfig,
    link: &LinkSpec,
    output: OutputMode,
    quiet: bool,
    show_progress: bool,
    output_writer: &mut dyn Write,
    error_writer: &mut dyn Write,
    secure_config: &SecureChannelConfig,
    scp03_profile: Option<Scp03Profile>,
) -> Result<RunOutcome, Box<dyn Error>> {
    let mut client = CliClient::connect(link, config, secure_config, scp03_profile, error_writer)?;
    let chunk_size = client.max_plaintext_data()?;
    let load_file = gp::encode_load_file_data_block(&options.fae)?;
    let block_count = load_block_count(load_file.len(), chunk_size)?;
    let security_domain = if let Some(aid) = &secure_config.security_domain {
        aid.clone()
    } else {
        let discovery = gp::get_status(gp::StatusCategory::IssuerSecurityDomain, false, &[])?;
        let response =
            exchange_with_cli_progress(&mut client, &discovery, show_progress, error_writer)?;
        if !matches!(response.status, (0x90, 0x00) | gp::SW_MORE_STATUS_DATA) {
            emit_response(
                output_writer,
                error_writer,
                &discovery,
                &response,
                output,
                quiet,
            )?;
            return Ok(RunOutcome {
                status: Some(response.status),
            });
        }
        gp::decode_status(&response.data)?
            .into_iter()
            .next()
            .map(|record| record.aid)
            .ok_or("GET STATUS did not return an Issuer Security Domain AID")?
    };
    let hash = Sha256::digest(&options.fae);
    let install_for_load = gp::install_for_load_with_parameters(
        &options.package_aid,
        &security_domain,
        &hash,
        &options.metadata.size.to_be_bytes(),
        &[],
    )?;
    let response =
        exchange_with_cli_progress(&mut client, &install_for_load, show_progress, error_writer)?;
    if response.status != (0x90, 0x00) {
        emit_response(
            output_writer,
            error_writer,
            &install_for_load,
            &response,
            output,
            quiet,
        )?;
        return Ok(RunOutcome {
            status: Some(response.status),
        });
    }

    let mut last_command = install_for_load;
    let mut last_response = response;
    for (index, chunk) in load_file.chunks(chunk_size).enumerate() {
        let end = (index * chunk_size) + chunk.len();
        if show_progress {
            writeln!(
                error_writer,
                "LOAD block {}/{}: {}/{} bytes",
                index + 1,
                block_count,
                end,
                load_file.len()
            )?;
        }
        let command = gp::load_block(index as u8, index + 1 == block_count, chunk)?;
        let response =
            exchange_with_cli_progress(&mut client, &command, show_progress, error_writer)?;
        if response.status != (0x90, 0x00) {
            writeln!(
                error_writer,
                "LOAD stopped at block {index} after {}/{} bytes",
                index * chunk_size,
                options.fae.len()
            )?;
            emit_response(
                output_writer,
                error_writer,
                &command,
                &response,
                output,
                quiet,
            )?;
            return Ok(RunOutcome {
                status: Some(response.status),
            });
        }
        last_command = command;
        last_response = response;
    }

    if let Some(instance_aid) = &options.instance_aid {
        let install = gp::install_and_make_selectable(
            &options.package_aid,
            &options.package_aid,
            instance_aid,
            &[],
            &options.install_parameters,
        )?;
        let response =
            exchange_with_cli_progress(&mut client, &install, show_progress, error_writer)?;
        emit_response(
            output_writer,
            error_writer,
            &install,
            &response,
            output,
            quiet,
        )?;
        Ok(RunOutcome {
            status: Some(response.status),
        })
    } else {
        emit_response(
            output_writer,
            error_writer,
            &last_command,
            &last_response,
            output,
            quiet,
        )?;
        Ok(RunOutcome {
            status: Some(last_response.status),
        })
    }
}

fn load_block_count(fae_len: usize, chunk_size: usize) -> Result<usize, Box<dyn Error>> {
    if chunk_size == 0 {
        return Err("Secure Channel leaves no room for LOAD data".into());
    }
    let block_count = fae_len.div_ceil(chunk_size);
    if block_count > 256 {
        return Err(format!(
            "FAE requires {block_count} LOAD blocks; short GP block numbering permits at most 256"
        )
        .into());
    }
    Ok(block_count)
}

fn exchange_with_cli_progress(
    client: &mut CliClient,
    command: &OwnedT0Command,
    enabled: bool,
    error_writer: &mut dyn Write,
) -> ToolResult<T0Response> {
    let mut progress = Progress::new(enabled, error_writer);
    let result = client.exchange(command, &mut || progress.tick("waiting RESPONSE..."));
    progress.clear();
    result
}

fn gp_tag_name(tag: u32) -> &'static str {
    match tag {
        0x66 => "Card Recognition Data",
        0x67 => "Card Capability Information",
        0x73 => "Card Recognition Data template",
        0x60 => "Card management type and version",
        0x63 => "Card identification scheme",
        0x64 => "Secure Channel protocol",
        0x06 => "Object Identifier",
        0xA0 => "Secure Channel capability",
        0x80 => "Secure Channel protocol identifier",
        0x81 => "Secure Channel option(s)",
        0x82 => "Supported key type(s)",
        0x83 => "Load-file data block hash algorithm",
        0x84 => "Privilege field width",
        0x9F70 => "Life cycle state",
        _ => "GlobalPlatform data object",
    }
}

fn emit_gp_tlv_human(
    writer: &mut dyn Write,
    data: &[u8],
    depth: usize,
) -> Result<(), Box<dyn Error>> {
    let mut offset = 0;
    while offset < data.len() {
        let start = offset;
        let (tag, value) = gp::read_tlv(data, &mut offset).ok_or("malformed BER-TLV data")?;
        let header_len = offset - start - value.len();
        write!(writer, "{}", "  ".repeat(depth))?;
        write_colored(writer, &data[start..start + header_len], ANSI_PINK)?;
        writeln!(
            writer,
            " # TL : tag {tag:X}, length {} — {}",
            value.len(),
            gp_tag_name(tag)
        )?;
        let constructed = data[start] & 0x20 != 0;
        if constructed {
            emit_gp_tlv_human(writer, value, depth + 1)?;
        } else if !value.is_empty() {
            write!(writer, "{}", "  ".repeat(depth + 1))?;
            write_colored(writer, value, ANSI_BLUE)?;
            writeln!(writer, " # {}", gp_tag_name(tag))?;
        }
    }
    Ok(())
}

fn decode_gp_status_records(data: &[u8]) -> Result<Vec<gp::StatusRecord>, Box<dyn Error>> {
    Ok(gp::decode_status(data)?)
}

fn gp_category_name(category: GpStatusCategory) -> &'static str {
    category.name()
}

fn lifecycle_name(value: u8) -> &'static str {
    match value {
        0x01 => "loaded",
        0x03 => "installed",
        0x07 => "selectable",
        0x7F | 0x80 => "locked",
        _ => "profile-specific",
    }
}

fn privilege_names(bytes: &[u8]) -> String {
    let Some(first) = bytes.first().copied() else {
        return "none".to_owned();
    };
    let names = [
        (0x80, "Security Domain"),
        (0x40, "DAP verification"),
        (0x20, "delegated management"),
        (0x10, "card lock"),
        (0x08, "card terminate"),
        (0x04, "card reset"),
        (0x02, "CVM management"),
        (0x01, "mandated DAP"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (first & bit != 0).then_some(name))
    .collect::<Vec<_>>();
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }
}

fn emit_gp_status_human(
    writer: &mut dyn Write,
    category: GpStatusCategory,
    data: &[u8],
) -> Result<(), Box<dyn Error>> {
    for (index, record) in decode_gp_status_records(data)?.iter().enumerate() {
        writeln!(
            writer,
            "{} # {} : {}",
            index + 1,
            gp_category_name(category),
            format_hex(&record.aid)
        )?;
        if let Some(value) = record.lifecycle {
            writeln!(
                writer,
                "  {value:02X} # Life cycle : {}",
                lifecycle_name(value)
            )?;
        }
        if !record.privileges.is_empty() {
            writeln!(
                writer,
                "  {} # Privileges : {}",
                format_hex(&record.privileges),
                privilege_names(&record.privileges)
            )?;
        }
        if !record.module_aid.is_empty() {
            writeln!(writer, "  {} # Module AID", format_hex(&record.module_aid))?;
        }
        if !record.package_aid.is_empty() {
            writeln!(
                writer,
                "  {} # Package AID",
                format_hex(&record.package_aid)
            )?;
        }
        if !record.parent_security_domain_aid.is_empty() {
            writeln!(
                writer,
                "  {} # Parent Security Domain AID",
                format_hex(&record.parent_security_domain_aid)
            )?;
        }
    }
    Ok(())
}

fn emit_gp_status_json(
    writer: &mut dyn Write,
    command: &OwnedT0Command,
    category: GpStatusCategory,
    data: &[u8],
) -> Result<(), Box<dyn Error>> {
    let records = decode_gp_status_records(data)?;
    write!(
        writer,
        "{{\"kind\":\"gp-get-status\",\"command\":{{\"name\":\"{}\",\"cla\":\"{:02X}\",\"ins\":\"{:02X}\",\"p1\":\"{:02X}\",\"p2\":\"{:02X}\",\"lc\":{},\"le\":{},\"data\":\"{}\"}},\"category\":\"{}\",\"records\":[",
        json_escape(&command_name(command)), command.cla, command.ins, command.p1, command.p2,
        command.lc, command.le, format_hex_compact(&command.data), json_escape(gp_category_name(category))
    )?;
    for (index, record) in records.iter().enumerate() {
        if index != 0 {
            write!(writer, ",")?;
        }
        let lifecycle = record.lifecycle.map_or("null".to_owned(), |value| {
            format!(
                "{{\"value\":\"{value:02X}\",\"name\":\"{}\"}}",
                lifecycle_name(value)
            )
        });
        write!(writer, "{{\"aid\":\"{}\",\"lifecycle\":{},\"privileges\":{{\"bytes\":\"{}\",\"names\":\"{}\"}},\"package_aid\":\"{}\",\"module_aid\":\"{}\",\"parent_security_domain_aid\":\"{}\"}}", format_hex_compact(&record.aid), lifecycle, format_hex_compact(&record.privileges), json_escape(&privilege_names(&record.privileges)), format_hex_compact(&record.package_aid), format_hex_compact(&record.module_aid), format_hex_compact(&record.parent_security_domain_aid))?;
    }
    writeln!(writer, "],\"status_word\":\"9000\",\"success\":true}}")?;
    Ok(())
}

fn connect_with_retry(
    link: &LinkSpec,
    config: T0ClientConfig,
    timeout: Duration,
    retry_interval: Duration,
) -> ToolResult<T0Client> {
    retry_until(timeout, retry_interval, || T0Client::connect(link, config))
}

fn retry_until<T>(
    timeout: Duration,
    retry_interval: Duration,
    mut operation: impl FnMut() -> ToolResult<T>,
) -> ToolResult<T> {
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        ApduToolError::new(ErrorKind::InvalidInput, "connection timeout is too large")
    })?;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(error);
                }
                thread::sleep(retry_interval.min(remaining));
            }
        }
    }
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("missing value after {option}").into())
}

fn parse_optional_duration(value: &str) -> Result<Option<Duration>, Box<dyn Error>> {
    if value.eq_ignore_ascii_case("infinite") {
        return Ok(None);
    }
    Ok(Some(parse_nonzero_duration(value, "--atr-timeout")?))
}

fn parse_nonzero_duration(value: &str, option: &str) -> Result<Duration, Box<dyn Error>> {
    let duration = parse_duration(value)?;
    if duration.is_zero() {
        return Err(format!("{option} must be greater than zero").into());
    }
    Ok(duration)
}

fn parse_duration(value: &str) -> Result<Duration, Box<dyn Error>> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1u128)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000u128)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000u128)
    } else {
        return Err(format!("invalid duration `{value}`; expected <n>ms, <n>s or <n>m").into());
    };
    let amount: u128 = number
        .parse()
        .map_err(|error| format!("invalid duration `{value}`: {error}"))?;
    let millis = amount
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration `{value}` is too large"))?;
    let millis = u64::try_from(millis).map_err(|_| format!("duration `{value}` is too large"))?;
    Ok(Duration::from_millis(millis))
}

fn requested_output_mode(args: &[String]) -> OutputMode {
    for (index, arg) in args.iter().enumerate() {
        if let Some(value) = arg.strip_prefix("--output=") {
            return OutputMode::parse(value).unwrap_or(OutputMode::Human);
        }
        if arg == "--output" {
            return args
                .get(index + 1)
                .and_then(|value| OutputMode::parse(value).ok())
                .unwrap_or(OutputMode::Human);
        }
    }
    env::var(ENV_OUTPUT)
        .ok()
        .and_then(|value| OutputMode::parse(&value).ok())
        .unwrap_or(OutputMode::Human)
}

fn error_exit_code(error: &ApduToolError) -> i32 {
    match error.kind() {
        ErrorKind::InvalidInput => 2,
        ErrorKind::Connection => 10,
        ErrorKind::SecureElementSilent => 11,
        ErrorKind::Desynchronization => 12,
        ErrorKind::T0Protocol => 13,
        ErrorKind::SecureChannel => 14,
        ErrorKind::StatusWord => 15,
    }
}

fn emit_error(mode: OutputMode, error: &(dyn Error + 'static)) {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let _ = emit_error_to(mode, error, &mut stdout.lock(), &mut stderr.lock());
}

fn emit_error_to(
    mode: OutputMode,
    error: &(dyn Error + 'static),
    output_writer: &mut dyn Write,
    error_writer: &mut dyn Write,
) -> io::Result<()> {
    match mode {
        OutputMode::Json => writeln!(
            output_writer,
            "{{\"success\":false,\"error\":\"{}\"}}",
            json_escape(&error.to_string())
        ),
        OutputMode::Human | OutputMode::Color => {
            writeln!(error_writer, "{ANSI_RED}Error: {error}{ANSI_RESET}")
        }
        OutputMode::Bin => writeln!(error_writer, "Error: {error}"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SemanticLine {
    start: usize,
    end: usize,
    metadata: bool,
    comment: String,
}

fn emit_atr(writer: &mut dyn Write, atr: &[u8], mode: OutputMode, quiet: bool) -> io::Result<()> {
    if quiet {
        return writeln!(writer, "{}", format_hex(atr));
    }
    match mode {
        OutputMode::Bin => writer.write_all(atr),
        OutputMode::Color => {
            emit_colored_lines(writer, atr, &atr_semantic_lines(atr))?;
            writeln!(writer)
        }
        OutputMode::Human => emit_human_atr(writer, atr),
        OutputMode::Json => writeln!(
            writer,
            "{{\"kind\":\"atr\",\"command\":\"atr\",\"bytes\":\"{}\",\"length\":{},\"success\":true}}",
            format_hex_compact(atr),
            atr.len()
        ),
    }
}

fn emit_response(
    writer: &mut dyn Write,
    error_writer: &mut dyn Write,
    command: &OwnedT0Command,
    response: &T0Response,
    mode: OutputMode,
    quiet: bool,
) -> io::Result<()> {
    let success = response.status == (0x90, 0x00);
    if quiet {
        let mut raw = response.data.clone();
        raw.extend_from_slice(&[response.status.0, response.status.1]);
        return writeln!(writer, "{}", format_hex(&raw));
    }
    match mode {
        OutputMode::Bin => {
            writer.write_all(&response.data)?;
            if !success {
                writeln!(
                    error_writer,
                    "SW: {:02X} {:02X}",
                    response.status.0, response.status.1
                )?;
            }
            Ok(())
        }
        OutputMode::Color => {
            emit_colored_data(writer, &response.data)?;
            if !response.data.is_empty() {
                write!(writer, " ")?;
            }
            write_colored(
                writer,
                &[response.status.0, response.status.1],
                if success { ANSI_GREEN } else { ANSI_RED },
            )?;
            writeln!(writer)
        }
        OutputMode::Human => {
            emit_human_data(writer, &response.data)?;
            write_colored(
                writer,
                &[response.status.0, response.status.1],
                if success { ANSI_GREEN } else { ANSI_RED },
            )?;
            writeln!(
                writer,
                " # Status Word : {}",
                status_word_description(response.status)
            )
        }
        OutputMode::Json => writeln!(
            writer,
            "{{\"kind\":\"response\",\"command\":{{\"name\":\"{}\",\"cla\":\"{:02X}\",\"ins\":\"{:02X}\",\"p1\":\"{:02X}\",\"p2\":\"{:02X}\",\"lc\":{},\"le\":{},\"data\":\"{}\"}},\"data\":\"{}\",\"length\":{},\"status_word\":\"{:02X}{:02X}\",\"status\":\"{}\",\"success\":{}}}",
            json_escape(&command_name(command)),
            command.cla,
            command.ins,
            command.p1,
            command.p2,
            command.lc,
            command.le,
            format_hex_compact(&command.data),
            format_hex_compact(&response.data),
            response.data.len(),
            response.status.0,
            response.status.1,
            json_escape(status_word_description(response.status)),
            success
        ),
    }
}

fn emit_human_command(writer: &mut dyn Write, command: &OwnedT0Command) -> io::Result<()> {
    let bytes = command.display_bytes();
    for field in decode_command_fields(command) {
        let color = if is_command_data_field(field.name) {
            ANSI_BLUE
        } else {
            ANSI_PINK
        };
        write_colored(
            writer,
            &bytes[field.span.start..field.span.start + field.span.len],
            color,
        )?;
        writeln!(writer, " # {} : {}", field.name, field.description)?;
    }
    Ok(())
}

fn is_command_data_field(name: &str) -> bool {
    matches!(name, "DATA" | "AID")
        || name.ends_with("_AID")
        || matches!(
            name,
            "PRIVILEGES" | "INSTALL_PARAMS" | "LOAD_FILE_HASH" | "LOAD_PARAMS" | "LOAD_TOKEN"
        )
}

fn emit_human_atr(writer: &mut dyn Write, atr: &[u8]) -> io::Result<()> {
    for line in atr_semantic_lines(atr) {
        write_colored(
            writer,
            &atr[line.start..line.end],
            if line.metadata { ANSI_PINK } else { ANSI_BLUE },
        )?;
        writeln!(writer, " # {}", line.comment)?;
    }
    Ok(())
}

fn atr_semantic_lines(atr: &[u8]) -> Vec<SemanticLine> {
    if atr.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![SemanticLine {
        start: 0,
        end: 1,
        metadata: true,
        comment: format!(
            "TS : {} convention",
            match atr[0] {
                0x3b => "Direct",
                0x3f => "Inverse",
                _ => "Unknown",
            }
        ),
    }];
    let Some(&t0) = atr.get(1) else {
        return lines;
    };
    lines.push(SemanticLine {
        start: 1,
        end: 2,
        metadata: true,
        comment: format!(
            "T0 : interface mask {:X}, {} historical byte(s)",
            t0 >> 4,
            t0 & 0x0f
        ),
    });

    let mut offset = 2usize;
    let mut presence = t0 >> 4;
    let mut group = 1usize;
    loop {
        for (mask, name) in [(0x1, "TA"), (0x2, "TB"), (0x4, "TC")] {
            if presence & mask != 0 {
                let Some(_) = atr.get(offset) else {
                    return lines;
                };
                lines.push(SemanticLine {
                    start: offset,
                    end: offset + 1,
                    metadata: true,
                    comment: format!("{name}{group} : interface byte"),
                });
                offset += 1;
            }
        }
        if presence & 0x8 == 0 {
            break;
        }
        let Some(&td) = atr.get(offset) else {
            return lines;
        };
        lines.push(SemanticLine {
            start: offset,
            end: offset + 1,
            metadata: true,
            comment: format!("TD{group} : protocol T={}", td & 0x0f),
        });
        offset += 1;
        presence = td >> 4;
        group += 1;
    }

    let historical_len = usize::from(t0 & 0x0f);
    let Some(historical_end) = offset.checked_add(historical_len) else {
        return lines;
    };
    if historical_end > atr.len() {
        if offset < atr.len() {
            lines.push(SemanticLine {
                start: offset,
                end: atr.len(),
                metadata: false,
                comment: "Truncated historical data".to_owned(),
            });
        }
        return lines;
    }
    if historical_len != 0 {
        let category = atr[offset];
        lines.push(SemanticLine {
            start: offset,
            end: offset + 1,
            metadata: true,
            comment: format!("Historical category indicator {category:02X}"),
        });
        offset += 1;
        if category == 0x80 {
            while offset < historical_end {
                let header = atr[offset];
                let length = usize::from(header & 0x0f);
                lines.push(SemanticLine {
                    start: offset,
                    end: offset + 1,
                    metadata: true,
                    comment: format!("Compact-TL : tag {}, length {length}", header >> 4),
                });
                offset += 1;
                let value_end = offset.saturating_add(length).min(historical_end);
                if value_end > offset {
                    lines.push(SemanticLine {
                        start: offset,
                        end: value_end,
                        metadata: false,
                        comment: "Historical data".to_owned(),
                    });
                }
                offset = value_end;
            }
        } else if offset < historical_end {
            lines.push(SemanticLine {
                start: offset,
                end: historical_end,
                metadata: false,
                comment: "Historical data".to_owned(),
            });
        }
    }
    if historical_end < atr.len() {
        lines.push(SemanticLine {
            start: historical_end,
            end: atr.len(),
            metadata: true,
            comment: "ATR check byte or trailing metadata".to_owned(),
        });
    }
    lines
}

fn emit_colored_data(writer: &mut dyn Write, data: &[u8]) -> io::Result<()> {
    let lines = semantic_data_lines(data);
    emit_colored_lines(writer, data, &lines)
}

fn emit_colored_lines(
    writer: &mut dyn Write,
    data: &[u8],
    lines: &[SemanticLine],
) -> io::Result<()> {
    for (index, line) in lines.iter().enumerate() {
        if index != 0 {
            write!(writer, " ")?;
        }
        write_colored(
            writer,
            &data[line.start..line.end],
            if line.metadata { ANSI_PINK } else { ANSI_BLUE },
        )?;
    }
    Ok(())
}

fn emit_human_data(writer: &mut dyn Write, data: &[u8]) -> io::Result<()> {
    for line in semantic_data_lines(data) {
        write_colored(
            writer,
            &data[line.start..line.end],
            if line.metadata { ANSI_PINK } else { ANSI_BLUE },
        )?;
        writeln!(writer, " # {}", line.comment)?;
    }
    Ok(())
}

fn semantic_data_lines(data: &[u8]) -> Vec<SemanticLine> {
    if data.is_empty() {
        return Vec::new();
    }
    parse_tlv_lines(data).unwrap_or_else(|| {
        vec![SemanticLine {
            start: 0,
            end: data.len(),
            metadata: false,
            comment: "Data".to_owned(),
        }]
    })
}

fn parse_tlv_lines(data: &[u8]) -> Option<Vec<SemanticLine>> {
    let mut lines = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let header_start = offset;
        let first_tag = *data.get(offset)?;
        offset += 1;
        if first_tag & 0x1f == 0x1f {
            loop {
                let byte = *data.get(offset)?;
                offset += 1;
                if byte & 0x80 == 0 {
                    break;
                }
            }
        }
        let tag_end = offset;
        let first_length = *data.get(offset)?;
        offset += 1;
        let length = if first_length & 0x80 == 0 {
            usize::from(first_length)
        } else {
            let count = usize::from(first_length & 0x7f);
            if !(1..=2).contains(&count) {
                return None;
            }
            let mut length = 0usize;
            for _ in 0..count {
                length = (length << 8) | usize::from(*data.get(offset)?);
                offset += 1;
            }
            length
        };
        let value_start = offset;
        let value_end = value_start.checked_add(length)?;
        if value_end > data.len() {
            return None;
        }
        lines.push(SemanticLine {
            start: header_start,
            end: value_start,
            metadata: true,
            comment: format!(
                "TL : tag {}, length {length}",
                format_hex(&data[header_start..tag_end])
            ),
        });
        if length != 0 {
            lines.push(SemanticLine {
                start: value_start,
                end: value_end,
                metadata: false,
                comment: "Data".to_owned(),
            });
        }
        offset = value_end;
    }
    Some(lines)
}

fn write_colored(writer: &mut dyn Write, bytes: &[u8], color: &str) -> io::Result<()> {
    write!(writer, "{color}{}{ANSI_RESET}", format_hex(bytes))
}

fn format_hex_compact(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn status_word_description(status: (u8, u8)) -> &'static str {
    match status {
        (0x90, 0x00) => "Success",
        (0x61, _) => "Response bytes available",
        (0x62, 0x83) => "Selected file or application invalidated",
        (0x63, 0x00) => "Authentication failed",
        (0x67, 0x00) => "Wrong length",
        (0x68, 0x81) => "Logical channel not supported",
        (0x68, 0x82) => "Secure messaging not supported",
        (0x69, 0x82) => "Security status not satisfied",
        (0x69, 0x85) => "Conditions of use not satisfied",
        (0x69, 0x87) => "Expected secure messaging object missing",
        (0x69, 0x88) => "Incorrect secure messaging object",
        (0x6a, 0x80) => "Incorrect data",
        (0x6a, 0x82) => "File or application not found",
        (0x6a, 0x84) => "Not enough memory space",
        (0x6a, 0x86) => "Incorrect P1 or P2",
        (0x6a, 0x88) => "Referenced data not found",
        (0x6c, _) => "Wrong Le",
        (0x6d, 0x00) => "Instruction not supported",
        (0x6e, 0x00) => "Class not supported",
        (0x6f, 0x00) => "Unspecified error",
        (0x62, _) => "Warning: state unchanged",
        (0x63, _) => "Warning: state changed",
        (0x64, _) => "Execution error: state unchanged",
        (0x65, _) => "Execution error: state changed",
        _ => "Unknown status word",
    }
}

fn render_command(command: &OwnedT0Command, verbose: u8) -> Vec<String> {
    let mut lines = vec![format!(
        "CMD: cla:{:02X} ins:{:02X} p1:{:02X} p2:{:02X} lc:{:02X} le:{:02X}",
        command.cla, command.ins, command.p1, command.p2, command.lc, command.le
    )];
    if !command.data.is_empty() {
        lines.push(format!(
            "DATA IN ({}): {}",
            command.data.len(),
            format_hex(&command.data)
        ));
    }
    if verbose > 0 {
        let fields = decode_command_fields(command);
        let raw = command.display_bytes();
        let formatted = if verbose > 1 {
            format_hex_with_fields(&raw, &fields)
        } else {
            format_hex(&raw)
        };
        lines.push(format!("CMD RAW: {formatted}"));
        lines.extend(command_verbose_lines(command, &fields, verbose > 1));
    }
    lines
}

fn parse_gp_command(args: Vec<String>) -> Result<CliCommand, Box<dyn Error>> {
    let Some((name, rest)) = args.split_first() else {
        return Err("gp expects `get-data` or `get-status`".into());
    };
    match name.as_str() {
        "get-data" => parse_gp_get_data(rest).map(CliCommand::GpGetData),
        "get-status" => parse_gp_get_status(rest).map(CliCommand::GpGetStatus),
        "store-data" => parse_gp_store_data(rest).map(CliCommand::GpMutation),
        "delete-data" => parse_gp_delete_data(rest).map(CliCommand::GpMutation),
        "delete" => parse_gp_delete(rest).map(CliCommand::GpMutation),
        "set-status" => parse_gp_set_status(rest).map(CliCommand::GpMutation),
        "put-key" => parse_gp_put_key(rest).map(CliCommand::GpPutKey),
        "install-for-load" => parse_gp_install_for_load(rest).map(CliCommand::GpMutation),
        "load-block" => parse_gp_load_block(rest).map(CliCommand::GpMutation),
        "install-for-install" => {
            parse_gp_install_application(rest, false).map(CliCommand::GpMutation)
        }
        "install-make-selectable" => {
            parse_gp_install_application(rest, true).map(CliCommand::GpMutation)
        }
        "load" => parse_gp_composed_load(rest, false).map(CliCommand::GpLoad),
        "deploy" => parse_gp_composed_load(rest, true).map(CliCommand::GpLoad),
        _ => Err(format!("unknown GP command `{name}`").into()),
    }
}

fn parse_gp_composed_load(args: &[String], deploy: bool) -> Result<GpLoadOptions, Box<dyn Error>> {
    let expected = if deploy { 3 } else { 2 };
    if args.len() < expected {
        return Err(if deploy {
            "gp deploy expects PACKAGE_AID FILE.fae INSTANCE_AID [--params HEX]".into()
        } else {
            "gp load expects PACKAGE_AID FILE.fae".into()
        });
    }
    let package_aid = parse_hex_text(&args[0])?;
    let path = PathBuf::from(&args[1]);
    let fae = std::fs::read(&path)?;
    let metadata = fae::validate(&fae)?;
    let instance_aid = deploy.then(|| parse_hex_text(&args[2])).transpose()?;
    let mut install_parameters = Vec::new();
    let mut has_parameters = false;
    let mut index = expected;
    while index < args.len() {
        match args[index].as_str() {
            "--params" if deploy => {
                if has_parameters {
                    return Err("--params may be specified only once".into());
                }
                index += 1;
                install_parameters = parse_hex_or_file(
                    args.get(index).ok_or("missing payload after --params")?,
                    "INSTALL payload",
                )?;
                has_parameters = true;
            }
            option => {
                return Err(format!(
                    "unknown gp {} option: {option}",
                    if deploy { "deploy" } else { "load" }
                )
                .into())
            }
        }
        index += 1;
    }
    // Reuse the primitive builders as local AID validation before opening a link.
    gp::install_for_load_with_parameters(&package_aid, &[], &[], &[], &[])?;
    if let Some(instance) = &instance_aid {
        gp::install_and_make_selectable(
            &package_aid,
            &package_aid,
            instance,
            &[],
            &install_parameters,
        )?;
    }
    Ok(GpLoadOptions {
        package_aid,
        instance_aid,
        install_parameters,
        fae,
        metadata,
    })
}

fn parse_hex_or_file(value: &str, label: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if let Some(path) = value.strip_prefix('@') {
        let bytes = std::fs::read(path)?;
        if let Ok(text) = std::str::from_utf8(&bytes) {
            if let Ok(parsed) = parse_hex_text(text) {
                return Ok(parsed);
            }
        }
        return Ok(bytes);
    }
    parse_hex_text(value).map_err(|error| format!("invalid {label}: {error}").into())
}

fn parse_gp_install_for_load(args: &[String]) -> Result<OwnedT0Command, Box<dyn Error>> {
    let mut package = None;
    let mut domain = None;
    let mut hash = Vec::new();
    let mut parameters = None;
    let mut size = None;
    let mut token = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let option = args[index].as_str();
        index += 1;
        let value = || {
            args.get(index)
                .ok_or_else(|| format!("missing value after {option}"))
        };
        match option {
            "--package-aid" => package = Some(parse_hex_or_file(value()?, "package AID")?),
            "--package-aid-file" => {
                package = Some(parse_hex_or_file(&format!("@{}", value()?), "package AID")?)
            }
            "--security-domain" => {
                domain = Some(parse_hex_or_file(value()?, "Security Domain AID")?)
            }
            "--security-domain-file" => {
                domain = Some(parse_hex_or_file(
                    &format!("@{}", value()?),
                    "Security Domain AID",
                )?)
            }
            "--hash" => hash = parse_hex_or_file(value()?, "load-file hash")?,
            "--hash-file" => hash = parse_hex_or_file(&format!("@{}", value()?), "load-file hash")?,
            "--parameters" => parameters = Some(parse_hex_or_file(value()?, "load parameters")?),
            "--parameters-file" => {
                parameters = Some(parse_hex_or_file(
                    &format!("@{}", value()?),
                    "load parameters",
                )?)
            }
            "--size" => size = Some(value()?.parse::<u32>().map_err(|_| "invalid --size")?),
            "--token" => token = parse_hex_or_file(value()?, "load token")?,
            "--token-file" => token = parse_hex_or_file(&format!("@{}", value()?), "load token")?,
            _ => return Err(format!("unknown gp install-for-load option: {option}").into()),
        }
        index += 1;
    }
    if parameters.is_some() && size.is_some() {
        return Err("--parameters and --size are mutually exclusive".into());
    }
    let parameters = parameters.unwrap_or_else(|| size.unwrap_or(0).to_be_bytes().to_vec());
    Ok(gp::install_for_load_with_parameters(
        &package.ok_or("gp install-for-load requires --package-aid")?,
        &domain.ok_or("gp install-for-load requires --security-domain")?,
        &hash,
        &parameters,
        &token,
    )?)
}

fn parse_gp_load_block(args: &[String]) -> Result<OwnedT0Command, Box<dyn Error>> {
    let mut number = None;
    let mut last = false;
    let mut file = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--number" => {
                index += 1;
                number = Some(parse_cli_byte(
                    args.get(index).ok_or("missing value after --number")?,
                    "block number",
                )?);
            }
            "--last" => last = true,
            option if option.starts_with('-') => {
                return Err(format!("unknown gp load-block option: {option}").into())
            }
            path if file.is_none() => file = Some(path),
            _ => return Err("gp load-block accepts exactly one input file".into()),
        }
        index += 1;
    }
    let data = std::fs::read(file.ok_or("gp load-block requires an input file")?)?;
    Ok(gp::load_block(
        number.ok_or("gp load-block requires --number")?,
        last,
        &data,
    )?)
}

fn parse_install_privileges(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if value.starts_with('@')
        || value.contains(':')
        || value.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return parse_hex_or_file(value, "privileges");
    }
    let mut byte = 0u8;
    for name in value.split(',').filter(|name| !name.is_empty()) {
        byte |= match name {
            "none" => 0x00,
            "security-domain" => 0x80,
            "dap-verification" => 0x40,
            "delegated-management" => 0x20,
            "card-lock" => 0x10,
            "card-terminate" => 0x08,
            "card-reset" => 0x04,
            "cvm-management" => 0x02,
            "mandated-dap" => 0x01,
            _ => return Err(format!("unknown INSTALL privilege `{name}`").into()),
        };
    }
    Ok(if byte == 0 { Vec::new() } else { vec![byte] })
}

fn parse_gp_install_application(
    args: &[String],
    make_selectable: bool,
) -> Result<OwnedT0Command, Box<dyn Error>> {
    let mut package = None;
    let mut module = None;
    let mut instance = None;
    let mut privileges = Vec::new();
    let mut parameters = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let option = args[index].as_str();
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("missing value after {option}"))?;
        match option {
            "--package-aid" => package = Some(parse_hex_or_file(value, "package AID")?),
            "--package-aid-file" => {
                package = Some(parse_hex_or_file(&format!("@{value}"), "package AID")?)
            }
            "--module-aid" => module = Some(parse_hex_or_file(value, "module AID")?),
            "--module-aid-file" => {
                module = Some(parse_hex_or_file(&format!("@{value}"), "module AID")?)
            }
            "--instance-aid" => instance = Some(parse_hex_or_file(value, "instance AID")?),
            "--instance-aid-file" => {
                instance = Some(parse_hex_or_file(&format!("@{value}"), "instance AID")?)
            }
            "--privileges" => privileges = parse_install_privileges(value)?,
            "--privileges-file" => {
                privileges = parse_hex_or_file(&format!("@{value}"), "privileges")?
            }
            "--parameters" => parameters = parse_hex_or_file(value, "install parameters")?,
            "--parameters-file" => {
                parameters = parse_hex_or_file(&format!("@{value}"), "install parameters")?
            }
            _ => return Err(format!("unknown GP install option: {option}").into()),
        }
        index += 1;
    }
    let package = package.ok_or("INSTALL requires --package-aid")?;
    let module = module.ok_or("INSTALL requires --module-aid")?;
    let instance = instance.ok_or("INSTALL requires --instance-aid")?;
    Ok(if make_selectable {
        gp::install_and_make_selectable(&package, &module, &instance, &privileges, &parameters)?
    } else {
        gp::install_for_install(&package, &module, &instance, &privileges, &parameters)?
    })
}

fn parse_gp_get_data(args: &[String]) -> Result<GpGetDataOptions, Box<dyn Error>> {
    let Some(tag_text) = args.first() else {
        return Err("gp get-data expects a two-byte TAG".into());
    };
    let tag = match tag_text.as_str() {
        "card-recognition" => 0x0066,
        "card-capabilities" => 0x0067,
        _ => {
            let tag_bytes = parse_hex_text(tag_text)?;
            if tag_bytes.len() != 2 {
                return Err("GP GET DATA tag must contain exactly two bytes".into());
            }
            u16::from_be_bytes([tag_bytes[0], tag_bytes[1]])
        }
    };
    let mut format = GpDataFormat::Hex;
    let mut output = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                index += 1;
                format = match args.get(index).map(String::as_str) {
                    Some("hex") => GpDataFormat::Hex,
                    Some("binary") => GpDataFormat::Binary,
                    Some("tlv") => GpDataFormat::Tlv,
                    Some(value) => {
                        return Err(format!(
                            "invalid GP data format `{value}`; expected hex, binary or tlv"
                        )
                        .into())
                    }
                    None => return Err("missing value after --format".into()),
                };
            }
            "--output" => {
                index += 1;
                let path = args.get(index).ok_or("missing path after --output")?;
                output = Some(PathBuf::from(path));
            }
            option => return Err(format!("unknown gp get-data option: {option}").into()),
        }
        index += 1;
    }
    Ok(GpGetDataOptions {
        tag,
        format,
        output,
    })
}

fn parse_gp_get_status(args: &[String]) -> Result<GpGetStatusOptions, Box<dyn Error>> {
    let Some(category) = args.first() else {
        return Err("gp get-status expects isd, applications, packages or modules".into());
    };
    let category = match category.as_str() {
        "isd" | "issuer-security-domain" => GpStatusCategory::IssuerSecurityDomain,
        "applications" => GpStatusCategory::Applications,
        "packages" => GpStatusCategory::Packages,
        "modules" => GpStatusCategory::Modules,
        value => return Err(format!("invalid GET STATUS category `{value}`").into()),
    };
    let mut aid_filter = Vec::new();
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--aid" => {
                index += 1;
                aid_filter = parse_hex_text(args.get(index).ok_or("missing AID after --aid")?)?;
                if aid_filter.len() > 16 {
                    return Err("GET STATUS AID filter cannot exceed 16 bytes".into());
                }
            }
            option => return Err(format!("unknown gp get-status option: {option}").into()),
        }
        index += 1;
    }
    Ok(GpGetStatusOptions {
        category,
        aid_filter,
    })
}

fn parse_gp_tag(value: &str) -> Result<u16, Box<dyn Error>> {
    let bytes = parse_hex_text(value)?;
    if bytes.len() != 2 {
        return Err("GP tag must contain exactly two bytes".into());
    }
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn parse_gp_store_data(args: &[String]) -> Result<OwnedT0Command, Box<dyn Error>> {
    let tag = parse_gp_tag(args.first().ok_or("gp store-data expects a TAG")?)?;
    let data = match &args[1..] {
        [flag, value] if flag == "--data" => parse_hex_text(value)?,
        [flag, path] if flag == "--input" => std::fs::read(path)?,
        [flag] if flag == "--stdin" => {
            let mut data = Vec::new();
            io::stdin().read_to_end(&mut data)?;
            data
        }
        _ => {
            return Err(
                "store-data requires exactly one of --data HEX, --input FILE or --stdin".into(),
            )
        }
    };
    Ok(gp::store_data(tag, &data)?)
}

fn parse_gp_delete_data(args: &[String]) -> Result<OwnedT0Command, Box<dyn Error>> {
    if args.len() != 1 {
        return Err("gp delete-data expects one TAG".into());
    }
    Ok(gp::delete_data(parse_gp_tag(&args[0])?)?)
}

fn parse_gp_delete(args: &[String]) -> Result<OwnedT0Command, Box<dyn Error>> {
    let [flag, aid] = args else {
        return Err("gp delete expects --aid AID".into());
    };
    if flag != "--aid" {
        return Err("gp delete expects --aid AID".into());
    }
    Ok(gp::delete_aid(&parse_hex_text(aid)?)?)
}

fn parse_gp_set_status(args: &[String]) -> Result<OwnedT0Command, Box<dyn Error>> {
    let [kind, aid, state] = args else {
        return Err("gp set-status expects TYPE AID STATE".into());
    };
    let kind = match kind.as_str() {
        "package" => gp::RegistryObjectKind::Package,
        "application" => gp::RegistryObjectKind::Application,
        "security-domain" => gp::RegistryObjectKind::SecurityDomain,
        _ => return Err("SET STATUS type must be package, application or security-domain".into()),
    };
    let state = match (kind, state.as_str()) {
        (_, "locked") => gp::RegistryState::Locked,
        (_, "unlocked")
        | (gp::RegistryObjectKind::Package, "loaded")
        | (
            gp::RegistryObjectKind::Application | gp::RegistryObjectKind::SecurityDomain,
            "selectable",
        ) => gp::RegistryState::Unlocked,
        _ => return Err("invalid SET STATUS type/state combination".into()),
    };
    Ok(gp::set_status(kind, &parse_hex_text(aid)?, state)?)
}

fn parse_cli_byte(value: &str, label: &str) -> Result<u8, Box<dyn Error>> {
    if let Some(hex) = value.strip_prefix("0x") {
        Ok(u8::from_str_radix(hex, 16).map_err(|error| format!("invalid {label}: {error}"))?)
    } else {
        Ok(value
            .parse()
            .map_err(|error| format!("invalid {label}: {error}"))?)
    }
}

fn parse_key_usage(value: &str) -> Result<gp::KeyUsage, Box<dyn Error>> {
    match value.to_ascii_lowercase().as_str() {
        "enc" | "scp03-enc" => Ok(gp::KeyUsage::Scp03Enc),
        "mac" | "scp03-mac" => Ok(gp::KeyUsage::Scp03Mac),
        "scp11-sd-ecka" | "sd-ecka" => Ok(gp::KeyUsage::Scp11SdEcka),
        "scp11-ca-kloc" | "ca-kloc" => Ok(gp::KeyUsage::Scp11CaKloc),
        _ => Err(format!(
            "unsupported key usage `{value}`; expected enc, mac, scp11-sd-ecka or scp11-ca-kloc"
        )
        .into()),
    }
}

fn parse_key_spec(value: &str) -> Result<(gp::KeyUsage, &str), Box<dyn Error>> {
    let (usage, source) = value
        .split_once(':')
        .ok_or("key specification must be USAGE:VALUE")?;
    Ok((parse_key_usage(usage)?, source))
}

fn read_key_file(path: &str, usage: gp::KeyUsage) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() == usage.material_len() {
        return Ok(bytes);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "key file must contain 16, 32 or 65 raw bytes, or hexadecimal text")?;
    parse_hex_text(text).map_err(|_| "key file contains invalid hexadecimal material".into())
}

#[cfg(unix)]
fn key_file_is_unprotected(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o077 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn key_file_is_unprotected(_path: &str) -> bool {
    false
}

fn parse_gp_put_key(args: &[String]) -> Result<GpPutKeyOptions, Box<dyn Error>> {
    let mut version = None;
    let mut id = None;
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let option = &args[index];
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("missing value after {option}"))?;
        match option.as_str() {
            "--version" => version = Some(parse_cli_byte(value, "key version")?),
            "--id" => id = Some(parse_cli_byte(value, "key identifier")?),
            "--key" => {
                let (usage, material) = parse_key_spec(value)?;
                entries.push(gp::KeyEntry {
                    usage,
                    material: parse_hex_text(material)
                        .map_err(|_| "inline key contains invalid hexadecimal material")?,
                });
                warnings.push("WARNING: key material supplied on the command line is visible in shell history and process listings; use --key-file with mode 0600 for production (--key is for debug purposes only).".to_owned());
            }
            "--key-file" => {
                let (usage, path) = parse_key_spec(value)?;
                if key_file_is_unprotected(path) {
                    warnings.push(format!("WARNING: key file `{path}` is accessible by group or other users; restrict it to mode 0600 before production use."));
                }
                entries.push(gp::KeyEntry {
                    usage,
                    material: read_key_file(path, usage)?,
                });
            }
            _ => return Err(format!("unknown gp put-key option: {option}").into()),
        }
        index += 1;
    }
    let command = gp::put_key(
        version.ok_or("missing --version")?,
        id.ok_or("missing --id")?,
        &entries,
    )?;
    Ok(GpPutKeyOptions { command, warnings })
}

fn gp_get_data_command(tag: u16) -> OwnedT0Command {
    gp::get_data(tag, 0).expect("GET DATA is a valid T=0 command")
}

fn gp_get_status_command(options: &GpGetStatusOptions, next: bool) -> OwnedT0Command {
    gp::get_status(options.category, next, &options.aid_filter)
        .expect("validated GET STATUS command")
}

fn parse_raw_command(args: Vec<String>) -> Result<OwnedT0Command, Box<dyn Error>> {
    enum RawSource {
        Inline(Vec<String>),
        File(PathBuf),
        Stdin,
    }

    let source = match args.as_slice() {
        [flag, path] if flag == "--file" => RawSource::File(PathBuf::from(path)),
        [flag] if flag == "--stdin" => RawSource::Stdin,
        [] => return Err("raw expects APDU bytes, --file PATH or --stdin".into()),
        _ if args.iter().any(|arg| arg == "--file" || arg == "--stdin") => {
            return Err("raw APDU sources are mutually exclusive".into())
        }
        _ if args.iter().any(|arg| arg.starts_with('-')) => {
            return Err(format!(
                "unknown raw option: {}",
                args.iter()
                    .find(|arg| arg.starts_with('-'))
                    .expect("checked above")
            )
            .into())
        }
        _ => RawSource::Inline(args),
    };

    let bytes = match source {
        RawSource::Inline(tokens) => parse_hex_tokens(&tokens)?,
        RawSource::File(path) => {
            let input = std::fs::read_to_string(&path)
                .map_err(|error| format!("could not read APDU file {}: {error}", path.display()))?;
            parse_hex_text(&input)?
        }
        RawSource::Stdin => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            parse_hex_text(&input)?
        }
    };
    parse_wire_command(&bytes)
}

fn parse_wire_command(bytes: &[u8]) -> Result<OwnedT0Command, Box<dyn Error>> {
    if bytes.len() < 6 {
        return Err(format!(
            "raw APDU expects at least 6 bytes (CLA INS P1 P2 LC LE), got {}",
            bytes.len()
        )
        .into());
    }
    Ok(OwnedT0Command::from_wire_fields(
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6..].to_vec(),
    )?)
}

fn parse_hex_tokens(tokens: &[String]) -> Result<Vec<u8>, Box<dyn Error>> {
    parse_hex_text(&tokens.join(" "))
}

fn parse_hex_text(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    for token in input.split(|character: char| character.is_ascii_whitespace() || character == ':')
    {
        if token.is_empty() {
            continue;
        }
        let hex = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
            .unwrap_or(token);
        if hex.is_empty() || hex.len() % 2 != 0 {
            return Err(format!("hex value must contain complete bytes: `{token}`").into());
        }
        for offset in (0..hex.len()).step_by(2) {
            bytes.push(
                u8::from_str_radix(&hex[offset..offset + 2], 16)
                    .map_err(|error| format!("invalid hexadecimal byte in `{token}`: {error}"))?,
            );
        }
    }
    if bytes.is_empty() {
        return Err("hex input is empty".into());
    }
    Ok(bytes)
}

fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_hex_with_fields(bytes: &[u8], fields: &[DecodedField]) -> String {
    let mut out = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            out.push(' ');
        }
        if let Some(field) = fields
            .iter()
            .find(|field| index >= field.span.start && index < field.span.start + field.span.len)
        {
            let color = FIELD_COLORS[field.color_index % FIELD_COLORS.len()];
            out.push_str(color);
            out.push_str(&format!("{byte:02X}"));
            out.push_str(ANSI_RESET);
        } else {
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

fn command_verbose_lines(
    command: &OwnedT0Command,
    fields: &[DecodedField],
    color: bool,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!("APDU decode: {}", command_name(command)));
    for field in fields {
        let name = if color {
            format!(
                "{}{}{}",
                FIELD_COLORS[field.color_index % FIELD_COLORS.len()],
                field.name,
                ANSI_RESET
            )
        } else {
            field.name.to_owned()
        };
        let value = if color {
            format!("{ANSI_WHITE}{}{ANSI_RESET}", field.value)
        } else {
            field.value.clone()
        };
        lines.push(format!("  {name}: {value} - {}", field.description));
    }
    lines.extend(extra_command_verbose_lines(command));
    lines
}

fn decode_command_fields(command: &OwnedT0Command) -> Vec<DecodedField> {
    let mut fields = vec![
        field(
            "CLA",
            0,
            1,
            format!("{:02X}", command.cla),
            cla_description(command.cla),
            0,
        ),
        field(
            "INS",
            1,
            1,
            format!("{:02X}", command.ins),
            command_name(command),
            1,
        ),
        field(
            "P1",
            2,
            1,
            format!("{:02X}", command.p1),
            p1_description(command),
            2,
        ),
        field(
            "P2",
            3,
            1,
            format!("{:02X}", command.p2),
            p2_description(command),
            3,
        ),
        field(
            "LC",
            4,
            1,
            format!("{:02X}", command.lc),
            "incoming data length".to_owned(),
            4,
        ),
        field(
            "LE",
            5,
            1,
            format!("{:02X}", command.le),
            "expected response length".to_owned(),
            5,
        ),
    ];

    match command.ins {
        0xA4 if command.cla == 0x00 => {
            if command.lc != 0 {
                fields.push(field(
                    "AID",
                    6,
                    command.data.len(),
                    format_hex(&command.data),
                    "selected DF/application name".to_owned(),
                    6,
                ));
            }
        }
        0xE6 if command.cla == 0x80 => {
            add_install_fields(command, &mut fields);
        }
        0x50 | 0x82 | 0x2A | 0x88 => {
            if !command.data.is_empty() {
                fields.push(field(
                    "DATA",
                    6,
                    command.data.len(),
                    format_hex(&command.data),
                    secure_channel_data_description(command),
                    6,
                ));
            }
        }
        _ => {
            if !command.data.is_empty() {
                fields.push(field(
                    "DATA",
                    6,
                    command.data.len(),
                    format_hex(&command.data),
                    "application payload".to_owned(),
                    6,
                ));
            }
        }
    }

    fields
}

fn field(
    name: &'static str,
    start: usize,
    len: usize,
    value: String,
    description: String,
    color_index: usize,
) -> DecodedField {
    DecodedField {
        name,
        span: ByteSpan { start, len },
        value,
        description,
        color_index,
    }
}

fn command_name(command: &OwnedT0Command) -> String {
    match (command.cla, command.ins) {
        (0x00, 0xA4) => "SELECT by DF/application name".to_owned(),
        (0x00, 0xC0) => "GET RESPONSE".to_owned(),
        (0x00, 0x84) => "GET CHALLENGE".to_owned(),
        (0x00, 0x70) => "MANAGE CHANNEL".to_owned(),
        (0x00, 0xB0) => "READ BINARY".to_owned(),
        (0x00, 0xD6) => "UPDATE BINARY".to_owned(),
        (0x00, 0xB2) => "READ RECORD".to_owned(),
        (0x00, 0x20) => "VERIFY".to_owned(),
        (0x00, 0x24) => "CHANGE REFERENCE DATA".to_owned(),
        (0x00, 0x2C) => "RESET RETRY COUNTER".to_owned(),
        (_, 0xE6) => match command.p1 {
            0x02 => "GlobalPlatform INSTALL [for load]".to_owned(),
            0x04 => "GlobalPlatform INSTALL [for install]".to_owned(),
            0x08 => "GlobalPlatform INSTALL [for make selectable]".to_owned(),
            0x0C => "GlobalPlatform INSTALL [for install and make selectable]".to_owned(),
            0x10 => "GlobalPlatform INSTALL [for extradition]".to_owned(),
            0x20 => "GlobalPlatform INSTALL [for registry update]".to_owned(),
            _ => "GlobalPlatform INSTALL".to_owned(),
        },
        (_, 0xE8) => "GlobalPlatform LOAD".to_owned(),
        (_, 0xCA | 0xCB) => "GlobalPlatform GET DATA".to_owned(),
        (_, 0xF2) => "GlobalPlatform GET STATUS".to_owned(),
        (_, 0xF0) => "GlobalPlatform SET STATUS".to_owned(),
        (_, 0xD8) => "GlobalPlatform PUT KEY".to_owned(),
        (_, 0xE4) => "GlobalPlatform DELETE".to_owned(),
        (_, 0xE2) => "GlobalPlatform STORE DATA".to_owned(),
        (_, 0x50) => "GlobalPlatform INITIALIZE UPDATE".to_owned(),
        (_, 0x82) if looks_like_scp11_mutual_authenticate(command) => {
            "SCP11 MUTUAL AUTHENTICATE".to_owned()
        }
        (_, 0x82) => "GlobalPlatform EXTERNAL AUTHENTICATE".to_owned(),
        (_, 0x2A) => "SCP11 PERFORM SECURITY OPERATION".to_owned(),
        (_, 0x88) => "SCP11b INTERNAL AUTHENTICATE".to_owned(),
        _ => "application or proprietary APDU".to_owned(),
    }
}

fn cla_description(cla: u8) -> String {
    match cla {
        0x00 => "ISO interindustry command".to_owned(),
        0x80 => "GlobalPlatform/proprietary command".to_owned(),
        0x84 => "secure messaging command".to_owned(),
        _ if cla & 0x04 != 0 => "command with secure messaging bit set".to_owned(),
        _ => "class byte".to_owned(),
    }
}

fn p1_description(command: &OwnedT0Command) -> String {
    match command.ins {
        0xA4 => match command.p1 {
            0x04 => "select by DF/application name".to_owned(),
            _ => "SELECT parameter P1".to_owned(),
        },
        0x50 => "key version number".to_owned(),
        0x82 if looks_like_scp11_mutual_authenticate(command) => "key version number".to_owned(),
        0x82 => "requested security level".to_owned(),
        0x2A | 0x88 => "key version number".to_owned(),
        0xE6 => "INSTALL command variant".to_owned(),
        _ => "P1".to_owned(),
    }
}

fn p2_description(command: &OwnedT0Command) -> String {
    match command.ins {
        0xA4 => match command.p2 {
            0x00 => "first or only occurrence".to_owned(),
            _ => "SELECT occurrence/control parameter".to_owned(),
        },
        0x50 | 0x82 | 0x2A | 0x88
            if command.ins != 0x82 || looks_like_scp11_mutual_authenticate(command) =>
        {
            "key identifier".to_owned()
        }
        0x82 => "EXTERNAL AUTHENTICATE P2".to_owned(),
        0xE6 => "INSTALL P2".to_owned(),
        _ => "P2".to_owned(),
    }
}

fn add_install_fields(command: &OwnedT0Command, fields: &mut Vec<DecodedField>) {
    let mut offset = 0usize;
    let for_load = [
        ("PACKAGE_AID", "load-file/package AID"),
        ("SECURITY_DOMAIN_AID", "target Security Domain AID"),
        ("LOAD_FILE_HASH", "load-file data block hash"),
        ("LOAD_PARAMS", "load parameters"),
        ("LOAD_TOKEN", "load token"),
    ];
    let for_install = [
        ("PACKAGE_AID", "package AID to instantiate"),
        ("APPLET_AID", "applet/module AID within the package"),
        ("INSTANCE_AID", "selectable application instance AID"),
        (
            "PRIVILEGES",
            "GlobalPlatform privilege bytes for this instance",
        ),
        ("INSTALL_PARAMS", "application install parameters"),
    ];
    let specs = if command.p1 == 0x02 {
        &for_load
    } else {
        &for_install
    };
    for (index, (name, description)) in specs.iter().enumerate() {
        let display_start = 6 + offset;
        let Some(value) = read_lv(&command.data, &mut offset) else {
            fields.push(field(
                name,
                display_start,
                command
                    .data
                    .len()
                    .saturating_sub(display_start.saturating_sub(6)),
                "<truncated>".to_owned(),
                (*description).to_owned(),
                6 + index,
            ));
            return;
        };
        fields.push(field(
            name,
            display_start,
            1 + value.len(),
            format_hex(value),
            (*description).to_owned(),
            6 + index,
        ));
    }
}

fn read_lv<'a>(data: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let len = *data.get(*offset)? as usize;
    *offset += 1;
    let end = (*offset).checked_add(len)?;
    if end > data.len() {
        return None;
    }
    let value = &data[*offset..end];
    *offset = end;
    Some(value)
}

fn extra_command_verbose_lines(command: &OwnedT0Command) -> Vec<String> {
    match command.ins {
        0xE6 if command.cla == 0x80 => install_extra_lines(command),
        0x50 => initialize_update_extra_lines(command),
        0x82 if !looks_like_scp11_mutual_authenticate(command) => {
            vec![format!(
                "  security level: {:02X} - {}",
                command.p1,
                describe_security_level(command.p1)
            )]
        }
        0x82 | 0x88 if looks_like_scp11_mutual_authenticate(command) => scp11_extra_lines(command),
        0x2A => vec![
            "  SCP11 PSO: stages certificate or public-key material before authentication"
                .to_owned(),
            format!("  payload length: {} byte(s)", command.data.len()),
        ],
        _ => Vec::new(),
    }
}

fn install_extra_lines(command: &OwnedT0Command) -> Vec<String> {
    let mut lines = Vec::new();
    let mut offset = 0usize;
    let package = read_lv(&command.data, &mut offset);
    let second = read_lv(&command.data, &mut offset);
    let third = read_lv(&command.data, &mut offset);
    let fourth = read_lv(&command.data, &mut offset);
    let fifth = read_lv(&command.data, &mut offset);
    if command.p1 == 0x02 {
        if let (Some(package), Some(domain), Some(hash), Some(params), Some(token)) =
            (package, second, third, fourth, fifth)
        {
            lines.push(format!(
                "  load summary: package {} into Security Domain {}",
                format_hex(package),
                format_hex(domain)
            ));
            lines.push(format!("  load-file hash: {} byte(s)", hash.len()));
            lines.push(format!(
                "  load parameters/token: {}/{} byte(s)",
                params.len(),
                token.len()
            ));
        }
        return lines;
    }
    if let (Some(package), Some(applet), Some(instance), Some(privileges), Some(params)) =
        (package, second, third, fourth, fifth)
    {
        lines.push(format!(
            "  install summary: instance {} from package {} / applet {}",
            format_hex(instance),
            format_hex(package),
            format_hex(applet)
        ));
        lines.push(format!(
            "  privileges: {} - {}",
            format_hex(privileges),
            if privileges.is_empty() {
                "ordinary Rustlet instance"
            } else {
                "raw GlobalPlatform privilege bytes"
            }
        ));
        lines.push(format!("  install parameters: {} byte(s)", params.len()));
    }
    lines
}

fn initialize_update_extra_lines(command: &OwnedT0Command) -> Vec<String> {
    vec![
        format!("  key version: {:02X}", command.p1),
        format!("  key id: {:02X}", command.p2),
        format!("  host challenge: {}", format_hex(&command.data)),
    ]
}

fn scp11_extra_lines(command: &OwnedT0Command) -> Vec<String> {
    let mut lines = vec![format!(
        "  SCP11 key reference: version {:02X}, id {:02X}",
        command.p1, command.p2
    )];
    if let Some(profile) = scp11_profile_from_a6(&command.data) {
        lines.push(format!("  SCP11 profile: {profile}"));
    }
    lines.push(format!(
        "  SCP11 request payload: {} byte(s)",
        command.data.len()
    ));
    lines
}

fn secure_channel_data_description(command: &OwnedT0Command) -> String {
    match command.ins {
        0x50 => "host challenge".to_owned(),
        0x82 if looks_like_scp11_mutual_authenticate(command) => {
            "SCP11 A6 authentication TLV".to_owned()
        }
        0x82 => "host cryptogram and optional secure-channel data".to_owned(),
        0x2A => "SCP11 certificate or public-key material".to_owned(),
        0x88 => "SCP11b A6 authentication TLV".to_owned(),
        _ => "secure-channel data".to_owned(),
    }
}

fn describe_security_level(level: u8) -> &'static str {
    match level {
        0x00 => "no secure messaging requested",
        0x01 => "C-MAC",
        0x03 => "C-MAC and C-DECRYPTION",
        0x11 => "C-MAC and R-MAC",
        0x13 => "C-MAC, C-DECRYPTION and R-MAC",
        _ => "raw/implementation-specific security level",
    }
}

fn looks_like_scp11_mutual_authenticate(command: &OwnedT0Command) -> bool {
    (command.ins == 0x82 || command.ins == 0x88) && command.data.first().copied() == Some(0xA6)
}

fn scp11_profile_from_a6(data: &[u8]) -> Option<&'static str> {
    let body = ber_tlv_value(data, 0xA6)?;
    let value = ber_tlv_value(body, 0x90)?;
    if value.len() < 2 || value[0] != 0x11 {
        return None;
    }
    match value[1] {
        0x00 => Some("SCP11b"),
        0x01 => Some("SCP11a"),
        0x03 => Some("SCP11c"),
        _ => Some("SCP11 unknown parameter"),
    }
}

fn ber_tlv_value(data: &[u8], tag: u16) -> Option<&[u8]> {
    let mut offset = 0usize;
    while offset < data.len() {
        let first = *data.get(offset)?;
        offset += 1;
        let parsed_tag = if first & 0x1F == 0x1F {
            let second = *data.get(offset)?;
            offset += 1;
            ((first as u16) << 8) | second as u16
        } else {
            first as u16
        };
        let len_byte = *data.get(offset)?;
        offset += 1;
        let len = if len_byte & 0x80 == 0 {
            len_byte as usize
        } else {
            let count = (len_byte & 0x7F) as usize;
            if count == 0 || count > 2 {
                return None;
            }
            let mut len = 0usize;
            for _ in 0..count {
                len = (len << 8) | *data.get(offset)? as usize;
                offset += 1;
            }
            len
        };
        let end = offset.checked_add(len)?;
        if end > data.len() {
            return None;
        }
        if parsed_tag == tag {
            return Some(&data[offset..end]);
        }
        offset = end;
    }
    None
}

fn atr_verbose_lines(atr: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("ATR decode:".to_owned());

    if atr.len() < 2 {
        lines.push("  malformed: ATR is shorter than TS/T0".to_owned());
        return lines;
    }

    let ts = atr[0];
    lines.push(format!(
        "  TS {:02X}: {}",
        ts,
        match ts {
            0x3B => "direct convention",
            0x3F => "inverse convention",
            _ => "unknown convention",
        }
    ));

    let t0 = atr[1];
    let y1 = t0 >> 4;
    let historical_len = (t0 & 0x0F) as usize;
    lines.push(format!(
        "  T0 {:02X}: Y1={:X}, historical-bytes={}",
        t0, y1, historical_len
    ));

    let mut offset = 2usize;
    if y1 & 0x1 != 0 {
        if offset < atr.len() {
            let ta1 = atr[offset];
            lines.push(format!("  TA1 {:02X}: default Fi/Di currently used", ta1));
            offset += 1;
        } else {
            lines.push("  TA1: missing".to_owned());
            return lines;
        }
    }
    if y1 & 0x2 != 0 {
        lines.push("  TB1: present but not decoded".to_owned());
        offset = offset.saturating_add(1);
    }
    if y1 & 0x4 != 0 {
        lines.push("  TC1: present but not decoded".to_owned());
        offset = offset.saturating_add(1);
    }
    if y1 & 0x8 != 0 {
        lines.push("  TD1: present but not decoded".to_owned());
        offset = offset.saturating_add(1);
    }

    if atr.len() < offset {
        lines.push("  malformed: interface bytes exceed ATR length".to_owned());
        return lines;
    }

    let available_historical = atr.len().saturating_sub(offset);
    if available_historical < historical_len {
        lines.push(format!(
            "  historical: malformed, expected {} byte(s), got {}",
            historical_len, available_historical
        ));
        return lines;
    }

    let historical = &atr[offset..offset + historical_len];
    lines.push(format!("  historical: {}", format_hex(historical)));
    decode_historical_bytes(historical, &mut lines);

    lines
}

fn decode_historical_bytes(historical: &[u8], lines: &mut Vec<String>) {
    if historical.is_empty() {
        lines.push("    empty historical bytes".to_owned());
        return;
    }

    let category = historical[0];
    match category {
        0x80 => lines.push("    category 80: compact-TLV follows".to_owned()),
        _ => {
            lines.push(format!(
                "    category {:02X}: not decoded as Oxide SE compact-TLV",
                category
            ));
            return;
        }
    }

    let mut offset = 1usize;
    while offset < historical.len() {
        let header = historical[offset];
        offset += 1;
        let tag = header >> 4;
        let len = (header & 0x0F) as usize;
        if offset + len > historical.len() {
            lines.push(format!(
                "    compact-TLV tag {} len {}: truncated",
                tag, len
            ));
            return;
        }
        let value = &historical[offset..offset + len];
        offset += len;

        lines.push(format!(
            "    compact-TLV tag {} len {}: {}",
            tag,
            len,
            format_hex(value)
        ));

        match tag {
            5 => decode_issuer_data(value, lines),
            7 => decode_card_capabilities(value, lines),
            _ => lines.push("      not decoded".to_owned()),
        }
    }
}

fn decode_issuer_data(value: &[u8], lines: &mut Vec<String>) {
    if value.len() == 6 && value[0..4] == [0x09, 0xC1, 0xDE, 0x5E] {
        lines.push("      Oxide SE marker: 09 C1 DE 5E (SE = Secure Element)".to_owned());
        if value[4] == 0x09 {
            lines.push("      Oxide SE version: 0.9 (beta; encoded 09)".to_owned());
        } else {
            lines.push(format!("      Oxide SE version byte: {:02X}", value[4]));
        }
        decode_oxide_se_capabilities(value[5], lines);
    } else if value.len() == 5 && value[0..3] == [0xAC, 0x1D, 0x5E] {
        lines.push("      legacy Oxide SE marker: AC 1D 5E".to_owned());
        lines.push(format!("      legacy OS version byte: {:02X}", value[3]));
        decode_oxide_se_capabilities(value[4], lines);
    } else if value.len() == 4 && value[0..2] == [0xAC, 0x1D] {
        lines.push("      Oxide SE legacy marker: AC 1D".to_owned());
        lines.push(format!("      legacy format version: {:02X}", value[2]));
        decode_oxide_se_capabilities(value[3], lines);
    } else {
        lines.push("      issuer data: unknown".to_owned());
    }
}

fn decode_oxide_se_capabilities(byte: u8, lines: &mut Vec<String>) {
    lines.push(format!("      build capabilities: {byte:02X}"));
    let root = if byte & 0x80 == 0 {
        "NullSecurityDomain (clear management, no cryptographic authentication)"
    } else {
        "non-null SecurityDomain"
    };
    let scp11a = if byte & 0x40 != 0 {
        "supported"
    } else {
        "not supported"
    };
    let scp11b = if byte & 0x20 != 0 {
        "supported"
    } else {
        "not supported"
    };
    let scp11c = if byte & 0x10 != 0 {
        "supported"
    } else {
        "not supported"
    };
    let scp03 = match byte & 0x03 {
        0b00 => "not supported",
        0b10 => "S8 supported",
        0b11 => "S16 supported",
        _ => "reserved encoding",
    };
    let reserved = if byte & 0x0C == 0 {
        "clear"
    } else {
        "non-zero (unexpected)"
    };
    lines.push(format!("        bit 7 root authority: {root}"));
    lines.push(format!("        bit 6 SCP11a: {scp11a}"));
    lines.push(format!("        bit 5 SCP11b: {scp11b}"));
    lines.push(format!("        bit 4 SCP11c: {scp11c}"));
    lines.push(format!("        bits 3..2 reserved: {reserved}"));
    lines.push(format!("        bits 1..0 SCP03 profile: {scp03}"));
}

fn decode_card_capabilities(value: &[u8], lines: &mut Vec<String>) {
    if value.len() != 3 {
        lines.push("      Card Capabilities: unexpected length".to_owned());
        return;
    }

    lines.push(format!(
        "      Card Capabilities byte 1 {:02X}: {}",
        value[0],
        if value[0] & 0x80 != 0 {
            "selection by full DF name supported"
        } else {
            "selection by full DF name not advertised"
        }
    ));
    lines.push(format!(
        "      Card Capabilities byte 2 {:02X}: no EF/file-system/write/data-coding feature advertised",
        value[1]
    ));
    lines.push(format!(
        "      Card Capabilities byte 3 {:02X}: no extended APDU or ISO logical-channel feature advertised",
        value[2]
    ));
}

fn print_usage() {
    println!("Usage: apdu-tool [OPTIONS] <COMMAND>");
    println!();
    println!("Commands:");
    println!("  atr                         wait for and display an ATR");
    println!("  close                       erase the complete persistent session");
    println!("  scp03 open OPTIONS          establish and persist an SCP03 channel");
    println!("  scp03 inspect               inspect SCP03 state without exposing secrets");
    println!("  scp03 close                 erase SCP03 state but retain the APDU session");
    println!("  select AID                  select an application by AID");
    println!("  raw HEX...                  send a strict raw APDU");
    println!("  raw --file PATH             read a hexadecimal APDU from a file");
    println!("  raw --stdin                 read a hexadecimal APDU from standard input");
    println!("  gp get-data TAG|NAME        read a GlobalPlatform data object");
    println!("  gp get-status CATEGORY      query the GlobalPlatform registry");
    println!("  gp store-data TAG SOURCE    create or replace a registry data object");
    println!("  gp delete-data TAG          delete a registry data object");
    println!("  gp delete --aid AID         delete a package or application");
    println!("  gp set-status TYPE AID STATE change a registry life-cycle state");
    println!("  gp put-key OPTIONS          install or rotate SCP03/SCP11 keys");
    println!("  gp install-for-load OPTIONS encode INSTALL [for load]");
    println!("  gp load-block --number N [--last] FILE encode one LOAD block");
    println!("  gp install-for-install OPTIONS encode INSTALL [for install]");
    println!("  gp install-make-selectable OPTIONS install and make selectable");
    println!("  gp load AID FILE.fae        INSTALL [for load] followed by LOAD blocks");
    println!("  gp deploy AID FILE.fae AID [--params HEX] load, install and make selectable");
    println!();
    println!("Global options:");
    println!("  --verbose, -v, -vv          decode known ATR and command fields");
    println!("  --serial, -s LINK           select a TCP, Unix or serial link");
    println!("  --secure-channel PROTOCOL   none, scp03, scp11a, scp11b or scp11c");
    println!("  --security-domain AID       select the Secure Channel Security Domain");
    println!("  --security-level LEVEL      command/response MAC and encryption policy");
    println!("  --credentials PATH          read Secure Channel credentials from a file");
    println!("  --keyset PATH               SCP03 alias for --credentials");
    println!("  --scp03-profile PROFILE     s8 or s16 (default: keyset, then s16)");
    println!("  --connect-timeout DURATION  ATR link retry deadline (default: 10s)");
    println!("  --atr-timeout DURATION      first ATR byte timeout (default: 10s)");
    println!("                               use `infinite` to wait without a deadline");
    println!("  --response-timeout DURATION APDU silence timeout (default: 10s)");
    println!("  --retry-interval DURATION   ATR connection retry interval (default: 100ms)");
    println!("  --progress                  show opt-in ATR/response activity animation");
    println!("  --quiet, -q                 print raw hexadecimal result bytes only");
    println!("  --output MODE               human, color, json or bin (default: human)");
    println!("  --help, -?                  show this help");
    println!();
    println!("CONTEXT ENVIRONMENT (CLI options take precedence):");
    println!("  APDU_LINK, APDU_OUTPUT, APDU_CONNECT_TIMEOUT, APDU_ATR_TIMEOUT");
    println!("  APDU_RESPONSE_TIMEOUT, APDU_RETRY_INTERVAL, APDU_SECURE_CHANNEL");
    println!("  APDU_SECURITY_DOMAIN, APDU_SECURITY_LEVEL, APDU_CREDENTIALS");
    println!("  APDU_KEYSET, APDU_SCP03_PROFILE");
    println!("  APDU_SESSION_FILE           persistent session path (default: session.json)");
    println!();
    println!("LINK syntax:");
    println!("  127.0.0.1:4444             TCP endpoint (default)");
    println!("  /tmp/rustlet.sock          Unix socket");
    println!("  /dev/tty.usbmodem1101:115200  physical serial port with baud rate");
    println!("  COM3:115200                Windows physical serial port with baud rate");
    println!("  COM3                       Windows physical serial port, default 115200 baud");
    println!();
    println!("Examples:");
    println!("  apdu-tool atr");
    println!("  apdu-tool scp03 open --security-level c-mac+c-enc --keyset keys.toml");
    println!("  apdu-tool select A0000047504F5320");
    println!("  apdu-tool -v --serial 127.0.0.1:4444 atr");
    println!("  apdu-tool raw 00 A4 04 00 08 00 A0000047504F5320");
    println!("  apdu-tool raw 00:A4:04:00:08:00:A0000047504F5320");
    println!("  apdu-tool --serial COM3:115200 raw --file command.apdu");
    println!("  apdu-tool gp get-data 0066 --format tlv");
    println!("  apdu-tool gp get-status applications --aid A000000003");
    println!("  apdu-tool gp store-data DF11 --data 01020304");
    println!("  apdu-tool gp set-status application A000000003 locked");
    println!(
        "  apdu-tool gp put-key --version 1 --id 3 --key-file enc:enc.key --key-file mac:mac.key"
    );
    println!("  apdu-tool close");
    println!("Verbose mode decodes the ATR compact-TLV fields and known management APDUs.");
    println!("Double-verbose mode (-vv) also colorizes decoded fields in the raw APDU line.");
}

fn print_raw_usage() {
    println!("Usage: apdu-tool [OPTIONS] raw HEX...");
    println!("   or: apdu-tool [OPTIONS] raw --file PATH");
    println!("   or: apdu-tool [OPTIONS] raw --stdin");
    println!();
    println!("HEX is the strict historical layout CLA INS P1 P2 LC LE [DATA...].");
    println!("Bytes may be separated by spaces or colons, or written continuously.");
    println!("Lc must exactly match the number of DATA bytes; omitted DATA is not generated.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn sample_command() -> OwnedT0Command {
        OwnedT0Command::from_wire_fields(0x80, 0x02, 0, 0, 0, 0, vec![]).unwrap()
    }

    #[test]
    fn t0_instruction_validation_rejects_status_byte_classes() {
        for ins in 0x60..=0x6f {
            assert!(!is_valid_t0_instruction(ins));
        }
        for ins in 0x90..=0x9f {
            assert!(!is_valid_t0_instruction(ins));
        }
        assert!(validate_t0_instruction(0x52).is_ok());
        assert!(validate_t0_instruction(0x90).is_err());
    }

    #[test]
    fn verbose_atr_decodes_oxide_se_marker_version_and_capabilities() {
        let atr = [
            0x3B, 0x1C, 0x11, 0x80, 0x56, 0x09, 0xC1, 0xDE, 0x5E, 0x09, 0x70, 0x73, 0x80, 0x00,
            0x00,
        ];
        let lines = atr_verbose_lines(&atr).join("\n");
        assert!(lines.contains("Oxide SE marker: 09 C1 DE 5E (SE = Secure Element)"));
        assert!(lines.contains("Oxide SE version: 0.9 (beta; encoded 09)"));
        assert!(lines.contains("build capabilities: 70"));
        assert!(lines.contains("bit 6 SCP11a: supported"));
        assert!(lines.contains("bit 5 SCP11b: supported"));
        assert!(lines.contains("bit 4 SCP11c: supported"));
        assert!(lines.contains("bits 1..0 SCP03 profile: not supported"));
        assert!(lines.contains("Card Capabilities byte 1 80"));
    }

    #[test]
    fn verbose_atr_documents_every_oxide_se_capability_bit() {
        let mut lines = Vec::new();
        decode_oxide_se_capabilities(0xF3, &mut lines);
        let lines = lines.join("\n");
        assert!(lines.contains("bit 7 root authority: non-null SecurityDomain"));
        assert!(lines.contains("bit 6 SCP11a: supported"));
        assert!(lines.contains("bit 5 SCP11b: supported"));
        assert!(lines.contains("bit 4 SCP11c: supported"));
        assert!(lines.contains("bits 3..2 reserved: clear"));
        assert!(lines.contains("bits 1..0 SCP03 profile: S16 supported"));
    }

    #[test]
    fn verbose_command_decodes_select_aid() {
        let command = OwnedT0Command {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            lc: 0x08,
            le: 0x00,
            data: vec![0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x20],
        };
        let fields = decode_command_fields(&command);
        let lines = command_verbose_lines(&command, &fields, false).join("\n");
        assert!(lines.contains("SELECT by DF/application name"));
        assert!(lines.contains("AID: A0 00 00 47 50 4F 53 20"));
    }

    #[test]
    fn persistent_session_commands_and_select_are_parsed() {
        let select = parse_args(
            ["select", "A0000047504F5322"]
                .map(str::to_owned)
                .into_iter(),
        )
        .unwrap();
        assert_eq!(
            select.command,
            CliCommand::Select(vec![0xA0, 0, 0, 0x47, 0x50, 0x4F, 0x53, 0x22])
        );

        let open = parse_args(
            [
                "scp03",
                "open",
                "--security-level",
                "c-mac+c-enc",
                "--keyset",
                "keys.toml",
                "--scp03-profile",
                "s16",
            ]
            .map(str::to_owned)
            .into_iter(),
        )
        .unwrap();
        assert_eq!(open.command, CliCommand::Scp03Open);
        assert_eq!(open.secure_channel.protocol, SecureChannelProtocol::Scp03);
        assert_eq!(open.secure_channel.security_level, SecurityLevel::CMacCEnc);
        assert_eq!(open.scp03_profile, Some(Scp03Profile::S16));

        assert_eq!(
            parse_args(["scp03", "inspect"].map(str::to_owned).into_iter())
                .unwrap()
                .command,
            CliCommand::Scp03Inspect
        );
        assert_eq!(
            parse_args(["scp03", "close"].map(str::to_owned).into_iter())
                .unwrap()
                .command,
            CliCommand::Scp03Close
        );
        assert_eq!(
            parse_args(["close"].map(str::to_owned).into_iter())
                .unwrap()
                .command,
            CliCommand::Close
        );
    }

    #[test]
    fn double_verbose_uses_same_color_for_raw_and_field_name() {
        let command = OwnedT0Command {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            lc: 0x08,
            le: 0x00,
            data: vec![0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x20],
        };
        let fields = decode_command_fields(&command);
        let raw = format_hex_with_fields(&command.display_bytes(), &fields);
        let lines = command_verbose_lines(&command, &fields, true).join("\n");

        assert!(raw.contains("\x1b[36m00\x1b[0m"));
        assert!(lines.contains("\x1b[36mCLA\x1b[0m: \x1b[97m00\x1b[0m"));
    }

    #[test]
    fn verbose_command_decodes_install_lv_fields() {
        let command = OwnedT0Command {
            cla: 0x80,
            ins: 0xE6,
            p1: 0x0C,
            p2: 0x00,
            lc: 0x1E,
            le: 0x00,
            data: vec![
                0x08, 0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x20, 0x08, 0xA0, 0x00, 0x00, 0x47,
                0x50, 0x4F, 0x53, 0x20, 0x08, 0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x20, 0x01,
                0x00, 0x00,
            ],
        };
        let fields = decode_command_fields(&command);
        let lines = command_verbose_lines(&command, &fields, false).join("\n");
        assert!(lines.contains("PACKAGE_AID: A0 00 00 47 50 4F 53 20"));
        assert!(lines.contains("INSTANCE_AID: A0 00 00 47 50 4F 53 20"));
        assert!(lines.contains("install summary"));
    }

    #[test]
    fn verbose_command_decodes_scp11_profile() {
        let command = OwnedT0Command {
            cla: 0x80,
            ins: 0x82,
            p1: 0x00,
            p2: 0x00,
            lc: 0x06,
            le: 0x56,
            data: vec![0xA6, 0x04, 0x90, 0x02, 0x11, 0x03],
        };
        let fields = decode_command_fields(&command);
        let lines = command_verbose_lines(&command, &fields, false).join("\n");
        assert!(lines.contains("SCP11 MUTUAL AUTHENTICATE"));
        assert!(lines.contains("SCP11 profile: SCP11c"));
    }

    #[test]
    fn serial_link_spec_accepts_tcp_endpoint() {
        assert_eq!(
            parse_link_spec("127.0.0.1:4444").unwrap(),
            LinkSpec::Tcp {
                host: "127.0.0.1".to_owned(),
                port: 4444,
            }
        );
    }

    #[test]
    fn serial_link_spec_accepts_unix_socket_path() {
        assert_eq!(
            parse_link_spec("/tmp/rustlet.sock").unwrap(),
            LinkSpec::UnixSocket {
                path: PathBuf::from("/tmp/rustlet.sock"),
            }
        );
    }

    #[test]
    fn serial_link_spec_accepts_unix_device_with_baud() {
        assert_eq!(
            parse_link_spec("/dev/tty.usbmodem1101:115200").unwrap(),
            LinkSpec::SerialPort {
                path: "/dev/tty.usbmodem1101".to_owned(),
                baud: 115_200,
            }
        );
    }

    #[test]
    fn serial_link_spec_accepts_windows_com_port_with_or_without_baud() {
        assert_eq!(
            parse_link_spec("COM3:9600").unwrap(),
            LinkSpec::SerialPort {
                path: "COM3".to_owned(),
                baud: 9_600,
            }
        );
        assert_eq!(
            parse_link_spec("COM3").unwrap(),
            LinkSpec::SerialPort {
                path: "COM3".to_owned(),
                baud: DEFAULT_SERIAL_BAUD,
            }
        );
    }

    #[test]
    fn atr_keeps_tcp_default_when_no_link_is_provided() {
        let options = parse_args(["atr"].map(str::to_owned).into_iter()).unwrap();
        assert_eq!(options.link, default_link_spec());
        assert_eq!(options.command, CliCommand::Atr);
        assert!(parse_args(["00"].map(str::to_owned).into_iter()).is_err());
    }

    #[test]
    fn serial_link_option_and_verbose_levels_are_preserved() {
        let options = parse_args(
            [
                "-v",
                "-vv",
                "--serial",
                "192.0.2.1:4567",
                "raw",
                "00",
                "02",
                "00",
                "00",
                "00",
                "00",
            ]
            .map(str::to_owned)
            .into_iter(),
        )
        .unwrap();
        assert_eq!(options.verbose, 3);
        assert_eq!(
            options.link,
            LinkSpec::Tcp {
                host: "192.0.2.1".to_owned(),
                port: 4567,
            }
        );

        assert!(parse_args(
            ["--host", "localhost", "atr"]
                .map(str::to_owned)
                .into_iter()
        )
        .is_err());
        assert!(parse_args(["--port=4444", "atr"].map(str::to_owned).into_iter()).is_err());
        assert!(parse_args(
            ["--unix-socket=/tmp/apdu.sock", "atr"]
                .map(str::to_owned)
                .into_iter()
        )
        .is_err());
    }

    #[test]
    fn secure_channel_common_options_are_parsed_together() {
        let options = parse_args(
            [
                "--secure-channel=scp11b",
                "--security-domain",
                "A0:00:00:00:03",
                "--security-level=c-mac+c-enc+r-mac+r-enc",
                "--credentials",
                "host-credentials.toml",
                "raw",
                "80",
                "02",
                "00",
                "00",
                "00",
                "00",
            ]
            .map(str::to_owned)
            .into_iter(),
        )
        .unwrap();
        assert_eq!(
            options.secure_channel,
            SecureChannelConfig {
                protocol: SecureChannelProtocol::Scp11b,
                security_domain: Some(vec![0xa0, 0x00, 0x00, 0x00, 0x03]),
                security_level: SecurityLevel::CMacCEncRMacREnc,
                credentials: Some(PathBuf::from("host-credentials.toml")),
            }
        );
    }

    #[test]
    fn timing_options_accept_units_and_infinite_atr_wait() {
        let options = parse_args(
            [
                "--connect-timeout=250ms",
                "--atr-timeout",
                "infinite",
                "--response-timeout=2s",
                "--retry-interval",
                "1m",
                "atr",
            ]
            .map(str::to_owned)
            .into_iter(),
        )
        .unwrap();
        assert_eq!(options.connect_timeout, Duration::from_millis(250));
        assert_eq!(options.atr_timeout, None);
        assert_eq!(options.response_timeout, Duration::from_secs(2));
        assert_eq!(options.retry_interval, Duration::from_secs(60));
        assert!(parse_duration("10").is_err());
        assert!(parse_nonzero_duration("0ms", "--retry-interval").is_err());
    }

    #[test]
    fn progress_is_opt_in_and_parsed_as_a_global_option() {
        let default = parse_args(["atr"].map(str::to_owned).into_iter()).unwrap();
        assert!(!default.progress);
        let enabled = parse_args(["--progress", "atr"].map(str::to_owned).into_iter()).unwrap();
        assert!(enabled.progress);
    }

    #[test]
    fn quiet_and_output_modes_are_parsed() {
        let options = parse_args(
            ["--quiet", "--output=json", "atr"]
                .map(str::to_owned)
                .into_iter(),
        )
        .unwrap();
        assert!(options.quiet);
        assert_eq!(options.output, OutputMode::Json);
        assert!(parse_args(["--output", "yaml", "atr"].map(str::to_owned).into_iter()).is_err());
    }

    #[test]
    fn gp_consultation_commands_are_parsed_and_encoded() {
        let get_data = parse_args(
            [
                "gp", "get-data", "00:66", "--format", "tlv", "--output", "card.bin",
            ]
            .map(str::to_owned)
            .into_iter(),
        )
        .unwrap();
        assert_eq!(
            get_data.command,
            CliCommand::GpGetData(GpGetDataOptions {
                tag: 0x0066,
                format: GpDataFormat::Tlv,
                output: Some(PathBuf::from("card.bin")),
            })
        );
        assert_eq!(
            gp_get_data_command(0x9F70).display_bytes(),
            [0x80, 0xCA, 0x9F, 0x70, 0, 0]
        );

        let get_status = parse_args(
            ["gp", "get-status", "applications", "--aid", "A0:00:00:03"]
                .map(str::to_owned)
                .into_iter(),
        )
        .unwrap();
        let CliCommand::GpGetStatus(options) = get_status.command else {
            panic!("wrong command")
        };
        assert_eq!(
            gp_get_status_command(&options, false).display_bytes(),
            [0x80, 0xF2, 0x40, 0x02, 0x06, 0x00, 0x4F, 0x04, 0xA0, 0x00, 0x00, 0x03]
        );
        assert_eq!(gp_get_status_command(&options, true).p2, 0x03);

        for (name, tag) in [("card-recognition", 0x0066), ("card-capabilities", 0x0067)] {
            let parsed = parse_gp_command(
                ["get-data", name, "--format", "tlv"]
                    .map(str::to_owned)
                    .to_vec(),
            )
            .unwrap();
            let CliCommand::GpGetData(options) = parsed else {
                panic!("wrong command")
            };
            assert_eq!(options.tag, tag);
        }
    }

    #[test]
    fn gp_registry_mutations_are_validated_and_encoded() {
        let CliCommand::GpMutation(store) = parse_gp_command(
            ["store-data", "DF11", "--data", "01:02:03"]
                .map(str::to_owned)
                .to_vec(),
        )
        .unwrap() else {
            panic!("wrong command")
        };
        assert_eq!(
            store.display_bytes(),
            [0x80, 0xE2, 0xA0, 0x00, 6, 0, 0xDF, 0x11, 3, 1, 2, 3]
        );

        let CliCommand::GpMutation(delete) =
            parse_gp_command(["delete-data", "DF11"].map(str::to_owned).to_vec()).unwrap()
        else {
            panic!("wrong command")
        };
        assert_eq!(&delete.data[2..], b"DATA\xDF\x11");

        assert!(parse_gp_command(
            ["set-status", "package", "A000000003", "selectable"]
                .map(str::to_owned)
                .to_vec(),
        )
        .is_err());
        assert!(parse_gp_command(
            ["store-data", "DF11", "--data", "01", "--stdin"]
                .map(str::to_owned)
                .to_vec(),
        )
        .is_err());
    }

    #[test]
    fn gp_loading_primitives_use_explicit_command_names() {
        let CliCommand::GpMutation(install_for_load) = parse_gp_command(
            [
                "install-for-load",
                "--package-aid",
                "01:00:A3:7F:E5",
                "--security-domain",
                "A0:00:00:00:03:00:00",
                "--hash",
                "AA:BB",
                "--parameters",
                "EF:02:01:00",
                "--token",
                "CC",
            ]
            .map(str::to_owned)
            .to_vec(),
        )
        .unwrap() else {
            panic!("wrong command")
        };
        assert_eq!((install_for_load.ins, install_for_load.p1), (0xe6, 0x02));
        assert_eq!(
            install_for_load.data,
            [
                5, 0x01, 0x00, 0xa3, 0x7f, 0xe5, 7, 0xa0, 0, 0, 0, 3, 0, 0, 2, 0xaa, 0xbb, 4, 0xef,
                2, 1, 0, 1, 0xcc,
            ]
        );
        let field_names = decode_command_fields(&install_for_load)
            .into_iter()
            .map(|field| field.name)
            .collect::<Vec<_>>();
        assert!(field_names.contains(&"SECURITY_DOMAIN_AID"));
        assert!(field_names.contains(&"LOAD_FILE_HASH"));
        assert!(field_names.contains(&"LOAD_PARAMS"));
        assert!(field_names.contains(&"LOAD_TOKEN"));

        let install_arguments = [
            "--package-aid",
            "01:00:A3:7F:E5",
            "--module-aid",
            "01:00:A3:7F:E5:01",
            "--instance-aid",
            "01:00:A3:7F:E5:02",
            "--privileges",
            "security-domain,delegated-management",
            "--parameters",
            "C9:00",
        ];
        for (name, p1) in [
            ("install-for-install", 0x04),
            ("install-make-selectable", 0x0c),
        ] {
            let mut arguments = vec![name.to_owned()];
            arguments.extend(install_arguments.map(str::to_owned));
            let CliCommand::GpMutation(command) = parse_gp_command(arguments).unwrap() else {
                panic!("wrong command")
            };
            assert_eq!((command.ins, command.p1, command.p2), (0xe6, p1, 0));
            assert!(command.data.windows(2).any(|value| value == [1, 0xa0]));
            assert!(command.data.ends_with(&[2, 0xc9, 0, 0]));
        }
        assert!(parse_gp_command(["install"].map(str::to_owned).to_vec()).is_err());
        assert!(parse_gp_command(["INSTALL"].map(str::to_owned).to_vec()).is_err());
    }

    #[test]
    fn gp_load_block_reads_exact_file_bytes_and_enforces_short_apdu_limit() {
        let path =
            std::env::temp_dir().join(format!("apdu-tool-load-block-{}.bin", std::process::id()));
        std::fs::write(&path, [0x00, 0x60, 0xff]).unwrap();
        let CliCommand::GpMutation(command) = parse_gp_command(vec![
            "load-block".to_owned(),
            "--number".to_owned(),
            "7".to_owned(),
            "--last".to_owned(),
            path.display().to_string(),
        ])
        .unwrap() else {
            panic!("wrong command")
        };
        assert_eq!((command.ins, command.p1, command.p2), (0xe8, 0x80, 7));
        assert_eq!(command.data, [0x00, 0x60, 0xff]);
        std::fs::write(&path, vec![0; 256]).unwrap();
        assert!(parse_gp_command(vec![
            "load-block".to_owned(),
            "--number".to_owned(),
            "0".to_owned(),
            path.display().to_string(),
        ])
        .is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn composed_load_block_plan_covers_full_last_block_and_number_limit() {
        assert_eq!(load_block_count(255, 255).unwrap(), 1);
        assert_eq!(load_block_count(510, 255).unwrap(), 2);
        assert_eq!(load_block_count(511, 255).unwrap(), 3);
        assert_eq!(load_block_count(255 * 256, 255).unwrap(), 256);
        assert!(load_block_count(255 * 256 + 1, 255).is_err());
        assert!(load_block_count(1, 0).is_err());
    }

    #[test]
    fn gp_put_key_supports_multiple_entries_and_warns_for_inline_secrets() {
        let CliCommand::GpPutKey(options) = parse_gp_command(
            [
                "put-key",
                "--version",
                "1",
                "--id",
                "3",
                "--key",
                "enc:000102030405060708090A0B0C0D0E0F",
                "--key",
                "mac:101112131415161718191A1B1C1D1E1F",
            ]
            .map(str::to_owned)
            .to_vec(),
        )
        .unwrap() else {
            panic!("wrong command")
        };
        assert_eq!(options.command.ins, gp::INS_PUT_KEY);
        assert_eq!(options.command.p1, 0x00);
        assert_eq!(options.command.p2, 0x83);
        assert_eq!(options.command.data.len(), 39);
        assert_eq!(options.warnings.len(), 2);
        assert!(format!("{:?}", options).contains("WARNING"));
        assert!(gp::put_key(
            1,
            3,
            &[gp::KeyEntry {
                usage: gp::KeyUsage::Scp03Enc,
                material: vec![0; 15]
            }]
        )
        .is_err());
        assert!(gp::put_key(
            1,
            3,
            &[gp::KeyEntry {
                usage: gp::KeyUsage::Scp03Mac,
                material: vec![0; 16]
            }]
        )
        .is_err());
    }

    #[test]
    fn gp_put_key_accepts_scp11_sd_and_ca_key_types() {
        let private = "7172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90";
        let CliCommand::GpPutKey(sd) = parse_gp_command(
            [
                "put-key",
                "--version",
                "2",
                "--id",
                "4",
                "--key",
                &format!("scp11-sd-ecka:{private}"),
            ]
            .map(str::to_owned)
            .to_vec(),
        )
        .unwrap() else {
            panic!("wrong command")
        };
        assert_eq!(sd.command.data[0], 2);
        assert_eq!(sd.command.data[1], gp::KeyUsage::Scp11SdEcka.key_type());
        assert_eq!(sd.command.data[2], 32);

        let ca = format!("04{}", "00".repeat(64));
        let CliCommand::GpPutKey(ca) = parse_gp_command(
            [
                "put-key",
                "--version",
                "2",
                "--id",
                "5",
                "--key",
                &format!("scp11-ca-kloc:{ca}"),
            ]
            .map(str::to_owned)
            .to_vec(),
        )
        .unwrap() else {
            panic!("wrong command")
        };
        assert_eq!(ca.command.data[0], 2);
        assert_eq!(ca.command.data[1], gp::KeyUsage::Scp11CaKloc.key_type());
        assert_eq!(ca.command.data[2], 65);
    }

    #[test]
    fn gp_status_records_have_stable_human_and_json_decoding() {
        let data = [
            0xE3, 0x0D, 0x4F, 0x02, 0xA0, 0x01, 0x9F, 0x70, 0x01, 0x07, 0xC5, 0x03, 0xA0, 0x00,
            0x00,
        ];
        let records = decode_gp_status_records(&data).unwrap();
        assert_eq!(records[0].aid, [0xA0, 0x01]);
        assert_eq!(records[0].lifecycle, Some(0x07));
        assert!(privilege_names(&records[0].privileges).contains("Security Domain"));

        let mut human = Vec::new();
        emit_gp_status_human(&mut human, GpStatusCategory::Applications, &data).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("Application/Security Domain : A0 01"));
        assert!(human.contains("Life cycle : selectable"));

        let mut json = Vec::new();
        let command = gp_get_status_command(
            &GpGetStatusOptions {
                category: GpStatusCategory::Applications,
                aid_filter: Vec::new(),
            },
            false,
        );
        emit_gp_status_json(&mut json, &command, GpStatusCategory::Applications, &data).unwrap();
        let json = String::from_utf8(json).unwrap();
        assert!(json.contains("\"aid\":\"A001\""));
        assert!(json.contains("\"name\":\"selectable\""));
    }

    #[test]
    fn progress_renders_requested_frames_and_clears_the_line() {
        let mut output = Vec::new();
        {
            let mut progress = Progress::new(true, &mut output);
            progress.tick("waiting ATR...");
            progress.tick("waiting ATR...");
            progress.tick("waiting ATR...");
            progress.tick("waiting ATR...");
            progress.clear();
        }
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "waiting ATR...-\rwaiting ATR...\\\rwaiting ATR...|\rwaiting ATR.../\r\r\x1b[2K"
        );

        let mut disabled_output = Vec::new();
        let mut progress = Progress::new(false, &mut disabled_output);
        progress.tick("waiting RESPONSE...");
        progress.clear();
        assert!(disabled_output.is_empty());
    }

    #[test]
    fn connection_retry_stops_after_success() {
        let mut attempts = 0;
        let result = retry_until(Duration::from_millis(50), Duration::ZERO, || {
            attempts += 1;
            if attempts < 3 {
                Err(ApduToolError::new(ErrorKind::Connection, "not ready"))
            } else {
                Ok(0x42)
            }
        })
        .unwrap();
        assert_eq!(result, 0x42);
        assert_eq!(attempts, 3);
    }

    #[test]
    fn raw_sends_before_reading_any_atr() {
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("could not bind TCP test listener: {error}"),
        };
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = [0u8; 5];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header, [0x80, 0x02, 0, 0, 0]);
            stream.write_all(&[0x90, 0x00]).unwrap();
        });
        let options = CliOptions {
            link: LinkSpec::Tcp {
                host: "127.0.0.1".to_owned(),
                port,
            },
            verbose: 0,
            progress: false,
            quiet: false,
            output: OutputMode::Human,
            connect_timeout: Duration::from_millis(100),
            atr_timeout: Some(Duration::from_millis(20)),
            response_timeout: Duration::from_millis(100),
            retry_interval: Duration::from_millis(5),
            secure_channel: SecureChannelConfig::default(),
            scp03_profile: None,
            command: CliCommand::Raw(
                OwnedT0Command::from_wire_fields(0x80, 0x02, 0, 0, 0, 0, vec![]).unwrap(),
            ),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        run_with_writers(options, &mut stdout, &mut stderr).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn atr_mode_retries_a_delayed_qemu_style_listener_and_sends_nothing() {
        let reservation = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("could not reserve TCP test port: {error}"),
        };
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let server = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            stream.write_all(&[0x3b, 0x00]).unwrap();
            let mut unexpected = [0u8; 1];
            match stream.read(&mut unexpected) {
                Ok(0) => {}
                Ok(_) => panic!("ATR mode unexpectedly transmitted data"),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => panic!("failed while checking ATR link: {error}"),
            }
        });
        let options = CliOptions {
            link: LinkSpec::Tcp {
                host: "127.0.0.1".to_owned(),
                port,
            },
            verbose: 0,
            progress: false,
            quiet: false,
            output: OutputMode::Human,
            connect_timeout: Duration::from_millis(300),
            atr_timeout: Some(Duration::from_millis(100)),
            response_timeout: Duration::from_millis(100),
            retry_interval: Duration::from_millis(5),
            secure_channel: SecureChannelConfig::default(),
            scp03_profile: None,
            command: CliCommand::Atr,
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        run_with_writers(options, &mut stdout, &mut stderr).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn atr_mode_reports_an_open_but_silent_secure_element() {
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("could not bind TCP test listener: {error}"),
        };
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(60));
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let error = run_with_writers(
            CliOptions {
                link: LinkSpec::Tcp {
                    host: "127.0.0.1".to_owned(),
                    port,
                },
                verbose: 0,
                progress: false,
                quiet: false,
                output: OutputMode::Human,
                connect_timeout: Duration::from_millis(100),
                atr_timeout: Some(Duration::from_millis(20)),
                response_timeout: Duration::from_millis(20),
                retry_interval: Duration::from_millis(5),
                secure_channel: SecureChannelConfig::default(),
                scp03_profile: None,
                command: CliCommand::Atr,
            },
            &mut stdout,
            &mut stderr,
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<ApduToolError>().unwrap().kind(),
            ErrorKind::SecureElementSilent
        );
        server.join().unwrap();
    }

    #[test]
    fn explicit_atr_and_raw_subcommands_have_distinct_models() {
        let atr = parse_args(["atr"].map(str::to_owned).into_iter()).unwrap();
        assert_eq!(atr.command, CliCommand::Atr);

        let raw = parse_args(
            ["raw", "80", "02", "00", "00", "02", "00", "AA", "BB"]
                .map(str::to_owned)
                .into_iter(),
        )
        .unwrap();
        let CliCommand::Raw(command) = raw.command else {
            panic!("expected explicit raw command");
        };
        assert_eq!(command.data, [0xaa, 0xbb]);
    }

    #[test]
    fn raw_accepts_spaced_colon_separated_and_continuous_hex() {
        let expected = vec![0x00, 0xa4, 0x04, 0x00, 0x02, 0x00, 0xaa, 0xbb];
        assert_eq!(parse_hex_text("00 A4 04 00 02 00 AA BB").unwrap(), expected);
        assert_eq!(parse_hex_text("00:A4:04:00:02:00:AA:BB").unwrap(), expected);
        assert_eq!(parse_hex_text("00A404000200AABB").unwrap(), expected);
        assert_eq!(parse_hex_text("0x00 0xA4 04000200 AABB").unwrap(), expected);
    }

    #[test]
    fn raw_file_is_read_and_validated_before_execution() {
        let path =
            std::env::temp_dir().join(format!("apdu-tool-command-{}.txt", std::process::id()));
        std::fs::write(&path, "80:02:00:00:02:00:AA:BB\n").unwrap();
        let options = parse_args(
            [
                "raw".to_owned(),
                "--file".to_owned(),
                path.to_string_lossy().into_owned(),
            ]
            .into_iter(),
        )
        .unwrap();
        std::fs::remove_file(path).unwrap();
        let CliCommand::Raw(command) = options.command else {
            panic!("expected raw command from file");
        };
        assert_eq!(command.data, [0xaa, 0xbb]);
    }

    #[test]
    fn raw_sources_are_mutually_exclusive_and_wire_length_is_strict() {
        let mixed = parse_raw_command(["--file", "command.apdu", "80"].map(str::to_owned).to_vec())
            .unwrap_err();
        assert!(mixed.to_string().contains("mutually exclusive"));

        let mismatch = parse_raw_command(
            ["80", "02", "00", "00", "02", "00", "AA"]
                .map(str::to_owned)
                .to_vec(),
        )
        .unwrap_err();
        assert!(mismatch.to_string().contains("DATA length mismatch"));
    }

    #[test]
    fn raw_rejects_invalid_instruction_before_link_is_opened() {
        let error = parse_args(
            ["raw", "80", "90", "00", "00", "00", "00"]
                .map(str::to_owned)
                .into_iter(),
        )
        .unwrap_err();
        let typed = error.downcast_ref::<ApduToolError>().unwrap();
        assert_eq!(typed.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn verbose_command_rendering_contract_is_preserved() {
        let command = OwnedT0Command {
            cla: 0x80,
            ins: 0x02,
            p1: 0,
            p2: 0,
            lc: 2,
            le: 0,
            data: vec![0x12, 0x34],
        };
        assert_eq!(
            render_command(&command, 0),
            [
                "CMD: cla:80 ins:02 p1:00 p2:00 lc:02 le:00",
                "DATA IN (2): 12 34",
            ]
        );
    }

    #[test]
    fn human_command_identifies_known_iso_and_gp_instructions() {
        let select = OwnedT0Command {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            lc: 2,
            le: 0,
            data: vec![0xA0, 0x00],
        };
        let mut output = Vec::new();
        emit_human_command(&mut output, &select).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("# INS : SELECT by DF/application name"));
        assert!(output.contains("# AID : selected DF/application name"));

        let get_response = OwnedT0Command {
            cla: 0x00,
            ins: 0xC0,
            p1: 0,
            p2: 0,
            lc: 0,
            le: 0x10,
            data: Vec::new(),
        };
        assert!(command_name(&get_response).contains("GET RESPONSE"));

        let install_for_load = OwnedT0Command {
            cla: 0x80,
            ins: 0xE6,
            p1: 0x02,
            p2: 0,
            lc: 0,
            le: 0,
            data: Vec::new(),
        };
        assert_eq!(
            command_name(&install_for_load),
            "GlobalPlatform INSTALL [for load]"
        );
    }

    #[test]
    fn output_modes_have_stable_response_contracts() {
        let response = T0Response {
            data: vec![0x9f, 0x70, 0x01, 0x07],
            status: (0x90, 0x00),
        };

        let mut quiet = Vec::new();
        emit_response(
            &mut quiet,
            &mut Vec::new(),
            &sample_command(),
            &response,
            OutputMode::Human,
            true,
        )
        .unwrap();
        assert_eq!(quiet, b"9F 70 01 07 90 00\n");

        let mut color = Vec::new();
        emit_response(
            &mut color,
            &mut Vec::new(),
            &sample_command(),
            &response,
            OutputMode::Color,
            false,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(color).unwrap(),
            "\x1b[95m9F 70 01\x1b[0m \x1b[34m07\x1b[0m \x1b[32m90 00\x1b[0m\n"
        );

        let mut human = Vec::new();
        emit_response(
            &mut human,
            &mut Vec::new(),
            &sample_command(),
            &response,
            OutputMode::Human,
            false,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(human).unwrap(),
            "\x1b[95m9F 70 01\x1b[0m # TL : tag 9F 70, length 1\n\x1b[34m07\x1b[0m # Data\n\x1b[32m90 00\x1b[0m # Status Word : Success\n"
        );

        let mut json = Vec::new();
        emit_response(
            &mut json,
            &mut Vec::new(),
            &sample_command(),
            &response,
            OutputMode::Json,
            false,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(json).unwrap(),
            "{\"kind\":\"response\",\"command\":{\"name\":\"application or proprietary APDU\",\"cla\":\"80\",\"ins\":\"02\",\"p1\":\"00\",\"p2\":\"00\",\"lc\":0,\"le\":0,\"data\":\"\"},\"data\":\"9F700107\",\"length\":4,\"status_word\":\"9000\",\"status\":\"Success\",\"success\":true}\n"
        );
    }

    #[test]
    fn binary_output_contains_only_data_and_reports_failure_status_on_stderr() {
        let response = T0Response {
            data: vec![0x01, 0x60, 0x02],
            status: (0x69, 0x85),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        emit_response(
            &mut stdout,
            &mut stderr,
            &sample_command(),
            &response,
            OutputMode::Bin,
            false,
        )
        .unwrap();
        assert_eq!(stdout, [0x01, 0x60, 0x02]);
        assert_eq!(stderr, b"SW: 69 85\n");
    }

    #[test]
    fn atr_output_supports_quiet_human_color_json_and_binary() {
        let atr = [0x3b, 0x03, 0x80, 0x11, 0xaa];
        let mut binary = Vec::new();
        emit_atr(&mut binary, &atr, OutputMode::Bin, false).unwrap();
        assert_eq!(binary, atr);

        let mut quiet = Vec::new();
        emit_atr(&mut quiet, &atr, OutputMode::Human, true).unwrap();
        assert_eq!(quiet, b"3B 03 80 11 AA\n");

        let mut human = Vec::new();
        emit_atr(&mut human, &atr, OutputMode::Human, false).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("\x1b[95m3B\x1b[0m # TS : Direct convention"));
        assert!(human.contains("\x1b[95m11\x1b[0m # Compact-TL : tag 1, length 1"));
        assert!(human.contains("\x1b[34mAA\x1b[0m # Historical data"));

        let mut json = Vec::new();
        emit_atr(&mut json, &atr, OutputMode::Json, false).unwrap();
        assert_eq!(
            String::from_utf8(json).unwrap(),
            "{\"kind\":\"atr\",\"command\":\"atr\",\"bytes\":\"3B038011AA\",\"length\":5,\"success\":true}\n"
        );
    }

    #[test]
    fn status_words_are_decoded_and_exit_codes_are_stable() {
        assert_eq!(status_word_description((0x90, 0x00)), "Success");
        assert_eq!(
            status_word_description((0x69, 0x85)),
            "Conditions of use not satisfied"
        );
        assert_eq!(
            status_word_description((0x6a, 0x88)),
            "Referenced data not found"
        );
        assert_eq!(
            error_exit_code(&ApduToolError::new(ErrorKind::Connection, "x")),
            10
        );
        assert_eq!(
            error_exit_code(&ApduToolError::new(ErrorKind::StatusWord, "x")),
            15
        );
        assert!(RunOutcome {
            status: Some((0x90, 0x00))
        }
        .success());
        assert!(!RunOutcome {
            status: Some((0x69, 0x85))
        }
        .success());
    }

    #[test]
    fn errors_are_structured_in_json_and_red_in_text_modes() {
        let error = ApduToolError::new(ErrorKind::Connection, "link \"closed\"");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        emit_error_to(OutputMode::Json, &error, &mut stdout, &mut stderr).unwrap();
        assert_eq!(
            String::from_utf8(stdout).unwrap(),
            "{\"success\":false,\"error\":\"link \\\"closed\\\"\"}\n"
        );
        assert!(stderr.is_empty());

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        emit_error_to(OutputMode::Human, &error, &mut stdout, &mut stderr).unwrap();
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "\x1b[31mError: link \"closed\"\x1b[0m\n"
        );
    }
}
