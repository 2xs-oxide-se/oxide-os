//! Transport-independent lifecycle for GlobalPlatform Secure Channels.
//!
//! Protocol implementations own their keys, counters and MAC chains through
//! [`SecureChannelEngine`].  [`SecureChannelSession`] prevents that state from
//! being used before establishment or after any security/transport failure.

use crate::{ApduToolError, ErrorKind, OwnedT0Command, T0Client, T0Response, ToolResult};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Secure Channel protocol selected by the operator.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecureChannelProtocol {
    #[default]
    None,
    Scp03,
    Scp11a,
    Scp11b,
    Scp11c,
}

impl SecureChannelProtocol {
    pub fn parse(value: &str) -> ToolResult<Self> {
        match value.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "scp03" => Ok(Self::Scp03),
            "scp11a" => Ok(Self::Scp11a),
            "scp11b" => Ok(Self::Scp11b),
            "scp11c" => Ok(Self::Scp11c),
            _ => Err(invalid_input(format!(
                "invalid Secure Channel `{value}`; expected none, scp03, scp11a, scp11b or scp11c"
            ))),
        }
    }
}

/// GlobalPlatform command/response protection requested for a session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityLevel {
    #[default]
    None,
    CMac,
    CMacCEnc,
    CMacRMac,
    CMacCEncRMac,
    CMacCEncRMacREnc,
}

impl SecurityLevel {
    pub fn parse(value: &str) -> ToolResult<Self> {
        let normalized = value.to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "none" => Ok(Self::None),
            "c-mac" => Ok(Self::CMac),
            "c-mac+c-enc" => Ok(Self::CMacCEnc),
            "c-mac+r-mac" => Ok(Self::CMacRMac),
            "c-mac+c-enc+r-mac" => Ok(Self::CMacCEncRMac),
            "c-mac+c-enc+r-mac+r-enc" => Ok(Self::CMacCEncRMacREnc),
            _ => Err(invalid_input(format!(
                "invalid security level `{value}`; expected none, c-mac, c-mac+c-enc, c-mac+r-mac, c-mac+c-enc+r-mac or c-mac+c-enc+r-mac+r-enc"
            ))),
        }
    }

    /// GlobalPlatform security-level bit field.
    pub const fn bits(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::CMac => 0x01,
            Self::CMacCEnc => 0x03,
            Self::CMacRMac => 0x11,
            Self::CMacCEncRMac => 0x13,
            Self::CMacCEncRMacREnc => 0x33,
        }
    }
}

/// Reusable operator configuration. Credential files may refer to secrets;
/// secret bytes themselves deliberately have no environment-variable option.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecureChannelConfig {
    pub protocol: SecureChannelProtocol,
    pub security_domain: Option<Vec<u8>>,
    pub security_level: SecurityLevel,
    pub credentials: Option<PathBuf>,
}

impl SecureChannelConfig {
    pub fn validate(&self) -> ToolResult<()> {
        if self.protocol == SecureChannelProtocol::None
            && (self.security_domain.is_some()
                || self.security_level != SecurityLevel::None
                || self.credentials.is_some())
        {
            return Err(invalid_input(
                "--security-domain, --security-level and --credentials require --secure-channel",
            ));
        }
        if self.protocol != SecureChannelProtocol::None && self.credentials.is_none() {
            return Err(invalid_input(
                "a Secure Channel requires --credentials or APDU_CREDENTIALS",
            ));
        }
        Ok(())
    }
}

/// Minimal APDU transport used during establishment and protected exchanges.
pub trait CommandTransport {
    fn exchange_command(&mut self, command: &OwnedT0Command) -> ToolResult<T0Response>;
}

impl CommandTransport for T0Client {
    fn exchange_command(&mut self, command: &OwnedT0Command) -> ToolResult<T0Response> {
        self.exchange(command.as_borrowed())
    }
}

/// Protocol-specific cryptographic state owned by one session.
///
/// Implementations keep static/session keys, counters and MAC chains private.
/// `clear` must erase sensitive state as far as its concrete storage permits.
pub trait SecureChannelEngine {
    fn establish(
        &mut self,
        transport: &mut dyn CommandTransport,
        config: &SecureChannelConfig,
    ) -> ToolResult<()>;
    /// Reject commands which the authentication profile cannot authorize
    /// before any bytes are sent to the card.
    fn validate_command(&self, _command: &OwnedT0Command) -> ToolResult<()> {
        Ok(())
    }
    fn protect(&mut self, command: &OwnedT0Command) -> ToolResult<OwnedT0Command>;
    fn unprotect(&mut self, response: T0Response) -> ToolResult<T0Response>;
    /// Additional bytes for a plaintext length. The resulting wrapped length
    /// (`plaintext_len + overhead`) must be monotonically non-decreasing.
    fn command_overhead(&self, plaintext_len: usize) -> ToolResult<usize>;
    fn clear(&mut self);
}

/// Reason why a session can no longer be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidationReason {
    Establishment,
    CommandProtection,
    ResponseVerification,
    Transport,
}

/// Observable lifecycle; an invalidated session can never be re-established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    New,
    Established,
    Invalidated(InvalidationReason),
    Closed,
}

/// One connection-bound Secure Channel session.
pub struct SecureChannelSession<E: SecureChannelEngine> {
    config: SecureChannelConfig,
    engine: E,
    state: SessionState,
}

impl<E: SecureChannelEngine> fmt::Debug for SecureChannelSession<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecureChannelSession")
            .field("protocol", &self.config.protocol)
            .field("security_domain", &self.config.security_domain)
            .field("security_level", &self.config.security_level)
            .field(
                "credentials",
                &self.config.credentials.as_ref().map(|_| "[configured]"),
            )
            .field("state", &self.state)
            .finish()
    }
}

impl<E: SecureChannelEngine> SecureChannelSession<E> {
    pub fn new(config: SecureChannelConfig, engine: E) -> ToolResult<Self> {
        config.validate()?;
        if config.protocol == SecureChannelProtocol::None {
            return Err(invalid_input(
                "a SecureChannelSession cannot use the `none` protocol",
            ));
        }
        Ok(Self {
            config,
            engine,
            state: SessionState::New,
        })
    }

    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Restore an engine whose state was authenticated and persisted by a
    /// previous process. This deliberately bypasses credential validation:
    /// the restored engine already owns derived session keys.
    pub fn from_established(config: SecureChannelConfig, engine: E) -> Self {
        Self {
            config,
            engine,
            state: SessionState::Established,
        }
    }

    pub fn engine(&self) -> &E {
        &self.engine
    }

    pub fn config(&self) -> &SecureChannelConfig {
        &self.config
    }

    pub fn establish(&mut self, transport: &mut dyn CommandTransport) -> ToolResult<()> {
        self.require_state(SessionState::New, "establish")?;
        if let Err(error) = self.engine.establish(transport, &self.config) {
            self.invalidate(InvalidationReason::Establishment);
            return Err(error);
        }
        self.state = SessionState::Established;
        Ok(())
    }

    /// Protect, exchange and verify on the same borrowed transport/session.
    pub fn exchange(
        &mut self,
        transport: &mut dyn CommandTransport,
        command: &OwnedT0Command,
    ) -> ToolResult<T0Response> {
        self.require_state(SessionState::Established, "exchange")?;
        self.engine.validate_command(command)?;
        let protected = match self.engine.protect(command) {
            Ok(command) => command,
            Err(error) => {
                self.invalidate(InvalidationReason::CommandProtection);
                return Err(error);
            }
        };
        let response = match transport.exchange_command(&protected) {
            Ok(response) => response,
            Err(error) => {
                self.invalidate(InvalidationReason::Transport);
                return Err(error);
            }
        };
        match self.engine.unprotect(response) {
            Ok(response) => Ok(response),
            Err(error) => {
                self.invalidate(InvalidationReason::ResponseVerification);
                Err(error)
            }
        }
    }

    /// Maximum plaintext data that fits after protocol-specific wrapping.
    pub fn max_plaintext_data(&self, apdu_data_capacity: usize) -> ToolResult<usize> {
        self.require_state(SessionState::Established, "calculate APDU capacity")?;
        let mut low = 0usize;
        let mut high = apdu_data_capacity;
        while low < high {
            let candidate = low + (high - low).div_ceil(2);
            let overhead = self.engine.command_overhead(candidate)?;
            if candidate
                .checked_add(overhead)
                .is_some_and(|wrapped| wrapped <= apdu_data_capacity)
            {
                low = candidate;
            } else {
                high = candidate - 1;
            }
        }
        Ok(low)
    }

    pub fn close(&mut self) {
        self.engine.clear();
        self.state = SessionState::Closed;
    }

    fn invalidate(&mut self, reason: InvalidationReason) {
        self.engine.clear();
        self.state = SessionState::Invalidated(reason);
    }

    fn require_state(&self, expected: SessionState, operation: &str) -> ToolResult<()> {
        if self.state == expected {
            return Ok(());
        }
        Err(ApduToolError::new(
            ErrorKind::SecureChannel,
            format!(
                "cannot {operation} Secure Channel while session state is {:?}",
                self.state
            ),
        ))
    }
}

impl<E: SecureChannelEngine> Drop for SecureChannelSession<E> {
    fn drop(&mut self) {
        self.engine.clear();
    }
}

fn invalid_input(message: impl Into<String>) -> ApduToolError {
    ApduToolError::new(ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct DeterministicEngine {
        counter: u8,
        cleared: bool,
        reject_response: bool,
    }

    impl SecureChannelEngine for DeterministicEngine {
        fn establish(
            &mut self,
            _transport: &mut dyn CommandTransport,
            _config: &SecureChannelConfig,
        ) -> ToolResult<()> {
            self.counter = 1;
            Ok(())
        }

        fn protect(&mut self, command: &OwnedT0Command) -> ToolResult<OwnedT0Command> {
            let mut protected = command.clone();
            protected.cla |= 0x04;
            protected.data.push(self.counter);
            protected.lc = protected.data.len() as u8;
            self.counter += 1;
            Ok(protected)
        }

        fn unprotect(&mut self, response: T0Response) -> ToolResult<T0Response> {
            if self.reject_response {
                return Err(ApduToolError::new(
                    ErrorKind::SecureChannel,
                    "deterministic invalid MAC",
                ));
            }
            Ok(response)
        }

        fn command_overhead(&self, plaintext_len: usize) -> ToolResult<usize> {
            Ok(1 + usize::from(!plaintext_len.is_multiple_of(16)))
        }

        fn clear(&mut self) {
            self.counter = 0;
            self.cleared = true;
        }
    }

    #[derive(Default)]
    struct RecordingTransport {
        commands: Vec<OwnedT0Command>,
        fail: bool,
    }

    impl CommandTransport for RecordingTransport {
        fn exchange_command(&mut self, command: &OwnedT0Command) -> ToolResult<T0Response> {
            if self.fail {
                return Err(ApduToolError::new(
                    ErrorKind::SecureElementSilent,
                    "deterministic timeout",
                ));
            }
            self.commands.push(command.clone());
            Ok(T0Response {
                data: vec![0x42],
                status: (0x90, 0x00),
            })
        }
    }

    fn config() -> SecureChannelConfig {
        SecureChannelConfig {
            protocol: SecureChannelProtocol::Scp03,
            security_domain: Some(vec![0xa0, 0x00, 0x00, 0x00, 0x03]),
            security_level: SecurityLevel::CMacCEnc,
            credentials: Some(PathBuf::from("keys.toml")),
        }
    }

    fn command() -> OwnedT0Command {
        OwnedT0Command::from_wire_fields(0x80, 0xca, 0x00, 0x66, 1, 0, vec![0xaa]).unwrap()
    }

    #[test]
    fn deterministic_session_reuses_one_engine_and_transport() {
        let mut session =
            SecureChannelSession::new(config(), DeterministicEngine::default()).unwrap();
        let mut transport = RecordingTransport::default();
        session.establish(&mut transport).unwrap();
        session.exchange(&mut transport, &command()).unwrap();
        session.exchange(&mut transport, &command()).unwrap();
        assert_eq!(session.state(), SessionState::Established);
        assert_eq!(transport.commands[0].data, [0xaa, 1]);
        assert_eq!(transport.commands[1].data, [0xaa, 2]);
        assert_eq!(session.max_plaintext_data(255).unwrap(), 253);
    }

    #[test]
    fn invalid_response_permanently_invalidates_and_clears_session() {
        let engine = DeterministicEngine {
            reject_response: true,
            ..DeterministicEngine::default()
        };
        let mut session = SecureChannelSession::new(config(), engine).unwrap();
        let mut transport = RecordingTransport::default();
        session.establish(&mut transport).unwrap();
        assert!(session.exchange(&mut transport, &command()).is_err());
        assert_eq!(
            session.state(),
            SessionState::Invalidated(InvalidationReason::ResponseVerification)
        );
        assert!(session.engine.cleared);
        assert!(session.exchange(&mut transport, &command()).is_err());
    }

    #[test]
    fn transport_failure_invalidates_session() {
        let mut session =
            SecureChannelSession::new(config(), DeterministicEngine::default()).unwrap();
        let mut transport = RecordingTransport {
            fail: true,
            ..RecordingTransport::default()
        };
        session.establish(&mut transport).unwrap();
        assert!(session.exchange(&mut transport, &command()).is_err());
        assert_eq!(
            session.state(),
            SessionState::Invalidated(InvalidationReason::Transport)
        );
    }

    #[test]
    fn configuration_rejects_context_without_protocol() {
        let invalid = SecureChannelConfig {
            security_level: SecurityLevel::CMac,
            ..SecureChannelConfig::default()
        };
        assert!(invalid.validate().is_err());

        let missing_credentials = SecureChannelConfig {
            protocol: SecureChannelProtocol::Scp11c,
            security_level: SecurityLevel::CMacCEncRMacREnc,
            ..SecureChannelConfig::default()
        };
        assert!(missing_credentials.validate().is_err());
    }
}
