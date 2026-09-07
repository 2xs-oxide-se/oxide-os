//! Persistent command-line session state.
//!
//! A Secure Channel snapshot contains live derived keys and chaining values.
//! The file is therefore created atomically with owner-only permissions and
//! is never included in Debug or user-facing inspection output.

use crate::scp03::Scp03Snapshot;
use crate::secure_channel::{SecureChannelProtocol, SecurityLevel};
use crate::{ApduToolError, ErrorKind, LinkSpec, ToolResult};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub const SESSION_FILE_ENV: &str = "APDU_SESSION_FILE";
const SESSION_VERSION: u8 = 1;
const MAX_SESSION_SIZE: u64 = 64 * 1024;

#[derive(Serialize, Deserialize)]
pub struct SessionFile {
    version: u8,
    pub link: LinkSpec,
    pub atr: Vec<u8>,
    pub selected_aid: Option<Vec<u8>>,
    pub secure_channel: Option<PersistedSecureChannel>,
}

#[derive(Serialize, Deserialize)]
pub struct PersistedSecureChannel {
    pub protocol: SecureChannelProtocol,
    pub security_domain: Option<Vec<u8>>,
    pub security_level: SecurityLevel,
    pub scp03: Scp03Snapshot,
}

impl SessionFile {
    pub fn new(link: LinkSpec, atr: Vec<u8>) -> Self {
        Self {
            version: SESSION_VERSION,
            link,
            atr,
            selected_aid: None,
            secure_channel: None,
        }
    }

    pub fn protocol(&self) -> SecureChannelProtocol {
        self.secure_channel
            .as_ref()
            .map(|channel| channel.protocol)
            .unwrap_or(SecureChannelProtocol::None)
    }
}

pub fn path_from_environment() -> ToolResult<PathBuf> {
    match std::env::var_os(SESSION_FILE_ENV) {
        Some(value) if value.is_empty() => Err(session_error(format!(
            "environment variable {SESSION_FILE_ENV} must not be empty"
        ))),
        Some(value) => Ok(PathBuf::from(value)),
        None => Ok(PathBuf::from("session.json")),
    }
}

pub fn load(path: &Path) -> ToolResult<SessionFile> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ApduToolError::with_source(
            ErrorKind::InvalidInput,
            format!("cannot open APDU session {}", path.display()),
            error,
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(session_error(format!(
            "APDU session {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_SESSION_SIZE {
        return Err(session_error(format!(
            "APDU session {} exceeds 64 KiB",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(session_error(format!(
                "APDU session {} is accessible by group or other users; run chmod 600 or remove it",
                path.display()
            )));
        }
    }
    let bytes = fs::read(path).map_err(|error| {
        ApduToolError::with_source(
            ErrorKind::InvalidInput,
            format!("cannot read APDU session {}", path.display()),
            error,
        )
    })?;
    let session: SessionFile = serde_json::from_slice(&bytes).map_err(|error| {
        ApduToolError::with_source(
            ErrorKind::InvalidInput,
            format!("invalid APDU session {}", path.display()),
            error,
        )
    })?;
    if session.version != SESSION_VERSION {
        return Err(session_error(format!(
            "unsupported APDU session version {} in {}",
            session.version,
            path.display()
        )));
    }
    Ok(session)
}

pub fn save(path: &Path, session: &SessionFile) -> ToolResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent)
            .map_err(|error| io_error(path, "create session directory", error))?;
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| session_error("session path must name a UTF-8 file"))?;
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&temporary)
        .map_err(|error| io_error(&temporary, "create temporary session", error))?;
    let write_result = (|| {
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, session).map_err(|error| {
            ApduToolError::with_source(ErrorKind::InvalidInput, "cannot encode APDU session", error)
        })?;
        writer
            .write_all(b"\n")
            .map_err(|error| io_error(&temporary, "write session", error))?;
        writer
            .flush()
            .map_err(|error| io_error(&temporary, "flush session", error))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|error| io_error(&temporary, "sync session", error))?;
        fs::rename(&temporary, path).map_err(|error| io_error(path, "publish session", error))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

pub fn remove(path: &Path) -> ToolResult<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(path, "remove session", error)),
    }
}

fn io_error(path: &Path, operation: &str, error: std::io::Error) -> ApduToolError {
    ApduToolError::with_source(
        ErrorKind::InvalidInput,
        format!("cannot {operation} {}", path.display()),
        error,
    )
}

fn session_error(message: impl Into<String>) -> ApduToolError {
    ApduToolError::new(ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_session_round_trips() {
        let directory = std::env::temp_dir().join(format!(
            "apdu-tool-session-test-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("session.json");
        let expected = SessionFile::new(
            LinkSpec::Tcp {
                host: "127.0.0.1".into(),
                port: 4444,
            },
            vec![0x3b, 0x00],
        );
        save(&path, &expected).unwrap();
        let actual = load(&path).unwrap();
        assert_eq!(actual.link, expected.link);
        assert_eq!(actual.atr, expected.atr);
        assert_eq!(actual.protocol(), SecureChannelProtocol::None);
        remove(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
}
