//! Host-side GlobalPlatform SCP03 S8/S16 engine.

use crate::gp;
use crate::secure_channel::{
    CommandTransport, SecureChannelConfig, SecureChannelEngine, SecurityLevel,
};
use crate::{ApduToolError, ErrorKind, OwnedT0Command, T0Response, ToolResult};
use aes::cipher::{
    block_padding::Iso7816, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit,
};
use cmac::{Cmac, Mac};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroize;

const AES_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scp03Profile {
    S8,
    S16,
}

impl Scp03Profile {
    pub fn parse(value: &str) -> ToolResult<Self> {
        match value.to_ascii_lowercase().as_str() {
            "s8" => Ok(Self::S8),
            "s16" => Ok(Self::S16),
            _ => Err(sc_error(format!(
                "invalid SCP03 profile `{value}`; expected s8 or s16"
            ))),
        }
    }

    pub const fn challenge_len(self) -> usize {
        match self {
            Self::S8 => 8,
            Self::S16 => 16,
        }
    }

    pub const fn mac_len(self) -> usize {
        self.challenge_len()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysetFile {
    version: u8,
    #[serde(default)]
    id: u8,
    profile: Option<String>,
    enc: String,
    mac: String,
}

/// Static SCP03 AES-128 keyset. Debug output never exposes key material.
#[derive(PartialEq, Eq)]
pub struct Scp03Keyset {
    pub version: u8,
    pub id: u8,
    enc: [u8; AES_LEN],
    mac: [u8; AES_LEN],
    pub profile: Option<Scp03Profile>,
}

impl std::fmt::Debug for Scp03Keyset {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Scp03Keyset")
            .field("version", &self.version)
            .field("id", &self.id)
            .field("profile", &self.profile)
            .field("enc", &"[REDACTED]")
            .field("mac", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Scp03Keyset {
    fn drop(&mut self) {
        self.enc.zeroize();
        self.mac.zeroize();
    }
}

impl Scp03Keyset {
    pub fn load(path: &Path) -> ToolResult<(Self, Vec<String>)> {
        let metadata = fs::metadata(path).map_err(|error| {
            ApduToolError::with_source(
                ErrorKind::SecureChannel,
                format!("cannot inspect SCP03 keyset {}", path.display()),
                error,
            )
        })?;
        if !metadata.is_file() {
            return Err(sc_error(format!(
                "SCP03 keyset {} is not a regular file",
                path.display()
            )));
        }
        if metadata.len() > 64 * 1024 {
            return Err(sc_error(format!(
                "SCP03 keyset {} exceeds the 64 KiB safety limit",
                path.display()
            )));
        }
        let mut warnings = Vec::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                warnings.push(format!(
                    "WARNING: SCP03 keyset {} is accessible by group or other users; use chmod 600",
                    path.display()
                ));
            }
        }
        let mut text = fs::read_to_string(path).map_err(|error| {
            ApduToolError::with_source(
                ErrorKind::SecureChannel,
                format!("cannot read SCP03 keyset {}", path.display()),
                error,
            )
        })?;
        let mut parsed: KeysetFile = match toml::from_str(&text) {
            Ok(parsed) => parsed,
            Err(error) => {
                text.zeroize();
                return Err(ApduToolError::with_source(
                    ErrorKind::SecureChannel,
                    format!("invalid SCP03 keyset {}", path.display()),
                    error,
                ));
            }
        };
        text.zeroize();
        let result = (|| {
            Ok(Self {
                version: parsed.version,
                id: parsed.id,
                enc: parse_aes128(&parsed.enc, "enc")?,
                mac: parse_aes128(&parsed.mac, "mac")?,
                profile: parsed
                    .profile
                    .as_deref()
                    .map(Scp03Profile::parse)
                    .transpose()?,
            })
        })();
        parsed.enc.zeroize();
        parsed.mac.zeroize();
        Ok((result?, warnings))
    }
}

struct SessionKeys {
    enc: [u8; AES_LEN],
    mac: [u8; AES_LEN],
    rmac: [u8; AES_LEN],
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.enc.zeroize();
        self.mac.zeroize();
        self.rmac.zeroize();
    }
}

/// Concrete engine plugged into `SecureChannelSession`.
pub struct Scp03Engine {
    keyset: Option<Scp03Keyset>,
    profile: Scp03Profile,
    host_challenge: Option<Vec<u8>>,
    keys: Option<SessionKeys>,
    command_chain: [u8; AES_LEN],
    response_chain: [u8; AES_LEN],
    command_counter: u32,
    response_counter: u32,
    level: SecurityLevel,
}

/// Sensitive, resumable SCP03 state. It may only be written to a protected
/// session file and must never be rendered by ordinary CLI output.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scp03Snapshot {
    profile: Scp03Profile,
    enc: [u8; AES_LEN],
    mac: [u8; AES_LEN],
    rmac: [u8; AES_LEN],
    command_chain: [u8; AES_LEN],
    response_chain: [u8; AES_LEN],
    command_counter: u32,
    response_counter: u32,
    level: SecurityLevel,
}

impl std::fmt::Debug for Scp03Snapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Scp03Snapshot")
            .field("profile", &self.profile)
            .field("keys", &"[REDACTED]")
            .field("chains", &"[REDACTED]")
            .field("command_counter", &self.command_counter)
            .field("response_counter", &self.response_counter)
            .field("level", &self.level)
            .finish()
    }
}

impl Drop for Scp03Snapshot {
    fn drop(&mut self) {
        self.enc.zeroize();
        self.mac.zeroize();
        self.rmac.zeroize();
        self.command_chain.zeroize();
        self.response_chain.zeroize();
        self.command_counter = 0;
        self.response_counter = 0;
    }
}

impl std::fmt::Debug for Scp03Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Scp03Engine")
            .field("keyset", &self.keyset)
            .field("profile", &self.profile)
            .field("established", &self.keys.is_some())
            .field("level", &self.level)
            .finish()
    }
}

impl Scp03Engine {
    pub fn new(keyset: Scp03Keyset, profile: Scp03Profile) -> Self {
        Self {
            keyset: Some(keyset),
            profile,
            host_challenge: None,
            keys: None,
            command_chain: [0; AES_LEN],
            response_chain: [0; AES_LEN],
            command_counter: 0,
            response_counter: 0,
            level: SecurityLevel::None,
        }
    }

    pub fn from_snapshot(snapshot: Scp03Snapshot) -> Self {
        Self {
            keyset: None,
            profile: snapshot.profile,
            host_challenge: None,
            keys: Some(SessionKeys {
                enc: snapshot.enc,
                mac: snapshot.mac,
                rmac: snapshot.rmac,
            }),
            command_chain: snapshot.command_chain,
            response_chain: snapshot.response_chain,
            command_counter: snapshot.command_counter,
            response_counter: snapshot.response_counter,
            level: snapshot.level,
        }
    }

    pub fn snapshot(&self) -> ToolResult<Scp03Snapshot> {
        let keys = self.session_keys()?;
        Ok(Scp03Snapshot {
            profile: self.profile,
            enc: keys.enc,
            mac: keys.mac,
            rmac: keys.rmac,
            command_chain: self.command_chain,
            response_chain: self.response_chain,
            command_counter: self.command_counter,
            response_counter: self.response_counter,
            level: self.level,
        })
    }

    #[cfg(test)]
    fn with_challenge(mut self, challenge: &[u8]) -> Self {
        self.host_challenge = Some(challenge.to_vec());
        self
    }

    fn session_keys(&self) -> ToolResult<&SessionKeys> {
        self.keys
            .as_ref()
            .ok_or_else(|| sc_error("SCP03 session keys are not established"))
    }
}

impl SecureChannelEngine for Scp03Engine {
    fn establish(
        &mut self,
        transport: &mut dyn CommandTransport,
        config: &SecureChannelConfig,
    ) -> ToolResult<()> {
        if let Some(aid) = &config.security_domain {
            if !(5..=16).contains(&aid.len()) {
                return Err(sc_error("Security Domain AID length must be in 5..=16"));
            }
            let select = OwnedT0Command::from_wire_fields(
                0x00,
                0xa4,
                0x04,
                0x00,
                u8::try_from(aid.len()).map_err(|_| sc_error("Security Domain AID is too long"))?,
                0x00,
                aid.clone(),
            )?;
            require_success(
                transport.exchange_command(&select)?,
                "SELECT Security Domain",
            )?;
        }
        self.level = config.security_level;
        if self.level == SecurityLevel::None {
            return Err(sc_error("SCP03 requires a non-empty --security-level"));
        }
        let host_challenge = match self.host_challenge.take() {
            Some(value) => value,
            None => random_bytes(self.profile.challenge_len())?,
        };
        if host_challenge.len() != self.profile.challenge_len() {
            return Err(sc_error(
                "SCP03 host challenge has the wrong profile length",
            ));
        }
        let initialize = gp::command(
            gp::INS_INITIALIZE_UPDATE,
            self.keyset
                .as_ref()
                .ok_or_else(|| sc_error("restored SCP03 state cannot be established again"))?
                .version,
            0x00,
            &host_challenge,
            if self.profile == Scp03Profile::S16 {
                0x2c
            } else {
                0x1c
            },
        )?;
        let response = transport.exchange_command(&initialize)?;
        require_success(response.clone(), "INITIALIZE UPDATE")?;
        let prefix_len = 12;
        let expected_len = prefix_len + self.profile.challenge_len() + self.profile.mac_len();
        if response.data.len() != expected_len {
            return Err(sc_error(format!(
                "INITIALIZE UPDATE returned {} bytes; expected {expected_len} for {:?}",
                response.data.len(),
                self.profile
            )));
        }
        let keyset = self
            .keyset
            .as_ref()
            .ok_or_else(|| sc_error("restored SCP03 state cannot be established again"))?;
        if response.data[10] != keyset.version || response.data[11] != 0x03 {
            return Err(sc_error(
                "INITIALIZE UPDATE selected a different key version or protocol",
            ));
        }
        let card_start = prefix_len;
        let card_end = card_start + self.profile.challenge_len();
        let card_challenge = &response.data[card_start..card_end];
        let card_cryptogram = &response.data[card_end..];
        let context = [&host_challenge[..], card_challenge].concat();
        let keys = SessionKeys {
            enc: kdf(&keyset.enc, 0x04, &context, AES_LEN)?
                .try_into()
                .unwrap(),
            mac: kdf(&keyset.mac, 0x06, &context, AES_LEN)?
                .try_into()
                .unwrap(),
            rmac: kdf(&keyset.mac, 0x07, &context, AES_LEN)?
                .try_into()
                .unwrap(),
        };
        let expected_card = kdf(&keys.mac, 0x00, &context, self.profile.mac_len())?;
        if !constant_time_eq(card_cryptogram, &expected_card) {
            return Err(sc_error(
                "INITIALIZE UPDATE card cryptogram verification failed",
            ));
        }
        let host_cryptogram = kdf(&keys.mac, 0x01, &context, self.profile.mac_len())?;
        let lc = host_cryptogram.len() + self.profile.mac_len();
        let header = [0x84, 0x82, self.level.bits(), 0x00, lc as u8];
        let full_mac = chained_cmac(&keys.mac, &[0; AES_LEN], &[&header, &host_cryptogram])?;
        let mut auth_data = host_cryptogram;
        auth_data.extend_from_slice(&full_mac[..self.profile.mac_len()]);
        let authenticate = OwnedT0Command::from_wire_fields(
            0x84,
            0x82,
            self.level.bits(),
            0,
            lc as u8,
            0,
            auth_data,
        )?;
        require_success(
            transport.exchange_command(&authenticate)?,
            "EXTERNAL AUTHENTICATE",
        )?;
        self.command_chain = full_mac;
        self.response_chain = full_mac;
        self.keys = Some(keys);
        Ok(())
    }

    fn protect(&mut self, command: &OwnedT0Command) -> ToolResult<OwnedT0Command> {
        let keys = self.session_keys()?;
        let mut next_counter = self.command_counter;
        let mut body = if uses_command_encryption(self.level) && !command.data.is_empty() {
            let iv = next_iv(&keys.enc, &mut next_counter, 0x01)?;
            encrypt(&keys.enc, &iv, &command.data)?
        } else {
            command.data.clone()
        };
        let final_len = body
            .len()
            .checked_add(self.profile.mac_len())
            .filter(|len| *len <= u8::MAX as usize)
            .ok_or_else(|| sc_error("protected SCP03 command exceeds short APDU capacity"))?;
        let header = [0x84, command.ins, command.p1, command.p2, final_len as u8];
        let full_mac = chained_cmac(&keys.mac, &self.command_chain, &[&header, &body])?;
        body.extend_from_slice(&full_mac[..self.profile.mac_len()]);
        self.command_chain = full_mac;
        self.command_counter = next_counter;
        OwnedT0Command::from_wire_fields(
            0x84,
            command.ins,
            command.p1,
            command.p2,
            final_len as u8,
            command.le,
            body,
        )
    }

    fn unprotect(&mut self, response: T0Response) -> ToolResult<T0Response> {
        if !uses_response_mac(self.level) {
            return Ok(response);
        }
        let data_len = response
            .data
            .len()
            .checked_sub(self.profile.mac_len())
            .ok_or_else(|| sc_error("SCP03 protected response is missing R-MAC"))?;
        let (protected_data, received_mac) = response.data.split_at(data_len);
        let keys = self.session_keys()?;
        let status_bytes = [response.status.0, response.status.1];
        let expected = chained_cmac(
            &keys.rmac,
            &self.response_chain,
            &[protected_data, &status_bytes],
        )?;
        if !constant_time_eq(received_mac, &expected[..self.profile.mac_len()]) {
            return Err(sc_error("SCP03 response MAC verification failed"));
        }
        let mut next_counter = self.response_counter;
        let data = if protected_data.is_empty() {
            Vec::new()
        } else if uses_response_encryption(self.level) {
            let iv = next_iv(&keys.enc, &mut next_counter, 0x02)?;
            decrypt(&keys.enc, &iv, protected_data)?
        } else {
            protected_data.to_vec()
        };
        self.response_chain = expected;
        self.response_counter = next_counter;
        Ok(T0Response {
            data,
            status: response.status,
        })
    }

    fn command_overhead(&self, plaintext_len: usize) -> ToolResult<usize> {
        let protected_len = if uses_command_encryption(self.level) && plaintext_len != 0 {
            padded_len(plaintext_len)?
        } else {
            plaintext_len
        };
        Ok(protected_len + self.profile.mac_len() - plaintext_len)
    }

    fn clear(&mut self) {
        if let Some(mut keys) = self.keys.take() {
            keys.enc.zeroize();
            keys.mac.zeroize();
            keys.rmac.zeroize();
        }
        self.command_chain.zeroize();
        self.response_chain.zeroize();
        self.command_counter = 0;
        self.response_counter = 0;
    }
}

fn uses_command_encryption(level: SecurityLevel) -> bool {
    matches!(
        level,
        SecurityLevel::CMacCEnc | SecurityLevel::CMacCEncRMac | SecurityLevel::CMacCEncRMacREnc
    )
}

fn uses_response_mac(level: SecurityLevel) -> bool {
    matches!(
        level,
        SecurityLevel::CMacRMac | SecurityLevel::CMacCEncRMac | SecurityLevel::CMacCEncRMacREnc
    )
}

fn uses_response_encryption(level: SecurityLevel) -> bool {
    level == SecurityLevel::CMacCEncRMacREnc
}

fn require_success(response: T0Response, operation: &str) -> ToolResult<T0Response> {
    if response.status == (0x90, 0x00) {
        Ok(response)
    } else {
        Err(sc_error(format!(
            "{operation} failed with status {:02X}{:02X}",
            response.status.0, response.status.1
        )))
    }
}

fn random_bytes(len: usize) -> ToolResult<Vec<u8>> {
    #[cfg(unix)]
    {
        let mut bytes = vec![0u8; len];
        fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|error| {
                ApduToolError::with_source(
                    ErrorKind::SecureChannel,
                    "cannot obtain an SCP03 host challenge from the operating system",
                    error,
                )
            })?;
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = len;
        Err(sc_error(
            "secure SCP03 host challenge generation is unavailable on this platform",
        ))
    }
}

fn parse_aes128(text: &str, name: &str) -> ToolResult<[u8; AES_LEN]> {
    let mut compact: String = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != ':')
        .collect();
    if compact.len() != AES_LEN * 2 || !compact.chars().all(|ch| ch.is_ascii_hexdigit()) {
        compact.zeroize();
        return Err(sc_error(format!(
            "SCP03 `{name}` must contain exactly 16 hexadecimal bytes"
        )));
    }
    let mut out = [0u8; AES_LEN];
    for (index, byte) in out.iter_mut().enumerate() {
        match u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16) {
            Ok(value) => *byte = value,
            Err(_) => {
                compact.zeroize();
                out.zeroize();
                return Err(sc_error(format!("invalid hexadecimal SCP03 `{name}`")));
            }
        }
    }
    compact.zeroize();
    Ok(out)
}

fn kdf(key: &[u8; AES_LEN], constant: u8, context: &[u8], len: usize) -> ToolResult<Vec<u8>> {
    let mut input = vec![0u8; 11];
    input.push(constant);
    input.push(0);
    input.extend_from_slice(&((len as u16) * 8).to_be_bytes());
    input.push(1);
    input.extend_from_slice(context);
    Ok(cmac(key, &[&input])?[..len].to_vec())
}

fn chained_cmac(
    key: &[u8; AES_LEN],
    chain: &[u8; AES_LEN],
    parts: &[&[u8]],
) -> ToolResult<[u8; AES_LEN]> {
    let mut all = Vec::with_capacity(AES_LEN + parts.iter().map(|part| part.len()).sum::<usize>());
    all.extend_from_slice(chain);
    for part in parts {
        all.extend_from_slice(part);
    }
    cmac(key, &[&all])
}

fn cmac(key: &[u8; AES_LEN], parts: &[&[u8]]) -> ToolResult<[u8; AES_LEN]> {
    let mut mac = <Cmac<aes::Aes128> as Mac>::new_from_slice(key)
        .map_err(|_| sc_error("invalid AES-128 CMAC key"))?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn next_iv(key: &[u8; AES_LEN], counter: &mut u32, direction: u8) -> ToolResult<[u8; AES_LEN]> {
    *counter = counter
        .checked_add(1)
        .ok_or_else(|| sc_error("SCP03 encryption counter overflow"))?;
    let mut block = [0u8; AES_LEN];
    block[0] = direction;
    block[12..].copy_from_slice(&counter.to_be_bytes());
    let cipher = aes::Aes128::new_from_slice(key).map_err(|_| sc_error("invalid AES key"))?;
    cipher.encrypt_block((&mut block).into());
    Ok(block)
}

fn encrypt(key: &[u8; AES_LEN], iv: &[u8; AES_LEN], input: &[u8]) -> ToolResult<Vec<u8>> {
    let mut buffer = input.to_vec();
    buffer.resize(input.len() + AES_LEN, 0);
    let encrypted = cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into())
        .encrypt_padded_mut::<Iso7816>(&mut buffer, input.len())
        .map_err(|_| sc_error("SCP03 command encryption failed"))?;
    Ok(encrypted.to_vec())
}

fn decrypt(key: &[u8; AES_LEN], iv: &[u8; AES_LEN], input: &[u8]) -> ToolResult<Vec<u8>> {
    let mut buffer = input.to_vec();
    let decrypted = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into())
        .decrypt_padded_mut::<Iso7816>(&mut buffer)
        .map_err(|_| sc_error("SCP03 response decryption or padding verification failed"))?;
    Ok(decrypted.to_vec())
}

fn padded_len(len: usize) -> ToolResult<usize> {
    len.checked_add(AES_LEN)
        .map(|value| value / AES_LEN * AES_LEN)
        .ok_or_else(|| sc_error("SCP03 padded length overflow"))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn sc_error(message: impl Into<String>) -> ApduToolError {
    ApduToolError::new(ErrorKind::SecureChannel, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENC: [u8; 16] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    const MAC: [u8; 16] = [
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
        0x5f,
    ];

    fn keyset(profile: Scp03Profile) -> Scp03Keyset {
        Scp03Keyset {
            version: 0,
            id: 0,
            enc: ENC,
            mac: MAC,
            profile: Some(profile),
        }
    }

    struct EstablishmentTransport {
        profile: Scp03Profile,
        host: Vec<u8>,
        card: Vec<u8>,
        step: usize,
        expected_level: SecurityLevel,
    }

    impl CommandTransport for EstablishmentTransport {
        fn exchange_command(&mut self, command: &OwnedT0Command) -> ToolResult<T0Response> {
            self.step += 1;
            if self.step == 1 {
                assert_eq!(command.ins, gp::INS_INITIALIZE_UPDATE);
                assert_eq!(command.data, self.host);
                let context = [&self.host[..], &self.card].concat();
                let session_mac: [u8; 16] = kdf(&MAC, 0x06, &context, 16)?.try_into().unwrap();
                let card_cryptogram = kdf(&session_mac, 0x00, &context, self.profile.mac_len())?;
                let mut data = vec![0u8; 12];
                data[10] = 0;
                data[11] = 3;
                data.extend_from_slice(&self.card);
                data.extend_from_slice(&card_cryptogram);
                return Ok(T0Response {
                    data,
                    status: (0x90, 0x00),
                });
            }
            assert_eq!(command.ins, 0x82);
            assert_eq!(command.p1, self.expected_level.bits());
            Ok(T0Response {
                data: Vec::new(),
                status: (0x90, 0x00),
            })
        }
    }

    fn config(level: SecurityLevel) -> SecureChannelConfig {
        SecureChannelConfig {
            protocol: crate::secure_channel::SecureChannelProtocol::Scp03,
            security_domain: None,
            security_level: level,
            credentials: Some("unused.toml".into()),
        }
    }

    #[test]
    fn s8_public_oxide_se_vector_establishes_and_seeds_mac_chain() {
        let host = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let card = b"RUSTLET0".to_vec();
        let mut engine =
            Scp03Engine::new(keyset(Scp03Profile::S8), Scp03Profile::S8).with_challenge(&host);
        let mut transport = EstablishmentTransport {
            profile: Scp03Profile::S8,
            host,
            card,
            step: 0,
            expected_level: SecurityLevel::CMac,
        };
        engine
            .establish(&mut transport, &config(SecurityLevel::CMac))
            .unwrap();
        assert_eq!(
            engine.command_chain,
            [
                0x6c, 0x00, 0x42, 0x17, 0x2b, 0x28, 0xd6, 0x69, 0xf9, 0x26, 0x6a, 0x2e, 0x53, 0x6e,
                0x3d, 0x9e,
            ]
        );
        assert_eq!(transport.step, 2);
    }

    #[test]
    fn s16_establishment_and_encrypted_command_use_full_mac() {
        let host = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ];
        let card = b"RUSTLET0RUSTLET1".to_vec();
        let mut engine =
            Scp03Engine::new(keyset(Scp03Profile::S16), Scp03Profile::S16).with_challenge(&host);
        let mut transport = EstablishmentTransport {
            profile: Scp03Profile::S16,
            host,
            card,
            step: 0,
            expected_level: SecurityLevel::CMacCEnc,
        };
        engine
            .establish(&mut transport, &config(SecurityLevel::CMacCEnc))
            .unwrap();
        assert_eq!(
            engine.command_chain,
            [
                0x67, 0x01, 0x74, 0x38, 0xd6, 0x2b, 0xce, 0xaa, 0x4c, 0x45, 0x21, 0xc3, 0xfa, 0x15,
                0x6f, 0x7b,
            ]
        );
        let plain =
            OwnedT0Command::from_wire_fields(0x80, 0xe2, 0, 0, 3, 0, vec![1, 2, 3]).unwrap();
        let protected = engine.protect(&plain).unwrap();
        assert_eq!(protected.cla, 0x84);
        assert_eq!(protected.data.len(), 32);
        assert_eq!(engine.command_counter, 1);
    }

    #[test]
    fn restored_snapshot_continues_without_reusing_command_state() {
        let mut engine = Scp03Engine::new(keyset(Scp03Profile::S16), Scp03Profile::S16);
        engine.level = SecurityLevel::CMacCEnc;
        engine.keys = Some(SessionKeys {
            enc: [1; 16],
            mac: [2; 16],
            rmac: [3; 16],
        });
        engine.command_chain = [4; 16];
        engine.command_counter = 7;
        let command =
            OwnedT0Command::from_wire_fields(0x80, 0xe2, 0, 0, 3, 0, vec![1, 2, 3]).unwrap();
        let snapshot = engine.snapshot().unwrap();
        let mut restored = Scp03Engine::from_snapshot(snapshot);
        let protected = restored.protect(&command).unwrap();
        assert_eq!(restored.command_counter, 8);
        assert_ne!(restored.command_chain, [4; 16]);
        assert_eq!(protected.cla, 0x84);
        assert_eq!(restored.snapshot().unwrap(), restored.snapshot().unwrap());
    }

    #[test]
    fn wrong_card_cryptogram_is_rejected_before_external_authenticate() {
        struct BadCard;
        impl CommandTransport for BadCard {
            fn exchange_command(&mut self, _command: &OwnedT0Command) -> ToolResult<T0Response> {
                Ok(T0Response {
                    data: vec![0u8; 28],
                    status: (0x90, 0x00),
                })
            }
        }
        let mut engine =
            Scp03Engine::new(keyset(Scp03Profile::S8), Scp03Profile::S8).with_challenge(&[1; 8]);
        assert!(engine
            .establish(&mut BadCard, &config(SecurityLevel::CMac))
            .is_err());
        assert!(engine.keys.is_none());
    }

    #[test]
    fn keyset_parser_rejects_unknown_fields_and_non_aes128_keys() {
        let unknown = r#"
version = 1
enc = "00000000000000000000000000000000"
mac = "00000000000000000000000000000000"
secret = "surprise"
"#;
        assert!(toml::from_str::<KeysetFile>(unknown).is_err());
        assert!(parse_aes128("00", "enc").is_err());
    }

    #[test]
    fn protected_response_rejects_a_bad_rmac() {
        let mut engine = Scp03Engine::new(keyset(Scp03Profile::S8), Scp03Profile::S8);
        engine.level = SecurityLevel::CMacRMac;
        engine.keys = Some(SessionKeys {
            enc: [1; 16],
            mac: [2; 16],
            rmac: [3; 16],
        });
        let data = vec![0; 8];
        assert!(engine
            .unprotect(T0Response {
                data,
                status: (0x90, 0x00),
            })
            .is_err());
        assert_eq!(engine.response_chain, [0; 16]);
    }

    #[test]
    fn protected_response_verifies_rmac_and_decrypts_renc() {
        let mut engine = Scp03Engine::new(keyset(Scp03Profile::S16), Scp03Profile::S16);
        engine.level = SecurityLevel::CMacCEncRMacREnc;
        engine.keys = Some(SessionKeys {
            enc: [1; 16],
            mac: [2; 16],
            rmac: [3; 16],
        });
        let mut response_counter = 0;
        let iv = next_iv(&[1; 16], &mut response_counter, 0x02).unwrap();
        let encrypted = encrypt(&[1; 16], &iv, b"registry").unwrap();
        let status = [0x90, 0x00];
        let response_mac = chained_cmac(&[3; 16], &[0; 16], &[&encrypted, &status]).unwrap();
        let data = [encrypted.clone(), response_mac.to_vec()].concat();

        let response = engine
            .unprotect(T0Response {
                data,
                status: (0x90, 0x00),
            })
            .unwrap();
        assert_eq!(response.data, b"registry");
        assert_eq!(response.status, (0x90, 0x00));
        assert_eq!(engine.response_chain, response_mac);
        assert_eq!(engine.response_counter, 1);
    }

    #[test]
    fn repeated_plaintext_commands_never_reuse_mac_or_encryption_state() {
        let mut engine = Scp03Engine::new(keyset(Scp03Profile::S8), Scp03Profile::S8);
        engine.level = SecurityLevel::CMacCEnc;
        engine.keys = Some(SessionKeys {
            enc: [1; 16],
            mac: [2; 16],
            rmac: [3; 16],
        });
        let command = OwnedT0Command::from_wire_fields(0x80, 0xe2, 0, 0, 1, 0, vec![0xaa]).unwrap();
        let first = engine.protect(&command).unwrap();
        let second = engine.protect(&command).unwrap();
        assert_ne!(first.data, second.data);
        assert_eq!(engine.command_counter, 2);
    }
}
