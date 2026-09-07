//! Host-side GlobalPlatform SCP11a/SCP11b/SCP11c engine.

use crate::gp;
use crate::secure_channel::{
    CommandTransport, SecureChannelConfig, SecureChannelEngine, SecureChannelProtocol,
    SecurityLevel,
};
use crate::{ApduToolError, ErrorKind, OwnedT0Command, T0Response, ToolResult};
use aes::cipher::{
    block_padding::Iso7816, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit,
};
use cmac::{Cmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const OXIDE_SE_DEFAULT_SCP11_HOST_ID: &str = "oxide-se-host";
const OXIDE_SE_DEFAULT_SCP11_SIN: &str = "oxide-se-sin";
const OXIDE_SE_DEFAULT_SCP11_SDIN: &str = "oxide-se-sdin";
const OXIDE_SE_DEFAULT_SCP11_CARD_GROUP_ID: &str = "oxide-se-card";
const HOST_PUBLIC_LEN: usize = 65;
const SCP11_FAMILY: u8 = 0x11;
const KEY_USAGE_FULL: u8 = 0x3c;
const KEY_TYPE_AES: u8 = 0x88;
const KEY_LENGTH_AES_128: u8 = 0x10;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialFile {
    #[serde(default)]
    version: u8,
    #[serde(default = "default_key_id")]
    id: u8,
    profile: Option<String>,
    #[serde(default = "default_host_id")]
    host_id: String,
    #[serde(default = "default_sin")]
    sin: String,
    #[serde(default = "default_sdin")]
    sdin: String,
    #[serde(default = "default_card_group_id")]
    card_group_id: String,
    host_private_key: Option<String>,
    host_private_key_file: Option<PathBuf>,
    host_certificate_file: Option<PathBuf>,
    #[serde(default)]
    certificate_chain_files: Vec<PathBuf>,
    card_public_key: Option<String>,
    card_public_key_file: Option<PathBuf>,
}

fn default_key_id() -> u8 {
    1
}
fn default_host_id() -> String {
    OXIDE_SE_DEFAULT_SCP11_HOST_ID.to_owned()
}
fn default_sin() -> String {
    OXIDE_SE_DEFAULT_SCP11_SIN.to_owned()
}
fn default_sdin() -> String {
    OXIDE_SE_DEFAULT_SCP11_SDIN.to_owned()
}
fn default_card_group_id() -> String {
    OXIDE_SE_DEFAULT_SCP11_CARD_GROUP_ID.to_owned()
}

/// Credentials and trust material needed by an SCP11 profile.
pub struct Scp11Credentials {
    pub version: u8,
    pub id: u8,
    profile: Option<SecureChannelProtocol>,
    host_id: Vec<u8>,
    sin: Vec<u8>,
    sdin: Vec<u8>,
    card_group_id: Vec<u8>,
    host_private: Option<[u8; 32]>,
    certificates: Vec<Vec<u8>>,
    card_public: [u8; HOST_PUBLIC_LEN],
}

impl Drop for Scp11Credentials {
    fn drop(&mut self) {
        if let Some(key) = &mut self.host_private {
            key.zeroize();
        }
    }
}

impl Scp11Credentials {
    pub fn load(path: &Path) -> ToolResult<(Self, Vec<String>)> {
        let metadata = fs::metadata(path).map_err(|e| {
            source_error(
                format!("cannot inspect SCP11 credentials {}", path.display()),
                e,
            )
        })?;
        if !metadata.is_file() || metadata.len() > 256 * 1024 {
            return Err(sc_error(format!(
                "SCP11 credentials {} must be a regular file no larger than 256 KiB",
                path.display()
            )));
        }
        let mut warnings = Vec::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                warnings.push(format!("WARNING: SCP11 credentials {} are accessible by group or other users; use chmod 600", path.display()));
            }
        }
        let mut text = fs::read_to_string(path).map_err(|e| {
            source_error(
                format!("cannot read SCP11 credentials {}", path.display()),
                e,
            )
        })?;
        let mut parsed: CredentialFile = toml::from_str(&text).map_err(|e| {
            source_error(format!("invalid SCP11 credentials {}", path.display()), e)
        })?;
        text.zeroize();
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let profile = parsed
            .profile
            .as_deref()
            .map(SecureChannelProtocol::parse)
            .transpose()?;
        if profile.is_some_and(|p| {
            !matches!(
                p,
                SecureChannelProtocol::Scp11a
                    | SecureChannelProtocol::Scp11b
                    | SecureChannelProtocol::Scp11c
            )
        }) {
            return Err(sc_error(
                "SCP11 credential profile must be scp11a, scp11b or scp11c",
            ));
        }
        if parsed.host_private_key.is_some() && parsed.host_private_key_file.is_some() {
            return Err(sc_error(
                "set only one of host_private_key and host_private_key_file",
            ));
        }
        if parsed.card_public_key.is_some() && parsed.card_public_key_file.is_some() {
            return Err(sc_error(
                "set only one of card_public_key and card_public_key_file",
            ));
        }
        let host_private = if let Some(value) = parsed.host_private_key.take() {
            warnings.push("WARNING: inline host_private_key is for debugging only; prefer host_private_key_file".to_owned());
            Some(parse_fixed_hex::<32>(&value, "host_private_key")?)
        } else if let Some(file) = &parsed.host_private_key_file {
            Some(read_fixed_material::<32>(
                &base.join(file),
                "host private key",
                &mut warnings,
            )?)
        } else {
            None
        };
        let card_public = if let Some(value) = parsed.card_public_key.take() {
            parse_fixed_hex::<HOST_PUBLIC_LEN>(&value, "card_public_key")?
        } else if let Some(file) = &parsed.card_public_key_file {
            read_fixed_material::<HOST_PUBLIC_LEN>(
                &base.join(file),
                "card public key",
                &mut warnings,
            )?
        } else {
            return Err(sc_error("SCP11 credentials require card_public_key_file (or inline card_public_key for debugging)"));
        };
        PublicKey::from_sec1_bytes(&card_public)
            .map_err(|_| sc_error("invalid P-256 card_public_key"))?;
        let mut certificate_paths = parsed.certificate_chain_files;
        if let Some(file) = parsed.host_certificate_file {
            certificate_paths.push(file);
        }
        let certificates = certificate_paths
            .into_iter()
            .map(|file| read_binary(&base.join(file), "SCP11 certificate", &mut warnings))
            .collect::<ToolResult<Vec<_>>>()?;
        Ok((
            Self {
                version: parsed.version,
                id: parsed.id,
                profile,
                host_id: parse_identifier(&parsed.host_id, "host_id")?,
                sin: parse_identifier(&parsed.sin, "sin")?,
                sdin: parse_identifier(&parsed.sdin, "sdin")?,
                card_group_id: parse_identifier(&parsed.card_group_id, "card_group_id")?,
                host_private,
                certificates,
                card_public,
            },
            warnings,
        ))
    }
}

#[derive(Debug)]
struct SessionKeys {
    receipt: [u8; 16],
    enc: [u8; 16],
    mac: [u8; 16],
    rmac: [u8; 16],
    dek: [u8; 16],
}
impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.receipt.zeroize();
        self.enc.zeroize();
        self.mac.zeroize();
        self.rmac.zeroize();
        self.dek.zeroize();
    }
}

pub struct Scp11Engine {
    profile: SecureChannelProtocol,
    credentials: Scp11Credentials,
    ephemeral: Option<[u8; 32]>,
    keys: Option<SessionKeys>,
    command_chain: [u8; 16],
    response_chain: [u8; 16],
    command_counter: u32,
    response_counter: u32,
    level: SecurityLevel,
}

impl Scp11Engine {
    pub fn new(profile: SecureChannelProtocol, credentials: Scp11Credentials) -> ToolResult<Self> {
        if !matches!(
            profile,
            SecureChannelProtocol::Scp11a
                | SecureChannelProtocol::Scp11b
                | SecureChannelProtocol::Scp11c
        ) {
            return Err(sc_error("Scp11Engine requires an SCP11 profile"));
        }
        if credentials.profile.is_some_and(|p| p != profile) {
            return Err(sc_error(
                "SCP11 credential profile does not match --secure-channel",
            ));
        }
        if profile != SecureChannelProtocol::Scp11b && credentials.host_private.is_none() {
            return Err(sc_error(
                "SCP11a/SCP11c credentials require a host private key",
            ));
        }
        if profile != SecureChannelProtocol::Scp11b && credentials.certificates.is_empty() {
            return Err(sc_error(
                "SCP11a/SCP11c credentials require a host certificate or certificate chain",
            ));
        }
        if profile != SecureChannelProtocol::Scp11b {
            let host_public = SecretKey::from_slice(credentials.host_private.as_ref().unwrap())
                .map_err(|_| sc_error("invalid P-256 host private key"))?
                .public_key()
                .to_sec1_bytes();
            if !credentials.certificates.last().is_some_and(|leaf| {
                leaf.windows(host_public.len())
                    .any(|value| value == host_public.as_ref())
            }) {
                return Err(sc_error(
                    "SCP11 host certificate does not contain the public key matching host_private_key",
                ));
            }
        }
        Ok(Self {
            profile,
            credentials,
            ephemeral: None,
            keys: None,
            command_chain: [0; 16],
            response_chain: [0; 16],
            command_counter: 0,
            response_counter: 0,
            level: SecurityLevel::None,
        })
    }

    fn keys(&self) -> ToolResult<&SessionKeys> {
        self.keys
            .as_ref()
            .ok_or_else(|| sc_error("SCP11 session keys are not established"))
    }
}

impl SecureChannelEngine for Scp11Engine {
    fn establish(
        &mut self,
        transport: &mut dyn CommandTransport,
        config: &SecureChannelConfig,
    ) -> ToolResult<()> {
        if let Some(aid) = &config.security_domain {
            let select = OwnedT0Command::from_wire_fields(
                0x00,
                0xa4,
                0x04,
                0x00,
                aid.len()
                    .try_into()
                    .map_err(|_| sc_error("Security Domain AID is too long"))?,
                0,
                aid.clone(),
            )?;
            require_success(
                transport.exchange_command(&select)?,
                "SELECT Security Domain",
            )?;
        }
        self.level = config.security_level;
        if self.level != SecurityLevel::CMacCEncRMacREnc {
            return Err(sc_error(
                "Oxide SE SCP11 currently requires --security-level c-mac+c-enc+r-mac+r-enc",
            ));
        }
        if self.profile != SecureChannelProtocol::Scp11b {
            for certificate in &self.credentials.certificates {
                let command = OwnedT0Command::from_wire_fields(
                    0x80,
                    0x2a,
                    self.credentials.version,
                    self.credentials.id,
                    certificate
                        .len()
                        .try_into()
                        .map_err(|_| sc_error("SCP11 certificate does not fit a short APDU"))?,
                    0,
                    certificate.clone(),
                )?;
                require_success(
                    transport.exchange_command(&command)?,
                    "PERFORM SECURITY OPERATION",
                )?;
            }
        }
        let ephemeral_bytes: [u8; 32] = random_secret()?;
        let ephemeral = SecretKey::from_slice(&ephemeral_bytes)
            .map_err(|_| sc_error("operating system generated an invalid P-256 secret"))?;
        let public = ephemeral.public_key().to_sec1_bytes();
        let data = authentication_data(self.profile, &self.credentials.host_id, &public)?;
        let ins = if self.profile == SecureChannelProtocol::Scp11b {
            0x88
        } else {
            0x82
        };
        let command = OwnedT0Command::from_wire_fields(
            0x80,
            ins,
            self.credentials.version,
            self.credentials.id,
            data.len().try_into().unwrap(),
            0x56,
            data.clone(),
        )?;
        let response = require_success(
            transport.exchange_command(&command)?,
            if ins == 0x88 {
                "INTERNAL AUTHENTICATE"
            } else {
                "MUTUAL AUTHENTICATE"
            },
        )?;
        let (card_public, receipt) = parse_authentication_response(&response.data)?;
        let keys = derive_keys(self.profile, &self.credentials, &ephemeral, card_public)?;
        let mut receipt_input = data;
        push_tlv(&mut receipt_input, &[0x5f, 0x49], card_public)?;
        let expected = cmac(&keys.receipt, &[&receipt_input])?;
        if !constant_time_eq(receipt, &expected) {
            return Err(sc_error("SCP11 receipt verification failed"));
        }
        self.command_chain = expected;
        self.response_chain = expected;
        self.ephemeral = Some(ephemeral_bytes);
        self.keys = Some(keys);
        Ok(())
    }

    fn validate_command(&self, command: &OwnedT0Command) -> ToolResult<()> {
        if self.profile == SecureChannelProtocol::Scp11b && is_oce_management(command) {
            return Err(sc_error(format!("SCP11b does not authenticate an OCE and cannot authorize INS={:02X} P1={:02X}; use SCP11a or SCP11c", command.ins, command.p1)));
        }
        Ok(())
    }

    fn protect(&mut self, command: &OwnedT0Command) -> ToolResult<OwnedT0Command> {
        let keys = self.keys()?;
        let mut next_counter = self.command_counter;
        let mut body = if !command.data.is_empty() {
            let iv = next_iv(&keys.enc, &mut next_counter, 0x11)?;
            encrypt(&keys.enc, &iv, &command.data)?
        } else {
            Vec::new()
        };
        let final_len = body
            .len()
            .checked_add(16)
            .filter(|n| *n <= 255)
            .ok_or_else(|| sc_error("protected SCP11 command exceeds short APDU capacity"))?;
        let header = [0x84, command.ins, command.p1, command.p2, final_len as u8];
        let full = chained_cmac(&keys.mac, &self.command_chain, &[&header, &body])?;
        body.extend_from_slice(&full);
        self.command_chain = full;
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
        let data_len = response
            .data
            .len()
            .checked_sub(16)
            .ok_or_else(|| sc_error("SCP11 protected response is missing R-MAC"))?;
        let (protected_data, received_mac) = response.data.split_at(data_len);
        let keys = self.keys()?;
        let status_bytes = [response.status.0, response.status.1];
        let expected = chained_cmac(
            &keys.rmac,
            &self.response_chain,
            &[protected_data, &status_bytes],
        )?;
        if !constant_time_eq(received_mac, &expected) {
            return Err(sc_error("SCP11 response MAC verification failed"));
        }
        let mut counter = self.response_counter;
        let data = if protected_data.is_empty() {
            Vec::new()
        } else {
            let iv = next_iv(&keys.enc, &mut counter, 0x12)?;
            decrypt(&keys.enc, &iv, protected_data)?
        };
        self.response_chain = expected;
        self.response_counter = counter;
        Ok(T0Response {
            data,
            status: response.status,
        })
    }

    fn command_overhead(&self, plaintext_len: usize) -> ToolResult<usize> {
        let protected_len = if plaintext_len == 0 {
            0
        } else {
            plaintext_len
                .checked_add(16 - plaintext_len % 16)
                .ok_or_else(|| sc_error("SCP11 command length overflow"))?
        };
        Ok(protected_len + 16 - plaintext_len)
    }

    fn clear(&mut self) {
        self.keys = None;
        if let Some(mut key) = self.ephemeral.take() {
            key.zeroize();
        }
        self.command_chain.zeroize();
        self.response_chain.zeroize();
        self.command_counter = 0;
        self.response_counter = 0;
    }
}

fn authentication_data(
    profile: SecureChannelProtocol,
    host_id: &[u8],
    public: &[u8],
) -> ToolResult<Vec<u8>> {
    let param = match profile {
        SecureChannelProtocol::Scp11a => 0x05,
        SecureChannelProtocol::Scp11b => 0x04,
        SecureChannelProtocol::Scp11c => 0x07,
        _ => unreachable!(),
    };
    let mut crt = Vec::new();
    push_tlv(&mut crt, &[0x90], &[SCP11_FAMILY, param])?;
    push_tlv(&mut crt, &[0x95], &[KEY_USAGE_FULL])?;
    push_tlv(&mut crt, &[0x80], &[KEY_TYPE_AES])?;
    push_tlv(&mut crt, &[0x81], &[KEY_LENGTH_AES_128])?;
    push_tlv(&mut crt, &[0x84], host_id)?;
    let mut data = Vec::new();
    push_tlv(&mut data, &[0xa6], &crt)?;
    push_tlv(&mut data, &[0x5f, 0x49], public)?;
    Ok(data)
}

fn derive_keys(
    profile: SecureChannelProtocol,
    credentials: &Scp11Credentials,
    ephemeral: &SecretKey,
    returned_public: &[u8],
) -> ToolResult<SessionKeys> {
    let first = shared(ephemeral, returned_public)?;
    let second = match profile {
        SecureChannelProtocol::Scp11a => shared(
            &SecretKey::from_slice(credentials.host_private.as_ref().unwrap())
                .map_err(|_| sc_error("invalid host private key"))?,
            &credentials.card_public,
        )?,
        SecureChannelProtocol::Scp11b => shared(ephemeral, &credentials.card_public)?,
        SecureChannelProtocol::Scp11c => {
            if !constant_time_eq(returned_public, &credentials.card_public) {
                return Err(sc_error(
                    "SCP11c card public key does not match the configured trust anchor",
                ));
            }
            shared(
                &SecretKey::from_slice(credentials.host_private.as_ref().unwrap())
                    .map_err(|_| sc_error("invalid host private key"))?,
                returned_public,
            )?
        }
        _ => unreachable!(),
    };
    derive_session_material(profile, credentials, &first, &second)
}

fn derive_session_material(
    profile: SecureChannelProtocol,
    credentials: &Scp11Credentials,
    first: &[u8; 32],
    second: &[u8; 32],
) -> ToolResult<SessionKeys> {
    let mut secret = Vec::with_capacity(64);
    secret.extend_from_slice(first);
    secret.extend_from_slice(second);
    let mut info = vec![
        KEY_USAGE_FULL,
        KEY_TYPE_AES,
        KEY_LENGTH_AES_128,
        credentials.host_id.len() as u8,
    ];
    info.extend_from_slice(&credentials.host_id);
    if profile == SecureChannelProtocol::Scp11c {
        info.push(credentials.card_group_id.len() as u8);
        info.extend_from_slice(&credentials.card_group_id);
    } else {
        info.push(credentials.sin.len() as u8);
        info.extend_from_slice(&credentials.sin);
        info.push(credentials.sdin.len() as u8);
        info.extend_from_slice(&credentials.sdin);
    }
    let mut out = [0u8; 80];
    x963_kdf(&secret, &info, &mut out);
    Ok(SessionKeys {
        receipt: out[0..16].try_into().unwrap(),
        enc: out[16..32].try_into().unwrap(),
        mac: out[32..48].try_into().unwrap(),
        rmac: out[48..64].try_into().unwrap(),
        dek: out[64..80].try_into().unwrap(),
    })
}

fn shared(secret: &SecretKey, public: &[u8]) -> ToolResult<[u8; 32]> {
    let public = PublicKey::from_sec1_bytes(public)
        .map_err(|_| sc_error("invalid card P-256 public key"))?;
    Ok(
        diffie_hellman(secret.to_nonzero_scalar(), public.as_affine())
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .unwrap(),
    )
}
fn x963_kdf(secret: &[u8], info: &[u8], out: &mut [u8]) {
    let mut offset = 0;
    let mut counter = 1u32;
    while offset < out.len() {
        let mut h = Sha256::new();
        h.update(secret);
        h.update(counter.to_be_bytes());
        h.update(info);
        let block = h.finalize();
        let take = (out.len() - offset).min(block.len());
        out[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        counter += 1;
    }
}

fn parse_authentication_response(data: &[u8]) -> ToolResult<(&[u8], &[u8])> {
    if data.len() != 86 || data[..3] != [0x5f, 0x49, 65] || data[68..70] != [0x86, 16] {
        return Err(sc_error(
            "invalid SCP11 authentication response; expected 5F49(65) followed by 86(16)",
        ));
    }
    Ok((&data[3..68], &data[70..86]))
}

fn is_oce_management(c: &OwnedT0Command) -> bool {
    matches!(c.ins, 0xe2 | 0xe4 | 0xd8 | 0xe6 | 0xe8 | 0xf0)
}
fn push_tlv(out: &mut Vec<u8>, tag: &[u8], value: &[u8]) -> ToolResult<()> {
    gp::push_tlv(out, tag, value).map_err(|e| sc_error(e.to_string()))
}
fn cmac(key: &[u8; 16], parts: &[&[u8]]) -> ToolResult<[u8; 16]> {
    let mut m = <Cmac<aes::Aes128> as Mac>::new_from_slice(key)
        .map_err(|_| sc_error("invalid AES CMAC key"))?;
    for p in parts {
        m.update(p);
    }
    Ok(m.finalize().into_bytes().into())
}
fn chained_cmac(key: &[u8; 16], chain: &[u8; 16], parts: &[&[u8]]) -> ToolResult<[u8; 16]> {
    let mut all = chain.to_vec();
    for p in parts {
        all.extend_from_slice(p);
    }
    cmac(key, &[&all])
}
fn next_iv(key: &[u8; 16], counter: &mut u32, direction: u8) -> ToolResult<[u8; 16]> {
    *counter = counter
        .checked_add(1)
        .ok_or_else(|| sc_error("SCP11 encryption counter overflow"))?;
    let mut block = [0u8; 16];
    block[0] = direction;
    block[12..].copy_from_slice(&counter.to_be_bytes());
    let cipher = aes::Aes128::new_from_slice(key).map_err(|_| sc_error("invalid AES key"))?;
    cipher.encrypt_block((&mut block).into());
    Ok(block)
}
fn encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> ToolResult<Vec<u8>> {
    let mut b = vec![0u8; data.len() + 16];
    b[..data.len()].copy_from_slice(data);
    let n = cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into())
        .encrypt_padded_mut::<Iso7816>(&mut b, data.len())
        .map_err(|_| sc_error("SCP11 encryption failed"))?
        .len();
    b.truncate(n);
    Ok(b)
}
fn decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> ToolResult<Vec<u8>> {
    let mut b = data.to_vec();
    let n = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into())
        .decrypt_padded_mut::<Iso7816>(&mut b)
        .map_err(|_| sc_error("SCP11 response padding is invalid"))?
        .len();
    b.truncate(n);
    Ok(b)
}
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}
fn require_success(r: T0Response, label: &str) -> ToolResult<T0Response> {
    if r.status == (0x90, 0x00) {
        Ok(r)
    } else {
        Err(sc_error(format!(
            "{label} failed with status {:02X}{:02X}",
            r.status.0, r.status.1
        )))
    }
}
fn random_secret() -> ToolResult<[u8; 32]> {
    for _ in 0..16 {
        let mut b = [0u8; 32];
        fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut b))
            .map_err(|e| source_error("cannot obtain an SCP11 ephemeral key", e))?;
        if SecretKey::from_slice(&b).is_ok() {
            return Ok(b);
        }
    }
    Err(sc_error("could not generate a valid P-256 ephemeral key"))
}
fn parse_identifier(s: &str, name: &str) -> ToolResult<Vec<u8>> {
    let bytes = if let Some(hex) = s.strip_prefix("hex:") {
        parse_hex(hex, name)?
    } else {
        s.as_bytes().to_vec()
    };
    if bytes.is_empty() || bytes.len() > 255 {
        return Err(sc_error(format!("SCP11 {name} length must be 1..=255")));
    }
    Ok(bytes)
}
fn parse_hex(s: &str, name: &str) -> ToolResult<Vec<u8>> {
    let compact: String = s
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();
    if !compact.len().is_multiple_of(2) || !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(sc_error(format!("invalid hexadecimal {name}")));
    }
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).map_err(|_| scp_error(name)))
        .collect()
}
fn parse_fixed_hex<const N: usize>(s: &str, name: &str) -> ToolResult<[u8; N]> {
    let v = parse_hex(s, name)?;
    v.try_into().map_err(|_| scp_error(name))
}
fn scp_error(name: &str) -> ApduToolError {
    sc_error(format!("SCP11 {name} has an invalid length"))
}
fn read_binary(path: &Path, label: &str, warnings: &mut Vec<String>) -> ToolResult<Vec<u8>> {
    warn_permissions(path, label, warnings)?;
    fs::read(path).map_err(|e| source_error(format!("cannot read {label} {}", path.display()), e))
}
fn read_fixed_material<const N: usize>(
    path: &Path,
    label: &str,
    warnings: &mut Vec<String>,
) -> ToolResult<[u8; N]> {
    let raw = read_binary(path, label, warnings)?;
    if raw.len() == N {
        return raw.try_into().map_err(|_| scp_error(label));
    }
    let text = std::str::from_utf8(&raw).map_err(|_| scp_error(label))?;
    parse_fixed_hex(text, label)
}
fn warn_permissions(path: &Path, label: &str, warnings: &mut Vec<String>) -> ToolResult<()> {
    let m = fs::metadata(path)
        .map_err(|e| source_error(format!("cannot inspect {label} {}", path.display()), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode() & 0o077 != 0 {
            warnings.push(format!(
                "WARNING: {label} {} is accessible by group or other users; use chmod 600",
                path.display()
            ));
        }
    }
    Ok(())
}
fn sc_error(message: impl Into<String>) -> ApduToolError {
    ApduToolError::new(ErrorKind::SecureChannel, message)
}
fn source_error(
    message: impl Into<String>,
    source: impl std::error::Error + Send + Sync + 'static,
) -> ApduToolError {
    ApduToolError::with_source(ErrorKind::SecureChannel, message, source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_channel::SecureChannelSession;

    fn credentials() -> Scp11Credentials {
        let card_secret = SecretKey::from_slice(&[0x41; 32]).unwrap();
        let host_public = SecretKey::from_slice(&[0x31; 32])
            .unwrap()
            .public_key()
            .to_sec1_bytes();
        Scp11Credentials {
            version: 0,
            id: 1,
            profile: None,
            host_id: OXIDE_SE_DEFAULT_SCP11_HOST_ID.as_bytes().to_vec(),
            sin: OXIDE_SE_DEFAULT_SCP11_SIN.as_bytes().to_vec(),
            sdin: OXIDE_SE_DEFAULT_SCP11_SDIN.as_bytes().to_vec(),
            card_group_id: OXIDE_SE_DEFAULT_SCP11_CARD_GROUP_ID.as_bytes().to_vec(),
            host_private: Some([0x31; 32]),
            certificates: vec![[&[0x7f, 0x21, 0x00][..], host_public.as_ref()].concat()],
            card_public: card_secret
                .public_key()
                .to_sec1_bytes()
                .as_ref()
                .try_into()
                .unwrap(),
        }
    }

    #[test]
    fn authentication_crt_distinguishes_all_three_profiles() {
        let public = SecretKey::from_slice(&[0x21; 32])
            .unwrap()
            .public_key()
            .to_sec1_bytes();
        for (profile, parameter) in [
            (SecureChannelProtocol::Scp11a, 0x05),
            (SecureChannelProtocol::Scp11b, 0x04),
            (SecureChannelProtocol::Scp11c, 0x07),
        ] {
            let data =
                authentication_data(profile, OXIDE_SE_DEFAULT_SCP11_HOST_ID.as_bytes(), &public)
                    .unwrap();
            assert!(data
                .windows(4)
                .any(|value| value == [0x90, 0x02, 0x11, parameter]));
            assert!(data.windows(3).any(|value| value == [0x95, 0x01, 0x3c]));
            assert!(data.ends_with(public.as_ref()));
        }
    }

    #[test]
    fn every_profile_derives_five_distinct_keys() {
        let credentials = credentials();
        let ephemeral = SecretKey::from_slice(&[0x21; 32]).unwrap();
        let returned = SecretKey::from_slice(&[0x51; 32])
            .unwrap()
            .public_key()
            .to_sec1_bytes();
        for profile in [SecureChannelProtocol::Scp11a, SecureChannelProtocol::Scp11b] {
            let keys = derive_keys(profile, &credentials, &ephemeral, &returned).unwrap();
            let all = [keys.receipt, keys.enc, keys.mac, keys.rmac, keys.dek];
            for left in 0..all.len() {
                for right in left + 1..all.len() {
                    assert_ne!(all[left], all[right]);
                }
            }
        }
        let keys = derive_keys(
            SecureChannelProtocol::Scp11c,
            &credentials,
            &ephemeral,
            &credentials.card_public,
        )
        .unwrap();
        assert_ne!(keys.receipt, keys.enc);
    }

    #[test]
    fn scp11c_rejects_an_untrusted_card_key() {
        let error = derive_keys(
            SecureChannelProtocol::Scp11c,
            &credentials(),
            &SecretKey::from_slice(&[0x21; 32]).unwrap(),
            SecretKey::from_slice(&[0x51; 32])
                .unwrap()
                .public_key()
                .to_sec1_bytes()
                .as_ref(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("trust anchor"));
    }

    #[test]
    fn certificate_not_bound_to_host_private_key_is_rejected() {
        let mut credentials = credentials();
        credentials.certificates = vec![vec![0x7f, 0x21, 0x00]];
        let error = Scp11Engine::new(SecureChannelProtocol::Scp11a, credentials)
            .err()
            .unwrap();
        assert!(error
            .to_string()
            .contains("does not contain the public key"));
    }

    #[test]
    fn malformed_or_stale_protected_responses_are_rejected() {
        assert!(parse_authentication_response(&[0; 86]).is_err());
        let mut engine = Scp11Engine::new(SecureChannelProtocol::Scp11b, credentials()).unwrap();
        engine.keys = Some(SessionKeys {
            receipt: [1; 16],
            enc: [2; 16],
            mac: [3; 16],
            rmac: [4; 16],
            dek: [5; 16],
        });
        let response = T0Response {
            data: vec![0; 16],
            status: (0x90, 0x00),
        };
        assert!(engine
            .unprotect(response)
            .unwrap_err()
            .to_string()
            .contains("MAC"));
    }

    #[test]
    fn protected_response_replay_is_rejected() {
        let mut engine = Scp11Engine::new(SecureChannelProtocol::Scp11b, credentials()).unwrap();
        engine.keys = Some(SessionKeys {
            receipt: [1; 16],
            enc: [2; 16],
            mac: [3; 16],
            rmac: [4; 16],
            dek: [5; 16],
        });
        engine.response_chain = [1; 16];
        let status = [0x90, 0x00];
        let response_mac = chained_cmac(&[4; 16], &[1; 16], &[&status]).unwrap();
        let response = T0Response {
            data: response_mac.to_vec(),
            status: (0x90, 0x00),
        };
        assert_eq!(
            engine.unprotect(response.clone()).unwrap().status,
            (0x90, 0x00)
        );
        assert!(engine
            .unprotect(response)
            .unwrap_err()
            .to_string()
            .contains("MAC"));
    }

    #[test]
    fn scp11b_blocks_management_locally_but_allows_consultation() {
        let engine = Scp11Engine::new(SecureChannelProtocol::Scp11b, credentials()).unwrap();
        let install = OwnedT0Command::from_wire_fields(0x80, 0xe6, 0x02, 0, 0, 0, vec![]).unwrap();
        assert!(engine
            .validate_command(&install)
            .unwrap_err()
            .to_string()
            .contains("SCP11b"));
        let get_data =
            OwnedT0Command::from_wire_fields(0x80, 0xca, 0x9f, 0x70, 0, 4, vec![]).unwrap();
        engine.validate_command(&get_data).unwrap();
    }

    struct CardAuthenticationTransport {
        profile: SecureChannelProtocol,
        credentials: Scp11Credentials,
        saw_certificate: bool,
    }

    impl CommandTransport for CardAuthenticationTransport {
        fn exchange_command(&mut self, command: &OwnedT0Command) -> ToolResult<T0Response> {
            if command.ins == 0x2a {
                self.saw_certificate = true;
                return Ok(T0Response {
                    data: vec![],
                    status: (0x90, 0x00),
                });
            }
            let expected_ins = if self.profile == SecureChannelProtocol::Scp11b {
                0x88
            } else {
                0x82
            };
            assert_eq!(command.ins, expected_ins);
            let host_public = &command.data[command.data.len() - HOST_PUBLIC_LEN..];
            let card_static = SecretKey::from_slice(&[0x41; 32]).unwrap();
            let card_ephemeral = SecretKey::from_slice(&[0x51; 32]).unwrap();
            let returned = if self.profile == SecureChannelProtocol::Scp11c {
                card_static.public_key().to_sec1_bytes()
            } else {
                card_ephemeral.public_key().to_sec1_bytes()
            };
            let first = shared(&card_ephemeral, host_public).unwrap();
            let first = if self.profile == SecureChannelProtocol::Scp11c {
                shared(&card_static, host_public).unwrap()
            } else {
                first
            };
            let host_static_public = SecretKey::from_slice(&[0x31; 32])
                .unwrap()
                .public_key()
                .to_sec1_bytes();
            let second = if self.profile == SecureChannelProtocol::Scp11b {
                shared(&card_static, host_public).unwrap()
            } else {
                shared(&card_static, &host_static_public).unwrap()
            };
            let keys =
                derive_session_material(self.profile, &self.credentials, &first, &second).unwrap();
            let mut receipt_input = command.data.clone();
            push_tlv(&mut receipt_input, &[0x5f, 0x49], &returned).unwrap();
            let receipt = cmac(&keys.receipt, &[&receipt_input]).unwrap();
            let mut data = Vec::new();
            push_tlv(&mut data, &[0x5f, 0x49], &returned).unwrap();
            push_tlv(&mut data, &[0x86], &receipt).unwrap();
            Ok(T0Response {
                data,
                status: (0x90, 0x00),
            })
        }
    }

    #[test]
    fn unilateral_and_mutual_authentication_establish_all_profiles() {
        for profile in [
            SecureChannelProtocol::Scp11a,
            SecureChannelProtocol::Scp11b,
            SecureChannelProtocol::Scp11c,
        ] {
            let config = SecureChannelConfig {
                protocol: profile,
                security_domain: None,
                security_level: SecurityLevel::CMacCEncRMacREnc,
                credentials: Some("credentials.toml".into()),
            };
            let engine = Scp11Engine::new(profile, credentials()).unwrap();
            let mut session = SecureChannelSession::new(config, engine).unwrap();
            let mut transport = CardAuthenticationTransport {
                profile,
                credentials: credentials(),
                saw_certificate: false,
            };
            session.establish(&mut transport).unwrap();
            assert_eq!(
                session.state(),
                crate::secure_channel::SessionState::Established
            );
            assert_eq!(
                transport.saw_certificate,
                profile != SecureChannelProtocol::Scp11b
            );
        }
    }
}
