use super::crypto::{self, AesKey, AES_BLOCK_SIZE, AES_CMAC_SIZE};
use super::gp_sm;

pub const S8_CHALLENGE_LEN: usize = 8;
pub const S8_CRYPTOGRAM_LEN: usize = 8;
pub const S8_MAC_LEN: usize = 8;
pub const S16_CHALLENGE_LEN: usize = 16;
pub const S16_CRYPTOGRAM_LEN: usize = 16;
pub const S16_MAC_LEN: usize = 16;
pub const AES128_STATIC_KEY_LEN: usize = 16;
pub const TRANSFORM_CAPACITY: usize = gp_sm::PROTECTED_TRANSFORM_CAPACITY;

const KDF_CARD_CRYPTOGRAM: u8 = 0x00;
const KDF_HOST_CRYPTOGRAM: u8 = 0x01;
const KDF_S_ENC: u8 = 0x04;
const KDF_S_MAC: u8 = 0x06;
const KDF_S_RMAC: u8 = 0x07;

/// SCP03 profile selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scp03Profile {
    /// Legacy SCP03 profile with 8-byte challenges, cryptograms, and MACs.
    S8,
    /// Stronger profile with 16-byte challenges, cryptograms, and MACs.
    S16,
}

impl Scp03Profile {
    pub const fn challenge_len(self) -> usize {
        match self {
            Self::S8 => S8_CHALLENGE_LEN,
            Self::S16 => S16_CHALLENGE_LEN,
        }
    }

    pub const fn cryptogram_len(self) -> usize {
        match self {
            Self::S8 => S8_CRYPTOGRAM_LEN,
            Self::S16 => S16_CRYPTOGRAM_LEN,
        }
    }

    pub const fn mac_len(self) -> usize {
        match self {
            Self::S8 => S8_MAC_LEN,
            Self::S16 => S16_MAC_LEN,
        }
    }
}

/// Current SCP03 secure messaging level.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    None = 0x00,
    Cmac = 0x01,
    CmacAndEnc = 0x03,
    CmacCencRmacRenc = 0x33,
}

impl SecurityLevel {
    /// Decodes one level from the deliberately selected Oxide SE profile.
    ///
    /// SCP03 levels requiring response protection (`11`, `13`, `33`) are
    /// profiled out of the kernel implementation. `33` remains representable
    /// for SCP11 and for Rustlet-backed Security Domains.
    pub const fn from_selected_scp03_p1(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Cmac),
            0x03 => Some(Self::CmacAndEnc),
            _ => None,
        }
    }

    /// Decodes a security level reported by a selected Security Domain.
    pub const fn from_selected_bits(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Cmac),
            0x03 => Some(Self::CmacAndEnc),
            0x33 => Some(Self::CmacCencRmacRenc),
            _ => None,
        }
    }

    pub const fn bits(self) -> u8 {
        self as u8
    }

    pub const fn uses_command_mac(self) -> bool {
        !matches!(self, Self::None)
    }

    pub const fn uses_command_encryption(self) -> bool {
        matches!(self, Self::CmacAndEnc | Self::CmacCencRmacRenc)
    }

    pub const fn uses_response_mac(self) -> bool {
        matches!(self, Self::CmacCencRmacRenc)
    }

    pub const fn uses_response_encryption(self) -> bool {
        matches!(self, Self::CmacCencRmacRenc)
    }
}

/// SCP03 static communication keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticKeys {
    enc: [u8; AES128_STATIC_KEY_LEN],
    mac: [u8; AES128_STATIC_KEY_LEN],
}

impl StaticKeys {
    pub const fn aes128(
        enc: [u8; AES128_STATIC_KEY_LEN],
        mac: [u8; AES128_STATIC_KEY_LEN],
    ) -> Self {
        Self { enc, mac }
    }

    pub const fn enc(&self) -> &[u8; AES128_STATIC_KEY_LEN] {
        &self.enc
    }

    pub const fn mac(&self) -> &[u8; AES128_STATIC_KEY_LEN] {
        &self.mac
    }
}

/// SCP03 session keys derived from static communication keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionKeys {
    enc: [u8; AES128_STATIC_KEY_LEN],
    mac: [u8; AES128_STATIC_KEY_LEN],
    rmac: [u8; AES128_STATIC_KEY_LEN],
}

impl SessionKeys {
    pub const fn enc(&self) -> &[u8; AES128_STATIC_KEY_LEN] {
        &self.enc
    }

    pub const fn mac(&self) -> &[u8; AES128_STATIC_KEY_LEN] {
        &self.mac
    }

    pub const fn rmac(&self) -> &[u8; AES128_STATIC_KEY_LEN] {
        &self.rmac
    }
}

/// Material produced by one SCP03 `INITIALIZE UPDATE` exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionMaterial {
    pub profile: Scp03Profile,
    pub card_cryptogram: [u8; S16_CRYPTOGRAM_LEN],
    pub host_cryptogram: [u8; S16_CRYPTOGRAM_LEN],
    pub keys: SessionKeys,
}

/// Stateful SCP03 secure messaging context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionState {
    profile: Scp03Profile,
    security_level: SecurityLevel,
    keys: SessionKeys,
    command_mac_chain: [u8; AES_CMAC_SIZE],
    response_mac_chain: [u8; AES_CMAC_SIZE],
    command_enc_counter: u32,
    response_enc_counter: u32,
}

impl SessionState {
    pub const fn new(
        profile: Scp03Profile,
        security_level: SecurityLevel,
        keys: SessionKeys,
    ) -> Self {
        Self::with_initial_mac_chain(profile, security_level, keys, [0; AES_CMAC_SIZE])
    }

    /// Creates an SCP03 secure-messaging state after explicit channel initiation.
    ///
    /// `initial_mac_chain` is the full 16-byte C-MAC computed for
    /// `EXTERNAL AUTHENTICATE`, even when the S8 wire profile transmits only
    /// its first eight bytes.
    pub const fn with_initial_mac_chain(
        profile: Scp03Profile,
        security_level: SecurityLevel,
        keys: SessionKeys,
        initial_mac_chain: [u8; AES_CMAC_SIZE],
    ) -> Self {
        Self {
            profile,
            security_level,
            keys,
            command_mac_chain: initial_mac_chain,
            response_mac_chain: initial_mac_chain,
            command_enc_counter: 0,
            response_enc_counter: 0,
        }
    }

    pub const fn profile(&self) -> Scp03Profile {
        self.profile
    }

    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    pub fn unwrap_command(
        &mut self,
        authenticated: &[u8],
        data: &[u8],
        mac: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Scp03Error> {
        self.unwrap_command_parts(authenticated, &[], data, mac, out)
    }

    /// Verifies and unwraps one command whose authenticated bytes are split
    /// between the APDU header and the protected data field.
    ///
    /// The two views are fed directly to CMAC. They must remain in wire order
    /// and must not overlap `out` while encrypted data is being transformed.
    pub fn unwrap_command_parts(
        &mut self,
        authenticated_header: &[u8],
        authenticated_data: &[u8],
        data: &[u8],
        mac: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Scp03Error> {
        if !self.security_level.uses_command_mac() {
            return Err(Scp03Error::InvalidState);
        }

        let computed_mac =
            self.compute_command_mac_parts(authenticated_header, authenticated_data)?;
        if !constant_time_eq(&computed_mac[..self.profile.mac_len()], mac) {
            return Err(Scp03Error::AuthenticationFailed);
        }
        let mut next_command_enc_counter = self.command_enc_counter;
        let data_len = if !self.security_level.uses_command_encryption() || data.is_empty() {
            copy_to_output(data, out)?
        } else {
            let key = aes_key(self.keys.enc())?;
            let iv = next_encryption_iv(
                &key,
                &mut next_command_enc_counter,
                EncryptionDirection::Command,
            )?;
            crypto::aes_cbc_decrypt_iso9797_m2(&key, &iv, data, out)?
        };

        // Invariant: rejected commands never consume a MAC-chain value or an
        // encryption counter, even when the MAC itself was valid.
        self.command_mac_chain = computed_mac;
        self.command_enc_counter = next_command_enc_counter;
        Ok(data_len)
    }

    pub fn wrap_response(
        &mut self,
        bytes: &[u8],
        status: (u8, u8),
        out: &mut [u8],
        mac_out: &mut [u8],
    ) -> Result<WrappedLengths, Scp03Error> {
        if !self.security_level.uses_response_mac() {
            let data_len = copy_to_output(bytes, out)?;
            return Ok(WrappedLengths {
                data_len,
                mac_len: 0,
            });
        }

        let mut next_response_enc_counter = self.response_enc_counter;
        let data_len = if self.security_level.uses_response_encryption() && !bytes.is_empty() {
            let key = aes_key(self.keys.enc())?;
            let iv = next_encryption_iv(
                &key,
                &mut next_response_enc_counter,
                EncryptionDirection::Response,
            )?;
            crypto::aes_cbc_encrypt_iso9797_m2(&key, &iv, bytes, out).map_err(Scp03Error::from)?
        } else {
            copy_to_output(bytes, out)?
        };

        let mac_len = self.profile.mac_len();
        if mac_out.len() < mac_len {
            return Err(Scp03Error::OutputTooSmall);
        }
        let status_bytes = [status.0, status.1];
        let mac = self.compute_response_mac_parts(&out[..data_len], &status_bytes)?;
        // Publish response state only after all bounds and crypto operations succeed.
        self.response_mac_chain = mac;
        self.response_enc_counter = next_response_enc_counter;
        mac_out[..mac_len].copy_from_slice(&mac[..mac_len]);

        Ok(WrappedLengths { data_len, mac_len })
    }

    fn compute_command_mac_parts(
        &self,
        authenticated_header: &[u8],
        authenticated_data: &[u8],
    ) -> Result<[u8; AES_CMAC_SIZE], Scp03Error> {
        compute_chained_cmac_parts(
            self.keys.mac(),
            &self.command_mac_chain,
            authenticated_header,
            authenticated_data,
        )
    }

    fn compute_response_mac_parts(
        &self,
        first: &[u8],
        second: &[u8],
    ) -> Result<[u8; AES_CMAC_SIZE], Scp03Error> {
        compute_chained_cmac_parts(self.keys.rmac(), &self.response_mac_chain, first, second)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrappedLengths {
    pub data_len: usize,
    pub mac_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scp03Error {
    InvalidProfileLength,
    InvalidState,
    AuthenticationFailed,
    OutputTooSmall,
    CounterOverflow,
    Crypto(crypto::CryptoError),
}

impl From<crypto::CryptoError> for Scp03Error {
    fn from(error: crypto::CryptoError) -> Self {
        Self::Crypto(error)
    }
}

/// Derives SCP03 session material for one host/card challenge pair.
pub fn derive_session(
    profile: Scp03Profile,
    static_keys: &StaticKeys,
    host_challenge: &[u8],
    card_challenge: &[u8],
) -> Result<SessionMaterial, Scp03Error> {
    if host_challenge.len() != profile.challenge_len()
        || card_challenge.len() != profile.challenge_len()
    {
        return Err(Scp03Error::InvalidProfileLength);
    }

    let mut context = [0u8; S16_CHALLENGE_LEN * 2];
    context[..host_challenge.len()].copy_from_slice(host_challenge);
    context[host_challenge.len()..host_challenge.len() + card_challenge.len()]
        .copy_from_slice(card_challenge);
    let context = &context[..host_challenge.len() + card_challenge.len()];

    let enc_key = aes_key(static_keys.enc())?;
    let mac_key = aes_key(static_keys.mac())?;
    let mut card_cryptogram = [0u8; S16_CRYPTOGRAM_LEN];
    let mut host_cryptogram = [0u8; S16_CRYPTOGRAM_LEN];
    let mut session_enc_key = [0u8; AES128_STATIC_KEY_LEN];
    let mut session_mac_key = [0u8; AES128_STATIC_KEY_LEN];
    let mut session_rmac_key = [0u8; AES128_STATIC_KEY_LEN];

    crypto::scp03_kdf(&enc_key, KDF_S_ENC, context, &mut session_enc_key)?;
    crypto::scp03_kdf(&mac_key, KDF_S_MAC, context, &mut session_mac_key)?;
    crypto::scp03_kdf(&mac_key, KDF_S_RMAC, context, &mut session_rmac_key)?;
    let session_mac_aes_key = aes_key(&session_mac_key)?;
    // SCP03 derives authentication cryptograms from S-MAC, not directly from
    // the static MAC key. This ordering is part of the interoperability contract.
    crypto::scp03_kdf(
        &session_mac_aes_key,
        KDF_CARD_CRYPTOGRAM,
        context,
        &mut card_cryptogram[..profile.cryptogram_len()],
    )?;
    crypto::scp03_kdf(
        &session_mac_aes_key,
        KDF_HOST_CRYPTOGRAM,
        context,
        &mut host_cryptogram[..profile.cryptogram_len()],
    )?;

    Ok(SessionMaterial {
        profile,
        card_cryptogram,
        host_cryptogram,
        keys: SessionKeys {
            enc: session_enc_key,
            mac: session_mac_key,
            rmac: session_rmac_key,
        },
    })
}

/// Compares one host cryptogram with the expected profile-sized value.
pub fn verify_host_cryptogram(
    profile: Scp03Profile,
    material: &SessionMaterial,
    host_cryptogram: &[u8],
) -> bool {
    material.profile == profile
        && constant_time_eq(
            &material.host_cryptogram[..profile.cryptogram_len()],
            host_cryptogram,
        )
}

/// Verifies the protected SCP03 `EXTERNAL AUTHENTICATE` command.
///
/// Explicit SCP03 initiation authenticates the command with a C-MAC computed
/// from an all-zero 16-byte chaining value. The command data is the
/// profile-sized host cryptogram followed by the profile-sized transmitted
/// C-MAC. On success, the full 16-byte C-MAC is returned for use as the
/// initial secure-messaging chain.
pub fn verify_external_authenticate(
    profile: Scp03Profile,
    material: &SessionMaterial,
    command_header: &[u8; 5],
    command_data: &[u8],
) -> Result<[u8; AES_CMAC_SIZE], Scp03Error> {
    let cryptogram_len = profile.cryptogram_len();
    let mac_len = profile.mac_len();
    let expected_data_len = cryptogram_len
        .checked_add(mac_len)
        .ok_or(Scp03Error::InvalidProfileLength)?;
    if material.profile != profile
        || command_header[0] != 0x84
        || command_header[1] != 0x82
        || command_header[3] != 0x00
        || command_header[4] as usize != expected_data_len
        || command_data.len() != expected_data_len
    {
        return Err(Scp03Error::InvalidProfileLength);
    }

    let (host_cryptogram, received_mac) = command_data.split_at(cryptogram_len);
    let full_mac = compute_chained_cmac_parts(
        material.keys.mac(),
        &[0; AES_CMAC_SIZE],
        command_header,
        host_cryptogram,
    )?;

    if !verify_host_cryptogram(profile, material, host_cryptogram)
        || !constant_time_eq(&full_mac[..mac_len], received_mac)
    {
        return Err(Scp03Error::AuthenticationFailed);
    }
    Ok(full_mac)
}

fn aes_key(key: &[u8; AES128_STATIC_KEY_LEN]) -> Result<AesKey, Scp03Error> {
    AesKey::from_bytes(key).map_err(Scp03Error::from)
}

fn compute_chained_cmac_parts(
    key: &[u8; AES128_STATIC_KEY_LEN],
    chain: &[u8; AES_CMAC_SIZE],
    first: &[u8],
    second: &[u8],
) -> Result<[u8; AES_CMAC_SIZE], Scp03Error> {
    let mut mac = [0u8; AES_CMAC_SIZE];
    let key = aes_key(key)?;
    crypto::aes_cmac_parts(&key, &[chain, first, second], &mut mac)?;
    Ok(mac)
}

#[derive(Clone, Copy)]
enum EncryptionDirection {
    Command,
    Response,
}

fn next_encryption_iv(
    key: &AesKey,
    counter: &mut u32,
    direction: EncryptionDirection,
) -> Result<[u8; AES_BLOCK_SIZE], Scp03Error> {
    *counter = counter.checked_add(1).ok_or(Scp03Error::CounterOverflow)?;
    let mut block = [0u8; AES_BLOCK_SIZE];
    block[0] = match direction {
        EncryptionDirection::Command => 0x01,
        EncryptionDirection::Response => 0x02,
    };
    block[12..16].copy_from_slice(&counter.to_be_bytes());
    crypto::aes_ecb_encrypt_in_place(key, &mut block)?;
    Ok(block)
}

fn copy_to_output(data: &[u8], out: &mut [u8]) -> Result<usize, Scp03Error> {
    if data.len() > out.len() {
        return Err(Scp03Error::OutputTooSmall);
    }
    out[..data.len()].copy_from_slice(data);
    Ok(data.len())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for index in 0..left.len() {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATIC_KEYS: StaticKeys = StaticKeys::aes128(
        [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f,
        ],
        [
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
            0x5e, 0x5f,
        ],
    );

    #[test]
    fn s8_session_derivation_is_deterministic() {
        let host_challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let card_challenge = *b"RUSTLET0";
        let first = derive_session(
            Scp03Profile::S8,
            &STATIC_KEYS,
            &host_challenge,
            &card_challenge,
        )
        .unwrap();
        let second = derive_session(
            Scp03Profile::S8,
            &STATIC_KEYS,
            &host_challenge,
            &card_challenge,
        )
        .unwrap();

        assert_eq!(first, second);
        assert_ne!(
            &first.card_cryptogram[..S8_CRYPTOGRAM_LEN],
            &[0; S8_CRYPTOGRAM_LEN]
        );
        assert_ne!(
            &first.host_cryptogram[..S8_CRYPTOGRAM_LEN],
            &[0; S8_CRYPTOGRAM_LEN]
        );
        assert_ne!(first.keys.enc(), first.keys.mac());
        assert_ne!(first.keys.mac(), first.keys.rmac());
    }

    #[test]
    fn s8_rejects_wrong_challenge_lengths() {
        assert_eq!(
            derive_session(Scp03Profile::S8, &STATIC_KEYS, &[0; 7], &[0; 8]),
            Err(Scp03Error::InvalidProfileLength)
        );
        assert_eq!(
            derive_session(Scp03Profile::S8, &STATIC_KEYS, &[0; 8], &[0; 16]),
            Err(Scp03Error::InvalidProfileLength)
        );
    }

    #[test]
    fn s16_construction_uses_profile_lengths() {
        let material =
            derive_session(Scp03Profile::S16, &STATIC_KEYS, &[0x11; 16], &[0x22; 16]).unwrap();

        assert_eq!(Scp03Profile::S16.challenge_len(), S16_CHALLENGE_LEN);
        assert_eq!(material.profile.cryptogram_len(), S16_CRYPTOGRAM_LEN);
        assert_eq!(material.profile.mac_len(), S16_MAC_LEN);
        assert!(verify_host_cryptogram(
            Scp03Profile::S16,
            &material,
            &material.host_cryptogram[..S16_CRYPTOGRAM_LEN],
        ));
        assert!(!verify_host_cryptogram(
            Scp03Profile::S8,
            &material,
            &material.host_cryptogram[..S8_CRYPTOGRAM_LEN],
        ));
    }

    #[test]
    fn s16_session_state_uses_full_length_mac() {
        let material =
            derive_session(Scp03Profile::S16, &STATIC_KEYS, &[0x11; 16], &[0x22; 16]).unwrap();
        let mut session = SessionState::new(
            Scp03Profile::S16,
            SecurityLevel::CmacCencRmacRenc,
            material.keys,
        );
        let mut out = [0u8; TRANSFORM_CAPACITY];
        let mut mac = [0u8; AES_CMAC_SIZE];

        let lengths = session
            .wrap_response(&[0x9f, 0x70, 0x01, 0x07], (0x90, 0x00), &mut out, &mut mac)
            .unwrap();

        assert_eq!(lengths.data_len, AES_BLOCK_SIZE);
        assert_eq!(lengths.mac_len, S16_MAC_LEN);
        assert_ne!(&mac[..S16_MAC_LEN], &[0; S16_MAC_LEN]);
    }

    #[test]
    fn s8_external_authenticate_verifies_protected_command_and_seeds_chain() {
        let material = derive_session(
            Scp03Profile::S8,
            &STATIC_KEYS,
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            b"RUSTLET0",
        )
        .unwrap();
        let full_mac = [
            0x6C, 0x00, 0x42, 0x17, 0x2B, 0x28, 0xD6, 0x69, 0xF9, 0x26, 0x6A, 0x2E, 0x53, 0x6E,
            0x3D, 0x9E,
        ];
        let mut data = [0u8; S8_CRYPTOGRAM_LEN + S8_MAC_LEN];
        data[..S8_CRYPTOGRAM_LEN].copy_from_slice(&material.host_cryptogram[..S8_CRYPTOGRAM_LEN]);
        data[S8_CRYPTOGRAM_LEN..].copy_from_slice(&full_mac[..S8_MAC_LEN]);

        assert_eq!(
            verify_external_authenticate(
                Scp03Profile::S8,
                &material,
                &[0x84, 0x82, 0x01, 0x00, 0x10],
                &data,
            ),
            Ok(full_mac)
        );
    }

    #[test]
    fn s16_external_authenticate_requires_full_mac_and_secure_messaging_cla() {
        let material = derive_session(
            Scp03Profile::S16,
            &STATIC_KEYS,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                0x17, 0x18,
            ],
            b"RUSTLET0RUSTLET1",
        )
        .unwrap();
        let full_mac = [
            0x67, 0x01, 0x74, 0x38, 0xD6, 0x2B, 0xCE, 0xAA, 0x4C, 0x45, 0x21, 0xC3, 0xFA, 0x15,
            0x6F, 0x7B,
        ];
        let mut data = [0u8; S16_CRYPTOGRAM_LEN + S16_MAC_LEN];
        data[..S16_CRYPTOGRAM_LEN].copy_from_slice(&material.host_cryptogram[..S16_CRYPTOGRAM_LEN]);
        data[S16_CRYPTOGRAM_LEN..].copy_from_slice(&full_mac);

        assert_eq!(
            verify_external_authenticate(
                Scp03Profile::S16,
                &material,
                &[0x84, 0x82, 0x03, 0x00, 0x20],
                &data,
            ),
            Ok(full_mac)
        );
        assert_eq!(
            verify_external_authenticate(
                Scp03Profile::S16,
                &material,
                &[0x80, 0x82, 0x03, 0x00, 0x20],
                &data,
            ),
            Err(Scp03Error::InvalidProfileLength)
        );
        data[S16_CRYPTOGRAM_LEN] ^= 0x01;
        assert_eq!(
            verify_external_authenticate(
                Scp03Profile::S16,
                &material,
                &[0x84, 0x82, 0x03, 0x00, 0x20],
                &data,
            ),
            Err(Scp03Error::AuthenticationFailed)
        );
    }

    #[test]
    fn s8_cmac_rejects_wrong_mac_and_replay_without_advancing_state() {
        let material = derive_session(Scp03Profile::S8, &STATIC_KEYS, &[1; 8], &[2; 8]).unwrap();
        let mut verifier = SessionState::new(Scp03Profile::S8, SecurityLevel::Cmac, material.keys);
        let authenticated = [0x84, 0xca, 0x9f, 0x70, 0x08];
        let mut out = [0u8; TRANSFORM_CAPACITY];
        let initial = verifier;

        assert_eq!(
            verifier.unwrap_command(&authenticated, &[], &[0xAA; S8_MAC_LEN], &mut out),
            Err(Scp03Error::AuthenticationFailed)
        );
        assert_eq!(verifier, initial);

        let command_mac = verifier
            .compute_command_mac_parts(&authenticated, &[])
            .unwrap();
        assert_eq!(
            verifier.unwrap_command(&authenticated, &[], &command_mac[..S8_MAC_LEN], &mut out,),
            Ok(0)
        );
        let accepted = verifier;
        assert_eq!(
            verifier.unwrap_command(&authenticated, &[], &command_mac[..S8_MAC_LEN], &mut out,),
            Err(Scp03Error::AuthenticationFailed)
        );
        assert_eq!(verifier, accepted);
    }

    #[test]
    fn s8_command_and_response_bounds_do_not_advance_session_state() {
        let material = derive_session(Scp03Profile::S8, &STATIC_KEYS, &[1; 8], &[2; 8]).unwrap();
        let mut command = SessionState::new(Scp03Profile::S8, SecurityLevel::Cmac, material.keys);
        let authenticated = [0x84, 0xe2, 0x00, 0x00, (1 + S8_MAC_LEN) as u8];
        let command_mac = command
            .compute_command_mac_parts(&authenticated, &[])
            .unwrap();
        let before_command = command;
        assert_eq!(
            command.unwrap_command(&authenticated, &[0x5A], &command_mac[..S8_MAC_LEN], &mut [],),
            Err(Scp03Error::OutputTooSmall)
        );
        assert_eq!(command, before_command);

        let mut response = SessionState::new(
            Scp03Profile::S8,
            SecurityLevel::CmacCencRmacRenc,
            material.keys,
        );
        let before_response = response;
        assert_eq!(
            response.wrap_response(&[0x5A], (0x90, 0x00), &mut [0u8; AES_BLOCK_SIZE], &mut [],),
            Err(Scp03Error::OutputTooSmall)
        );
        assert_eq!(response, before_response);
    }

    #[test]
    fn s8_cenc_round_trips_payload() {
        let material = derive_session(Scp03Profile::S8, &STATIC_KEYS, &[1; 8], &[2; 8]).unwrap();
        let mut sender = SessionState::new(
            Scp03Profile::S8,
            SecurityLevel::CmacCencRmacRenc,
            material.keys,
        );
        let mut receiver =
            SessionState::new(Scp03Profile::S8, SecurityLevel::CmacAndEnc, material.keys);
        let plaintext = b"Oxide SE SCP03 C-ENC";
        let mut encrypted = [0u8; TRANSFORM_CAPACITY];
        let mut mac = [0u8; AES_CMAC_SIZE];
        let response = sender
            .wrap_response(plaintext, (0x90, 0x00), &mut encrypted, &mut mac)
            .unwrap();

        assert!(response.data_len > plaintext.len());
        assert_eq!(response.mac_len, S8_MAC_LEN);

        // Invariant: command and response encryption use different IV domains.
        let bad = receiver.unwrap_command(
            &[
                0x84,
                0xe2,
                0x00,
                0x00,
                (response.data_len + response.mac_len) as u8,
            ],
            &encrypted[..response.data_len],
            &mac[..response.mac_len],
            &mut [0u8; TRANSFORM_CAPACITY],
        );
        assert!(bad.is_err());
    }

    #[test]
    fn selected_scp03_security_level_matrix_is_exhaustive() {
        for value in 0u8..=u8::MAX {
            let expected = matches!(value, 0x00 | 0x01 | 0x03);
            assert_eq!(
                SecurityLevel::from_selected_scp03_p1(value).is_some(),
                expected,
                "unexpected selected SCP03 level {value:02X}"
            );
        }
    }

    #[test]
    fn selected_scp03_levels_never_protect_responses() {
        for level in [
            SecurityLevel::None,
            SecurityLevel::Cmac,
            SecurityLevel::CmacAndEnc,
        ] {
            assert!(!level.uses_response_mac());
            assert!(!level.uses_response_encryption());
        }
        assert!(SecurityLevel::CmacCencRmacRenc.uses_response_mac());
        assert!(SecurityLevel::CmacCencRmacRenc.uses_response_encryption());
    }
}
