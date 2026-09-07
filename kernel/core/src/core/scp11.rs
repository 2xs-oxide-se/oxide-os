//! Shared SCP11 building blocks.
//!
//! This module owns the low-level material that can be reused by SCP11a,
//! SCP11b, and SCP11c: derived symmetric keys, secure-messaging state,
//! protected-APDU transforms, certificate/TLV parsing helpers, and the X9.63/SHA-256 KDF.
//! Profile-specific establishment policy remains layered above these helpers.

use super::crypto::{
    self, AesKey, AES_BLOCK_SIZE, AES_CMAC_SIZE, P256_PUBLIC_KEY_UNCOMPRESSED_SIZE,
    P256_SHARED_SECRET_SIZE,
};
use super::gp_sm;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const GP_CERTIFICATE_TAG: u16 = 0x7F21;
const MUTUAL_AUTHENTICATE_CRT_TAG: u16 = 0xA6;
const TAG_SCP_IDENTIFIER: u16 = 0x90;
const TAG_KEY_USAGE_QUALIFIER: u16 = 0x95;
const TAG_KEY_TYPE: u16 = 0x80;
const TAG_KEY_LENGTH: u16 = 0x81;
const TAG_HOST_ID: u16 = 0x84;
const TAG_EPHEMERAL_PUBLIC_KEY: u16 = 0x5F49;
const TAG_RECEIPT: u16 = 0x86;
const DEV_CA_PUBLIC_KEY: [u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE] = [
    0x04, 0xBE, 0x57, 0x7B, 0x5B, 0x33, 0xB8, 0xC3, 0xDC, 0xFA, 0x81, 0x85, 0x85, 0x93, 0xD8, 0x49,
    0x38, 0x20, 0x3E, 0x78, 0xBA, 0x10, 0xF8, 0x7F, 0xB7, 0x53, 0x76, 0xEE, 0xA9, 0x37, 0xD5, 0x59,
    0x2A, 0xF5, 0x2B, 0xDC, 0x64, 0x1C, 0x43, 0xAD, 0xEA, 0x9E, 0x34, 0x2F, 0xFC, 0x6F, 0xDB, 0xFE,
    0x5C, 0x86, 0x3C, 0x9F, 0x6E, 0xD3, 0x04, 0x71, 0x99, 0x9A, 0x1D, 0x01, 0xEC, 0xF5, 0x40, 0x65,
    0xBE,
];
/// Size of one SCP11c symmetric session key.
pub const SESSION_KEY_LEN: usize = 16;
/// MAC length used by the current SCP11c MAC-only secure messaging profile.
pub const MAC_LEN: usize = AES_CMAC_SIZE;
/// Maximum plaintext or ciphertext payload staged by one SCP11c transform.
pub const TRANSFORM_CAPACITY: usize = gp_sm::PROTECTED_TRANSFORM_CAPACITY;
/// SCP11 key usage qualifier requesting C-ENC, R-ENC, C-MAC, and R-MAC.
pub const KEY_USAGE_FULL: u8 = 0x3C;
/// SCP11 key usage qualifier requesting C-MAC and R-MAC.
pub const KEY_USAGE_MACS: u8 = 0x34;
/// SCP11c-only key usage qualifier requesting C-MAC and C-ENC.
pub const KEY_USAGE_COMMAND_ONLY: u8 = 0x1C;
/// SCP11c-only key usage qualifier requesting C-MAC, C-ENC, and R-MAC.
pub const KEY_USAGE_COMMAND_ENC_RESPONSE_MAC: u8 = 0x74;
/// AES key type used by the current SCP11c development profile.
pub const KEY_TYPE_AES: u8 = 0x88;
/// AES-128 key length used by the current SCP11c development profile.
pub const KEY_LENGTH_AES_128: u8 = 0x10;
/// Maximum Host ID accepted in the SCP11c SharedInfo material.
pub const HOST_ID_CAPACITY: usize = 16;
/// Maximum Card Group ID staged in the SCP11c SharedInfo material.
pub const CARD_GROUP_ID_CAPACITY: usize = 16;
/// Maximum Secure Channel Initiation String staged in SCP11a SharedInfo.
pub const SCP11A_SIN_CAPACITY: usize = 16;
/// Maximum Secure Domain Identification Number staged in SCP11a SharedInfo.
pub const SCP11A_SDIN_CAPACITY: usize = 16;
/// SCP11a KDF input secret size: static ECDH contribution plus ephemeral one.
pub const SCP11A_SHARED_SECRET_LEN: usize = P256_SHARED_SECRET_SIZE * 2;
/// First byte of the SCP identifier DO value for the SCP11 family.
pub const SCP11_IDENTIFIER_FAMILY: u8 = 0x11;
/// SCP identifier parameter byte for the current SCP11a development profile.
pub const SCP11A_IDENTIFIER_PARAM: u8 = 0x05;
/// SCP identifier parameter byte for the current SCP11b development profile.
pub const SCP11B_IDENTIFIER_PARAM: u8 = 0x04;
/// SCP identifier parameter byte for the current SCP11c development profile.
pub const SCP11C_IDENTIFIER_PARAM: u8 = 0x07;
/// Size of a TLV-encoded `MUTUAL AUTHENTICATE` response: `5F49 || 86`.
pub const MUTUAL_AUTHENTICATE_RESPONSE_LEN: usize =
    3 + P256_PUBLIC_KEY_UNCOMPRESSED_SIZE + 2 + AES_CMAC_SIZE;
/// Total size of the SCP11c `KeyData` block.
pub const SESSION_DERIVED_LEN: usize = SESSION_KEY_LEN * 5;
/// SCP11c concatenates its ephemeral/static and static/static ECDH results.
pub const SCP11C_SHARED_SECRET_LEN: usize = P256_SHARED_SECRET_SIZE * 2;

/// SCP11 establishment profile selected above the shared secure-messaging code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scp11Profile {
    A,
    B,
    C,
}

/// Parameters encoded by the second byte of the SCP identifier DO.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scp11Parameters {
    /// SCP11a, SCP11b, or SCP11c selected by bits b2-b1.
    pub profile: Scp11Profile,
    /// Whether bit b3 binds host and card identities into SharedInfo.
    pub include_identifiers: bool,
}

/// Host-authentication material required by one SCP11 establishment profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scp11HostAuthentication {
    None,
    Certificate,
}

/// Static policy selected by the SCP11 establishment profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scp11EstablishmentPolicy {
    pub profile: Scp11Profile,
    pub host_authentication: Scp11HostAuthentication,
    pub requires_pso_certificate: bool,
    pub mutual_authenticate_supported: bool,
}

impl Scp11Profile {
    /// Returns the kernel policy currently implemented for this SCP11 profile.
    ///
    /// SCP11a and SCP11b are intentionally exposed here before their APDU path
    /// is wired, so host-based tests can lock down profile selection without
    /// pretending that the full establishment sequence already exists.
    pub const fn establishment_policy(self) -> Scp11EstablishmentPolicy {
        match self {
            Self::A => Scp11EstablishmentPolicy {
                profile: self,
                host_authentication: Scp11HostAuthentication::Certificate,
                requires_pso_certificate: true,
                mutual_authenticate_supported: true,
            },
            Self::B => Scp11EstablishmentPolicy {
                profile: self,
                host_authentication: Scp11HostAuthentication::None,
                requires_pso_certificate: false,
                mutual_authenticate_supported: true,
            },
            Self::C => Scp11EstablishmentPolicy {
                profile: self,
                host_authentication: Scp11HostAuthentication::Certificate,
                requires_pso_certificate: true,
                mutual_authenticate_supported: true,
            },
        }
    }
}

/// Returns whether a GP key-usage qualifier is defined for this SCP11 profile.
pub const fn is_gp_key_usage_qualifier(profile: Scp11Profile, qualifier: u8) -> bool {
    match profile {
        Scp11Profile::A | Scp11Profile::B => {
            matches!(qualifier, KEY_USAGE_MACS | KEY_USAGE_FULL)
        }
        Scp11Profile::C => matches!(
            qualifier,
            KEY_USAGE_MACS
                | KEY_USAGE_FULL
                | KEY_USAGE_COMMAND_ONLY
                | KEY_USAGE_COMMAND_ENC_RESPONSE_MAC
        ),
    }
}

/// Returns whether the deliberately selected Oxide SE profile accepts `qualifier`.
///
/// The current kernel selects full bidirectional protection for every SCP11
/// variant and rejects every other GP-defined or RFU value.
pub const fn is_selected_key_usage_qualifier(_profile: Scp11Profile, qualifier: u8) -> bool {
    qualifier == KEY_USAGE_FULL
}

/// Symmetric SCP11 key material derived by one establishment exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scp11SessionKeys {
    enc: [u8; SESSION_KEY_LEN],
    mac: [u8; SESSION_KEY_LEN],
    rmac: [u8; SESSION_KEY_LEN],
    dek: [u8; SESSION_KEY_LEN],
    receipt: [u8; SESSION_KEY_LEN],
}

impl Scp11SessionKeys {
    pub const fn enc(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.enc
    }

    pub const fn mac(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.mac
    }

    pub const fn rmac(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.rmac
    }

    pub const fn dek(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.dek
    }

    pub const fn receipt(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.receipt
    }
}

fn session_keys_from_derived(derived: &[u8; SESSION_DERIVED_LEN]) -> Scp11SessionKeys {
    let mut enc = [0u8; SESSION_KEY_LEN];
    let mut mac = [0u8; SESSION_KEY_LEN];
    let mut rmac = [0u8; SESSION_KEY_LEN];
    let mut dek = [0u8; SESSION_KEY_LEN];
    let mut receipt = [0u8; SESSION_KEY_LEN];
    // Invariant: Amendment F assigns KeyData in receipt, S-ENC, S-MAC,
    // S-RMAC, S-DEK order. Both sides must consume exactly that order.
    receipt.copy_from_slice(&derived[..SESSION_KEY_LEN]);
    enc.copy_from_slice(&derived[SESSION_KEY_LEN..2 * SESSION_KEY_LEN]);
    mac.copy_from_slice(&derived[2 * SESSION_KEY_LEN..3 * SESSION_KEY_LEN]);
    rmac.copy_from_slice(&derived[3 * SESSION_KEY_LEN..4 * SESSION_KEY_LEN]);
    dek.copy_from_slice(&derived[4 * SESSION_KEY_LEN..]);
    Scp11SessionKeys {
        enc,
        mac,
        rmac,
        dek,
        receipt,
    }
}

/// Parsed SCP11 `MUTUAL AUTHENTICATE` or `INTERNAL AUTHENTICATE` CRT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutualAuthenticateRequest<'a> {
    pub parameters: Scp11Parameters,
    pub key_usage_qualifier: u8,
    pub key_type: u8,
    pub key_length: u8,
    pub host_id: &'a [u8],
    pub host_ephemeral_public: &'a [u8],
}

impl<'a> MutualAuthenticateRequest<'a> {
    pub fn validate_supported_profile(&self) -> crypto::CryptoResult<()> {
        if !is_selected_key_usage_qualifier(self.parameters.profile, self.key_usage_qualifier)
            || self.key_type != KEY_TYPE_AES
            || self.key_length != KEY_LENGTH_AES_128
            || self.host_id.len() > HOST_ID_CAPACITY
            || self.host_ephemeral_public.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE
        {
            return Err(crypto::CryptoError::InvalidBufferLength);
        }
        Ok(())
    }
}

/// Small, bounded SharedInfo representation used by SCP11a X9.63 KDF.
///
/// SCP11a binds both a static ECDH contribution and an ephemeral ECDH
/// contribution into the same KDF. The identity fields are copied into bounded
/// arrays so the host-tested implementation has the same memory shape as the
/// kernel path that will consume it later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scp11aSharedInfo {
    key_usage_qualifier: u8,
    key_type: u8,
    key_length: u8,
    include_identifiers: bool,
    host_id_len: u8,
    host_id: [u8; HOST_ID_CAPACITY],
    sin_len: u8,
    sin: [u8; SCP11A_SIN_CAPACITY],
    sdin_len: u8,
    sdin: [u8; SCP11A_SDIN_CAPACITY],
}

impl Scp11aSharedInfo {
    /// Builds the SCP11a SharedInfo payload from bounded GP identity fields.
    pub fn new(
        key_usage_qualifier: u8,
        key_type: u8,
        key_length: u8,
        host_id: &[u8],
        sin: &[u8],
        sdin: &[u8],
    ) -> crypto::CryptoResult<Self> {
        let identifiers_are_consistent = matches!(
            (host_id.is_empty(), sin.is_empty(), sdin.is_empty()),
            (true, true, true) | (false, false, false)
        );
        // Invariant: only the AES-128 full secure-messaging profile is wired
        // by the current build profile.
        if key_usage_qualifier != KEY_USAGE_FULL
            || key_type != KEY_TYPE_AES
            || key_length != KEY_LENGTH_AES_128
            || host_id.len() > HOST_ID_CAPACITY
            || sin.len() > SCP11A_SIN_CAPACITY
            || sdin.len() > SCP11A_SDIN_CAPACITY
            || !identifiers_are_consistent
        {
            return Err(crypto::CryptoError::InvalidBufferLength);
        }

        let mut stored_host_id = [0u8; HOST_ID_CAPACITY];
        stored_host_id[..host_id.len()].copy_from_slice(host_id);
        let mut stored_sin = [0u8; SCP11A_SIN_CAPACITY];
        stored_sin[..sin.len()].copy_from_slice(sin);
        let mut stored_sdin = [0u8; SCP11A_SDIN_CAPACITY];
        stored_sdin[..sdin.len()].copy_from_slice(sdin);
        Ok(Self {
            key_usage_qualifier,
            key_type,
            key_length,
            include_identifiers: !host_id.is_empty(),
            host_id_len: host_id.len() as u8,
            host_id: stored_host_id,
            sin_len: sin.len() as u8,
            sin: stored_sin,
            sdin_len: sdin.len() as u8,
            sdin: stored_sdin,
        })
    }

    fn write_kdf_input(&self, out: &mut [u8]) -> crypto::CryptoResult<usize> {
        let identity_len = if self.include_identifiers {
            3 + self.host_id_len as usize + self.sin_len as usize + self.sdin_len as usize
        } else {
            0
        };
        let needed = 3 + identity_len;
        if needed > out.len() {
            return Err(crypto::CryptoError::InvalidBufferLength);
        }

        let mut cursor = 0;
        out[cursor] = self.key_usage_qualifier;
        out[cursor + 1] = self.key_type;
        out[cursor + 2] = self.key_length;
        cursor += 3;

        if !self.include_identifiers {
            return Ok(cursor);
        }

        out[cursor] = self.host_id_len;
        cursor += 1;
        let host_len = self.host_id_len as usize;
        out[cursor..cursor + host_len].copy_from_slice(&self.host_id[..host_len]);
        cursor += host_len;

        out[cursor] = self.sin_len;
        cursor += 1;
        let sin_len = self.sin_len as usize;
        out[cursor..cursor + sin_len].copy_from_slice(&self.sin[..sin_len]);
        cursor += sin_len;

        out[cursor] = self.sdin_len;
        cursor += 1;
        let sdin_len = self.sdin_len as usize;
        out[cursor..cursor + sdin_len].copy_from_slice(&self.sdin[..sdin_len]);
        cursor += sdin_len;

        Ok(cursor)
    }
}

/// Small, bounded SharedInfo representation used by SCP11c X9.63 KDF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedInfo {
    key_usage_qualifier: u8,
    key_type: u8,
    key_length: u8,
    host_id_len: u8,
    host_id: [u8; HOST_ID_CAPACITY],
    card_group_id_len: u8,
    card_group_id: [u8; CARD_GROUP_ID_CAPACITY],
}

impl SharedInfo {
    /// Builds SCP11c SharedInfo from the parsed host request and SD-owned identity.
    pub fn new(
        request: &MutualAuthenticateRequest<'_>,
        card_group_id: &[u8],
    ) -> crypto::CryptoResult<Self> {
        request.validate_supported_profile()?;
        if card_group_id.len() > CARD_GROUP_ID_CAPACITY {
            return Err(crypto::CryptoError::InvalidBufferLength);
        }
        let selected_card_group_id = if request.parameters.include_identifiers {
            card_group_id
        } else {
            &[]
        };
        let mut host_id = [0u8; HOST_ID_CAPACITY];
        host_id[..request.host_id.len()].copy_from_slice(request.host_id);
        let mut stored_card_group_id = [0u8; CARD_GROUP_ID_CAPACITY];
        stored_card_group_id[..selected_card_group_id.len()]
            .copy_from_slice(selected_card_group_id);
        Ok(Self {
            key_usage_qualifier: request.key_usage_qualifier,
            key_type: request.key_type,
            key_length: request.key_length,
            host_id_len: request.host_id.len() as u8,
            host_id,
            card_group_id_len: selected_card_group_id.len() as u8,
            card_group_id: stored_card_group_id,
        })
    }

    fn write_kdf_input(&self, out: &mut [u8]) -> crypto::CryptoResult<usize> {
        let identity_len = if self.host_id_len == 0 {
            0
        } else {
            2 + self.host_id_len as usize + self.card_group_id_len as usize
        };
        let needed = 3 + identity_len;
        if needed > out.len() {
            return Err(crypto::CryptoError::InvalidBufferLength);
        }

        let mut cursor = 0;
        out[cursor] = self.key_usage_qualifier;
        out[cursor + 1] = self.key_type;
        out[cursor + 2] = self.key_length;
        cursor += 3;
        if self.host_id_len == 0 {
            return Ok(cursor);
        }
        out[cursor] = self.host_id_len;
        cursor += 1;
        let host_len = self.host_id_len as usize;
        out[cursor..cursor + host_len].copy_from_slice(&self.host_id[..host_len]);
        cursor += host_len;
        out[cursor] = self.card_group_id_len;
        cursor += 1;
        let card_group_len = self.card_group_id_len as usize;
        out[cursor..cursor + card_group_len].copy_from_slice(&self.card_group_id[..card_group_len]);
        cursor += card_group_len;
        Ok(cursor)
    }
}

/// Stateful SCP11 secure-messaging context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scp11SessionState {
    keys: Scp11SessionKeys,
    command_mac_chain: [u8; AES_CMAC_SIZE],
    response_mac_chain: [u8; AES_CMAC_SIZE],
    command_enc_counter: u32,
    response_enc_counter: u32,
}

impl Scp11SessionState {
    pub const fn new(keys: Scp11SessionKeys, receipt: [u8; AES_CMAC_SIZE]) -> Self {
        Self {
            keys,
            command_mac_chain: receipt,
            response_mac_chain: receipt,
            command_enc_counter: 0,
            response_enc_counter: 0,
        }
    }

    /// Returns the receipt that seeds the command MAC chain.
    pub const fn initial_receipt(&self) -> &[u8; AES_CMAC_SIZE] {
        &self.command_mac_chain
    }

    pub fn unwrap_command(
        &mut self,
        authenticated: &[u8],
        data: &[u8],
        mac: &[u8],
        out: &mut [u8],
    ) -> crypto::CryptoResult<usize> {
        self.unwrap_command_parts(authenticated, &[], data, mac, out)
    }

    /// Verifies and unwraps one command whose authenticated bytes are split
    /// between the APDU header and the protected data field.
    ///
    /// The views are consumed in wire order without first concatenating them
    /// into an APDU-sized temporary buffer.
    pub fn unwrap_command_parts(
        &mut self,
        authenticated_header: &[u8],
        authenticated_data: &[u8],
        data: &[u8],
        mac: &[u8],
        out: &mut [u8],
    ) -> crypto::CryptoResult<usize> {
        if mac.len() != MAC_LEN {
            return Err(crypto::CryptoError::InvalidBufferLength);
        }
        let computed_mac =
            self.compute_command_mac_parts(authenticated_header, authenticated_data)?;
        if !constant_time_eq(&computed_mac[..MAC_LEN], mac) {
            return Err(crypto::CryptoError::InvalidBufferLength);
        }
        let mut next_command_enc_counter = self.command_enc_counter;
        let data_len = if data.is_empty() {
            copy_to_output(data, out)?
        } else {
            let key = AesKey::from_bytes(self.keys.enc())?;
            let iv = next_encryption_iv(
                &key,
                &mut next_command_enc_counter,
                EncryptionDirection::Command,
            )?;
            crypto::aes_cbc_decrypt_iso9797_m2(&key, &iv, data, out)?
        };
        // Invariant: a rejected protected command leaves all replay state intact.
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
    ) -> crypto::CryptoResult<Scp11WrappedLengths> {
        let mut next_response_enc_counter = self.response_enc_counter;
        let data_len = if bytes.is_empty() {
            copy_to_output(bytes, out)?
        } else {
            let key = AesKey::from_bytes(self.keys.enc())?;
            let iv = next_encryption_iv(
                &key,
                &mut next_response_enc_counter,
                EncryptionDirection::Response,
            )?;
            crypto::aes_cbc_encrypt_iso9797_m2(&key, &iv, bytes, out)?
        };
        if mac_out.len() < MAC_LEN {
            return Err(crypto::CryptoError::InvalidBufferLength);
        }
        let status_bytes = [status.0, status.1];
        let mac = self.compute_response_mac_parts(&out[..data_len], &status_bytes)?;
        self.response_mac_chain = mac;
        self.response_enc_counter = next_response_enc_counter;
        mac_out[..MAC_LEN].copy_from_slice(&mac[..MAC_LEN]);
        Ok(Scp11WrappedLengths {
            data_len,
            mac_len: MAC_LEN,
        })
    }

    #[cfg(test)]
    fn compute_command_mac(
        &self,
        authenticated: &[u8],
    ) -> crypto::CryptoResult<[u8; AES_CMAC_SIZE]> {
        self.compute_command_mac_parts(authenticated, &[])
    }

    fn compute_command_mac_parts(
        &self,
        authenticated_header: &[u8],
        authenticated_data: &[u8],
    ) -> crypto::CryptoResult<[u8; AES_CMAC_SIZE]> {
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
    ) -> crypto::CryptoResult<[u8; AES_CMAC_SIZE]> {
        compute_chained_cmac_parts(self.keys.rmac(), &self.response_mac_chain, first, second)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scp11WrappedLengths {
    pub data_len: usize,
    pub mac_len: usize,
}

/// Verified subset of one GlobalPlatform OCE certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedOceCertificate<'a> {
    public_key: &'a [u8],
    subject_id: Option<&'a [u8]>,
    discretionary_data: Option<&'a [u8]>,
}

impl<'a> VerifiedOceCertificate<'a> {
    pub const fn public_key(&self) -> &'a [u8] {
        self.public_key
    }

    pub fn subject_id(&self) -> &'a [u8] {
        self.subject_id.unwrap_or(&[])
    }

    pub fn discretionary_data(&self) -> &'a [u8] {
        self.discretionary_data.unwrap_or(&[])
    }
}

/// Returns the development CA public key used by the current bootstrap profile.
pub const fn dev_ca_public_key() -> &'static [u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE] {
    &DEV_CA_PUBLIC_KEY
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u16,
    value: &'a [u8],
}

fn parse_tlv<'a>(input: &'a [u8], cursor: &mut usize) -> Option<Tlv<'a>> {
    if *cursor >= input.len() {
        return None;
    }
    let first = *input.get(*cursor)?;
    *cursor += 1;
    let tag = if (first & 0x1F) == 0x1F {
        let second = *input.get(*cursor)?;
        *cursor += 1;
        ((first as u16) << 8) | second as u16
    } else {
        first as u16
    };
    let len_first = *input.get(*cursor)?;
    *cursor += 1;
    let len = if len_first & 0x80 == 0 {
        len_first as usize
    } else {
        match len_first {
            0x81 => {
                let value = *input.get(*cursor)? as usize;
                *cursor += 1;
                value
            }
            _ => return None,
        }
    };
    let end = (*cursor).checked_add(len)?;
    let value = input.get(*cursor..end)?;
    *cursor = end;
    Some(Tlv { tag, value })
}

fn parse_public_key_template(value: &[u8]) -> Option<&[u8]> {
    let mut cursor = 0;
    let mut public_key = None;
    let mut parameter_ref_present = false;
    while cursor < value.len() {
        let tlv = parse_tlv(value, &mut cursor)?;
        match tlv.tag {
            0xB0 => {
                if tlv.value.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE {
                    return None;
                }
                public_key = Some(tlv.value);
            }
            0xF0 => {
                if tlv.value.is_empty() || tlv.value.len() > 2 {
                    return None;
                }
                parameter_ref_present = true;
            }
            _ => return None,
        }
    }
    if !parameter_ref_present {
        return None;
    }
    public_key
}

/// Parses the SCP11c `MUTUAL AUTHENTICATE` control reference template.
pub fn parse_mutual_authenticate_request(
    data: &[u8],
) -> crypto::CryptoResult<MutualAuthenticateRequest<'_>> {
    parse_mutual_authenticate_request_for_profile(Scp11Profile::C, data)
}

/// Parses the minimal SCP11a `MUTUAL AUTHENTICATE` request CRT currently wired by the kernel.
pub fn parse_scp11a_mutual_authenticate_request(
    data: &[u8],
) -> crypto::CryptoResult<MutualAuthenticateRequest<'_>> {
    parse_mutual_authenticate_request_for_profile(Scp11Profile::A, data)
}

/// Parses the minimal SCP11b `INTERNAL AUTHENTICATE` request CRT currently wired by the kernel.
pub fn parse_scp11b_internal_authenticate_request(
    data: &[u8],
) -> crypto::CryptoResult<MutualAuthenticateRequest<'_>> {
    parse_mutual_authenticate_request_for_profile(Scp11Profile::B, data)
}

/// Parses one `MUTUAL AUTHENTICATE` CRT according to the selected SCP11 profile.
///
/// The current profile gate keeps SCP11c on its dedicated parser façade while
/// SCP11a/SCP11b use their explicit profile entry points.
pub fn parse_mutual_authenticate_request_for_profile(
    profile: Scp11Profile,
    data: &[u8],
) -> crypto::CryptoResult<MutualAuthenticateRequest<'_>> {
    let (detected, request) = parse_mutual_authenticate_request_inner(data)?;
    if detected != profile {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }
    Ok(request)
}

/// Detects the SCP11 establishment profile declared by the CRT `90 02 11 pp` DO.
pub fn detect_mutual_authenticate_profile(data: &[u8]) -> crypto::CryptoResult<Scp11Profile> {
    let mut cursor = 0;
    let outer = parse_tlv(data, &mut cursor).ok_or(crypto::CryptoError::InvalidBufferLength)?;
    if outer.tag != MUTUAL_AUTHENTICATE_CRT_TAG {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }
    let ephemeral = parse_tlv(data, &mut cursor).ok_or(crypto::CryptoError::InvalidBufferLength)?;
    if ephemeral.tag != TAG_EPHEMERAL_PUBLIC_KEY
        || ephemeral.value.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE
        || cursor != data.len()
    {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }

    let mut inner_cursor = 0;
    while inner_cursor < outer.value.len() {
        let field = parse_tlv(outer.value, &mut inner_cursor)
            .ok_or(crypto::CryptoError::InvalidBufferLength)?;
        if field.tag == TAG_SCP_IDENTIFIER {
            return Ok(parse_scp_identifier_parameters(field.value)?.profile);
        }
    }

    Err(crypto::CryptoError::InvalidBufferLength)
}

fn parse_mutual_authenticate_request_inner(
    data: &[u8],
) -> crypto::CryptoResult<(Scp11Profile, MutualAuthenticateRequest<'_>)> {
    let mut cursor = 0;
    let outer = parse_tlv(data, &mut cursor).ok_or(crypto::CryptoError::InvalidBufferLength)?;
    if outer.tag != MUTUAL_AUTHENTICATE_CRT_TAG {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }
    // Invariant: tag 5F49 is a sibling of the A6 CRT, not one of its sub-TLVs.
    let host_ephemeral =
        parse_tlv(data, &mut cursor).ok_or(crypto::CryptoError::InvalidBufferLength)?;
    if host_ephemeral.tag != TAG_EPHEMERAL_PUBLIC_KEY
        || host_ephemeral.value.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE
        || cursor != data.len()
    {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }

    let mut key_usage_qualifier = None;
    let mut key_type = None;
    let mut key_length = None;
    let mut scp_parameters = None;
    let mut host_id = None;
    let mut inner_cursor = 0;
    while inner_cursor < outer.value.len() {
        let field = parse_tlv(outer.value, &mut inner_cursor)
            .ok_or(crypto::CryptoError::InvalidBufferLength)?;
        match field.tag {
            TAG_SCP_IDENTIFIER => {
                if scp_parameters.is_some() {
                    return Err(crypto::CryptoError::InvalidBufferLength);
                }
                scp_parameters = Some(parse_scp_identifier_parameters(field.value)?);
            }
            TAG_KEY_USAGE_QUALIFIER => {
                if field.value.len() != 1 {
                    return Err(crypto::CryptoError::InvalidBufferLength);
                }
                if key_usage_qualifier.is_some() {
                    return Err(crypto::CryptoError::InvalidBufferLength);
                }
                key_usage_qualifier = Some(field.value[0]);
            }
            TAG_KEY_TYPE => {
                if field.value.len() != 1 {
                    return Err(crypto::CryptoError::InvalidBufferLength);
                }
                if key_type.is_some() {
                    return Err(crypto::CryptoError::InvalidBufferLength);
                }
                key_type = Some(field.value[0]);
            }
            TAG_KEY_LENGTH => {
                if field.value.len() != 1 {
                    return Err(crypto::CryptoError::InvalidBufferLength);
                }
                if key_length.is_some() {
                    return Err(crypto::CryptoError::InvalidBufferLength);
                }
                key_length = Some(field.value[0]);
            }
            TAG_HOST_ID => {
                if host_id.is_some() || field.value.is_empty() {
                    return Err(crypto::CryptoError::InvalidBufferLength);
                }
                host_id = Some(field.value);
            }
            _ => return Err(crypto::CryptoError::InvalidBufferLength),
        }
    }

    let parameters = scp_parameters.ok_or(crypto::CryptoError::InvalidBufferLength)?;
    // Invariant: GP requires tag 84 exactly when SCP parameter bit b3 asks the
    // KDF to bind Host ID and the SD-owned card identity fields.
    if parameters.include_identifiers != host_id.is_some() {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }
    let request = MutualAuthenticateRequest {
        parameters,
        key_usage_qualifier: key_usage_qualifier.ok_or(crypto::CryptoError::InvalidBufferLength)?,
        key_type: key_type.ok_or(crypto::CryptoError::InvalidBufferLength)?,
        key_length: key_length.ok_or(crypto::CryptoError::InvalidBufferLength)?,
        host_id: host_id.unwrap_or(&[]),
        host_ephemeral_public: host_ephemeral.value,
    };
    request.validate_supported_profile()?;
    Ok((parameters.profile, request))
}

fn parse_scp_identifier_parameters(value: &[u8]) -> crypto::CryptoResult<Scp11Parameters> {
    if value.len() != 2 || value[0] != SCP11_IDENTIFIER_FAMILY {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }
    let parameter = value[1];
    if (parameter & 0xF8) != 0 {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }
    let profile = match parameter & 0x03 {
        0x00 => Scp11Profile::B,
        0x01 => Scp11Profile::A,
        0x03 => Scp11Profile::C,
        _ => return Err(crypto::CryptoError::InvalidBufferLength),
    };
    Ok(Scp11Parameters {
        profile,
        include_identifiers: (parameter & 0x04) != 0,
    })
}

/// Parses and verifies one GlobalPlatform `CERT.OCE.ECKA` certificate.
#[inline(never)]
pub fn verify_oce_certificate<'a>(
    ca_public_key_sec1: &[u8],
    certificate: &'a [u8],
) -> crypto::CryptoResult<VerifiedOceCertificate<'a>> {
    let mut cursor = 0;
    let outer =
        parse_tlv(certificate, &mut cursor).ok_or(crypto::CryptoError::InvalidBufferLength)?;
    if outer.tag != GP_CERTIFICATE_TAG || cursor != certificate.len() {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }

    let mut subject_id = None;
    let mut discretionary_data = None;
    let mut public_key = None;
    let mut key_usage_ok = false;
    let mut signature = None;
    let mut signed_data_len = None;
    let mut inner_cursor = 0;
    while inner_cursor < outer.value.len() {
        let field_start = inner_cursor;
        let field = parse_tlv(outer.value, &mut inner_cursor)
            .ok_or(crypto::CryptoError::InvalidBufferLength)?;
        match field.tag {
            0x93 | 0x42 | 0x5F24 | 0x5F25 | 0x73 | 0x53 => {}
            0x5F20 => {
                subject_id = Some(field.value);
            }
            0x95 => {
                key_usage_ok = field.value == [0x00, 0x80];
            }
            0xBF20 => {
                discretionary_data = Some(field.value);
            }
            0x7F49 => {
                public_key = Some(
                    parse_public_key_template(field.value)
                        .ok_or(crypto::CryptoError::InvalidBufferLength)?,
                );
            }
            0x5F37 => {
                if inner_cursor != outer.value.len() || field.value.len() != 64 {
                    return Err(crypto::CryptoError::InvalidBufferLength);
                }
                signature = Some(field.value);
                signed_data_len = Some(field_start);
            }
            _ => return Err(crypto::CryptoError::InvalidBufferLength),
        }
    }

    let public_key = public_key.ok_or(crypto::CryptoError::InvalidBufferLength)?;
    let subject_id = subject_id.ok_or(crypto::CryptoError::InvalidBufferLength)?;
    let signature = signature.ok_or(crypto::CryptoError::InvalidBufferLength)?;
    let signed_data_len = signed_data_len.ok_or(crypto::CryptoError::InvalidBufferLength)?;
    if !key_usage_ok {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }

    verify_oce_signature(
        ca_public_key_sec1,
        &outer.value[..signed_data_len],
        signature,
    )?;

    Ok(VerifiedOceCertificate {
        public_key,
        subject_id: Some(subject_id),
        discretionary_data,
    })
}

#[inline(never)]
fn verify_oce_signature(
    ca_public_key_sec1: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> crypto::CryptoResult<()> {
    let digest = Sha256::digest(signed_data);
    let verifying_key = VerifyingKey::from_sec1_bytes(ca_public_key_sec1)
        .map_err(|_| crypto::CryptoError::InvalidKeyLength)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| crypto::CryptoError::InvalidBufferLength)?;
    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|_| crypto::CryptoError::InvalidBufferLength)
}

/// Computes the SCP11 receipt returned by an authentication command.
///
/// `command_data` is the exact command data field, starting with the `A6`
/// control reference template and including the OCE `5F49` object. Amendment F
/// appends the card `5F49` object before applying AES-CMAC.
pub fn compute_mutual_authenticate_receipt(
    keys: &Scp11SessionKeys,
    command_data: &[u8],
    card_public: &[u8],
    out: &mut [u8; AES_CMAC_SIZE],
) -> crypto::CryptoResult<()> {
    if command_data.is_empty() || card_public.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }

    let card_public_header = [0x5F, 0x49, P256_PUBLIC_KEY_UNCOMPRESSED_SIZE as u8];
    let mac_key = AesKey::from_bytes(keys.receipt())?;
    crypto::aes_cmac_parts(
        &mac_key,
        &[command_data, &card_public_header, card_public],
        out,
    )
}

/// Derives SCP11c session keys from the two card-static ECDH contributions.
///
/// GlobalPlatform defines the KDF input secret as `ShSes || ShSss`: the
/// OCE-ephemeral/card-static result followed by the
/// OCE-static/card-static result.
pub fn derive_scp11c_session_keys(
    ephemeral_shared_secret: &[u8],
    static_shared_secret: &[u8],
    shared_info: &SharedInfo,
) -> crypto::CryptoResult<Scp11SessionKeys> {
    if ephemeral_shared_secret.len() != P256_SHARED_SECRET_SIZE
        || static_shared_secret.len() != P256_SHARED_SECRET_SIZE
    {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }

    let mut secret = [0u8; SCP11C_SHARED_SECRET_LEN];
    secret[..P256_SHARED_SECRET_SIZE].copy_from_slice(ephemeral_shared_secret);
    secret[P256_SHARED_SECRET_SIZE..].copy_from_slice(static_shared_secret);

    let mut info = [0u8; 3 + 1 + HOST_ID_CAPACITY + 1 + CARD_GROUP_ID_CAPACITY];
    let info_len = shared_info.write_kdf_input(&mut info)?;

    let mut derived = [0u8; SESSION_DERIVED_LEN];
    x963_sha256_kdf(&secret, &info[..info_len], &mut derived)?;
    Ok(session_keys_from_derived(&derived))
}

/// Derives SCP11a session keys from static and ephemeral ECDH contributions.
///
/// The caller provides the two already-computed P-256 shared secrets. This keeps
/// the function host-testable and lets the future kernel APDU path decide where
/// the static and ephemeral ECDH operations are performed without duplicating
/// KDF logic.
pub fn derive_scp11a_session_keys(
    ephemeral_shared_secret: &[u8],
    static_shared_secret: &[u8],
    shared_info: &Scp11aSharedInfo,
) -> crypto::CryptoResult<Scp11SessionKeys> {
    if static_shared_secret.len() != P256_SHARED_SECRET_SIZE
        || ephemeral_shared_secret.len() != P256_SHARED_SECRET_SIZE
    {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }

    // Invariant: SCP11a KDF input is ShSee || ShSss.
    let mut secret = [0u8; SCP11A_SHARED_SECRET_LEN];
    secret[..P256_SHARED_SECRET_SIZE].copy_from_slice(ephemeral_shared_secret);
    secret[P256_SHARED_SECRET_SIZE..].copy_from_slice(static_shared_secret);

    let mut info =
        [0u8; 3 + 1 + HOST_ID_CAPACITY + 1 + SCP11A_SIN_CAPACITY + 1 + SCP11A_SDIN_CAPACITY];
    let info_len = shared_info.write_kdf_input(&mut info)?;

    let mut derived = [0u8; SESSION_DERIVED_LEN];
    x963_sha256_kdf(&secret, &info[..info_len], &mut derived)?;
    Ok(session_keys_from_derived(&derived))
}

/// Derives SCP11b session keys from its two ECDH contributions.
///
/// SCP11b reuses the SCP11a SharedInfo shape but does not authenticate an OCE
/// static certificate through PSO. Its KDF secret is the ephemeral/ephemeral
/// contribution followed by the OCE-ephemeral/card-static contribution.
pub fn derive_scp11b_session_keys(
    ephemeral_shared_secret: &[u8],
    static_shared_secret: &[u8],
    shared_info: &Scp11aSharedInfo,
) -> crypto::CryptoResult<Scp11SessionKeys> {
    if static_shared_secret.len() != P256_SHARED_SECRET_SIZE
        || ephemeral_shared_secret.len() != P256_SHARED_SECRET_SIZE
    {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }

    let mut secret = [0u8; SCP11A_SHARED_SECRET_LEN];
    secret[..P256_SHARED_SECRET_SIZE].copy_from_slice(ephemeral_shared_secret);
    secret[P256_SHARED_SECRET_SIZE..].copy_from_slice(static_shared_secret);

    let mut info =
        [0u8; 3 + 1 + HOST_ID_CAPACITY + 1 + SCP11A_SIN_CAPACITY + 1 + SCP11A_SDIN_CAPACITY];
    let info_len = shared_info.write_kdf_input(&mut info)?;

    let mut derived = [0u8; SESSION_DERIVED_LEN];
    x963_sha256_kdf(&secret, &info[..info_len], &mut derived)?;
    Ok(session_keys_from_derived(&derived))
}

/// Encodes the SCP11c `MUTUAL AUTHENTICATE` response TLV.
pub fn encode_mutual_authenticate_response(
    card_public: &[u8],
    receipt: &[u8; AES_CMAC_SIZE],
    out: &mut [u8],
) -> crypto::CryptoResult<usize> {
    if card_public.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE
        || out.len() < MUTUAL_AUTHENTICATE_RESPONSE_LEN
    {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }
    let mut cursor = 0;
    out[cursor] = 0x5F;
    out[cursor + 1] = 0x49;
    out[cursor + 2] = P256_PUBLIC_KEY_UNCOMPRESSED_SIZE as u8;
    cursor += 3;
    out[cursor..cursor + P256_PUBLIC_KEY_UNCOMPRESSED_SIZE].copy_from_slice(card_public);
    cursor += P256_PUBLIC_KEY_UNCOMPRESSED_SIZE;
    out[cursor] = TAG_RECEIPT as u8;
    out[cursor + 1] = AES_CMAC_SIZE as u8;
    cursor += 2;
    out[cursor..cursor + AES_CMAC_SIZE].copy_from_slice(receipt);
    cursor += AES_CMAC_SIZE;
    Ok(cursor)
}

fn x963_sha256_kdf(
    shared_secret: &[u8],
    shared_info: &[u8],
    out: &mut [u8],
) -> crypto::CryptoResult<()> {
    crypto::x963_sha256_kdf(shared_secret, shared_info, out)
}

fn compute_chained_cmac_parts(
    key: &[u8; SESSION_KEY_LEN],
    chain: &[u8; AES_CMAC_SIZE],
    first: &[u8],
    second: &[u8],
) -> crypto::CryptoResult<[u8; AES_CMAC_SIZE]> {
    let aes_key = AesKey::from_bytes(key)?;
    let mut out = [0u8; AES_CMAC_SIZE];
    crypto::aes_cmac_parts(&aes_key, &[chain, first, second], &mut out)?;
    Ok(out)
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
) -> crypto::CryptoResult<[u8; AES_BLOCK_SIZE]> {
    *counter = counter
        .checked_add(1)
        .ok_or(crypto::CryptoError::InvalidBufferLength)?;
    let mut block = [0u8; AES_BLOCK_SIZE];
    block[0] = match direction {
        EncryptionDirection::Command => 0x11,
        EncryptionDirection::Response => 0x12,
    };
    block[12..16].copy_from_slice(&counter.to_be_bytes());
    crypto::aes_ecb_encrypt_in_place(key, &mut block)?;
    Ok(block)
}

fn copy_to_output(data: &[u8], out: &mut [u8]) -> crypto::CryptoResult<usize> {
    if data.len() > out.len() {
        return Err(crypto::CryptoError::InvalidBufferLength);
    }
    out[..data.len()].copy_from_slice(data);
    Ok(data.len())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    let mut index = 0;
    while index < left.len() {
        diff |= left[index] ^ right[index];
        index += 1;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn encode_short_tlv(tag: &[u8], value: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(tag);
        out.push(value.len() as u8);
        out.extend_from_slice(value);
    }

    fn encode_mutual_authenticate_crt(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut crt = Vec::new();
        let mut ephemeral_public = None;
        for (tag, value) in fields {
            if *tag == [0x5F, 0x49] {
                ephemeral_public = Some(*value);
            } else {
                encode_short_tlv(tag, value, &mut crt);
            }
        }
        let mut request = Vec::new();
        encode_short_tlv(&[0xA6], &crt, &mut request);
        if let Some(public) = ephemeral_public {
            encode_short_tlv(&[0x5F, 0x49], public, &mut request);
        }
        request
    }

    fn supported_mutual_authenticate_request_for_profile(profile: Scp11Profile) -> Vec<u8> {
        let param = match profile {
            Scp11Profile::A => SCP11A_IDENTIFIER_PARAM,
            Scp11Profile::B => SCP11B_IDENTIFIER_PARAM,
            Scp11Profile::C => SCP11C_IDENTIFIER_PARAM,
        };
        let host_public = [0x04; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
        encode_mutual_authenticate_crt(&[
            (&[0x90], &[SCP11_IDENTIFIER_FAMILY, param]),
            (&[0x95], &[KEY_USAGE_FULL]),
            (&[0x80], &[KEY_TYPE_AES]),
            (&[0x81], &[KEY_LENGTH_AES_128]),
            (&[0x84], b"host"),
            (&[0x5F, 0x49], &host_public),
        ])
    }

    #[test]
    fn scp11_profile_policies_distinguish_a_b_and_c() {
        let scp11a = Scp11Profile::A.establishment_policy();
        assert_eq!(
            scp11a.host_authentication,
            Scp11HostAuthentication::Certificate
        );
        assert!(scp11a.requires_pso_certificate);
        assert!(scp11a.mutual_authenticate_supported);

        let scp11b = Scp11Profile::B.establishment_policy();
        assert_eq!(scp11b.host_authentication, Scp11HostAuthentication::None);
        assert!(!scp11b.requires_pso_certificate);
        assert!(scp11b.mutual_authenticate_supported);

        let scp11c = Scp11Profile::C.establishment_policy();
        assert_eq!(
            scp11c.host_authentication,
            Scp11HostAuthentication::Certificate
        );
        assert!(scp11c.requires_pso_certificate);
        assert!(scp11c.mutual_authenticate_supported);
    }

    #[test]
    fn gp_and_selected_key_usage_matrices_are_explicit() {
        for profile in [Scp11Profile::A, Scp11Profile::B, Scp11Profile::C] {
            for qualifier in 0u8..=u8::MAX {
                let gp_defined = match profile {
                    Scp11Profile::A | Scp11Profile::B => {
                        matches!(qualifier, KEY_USAGE_MACS | KEY_USAGE_FULL)
                    }
                    Scp11Profile::C => matches!(
                        qualifier,
                        KEY_USAGE_MACS
                            | KEY_USAGE_FULL
                            | KEY_USAGE_COMMAND_ONLY
                            | KEY_USAGE_COMMAND_ENC_RESPONSE_MAC
                    ),
                };
                assert_eq!(is_gp_key_usage_qualifier(profile, qualifier), gp_defined);
                assert_eq!(
                    is_selected_key_usage_qualifier(profile, qualifier),
                    qualifier == KEY_USAGE_FULL
                );
            }
        }
    }

    #[test]
    fn profile_parser_entry_points_accept_supported_scp11_crts() {
        for profile in [Scp11Profile::A, Scp11Profile::B, Scp11Profile::C] {
            let request = supported_mutual_authenticate_request_for_profile(profile);
            assert!(parse_mutual_authenticate_request_for_profile(profile, &request).is_ok());
            assert_eq!(detect_mutual_authenticate_profile(&request), Ok(profile));
        }
    }

    #[test]
    fn profile_parser_entry_points_reject_mismatched_scp11_identifier() {
        let scp11a = supported_mutual_authenticate_request_for_profile(Scp11Profile::A);
        assert!(parse_mutual_authenticate_request_for_profile(Scp11Profile::C, &scp11a).is_err());
    }

    #[test]
    fn scp11_identifier_requires_host_id_exactly_when_b3_is_set() {
        let host_public = [0x04; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
        let missing_host_id = encode_mutual_authenticate_crt(&[
            (&[0x90], &[SCP11_IDENTIFIER_FAMILY, SCP11C_IDENTIFIER_PARAM]),
            (&[0x95], &[KEY_USAGE_FULL]),
            (&[0x80], &[KEY_TYPE_AES]),
            (&[0x81], &[KEY_LENGTH_AES_128]),
            (&[0x5F, 0x49], &host_public),
        ]);
        assert!(parse_mutual_authenticate_request(&missing_host_id).is_err());

        let unexpected_host_id = encode_mutual_authenticate_crt(&[
            (&[0x90], &[SCP11_IDENTIFIER_FAMILY, 0x03]),
            (&[0x95], &[KEY_USAGE_FULL]),
            (&[0x80], &[KEY_TYPE_AES]),
            (&[0x81], &[KEY_LENGTH_AES_128]),
            (&[0x84], b"host"),
            (&[0x5F, 0x49], &host_public),
        ]);
        assert!(parse_mutual_authenticate_request(&unexpected_host_id).is_err());

        let identifiers_omitted = encode_mutual_authenticate_crt(&[
            (&[0x90], &[SCP11_IDENTIFIER_FAMILY, 0x03]),
            (&[0x95], &[KEY_USAGE_FULL]),
            (&[0x80], &[KEY_TYPE_AES]),
            (&[0x81], &[KEY_LENGTH_AES_128]),
            (&[0x5F, 0x49], &host_public),
        ]);
        let parsed = parse_mutual_authenticate_request(&identifiers_omitted).unwrap();
        assert!(!parsed.parameters.include_identifiers);
        assert!(parsed.host_id.is_empty());
    }

    #[test]
    fn scp11_identifier_rejects_rfu_bits_and_host_supplied_card_identity() {
        let host_public = [0x04; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
        let rfu_parameter = encode_mutual_authenticate_crt(&[
            (&[0x90], &[SCP11_IDENTIFIER_FAMILY, 0x87]),
            (&[0x95], &[KEY_USAGE_FULL]),
            (&[0x80], &[KEY_TYPE_AES]),
            (&[0x81], &[KEY_LENGTH_AES_128]),
            (&[0x84], b"host"),
            (&[0x5F, 0x49], &host_public),
        ]);
        assert!(parse_mutual_authenticate_request(&rfu_parameter).is_err());

        let host_supplied_card_group = encode_mutual_authenticate_crt(&[
            (&[0x90], &[SCP11_IDENTIFIER_FAMILY, SCP11C_IDENTIFIER_PARAM]),
            (&[0x95], &[KEY_USAGE_FULL]),
            (&[0x80], &[KEY_TYPE_AES]),
            (&[0x81], &[KEY_LENGTH_AES_128]),
            (&[0x84], b"host"),
            (&[0x85], b"card"),
            (&[0x5F, 0x49], &host_public),
        ]);
        assert!(parse_mutual_authenticate_request(&host_supplied_card_group).is_err());
    }

    #[test]
    fn scp11a_shared_info_rejects_oversized_identifiers() {
        let too_long_host_id = [0xA5; HOST_ID_CAPACITY + 1];
        assert!(Scp11aSharedInfo::new(
            KEY_USAGE_FULL,
            KEY_TYPE_AES,
            KEY_LENGTH_AES_128,
            &too_long_host_id,
            b"sin",
            b"sdin",
        )
        .is_err());

        let too_long_sin = [0xA5; SCP11A_SIN_CAPACITY + 1];
        assert!(Scp11aSharedInfo::new(
            KEY_USAGE_FULL,
            KEY_TYPE_AES,
            KEY_LENGTH_AES_128,
            b"host",
            &too_long_sin,
            b"sdin",
        )
        .is_err());

        let too_long_sdin = [0xA5; SCP11A_SDIN_CAPACITY + 1];
        assert!(Scp11aSharedInfo::new(
            KEY_USAGE_FULL,
            KEY_TYPE_AES,
            KEY_LENGTH_AES_128,
            b"host",
            b"sin",
            &too_long_sdin,
        )
        .is_err());
    }

    #[test]
    fn scp11a_session_derivation_uses_static_and_ephemeral_contributions() {
        let static_shared = [0xA1; P256_SHARED_SECRET_SIZE];
        let ephemeral_shared = [0xB2; P256_SHARED_SECRET_SIZE];
        let changed_static = [0xC3; P256_SHARED_SECRET_SIZE];
        let changed_ephemeral = [0xD4; P256_SHARED_SECRET_SIZE];
        let shared_info = Scp11aSharedInfo::new(
            KEY_USAGE_FULL,
            KEY_TYPE_AES,
            KEY_LENGTH_AES_128,
            b"host",
            b"sin",
            b"sdin",
        )
        .unwrap();

        let baseline =
            derive_scp11a_session_keys(&ephemeral_shared, &static_shared, &shared_info).unwrap();
        let changed_static_keys =
            derive_scp11a_session_keys(&ephemeral_shared, &changed_static, &shared_info).unwrap();
        let changed_ephemeral_keys =
            derive_scp11a_session_keys(&changed_ephemeral, &static_shared, &shared_info).unwrap();

        assert_ne!(baseline, changed_static_keys);
        assert_ne!(baseline, changed_ephemeral_keys);
        assert_ne!(baseline.enc(), baseline.mac());
        assert_ne!(baseline.mac(), baseline.rmac());
    }

    #[test]
    fn scp11a_session_derivation_rejects_short_shared_secret() {
        let short_shared = [0xA1; P256_SHARED_SECRET_SIZE - 1];
        let valid_shared = [0xB2; P256_SHARED_SECRET_SIZE];
        let shared_info = Scp11aSharedInfo::new(
            KEY_USAGE_FULL,
            KEY_TYPE_AES,
            KEY_LENGTH_AES_128,
            b"host",
            b"sin",
            b"sdin",
        )
        .unwrap();

        assert!(derive_scp11a_session_keys(&short_shared, &valid_shared, &shared_info).is_err());
    }

    #[test]
    fn scp11a_and_scp11b_derivation_use_ephemeral_then_static_contribution() {
        let static_shared = [0xA1; P256_SHARED_SECRET_SIZE];
        let ephemeral_shared = [0xB2; P256_SHARED_SECRET_SIZE];
        let shared_info = Scp11aSharedInfo::new(
            KEY_USAGE_FULL,
            KEY_TYPE_AES,
            KEY_LENGTH_AES_128,
            b"host",
            b"sin",
            b"sdin",
        )
        .unwrap();

        let scp11a_order =
            derive_scp11a_session_keys(&ephemeral_shared, &static_shared, &shared_info).unwrap();
        let scp11b_order =
            derive_scp11b_session_keys(&ephemeral_shared, &static_shared, &shared_info).unwrap();

        assert_eq!(scp11a_order, scp11b_order);
        assert_ne!(scp11b_order.enc(), scp11b_order.mac());
        assert_ne!(scp11b_order.mac(), scp11b_order.rmac());
    }

    #[test]
    fn scp11c_session_derivation_uses_both_card_static_contributions() {
        let ephemeral_shared = [0xA5; P256_SHARED_SECRET_SIZE];
        let static_shared = [0x5A; P256_SHARED_SECRET_SIZE];
        let host = [0x04; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
        let request = MutualAuthenticateRequest {
            parameters: Scp11Parameters {
                profile: Scp11Profile::C,
                include_identifiers: true,
            },
            key_usage_qualifier: KEY_USAGE_FULL,
            key_type: KEY_TYPE_AES,
            key_length: KEY_LENGTH_AES_128,
            host_id: b"host",
            host_ephemeral_public: &host,
        };
        let shared_info = SharedInfo::new(&request, b"card").unwrap();
        let keys =
            derive_scp11c_session_keys(&ephemeral_shared, &static_shared, &shared_info).unwrap();
        let changed_ephemeral = derive_scp11c_session_keys(
            &[0xA4; P256_SHARED_SECRET_SIZE],
            &static_shared,
            &shared_info,
        )
        .unwrap();
        let changed_static = derive_scp11c_session_keys(
            &ephemeral_shared,
            &[0x5B; P256_SHARED_SECRET_SIZE],
            &shared_info,
        )
        .unwrap();
        assert_ne!(keys.enc(), keys.mac());
        assert_ne!(keys.enc(), keys.rmac());
        assert_ne!(keys.mac(), keys.rmac());
        assert_ne!(keys.rmac(), keys.dek());
        assert_ne!(keys.dek(), keys.receipt());
        assert_ne!(keys, changed_ephemeral);
        assert_ne!(keys, changed_static);
    }

    #[test]
    fn mutual_authentication_receipt_is_stable_for_same_inputs() {
        let ephemeral_shared = [0xA5; P256_SHARED_SECRET_SIZE];
        let static_shared = [0x5A; P256_SHARED_SECRET_SIZE];
        let host = [0x04; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
        let card = [0x05; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
        let request = MutualAuthenticateRequest {
            parameters: Scp11Parameters {
                profile: Scp11Profile::C,
                include_identifiers: true,
            },
            key_usage_qualifier: KEY_USAGE_FULL,
            key_type: KEY_TYPE_AES,
            key_length: KEY_LENGTH_AES_128,
            host_id: b"host",
            host_ephemeral_public: &host,
        };
        let shared_info = SharedInfo::new(&request, b"card").unwrap();
        let keys =
            derive_scp11c_session_keys(&ephemeral_shared, &static_shared, &shared_info).unwrap();
        let command_data = supported_mutual_authenticate_request_for_profile(Scp11Profile::C);
        let mut left = [0u8; AES_CMAC_SIZE];
        let mut right = [0u8; AES_CMAC_SIZE];
        compute_mutual_authenticate_receipt(&keys, &command_data, &card, &mut left).unwrap();
        compute_mutual_authenticate_receipt(&keys, &command_data, &card, &mut right).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn mac_only_secure_messaging_verifies_and_wraps() {
        let keys = Scp11SessionKeys {
            enc: [0x10; SESSION_KEY_LEN],
            mac: [0x20; SESSION_KEY_LEN],
            rmac: [0x30; SESSION_KEY_LEN],
            dek: [0x40; SESSION_KEY_LEN],
            receipt: [0x50; SESSION_KEY_LEN],
        };
        let authenticated = [0x84, 0xca, 0x9f, 0x70, MAC_LEN as u8];
        let receipt = [0xA5; AES_CMAC_SIZE];
        let sender = Scp11SessionState::new(keys, receipt);
        let command_mac = sender.compute_command_mac(&authenticated).unwrap();

        let mut receiver = Scp11SessionState::new(keys, receipt);
        let mut out = [0u8; TRANSFORM_CAPACITY];
        assert_eq!(
            receiver
                .unwrap_command(&authenticated, &[], &command_mac, &mut out)
                .unwrap(),
            0
        );

        let response_iv = next_encryption_iv(
            &AesKey::from_bytes(keys.enc()).unwrap(),
            &mut 0,
            EncryptionDirection::Response,
        )
        .unwrap();
        let mut expected_encrypted = [0u8; TRANSFORM_CAPACITY];
        let expected_len = crypto::aes_cbc_encrypt_iso9797_m2(
            &AesKey::from_bytes(keys.enc()).unwrap(),
            &response_iv,
            &[0x9f, 0x70, 0x01, 0x07],
            &mut expected_encrypted,
        )
        .unwrap();

        let mut response = [0u8; TRANSFORM_CAPACITY];
        let mut response_mac = [0u8; MAC_LEN];
        let lengths = receiver
            .wrap_response(
                &[0x9f, 0x70, 0x01, 0x07],
                (0x90, 0x00),
                &mut response,
                &mut response_mac,
            )
            .unwrap();
        assert_eq!(lengths.data_len, expected_len);
        assert_eq!(lengths.mac_len, MAC_LEN);
        assert_eq!(
            &response[..lengths.data_len],
            &expected_encrypted[..expected_len]
        );
        assert_ne!(response_mac, [0; MAC_LEN]);
    }

    #[test]
    fn secure_messaging_replay_and_bounds_do_not_advance_session_state() {
        let keys = Scp11SessionKeys {
            enc: [0x10; SESSION_KEY_LEN],
            mac: [0x20; SESSION_KEY_LEN],
            rmac: [0x30; SESSION_KEY_LEN],
            dek: [0x40; SESSION_KEY_LEN],
            receipt: [0x50; SESSION_KEY_LEN],
        };
        let authenticated = [0x84, 0xca, 0x9f, 0x70, MAC_LEN as u8];
        let receipt = [0xA5; AES_CMAC_SIZE];
        let mut receiver = Scp11SessionState::new(keys, receipt);
        let command_mac = receiver.compute_command_mac(&authenticated).unwrap();
        let mut out = [0u8; TRANSFORM_CAPACITY];

        assert_eq!(
            receiver.unwrap_command(&authenticated, &[], &command_mac, &mut out),
            Ok(0)
        );
        let accepted = receiver;
        assert_eq!(
            receiver.unwrap_command(&authenticated, &[], &command_mac, &mut out),
            Err(crypto::CryptoError::InvalidBufferLength)
        );
        assert_eq!(receiver, accepted);

        let data_header = [0x84, 0xe2, 0x00, 0x00, (1 + MAC_LEN) as u8];
        let mut bounded = Scp11SessionState::new(keys, receipt);
        let data_mac = bounded.compute_command_mac(&data_header).unwrap();
        let before_command = bounded;
        assert_eq!(
            bounded.unwrap_command(&data_header, &[0x5A], &data_mac, &mut []),
            Err(crypto::CryptoError::InvalidOutputLength)
        );
        assert_eq!(bounded, before_command);

        let before_response = bounded;
        assert_eq!(
            bounded.wrap_response(&[0x5A], (0x90, 0x00), &mut [0u8; AES_BLOCK_SIZE], &mut [],),
            Err(crypto::CryptoError::InvalidBufferLength)
        );
        assert_eq!(bounded, before_response);
    }

    #[test]
    fn vectored_command_mac_matches_contiguous_command_mac() {
        let keys = Scp11SessionKeys {
            enc: [0x10; SESSION_KEY_LEN],
            mac: [0x20; SESSION_KEY_LEN],
            rmac: [0x30; SESSION_KEY_LEN],
            dek: [0x40; SESSION_KEY_LEN],
            receipt: [0x50; SESSION_KEY_LEN],
        };
        let header = [0x84, 0xca, 0x9f, 0x70, MAC_LEN as u8 + 3];
        let data_objects = [0x97, 0x01, 0x00];
        let mut contiguous = [0u8; 8];
        contiguous[..header.len()].copy_from_slice(&header);
        contiguous[header.len()..].copy_from_slice(&data_objects);
        let receipt = [0xA5; AES_CMAC_SIZE];
        let sender = Scp11SessionState::new(keys, receipt);
        let command_mac = sender.compute_command_mac(&contiguous).unwrap();

        let mut receiver = Scp11SessionState::new(keys, receipt);
        let mut out = [0u8; TRANSFORM_CAPACITY];
        assert_eq!(
            receiver
                .unwrap_command_parts(&header, &data_objects, &[], &command_mac, &mut out)
                .unwrap(),
            0
        );
    }

    #[test]
    fn mutual_authenticate_request_rejects_duplicate_key_type() {
        let host_public = [0x04; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
        let request = encode_mutual_authenticate_crt(&[
            (&[0x90], &[KEY_USAGE_FULL]),
            (&[0x95], &[KEY_TYPE_AES]),
            (&[0x95], &[KEY_TYPE_AES]),
            (&[0x80], &[KEY_LENGTH_AES_128]),
            (&[0x81], b"host"),
            (&[0x5F, 0x49], &host_public),
        ]);
        assert!(parse_mutual_authenticate_request(&request).is_err());
    }

    #[test]
    fn mutual_authenticate_request_rejects_malformed_ephemeral_public_key() {
        let malformed_public = [0x04; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE - 1];
        let request = encode_mutual_authenticate_crt(&[
            (&[0x90], &[KEY_USAGE_FULL]),
            (&[0x95], &[KEY_TYPE_AES]),
            (&[0x80], &[KEY_LENGTH_AES_128]),
            (&[0x81], b"host"),
            (&[0x5F, 0x49], &malformed_public),
        ]);
        assert!(parse_mutual_authenticate_request(&request).is_err());
    }
}
