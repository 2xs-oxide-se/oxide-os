#![no_std]
#![no_main]

use rustlet_runtime::{
    declare_security_domain, Aid, Algorithm, Apdu, ApduStatus, Cipher, CipherMode, EcCurve,
    EcKeyPair, EcPrivateKey, KeyAgreement, Mac, MacAlgorithm, RandomAlgorithm, RandomData, Rustlet,
    RustletCtx, RustletSecurityDomain, SecurityLevel, Uninitialized,
};

declare_security_domain!(CompleteSecurityDomain);

const COMPLETE_SECURITY_DOMAIN_AID: Aid =
    Aid::from_array([0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x06]);
const SCP03_MAX_CHALLENGE_LEN: usize = 16;
const SCP03_MAX_CRYPTOGRAM_LEN: usize = 16;
const SCP03_S8_CHALLENGE_LEN: usize = 8;
const SCP03_S8_CRYPTOGRAM_LEN: usize = 8;
const SCP03_S8_MAC_LEN: usize = 8;
const SCP03_S16_CHALLENGE_LEN: usize = 16;
const SCP03_S16_CRYPTOGRAM_LEN: usize = 16;
const SCP03_S16_MAC_LEN: usize = 16;
const SCP03_DEFAULT_KEY_VERSION: u8 = 0x01;
const SCP03_KEY_USAGE_ENC: u8 = 0x01;
const SCP03_KEY_USAGE_MAC: u8 = 0x02;
const SCP03_KDF_CARD_CRYPTOGRAM: u8 = 0x00;
const SCP03_KDF_HOST_CRYPTOGRAM: u8 = 0x01;
const SCP03_KDF_S_ENC: u8 = 0x04;
const SCP03_KDF_S_MAC: u8 = 0x06;
const SCP03_KDF_S_RMAC: u8 = 0x07;
const SCP03_STATE_INACTIVE: u8 = 0;
const SCP03_STATE_INITIALIZED: u8 = 1;
const SCP03_STATE_AUTHENTICATED: u8 = 2;
const SCP11_STATE_INACTIVE: u8 = 0;
const SCP11_STATE_STAGED: u8 = 1;
const SCP11_STATE_AUTHENTICATED: u8 = 2;
const SCP03_PROFILE_S8: u8 = 1;
const SCP03_PROFILE_S16: u8 = 2;
const SCP03_DIRECTION_COMMAND: u8 = 0x01;
const SCP03_DIRECTION_RESPONSE: u8 = 0x02;
const SCP11_DIRECTION_COMMAND: u8 = 0x11;
const SCP11_DIRECTION_RESPONSE: u8 = 0x12;
const SCP11_KEY_USAGE_FULL: u8 = 0x3C;
const SCP11_KEY_TYPE_AES: u8 = 0x88;
const SCP11_KEY_LENGTH_AES_128: u8 = 0x10;
const OXIDE_SE_SCP11_HOST_ID: &[u8] = b"oxide-se-host";
const OXIDE_SE_SCP11_SIN: &[u8] = b"oxide-se-sin";
const OXIDE_SE_SCP11_SDIN: &[u8] = b"oxide-se-sdin";
const OXIDE_SE_SCP11_CARD_GROUP_ID: &[u8] = b"oxide-se-card";
const SCP11_IDENTIFIER_FAMILY: u8 = 0x11;
const SCP11A_IDENTIFIER_PARAM: u8 = 0x05;
const SCP11B_IDENTIFIER_PARAM: u8 = 0x04;
const SCP11C_IDENTIFIER_PARAM: u8 = 0x07;
const SCP11_ECKA_KEY_VERSION: u8 = 0x00;
const SCP11_ECKA_KEY_ID: u8 = 0x01;
const SCP11_CA_KEY_VERSION: u8 = 0x00;
const SCP11_CA_KEY_ID: u8 = 0x00;
const SCP11_SESSION_KEY_LEN: usize = 16;
const SCP11_DERIVED_LEN: usize = SCP11_SESSION_KEY_LEN * 5;
const SCP11_RECEIPT_INPUT_CAPACITY: usize = 256;
const P256_PRIVATE_KEY_LEN: usize = 32;
const P256_PUBLIC_KEY_LEN: usize = 65;
const P256_SHARED_SECRET_LEN: usize = 32;
const SCP11_DEV_CARD_STATIC_PRIVATE_KEY: [u8; P256_PRIVATE_KEY_LEN] = [
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
];
const SCP11_DEV_CARD_STATIC_PUBLIC_KEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0x8A, 0xB5, 0x47, 0xC6, 0x0E, 0x31, 0xC0, 0x03, 0x21, 0x15, 0xC8, 0x95, 0xDD, 0xEE, 0xD6,
    0xD8, 0x31, 0x9B, 0x5D, 0xA6, 0x2E, 0x4A, 0x92, 0xDE, 0xD1, 0xDF, 0x03, 0xA8, 0x79, 0xB1, 0x90,
    0xCD, 0xC5, 0x01, 0xAA, 0xFA, 0x10, 0xC3, 0xD2, 0xCF, 0x45, 0x66, 0xC6, 0xC5, 0x36, 0x67, 0xB9,
    0x62, 0x6D, 0x12, 0xE9, 0x7E, 0xD2, 0x29, 0xCE, 0x90, 0xB8, 0xCA, 0x29, 0xA0, 0x64, 0x27, 0xDD,
    0x58,
];

/// Full user-land Security Domain used by the integration test suite.
///
/// It exercises the full Rustlet-side SCP03 path: session bootstrap, secure
/// messaging, `PUT KEY`, and protected `INSTALL`.
#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct CompleteSecurityDomain {
    /// Session material is deliberately absent from the Postcard state.
    ///
    /// The runtime wrapper persists lifecycle and privileges separately. This
    /// example currently has no additional application-owned persistent data.
    #[serde(skip)]
    secure_channel: VolatileSecureChannelState,
}

/// RAM-only state of an active SCP03 or SCP11 session.
///
/// This value remains live while the Security Domain is loaded, but returns to
/// `Default` after unload/reload. `reset_secure_channel()` still clears it
/// explicitly so session termination does not depend on unloading the Rustlet.
#[derive(Default)]
struct VolatileSecureChannelState {
    scp03_state: u8,
    scp03_profile: u8,
    scp03_security_level_bits: u8,
    scp03_expected_host_cryptogram: [u8; SCP03_MAX_CRYPTOGRAM_LEN],
    scp03_session_enc_key: [u8; 16],
    scp03_session_mac_key: [u8; 16],
    scp03_session_rmac_key: [u8; 16],
    scp03_command_mac_chain: [u8; 16],
    scp03_response_mac_chain: [u8; 16],
    scp03_command_enc_counter: u32,
    scp03_response_enc_counter: u32,
    scp11a_state: u8,
    scp11a_storage0: [u8; 32],
    scp11a_storage1: [u8; 32],
    scp11a_storage2: [u8; 32],
    scp11a_storage3: [u8; 32],
    scp11a_command_enc_counter: u32,
    scp11a_response_enc_counter: u32,
}

impl Rustlet for CompleteSecurityDomain {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);
        if apdu.is_select() {
            return self.handle_select(apdu);
        }

        let header = apdu.header();
        if header.cla == 0x80 {
            return match header.ins {
                0xE6 => self.handle_install(apdu),
                0xCA => self.handle_get_data(apdu),
                _ => apdu.reject(ApduStatus::instruction_not_supported()),
            };
        }

        match apdu.ins() {
            0x00 => apdu.accept(),
            0x02 => {
                let rx = apdu.as_receiving();
                let mut echo = [0u8; 16];
                let incoming_len = rx.data().len();
                if incoming_len > echo.len() {
                    return rx.reject(ApduStatus::wrong_length());
                }
                echo[..incoming_len].copy_from_slice(rx.data());
                rx.accept_and_send(&echo[..incoming_len])
            }
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}

impl RustletSecurityDomain for CompleteSecurityDomain {
    fn supports_scp03(&self) -> bool {
        true
    }

    fn supports_scp11a(&self) -> bool {
        true
    }

    fn supports_scp11b(&self) -> bool {
        true
    }

    fn supports_scp11c(&self) -> bool {
        true
    }

    fn claims_delegated_secure_channel_command(
        &self,
        header: rustlet_runtime::DelegatedSecureChannelHeader,
    ) -> bool {
        matches!(
            (header.cla, header.ins, header.p2),
            (0x80, 0x50, _) | (0x84, 0x82, 0x00)
        )
    }

    fn scp11_stage_oce_certificate(
        &mut self,
        _ctx: &mut RustletCtx,
        certificate: &rustlet_runtime::Scp11OceCertificate<'_>,
    ) -> Result<(), ApduStatus> {
        if certificate.ca_key_version != SCP11_CA_KEY_VERSION
            || certificate.ca_key_id != SCP11_CA_KEY_ID
        {
            return Err(ApduStatus::referenced_data_not_found());
        }
        if certificate.public_key.len() != P256_PUBLIC_KEY_LEN {
            return Err(ApduStatus::wrong_data());
        }
        self.clear_scp11_state();
        self.secure_channel
            .scp11a_storage0
            .copy_from_slice(&certificate.public_key[1..33]);
        self.secure_channel
            .scp11a_storage1
            .copy_from_slice(&certificate.public_key[33..65]);
        self.secure_channel.scp11a_state = SCP11_STATE_STAGED;
        Ok(())
    }

    fn scp11a_mutual_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &rustlet_runtime::Scp11aMutualAuthenticate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        if self.secure_channel.scp11a_state != SCP11_STATE_STAGED {
            return Err(ApduStatus::conditions_not_satisfied());
        }
        if command.ecka_key_version != SCP11_ECKA_KEY_VERSION
            || command.ecka_key_id != SCP11_ECKA_KEY_ID
        {
            return Err(ApduStatus::referenced_data_not_found());
        }
        if command.key_usage_qualifier != SCP11_KEY_USAGE_FULL
            || command.key_type != SCP11_KEY_TYPE_AES
            || command.key_length != SCP11_KEY_LENGTH_AES_128
            || (command.include_identifiers && command.host_id != OXIDE_SE_SCP11_HOST_ID)
            || (!command.include_identifiers && !command.host_id.is_empty())
            || command.host_ephemeral_public.len() != P256_PUBLIC_KEY_LEN
        {
            return Err(ApduStatus::wrong_data());
        }
        let scratch_len = 2 * P256_SHARED_SECRET_LEN
            + 3
            + 1
            + command.host_id.len()
            + 1
            + if command.include_identifiers {
                OXIDE_SE_SCP11_SIN.len()
            } else {
                0
            }
            + 1
            + if command.include_identifiers {
                OXIDE_SE_SCP11_SDIN.len()
            } else {
                0
            };
        if out.len() < 86 || out.len() < scratch_len {
            return Err(ApduStatus::wrong_length());
        }

        let card_ephemeral = {
            let mut provider = ctx.crypto();
            EcKeyPair::generate(&mut provider, EcCurve::P256).map_err(crypto_error_to_status)?
        };
        let card_ephemeral_public = *card_ephemeral.public_key().as_bytes();
        {
            let mut provider = ctx.crypto();
            let card_static_private =
                EcPrivateKey::p256_from_bytes(SCP11_DEV_CARD_STATIC_PRIVATE_KEY);
            let (shared_scratch, tail) = out.split_at_mut(P256_SHARED_SECRET_LEN * 2);
            tail[0] = 0x04;
            tail[1..33].copy_from_slice(&self.secure_channel.scp11a_storage0);
            tail[33..65].copy_from_slice(&self.secure_channel.scp11a_storage1);
            KeyAgreement::new(&mut provider)
                .init(&card_static_private)
                .map_err(crypto_error_to_status)?
                .generate_secret(
                    &tail[..P256_PUBLIC_KEY_LEN],
                    &mut shared_scratch[P256_SHARED_SECRET_LEN..],
                )
                .map_err(crypto_error_to_status)?;
        }
        {
            let mut provider = ctx.crypto();
            KeyAgreement::new(&mut provider)
                .init(&card_ephemeral.private_key())
                .map_err(crypto_error_to_status)?
                .generate_secret(
                    command.host_ephemeral_public,
                    &mut out[..P256_SHARED_SECRET_LEN],
                )
                .map_err(crypto_error_to_status)?;
        }

        let mut info_len = 0usize;
        let info_offset = P256_SHARED_SECRET_LEN * 2;
        out[info_offset + info_len] = command.key_usage_qualifier;
        out[info_offset + info_len + 1] = command.key_type;
        out[info_offset + info_len + 2] = command.key_length;
        info_len += 3;
        out[info_offset + info_len] = command.host_id.len() as u8;
        info_len += 1;
        out[info_offset + info_len..info_offset + info_len + command.host_id.len()]
            .copy_from_slice(command.host_id);
        info_len += command.host_id.len();
        let sin = if command.include_identifiers {
            OXIDE_SE_SCP11_SIN
        } else {
            &[]
        };
        out[info_offset + info_len] = sin.len() as u8;
        info_len += 1;
        out[info_offset + info_len..info_offset + info_len + sin.len()].copy_from_slice(sin);
        info_len += sin.len();
        let sdin = if command.include_identifiers {
            OXIDE_SE_SCP11_SDIN
        } else {
            &[]
        };
        out[info_offset + info_len] = sdin.len() as u8;
        info_len += 1;
        out[info_offset + info_len..info_offset + info_len + sdin.len()].copy_from_slice(sdin);
        info_len += sdin.len();
        self.finish_scp11_mutual_authenticate(
            ctx,
            P256_SHARED_SECRET_LEN * 2,
            info_offset,
            info_len,
            SCP11A_IDENTIFIER_PARAM,
            command.include_identifiers,
            command.key_usage_qualifier,
            command.key_type,
            command.key_length,
            command.host_id,
            command.host_ephemeral_public,
            &card_ephemeral_public,
            out,
        )
    }

    fn scp11c_mutual_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &rustlet_runtime::Scp11cMutualAuthenticate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        if self.secure_channel.scp11a_state != SCP11_STATE_STAGED {
            return Err(ApduStatus::conditions_not_satisfied());
        }
        if command.ecka_key_version != SCP11_ECKA_KEY_VERSION
            || command.ecka_key_id != SCP11_ECKA_KEY_ID
        {
            return Err(ApduStatus::referenced_data_not_found());
        }
        if command.key_usage_qualifier != SCP11_KEY_USAGE_FULL
            || command.key_type != SCP11_KEY_TYPE_AES
            || command.key_length != SCP11_KEY_LENGTH_AES_128
            || (command.include_identifiers && command.host_id != OXIDE_SE_SCP11_HOST_ID)
            || (!command.include_identifiers && !command.host_id.is_empty())
            || command.host_ephemeral_public.len() != P256_PUBLIC_KEY_LEN
        {
            return Err(ApduStatus::wrong_data());
        }
        let scratch_len = 2 * P256_SHARED_SECRET_LEN
            + 3
            + 1
            + command.host_id.len()
            + 1
            + if command.include_identifiers {
                OXIDE_SE_SCP11_CARD_GROUP_ID.len()
            } else {
                0
            };
        if out.len() < 86 || out.len() < scratch_len {
            return Err(ApduStatus::wrong_length());
        }

        // Invariant: SCP11c concatenates ShSes then ShSss and never creates a
        // card-ephemeral key pair.
        {
            let mut provider = ctx.crypto();
            let card_static_private =
                EcPrivateKey::p256_from_bytes(SCP11_DEV_CARD_STATIC_PRIVATE_KEY);
            KeyAgreement::new(&mut provider)
                .init(&card_static_private)
                .map_err(crypto_error_to_status)?
                .generate_secret(
                    command.host_ephemeral_public,
                    &mut out[..P256_SHARED_SECRET_LEN],
                )
                .map_err(crypto_error_to_status)?;
        }
        out[2 * P256_SHARED_SECRET_LEN] = 0x04;
        out[2 * P256_SHARED_SECRET_LEN + 1..2 * P256_SHARED_SECRET_LEN + 33]
            .copy_from_slice(&self.secure_channel.scp11a_storage0);
        out[2 * P256_SHARED_SECRET_LEN + 33..2 * P256_SHARED_SECRET_LEN + 65]
            .copy_from_slice(&self.secure_channel.scp11a_storage1);
        {
            let mut provider = ctx.crypto();
            let card_static_private =
                EcPrivateKey::p256_from_bytes(SCP11_DEV_CARD_STATIC_PRIVATE_KEY);
            let (secret_scratch, public_scratch) = out.split_at_mut(2 * P256_SHARED_SECRET_LEN);
            KeyAgreement::new(&mut provider)
                .init(&card_static_private)
                .map_err(crypto_error_to_status)?
                .generate_secret(
                    &public_scratch[..P256_PUBLIC_KEY_LEN],
                    &mut secret_scratch[P256_SHARED_SECRET_LEN..],
                )
                .map_err(crypto_error_to_status)?;
        }

        let mut info_len = 0usize;
        let info_offset = P256_SHARED_SECRET_LEN * 2;
        out[info_offset + info_len] = command.key_usage_qualifier;
        out[info_offset + info_len + 1] = command.key_type;
        out[info_offset + info_len + 2] = command.key_length;
        info_len += 3;
        out[info_offset + info_len] = command.host_id.len() as u8;
        info_len += 1;
        out[info_offset + info_len..info_offset + info_len + command.host_id.len()]
            .copy_from_slice(command.host_id);
        info_len += command.host_id.len();
        let card_group_id = if command.include_identifiers {
            OXIDE_SE_SCP11_CARD_GROUP_ID
        } else {
            &[]
        };
        out[info_offset + info_len] = card_group_id.len() as u8;
        info_len += 1;
        out[info_offset + info_len..info_offset + info_len + card_group_id.len()]
            .copy_from_slice(card_group_id);
        info_len += card_group_id.len();
        self.finish_scp11_mutual_authenticate(
            ctx,
            P256_SHARED_SECRET_LEN * 2,
            info_offset,
            info_len,
            SCP11C_IDENTIFIER_PARAM,
            command.include_identifiers,
            command.key_usage_qualifier,
            command.key_type,
            command.key_length,
            command.host_id,
            command.host_ephemeral_public,
            &SCP11_DEV_CARD_STATIC_PUBLIC_KEY,
            out,
        )
    }

    fn scp11b_internal_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &rustlet_runtime::Scp11bInternalAuthenticate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        if command.ecka_key_version != SCP11_ECKA_KEY_VERSION
            || command.ecka_key_id != SCP11_ECKA_KEY_ID
        {
            return Err(ApduStatus::referenced_data_not_found());
        }
        if command.key_usage_qualifier != SCP11_KEY_USAGE_FULL
            || command.key_type != SCP11_KEY_TYPE_AES
            || command.key_length != SCP11_KEY_LENGTH_AES_128
            || (command.include_identifiers && command.host_id != OXIDE_SE_SCP11_HOST_ID)
            || (!command.include_identifiers && !command.host_id.is_empty())
            || command.host_ephemeral_public.len() != P256_PUBLIC_KEY_LEN
        {
            return Err(ApduStatus::wrong_data());
        }
        if out.len() < 86 {
            return Err(ApduStatus::wrong_length());
        }

        self.clear_scp11_state();
        let card_ephemeral = {
            let mut provider = ctx.crypto();
            EcKeyPair::generate(&mut provider, EcCurve::P256).map_err(crypto_error_to_status)?
        };
        let card_ephemeral_public = *card_ephemeral.public_key().as_bytes();
        {
            let mut provider = ctx.crypto();
            KeyAgreement::new(&mut provider)
                .init(&card_ephemeral.private_key())
                .map_err(crypto_error_to_status)?
                .generate_secret(
                    command.host_ephemeral_public,
                    &mut out[..P256_SHARED_SECRET_LEN],
                )
                .map_err(crypto_error_to_status)?;
        }
        {
            let mut provider = ctx.crypto();
            let card_static_private =
                EcPrivateKey::p256_from_bytes(SCP11_DEV_CARD_STATIC_PRIVATE_KEY);
            KeyAgreement::new(&mut provider)
                .init(&card_static_private)
                .map_err(crypto_error_to_status)?
                .generate_secret(
                    command.host_ephemeral_public,
                    &mut out[P256_SHARED_SECRET_LEN..P256_SHARED_SECRET_LEN * 2],
                )
                .map_err(crypto_error_to_status)?;
        }

        let mut info_len = 0usize;
        let info_offset = P256_SHARED_SECRET_LEN * 2;
        out[info_offset + info_len] = command.key_usage_qualifier;
        out[info_offset + info_len + 1] = command.key_type;
        out[info_offset + info_len + 2] = command.key_length;
        info_len += 3;
        out[info_offset + info_len] = command.host_id.len() as u8;
        info_len += 1;
        out[info_offset + info_len..info_offset + info_len + command.host_id.len()]
            .copy_from_slice(command.host_id);
        info_len += command.host_id.len();
        let sin = if command.include_identifiers {
            OXIDE_SE_SCP11_SIN
        } else {
            &[]
        };
        out[info_offset + info_len] = sin.len() as u8;
        info_len += 1;
        out[info_offset + info_len..info_offset + info_len + sin.len()].copy_from_slice(sin);
        info_len += sin.len();
        let sdin = if command.include_identifiers {
            OXIDE_SE_SCP11_SDIN
        } else {
            &[]
        };
        out[info_offset + info_len] = sdin.len() as u8;
        info_len += 1;
        out[info_offset + info_len..info_offset + info_len + sdin.len()].copy_from_slice(sdin);
        info_len += sdin.len();
        self.finish_scp11_mutual_authenticate(
            ctx,
            P256_SHARED_SECRET_LEN * 2,
            info_offset,
            info_len,
            SCP11B_IDENTIFIER_PARAM,
            command.include_identifiers,
            command.key_usage_qualifier,
            command.key_type,
            command.key_length,
            command.host_id,
            command.host_ephemeral_public,
            &card_ephemeral_public,
            out,
        )
    }

    fn initialize_update(
        &mut self,
        ctx: &mut RustletCtx,
        command: &rustlet_runtime::InitializeUpdate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        // Every establishment attempt supersedes any earlier staged or active
        // channel, including attempts that are rejected below.
        self.clear_secure_channel_state();
        self.clear_scp11_state();
        let Some(profile) = profile_from_challenge_len(command.host_challenge.len()) else {
            return Err(ApduStatus::wrong_length());
        };
        if command.key_id != 0x00 {
            return Err(ApduStatus::incorrect_p1_p2());
        }
        let (key_version, key_id) = resolve_requested_keyset(command.key_version, command.key_id);
        let challenge_len = profile.challenge_len();
        let cryptogram_len = profile.cryptogram_len();
        let mut card_challenge = [0u8; SCP03_MAX_CHALLENGE_LEN];
        RandomData::get_instance(RandomAlgorithm::SecureRandom)
            .and_then(|mut random| random.generate_data(&mut card_challenge[..challenge_len]))
            .map_err(|_| ApduStatus::conditions_not_satisfied())?;
        let (card_cryptogram, host_cryptogram, session_enc_key, session_mac_key, session_rmac_key) =
            derive_scp03_material(
                ctx,
                profile,
                command.host_challenge,
                &card_challenge[..challenge_len],
                key_version,
                key_id,
            )?;

        let response_len = 12 + challenge_len + cryptogram_len;
        if out.len() < response_len {
            return Err(ApduStatus::wrong_length());
        }

        out[..response_len].fill(0);
        out[10] = key_version;
        out[11] = 0x03;
        out[12..12 + challenge_len].copy_from_slice(&card_challenge[..challenge_len]);
        out[12 + challenge_len..response_len].copy_from_slice(&card_cryptogram[..cryptogram_len]);

        self.secure_channel.scp03_state = SCP03_STATE_INITIALIZED;
        self.secure_channel.scp03_profile = profile.id();
        self.secure_channel.scp03_security_level_bits = SecurityLevel::NONE.bits();
        self.secure_channel.scp03_expected_host_cryptogram = [0u8; SCP03_MAX_CRYPTOGRAM_LEN];
        self.secure_channel.scp03_expected_host_cryptogram[..cryptogram_len]
            .copy_from_slice(&host_cryptogram[..cryptogram_len]);
        self.secure_channel.scp03_session_enc_key = session_enc_key;
        self.secure_channel.scp03_session_mac_key = session_mac_key;
        self.secure_channel.scp03_session_rmac_key = session_rmac_key;
        self.secure_channel.scp03_command_mac_chain = [0u8; 16];
        self.secure_channel.scp03_response_mac_chain = [0u8; 16];
        self.secure_channel.scp03_command_enc_counter = 0;
        self.secure_channel.scp03_response_enc_counter = 0;
        Ok(response_len)
    }

    fn external_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &rustlet_runtime::ExternalAuthenticate<'_>,
    ) -> Result<SecurityLevel, ApduStatus> {
        let Some(profile) = self.profile() else {
            return Err(ApduStatus::conditions_not_satisfied());
        };
        if self.secure_channel.scp03_state != SCP03_STATE_INITIALIZED {
            return Err(ApduStatus::conditions_not_satisfied());
        }

        let security_level = command.security_level;
        if !is_supported_security_level(security_level) {
            self.clear_secure_channel_state();
            return Err(ApduStatus::incorrect_p1_p2());
        }
        let cryptogram_len = profile.cryptogram_len();
        let mac_len = profile.mac_len();
        let expected_data_len = cryptogram_len
            .checked_add(mac_len)
            .ok_or_else(ApduStatus::wrong_length)?;
        if command.cla != 0x84 || command.p2 != 0x00 {
            self.clear_secure_channel_state();
            return Err(ApduStatus::incorrect_p1_p2());
        }
        if command.authentication_data.len() != expected_data_len {
            self.clear_secure_channel_state();
            return Err(ApduStatus::wrong_length());
        }
        let (host_cryptogram, received_mac) = command.authentication_data.split_at(cryptogram_len);
        let header = [
            command.cla,
            0x82,
            security_level.bits(),
            command.p2,
            expected_data_len as u8,
        ];
        let initial_mac_chain = compute_external_authenticate_cmac(
            ctx,
            &self.secure_channel.scp03_session_mac_key,
            &header,
            host_cryptogram,
        )?;
        if !constant_time_eq(
            host_cryptogram,
            &self.secure_channel.scp03_expected_host_cryptogram[..cryptogram_len],
        ) || !constant_time_eq(received_mac, &initial_mac_chain[..mac_len])
        {
            self.clear_secure_channel_state();
            return Err(ApduStatus::authentication_failed());
        }

        self.secure_channel.scp03_security_level_bits = security_level.bits();
        self.secure_channel.scp03_state = SCP03_STATE_AUTHENTICATED;
        self.secure_channel.scp03_command_mac_chain = initial_mac_chain;
        self.secure_channel.scp03_response_mac_chain = initial_mac_chain;
        Ok(security_level)
    }

    fn current_security_level(&self) -> SecurityLevel {
        if self.secure_channel.scp11a_state == SCP11_STATE_AUTHENTICATED {
            return SecurityLevel::from_bits(
                SecurityLevel::C_MAC.bits()
                    | SecurityLevel::C_ENC.bits()
                    | SecurityLevel::R_MAC.bits()
                    | SecurityLevel::R_ENC.bits(),
            );
        }
        SecurityLevel::from_bits(self.secure_channel.scp03_security_level_bits)
    }

    fn secure_channel_open(&self) -> bool {
        self.secure_channel.scp11a_state == SCP11_STATE_AUTHENTICATED
            || self.secure_channel.scp03_state == SCP03_STATE_AUTHENTICATED
    }

    fn current_mac_len(&self) -> usize {
        if self.secure_channel.scp11a_state == SCP11_STATE_AUTHENTICATED {
            return 16;
        }
        if self.secure_channel_open() {
            self.profile().map(|profile| profile.mac_len()).unwrap_or(0)
        } else {
            0
        }
    }

    fn unwrap_command(
        &mut self,
        ctx: &mut RustletCtx,
        command: &rustlet_runtime::WrappedCommand<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        if self.secure_channel.scp11a_state == SCP11_STATE_AUTHENTICATED {
            return self.unwrap_scp11_command(ctx, command, out);
        }
        let Some(profile) = self.profile() else {
            return Err(ApduStatus::conditions_not_satisfied());
        };
        if !self.secure_channel_open()
            || !uses_command_mac(self.current_security_level())
            || command.mac.len() != profile.mac_len()
        {
            return Err(ApduStatus::conditions_not_satisfied());
        }

        let chain = compute_chained_cmac(
            ctx,
            &self.secure_channel.scp03_session_mac_key,
            &self.secure_channel.scp03_command_mac_chain,
            command.authenticated,
        )?;
        if !constant_time_eq(&command.mac, &chain[..profile.mac_len()]) {
            return Err(ApduStatus::conditions_not_satisfied());
        }
        self.secure_channel.scp03_command_mac_chain = chain;
        if uses_command_encryption(self.current_security_level()) {
            if command.data.is_empty() {
                return Ok(0);
            }
            let iv = next_encryption_iv(
                ctx,
                &self.secure_channel.scp03_session_enc_key,
                &mut self.secure_channel.scp03_command_enc_counter,
                SCP03_DIRECTION_COMMAND,
            )?;
            decrypt_iso9797_m2(
                ctx,
                &self.secure_channel.scp03_session_enc_key,
                &iv,
                command.data,
                out,
            )
        } else {
            if command.data.len() > out.len() {
                return Err(ApduStatus::wrong_length());
            }
            out[..command.data.len()].copy_from_slice(command.data);
            Ok(command.data.len())
        }
    }

    fn wrap_response(
        &mut self,
        ctx: &mut RustletCtx,
        response: &rustlet_runtime::PlainResponse<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        if self.secure_channel.scp11a_state == SCP11_STATE_AUTHENTICATED {
            return self.wrap_scp11_response(ctx, response, out);
        }
        let Some(profile) = self.profile() else {
            return Err(ApduStatus::conditions_not_satisfied());
        };
        if !self.secure_channel_open() || !uses_response_mac(self.current_security_level()) {
            return Err(ApduStatus::conditions_not_satisfied());
        }

        let data_offset = 4usize;
        let payload_len = if uses_response_encryption(self.current_security_level())
            && !response.data.is_empty()
        {
            let iv = next_encryption_iv(
                ctx,
                &self.secure_channel.scp03_session_enc_key,
                &mut self.secure_channel.scp03_response_enc_counter,
                SCP03_DIRECTION_RESPONSE,
            )?;
            encrypt_iso9797_m2(
                ctx,
                &self.secure_channel.scp03_session_enc_key,
                &iv,
                response.data,
                &mut out[data_offset..],
            )?
        } else {
            if data_offset
                .checked_add(response.data.len())
                .is_none_or(|len| len > out.len())
            {
                return Err(ApduStatus::wrong_length());
            }
            out[data_offset..data_offset + response.data.len()].copy_from_slice(response.data);
            response.data.len()
        };
        let mac_offset = data_offset
            .checked_add(payload_len)
            .ok_or_else(ApduStatus::wrong_length)?;
        let total_len = payload_len
            .checked_add(profile.mac_len())
            .and_then(|len| len.checked_add(4))
            .ok_or_else(ApduStatus::wrong_length)?;
        if total_len > out.len() {
            return Err(ApduStatus::wrong_length());
        }

        let chain = compute_chained_response_cmac(
            ctx,
            &self.secure_channel.scp03_session_rmac_key,
            &self.secure_channel.scp03_response_mac_chain,
            &out[data_offset..data_offset + payload_len],
            response.status,
        )?;
        self.secure_channel.scp03_response_mac_chain = chain;

        out[0] = ((payload_len >> 8) & 0xff) as u8;
        out[1] = (payload_len & 0xff) as u8;
        out[2] = 0x00;
        out[3] = profile.mac_len() as u8;
        out[mac_offset..mac_offset + profile.mac_len()]
            .copy_from_slice(&chain[..profile.mac_len()]);
        Ok(total_len)
    }

    fn reset_secure_channel(&mut self) {
        self.clear_secure_channel_state();
        self.clear_scp11_state();
    }
}

impl CompleteSecurityDomain {
    fn finish_scp11_mutual_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        secret_len: usize,
        shared_info_offset: usize,
        shared_info_len: usize,
        identifier_param: u8,
        include_identifiers: bool,
        key_usage_qualifier: u8,
        key_type: u8,
        key_length: u8,
        host_id: &[u8],
        host_public: &[u8],
        card_public: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        let shared_info_end = shared_info_offset
            .checked_add(shared_info_len)
            .ok_or_else(ApduStatus::wrong_length)?;
        if secret_len > out.len()
            || shared_info_end > out.len()
            || host_public.len() != P256_PUBLIC_KEY_LEN
            || card_public.len() != P256_PUBLIC_KEY_LEN
        {
            return Err(ApduStatus::wrong_length());
        }

        // Invariant: SCP11a and SCP11c differ in their secret material and SharedInfo,
        // but both split the resulting 80 bytes into the same GP session keys.
        let mut derived = [0u8; SCP11_DERIVED_LEN];
        ctx.crypto()
            .derive_x963_sha256(
                &out[..secret_len],
                &out[shared_info_offset..shared_info_end],
                &mut derived,
            )
            .map_err(crypto_error_to_status)?;
        // Invariant: Amendment F orders KeyData as receipt, S-ENC, S-MAC,
        // S-RMAC, S-DEK. Storage layout is internal and keeps only the keys
        // consumed by this Security Domain.
        self.secure_channel.scp11a_storage2[..16].copy_from_slice(&derived[..16]);
        self.secure_channel.scp11a_storage0[..16].copy_from_slice(&derived[16..32]);
        self.secure_channel.scp11a_storage0[16..32].copy_from_slice(&derived[32..48]);
        self.secure_channel.scp11a_storage1[..16].copy_from_slice(&derived[48..64]);

        let receipt = compute_scp11_receipt(
            ctx,
            self.scp11_receipt_key(),
            identifier_param,
            include_identifiers,
            key_usage_qualifier,
            key_type,
            key_length,
            host_id,
            host_public,
            card_public,
        )?;
        self.secure_channel.scp11a_storage2[16..32].copy_from_slice(&receipt);
        self.secure_channel.scp11a_storage3[..16].copy_from_slice(&receipt);
        self.secure_channel.scp11a_command_enc_counter = 0;
        self.secure_channel.scp11a_response_enc_counter = 0;
        self.secure_channel.scp11a_state = SCP11_STATE_AUTHENTICATED;

        out[0] = 0x5F;
        out[1] = 0x49;
        out[2] = P256_PUBLIC_KEY_LEN as u8;
        out[3..3 + P256_PUBLIC_KEY_LEN].copy_from_slice(card_public);
        out[68] = 0x86;
        out[69] = 16;
        out[70..86].copy_from_slice(&receipt);
        Ok(86)
    }
}

impl CompleteSecurityDomain {
    /// Clears every staged SCP03 field.
    ///
    /// Session state is never serialized, but explicit clearing remains a
    /// security invariant: terminating a channel must erase its secrets while
    /// the Security Domain stays loaded, without waiting for an unload.
    fn clear_secure_channel_state(&mut self) {
        self.secure_channel.scp03_state = SCP03_STATE_INACTIVE;
        self.secure_channel.scp03_profile = 0;
        self.secure_channel.scp03_security_level_bits = SecurityLevel::NONE.bits();
        self.secure_channel.scp03_expected_host_cryptogram = [0u8; SCP03_MAX_CRYPTOGRAM_LEN];
        self.secure_channel.scp03_session_enc_key = [0u8; 16];
        self.secure_channel.scp03_session_mac_key = [0u8; 16];
        self.secure_channel.scp03_session_rmac_key = [0u8; 16];
        self.secure_channel.scp03_command_mac_chain = [0u8; 16];
        self.secure_channel.scp03_response_mac_chain = [0u8; 16];
        self.secure_channel.scp03_command_enc_counter = 0;
        self.secure_channel.scp03_response_enc_counter = 0;
    }

    fn clear_scp11_state(&mut self) {
        self.secure_channel.scp11a_state = SCP11_STATE_INACTIVE;
        self.secure_channel.scp11a_storage0 = [0u8; 32];
        self.secure_channel.scp11a_storage1 = [0u8; 32];
        self.secure_channel.scp11a_storage2 = [0u8; 32];
        self.secure_channel.scp11a_storage3 = [0u8; 32];
        self.secure_channel.scp11a_command_enc_counter = 0;
        self.secure_channel.scp11a_response_enc_counter = 0;
    }

    fn scp11_enc_key(&self) -> &[u8; 16] {
        (&self.secure_channel.scp11a_storage0[..16])
            .try_into()
            .unwrap()
    }

    fn scp11_mac_key(&self) -> &[u8; 16] {
        (&self.secure_channel.scp11a_storage0[16..32])
            .try_into()
            .unwrap()
    }

    fn scp11_rmac_key(&self) -> &[u8; 16] {
        (&self.secure_channel.scp11a_storage1[..16])
            .try_into()
            .unwrap()
    }

    fn scp11_receipt_key(&self) -> &[u8; 16] {
        (&self.secure_channel.scp11a_storage2[..16])
            .try_into()
            .unwrap()
    }

    fn scp11_command_mac_chain(&self) -> &[u8; 16] {
        (&self.secure_channel.scp11a_storage2[16..32])
            .try_into()
            .unwrap()
    }

    fn scp11_response_mac_chain(&self) -> &[u8; 16] {
        (&self.secure_channel.scp11a_storage3[..16])
            .try_into()
            .unwrap()
    }

    fn unwrap_scp11_command(
        &mut self,
        ctx: &mut RustletCtx,
        command: &rustlet_runtime::WrappedCommand<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        if command.mac.len() != 16 {
            return Err(ApduStatus::conditions_not_satisfied());
        }
        let chain = compute_chained_cmac(
            ctx,
            self.scp11_mac_key(),
            self.scp11_command_mac_chain(),
            command.authenticated,
        )?;
        if !constant_time_eq(command.mac, &chain) {
            return Err(ApduStatus::conditions_not_satisfied());
        }
        self.secure_channel.scp11a_storage2[16..32].copy_from_slice(&chain);
        if command.data.is_empty() {
            return Ok(0);
        }
        let enc_key = *self.scp11_enc_key();
        let iv = next_encryption_iv(
            ctx,
            &enc_key,
            &mut self.secure_channel.scp11a_command_enc_counter,
            SCP11_DIRECTION_COMMAND,
        )?;
        decrypt_iso9797_m2(ctx, &enc_key, &iv, command.data, out)
    }

    fn wrap_scp11_response(
        &mut self,
        ctx: &mut RustletCtx,
        response: &rustlet_runtime::PlainResponse<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        let data_offset = 4usize;
        let payload_len = if response.data.is_empty() {
            0
        } else {
            let enc_key = *self.scp11_enc_key();
            let iv = next_encryption_iv(
                ctx,
                &enc_key,
                &mut self.secure_channel.scp11a_response_enc_counter,
                SCP11_DIRECTION_RESPONSE,
            )?;
            encrypt_iso9797_m2(ctx, &enc_key, &iv, response.data, &mut out[data_offset..])?
        };
        let mac_offset = data_offset
            .checked_add(payload_len)
            .ok_or_else(ApduStatus::wrong_length)?;
        let total_len = payload_len
            .checked_add(16)
            .and_then(|len| len.checked_add(4))
            .ok_or_else(ApduStatus::wrong_length)?;
        if total_len > out.len() {
            return Err(ApduStatus::wrong_length());
        }

        let chain = compute_chained_response_cmac(
            ctx,
            self.scp11_rmac_key(),
            self.scp11_response_mac_chain(),
            &out[data_offset..data_offset + payload_len],
            response.status,
        )?;
        self.secure_channel.scp11a_storage3[..16].copy_from_slice(&chain);

        out[0] = ((payload_len >> 8) & 0xff) as u8;
        out[1] = (payload_len & 0xff) as u8;
        out[2] = 0x00;
        out[3] = 16;
        out[mac_offset..mac_offset + 16].copy_from_slice(&chain);
        Ok(total_len)
    }

    fn handle_select(&mut self, apdu: Apdu<'_, rustlet_runtime::Command>) -> ApduStatus {
        let fci = [
            0x6F,
            0x10,
            0x84,
            COMPLETE_SECURITY_DOMAIN_AID.len,
            COMPLETE_SECURITY_DOMAIN_AID.bytes[0],
            COMPLETE_SECURITY_DOMAIN_AID.bytes[1],
            COMPLETE_SECURITY_DOMAIN_AID.bytes[2],
            COMPLETE_SECURITY_DOMAIN_AID.bytes[3],
            COMPLETE_SECURITY_DOMAIN_AID.bytes[4],
            COMPLETE_SECURITY_DOMAIN_AID.bytes[5],
            COMPLETE_SECURITY_DOMAIN_AID.bytes[6],
            COMPLETE_SECURITY_DOMAIN_AID.bytes[7],
            0xA5,
            0x04,
            0x9F,
            0x65,
            0x01,
            0x01,
        ];
        apdu.as_sending().send(&fci)
    }

    fn handle_install(&mut self, apdu: Apdu<'_, rustlet_runtime::Command>) -> ApduStatus {
        let rx = apdu.as_receiving();
        let Some((package_aid, instance_aid)) = parse_install_targets(rx.data()) else {
            return rx.reject(ApduStatus::wrong_data());
        };
        if package_aid.len == 0 || instance_aid.len == 0 {
            return rx.reject(ApduStatus::wrong_data());
        }

        rx.accept()
    }

    fn handle_get_data(&mut self, apdu: Apdu<'_, rustlet_runtime::Command>) -> ApduStatus {
        apdu.as_sending().send(&[0x9F, 0x70, 0x01, 0x07])
    }
}

/// Parses the `package AID` and `instance AID` carried by `INSTALL [for install]`.
fn parse_install_targets(data: &[u8]) -> Option<(Aid, Aid)> {
    let (package_aid, rest) = parse_lv_field(data)?;
    let (_applet_aid, rest) = parse_lv_field(rest)?;
    let (instance_aid, rest) = parse_lv_field(rest)?;
    let (_privileges, rest) = parse_lv_field(rest)?;
    let (_install_parameters, rest) = parse_lv_field(rest)?;
    if !rest.is_empty() {
        return None;
    }

    Some((Aid::new(package_aid), Aid::new(instance_aid)))
}

/// Parses one `LV` field and returns the decoded value plus the remaining tail.
fn parse_lv_field(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = data.split_first()?;
    let len = len as usize;
    if rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}

/// Local SCP03 profile descriptor used by the test Security Domain.
#[derive(Clone, Copy)]
struct Scp03Profile {
    id: u8,
    challenge_len: usize,
    cryptogram_len: usize,
    mac_len: usize,
}

impl Scp03Profile {
    const fn s8() -> Self {
        Self {
            id: SCP03_PROFILE_S8,
            challenge_len: SCP03_S8_CHALLENGE_LEN,
            cryptogram_len: SCP03_S8_CRYPTOGRAM_LEN,
            mac_len: SCP03_S8_MAC_LEN,
        }
    }

    const fn s16() -> Self {
        Self {
            id: SCP03_PROFILE_S16,
            challenge_len: SCP03_S16_CHALLENGE_LEN,
            cryptogram_len: SCP03_S16_CRYPTOGRAM_LEN,
            mac_len: SCP03_S16_MAC_LEN,
        }
    }

    const fn id(self) -> u8 {
        self.id
    }

    const fn challenge_len(self) -> usize {
        self.challenge_len
    }

    const fn cryptogram_len(self) -> usize {
        self.cryptogram_len
    }

    const fn mac_len(self) -> usize {
        self.mac_len
    }

}

impl CompleteSecurityDomain {
    fn profile(&self) -> Option<Scp03Profile> {
        match self.secure_channel.scp03_profile {
            SCP03_PROFILE_S8 => Some(Scp03Profile::s8()),
            SCP03_PROFILE_S16 => Some(Scp03Profile::s16()),
            _ => None,
        }
    }
}

fn profile_from_challenge_len(len: usize) -> Option<Scp03Profile> {
    match len {
        SCP03_S8_CHALLENGE_LEN => Some(Scp03Profile::s8()),
        SCP03_S16_CHALLENGE_LEN => Some(Scp03Profile::s16()),
        _ => None,
    }
}

fn resolve_requested_keyset(key_version: u8, _p2: u8) -> (u8, u8) {
    (
        if key_version == 0x00 {
            SCP03_DEFAULT_KEY_VERSION
        } else {
            key_version
        },
        // INTERNAL ABI sentinel: INITIALIZE UPDATE P2 is mandated to zero by
        // GP, so the kernel resolves the actual key identifier by version.
        0,
    )
}

/// Derives the full SCP03 session material for one user-land Security Domain session.
fn derive_scp03_material(
    ctx: &mut RustletCtx,
    profile: Scp03Profile,
    host_challenge: &[u8],
    card_challenge: &[u8],
    key_version: u8,
    key_id: u8,
) -> Result<
    (
        [u8; SCP03_MAX_CRYPTOGRAM_LEN],
        [u8; SCP03_MAX_CRYPTOGRAM_LEN],
        [u8; 16],
        [u8; 16],
        [u8; 16],
    ),
    ApduStatus,
> {
    let mut enc_key = [0u8; 16];
    let mut mac_key = [0u8; 16];
    let enc_len = ctx
        .load_scp03_key_material(key_version, key_id, SCP03_KEY_USAGE_ENC, &mut enc_key)
        .map_err(|_| ApduStatus::referenced_data_not_found())?;
    let mac_len = ctx
        .load_scp03_key_material(key_version, key_id, SCP03_KEY_USAGE_MAC, &mut mac_key)
        .map_err(|_| ApduStatus::referenced_data_not_found())?;
    if enc_len != enc_key.len() || mac_len != mac_key.len() {
        return Err(ApduStatus::referenced_data_not_found());
    }

    let mut context = [0u8; SCP03_MAX_CHALLENGE_LEN * 2];
    context[..host_challenge.len()].copy_from_slice(host_challenge);
    context[host_challenge.len()..host_challenge.len() + card_challenge.len()]
        .copy_from_slice(card_challenge);
    let context = &context[..host_challenge.len() + card_challenge.len()];

    let session_enc_key = scp03_kdf::<16>(ctx, SCP03_KDF_S_ENC, context, &enc_key)?;
    let session_mac_key = scp03_kdf::<16>(ctx, SCP03_KDF_S_MAC, context, &mac_key)?;
    let session_rmac_key = scp03_kdf::<16>(ctx, SCP03_KDF_S_RMAC, context, &mac_key)?;
    let mut card_cryptogram = [0u8; SCP03_MAX_CRYPTOGRAM_LEN];
    let mut host_cryptogram = [0u8; SCP03_MAX_CRYPTOGRAM_LEN];
    match profile.id() {
        SCP03_PROFILE_S8 => {
            card_cryptogram[..SCP03_S8_CRYPTOGRAM_LEN].copy_from_slice(&scp03_kdf::<
                SCP03_S8_CRYPTOGRAM_LEN,
            >(
                ctx,
                SCP03_KDF_CARD_CRYPTOGRAM,
                context,
                &session_mac_key,
            )?);
            host_cryptogram[..SCP03_S8_CRYPTOGRAM_LEN].copy_from_slice(&scp03_kdf::<
                SCP03_S8_CRYPTOGRAM_LEN,
            >(
                ctx,
                SCP03_KDF_HOST_CRYPTOGRAM,
                context,
                &session_mac_key,
            )?);
        }
        SCP03_PROFILE_S16 => {
            card_cryptogram[..SCP03_S16_CRYPTOGRAM_LEN].copy_from_slice(&scp03_kdf::<
                SCP03_S16_CRYPTOGRAM_LEN,
            >(
                ctx,
                SCP03_KDF_CARD_CRYPTOGRAM,
                context,
                &session_mac_key,
            )?);
            host_cryptogram[..SCP03_S16_CRYPTOGRAM_LEN].copy_from_slice(&scp03_kdf::<
                SCP03_S16_CRYPTOGRAM_LEN,
            >(
                ctx,
                SCP03_KDF_HOST_CRYPTOGRAM,
                context,
                &session_mac_key,
            )?);
        }
        _ => return Err(ApduStatus::wrong_data()),
    }
    Ok((
        card_cryptogram,
        host_cryptogram,
        session_enc_key,
        session_mac_key,
        session_rmac_key,
    ))
}

/// Implements the SCP03 CMAC-based KDF through the runtime crypto API.
fn scp03_kdf<const N: usize>(
    ctx: &mut RustletCtx,
    derivation_constant: u8,
    context: &[u8],
    key: &[u8; 16],
) -> Result<[u8; N], ApduStatus> {
    let mut provider = ctx.crypto();
    let mut mac = Mac::<Uninitialized>::new(&mut provider)
        .init(key, MacAlgorithm::AesCmac)
        .map_err(crypto_error_to_status)?;
    mac.update(&[0u8; 11]).map_err(crypto_error_to_status)?;
    mac.update(&[derivation_constant])
        .map_err(crypto_error_to_status)?;
    mac.update(&[0x00]).map_err(crypto_error_to_status)?;
    mac.update(&((N as u16) * 8).to_be_bytes())
        .map_err(crypto_error_to_status)?;
    mac.update(&[0x01]).map_err(crypto_error_to_status)?;
    mac.update(context).map_err(crypto_error_to_status)?;
    let tag = mac.compute().map_err(crypto_error_to_status)?;

    let mut out = [0u8; N];
    out.copy_from_slice(&tag.as_ref()[..N]);
    Ok(out)
}

/// Returns true when the requested level matches the subset implemented by this test SD.
fn is_supported_security_level(level: SecurityLevel) -> bool {
    let bits = level.bits();
    bits == SecurityLevel::NONE.bits()
        || bits == SecurityLevel::C_MAC.bits()
        || bits == (SecurityLevel::C_MAC.bits() | SecurityLevel::C_ENC.bits())
        || bits
            == (SecurityLevel::C_MAC.bits()
                | SecurityLevel::C_ENC.bits()
                | SecurityLevel::R_MAC.bits()
                | SecurityLevel::R_ENC.bits())
}

/// Returns true when command MAC protection is active.
fn uses_command_mac(level: SecurityLevel) -> bool {
    (level.bits() & SecurityLevel::C_MAC.bits()) == SecurityLevel::C_MAC.bits()
}

/// Returns true when command encryption is active.
fn uses_command_encryption(level: SecurityLevel) -> bool {
    (level.bits() & SecurityLevel::C_ENC.bits()) == SecurityLevel::C_ENC.bits()
}

/// Returns true when response MAC protection is active.
fn uses_response_mac(level: SecurityLevel) -> bool {
    (level.bits() & SecurityLevel::R_MAC.bits()) == SecurityLevel::R_MAC.bits()
}

/// Returns true when response encryption is active.
fn uses_response_encryption(level: SecurityLevel) -> bool {
    (level.bits() & SecurityLevel::R_ENC.bits()) == SecurityLevel::R_ENC.bits()
}

/// Computes one chained CMAC over the current chain value and one input slice.
fn compute_chained_cmac(
    ctx: &mut RustletCtx,
    key: &[u8; 16],
    chain: &[u8; 16],
    input: &[u8],
) -> Result<[u8; 16], ApduStatus> {
    let mut provider = ctx.crypto();
    let mut mac = Mac::<Uninitialized>::new(&mut provider)
        .init(key, MacAlgorithm::AesCmac)
        .map_err(crypto_error_to_status)?;
    mac.update(chain).map_err(crypto_error_to_status)?;
    mac.update(input).map_err(crypto_error_to_status)?;
    let tag = mac.compute().map_err(crypto_error_to_status)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

/// Computes Amendment D response authentication over data followed by SW1-SW2.
fn compute_chained_response_cmac(
    ctx: &mut RustletCtx,
    key: &[u8; 16],
    chain: &[u8; 16],
    data: &[u8],
    status: ApduStatus,
) -> Result<[u8; 16], ApduStatus> {
    let mut provider = ctx.crypto();
    let mut mac = Mac::<Uninitialized>::new(&mut provider)
        .init(key, MacAlgorithm::AesCmac)
        .map_err(crypto_error_to_status)?;
    mac.update(chain).map_err(crypto_error_to_status)?;
    mac.update(data).map_err(crypto_error_to_status)?;
    mac.update(&[status.sw1, status.sw2])
        .map_err(crypto_error_to_status)?;
    let tag = mac.compute().map_err(crypto_error_to_status)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

/// Computes the mandatory C-MAC protecting SCP03 `EXTERNAL AUTHENTICATE`.
fn compute_external_authenticate_cmac(
    ctx: &mut RustletCtx,
    key: &[u8; 16],
    header: &[u8; 5],
    host_cryptogram: &[u8],
) -> Result<[u8; 16], ApduStatus> {
    let mut provider = ctx.crypto();
    let mut mac = Mac::<Uninitialized>::new(&mut provider)
        .init(key, MacAlgorithm::AesCmac)
        .map_err(crypto_error_to_status)?;
    mac.update(&[0u8; 16]).map_err(crypto_error_to_status)?;
    mac.update(header).map_err(crypto_error_to_status)?;
    mac.update(host_cryptogram)
        .map_err(crypto_error_to_status)?;
    let tag = mac.compute().map_err(crypto_error_to_status)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

fn compute_scp11_receipt(
    ctx: &mut RustletCtx,
    key: &[u8; 16],
    identifier_param: u8,
    include_identifiers: bool,
    key_usage_qualifier: u8,
    key_type: u8,
    key_length: u8,
    host_id: &[u8],
    host_public: &[u8],
    card_public: &[u8],
) -> Result<[u8; 16], ApduStatus> {
    if host_public.len() != P256_PUBLIC_KEY_LEN
        || card_public.len() != P256_PUBLIC_KEY_LEN
        || host_id.len() > u8::MAX as usize
        || (!include_identifiers && !host_id.is_empty())
    {
        return Err(ApduStatus::wrong_length());
    }
    let host_id_tlv_len = if include_identifiers {
        2usize
            .checked_add(host_id.len())
            .ok_or_else(ApduStatus::wrong_length)?
    } else {
        0
    };
    let crt_len = 13usize
        .checked_add(host_id_tlv_len)
        .ok_or_else(ApduStatus::wrong_length)?;
    if crt_len > u8::MAX as usize {
        return Err(ApduStatus::wrong_length());
    }

    // Assemble the receipt input once, then use the one-shot runtime service.
    // Keeping a typestate `Mac` live here would add its 256-byte accumulation
    // buffer (and compiler-generated moves of it) to the already deep SCP11a
    // call chain on the 2 KiB Rustlet stack.
    let mut input = [0u8; SCP11_RECEIPT_INPUT_CAPACITY];
    let mut input_len = 0;
    append_scp11_receipt_input(&mut input, &mut input_len, &[0xA6, crt_len as u8])?;
    append_scp11_receipt_input(&mut input, &mut input_len, &[
        0x90,
        0x02,
        SCP11_IDENTIFIER_FAMILY,
        identifier_param,
        0x95,
        0x01,
        key_usage_qualifier,
        0x80,
        0x01,
        key_type,
        0x81,
        0x01,
        key_length,
    ])?;
    if include_identifiers {
        append_scp11_receipt_input(
            &mut input,
            &mut input_len,
            &[0x84, host_id.len() as u8],
        )?;
        append_scp11_receipt_input(&mut input, &mut input_len, host_id)?;
    }
    append_scp11_receipt_input(
        &mut input,
        &mut input_len,
        &[0x5F, 0x49, P256_PUBLIC_KEY_LEN as u8],
    )?;
    append_scp11_receipt_input(&mut input, &mut input_len, host_public)?;
    append_scp11_receipt_input(
        &mut input,
        &mut input_len,
        &[0x5F, 0x49, P256_PUBLIC_KEY_LEN as u8],
    )?;
    append_scp11_receipt_input(&mut input, &mut input_len, card_public)?;
    let mut provider = ctx.crypto();
    let tag = provider
        .compute_mac(key, MacAlgorithm::AesCmac, &input[..input_len])
        .map_err(crypto_error_to_status)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

fn append_scp11_receipt_input(
    input: &mut [u8],
    input_len: &mut usize,
    part: &[u8],
) -> Result<(), ApduStatus> {
    let end = input_len
        .checked_add(part.len())
        .ok_or_else(ApduStatus::wrong_length)?;
    let destination = input
        .get_mut(*input_len..end)
        .ok_or_else(ApduStatus::wrong_length)?;
    destination.copy_from_slice(part);
    *input_len = end;
    Ok(())
}

/// Derives the next SCP03 CBC IV from the session `S-ENC` key and direction counter.
fn next_encryption_iv(
    ctx: &mut RustletCtx,
    key: &[u8; 16],
    counter: &mut u32,
    direction: u8,
) -> Result<[u8; 16], ApduStatus> {
    *counter = counter
        .checked_add(1)
        .ok_or_else(ApduStatus::conditions_not_satisfied)?;
    let mut block = [0u8; 16];
    block[0] = direction;
    block[12..16].copy_from_slice(&counter.to_be_bytes());
    let mut provider = ctx.crypto();
    let cipher = Cipher::<Uninitialized>::new(&mut provider)
        .init(
            key,
            &[0u8; 16],
            CipherMode::Encrypt,
            Algorithm::Aes128EcbNoPadding,
        )
        .map_err(crypto_error_to_status)?;
    let mut out = [0u8; 16];
    let len = cipher
        .finish(&block, &mut out)
        .map_err(crypto_error_to_status)?;
    if len != out.len() {
        return Err(ApduStatus::conditions_not_satisfied());
    }
    Ok(out)
}

/// Decrypts one ISO9797-M2 padded payload through the runtime crypto API.
fn decrypt_iso9797_m2(
    ctx: &mut RustletCtx,
    key: &[u8; 16],
    iv: &[u8; 16],
    input: &[u8],
    out: &mut [u8],
) -> Result<usize, ApduStatus> {
    let mut provider = ctx.crypto();
    let cipher = Cipher::<Uninitialized>::new(&mut provider)
        .init(key, iv, CipherMode::Decrypt, Algorithm::Aes128CbcIso9797M2)
        .map_err(crypto_error_to_status)?;
    cipher.finish(input, out).map_err(crypto_error_to_status)
}

/// Encrypts one ISO9797-M2 padded payload through the runtime crypto API.
fn encrypt_iso9797_m2(
    ctx: &mut RustletCtx,
    key: &[u8; 16],
    iv: &[u8; 16],
    input: &[u8],
    out: &mut [u8],
) -> Result<usize, ApduStatus> {
    let mut provider = ctx.crypto();
    let cipher = Cipher::<Uninitialized>::new(&mut provider)
        .init(key, iv, CipherMode::Encrypt, Algorithm::Aes128CbcIso9797M2)
        .map_err(crypto_error_to_status)?;
    cipher.finish(input, out).map_err(crypto_error_to_status)
}

/// Compares two slices without leaking the first differing position.
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

/// Maps runtime crypto failures to the GP-style status used by this test SD.
fn crypto_error_to_status(error: rustlet_runtime::CryptoError) -> ApduStatus {
    let _ = error;
    ApduStatus::conditions_not_satisfied()
}
