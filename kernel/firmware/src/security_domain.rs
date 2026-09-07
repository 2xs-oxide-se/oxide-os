#![allow(dead_code)]

use crate::core::crypto::{
    self, AES_CMAC_SIZE, P256_PRIVATE_KEY_SIZE, P256_PUBLIC_KEY_UNCOMPRESSED_SIZE,
    P256_SHARED_SECRET_SIZE,
};
use crate::core::scp03::{self, Scp03Profile};
use crate::core::{scp11, scp11c};
use rustlet_runtime::Aid;

/// Maximum plaintext or ciphertext payload staged by one SCP03 transform.
const SCP03_TRANSFORM_CAPACITY: usize = scp03::TRANSFORM_CAPACITY;
/// Maximum establishment response size supported by the generic secure-channel bridge.
const SECURE_CHANNEL_RESPONSE_CAPACITY: usize = 96;
/// Maximum `INITIALIZE UPDATE` response size supported by the kernel bridge.
const SCP03_RESPONSE_CAPACITY: usize = 64;
/// Largest MAC length supported by the SCP03 bridge.
const SCP03_MAC_CAPACITY: usize = scp03::S16_MAC_LEN;
/// Static SCP03 key size currently supported by the kernel bridge.
pub const SCP03_STATIC_KEY_LEN: usize = scp03::AES128_STATIC_KEY_LEN;
/// Usage identifier for one SCP03 ENC key object.
pub const SCP03_PUT_KEY_USAGE_ENC: u8 = 0x01;
/// Usage identifier for one SCP03 MAC key object.
pub const SCP03_PUT_KEY_USAGE_MAC: u8 = 0x02;
/// Oxide SE PUT KEY discriminator for the SD P-256 ECKA private key.
pub const SCP11_PUT_KEY_USAGE_SD_ECKA: u8 = 0x11;
/// Oxide SE PUT KEY discriminator for the CA-KLOC P-256 public key.
pub const SCP11_PUT_KEY_USAGE_CA_KLOC: u8 = 0x12;
const KERNEL_SECURITY_DOMAIN_STATE_VERSION: u8 = 1;
const KERNEL_SECURITY_DOMAIN_STATE_LEN: usize = 6;
const KERNEL_SECURITY_DOMAIN_LEGACY_STATE_LEN: usize = 5;
const SCP11_DEV_CARD_STATIC_PRIVATE_KEY: [u8; P256_PRIVATE_KEY_SIZE] = [
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
];
const SCP11_DEV_CARD_STATIC_PUBLIC_KEY: [u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE] = [
    0x04, 0x8a, 0xb5, 0x47, 0xc6, 0x0e, 0x31, 0xc0, 0x03, 0x21, 0x15, 0xc8, 0x95, 0xdd, 0xee, 0xd6,
    0xd8, 0x31, 0x9b, 0x5d, 0xa6, 0x2e, 0x4a, 0x92, 0xde, 0xd1, 0xdf, 0x03, 0xa8, 0x79, 0xb1, 0x90,
    0xcd, 0xc5, 0x01, 0xaa, 0xfa, 0x10, 0xc3, 0xd2, 0xcf, 0x45, 0x66, 0xc6, 0xc5, 0x36, 0x67, 0xb9,
    0x62, 0x6d, 0x12, 0xe9, 0x7e, 0xd2, 0x29, 0xce, 0x90, 0xb8, 0xca, 0x29, 0xa0, 0x64, 0x27, 0xdd,
    0x58,
];
const SCP11_DEV_ECKA_KEY_VERSION: u8 = 0x00;
const SCP11_DEV_ECKA_KEY_ID: u8 = 0x01;
const SCP11_DEV_CA_KEY_VERSION: u8 = 0x00;
const SCP11_DEV_CA_KEY_ID: u8 = 0x00;
const OXIDE_SE_SCP11_DEV_SIN: &[u8] = b"oxide-se-sin";
const OXIDE_SE_SCP11_DEV_SDIN: &[u8] = b"oxide-se-sdin";
const OXIDE_SE_SCP11_DEV_CARD_GROUP_ID: &[u8] = b"oxide-se-card";

fn scp11_sd_private_key(owner: &Aid, version: u8, id: u8) -> Option<[u8; P256_PRIVATE_KEY_SIZE]> {
    let mut key = [0u8; P256_PRIVATE_KEY_SIZE];
    if crate::selected_app::load_scp11_key_material(
        owner,
        version,
        id,
        SCP11_PUT_KEY_USAGE_SD_ECKA,
        &mut key,
    ) == Some(key.len())
    {
        return Some(key);
    }
    (version == SCP11_DEV_ECKA_KEY_VERSION && id == SCP11_DEV_ECKA_KEY_ID)
        .then_some(SCP11_DEV_CARD_STATIC_PRIVATE_KEY)
}

fn scp11_ca_kloc_public_key(
    owner: &Aid,
    version: u8,
    id: u8,
) -> Option<[u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE]> {
    let mut key = [0u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
    if crate::selected_app::load_scp11_key_material(
        owner,
        version,
        id,
        SCP11_PUT_KEY_USAGE_CA_KLOC,
        &mut key,
    ) == Some(key.len())
    {
        return Some(key);
    }
    (version == SCP11_DEV_CA_KEY_VERSION && id == SCP11_DEV_CA_KEY_ID)
        .then(|| *scp11c::dev_ca_public_key())
}

pub use crate::core::scp03::SecurityLevel;
/// Protocol identifiers exposed by the generic secure-channel façade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureChannelProtocol {
    Scp03,
    Scp11(scp11::Scp11Profile),
}

/// Authentication of the off-card peer established by one secure channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureChannelPeerAuthentication {
    /// No off-card entity has been authenticated.
    None,
    /// The selected development profile binds the peer to the SD owner.
    Owner,
    /// A non-owner OCE authenticated through SCP11 certificate processing.
    Any,
    /// SCP11b authenticated the card only; OCE authorization needs another mechanism.
    CardOnly,
}

/// Component that owns protocol-specific authorization for one session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureChannelPolicyOwner {
    /// The kernel recognizes the protocol and applies its compiled GP matrix.
    KernelProfile,
    /// The active Rustlet Security Domain owns an otherwise unknown protocol.
    RustletSecurityDomain,
}

/// Management operation families filtered before Security Domain policy hooks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementOperation {
    GetData,
    GetStatus,
    StoreData,
    PutKey,
    InstallForLoad,
    Load,
    InstallForInstall,
    Delete,
    SetStatus,
}

/// Registry target category relevant to protocol-level management restrictions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementTarget {
    Unspecified,
    Object,
    Key,
}

/// APDU-level interpretation of a management operation.
///
/// GlobalPlatform does not assign separate instruction bytes to Global
/// Delete, Global Lock, or Global Registry. oXiDe recognizes those forms when
/// the corresponding DELETE, SET STATUS, or GET STATUS command is addressed
/// to the technical root. Both forms retain the same internal operation and
/// differ only in the authority passed to the common implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementApduForm {
    Ordinary,
    Global,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdaptedManagementOperation {
    pub operation: ManagementOperation,
    pub authority_aid: Aid,
    pub form: ManagementApduForm,
}

pub fn adapt_management_apdu(
    operation: ManagementOperation,
    addressed_authority_aid: Aid,
    root_aid: Aid,
) -> AdaptedManagementOperation {
    let has_global_form = matches!(
        operation,
        ManagementOperation::Delete
            | ManagementOperation::SetStatus
            | ManagementOperation::GetStatus
    );
    if has_global_form && addressed_authority_aid == root_aid {
        AdaptedManagementOperation {
            operation,
            authority_aid: root_aid,
            form: ManagementApduForm::Global,
        }
    } else {
        AdaptedManagementOperation {
            operation,
            authority_aid: addressed_authority_aid,
            form: ManagementApduForm::Ordinary,
        }
    }
}
/// Errors returned by the kernel-side management authority boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementError {
    Rejected,
    Unsupported,
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scp03KeyUsage {
    /// Encryption material used to derive `S-ENC`.
    Enc,
    /// Authentication material used to derive `S-MAC` and `S-RMAC`.
    Mac,
}

impl Scp03KeyUsage {
    /// Encodes the usage as one byte stored in registry key objects.
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Enc => SCP03_PUT_KEY_USAGE_ENC,
            Self::Mac => SCP03_PUT_KEY_USAGE_MAC,
        }
    }

    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            SCP03_PUT_KEY_USAGE_ENC => Some(Self::Enc),
            SCP03_PUT_KEY_USAGE_MAC => Some(Self::Mac),
            _ => None,
        }
    }
}

/// Errors returned by the kernel-side secure channel authority boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureChannelError {
    Rejected,
    Unsupported,
    Status(crate::apdu_manager::ApduStatus),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityDomainLifecycle {
    Selectable,
    Locked,
}

impl SecurityDomainLifecycle {
    const LEGACY_INSTALLED_BYTE: u8 = 0x03;
    const SELECTABLE_BYTE: u8 = 0x07;
    const LOCKED_BYTE: u8 = 0x7f;

    /// Returns the lifecycle byte exposed by `GET DATA 9F70`.
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Selectable => Self::SELECTABLE_BYTE,
            Self::Locked => Self::LOCKED_BYTE,
        }
    }

    /// Decodes one persisted lifecycle byte.
    ///
    /// Unknown and legacy zero values are treated as selectable so old
    /// development registries remain bootable.
    pub const fn from_stored_byte(byte: u8) -> Self {
        match byte {
            Self::LOCKED_BYTE => Self::Locked,
            Self::LEGACY_INSTALLED_BYTE => Self::Selectable,
            _ => Self::Selectable,
        }
    }

    /// Returns true when this Security Domain may exercise management hooks.
    pub const fn may_manage(self) -> bool {
        matches!(self, Self::Selectable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KernelSecurityDomainAdministrativeState {
    privileges: SecurityDomainPrivileges,
    lifecycle: SecurityDomainLifecycle,
}

impl KernelSecurityDomainAdministrativeState {
    /// Builds one empty administrative state for a disabled or unknown instance.
    const fn empty() -> Self {
        Self {
            privileges: SecurityDomainPrivileges::empty(),
            lifecycle: SecurityDomainLifecycle::Locked,
        }
    }

    /// Builds one fully privileged development state.
    const fn open() -> Self {
        Self {
            privileges: SecurityDomainPrivileges::open(),
            lifecycle: SecurityDomainLifecycle::Selectable,
        }
    }

    /// Decodes the privilege bytes carried by `INSTALL [for install]`.
    fn from_install_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            privileges: SecurityDomainPrivileges::from_install_bytes(bytes)?,
            lifecycle: SecurityDomainLifecycle::Selectable,
        })
    }

    /// Returns the effective privileges granted to the instance.
    const fn privileges(self) -> SecurityDomainPrivileges {
        self.privileges
    }

    /// Returns the current lifecycle.
    const fn lifecycle(self) -> SecurityDomainLifecycle {
        self.lifecycle
    }

    /// Returns true if this state may exercise management hooks.
    const fn may_manage(self) -> bool {
        self.lifecycle.may_manage()
    }

    /// Encodes the administrative state stored in the global registry.
    fn encode(self) -> [u8; KERNEL_SECURITY_DOMAIN_STATE_LEN] {
        let encoded = self.privileges.encoded_bytes();
        [
            KERNEL_SECURITY_DOMAIN_STATE_VERSION,
            self.lifecycle.as_byte(),
            self.privileges.encoded_len() as u8,
            encoded[0],
            encoded[1],
            encoded[2],
        ]
    }

    /// Decodes one administrative state fetched from the global registry.
    fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            KERNEL_SECURITY_DOMAIN_STATE_LEN => {
                if bytes[0] != KERNEL_SECURITY_DOMAIN_STATE_VERSION {
                    return None;
                }
                let encoded_len = bytes[2] as usize;
                if encoded_len > 3 {
                    return None;
                }
                Some(Self {
                    lifecycle: SecurityDomainLifecycle::from_stored_byte(bytes[1]),
                    privileges: SecurityDomainPrivileges::from_install_bytes(
                        &bytes[3..3 + encoded_len],
                    )?,
                })
            }
            KERNEL_SECURITY_DOMAIN_LEGACY_STATE_LEN => {
                if bytes[0] != KERNEL_SECURITY_DOMAIN_STATE_VERSION {
                    return None;
                }
                let encoded_len = bytes[1] as usize;
                if encoded_len > 3 {
                    return None;
                }
                Some(Self {
                    lifecycle: SecurityDomainLifecycle::Selectable,
                    privileges: SecurityDomainPrivileges::from_install_bytes(
                        &bytes[2..2 + encoded_len],
                    )?,
                })
            }
            _ => None,
        }
    }
}

fn security_level_from_external_authenticate_p1(p1: u8) -> Option<SecurityLevel> {
    SecurityLevel::from_selected_scp03_p1(p1)
}

/// Internal SCP03 lifecycle tracked by one kernel-side authority instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scp03SessionState {
    /// No SCP session is currently staged.
    Inactive,
    /// `INITIALIZE UPDATE` completed and waits for `EXTERNAL AUTHENTICATE`.
    Initialized,
    /// Secure messaging is active for the bound Security Domain instance.
    Authenticated,
}

/// Runtime SCP03 session material attached to one kernel-side Security Domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SecurityDomainSession {
    state: Scp03SessionState,
    security_level: SecurityLevel,
    key_version: u8,
    key_index: u8,
    material: Option<scp03::SessionMaterial>,
    secure_messaging: Option<scp03::SessionState>,
}

impl SecurityDomainSession {
    /// Creates a fully reset SCP03 session state.
    const fn inactive() -> Self {
        Self {
            state: Scp03SessionState::Inactive,
            security_level: SecurityLevel::None,
            key_version: 0,
            key_index: 0,
            material: None,
            secure_messaging: None,
        }
    }

    /// Clears every staged SCP03 field.
    fn reset(&mut self) {
        *self = Self::inactive();
    }

    /// Activates secure messaging from the authenticated establishment command.
    fn activate_secure_messaging_state(&mut self, initial_mac_chain: [u8; 16]) {
        if let Some(material) = self.material {
            self.secure_messaging = Some(scp03::SessionState::with_initial_mac_chain(
                material.profile,
                self.security_level,
                material.keys,
                initial_mac_chain,
            ));
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scp11Session {
    active: bool,
    profile: Option<scp11::Scp11Profile>,
    keys: Option<scp11::Scp11SessionKeys>,
    secure_messaging: Option<scp11::Scp11SessionState>,
    staged_oce_public_present: bool,
    staged_oce_public: [u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE],
    staged_oce_subject_len: u8,
    staged_oce_subject: [u8; 16],
    staged_oce_discretionary_len: u8,
    staged_oce_discretionary: [u8; 64],
}

impl Scp11Session {
    const fn inactive() -> Self {
        Self {
            active: false,
            profile: None,
            keys: None,
            secure_messaging: None,
            staged_oce_public_present: false,
            staged_oce_public: [0; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE],
            staged_oce_subject_len: 0,
            staged_oce_subject: [0; 16],
            staged_oce_discretionary_len: 0,
            staged_oce_discretionary: [0; 64],
        }
    }

    fn reset_staged_oce(&mut self) {
        self.staged_oce_public_present = false;
        self.staged_oce_public = [0; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
        self.staged_oce_subject_len = 0;
        self.staged_oce_subject = [0; 16];
        self.staged_oce_discretionary_len = 0;
        self.staged_oce_discretionary = [0; 64];
    }

    fn reset(&mut self) {
        self.active = false;
        self.profile = None;
        self.keys = None;
        self.secure_messaging = None;
    }

    /// Stages one verified OCE certificate for the next SCP11c mutual authentication.
    ///
    /// The certificate is copied into bounded kernel-owned buffers so later
    /// `MUTUAL AUTHENTICATE` processing never depends on transient APDU storage.
    fn stage_oce_certificate(
        &mut self,
        certificate: &scp11c::VerifiedOceCertificate<'_>,
    ) -> Result<(), SecureChannelError> {
        let subject = certificate.subject_id();
        let discretionary = certificate.discretionary_data();
        if subject.len() > self.staged_oce_subject.len()
            || discretionary.len() > self.staged_oce_discretionary.len()
        {
            return Err(SecureChannelError::Rejected);
        }

        // Invariant: staging a new OCE certificate drops any previous live
        // SCP11 session before replacing the trust material.
        self.reset();
        self.reset_staged_oce();
        self.staged_oce_public
            .copy_from_slice(certificate.public_key());
        self.staged_oce_public_present = true;
        self.staged_oce_subject[..subject.len()].copy_from_slice(subject);
        self.staged_oce_subject_len = subject.len() as u8;
        self.staged_oce_discretionary[..discretionary.len()].copy_from_slice(discretionary);
        self.staged_oce_discretionary_len = discretionary.len() as u8;
        Ok(())
    }

    fn staged_oce_public(&self) -> Option<&[u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE]> {
        if self.staged_oce_public_present {
            Some(&self.staged_oce_public)
        } else {
            None
        }
    }

    /// Completes one SCP11 `MUTUAL AUTHENTICATE` against the staged OCE certificate.
    ///
    /// SCP11a combines the staged OCE static key with ephemeral card material.
    /// SCP11b skips PSO and uses card static/ephemeral contributions. SCP11c
    /// uses the card static key for both the staged OCE static key and the
    /// request OCE ephemeral key. On success all profiles enter the same
    /// secure-messaging state.
    fn mutual_authenticate(
        &mut self,
        profile: scp11::Scp11Profile,
        key_version: u8,
        key_id: u8,
        data: &[u8],
        response: &mut [u8],
    ) -> Result<usize, SecureChannelError> {
        if response.len() < SECURE_CHANNEL_RESPONSE_CAPACITY {
            return Err(SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::wrong_length(),
            ));
        }
        // Invariant: each new mutual authentication starts from a clean SCP11
        // session state but keeps the staged OCE certificate intact.
        self.reset();
        let owner = current_management_authority_aid();
        let card_static_private =
            scp11_sd_private_key(&owner, key_version, key_id).ok_or_else(|| {
                SecureChannelError::Status(
                    crate::apdu_manager::ApduStatus::referenced_data_not_found(),
                )
            })?;
        let request = match profile {
            scp11::Scp11Profile::A => scp11::parse_scp11a_mutual_authenticate_request(data),
            scp11::Scp11Profile::B => scp11::parse_scp11b_internal_authenticate_request(data),
            scp11::Scp11Profile::C => scp11c::parse_mutual_authenticate_request(data),
        }
        .map_err(|_| SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_data()))?;
        let host_public = request.host_ephemeral_public;

        let mut card_public = [0u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
        let keys = match profile {
            scp11::Scp11Profile::A => {
                let mut private_key = [0u8; P256_PRIVATE_KEY_SIZE];
                crypto::p256_generate_keypair(&mut private_key, &mut card_public)
                    .map_err(|_| SecureChannelError::Rejected)?;
                let mut ephemeral_shared_secret = [0u8; P256_SHARED_SECRET_SIZE];
                crypto::p256_ecdh(&private_key, host_public, &mut ephemeral_shared_secret)
                    .map_err(|_| {
                        SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_data())
                    })?;
                let Some(staged_oce_public) = self.staged_oce_public() else {
                    return Err(SecureChannelError::Status(
                        crate::apdu_manager::ApduStatus::conditions_not_satisfied(),
                    ));
                };
                let shared_info = scp11::Scp11aSharedInfo::new(
                    request.key_usage_qualifier,
                    request.key_type,
                    request.key_length,
                    request.host_id,
                    if request.parameters.include_identifiers {
                        OXIDE_SE_SCP11_DEV_SIN
                    } else {
                        &[]
                    },
                    if request.parameters.include_identifiers {
                        OXIDE_SE_SCP11_DEV_SDIN
                    } else {
                        &[]
                    },
                )
                .map_err(|_| {
                    SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_data())
                })?;
                let mut static_shared_secret = [0u8; P256_SHARED_SECRET_SIZE];
                crypto::p256_ecdh(
                    &card_static_private,
                    staged_oce_public,
                    &mut static_shared_secret,
                )
                .map_err(|_| SecureChannelError::Rejected)?;
                scp11::derive_scp11a_session_keys(
                    &ephemeral_shared_secret,
                    &static_shared_secret,
                    &shared_info,
                )
            }
            scp11::Scp11Profile::B => {
                let mut private_key = [0u8; P256_PRIVATE_KEY_SIZE];
                crypto::p256_generate_keypair(&mut private_key, &mut card_public)
                    .map_err(|_| SecureChannelError::Rejected)?;
                let mut ephemeral_shared_secret = [0u8; P256_SHARED_SECRET_SIZE];
                crypto::p256_ecdh(&private_key, host_public, &mut ephemeral_shared_secret)
                    .map_err(|_| {
                        SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_data())
                    })?;
                let shared_info = scp11::Scp11aSharedInfo::new(
                    request.key_usage_qualifier,
                    request.key_type,
                    request.key_length,
                    request.host_id,
                    if request.parameters.include_identifiers {
                        OXIDE_SE_SCP11_DEV_SIN
                    } else {
                        &[]
                    },
                    if request.parameters.include_identifiers {
                        OXIDE_SE_SCP11_DEV_SDIN
                    } else {
                        &[]
                    },
                )
                .map_err(|_| {
                    SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_data())
                })?;
                let mut static_shared_secret = [0u8; P256_SHARED_SECRET_SIZE];
                crypto::p256_ecdh(&card_static_private, host_public, &mut static_shared_secret)
                    .map_err(|_| SecureChannelError::Rejected)?;
                scp11::derive_scp11b_session_keys(
                    &ephemeral_shared_secret,
                    &static_shared_secret,
                    &shared_info,
                )
            }
            scp11::Scp11Profile::C => {
                let Some(staged_oce_public) = self.staged_oce_public() else {
                    return Err(SecureChannelError::Status(
                        crate::apdu_manager::ApduStatus::conditions_not_satisfied(),
                    ));
                };
                crypto::p256_public_from_private(&card_static_private, &mut card_public)
                    .map_err(|_| SecureChannelError::Rejected)?;
                // Invariant: SCP11c has no card-ephemeral key pair. Both ECDH
                // contributions use the selected SD's static private key.
                let mut ephemeral_shared_secret = [0u8; P256_SHARED_SECRET_SIZE];
                crypto::p256_ecdh(
                    &card_static_private,
                    host_public,
                    &mut ephemeral_shared_secret,
                )
                .map_err(|_| {
                    SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_data())
                })?;
                let mut static_shared_secret = [0u8; P256_SHARED_SECRET_SIZE];
                crypto::p256_ecdh(
                    &card_static_private,
                    staged_oce_public,
                    &mut static_shared_secret,
                )
                .map_err(|_| SecureChannelError::Rejected)?;
                let shared_info = scp11c::SharedInfo::new(
                    &request,
                    OXIDE_SE_SCP11_DEV_CARD_GROUP_ID,
                )
                .map_err(|_| {
                    SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_data())
                })?;
                scp11c::derive_scp11c_session_keys(
                    &ephemeral_shared_secret,
                    &static_shared_secret,
                    &shared_info,
                )
            }
        }
        .map_err(|_| SecureChannelError::Rejected)?;
        let receipt_workspace =
            <&mut [u8; AES_CMAC_SIZE]>::try_from(&mut response[..AES_CMAC_SIZE])
                .map_err(|_| SecureChannelError::Rejected)?;
        scp11c::compute_mutual_authenticate_receipt(&keys, data, &card_public, receipt_workspace)
            .map_err(|_| SecureChannelError::Rejected)?;
        self.activate(profile, keys, receipt_workspace);
        let receipt = self
            .secure_messaging
            .as_ref()
            .ok_or(SecureChannelError::Rejected)?
            .initial_receipt();
        let len = scp11c::encode_mutual_authenticate_response(&card_public, receipt, response)
            .map_err(|_| SecureChannelError::Rejected)?;
        Ok(len)
    }

    #[inline(never)]
    fn activate(
        &mut self,
        profile: scp11::Scp11Profile,
        keys: scp11::Scp11SessionKeys,
        receipt: &[u8; AES_CMAC_SIZE],
    ) {
        self.active = true;
        self.profile = Some(profile);
        self.keys = Some(keys);
        self.secure_messaging = Some(scp11::Scp11SessionState::new(keys, *receipt));
    }
}

/// Minimal privilege view exposed by the active management context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityDomainPrivileges {
    bytes: [u8; 3],
    encoded_len: u8,
    developer_open: bool,
}

impl SecurityDomainPrivileges {
    /// GlobalPlatform first-byte bit declaring one Security Domain instance.
    const SECURITY_DOMAIN: u8 = 0x80;
    /// GlobalPlatform first-byte bit enabling DAP verification.
    const DAP_VERIFICATION: u8 = 0x40;
    /// GlobalPlatform first-byte bit enabling delegated management.
    const DELEGATED_MANAGEMENT: u8 = 0x20;
    /// GlobalPlatform first-byte bit enabling card lock.
    const CARD_LOCK: u8 = 0x10;
    /// GlobalPlatform first-byte bit enabling card terminate.
    const CARD_TERMINATE: u8 = 0x08;
    /// GlobalPlatform first-byte bit enabling card reset.
    const CARD_RESET: u8 = 0x04;
    /// GlobalPlatform first-byte bit enabling CVM management.
    const CVM_MANAGEMENT: u8 = 0x02;
    /// GlobalPlatform first-byte bit enabling mandated DAP verification.
    const MANDATED_DAP_VERIFICATION: u8 = 0x01;
    /// GlobalPlatform second-byte bit enabling trusted path.
    const TRUSTED_PATH: u8 = 0x80;
    /// GlobalPlatform second-byte bit enabling authorized management.
    const AUTHORIZED_MANAGEMENT: u8 = 0x40;
    /// GlobalPlatform second-byte bit enabling token verification.
    const TOKEN_VERIFICATION: u8 = 0x20;
    /// GlobalPlatform second-byte bit enabling global delete.
    const GLOBAL_DELETE: u8 = 0x10;
    /// GlobalPlatform second-byte bit enabling global lock.
    const GLOBAL_LOCK: u8 = 0x08;
    /// GlobalPlatform second-byte bit enabling global registry.
    const GLOBAL_REGISTRY: u8 = 0x04;
    /// GlobalPlatform second-byte bit enabling final application.
    const FINAL_APPLICATION: u8 = 0x02;
    /// GlobalPlatform second-byte bit enabling global service.
    const GLOBAL_SERVICE: u8 = 0x01;
    /// GlobalPlatform third-byte bit enabling receipt generation.
    const RECEIPT_GENERATION: u8 = 0x80;
    /// GlobalPlatform third-byte bit enabling ciphered load file data block.
    const CIPHERED_LOAD_FILE_DATA_BLOCK: u8 = 0x40;
    /// GlobalPlatform third-byte bit enabling contactless activation.
    const CONTACTLESS_ACTIVATION: u8 = 0x20;
    /// GlobalPlatform third-byte bit enabling contactless self-activation.
    const CONTACTLESS_SELF_ACTIVATION: u8 = 0x10;

    /// Returns a privilege set with no granted rights.
    pub const fn empty() -> Self {
        Self {
            bytes: [0; 3],
            encoded_len: 0,
            developer_open: false,
        }
    }

    /// Returns an unrestricted development privilege set.
    ///
    /// This bypass remains kernel-local and is only used by bootstrap or
    /// debug-oriented flows.
    pub const fn open() -> Self {
        Self {
            bytes: [0xff; 3],
            encoded_len: 3,
            developer_open: true,
        }
    }

    /// Decodes raw GlobalPlatform privilege bytes as carried by `INSTALL`.
    pub fn from_install_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > 3 {
            return None;
        }
        let mut encoded = [0u8; 3];
        let mut index = 0;
        while index < bytes.len() {
            encoded[index] = bytes[index];
            index += 1;
        }
        Some(Self {
            bytes: encoded,
            encoded_len: bytes.len() as u8,
            developer_open: false,
        })
    }

    /// Returns the number of encoded privilege bytes preserved from `INSTALL`.
    pub const fn encoded_len(self) -> usize {
        self.encoded_len as usize
    }

    /// Returns the raw privilege bytes preserved for this instance.
    pub const fn encoded_bytes(self) -> [u8; 3] {
        self.bytes
    }

    /// Returns the first GlobalPlatform privilege byte.
    pub const fn first_byte(self) -> u8 {
        self.bytes[0]
    }

    /// Returns true when the current instance is marked as a Security Domain.
    pub const fn is_security_domain(self) -> bool {
        self.developer_open || (self.first_byte() & Self::SECURITY_DOMAIN) != 0
    }

    /// Returns true when delegated management is granted.
    pub const fn has_delegated_management(self) -> bool {
        self.developer_open || (self.first_byte() & Self::DELEGATED_MANAGEMENT) != 0
    }

    /// Returns true if DAP verification is granted.
    pub const fn has_dap_verification(self) -> bool {
        self.developer_open || (self.first_byte() & Self::DAP_VERIFICATION) != 0
    }

    /// Returns true if card lock is granted.
    pub const fn may_lock_card(self) -> bool {
        self.developer_open || (self.first_byte() & Self::CARD_LOCK) != 0
    }

    /// Returns true if card termination is granted.
    pub const fn may_terminate_card(self) -> bool {
        self.developer_open || (self.first_byte() & Self::CARD_TERMINATE) != 0
    }

    /// Returns true if card reset is granted.
    pub const fn may_reset_card(self) -> bool {
        self.developer_open || (self.first_byte() & Self::CARD_RESET) != 0
    }

    /// Returns true if CVM management is granted.
    pub const fn may_manage_cvm(self) -> bool {
        self.developer_open || (self.first_byte() & Self::CVM_MANAGEMENT) != 0
    }

    /// Returns true if mandated DAP verification is granted.
    pub const fn has_mandated_dap_verification(self) -> bool {
        self.developer_open || (self.first_byte() & Self::MANDATED_DAP_VERIFICATION) != 0
    }

    /// Returns true if trusted-path services are granted.
    pub const fn may_use_trusted_path(self) -> bool {
        self.developer_open || (self.bytes[1] & Self::TRUSTED_PATH) != 0
    }

    /// Returns true if authorized management is granted.
    pub const fn has_authorized_management(self) -> bool {
        self.developer_open || (self.bytes[1] & Self::AUTHORIZED_MANAGEMENT) != 0
    }

    /// Returns true if token verification is granted.
    pub const fn may_verify_token(self) -> bool {
        self.developer_open || (self.bytes[1] & Self::TOKEN_VERIFICATION) != 0
    }

    /// Returns true if global deletion is granted.
    pub const fn may_global_delete(self) -> bool {
        self.developer_open || (self.bytes[1] & Self::GLOBAL_DELETE) != 0
    }

    /// Returns true if global lock is granted.
    pub const fn may_global_lock(self) -> bool {
        self.developer_open || (self.bytes[1] & Self::GLOBAL_LOCK) != 0
    }

    /// Returns true if global-registry access is granted.
    pub const fn may_global_registry(self) -> bool {
        self.developer_open || (self.bytes[1] & Self::GLOBAL_REGISTRY) != 0
    }

    /// Returns true if final-application authority is granted.
    pub const fn is_final_application(self) -> bool {
        self.developer_open || (self.bytes[1] & Self::FINAL_APPLICATION) != 0
    }

    /// Returns true if global service is granted.
    pub const fn may_global_service(self) -> bool {
        self.developer_open || (self.bytes[1] & Self::GLOBAL_SERVICE) != 0
    }

    /// Returns true if receipt generation is granted.
    pub const fn may_generate_receipt(self) -> bool {
        self.developer_open || (self.bytes[2] & Self::RECEIPT_GENERATION) != 0
    }

    /// Returns true if ciphered load-file data blocks are granted.
    pub const fn may_cipher_load_file_data_block(self) -> bool {
        self.developer_open || (self.bytes[2] & Self::CIPHERED_LOAD_FILE_DATA_BLOCK) != 0
    }

    /// Returns true if contactless activation is granted.
    pub const fn may_contactless_activate(self) -> bool {
        self.developer_open || (self.bytes[2] & Self::CONTACTLESS_ACTIVATION) != 0
    }

    /// Returns true if contactless self-activation is granted.
    pub const fn may_contactless_self_activate(self) -> bool {
        self.developer_open || (self.bytes[2] & Self::CONTACTLESS_SELF_ACTIVATION) != 0
    }

    /// Returns true when content loading is allowed under the current policy.
    pub const fn may_install_for_load(self) -> bool {
        self.developer_open || self.has_delegated_management() || self.has_authorized_management()
    }

    /// Returns true when instance installation is allowed under the current policy.
    pub const fn may_install_for_install(self) -> bool {
        self.developer_open || self.has_delegated_management() || self.has_authorized_management()
    }

    /// Returns true when applet management is allowed under the current policy.
    pub const fn may_manage_applet(self) -> bool {
        self.developer_open || self.has_delegated_management()
    }

    /// Returns true when lifecycle promotion to selectable is allowed.
    pub const fn may_make_selectable(self) -> bool {
        self.developer_open || self.has_delegated_management()
    }

    /// Returns true when managed content deletion is allowed.
    pub const fn may_delete_managed_content(self) -> bool {
        self.developer_open
            || self.has_delegated_management()
            || self.has_authorized_management()
            || self.may_global_delete()
    }

    /// Returns true when `PUT KEY` is allowed.
    pub const fn may_put_key(self) -> bool {
        self.developer_open || self.has_delegated_management() || self.has_authorized_management()
    }

    /// Returns true when this authority may exercise the current kernel-side
    /// management plane.
    pub const fn may_manage_security_domain_plane(self) -> bool {
        self.developer_open || self.has_delegated_management() || self.has_authorized_management()
    }

    /// Returns true when this authority may access the current kernel registry
    /// view beyond ordinary applet-only semantics.
    pub const fn may_access_registry_plane(self) -> bool {
        self.developer_open || self.has_delegated_management() || self.may_global_registry()
    }

    /// Returns true when `self` includes every right requested by `other`.
    ///
    /// Extension bytes are compared conservatively as raw bitfields until the
    /// runtime grows a richer interpretation for them.
    pub const fn contains(self, other: Self) -> bool {
        if self.developer_open {
            return true;
        }

        let lhs = self.encoded_bytes();
        let rhs = other.encoded_bytes();
        let mut index = 0;
        while index < 3 {
            if (lhs[index] & rhs[index]) != rhs[index] {
                return false;
            }
            index += 1;
        }
        true
    }
}

/// Parsed kernel-side view of `INSTALL [for load]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InstallForLoadCommand<'a> {
    pub package_aid: Aid,
    pub security_domain_aid: Aid,
    pub load_file_hash: &'a [u8],
    pub load_parameters: &'a [u8],
}

/// Parsed kernel-side view of `INSTALL [for install]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InstallForInstallCommand<'a> {
    pub package_aid: Aid,
    pub applet_aid: Aid,
    pub instance_aid: Aid,
    pub privileges: &'a [u8],
    pub install_parameters: &'a [u8],
}

/// Parsed kernel-side view of `PUT KEY`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PutKeyCommand<'a> {
    pub key_version: u8,
    pub key_id: u8,
    pub key_data: &'a [u8],
}

/// Decoded GlobalPlatform reference controls for one `PUT KEY` APDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PutKeyReferenceControl {
    pub key_version: u8,
    pub first_key_id: u8,
    pub multiple_keys: bool,
    pub last_command: bool,
}

impl PutKeyReferenceControl {
    const CONTROL_BIT: u8 = 0x80;
    const VALUE_MASK: u8 = 0x7f;

    /// Decodes `PUT KEY` P1/P2 according to the GP control-bit layout.
    pub const fn decode(p1: u8, p2: u8) -> Self {
        Self {
            key_version: p1 & Self::VALUE_MASK,
            first_key_id: p2 & Self::VALUE_MASK,
            multiple_keys: (p2 & Self::CONTROL_BIT) != 0,
            last_command: (p1 & Self::CONTROL_BIT) == 0,
        }
    }

    /// Returns the effective key identifier for one entry in the APDU payload.
    pub const fn key_id_for_entry(self, entry_index: usize) -> Option<u8> {
        if !self.multiple_keys && entry_index != 0 {
            return None;
        }
        if entry_index > u8::MAX as usize {
            return None;
        }
        let index = entry_index as u8;
        let Some(key_id) = self.first_key_id.checked_add(index) else {
            return None;
        };
        if key_id > Self::VALUE_MASK {
            return None;
        }
        Some(key_id)
    }
}

/// Parsed kernel-side view of `STORE DATA`.
pub struct StoreDataCommand<'a> {
    pub tag: u16,
    pub data: &'a [u8],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SetStatusCommand {
    pub target_kind: u8,
    pub target_state: u8,
    pub target_aid: Aid,
}

pub const SET_STATUS_KIND_PACKAGE: u8 = 0x20;
pub const SET_STATUS_KIND_APPLICATION: u8 = 0x40;
pub const SET_STATUS_KIND_SECURITY_DOMAIN: u8 = 0x80;
pub const SET_STATUS_STATE_UNLOCK: u8 = 0x00;
pub const SET_STATUS_STATE_LOCK: u8 = 0x80;

/// Tags handled by kernel-owned `GET DATA` flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetDataTag {
    CardRecognitionData,
    CardCapabilityInformation,
    LifeCycleState,
    Other(u16),
}

impl GetDataTag {
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::CardRecognitionData => 0x0066,
            Self::CardCapabilityInformation => 0x0067,
            Self::LifeCycleState => 0x9f70,
            Self::Other(tag) => tag,
        }
    }
}

fn copy_data_object(data: &[u8], out: &mut [u8]) -> Result<usize, ManagementError> {
    if out.len() < data.len() {
        return Err(ManagementError::Rejected);
    }
    out[..data.len()].copy_from_slice(data);
    Ok(data.len())
}

fn write_lifecycle_data(
    lifecycle: SecurityDomainLifecycle,
    out: &mut [u8],
) -> Result<usize, ManagementError> {
    copy_data_object(&[0x9f, 0x70, 0x01, lifecycle.as_byte()], out)
}

fn write_standard_get_data(
    tag: GetDataTag,
    lifecycle: SecurityDomainLifecycle,
    capabilities: rustlet_runtime::gp::SecurityDomainCapabilities,
    out: &mut [u8],
) -> Option<Result<usize, ManagementError>> {
    match tag {
        GetDataTag::LifeCycleState => Some(write_lifecycle_data(lifecycle, out)),
        GetDataTag::CardRecognitionData => Some(
            rustlet_runtime::gp::write_card_recognition_data(capabilities, out)
                .map_err(|_| ManagementError::Rejected),
        ),
        GetDataTag::CardCapabilityInformation if capabilities.has_secure_channel() => Some(
            rustlet_runtime::gp::write_card_capability_information(capabilities, out)
                .map_err(|_| ManagementError::Rejected),
        ),
        GetDataTag::CardCapabilityInformation => Some(Err(ManagementError::NotFound)),
        GetDataTag::Other(_) => None,
    }
}

fn kernel_security_domain_capabilities() -> rustlet_runtime::gp::SecurityDomainCapabilities {
    let mode = crate::core::target::secure_channel_mode();
    let scp03_s8 = mode.supports_scp03()
        && matches!(
            crate::core::target::kernel_scp03_profile(),
            crate::core::target::KernelScp03Profile::S8
        );
    let scp03_s16 = mode.supports_scp03()
        && matches!(
            crate::core::target::kernel_scp03_profile(),
            crate::core::target::KernelScp03Profile::S16
        );
    let scp11 = crate::core::target::scp11_profiles();
    rustlet_runtime::gp::SecurityDomainCapabilities {
        scp03_s8,
        scp03_s16,
        scp11a: mode.supports_scp11() && scp11.supports(scp11::Scp11Profile::A),
        scp11b: mode.supports_scp11() && scp11.supports(scp11::Scp11Profile::B),
        scp11c: mode.supports_scp11() && scp11.supports(scp11::Scp11Profile::C),
    }
}

fn load_registry_get_data(
    parent_sd_aid: &Aid,
    tag: GetDataTag,
    out: &mut [u8],
) -> Result<usize, ManagementError> {
    crate::selected_app::load_registry_data_object(parent_sd_aid, tag.as_u16(), out)
        .ok_or(ManagementError::Unsupported)
}

/// Parsed kernel-side view of `INITIALIZE UPDATE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitializeUpdateCommand<'a> {
    pub key_version: u8,
    pub key_id: u8,
    pub host_challenge: &'a [u8],
}

/// Result of a successful `INITIALIZE UPDATE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitializeUpdateContext {
    pub security_level: SecurityLevel,
    pub response_len: usize,
}

/// Parsed kernel-side view of `EXTERNAL AUTHENTICATE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalAuthenticateCommand<'a> {
    pub security_level: u8,
    pub data: &'a [u8],
}

/// Secure-channel establishment command seen by the generic APDU façade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegatedSecureChannelHeader {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub p3: u8,
}

/// Secure-channel establishment command seen by the generic APDU façade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecureChannelEstablishmentCommand<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub p3: u8,
    pub data: &'a [u8],
}

/// Coarse session phase exposed by secure-channel engines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureChannelPhase {
    Inactive,
    Initialized,
    Authenticated,
}

/// Minimal secure-channel state snapshot shared with the APDU façade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecureChannelSessionStateView {
    pub protocol: Option<SecureChannelProtocol>,
    pub policy_owner: Option<SecureChannelPolicyOwner>,
    pub phase: SecureChannelPhase,
    pub peer_authentication: SecureChannelPeerAuthentication,
    pub security_level: SecurityLevel,
    pub mac_len: usize,
}

impl SecureChannelSessionStateView {
    pub const fn inactive() -> Self {
        Self {
            protocol: None,
            policy_owner: None,
            phase: SecureChannelPhase::Inactive,
            peer_authentication: SecureChannelPeerAuthentication::None,
            security_level: SecurityLevel::None,
            mac_len: 0,
        }
    }

    pub const fn secure_channel_open(self) -> bool {
        matches!(self.phase, SecureChannelPhase::Authenticated)
    }

    /// Returns whether the selected profile protects response APDUs.
    pub const fn protects_response(self) -> bool {
        self.security_level.uses_response_mac()
    }
}

/// Applies protocol-level management restrictions to one authenticated session.
///
/// Security Domain privileges, hierarchy reachability, and backend hooks are
/// deliberately evaluated afterwards. This function only expresses restrictions
/// that a backend is never allowed to weaken.
pub const fn secure_channel_allows_management(
    session: SecureChannelSessionStateView,
    operation: ManagementOperation,
    target: ManagementTarget,
) -> bool {
    if !session.secure_channel_open() {
        return false;
    }

    if matches!(
        session.policy_owner,
        Some(SecureChannelPolicyOwner::RustletSecurityDomain)
    ) {
        // Structural registry reachability, privilege non-escalation, and the
        // Security Domain family hooks are still enforced after this gate.
        return true;
    }

    match session.protocol {
        Some(SecureChannelProtocol::Scp03) => {
            matches!(
                session.peer_authentication,
                SecureChannelPeerAuthentication::Owner
            )
        }
        Some(SecureChannelProtocol::Scp11(scp11::Scp11Profile::A)) => {
            matches!(
                session.peer_authentication,
                SecureChannelPeerAuthentication::Owner
            )
        }
        Some(SecureChannelProtocol::Scp11(scp11::Scp11Profile::B)) => {
            // SCP11b authenticates the card, not the OCE. Until an explicit
            // secondary OCE authentication mechanism is modeled, only the
            // read-only GET DATA family is exposed through this channel.
            matches!(
                session.peer_authentication,
                SecureChannelPeerAuthentication::CardOnly
            ) && matches!(
                operation,
                ManagementOperation::GetData | ManagementOperation::GetStatus
            )
        }
        Some(SecureChannelProtocol::Scp11(scp11::Scp11Profile::C)) => {
            match session.peer_authentication {
                SecureChannelPeerAuthentication::Owner => match operation {
                    ManagementOperation::PutKey | ManagementOperation::SetStatus => false,
                    ManagementOperation::Delete => !matches!(target, ManagementTarget::Key),
                    _ => true,
                },
                SecureChannelPeerAuthentication::Any => {
                    // The current profile deliberately omits BF20 processing.
                    // Amendment F still permits GET DATA without BF20.
                    matches!(
                        operation,
                        ManagementOperation::GetData | ManagementOperation::GetStatus
                    )
                }
                SecureChannelPeerAuthentication::None
                | SecureChannelPeerAuthentication::CardOnly => false,
            }
        }
        None => false,
    }
}

/// Applies the non-overridable management matrix to the active session binding.
///
/// This deliberately uses the kernel-owned binding rather than calling
/// `session_state()` again: a Rustlet-backed Security Domain reports its state
/// through the shared APDU page, which already contains the unwrapped
/// management command at this point.
pub fn active_secure_channel_allows_management(
    operation: ManagementOperation,
    target: ManagementTarget,
) -> bool {
    let protocol = active_security_domain_session_protocol();
    let delegated = active_security_domain_session_is_delegated();
    if protocol.is_none() && !delegated {
        return false;
    }
    secure_channel_allows_management(
        SecureChannelSessionStateView {
            protocol,
            policy_owner: Some(if delegated {
                SecureChannelPolicyOwner::RustletSecurityDomain
            } else {
                SecureChannelPolicyOwner::KernelProfile
            }),
            phase: SecureChannelPhase::Authenticated,
            peer_authentication: protocol
                .map(peer_authentication_for_protocol)
                .unwrap_or(SecureChannelPeerAuthentication::None),
            security_level: SecurityLevel::None,
            mac_len: 0,
        },
        operation,
        target,
    )
}

/// Result of one secure-channel establishment step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecureChannelEstablishmentResult {
    pub response_len: usize,
    pub response_location: SecureChannelEstablishmentResponseLocation,
}

/// Storage containing the establishment response bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureChannelEstablishmentResponseLocation {
    /// The establishment step has no response payload.
    None,
    /// The native Security Domain wrote into the caller-provided scratch.
    CallerScratch,
    /// SDDISPATCH left the response in the shared APDU payload.
    SharedApduPayload,
}

/// Kernel-owned wrapped APDU passed through the secure channel boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrappedCommandApdu<'a> {
    authenticated_prefix: [u8; 5],
    authenticated_prefix_len: u8,
    protected_data: &'a [u8],
    authenticated_data_len: u8,
    encrypted_data_offset: u8,
    encrypted_data_len: u8,
    mac_offset: u8,
    mac_len: u8,
}

impl<'a> WrappedCommandApdu<'a> {
    /// Creates a compact zero-copy descriptor over one protected APDU field.
    ///
    /// All offsets are relative to `protected_data`. Keeping field starts and
    /// lengths as bytes is valid because each short-APDU field is capped at
    /// 255 bytes. The backing slice may additionally contain the five-byte
    /// command header used by the legacy contiguous SCP11 MAC input.
    pub fn new(
        authenticated_prefix: &[u8],
        protected_data: &'a [u8],
        authenticated_data_len: usize,
        encrypted_data_offset: usize,
        encrypted_data_len: usize,
        mac_offset: usize,
        mac_len: usize,
    ) -> Option<Self> {
        if authenticated_prefix.len() > 5
            || authenticated_data_len > u8::MAX as usize
            || authenticated_data_len > protected_data.len()
            || encrypted_data_offset > u8::MAX as usize
            || encrypted_data_len > u8::MAX as usize
            || encrypted_data_offset.checked_add(encrypted_data_len)? > protected_data.len()
            || mac_offset > u8::MAX as usize
            || mac_len > u8::MAX as usize
            || mac_offset.checked_add(mac_len)? > protected_data.len()
        {
            return None;
        }
        let mut prefix = [0u8; 5];
        prefix[..authenticated_prefix.len()].copy_from_slice(authenticated_prefix);
        Some(Self {
            authenticated_prefix: prefix,
            authenticated_prefix_len: authenticated_prefix.len() as u8,
            protected_data,
            authenticated_data_len: authenticated_data_len as u8,
            encrypted_data_offset: encrypted_data_offset as u8,
            encrypted_data_len: encrypted_data_len as u8,
            mac_offset: mac_offset as u8,
            mac_len: mac_len as u8,
        })
    }

    pub fn authenticated_prefix(&self) -> &[u8] {
        &self.authenticated_prefix[..self.authenticated_prefix_len as usize]
    }

    pub fn authenticated_data(&self) -> &[u8] {
        &self.protected_data[..self.authenticated_data_len as usize]
    }

    pub fn data(&self) -> &[u8] {
        let start = self.encrypted_data_offset as usize;
        &self.protected_data[start..start + self.encrypted_data_len as usize]
    }

    pub fn mac(&self) -> &[u8] {
        let start = self.mac_offset as usize;
        &self.protected_data[start..start + self.mac_len as usize]
    }
}

/// Kernel-owned plaintext response before secure channel wrapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlainResponseApdu<'a> {
    pub bytes: &'a [u8],
    pub status: (u8, u8),
}

/// Lengths produced by one secure-channel wrapping operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrappedResponseLengths {
    pub data_len: usize,
    pub mac_len: usize,
}

/// Security Domain management authority seen by the kernel.
///
/// The kernel owns APDU parsing and lifecycle mutation. Implementations of
/// this trait only express authority, privileges, and policy decisions.
pub trait SecurityDomainManagement {
    /// Returns the management identity represented by this authority.
    fn aid(&self) -> Aid;

    /// Returns whether this authority is the root Security Domain.
    fn is_root_security_domain(&self) -> bool;

    /// Returns the effective privilege set granted to this authority.
    fn privileges(&self) -> SecurityDomainPrivileges;

    /// Returns whether this authority accepts management commands that do not
    /// come through one secure channel session.
    fn permits_management_without_secure_channel(&self) -> bool;

    /// Returns whether this authority accepts clear `SET STATUS` commands.
    fn permits_set_status_without_secure_channel(&self) -> bool;

    /// Validates `INSTALL [for load]` in the current management context.
    fn install_for_load(&self, command: &InstallForLoadCommand<'_>) -> Result<(), ManagementError>;

    /// Validates `INSTALL [for install]` in the current management context.
    fn install_for_install(
        &self,
        command: &InstallForInstallCommand<'_>,
    ) -> Result<(), ManagementError>;

    /// Validates deletion of one managed object.
    fn delete_aid(&self, aid: &Aid) -> Result<(), ManagementError>;

    /// Validates one `PUT KEY` command in the current management context.
    fn put_key(&self, command: &PutKeyCommand<'_>) -> Result<(), ManagementError>;

    /// Validates one `STORE DATA` command in the current management context.
    fn store_data(&self, command: &StoreDataCommand<'_>) -> Result<(), ManagementError>;

    /// Validates one `SET STATUS` lifecycle transition.
    fn set_status(&self, command: &SetStatusCommand) -> Result<(), ManagementError>;

    /// Returns management-scoped data for one `GET DATA` tag.
    fn get_data(&self, tag: GetDataTag, out: &mut [u8]) -> Result<usize, ManagementError>;

    /// Returns whether this authority may manage the given instance.
    fn may_manage_applet(&self, package_aid: &Aid, applet_aid: &Aid, instance_aid: &Aid) -> bool;

    /// Returns whether this authority may make the given instance selectable.
    fn may_make_selectable(&self, instance_aid: &Aid) -> bool;

    /// Returns whether this authority may exercise the current kernel
    /// management plane after the base privilege filter.
    fn may_manage_security_domain_plane(&self) -> bool;

    /// Returns whether this authority may access the current kernel registry
    /// plane after the base privilege filter.
    fn may_access_registry_plane(&self) -> bool;
}

/// Security Domain secure-channel engine seen by the kernel.
///
/// The APDU façade is protocol-agnostic: it only asks the active Security
/// Domain to advance secure-channel establishment, to expose a compact session
/// state view, and to unwrap/wrap protected APDUs.
pub trait SecurityDomainSecureChannel {
    /// Returns whether the requested secure-channel protocol is supported.
    fn supports_secure_channel_protocol(&self, protocol: SecureChannelProtocol) -> bool;

    /// Returns whether this Rustlet-backed Security Domain claims an
    /// establishment command not owned by the configured kernel profile.
    fn claims_delegated_secure_channel_command(&self, header: DelegatedSecureChannelHeader)
        -> bool;

    /// Advances one Security-Domain-owned establishment exchange.
    fn handle_delegated_secure_channel_command(
        &mut self,
        command: &SecureChannelEstablishmentCommand<'_>,
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError>;

    /// Advances one protocol-specific establishment step.
    fn handle_establishment(
        &mut self,
        command: &SecureChannelEstablishmentCommand<'_>,
        response_scratch: &mut [u8],
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError>;

    /// Returns the current compact session state view.
    fn session_state(&self) -> SecureChannelSessionStateView;

    /// Unwraps one protected command APDU into `out`.
    ///
    /// Invariant: the caller owns `out` and decides where the plaintext is
    /// staged next. Secure-channel engines must not allocate another APDU-sized
    /// temporary merely to return the result.
    fn unwrap_command_into(
        &mut self,
        apdu: &WrappedCommandApdu<'_>,
        out: &mut [u8],
    ) -> Result<usize, SecureChannelError>;

    /// Wraps one plaintext response APDU into caller-provided buffers.
    ///
    /// Invariant: `data_out` receives the clear or encrypted response payload,
    /// while `mac_out` receives the separate R-MAC when response authentication
    /// is active.
    fn wrap_response_into(
        &mut self,
        response: &PlainResponseApdu<'_>,
        data_out: &mut [u8],
        mac_out: &mut [u8],
    ) -> Result<WrappedResponseLengths, SecureChannelError>;

    /// Resets the current secure channel state.
    fn reset_secure_channel(&mut self);
}

/// Combined Security Domain authority boundary used by the kernel.
pub trait SecurityDomain: SecurityDomainManagement + SecurityDomainSecureChannel {}

impl<T> SecurityDomain for T where T: SecurityDomainManagement + SecurityDomainSecureChannel {}

/// Encodes Security Domain administrative privilege bytes for registry storage.
pub fn encode_administrative_state(
    privilege_bytes: &[u8],
) -> Option<[u8; KERNEL_SECURITY_DOMAIN_STATE_LEN]> {
    Some(KernelSecurityDomainAdministrativeState::from_install_bytes(privilege_bytes)?.encode())
}

/// Bootstrap management authority used when no real Security Domain is active.
///
/// This object is kernel-native. It is not executed in user mode and it does
/// not model a real GlobalPlatform Security Domain yet.
pub struct NullSecurityDomain;

impl NullSecurityDomain {
    /// Creates the unique kernel-side null authority singleton.
    pub const fn new() -> Self {
        Self
    }
}

impl Default for NullSecurityDomain {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityDomainManagement for NullSecurityDomain {
    fn aid(&self) -> Aid {
        current_management_authority_aid()
    }

    fn is_root_security_domain(&self) -> bool {
        self.aid() == root_security_domain_aid()
    }

    fn privileges(&self) -> SecurityDomainPrivileges {
        let root_aid = self.aid();
        if let Some(state) = crate::selected_app::find_security_domain_state_by_aid(&root_aid) {
            if let Some(decoded) = KernelSecurityDomainAdministrativeState::decode(state) {
                return decoded.privileges();
            }
        }
        SecurityDomainPrivileges::open()
    }

    fn permits_management_without_secure_channel(&self) -> bool {
        true
    }

    fn permits_set_status_without_secure_channel(&self) -> bool {
        true
    }

    fn install_for_load(
        &self,
        _command: &InstallForLoadCommand<'_>,
    ) -> Result<(), ManagementError> {
        if self.privileges().may_install_for_load() {
            Ok(())
        } else {
            Err(ManagementError::Rejected)
        }
    }

    fn install_for_install(
        &self,
        command: &InstallForInstallCommand<'_>,
    ) -> Result<(), ManagementError> {
        let Some(requested_privileges) =
            SecurityDomainPrivileges::from_install_bytes(command.privileges)
        else {
            return Err(ManagementError::Rejected);
        };
        let current_privileges = self.privileges();
        if current_privileges.may_install_for_install()
            && current_privileges.contains(requested_privileges)
        {
            Ok(())
        } else {
            Err(ManagementError::Rejected)
        }
    }

    fn delete_aid(&self, aid: &Aid) -> Result<(), ManagementError> {
        if !self.privileges().may_delete_managed_content()
            || crate::selected_app::find_managed_object_kind_by_aid(aid).is_none()
        {
            Err(ManagementError::Rejected)
        } else {
            Ok(())
        }
    }

    fn put_key(&self, _command: &PutKeyCommand<'_>) -> Result<(), ManagementError> {
        if self.privileges().may_put_key() {
            Ok(())
        } else {
            Err(ManagementError::Rejected)
        }
    }

    fn store_data(&self, _command: &StoreDataCommand<'_>) -> Result<(), ManagementError> {
        if self.privileges().may_access_registry_plane() {
            Ok(())
        } else {
            Err(ManagementError::Rejected)
        }
    }

    fn set_status(&self, _command: &SetStatusCommand) -> Result<(), ManagementError> {
        if self.privileges().may_access_registry_plane() {
            Ok(())
        } else {
            Err(ManagementError::Rejected)
        }
    }

    fn get_data(&self, tag: GetDataTag, out: &mut [u8]) -> Result<usize, ManagementError> {
        if let Some(result) = write_standard_get_data(
            tag,
            SecurityDomainLifecycle::Selectable,
            rustlet_runtime::gp::SecurityDomainCapabilities::none(),
            out,
        ) {
            return result;
        }
        load_registry_get_data(&self.aid(), tag, out)
    }

    fn may_manage_applet(
        &self,
        _package_aid: &Aid,
        _applet_aid: &Aid,
        _instance_aid: &Aid,
    ) -> bool {
        self.privileges().may_manage_applet()
    }

    fn may_make_selectable(&self, _instance_aid: &Aid) -> bool {
        self.privileges().may_make_selectable()
    }

    fn may_manage_security_domain_plane(&self) -> bool {
        self.privileges().may_manage_security_domain_plane()
    }

    fn may_access_registry_plane(&self) -> bool {
        self.privileges().may_access_registry_plane()
    }
}

impl SecurityDomainSecureChannel for NullSecurityDomain {
    fn supports_secure_channel_protocol(&self, _protocol: SecureChannelProtocol) -> bool {
        false
    }

    fn claims_delegated_secure_channel_command(
        &self,
        _header: DelegatedSecureChannelHeader,
    ) -> bool {
        false
    }

    fn handle_delegated_secure_channel_command(
        &mut self,
        _command: &SecureChannelEstablishmentCommand<'_>,
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
        Err(SecureChannelError::Unsupported)
    }

    fn handle_establishment(
        &mut self,
        _command: &SecureChannelEstablishmentCommand<'_>,
        _response_scratch: &mut [u8],
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
        Err(SecureChannelError::Unsupported)
    }

    fn session_state(&self) -> SecureChannelSessionStateView {
        SecureChannelSessionStateView::inactive()
    }

    fn unwrap_command_into(
        &mut self,
        apdu: &WrappedCommandApdu<'_>,
        out: &mut [u8],
    ) -> Result<usize, SecureChannelError> {
        let _ = apdu.authenticated_prefix();
        let _ = apdu.authenticated_data();
        let _ = apdu.mac();
        copy_unwrapped_data_into(apdu.data(), out)
    }

    fn wrap_response_into(
        &mut self,
        _response: &PlainResponseApdu<'_>,
        _data_out: &mut [u8],
        _mac_out: &mut [u8],
    ) -> Result<WrappedResponseLengths, SecureChannelError> {
        Ok(WrappedResponseLengths {
            data_len: 0,
            mac_len: 0,
        })
    }

    fn reset_secure_channel(&mut self) {}
}

/// Kernel proxy delegating management decisions to the selected Rustlet SD.
pub struct RustletSecurityDomainProxy;

impl RustletSecurityDomainProxy {
    /// Creates the unique kernel-side Rustlet SD proxy singleton.
    pub const fn new() -> Self {
        Self
    }
}

impl Default for RustletSecurityDomainProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityDomainManagement for RustletSecurityDomainProxy {
    fn aid(&self) -> Aid {
        current_management_authority_aid()
    }

    fn is_root_security_domain(&self) -> bool {
        self.aid() == root_security_domain_aid()
    }

    fn privileges(&self) -> SecurityDomainPrivileges {
        let privilege_bytes =
            crate::selected_app::security_domain_privilege_bytes_by_aid(&self.aid())
                .unwrap_or([0, 0, 0]);
        SecurityDomainPrivileges::from_install_bytes(&privilege_bytes)
            .unwrap_or_else(SecurityDomainPrivileges::empty)
    }

    fn permits_management_without_secure_channel(&self) -> bool {
        false
    }

    fn permits_set_status_without_secure_channel(&self) -> bool {
        false
    }

    fn install_for_load(&self, command: &InstallForLoadCommand<'_>) -> Result<(), ManagementError> {
        if !self.privileges().may_install_for_load() {
            return Err(ManagementError::Rejected);
        }
        status_to_management_result(crate::selected_app::security_domain_authorize_load(
            &command.package_aid,
        ))
    }

    fn install_for_install(
        &self,
        command: &InstallForInstallCommand<'_>,
    ) -> Result<(), ManagementError> {
        let Some(requested_privileges) =
            SecurityDomainPrivileges::from_install_bytes(command.privileges)
        else {
            return Err(ManagementError::Rejected);
        };
        let current_privileges = self.privileges();
        if !current_privileges.may_install_for_install()
            || !current_privileges.contains(requested_privileges)
        {
            return Err(ManagementError::Rejected);
        }
        status_to_management_result(crate::selected_app::security_domain_authorize_install(
            &command.package_aid,
            &command.applet_aid,
            &command.instance_aid,
            command.privileges,
            command.install_parameters,
        ))
    }

    fn delete_aid(&self, aid: &Aid) -> Result<(), ManagementError> {
        if !self.privileges().may_delete_managed_content() {
            return Err(ManagementError::Rejected);
        }
        if crate::selected_app::find_managed_object_kind_by_aid(aid).is_none() {
            return Err(ManagementError::Rejected);
        }
        status_to_management_result(crate::selected_app::security_domain_delete_aid(aid))
    }

    fn put_key(&self, command: &PutKeyCommand<'_>) -> Result<(), ManagementError> {
        if !self.privileges().may_put_key() {
            return Err(ManagementError::Rejected);
        }
        status_to_management_result(crate::selected_app::security_domain_authorize_put_key(
            command.key_version,
            command.key_id,
            command.key_data,
        ))
    }

    fn store_data(&self, command: &StoreDataCommand<'_>) -> Result<(), ManagementError> {
        if !self.privileges().may_access_registry_plane() {
            return Err(ManagementError::Rejected);
        }
        status_to_management_result(crate::selected_app::security_domain_authorize_store_data(
            command.tag,
            command.data,
        ))
    }

    fn set_status(&self, command: &SetStatusCommand) -> Result<(), ManagementError> {
        if !self.privileges().may_access_registry_plane() {
            return Err(ManagementError::Rejected);
        }
        status_to_management_result(crate::selected_app::security_domain_authorize_set_status(
            command.target_kind,
            command.target_state,
            &command.target_aid,
        ))
    }

    fn get_data(&self, tag: GetDataTag, out: &mut [u8]) -> Result<usize, ManagementError> {
        match crate::selected_app::security_domain_get_data(tag.as_u16(), out)
            .map_err(status_to_management_error)
        {
            Err(ManagementError::Unsupported) => {
                match tag {
                    GetDataTag::CardRecognitionData => {
                        return rustlet_runtime::gp::write_card_recognition_data(
                            rustlet_runtime::gp::SecurityDomainCapabilities::none(),
                            out,
                        )
                        .map_err(|_| ManagementError::Rejected);
                    }
                    GetDataTag::CardCapabilityInformation => {
                        return Err(ManagementError::NotFound);
                    }
                    GetDataTag::LifeCycleState | GetDataTag::Other(_) => {}
                }
                load_registry_get_data(&self.aid(), tag, out)
            }
            result => result,
        }
    }

    fn may_manage_applet(&self, package_aid: &Aid, applet_aid: &Aid, instance_aid: &Aid) -> bool {
        if !self.privileges().may_manage_applet() {
            return false;
        }
        crate::selected_app::security_domain_may_manage_applet(
            package_aid,
            applet_aid,
            instance_aid,
        )
    }

    fn may_make_selectable(&self, instance_aid: &Aid) -> bool {
        if !self.privileges().may_make_selectable() {
            return false;
        }
        crate::selected_app::security_domain_may_make_selectable(instance_aid)
    }

    fn may_manage_security_domain_plane(&self) -> bool {
        self.privileges().may_manage_security_domain_plane()
    }

    fn may_access_registry_plane(&self) -> bool {
        self.privileges().may_access_registry_plane()
    }
}

impl SecurityDomainSecureChannel for RustletSecurityDomainProxy {
    fn supports_secure_channel_protocol(&self, protocol: SecureChannelProtocol) -> bool {
        crate::selected_app::security_domain_supports_secure_channel_protocol(protocol)
    }

    fn claims_delegated_secure_channel_command(
        &self,
        header: DelegatedSecureChannelHeader,
    ) -> bool {
        crate::selected_app::security_domain_claims_delegated_secure_channel_command(header)
    }

    fn handle_delegated_secure_channel_command(
        &mut self,
        command: &SecureChannelEstablishmentCommand<'_>,
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
        let response_len =
            crate::selected_app::security_domain_handle_delegated_secure_channel_command(command)
                .map_err(SecureChannelError::Status)?;
        bind_delegated_session_to_active_security_domain_instance();
        Ok(SecureChannelEstablishmentResult {
            response_len,
            response_location: if response_len == 0 {
                SecureChannelEstablishmentResponseLocation::None
            } else {
                SecureChannelEstablishmentResponseLocation::SharedApduPayload
            },
        })
    }

    fn handle_establishment(
        &mut self,
        command: &SecureChannelEstablishmentCommand<'_>,
        _response_scratch: &mut [u8],
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
        let mode = crate::core::target::secure_channel_mode();
        let response_len = match command.ins {
            0x2A if mode.supports_scp11() => {
                let ca_public = scp11_ca_kloc_public_key(&self.aid(), command.p1, command.p2)
                    .ok_or_else(|| {
                        SecureChannelError::Status(
                            crate::apdu_manager::ApduStatus::referenced_data_not_found(),
                        )
                    })?;
                let certificate = scp11c::verify_oce_certificate(&ca_public, command.data)
                    .map_err(|_| {
                        SecureChannelError::Status(
                            crate::apdu_manager::ApduStatus::certificate_verification_failed(),
                        )
                    })?;
                crate::selected_app::security_domain_scp11_stage_oce_certificate(
                    command.p1,
                    command.p2,
                    certificate.public_key(),
                    certificate.subject_id(),
                    certificate.discretionary_data(),
                )
                .map_err(SecureChannelError::Status)?;
                0
            }
            0x50 if mode.supports_scp03() => {
                let response_len = crate::selected_app::security_domain_initialize_update(
                    command.p1,
                    command.p2,
                    command.data,
                )
                .map_err(SecureChannelError::Status)?;
                bind_session_to_active_security_domain_instance(SecureChannelProtocol::Scp03);
                response_len
            }
            0x82 if command.p2 == 0x00 && mode.supports_scp03() => {
                let _ = crate::selected_app::security_domain_external_authenticate(
                    command.cla,
                    command.p1,
                    command.p2,
                    command.data,
                )
                .map_err(SecureChannelError::Status)?;
                bind_session_to_active_security_domain_instance(SecureChannelProtocol::Scp03);
                0
            }
            0x82 if mode.supports_scp11() => {
                let profile =
                    scp11::detect_mutual_authenticate_profile(command.data).map_err(|_| {
                        SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_data())
                    })?;
                if !crate::core::target::scp11_profiles().supports(profile) {
                    return Err(SecureChannelError::Unsupported);
                }
                let response_len = match profile {
                    scp11::Scp11Profile::A => {
                        let request = scp11::parse_scp11a_mutual_authenticate_request(command.data)
                            .map_err(|_| {
                                SecureChannelError::Status(
                                    crate::apdu_manager::ApduStatus::wrong_data(),
                                )
                            })?;
                        crate::selected_app::security_domain_scp11a_mutual_authenticate(
                            command.p1, command.p2, &request,
                        )
                        .map_err(SecureChannelError::Status)?
                    }
                    scp11::Scp11Profile::C => {
                        let request = scp11c::parse_mutual_authenticate_request(command.data)
                            .map_err(|_| {
                                SecureChannelError::Status(
                                    crate::apdu_manager::ApduStatus::wrong_data(),
                                )
                            })?;
                        crate::selected_app::security_domain_scp11c_mutual_authenticate(
                            command.p1, command.p2, &request,
                        )
                        .map_err(SecureChannelError::Status)?
                    }
                    scp11::Scp11Profile::B => return Err(SecureChannelError::Unsupported),
                };
                bind_session_to_active_security_domain_instance(SecureChannelProtocol::Scp11(
                    profile,
                ));
                response_len
            }
            0x88 if mode.supports_scp11() => match crate::core::target::scp11_profiles()
                .internal_authenticate_profile()
            {
                Some(scp11::Scp11Profile::B) => {
                    let request = scp11::parse_scp11b_internal_authenticate_request(command.data)
                        .map_err(|_| {
                        SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_data())
                    })?;
                    let response_len =
                        crate::selected_app::security_domain_scp11b_internal_authenticate(
                            command.p1, command.p2, &request,
                        )
                        .map_err(SecureChannelError::Status)?;
                    bind_session_to_active_security_domain_instance(SecureChannelProtocol::Scp11(
                        scp11::Scp11Profile::B,
                    ));
                    response_len
                }
                _ => return Err(SecureChannelError::Unsupported),
            },
            _ => return Err(SecureChannelError::Unsupported),
        };

        Ok(SecureChannelEstablishmentResult {
            response_len,
            response_location: if response_len == 0 {
                SecureChannelEstablishmentResponseLocation::None
            } else {
                // Invariant: SDDISPATCH and the transport share the gate-page
                // payload, so returning a length must not trigger a copy.
                SecureChannelEstablishmentResponseLocation::SharedApduPayload
            },
        })
    }

    fn session_state(&self) -> SecureChannelSessionStateView {
        let security_level = crate::selected_app::security_domain_current_security_level()
            .and_then(SecurityLevel::from_selected_bits)
            .unwrap_or(SecurityLevel::None);
        let secure_channel_open = crate::selected_app::security_domain_secure_channel_open();
        let mac_len = crate::selected_app::security_domain_current_mac_len().unwrap_or(0);
        let phase = if secure_channel_open {
            SecureChannelPhase::Authenticated
        } else if security_level == SecurityLevel::None && mac_len != 0 {
            SecureChannelPhase::Initialized
        } else {
            SecureChannelPhase::Inactive
        };

        SecureChannelSessionStateView {
            protocol: if secure_channel_open || mac_len != 0 {
                active_security_domain_session_protocol()
            } else {
                None
            },
            policy_owner: if secure_channel_open || mac_len != 0 {
                Some(if active_security_domain_session_is_delegated() {
                    SecureChannelPolicyOwner::RustletSecurityDomain
                } else {
                    SecureChannelPolicyOwner::KernelProfile
                })
            } else {
                None
            },
            phase,
            peer_authentication: active_security_domain_session_protocol()
                .map(peer_authentication_for_protocol)
                .unwrap_or(SecureChannelPeerAuthentication::None),
            security_level,
            mac_len,
        }
    }

    fn unwrap_command_into(
        &mut self,
        apdu: &WrappedCommandApdu<'_>,
        out: &mut [u8],
    ) -> Result<usize, SecureChannelError> {
        let data_len = crate::selected_app::security_domain_unwrap_command(
            apdu.authenticated_prefix(),
            apdu.authenticated_data(),
            apdu.data(),
            apdu.mac(),
            out,
        )
        .map_err(status_to_secure_channel_error)?;
        Ok(data_len)
    }

    fn wrap_response_into(
        &mut self,
        response: &PlainResponseApdu<'_>,
        data_out: &mut [u8],
        mac_out: &mut [u8],
    ) -> Result<WrappedResponseLengths, SecureChannelError> {
        let (data_len, mac_len) = crate::selected_app::security_domain_wrap_response(
            response.bytes,
            response.status,
            data_out,
            mac_out,
        )
        .map_err(status_to_secure_channel_error)?;

        Ok(WrappedResponseLengths { data_len, mac_len })
    }

    fn reset_secure_channel(&mut self) {
        crate::selected_app::security_domain_reset_secure_channel()
    }
}

/// Kernel-native Security Domain engine implementing management and SCP03 in-kernel.
///
/// It owns the authority-local policy and the session lifecycle. Pure SCP03
/// cryptographic transforms remain delegated to `core::scp03`.
struct KernelSecurityDomainEngine {
    config: KernelSecurityDomainConfig,
    administrative_state: KernelSecurityDomainAdministrativeState,
    session: SecurityDomainSession,
    scp11_session: Scp11Session,
}

/// Kernel-native Security Domain configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelSecurityDomainConfig {
    pub scp03_profile: Scp03Profile,
}

impl KernelSecurityDomainConfig {
    /// Returns the development SCP03 profile bootstrapped by the kernel.
    pub const fn from_build() -> Self {
        let scp03_profile = match crate::core::target::kernel_scp03_profile() {
            crate::core::target::KernelScp03Profile::S8 => Scp03Profile::S8,
            crate::core::target::KernelScp03Profile::S16 => Scp03Profile::S16,
        };
        Self { scp03_profile }
    }
}

impl KernelSecurityDomainEngine {
    const DEFAULT_KEY_VERSION: u8 = 0x01;
    const DEFAULT_KEY_ID: u8 = 0x03;

    /// Creates the default kernel-native Security Domain engine.
    pub const fn new() -> Self {
        Self::with_config(KernelSecurityDomainConfig::from_build())
    }

    /// Creates the engine with one explicit SCP03 profile configuration.
    pub const fn with_config(config: KernelSecurityDomainConfig) -> Self {
        Self {
            config,
            administrative_state: KernelSecurityDomainAdministrativeState::open(),
            session: SecurityDomainSession::inactive(),
            scp11_session: Scp11Session::inactive(),
        }
    }

    /// Formats the `INITIALIZE UPDATE` response from the currently derived session.
    fn initialize_update_response(
        &self,
        card_challenge: &[u8],
        response: &mut [u8],
    ) -> InitializeUpdateContext {
        let challenge_len = self.config.scp03_profile.challenge_len();
        let cryptogram_len = self.config.scp03_profile.cryptogram_len();
        let response_len = 12 + challenge_len + cryptogram_len;
        let Some(material) = self
            .session
            .material
            .filter(|_| response.len() >= response_len)
        else {
            return InitializeUpdateContext {
                security_level: SecurityLevel::None,
                response_len: 0,
            };
        };
        // Invariant: this response keeps the GP SCP03 field layout owned by the kernel.
        // The reusable caller scratch may still contain an earlier transform,
        // so every byte in the declared response is initialized here.
        response[..response_len].fill(0);
        response[10] = self.session.key_version;
        // SCP identifier 03, not the implementation's internal key-object ID.
        response[11] = 0x03;
        response[12..12 + challenge_len].copy_from_slice(card_challenge);
        response[12 + challenge_len..12 + challenge_len + cryptogram_len]
            .copy_from_slice(&material.card_cryptogram[..cryptogram_len]);

        InitializeUpdateContext {
            security_level: SecurityLevel::None,
            response_len,
        }
    }

    /// Rejects management commands unless one authenticated secure channel is
    /// active for this Security Domain instance.
    fn require_encrypted_management(&self) -> Result<(), ManagementError> {
        let bound_to_active_instance =
            active_security_domain_session_instance_aid() == Some(self.aid());
        let scp03_management_open = self.session.state == Scp03SessionState::Authenticated
            && self.session.security_level == SecurityLevel::CmacAndEnc;
        let scp11_management_open = self.scp11_session.active;

        if bound_to_active_instance && (scp03_management_open || scp11_management_open) {
            return Ok(());
        }

        Err(ManagementError::Rejected)
    }

    /// Returns the administrative state currently enforced by the engine.
    fn administrative_state(&self) -> KernelSecurityDomainAdministrativeState {
        let aid = self.aid();
        if let Some(state) = crate::selected_app::find_security_domain_state_by_aid(&aid) {
            if let Some(decoded) = KernelSecurityDomainAdministrativeState::decode(state) {
                return decoded;
            }
        }
        self.administrative_state
    }

    /// Resolves the GP key-version selector to the internal SCP03 keyset.
    fn resolve_requested_keyset(&self, key_version: u8, _p2: u8) -> (u8, u8) {
        (
            if key_version == 0x00 {
                Self::DEFAULT_KEY_VERSION
            } else {
                key_version
            },
            Self::DEFAULT_KEY_ID,
        )
    }

    #[inline(never)]
    fn perform_security_operation(
        &mut self,
        ca_key_version: u8,
        ca_key_id: u8,
        data: &[u8],
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
        if !crate::core::target::scp11_profiles().supports_pso_certificate() {
            return Err(SecureChannelError::Unsupported);
        }
        let ca_public = scp11_ca_kloc_public_key(&self.aid(), ca_key_version, ca_key_id)
            .ok_or_else(|| {
                SecureChannelError::Status(
                    crate::apdu_manager::ApduStatus::referenced_data_not_found(),
                )
            })?;
        let certificate = scp11c::verify_oce_certificate(&ca_public, data).map_err(|_| {
            SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::certificate_verification_failed(),
            )
        })?;
        self.scp11_session
            .stage_oce_certificate(&certificate)
            .map_err(|_| {
                SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_data())
            })?;
        Ok(SecureChannelEstablishmentResult {
            response_len: 0,
            response_location: SecureChannelEstablishmentResponseLocation::None,
        })
    }

    #[inline(never)]
    fn initialize_update(
        &mut self,
        p1: u8,
        p2: u8,
        data: &[u8],
        response: &mut [u8],
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
        self.scp11_session.reset();
        let command = InitializeUpdateCommand {
            key_version: p1,
            key_id: p2,
            host_challenge: data,
        };
        let profile = self.config.scp03_profile;
        if command.host_challenge.len() != profile.challenge_len() {
            return Err(SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::wrong_length(),
            ));
        }

        if command.key_id != 0x00 {
            self.session.reset();
            return Err(SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::incorrect_p1_p2(),
            ));
        }

        let (key_version, _) = self.resolve_requested_keyset(command.key_version, command.key_id);
        let Some((static_keys, key_id)) =
            crate::selected_app::load_scp03_static_keys_for_version(&self.aid(), key_version)
        else {
            self.session.reset();
            return Err(SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::referenced_data_not_found(),
            ));
        };
        self.session.key_version = key_version;
        self.session.key_index = key_id;
        let mut card_challenge = [0u8; scp03::S16_CHALLENGE_LEN];
        crate::core::crypto::fill_random(&mut card_challenge[..profile.challenge_len()]).map_err(
            |_| {
                self.session.reset();
                SecureChannelError::Status(
                    crate::apdu_manager::ApduStatus::conditions_not_satisfied(),
                )
            },
        )?;
        let material = scp03::derive_session(
            profile,
            &static_keys,
            command.host_challenge,
            &card_challenge[..profile.challenge_len()],
        )
        .map_err(|_| {
            self.session.reset();
            SecureChannelError::Rejected
        })?;
        self.session.material = Some(material);
        self.session.secure_messaging = None;
        self.session.security_level = SecurityLevel::None;
        self.session.state = Scp03SessionState::Initialized;
        bind_session_to_active_security_domain_instance(SecureChannelProtocol::Scp03);
        let context =
            self.initialize_update_response(&card_challenge[..profile.challenge_len()], response);
        if context.response_len == 0 {
            return Err(SecureChannelError::Rejected);
        }
        Ok(SecureChannelEstablishmentResult {
            response_len: context.response_len,
            response_location: SecureChannelEstablishmentResponseLocation::CallerScratch,
        })
    }

    #[inline(never)]
    fn external_authenticate(
        &mut self,
        cla: u8,
        requested_security_level: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
        let Some(security_level) =
            security_level_from_external_authenticate_p1(requested_security_level)
        else {
            self.session.reset();
            return Err(SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::incorrect_p1_p2(),
            ));
        };
        let Some(material) = self.session.material else {
            return Err(SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::conditions_not_satisfied(),
            ));
        };
        let profile = self.config.scp03_profile;
        if self.session.state != Scp03SessionState::Initialized {
            return Err(SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::conditions_not_satisfied(),
            ));
        }
        if cla != 0x84 || p2 != 0x00 {
            self.session.reset();
            return Err(SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::incorrect_p1_p2(),
            ));
        }
        let expected_data_len = profile.cryptogram_len() + profile.mac_len();
        if data.len() != expected_data_len {
            self.session.reset();
            return Err(SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::wrong_length(),
            ));
        }
        let data_len = u8::try_from(data.len()).map_err(|_| {
            SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_length())
        })?;
        let command_header = [cla, 0x82, requested_security_level, p2, data_len];
        let initial_mac_chain =
            scp03::verify_external_authenticate(profile, &material, &command_header, data)
                .map_err(|error| {
                    self.session.reset();
                    match error {
                        scp03::Scp03Error::AuthenticationFailed => SecureChannelError::Status(
                            crate::apdu_manager::ApduStatus::authentication_failed(),
                        ),
                        scp03::Scp03Error::InvalidProfileLength => SecureChannelError::Status(
                            crate::apdu_manager::ApduStatus::wrong_length(),
                        ),
                        _ => SecureChannelError::Rejected,
                    }
                })?;

        self.session.state = Scp03SessionState::Authenticated;
        self.session.security_level = security_level;
        self.session
            .activate_secure_messaging_state(initial_mac_chain);
        bind_session_to_active_security_domain_instance(SecureChannelProtocol::Scp03);
        Ok(SecureChannelEstablishmentResult {
            response_len: 0,
            response_location: SecureChannelEstablishmentResponseLocation::None,
        })
    }

    #[inline(never)]
    fn mutual_authenticate(
        &mut self,
        profile: scp11::Scp11Profile,
        key_version: u8,
        key_id: u8,
        data: &[u8],
        response: &mut [u8],
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
        self.session.reset();
        if !crate::core::target::scp11_profiles().supports(profile) {
            return Err(SecureChannelError::Unsupported);
        }
        let response_len =
            self.scp11_session
                .mutual_authenticate(profile, key_version, key_id, data, response)?;
        bind_session_to_active_security_domain_instance(SecureChannelProtocol::Scp11(profile));
        Ok(SecureChannelEstablishmentResult {
            response_len,
            response_location: SecureChannelEstablishmentResponseLocation::CallerScratch,
        })
    }
}

impl SecurityDomainManagement for KernelSecurityDomainEngine {
    fn aid(&self) -> Aid {
        current_management_authority_aid()
    }

    fn is_root_security_domain(&self) -> bool {
        self.aid() == root_security_domain_aid()
    }

    fn privileges(&self) -> SecurityDomainPrivileges {
        self.administrative_state().privileges()
    }

    fn permits_management_without_secure_channel(&self) -> bool {
        false
    }

    fn permits_set_status_without_secure_channel(&self) -> bool {
        false
    }

    fn install_for_load(
        &self,
        _command: &InstallForLoadCommand<'_>,
    ) -> Result<(), ManagementError> {
        let state = self.administrative_state();
        if !state.may_manage() || !state.privileges().may_install_for_load() {
            return Err(ManagementError::Rejected);
        }
        self.require_encrypted_management()
    }

    fn install_for_install(
        &self,
        command: &InstallForInstallCommand<'_>,
    ) -> Result<(), ManagementError> {
        let Some(requested_privileges) =
            SecurityDomainPrivileges::from_install_bytes(command.privileges)
        else {
            return Err(ManagementError::Rejected);
        };
        let state = self.administrative_state();
        let current_privileges = state.privileges();
        if !state.may_manage()
            || !current_privileges.may_install_for_install()
            || !current_privileges.contains(requested_privileges)
        {
            return Err(ManagementError::Rejected);
        }
        self.require_encrypted_management()
    }

    fn delete_aid(&self, aid: &Aid) -> Result<(), ManagementError> {
        let state = self.administrative_state();
        if !state.may_manage() || !state.privileges().may_delete_managed_content() {
            return Err(ManagementError::Rejected);
        }
        if crate::selected_app::find_managed_object_kind_by_aid(aid).is_none() {
            return Err(ManagementError::Rejected);
        }
        self.require_encrypted_management()
    }

    fn put_key(&self, _command: &PutKeyCommand<'_>) -> Result<(), ManagementError> {
        let state = self.administrative_state();
        if !state.may_manage() || !state.privileges().may_put_key() {
            return Err(ManagementError::Rejected);
        }
        self.require_encrypted_management()
    }

    fn store_data(&self, _command: &StoreDataCommand<'_>) -> Result<(), ManagementError> {
        let state = self.administrative_state();
        if !state.may_manage() || !state.privileges().may_access_registry_plane() {
            return Err(ManagementError::Rejected);
        }
        self.require_encrypted_management()
    }

    fn set_status(&self, _command: &SetStatusCommand) -> Result<(), ManagementError> {
        let state = self.administrative_state();
        if !state.may_manage() || !state.privileges().may_access_registry_plane() {
            return Err(ManagementError::Rejected);
        }
        self.require_encrypted_management()
    }

    fn get_data(&self, tag: GetDataTag, out: &mut [u8]) -> Result<usize, ManagementError> {
        if let Some(result) = write_standard_get_data(
            tag,
            self.administrative_state().lifecycle(),
            kernel_security_domain_capabilities(),
            out,
        ) {
            return result;
        }
        load_registry_get_data(&self.aid(), tag, out)
    }

    fn may_manage_applet(&self, _package_aid: &Aid, _applet_aid: &Aid, instance_aid: &Aid) -> bool {
        let _ = instance_aid;
        let state = self.administrative_state();
        state.may_manage() && state.privileges().may_manage_applet()
    }

    fn may_make_selectable(&self, instance_aid: &Aid) -> bool {
        let _ = instance_aid;
        let state = self.administrative_state();
        state.may_manage() && state.privileges().may_make_selectable()
    }

    fn may_manage_security_domain_plane(&self) -> bool {
        let state = self.administrative_state();
        state.may_manage() && state.privileges().may_manage_security_domain_plane()
    }

    fn may_access_registry_plane(&self) -> bool {
        let state = self.administrative_state();
        state.may_manage() && state.privileges().may_access_registry_plane()
    }
}

impl SecurityDomainSecureChannel for KernelSecurityDomainEngine {
    fn supports_secure_channel_protocol(&self, protocol: SecureChannelProtocol) -> bool {
        match protocol {
            SecureChannelProtocol::Scp03 => {
                crate::core::target::secure_channel_mode().supports_scp03()
            }
            SecureChannelProtocol::Scp11(profile) => {
                crate::core::target::secure_channel_mode().supports_scp11()
                    && crate::core::target::scp11_profiles().supports(profile)
            }
        }
    }

    fn claims_delegated_secure_channel_command(
        &self,
        _header: DelegatedSecureChannelHeader,
    ) -> bool {
        false
    }

    fn handle_delegated_secure_channel_command(
        &mut self,
        _command: &SecureChannelEstablishmentCommand<'_>,
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
        Err(SecureChannelError::Unsupported)
    }

    fn handle_establishment(
        &mut self,
        command: &SecureChannelEstablishmentCommand<'_>,
        response_scratch: &mut [u8],
    ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
        let mode = crate::core::target::secure_channel_mode();
        if !mode.supports_scp03() && !mode.supports_scp11() {
            return Err(SecureChannelError::Unsupported);
        }
        match command.ins {
            0x2A if mode.supports_scp11() => {
                self.perform_security_operation(command.p1, command.p2, command.data)
            }
            0x50 if mode.supports_scp03() => {
                self.initialize_update(command.p1, command.p2, command.data, response_scratch)
            }
            0x82 if command.p2 == 0x00 && mode.supports_scp03() => {
                self.external_authenticate(command.cla, command.p1, command.p2, command.data)
            }
            0x82 if mode.supports_scp11() => {
                let profile =
                    scp11::detect_mutual_authenticate_profile(command.data).map_err(|_| {
                        SecureChannelError::Status(crate::apdu_manager::ApduStatus::wrong_data())
                    })?;
                if !matches!(profile, scp11::Scp11Profile::A | scp11::Scp11Profile::C) {
                    return Err(SecureChannelError::Unsupported);
                }
                self.mutual_authenticate(
                    profile,
                    command.p1,
                    command.p2,
                    command.data,
                    response_scratch,
                )
            }
            0x88 if mode.supports_scp11() => {
                let Some(profile) =
                    crate::core::target::scp11_profiles().internal_authenticate_profile()
                else {
                    return Err(SecureChannelError::Unsupported);
                };
                self.mutual_authenticate(
                    profile,
                    command.p1,
                    command.p2,
                    command.data,
                    response_scratch,
                )
            }
            _ => Err(SecureChannelError::Unsupported),
        }
    }

    fn session_state(&self) -> SecureChannelSessionStateView {
        #[cfg(not(test))]
        {
            let mode = crate::core::target::secure_channel_mode();
            if !mode.supports_scp03() && !mode.supports_scp11() {
                return SecureChannelSessionStateView::inactive();
            }
        }
        if active_security_domain_session_instance_aid() != Some(self.aid()) {
            return SecureChannelSessionStateView::inactive();
        }
        if self.scp11_session.active {
            return SecureChannelSessionStateView {
                protocol: self.scp11_session.profile.map(SecureChannelProtocol::Scp11),
                policy_owner: Some(SecureChannelPolicyOwner::KernelProfile),
                phase: SecureChannelPhase::Authenticated,
                peer_authentication: self
                    .scp11_session
                    .profile
                    .map(|profile| {
                        peer_authentication_for_protocol(SecureChannelProtocol::Scp11(profile))
                    })
                    .unwrap_or(SecureChannelPeerAuthentication::None),
                security_level: SecurityLevel::CmacCencRmacRenc,
                mac_len: scp11c::MAC_LEN,
            };
        }
        let phase = match self.session.state {
            Scp03SessionState::Inactive => SecureChannelPhase::Inactive,
            Scp03SessionState::Initialized => SecureChannelPhase::Initialized,
            Scp03SessionState::Authenticated => SecureChannelPhase::Authenticated,
        };
        let mac_len = self
            .session
            .secure_messaging
            .map(|session| session.profile().mac_len())
            .unwrap_or_else(|| match self.session.state {
                Scp03SessionState::Inactive => 0,
                _ => self.config.scp03_profile.mac_len(),
            });
        SecureChannelSessionStateView {
            protocol: if matches!(self.session.state, Scp03SessionState::Inactive) {
                None
            } else {
                Some(SecureChannelProtocol::Scp03)
            },
            policy_owner: if matches!(self.session.state, Scp03SessionState::Inactive) {
                None
            } else {
                Some(SecureChannelPolicyOwner::KernelProfile)
            },
            phase,
            peer_authentication: if matches!(phase, SecureChannelPhase::Authenticated) {
                SecureChannelPeerAuthentication::Owner
            } else {
                SecureChannelPeerAuthentication::None
            },
            security_level: self.session.security_level,
            mac_len,
        }
    }

    fn unwrap_command_into(
        &mut self,
        apdu: &WrappedCommandApdu<'_>,
        out: &mut [u8],
    ) -> Result<usize, SecureChannelError> {
        let mode = crate::core::target::secure_channel_mode();
        if !mode.supports_scp03() && !mode.supports_scp11() {
            return Err(SecureChannelError::Unsupported);
        }
        if self.scp11_session.active {
            let secure_messaging = self
                .scp11_session
                .secure_messaging
                .as_mut()
                .ok_or(SecureChannelError::Rejected)?;
            let data_len = secure_messaging
                .unwrap_command_parts(
                    apdu.authenticated_prefix(),
                    apdu.authenticated_data(),
                    apdu.data(),
                    apdu.mac(),
                    out,
                )
                .map_err(|_| SecureChannelError::Rejected)?;
            return Ok(data_len);
        }

        let secure_messaging = self
            .session
            .secure_messaging
            .as_mut()
            .ok_or(SecureChannelError::Rejected)?;
        let data_len = secure_messaging
            .unwrap_command_parts(
                apdu.authenticated_prefix(),
                apdu.authenticated_data(),
                apdu.data(),
                apdu.mac(),
                out,
            )
            .map_err(|_| SecureChannelError::Rejected)?;
        Ok(data_len)
    }

    fn wrap_response_into(
        &mut self,
        response: &PlainResponseApdu<'_>,
        data_out: &mut [u8],
        mac_out: &mut [u8],
    ) -> Result<WrappedResponseLengths, SecureChannelError> {
        let mode = crate::core::target::secure_channel_mode();
        if !mode.supports_scp03() && !mode.supports_scp11() {
            return Err(SecureChannelError::Unsupported);
        }
        if self.scp11_session.active {
            let secure_messaging = self
                .scp11_session
                .secure_messaging
                .as_mut()
                .ok_or(SecureChannelError::Rejected)?;
            let lengths = secure_messaging
                .wrap_response(response.bytes, response.status, data_out, mac_out)
                .map_err(|_| SecureChannelError::Rejected)?;
            return Ok(WrappedResponseLengths {
                data_len: lengths.data_len,
                mac_len: lengths.mac_len,
            });
        }

        let secure_messaging = self
            .session
            .secure_messaging
            .as_mut()
            .ok_or(SecureChannelError::Rejected)?;
        let lengths = secure_messaging
            .wrap_response(response.bytes, response.status, data_out, mac_out)
            .map_err(|_| SecureChannelError::Rejected)?;
        Ok(WrappedResponseLengths {
            data_len: lengths.data_len,
            mac_len: lengths.mac_len,
        })
    }

    fn reset_secure_channel(&mut self) {
        self.session.reset();
        self.scp11_session.reset();
        clear_active_security_domain_session_binding();
    }
}

/// Kernel-native Security Domain using one build-selected SCP03 profile.
pub struct KernelSecurityDomain {
    inner: KernelSecurityDomainEngine,
}

impl KernelSecurityDomain {
    /// Creates the kernel-native authority singleton payload.
    pub const fn new() -> Self {
        Self {
            inner: KernelSecurityDomainEngine::new(),
        }
    }
}

impl Default for KernelSecurityDomain {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! impl_kernel_security_domain_profile {
    ($ty:ty) => {
        impl SecurityDomainManagement for $ty {
            fn aid(&self) -> Aid {
                self.inner.aid()
            }

            fn is_root_security_domain(&self) -> bool {
                self.inner.is_root_security_domain()
            }

            fn privileges(&self) -> SecurityDomainPrivileges {
                self.inner.privileges()
            }

            fn permits_management_without_secure_channel(&self) -> bool {
                self.inner.permits_management_without_secure_channel()
            }

            fn permits_set_status_without_secure_channel(&self) -> bool {
                self.inner.permits_set_status_without_secure_channel()
            }

            fn install_for_load(
                &self,
                command: &InstallForLoadCommand<'_>,
            ) -> Result<(), ManagementError> {
                self.inner.install_for_load(command)
            }

            fn install_for_install(
                &self,
                command: &InstallForInstallCommand<'_>,
            ) -> Result<(), ManagementError> {
                self.inner.install_for_install(command)
            }

            fn delete_aid(&self, aid: &Aid) -> Result<(), ManagementError> {
                self.inner.delete_aid(aid)
            }

            fn put_key(&self, command: &PutKeyCommand<'_>) -> Result<(), ManagementError> {
                self.inner.put_key(command)
            }

            fn store_data(&self, command: &StoreDataCommand<'_>) -> Result<(), ManagementError> {
                self.inner.store_data(command)
            }

            fn set_status(&self, command: &SetStatusCommand) -> Result<(), ManagementError> {
                self.inner.set_status(command)
            }

            fn get_data(&self, tag: GetDataTag, out: &mut [u8]) -> Result<usize, ManagementError> {
                self.inner.get_data(tag, out)
            }

            fn may_manage_applet(
                &self,
                package_aid: &Aid,
                applet_aid: &Aid,
                instance_aid: &Aid,
            ) -> bool {
                self.inner
                    .may_manage_applet(package_aid, applet_aid, instance_aid)
            }

            fn may_make_selectable(&self, instance_aid: &Aid) -> bool {
                self.inner.may_make_selectable(instance_aid)
            }

            fn may_manage_security_domain_plane(&self) -> bool {
                self.inner.may_manage_security_domain_plane()
            }

            fn may_access_registry_plane(&self) -> bool {
                self.inner.may_access_registry_plane()
            }
        }

        impl SecurityDomainSecureChannel for $ty {
            fn supports_secure_channel_protocol(&self, protocol: SecureChannelProtocol) -> bool {
                self.inner.supports_secure_channel_protocol(protocol)
            }

            fn claims_delegated_secure_channel_command(
                &self,
                header: DelegatedSecureChannelHeader,
            ) -> bool {
                self.inner.claims_delegated_secure_channel_command(header)
            }

            fn handle_delegated_secure_channel_command(
                &mut self,
                command: &SecureChannelEstablishmentCommand<'_>,
            ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
                self.inner.handle_delegated_secure_channel_command(command)
            }

            fn handle_establishment(
                &mut self,
                command: &SecureChannelEstablishmentCommand<'_>,
                response_scratch: &mut [u8],
            ) -> Result<SecureChannelEstablishmentResult, SecureChannelError> {
                self.inner.handle_establishment(command, response_scratch)
            }

            fn session_state(&self) -> SecureChannelSessionStateView {
                self.inner.session_state()
            }

            fn unwrap_command_into(
                &mut self,
                apdu: &WrappedCommandApdu<'_>,
                out: &mut [u8],
            ) -> Result<usize, SecureChannelError> {
                self.inner.unwrap_command_into(apdu, out)
            }

            fn wrap_response_into(
                &mut self,
                response: &PlainResponseApdu<'_>,
                data_out: &mut [u8],
                mac_out: &mut [u8],
            ) -> Result<WrappedResponseLengths, SecureChannelError> {
                self.inner.wrap_response_into(response, data_out, mac_out)
            }

            fn reset_secure_channel(&mut self) {
                self.inner.reset_secure_channel()
            }
        }
    };
}

impl_kernel_security_domain_profile!(KernelSecurityDomain);

static mut NULL_SECURITY_DOMAIN: NullSecurityDomain = NullSecurityDomain::new();
static mut KERNEL_SECURITY_DOMAIN: KernelSecurityDomain = KernelSecurityDomain::new();
static mut RUSTLET_SECURITY_DOMAIN_PROXY: RustletSecurityDomainProxy =
    RustletSecurityDomainProxy::new();
static mut ACTIVE_SECURITY_DOMAIN_SESSION_INSTANCE_AID: Option<Aid> = None;
static mut ACTIVE_SECURITY_DOMAIN_SESSION_PROTOCOL: Option<SecureChannelProtocol> = None;
static mut ACTIVE_SECURITY_DOMAIN_SESSION_IS_DELEGATED: bool = false;
static mut MANAGEMENT_AUTHORITY_OVERRIDE_AID: Option<Aid> = None;

/// Returns the active kernel-side management authority.
///
/// Invariant: this selector is the only kernel-wide Security Domain switch.
pub fn current_security_domain() -> &'static mut dyn SecurityDomain {
    match current_management_authority_backend() {
        crate::predeployment::RootSecurityDomainBackend::NullSecurityDomain => unsafe {
            &mut *core::ptr::addr_of_mut!(NULL_SECURITY_DOMAIN)
        },
        crate::predeployment::RootSecurityDomainBackend::KernelSecurityDomain => unsafe {
            &mut *core::ptr::addr_of_mut!(KERNEL_SECURITY_DOMAIN)
        },
        crate::predeployment::RootSecurityDomainBackend::RustletSecurityDomainProxy => unsafe {
            &mut *core::ptr::addr_of_mut!(RUSTLET_SECURITY_DOMAIN_PROXY)
        },
    }
}

fn current_management_authority_backend() -> crate::predeployment::RootSecurityDomainBackend {
    let aid = current_management_authority_aid();
    if let Some(kind) = crate::selected_app::security_domain_backend_by_aid(&aid) {
        match kind {
            crate::selected_app::SecurityDomainObjectBackend::NullSecurityDomain => {
                crate::predeployment::RootSecurityDomainBackend::NullSecurityDomain
            }
            crate::selected_app::SecurityDomainObjectBackend::KernelSecurityDomain => {
                crate::predeployment::RootSecurityDomainBackend::KernelSecurityDomain
            }
            crate::selected_app::SecurityDomainObjectBackend::RustletSecurityDomain => {
                crate::predeployment::RootSecurityDomainBackend::RustletSecurityDomainProxy
            }
        }
    } else {
        crate::predeployment::root_backend()
    }
}

/// Returns whether the active authority executes secure-channel policy in a Rustlet.
///
/// The APDU layer uses this to avoid borrowing the shared Rustlet control
/// buffer as transform workspace while an SDDISPATCH call may overwrite it.
pub fn current_security_domain_is_rustlet_backed() -> bool {
    matches!(
        current_management_authority_backend(),
        crate::predeployment::RootSecurityDomainBackend::RustletSecurityDomainProxy
    )
}

/// Runs one management decision under one explicit authority instance AID.
pub fn with_management_authority_aid<T>(
    aid: Aid,
    f: impl FnOnce(&mut dyn SecurityDomain) -> T,
) -> T {
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(MANAGEMENT_AUTHORITY_OVERRIDE_AID),
            Some(aid),
        );
    }
    let result = f(current_security_domain());
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(MANAGEMENT_AUTHORITY_OVERRIDE_AID),
            None,
        );
    }
    result
}

fn status_to_management_result(
    status: crate::apdu_manager::ApduStatus,
) -> Result<(), ManagementError> {
    if status.sw1 == 0x90 && status.sw2 == 0x00 {
        Ok(())
    } else {
        Err(status_to_management_error(status))
    }
}

fn status_to_management_error(status: crate::apdu_manager::ApduStatus) -> ManagementError {
    match (status.sw1, status.sw2) {
        (0x6d, 0x00) => ManagementError::Unsupported,
        (0x6a, 0x88) => ManagementError::NotFound,
        _ => ManagementError::Rejected,
    }
}

fn status_to_secure_channel_error(status: crate::apdu_manager::ApduStatus) -> SecureChannelError {
    if status.sw1 == 0x6d && status.sw2 == 0x00 {
        SecureChannelError::Unsupported
    } else {
        SecureChannelError::Status(status)
    }
}

/// Returns the configured root Security Domain instance AID.
pub fn root_security_domain_aid() -> Aid {
    crate::predeployment::root_instance_aid()
}

fn active_security_domain_session_instance_aid() -> Option<Aid> {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            ACTIVE_SECURITY_DOMAIN_SESSION_INSTANCE_AID
        ))
    }
}

fn active_security_domain_session_protocol() -> Option<SecureChannelProtocol> {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_SECURITY_DOMAIN_SESSION_PROTOCOL))
    }
}

fn active_security_domain_session_is_delegated() -> bool {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(
            ACTIVE_SECURITY_DOMAIN_SESSION_IS_DELEGATED
        ))
    }
}

const fn peer_authentication_for_protocol(
    protocol: SecureChannelProtocol,
) -> SecureChannelPeerAuthentication {
    match protocol {
        SecureChannelProtocol::Scp03
        | SecureChannelProtocol::Scp11(scp11::Scp11Profile::A)
        | SecureChannelProtocol::Scp11(scp11::Scp11Profile::C) => {
            // The selected development profile only trusts the configured
            // owner credentials. ANY_AUTHENTICATED/BF20 is profiled out.
            SecureChannelPeerAuthentication::Owner
        }
        SecureChannelProtocol::Scp11(scp11::Scp11Profile::B) => {
            SecureChannelPeerAuthentication::CardOnly
        }
    }
}

fn current_management_authority_aid() -> Aid {
    let override_aid =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MANAGEMENT_AUTHORITY_OVERRIDE_AID)) };
    override_aid.unwrap_or_else(crate::selected_app::active_security_domain_instance_aid)
}

fn bind_session_to_active_security_domain_instance(protocol: SecureChannelProtocol) {
    let aid = crate::selected_app::active_security_domain_instance_aid();
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SESSION_INSTANCE_AID),
            Some(aid),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SESSION_PROTOCOL),
            Some(protocol),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SESSION_IS_DELEGATED),
            false,
        );
    }
}

fn bind_delegated_session_to_active_security_domain_instance() {
    let aid = crate::selected_app::active_security_domain_instance_aid();
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SESSION_INSTANCE_AID),
            Some(aid),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SESSION_PROTOCOL),
            None,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SESSION_IS_DELEGATED),
            true,
        );
    }
}

fn clear_active_security_domain_session_binding() {
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SESSION_INSTANCE_AID),
            None,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SESSION_PROTOCOL),
            None,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SESSION_IS_DELEGATED),
            false,
        );
    }
}

/// Called whenever the active administrative instance changes.
///
/// The secure channel is instance-bound, so switching the active authority
/// invalidates any previously authenticated session.
pub fn on_active_security_domain_instance_switched(_previous: Aid, _next: Aid) {
    current_security_domain().reset_secure_channel();
}

/// Records one kernel-native Security Domain instance in the registry.
///
/// This helper is only meaningful when the current target uses a kernel-native
/// backend; other backends accept the call as a no-op.
pub fn record_kernel_security_domain_instance_state(
    instance_aid: &Aid,
    privilege_bytes: &[u8],
) -> bool {
    if !matches!(
        crate::predeployment::root_backend(),
        crate::predeployment::RootSecurityDomainBackend::KernelSecurityDomain
    ) {
        return true;
    }

    let Some(state) = KernelSecurityDomainAdministrativeState::from_install_bytes(privilege_bytes)
    else {
        return false;
    };
    crate::selected_app::upsert_security_domain_state_object(
        crate::selected_app::top_level_parent_sd_aid(),
        crate::predeployment::root_package_aid(),
        *instance_aid,
        crate::selected_app::SecurityDomainObjectBackend::KernelSecurityDomain,
        state.privileges().encoded_bytes(),
        &state.encode(),
    )
}

/// Returns the effective privileges stored for one kernel-native Security Domain instance.
pub fn kernel_security_domain_instance_privileges(aid: &Aid) -> Option<SecurityDomainPrivileges> {
    let state = crate::selected_app::find_security_domain_state_by_aid(aid)?;
    KernelSecurityDomainAdministrativeState::decode(state).map(|decoded| decoded.privileges())
}

fn copy_unwrapped_data_into(data: &[u8], out: &mut [u8]) -> Result<usize, SecureChannelError> {
    if data.len() > out.len() {
        return Err(SecureChannelError::Rejected);
    }
    out[..data.len()].copy_from_slice(data);
    Ok(data.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn root_addressed_gp_management_forms_reuse_the_common_operation() {
        let root = Aid::from_array([0xA0, 0x01]);
        let child = Aid::from_array([0xA0, 0x02]);
        for operation in [
            ManagementOperation::Delete,
            ManagementOperation::SetStatus,
            ManagementOperation::GetStatus,
        ] {
            let global = adapt_management_apdu(operation, root, root);
            assert_eq!(global.operation, operation);
            assert!(global.authority_aid == root);
            assert_eq!(global.form, ManagementApduForm::Global);

            let ordinary = adapt_management_apdu(operation, child, root);
            assert_eq!(ordinary.operation, operation);
            assert!(ordinary.authority_aid == child);
            assert_eq!(ordinary.form, ManagementApduForm::Ordinary);
        }
    }

    const TEST_SCP11_OCE_STATIC_PUBLIC: [u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE] = [
        0x04, 0x0C, 0x7F, 0xCC, 0x32, 0x1C, 0x77, 0x11, 0x92, 0x03, 0xDB, 0xE7, 0x98, 0x64, 0x90,
        0x7E, 0x4F, 0x0A, 0x01, 0x91, 0x77, 0x89, 0xDE, 0xA2, 0xD4, 0x73, 0x15, 0x31, 0xA5, 0x2A,
        0x22, 0xE2, 0xBA, 0xC1, 0x76, 0x6D, 0x21, 0xE4, 0x61, 0x7D, 0x72, 0xFB, 0xBE, 0xF8, 0x7D,
        0x6E, 0xDF, 0x2D, 0x8F, 0x80, 0xB5, 0x26, 0x95, 0x6E, 0x3C, 0x2C, 0x17, 0x01, 0xF1, 0x6B,
        0x7F, 0x31, 0x15, 0x00, 0xC6,
    ];
    const TEST_SCP11_OCE_EPHEMERAL_PUBLIC: [u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE] = [
        0x04, 0x1A, 0x97, 0xD0, 0x7A, 0x2F, 0xEC, 0xE5, 0x6C, 0x45, 0xC4, 0x3F, 0x38, 0x00, 0x91,
        0x2D, 0x56, 0x99, 0x10, 0xE0, 0x36, 0x0E, 0x25, 0x38, 0x1C, 0x4C, 0x57, 0x85, 0x95, 0x14,
        0xEA, 0xAC, 0x5A, 0xF0, 0x76, 0xCE, 0x5E, 0xBA, 0x72, 0x00, 0xA1, 0x01, 0x7D, 0xE2, 0x96,
        0x33, 0x5B, 0x91, 0x04, 0x77, 0x7B, 0xCD, 0xD9, 0xFB, 0x9F, 0x15, 0x46, 0xAC, 0xE5, 0xF2,
        0x71, 0x9F, 0x53, 0xE7, 0xF4,
    ];

    const TEST_SCP11C_OCE_CERTIFICATE: [u8; 199] = [
        0x7F, 0x21, 0x81, 0xC3, 0x93, 0x01, 0x01, 0x42, 0x04, 0x52, 0x4C, 0x4F, 0x53, 0x5F, 0x20,
        0x09, 0x6F, 0x63, 0x65, 0x2D, 0x64, 0x65, 0x62, 0x75, 0x67, 0x95, 0x02, 0x00, 0x80, 0x5F,
        0x25, 0x04, 0x20, 0x24, 0x01, 0x01, 0x5F, 0x24, 0x04, 0x20, 0x34, 0x01, 0x01, 0xBF, 0x20,
        0x0D, 0x72, 0x75, 0x73, 0x74, 0x6C, 0x65, 0x74, 0x6F, 0x73, 0x2D, 0x6F, 0x63, 0x65, 0x7F,
        0x49, 0x46, 0xB0, 0x41, 0x04, 0x0C, 0x7F, 0xCC, 0x32, 0x1C, 0x77, 0x11, 0x92, 0x03, 0xDB,
        0xE7, 0x98, 0x64, 0x90, 0x7E, 0x4F, 0x0A, 0x01, 0x91, 0x77, 0x89, 0xDE, 0xA2, 0xD4, 0x73,
        0x15, 0x31, 0xA5, 0x2A, 0x22, 0xE2, 0xBA, 0xC1, 0x76, 0x6D, 0x21, 0xE4, 0x61, 0x7D, 0x72,
        0xFB, 0xBE, 0xF8, 0x7D, 0x6E, 0xDF, 0x2D, 0x8F, 0x80, 0xB5, 0x26, 0x95, 0x6E, 0x3C, 0x2C,
        0x17, 0x01, 0xF1, 0x6B, 0x7F, 0x31, 0x15, 0x00, 0xC6, 0xF0, 0x01, 0x00, 0x5F, 0x37, 0x40,
        0xD6, 0xBA, 0x17, 0x56, 0x97, 0x56, 0xF4, 0x18, 0xE9, 0x51, 0x93, 0xD3, 0x97, 0x1B, 0xE8,
        0x0D, 0x79, 0x62, 0xD8, 0xDB, 0x73, 0xB8, 0x03, 0xCE, 0xB0, 0xED, 0xEE, 0xB9, 0x42, 0xEA,
        0x08, 0x3E, 0x94, 0x11, 0xE8, 0xE8, 0x46, 0xF0, 0xE3, 0x2F, 0x34, 0x3F, 0x1B, 0x97, 0xD7,
        0x59, 0xA8, 0x8E, 0xAA, 0x6F, 0xF0, 0x18, 0xBC, 0xE3, 0x8F, 0xEC, 0x52, 0x98, 0xCF, 0x4B,
        0x6B, 0xA5, 0x61, 0xB6,
    ];

    fn test_scp11c_certificate() -> scp11c::VerifiedOceCertificate<'static> {
        scp11c::verify_oce_certificate(scp11c::dev_ca_public_key(), &TEST_SCP11C_OCE_CERTIFICATE)
            .expect("valid development OCE certificate")
    }

    fn tlv(tag: &[u8], value: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(tag);
        assert!(
            value.len() < 0x80,
            "test helper only supports short-form TLV"
        );
        out.push(value.len() as u8);
        out.extend_from_slice(value);
    }

    fn build_test_mutual_authenticate_request(host_public: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        tlv(
            &[0x90],
            &[
                scp11::SCP11_IDENTIFIER_FAMILY,
                scp11::SCP11C_IDENTIFIER_PARAM,
            ],
            &mut body,
        );
        tlv(&[0x95], &[scp11c::KEY_USAGE_FULL], &mut body);
        tlv(&[0x80], &[scp11c::KEY_TYPE_AES], &mut body);
        tlv(&[0x81], &[scp11c::KEY_LENGTH_AES_128], &mut body);
        tlv(&[0x84], b"host", &mut body);
        let mut request = Vec::new();
        tlv(&[0xA6], &body, &mut request);
        tlv(&[0x5F, 0x49], host_public, &mut request);
        request
    }

    #[test]
    fn kernel_security_domain_state_roundtrip() {
        let state =
            KernelSecurityDomainAdministrativeState::from_install_bytes(&[0xA0, 0x00, 0x01])
                .expect("decode install bytes");
        let encoded = state.encode();
        let decoded = KernelSecurityDomainAdministrativeState::decode(&encoded)
            .expect("decode encoded state");
        assert_eq!(decoded, state);
        assert!(decoded.privileges().contains(
            SecurityDomainPrivileges::from_install_bytes(&[0x20]).expect("requested privileges")
        ));
        assert_eq!(decoded.lifecycle(), SecurityDomainLifecycle::Selectable);
    }

    #[test]
    fn kernel_security_domain_state_encoding_helper() {
        let encoded =
            encode_administrative_state(&[0x20, 0x00, 0x00]).expect("encode administrative state");
        let decoded =
            KernelSecurityDomainAdministrativeState::decode(&encoded).expect("decode helper state");
        assert_eq!(
            decoded.privileges(),
            SecurityDomainPrivileges::from_install_bytes(&[0x20, 0x00, 0x00])
                .expect("decode privileges")
        );
        assert_eq!(decoded.lifecycle(), SecurityDomainLifecycle::Selectable);
    }

    #[test]
    fn kernel_security_domain_legacy_state_decodes_as_selectable() {
        let legacy = [KERNEL_SECURITY_DOMAIN_STATE_VERSION, 1, 0x20, 0x00, 0x00];
        let decoded = KernelSecurityDomainAdministrativeState::decode(&legacy)
            .expect("decode legacy administrative state");
        assert_eq!(decoded.lifecycle(), SecurityDomainLifecycle::Selectable);
        assert!(decoded.privileges().may_install_for_load());
    }

    #[test]
    fn privilege_contains_extension_bytes_conservatively() {
        let parent = SecurityDomainPrivileges::from_install_bytes(&[0x20, 0x00, 0x01])
            .expect("parent privileges");
        let allowed_child = SecurityDomainPrivileges::from_install_bytes(&[0x20, 0x00, 0x01])
            .expect("allowed child");
        let rejected_child = SecurityDomainPrivileges::from_install_bytes(&[0x20, 0x00, 0x03])
            .expect("rejected child");
        assert!(parent.contains(allowed_child));
        assert!(!parent.contains(rejected_child));
    }

    #[test]
    fn put_key_reference_control_decodes_gp_control_bits() {
        let control = PutKeyReferenceControl::decode(0x01, 0x83);
        assert_eq!(control.key_version, 0x01);
        assert_eq!(control.first_key_id, 0x03);
        assert!(control.last_command);
        assert!(control.multiple_keys);
        assert_eq!(control.key_id_for_entry(0), Some(0x03));
        assert_eq!(control.key_id_for_entry(1), Some(0x04));
    }

    #[test]
    fn put_key_reference_control_rejects_extra_single_key_entries() {
        let control = PutKeyReferenceControl::decode(0x01, 0x03);
        assert_eq!(control.key_id_for_entry(0), Some(0x03));
        assert_eq!(control.key_id_for_entry(1), None);
    }

    #[test]
    fn put_key_reference_control_rejects_key_identifier_overflow() {
        let control = PutKeyReferenceControl::decode(0x01, 0xff);
        assert_eq!(control.key_id_for_entry(0), Some(0x7f));
        assert_eq!(control.key_id_for_entry(1), None);
    }

    #[test]
    fn kernel_get_data_virtual_tags_are_resolved_before_registry_fallback() {
        let mut out = [0u8; 64];
        let len = write_standard_get_data(
            GetDataTag::LifeCycleState,
            SecurityDomainLifecycle::Selectable,
            rustlet_runtime::gp::SecurityDomainCapabilities::none(),
            &mut out,
        )
        .expect("lifecycle is a virtual kernel data object")
        .expect("lifecycle fits");
        assert_eq!(&out[..len], &[0x9f, 0x70, 0x01, 0x07]);
        assert!(write_standard_get_data(
            GetDataTag::Other(0xdf10),
            SecurityDomainLifecycle::Selectable,
            rustlet_runtime::gp::SecurityDomainCapabilities::none(),
            &mut out,
        )
        .is_none());

        let len = write_standard_get_data(
            GetDataTag::CardRecognitionData,
            SecurityDomainLifecycle::Selectable,
            rustlet_runtime::gp::SecurityDomainCapabilities::none(),
            &mut out,
        )
        .expect("card recognition data is virtual")
        .expect("card recognition data fits");
        assert_eq!(&out[..2], &[0x66, 0x23]);
        assert_eq!(len, 37);

        assert_eq!(
            write_standard_get_data(
                GetDataTag::CardCapabilityInformation,
                SecurityDomainLifecycle::Selectable,
                rustlet_runtime::gp::SecurityDomainCapabilities::none(),
                &mut out,
            ),
            Some(Err(ManagementError::NotFound))
        );
    }

    #[test]
    fn kernel_get_data_reports_locked_lifecycle_state() {
        let mut out = [0u8; 16];
        let len = write_standard_get_data(
            GetDataTag::LifeCycleState,
            SecurityDomainLifecycle::Locked,
            rustlet_runtime::gp::SecurityDomainCapabilities::none(),
            &mut out,
        )
        .expect("lifecycle is a virtual kernel data object")
        .expect("lifecycle fits");
        assert_eq!(&out[..len], &[0x9f, 0x70, 0x01, 0x7f]);
    }

    #[test]
    fn locked_kernel_security_domain_rejects_management_hooks() {
        let mut engine = KernelSecurityDomainEngine::new();
        engine.administrative_state = KernelSecurityDomainAdministrativeState {
            privileges: SecurityDomainPrivileges::open(),
            lifecycle: SecurityDomainLifecycle::Locked,
        };
        let command = StoreDataCommand {
            tag: 0xdf10,
            data: b"hello",
        };

        assert_eq!(engine.store_data(&command), Err(ManagementError::Rejected));
        assert!(!engine.may_access_registry_plane());
        assert!(!engine.may_manage_security_domain_plane());
        assert!(!engine.may_make_selectable(&Aid::new(&[0xa0, 0x01])));
    }

    #[test]
    fn null_security_domain_store_data_follows_registry_privilege() {
        let command = StoreDataCommand {
            tag: 0xdf10,
            data: b"hello",
        };
        let sd = NullSecurityDomain;
        assert_eq!(sd.store_data(&command), Ok(()));
    }

    #[test]
    fn scp11c_stage_oce_certificate_resets_previous_session_state() {
        let certificate = test_scp11c_certificate();
        let mut session = Scp11Session::inactive();
        session
            .stage_oce_certificate(&certificate)
            .expect("initial staging OCE certificate should succeed");
        let request = build_test_mutual_authenticate_request(&TEST_SCP11_OCE_EPHEMERAL_PUBLIC);
        let mut response = [0u8; SECURE_CHANNEL_RESPONSE_CAPACITY];
        session
            .mutual_authenticate(
                scp11::Scp11Profile::C,
                SCP11_DEV_ECKA_KEY_VERSION,
                SCP11_DEV_ECKA_KEY_ID,
                &request,
                &mut response,
            )
            .expect("mutual authenticate should establish one live session");
        assert!(session.active);
        assert!(session.keys.is_some());
        assert!(session.secure_messaging.is_some());

        session
            .stage_oce_certificate(&certificate)
            .expect("staging OCE certificate should succeed");

        assert!(!session.active);
        assert!(session.keys.is_none());
        assert!(session.secure_messaging.is_none());
        assert_eq!(
            session.staged_oce_public().map(|value| value.as_slice()),
            Some(certificate.public_key())
        );
    }

    #[test]
    fn scp11c_mutual_authenticate_rejects_without_staged_certificate() {
        let mut session = Scp11Session::inactive();
        let request = build_test_mutual_authenticate_request(&TEST_SCP11_OCE_EPHEMERAL_PUBLIC);
        let mut response = [0u8; SECURE_CHANNEL_RESPONSE_CAPACITY];
        assert_eq!(
            session
                .mutual_authenticate(
                    scp11::Scp11Profile::C,
                    SCP11_DEV_ECKA_KEY_VERSION,
                    SCP11_DEV_ECKA_KEY_ID,
                    &request,
                    &mut response,
                )
                .err(),
            Some(SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::conditions_not_satisfied()
            ))
        );
    }

    #[test]
    fn scp11_mutual_authenticate_resolves_the_requested_ecka_key() {
        let certificate = test_scp11c_certificate();
        let mut session = Scp11Session::inactive();
        session
            .stage_oce_certificate(&certificate)
            .expect("staging OCE certificate should succeed");
        let request = build_test_mutual_authenticate_request(&TEST_SCP11_OCE_EPHEMERAL_PUBLIC);
        let mut response = [0u8; SECURE_CHANNEL_RESPONSE_CAPACITY];
        assert_eq!(
            session
                .mutual_authenticate(
                    scp11::Scp11Profile::C,
                    SCP11_DEV_ECKA_KEY_VERSION,
                    SCP11_DEV_ECKA_KEY_ID + 1,
                    &request,
                    &mut response,
                )
                .err(),
            Some(SecureChannelError::Status(
                crate::apdu_manager::ApduStatus::referenced_data_not_found()
            ))
        );
        assert!(!session.active);
        assert!(session.staged_oce_public().is_some());
    }

    #[test]
    fn scp11c_mutual_authenticate_accepts_distinct_static_and_ephemeral_oce_keys() {
        let certificate = test_scp11c_certificate();
        let mut session = Scp11Session::inactive();
        session
            .stage_oce_certificate(&certificate)
            .expect("staging OCE certificate should succeed");
        assert_eq!(certificate.public_key(), &TEST_SCP11_OCE_STATIC_PUBLIC);
        assert_ne!(
            TEST_SCP11_OCE_EPHEMERAL_PUBLIC,
            TEST_SCP11_OCE_STATIC_PUBLIC
        );
        let request = build_test_mutual_authenticate_request(&TEST_SCP11_OCE_EPHEMERAL_PUBLIC);
        let mut response = [0u8; SECURE_CHANNEL_RESPONSE_CAPACITY];
        let response_len = session
            .mutual_authenticate(
                scp11::Scp11Profile::C,
                SCP11_DEV_ECKA_KEY_VERSION,
                SCP11_DEV_ECKA_KEY_ID,
                &request,
                &mut response,
            )
            .expect("distinct certified-static and request-ephemeral keys are required");
        assert_eq!(response_len, scp11c::MUTUAL_AUTHENTICATE_RESPONSE_LEN);
        assert_eq!(
            &response[3..3 + P256_PUBLIC_KEY_UNCOMPRESSED_SIZE],
            &SCP11_DEV_CARD_STATIC_PUBLIC_KEY
        );
    }

    #[test]
    fn scp11c_mutual_authenticate_activates_session_after_valid_pso() {
        let certificate = test_scp11c_certificate();
        let mut session = Scp11Session::inactive();
        session
            .stage_oce_certificate(&certificate)
            .expect("staging OCE certificate should succeed");
        let request = build_test_mutual_authenticate_request(&TEST_SCP11_OCE_EPHEMERAL_PUBLIC);
        let mut response = [0u8; SECURE_CHANNEL_RESPONSE_CAPACITY];
        let response_len = session
            .mutual_authenticate(
                scp11::Scp11Profile::C,
                SCP11_DEV_ECKA_KEY_VERSION,
                SCP11_DEV_ECKA_KEY_ID,
                &request,
                &mut response,
            )
            .expect("mutual authenticate should succeed after matching PSO");

        assert!(session.active);
        assert!(session.keys.is_some());
        assert!(session.secure_messaging.is_some());
        assert_eq!(response_len, scp11c::MUTUAL_AUTHENTICATE_RESPONSE_LEN);
        assert_eq!(
            &response[3..3 + P256_PUBLIC_KEY_UNCOMPRESSED_SIZE],
            &SCP11_DEV_CARD_STATIC_PUBLIC_KEY
        );
    }

    #[test]
    fn scp11c_session_state_is_hidden_until_bound_to_active_instance() {
        let certificate = test_scp11c_certificate();
        let mut engine = KernelSecurityDomainEngine::new();
        let request = build_test_mutual_authenticate_request(&TEST_SCP11_OCE_EPHEMERAL_PUBLIC);
        engine
            .scp11_session
            .stage_oce_certificate(&certificate)
            .expect("staging OCE certificate should succeed");
        let mut response = [0u8; SECURE_CHANNEL_RESPONSE_CAPACITY];
        engine
            .scp11_session
            .mutual_authenticate(
                scp11::Scp11Profile::C,
                SCP11_DEV_ECKA_KEY_VERSION,
                SCP11_DEV_ECKA_KEY_ID,
                &request,
                &mut response,
            )
            .expect("mutual authenticate should succeed after matching PSO");

        // Invariant: a live SCP11 session is visible only when the session is
        // explicitly bound to the currently active Security Domain instance.
        assert_eq!(engine.session_state().protocol, None);

        bind_session_to_active_security_domain_instance(SecureChannelProtocol::Scp11(
            scp11::Scp11Profile::C,
        ));
        assert_eq!(
            engine.session_state().protocol,
            Some(SecureChannelProtocol::Scp11(scp11::Scp11Profile::C))
        );
        clear_active_security_domain_session_binding();
    }

    fn authenticated_session(
        protocol: SecureChannelProtocol,
        peer_authentication: SecureChannelPeerAuthentication,
    ) -> SecureChannelSessionStateView {
        SecureChannelSessionStateView {
            protocol: Some(protocol),
            policy_owner: Some(SecureChannelPolicyOwner::KernelProfile),
            phase: SecureChannelPhase::Authenticated,
            peer_authentication,
            security_level: SecurityLevel::CmacCencRmacRenc,
            mac_len: 16,
        }
    }

    #[test]
    fn delegated_session_leaves_protocol_policy_to_the_rustlet_security_domain() {
        let delegated = SecureChannelSessionStateView {
            protocol: None,
            policy_owner: Some(SecureChannelPolicyOwner::RustletSecurityDomain),
            phase: SecureChannelPhase::Authenticated,
            peer_authentication: SecureChannelPeerAuthentication::None,
            security_level: SecurityLevel::None,
            mac_len: 16,
        };
        for operation in [
            ManagementOperation::GetData,
            ManagementOperation::GetStatus,
            ManagementOperation::StoreData,
            ManagementOperation::PutKey,
            ManagementOperation::InstallForLoad,
            ManagementOperation::InstallForInstall,
            ManagementOperation::Delete,
            ManagementOperation::SetStatus,
        ] {
            assert!(secure_channel_allows_management(
                delegated,
                operation,
                ManagementTarget::Unspecified,
            ));
        }

        assert!(!secure_channel_allows_management(
            SecureChannelSessionStateView {
                phase: SecureChannelPhase::Inactive,
                ..delegated
            },
            ManagementOperation::GetData,
            ManagementTarget::Unspecified,
        ));
    }

    #[test]
    fn management_matrix_keeps_scp03_and_owner_scp11a_management_enabled() {
        for protocol in [
            SecureChannelProtocol::Scp03,
            SecureChannelProtocol::Scp11(scp11::Scp11Profile::A),
        ] {
            let session = authenticated_session(protocol, SecureChannelPeerAuthentication::Owner);
            for operation in [
                ManagementOperation::GetData,
                ManagementOperation::GetStatus,
                ManagementOperation::StoreData,
                ManagementOperation::PutKey,
                ManagementOperation::InstallForLoad,
                ManagementOperation::Load,
                ManagementOperation::InstallForInstall,
                ManagementOperation::Delete,
                ManagementOperation::SetStatus,
            ] {
                assert!(secure_channel_allows_management(
                    session,
                    operation,
                    ManagementTarget::Object
                ));
            }
        }
    }

    #[test]
    fn management_matrix_limits_scp11b_to_read_only_get_data() {
        let session = authenticated_session(
            SecureChannelProtocol::Scp11(scp11::Scp11Profile::B),
            SecureChannelPeerAuthentication::CardOnly,
        );
        assert!(secure_channel_allows_management(
            session,
            ManagementOperation::GetData,
            ManagementTarget::Unspecified
        ));
        assert!(secure_channel_allows_management(
            session,
            ManagementOperation::GetStatus,
            ManagementTarget::Unspecified
        ));
        for operation in [
            ManagementOperation::StoreData,
            ManagementOperation::PutKey,
            ManagementOperation::InstallForLoad,
            ManagementOperation::Load,
            ManagementOperation::InstallForInstall,
            ManagementOperation::Delete,
            ManagementOperation::SetStatus,
        ] {
            assert!(!secure_channel_allows_management(
                session,
                operation,
                ManagementTarget::Object
            ));
        }
    }

    #[test]
    fn management_matrix_applies_scp11c_absolute_restrictions() {
        let session = authenticated_session(
            SecureChannelProtocol::Scp11(scp11::Scp11Profile::C),
            SecureChannelPeerAuthentication::Owner,
        );
        assert!(!secure_channel_allows_management(
            session,
            ManagementOperation::PutKey,
            ManagementTarget::Key
        ));
        assert!(!secure_channel_allows_management(
            session,
            ManagementOperation::SetStatus,
            ManagementTarget::Object
        ));
        assert!(!secure_channel_allows_management(
            session,
            ManagementOperation::Delete,
            ManagementTarget::Key
        ));
        assert!(secure_channel_allows_management(
            session,
            ManagementOperation::Delete,
            ManagementTarget::Object
        ));
        assert!(secure_channel_allows_management(
            session,
            ManagementOperation::InstallForInstall,
            ManagementTarget::Object
        ));
    }

    #[test]
    fn management_matrix_profiles_out_scp11_any_authenticated_mutations() {
        let session = authenticated_session(
            SecureChannelProtocol::Scp11(scp11::Scp11Profile::C),
            SecureChannelPeerAuthentication::Any,
        );
        assert!(secure_channel_allows_management(
            session,
            ManagementOperation::GetData,
            ManagementTarget::Unspecified
        ));
        assert!(secure_channel_allows_management(
            session,
            ManagementOperation::GetStatus,
            ManagementTarget::Unspecified
        ));
        assert!(!secure_channel_allows_management(
            session,
            ManagementOperation::InstallForInstall,
            ManagementTarget::Object
        ));
        assert!(!secure_channel_allows_management(
            session,
            ManagementOperation::StoreData,
            ManagementTarget::Object
        ));
    }
}
