use crate::rt::Rustlet;
use crate::{Aid, ApduStatus, RustletCtx};

/// Privileges granted to a Rustlet Security Domain.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(crate = "crate::serde")]
pub struct SecurityDomainPrivileges {
    bytes: [u8; 3],
    encoded_len: u8,
    developer_open: bool,
}

/// Error returned when decoding GlobalPlatform privilege bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SecurityDomainPrivilegeError {
    TooLong,
}

/// Minimal lifecycle state carried by one Security Domain instance.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(crate = "crate::serde")]
pub enum SecurityDomainLifecycle {
    Installed,
    Selectable,
    Locked,
}

impl SecurityDomainLifecycle {
    const INSTALLED_BYTE: u8 = 0x03;
    const SELECTABLE_BYTE: u8 = 0x07;
    const LOCKED_BYTE: u8 = 0x7f;

    /// Returns the encoded lifecycle byte used by `GET DATA 9F70`.
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Installed => Self::INSTALLED_BYTE,
            Self::Selectable => Self::SELECTABLE_BYTE,
            Self::Locked => Self::LOCKED_BYTE,
        }
    }

    /// Decodes one stored lifecycle byte.
    ///
    /// `0x00` is accepted as the legacy "selectable" encoding.
    pub const fn from_stored_byte(byte: u8) -> Self {
        match byte {
            Self::INSTALLED_BYTE => Self::Installed,
            Self::LOCKED_BYTE => Self::Locked,
            _ => Self::Selectable,
        }
    }

    /// Returns true if the instance may currently exercise management authority.
    pub const fn may_manage(self) -> bool {
        matches!(self, Self::Selectable)
    }
}

/// Standard persistent administrative state of one Security Domain instance.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(crate = "crate::serde")]
pub struct SecurityDomainAdministrativeState {
    privileges: SecurityDomainPrivileges,
    lifecycle: SecurityDomainLifecycle,
}

impl SecurityDomainAdministrativeState {
    const LIFECYCLE_RESPONSE_LEN: usize = 4;

    /// Creates an empty administrative state.
    pub const fn empty() -> Self {
        Self {
            privileges: SecurityDomainPrivileges::empty(),
            lifecycle: SecurityDomainLifecycle::Selectable,
        }
    }

    /// Creates an administrative state from decoded privileges and lifecycle.
    pub const fn from_parts(
        privileges: SecurityDomainPrivileges,
        lifecycle: SecurityDomainLifecycle,
    ) -> Self {
        Self {
            privileges,
            lifecycle,
        }
    }

    /// Returns the effective Security Domain privileges.
    pub const fn privileges(self) -> SecurityDomainPrivileges {
        self.privileges
    }

    /// Returns the current lifecycle.
    pub const fn lifecycle(self) -> SecurityDomainLifecycle {
        self.lifecycle
    }

    /// Writes the standard `GET DATA 9F70` response for this instance.
    pub fn write_lifecycle_data(self, out: &mut [u8]) -> Result<usize, ApduStatus> {
        if out.len() < Self::LIFECYCLE_RESPONSE_LEN {
            return Err(ApduStatus::wrong_length());
        }
        out[0] = 0x9f;
        out[1] = 0x70;
        out[2] = 0x01;
        out[3] = self.lifecycle().as_byte();
        Ok(Self::LIFECYCLE_RESPONSE_LEN)
    }
}

impl SecurityDomainPrivileges {
    /// First-byte bit declaring one Security Domain instance.
    pub const SECURITY_DOMAIN: u8 = 0x80;
    /// First-byte bit granting DAP verification.
    pub const DAP_VERIFICATION: u8 = 0x40;
    /// First-byte bit granting delegated management.
    pub const DELEGATED_MANAGEMENT: u8 = 0x20;
    /// First-byte bit granting card lock authority.
    pub const CARD_LOCK: u8 = 0x10;
    /// First-byte bit granting card termination authority.
    pub const CARD_TERMINATE: u8 = 0x08;
    /// First-byte bit granting card reset authority.
    pub const CARD_RESET: u8 = 0x04;
    /// First-byte bit granting CVM management authority.
    pub const CVM_MANAGEMENT: u8 = 0x02;
    /// First-byte bit granting mandated DAP verification.
    pub const MANDATED_DAP_VERIFICATION: u8 = 0x01;

    /// Creates an empty privilege set.
    pub const fn empty() -> Self {
        Self {
            bytes: [0; 3],
            encoded_len: 0,
            developer_open: false,
        }
    }

    /// Creates an open development privilege set.
    pub const fn open() -> Self {
        Self {
            bytes: [0xff; 3],
            encoded_len: 3,
            developer_open: true,
        }
    }

    /// Decodes the raw GlobalPlatform privilege bytes carried by `INSTALL`.
    ///
    /// The current runtime interprets the complete first byte and preserves the
    /// remaining two bytes as raw encoded state for later evolution.
    pub fn from_install_bytes(bytes: &[u8]) -> Result<Self, SecurityDomainPrivilegeError> {
        if bytes.len() > 3 {
            return Err(SecurityDomainPrivilegeError::TooLong);
        }

        let mut encoded = [0u8; 3];
        let mut index = 0;
        while index < bytes.len() {
            encoded[index] = bytes[index];
            index += 1;
        }

        Ok(Self {
            bytes: encoded,
            encoded_len: bytes.len() as u8,
            developer_open: false,
        })
    }

    /// Returns the raw encoded privilege bytes.
    pub const fn encoded_bytes(self) -> [u8; 3] {
        self.bytes
    }

    /// Returns how many privilege bytes were explicitly encoded.
    pub const fn encoded_len(self) -> usize {
        self.encoded_len as usize
    }

    /// Returns the first GlobalPlatform privilege byte.
    pub const fn first_byte(self) -> u8 {
        self.bytes[0]
    }

    /// Returns true when bytes 2 or 3 are present and therefore preserved but
    /// not yet interpreted by the runtime.
    pub const fn has_unimplemented_extension_bytes(self) -> bool {
        self.encoded_len > 1
    }

    /// Returns true if the instance is marked as a Security Domain.
    pub const fn is_security_domain(self) -> bool {
        self.developer_open || (self.first_byte() & Self::SECURITY_DOMAIN) != 0
    }

    /// Returns true if DAP verification is granted.
    pub const fn has_dap_verification(self) -> bool {
        self.developer_open || (self.first_byte() & Self::DAP_VERIFICATION) != 0
    }

    /// Returns true if delegated management is granted.
    pub const fn has_delegated_management(self) -> bool {
        self.developer_open || (self.first_byte() & Self::DELEGATED_MANAGEMENT) != 0
    }

    /// Returns true if card lock is granted.
    pub const fn may_lock_card(self) -> bool {
        self.developer_open || (self.first_byte() & Self::CARD_LOCK) != 0
    }

    /// Returns true if card termination is granted.
    pub const fn may_terminate_card(self) -> bool {
        self.developer_open || (self.first_byte() & Self::CARD_TERMINATE) != 0
    }

    /// Returns true if card reset / historical bytes management is granted.
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

    /// Returns true if the current privilege set authorizes content loading.
    ///
    /// With first-byte-only semantics, delegated management is the current
    /// management gate used by the runtime.
    pub const fn may_install_for_load(self) -> bool {
        self.developer_open || self.has_delegated_management()
    }

    /// Returns true if the current privilege set authorizes instance
    /// installation.
    pub const fn may_install_for_install(self) -> bool {
        self.developer_open || self.has_delegated_management()
    }

    /// Returns true if the current privilege set authorizes management of one
    /// application instance under the current framework policy.
    pub const fn may_manage_applet(self) -> bool {
        self.developer_open || self.has_delegated_management()
    }

    /// Returns true if the current privilege set authorizes making an instance
    /// selectable under the current framework policy.
    pub const fn may_make_selectable(self) -> bool {
        self.developer_open || self.has_delegated_management()
    }

    /// Returns true if the current privilege set authorizes deletion of
    /// managed content under the current framework policy.
    pub const fn may_delete_managed_content(self) -> bool {
        self.developer_open || self.has_delegated_management()
    }

    /// Returns true if the current privilege set authorizes `PUT KEY` under
    /// the current framework policy.
    pub const fn may_put_key(self) -> bool {
        self.developer_open || self.has_delegated_management()
    }

    /// Returns true if authorized management is granted.
    pub const fn has_authorized_management(self) -> bool {
        self.developer_open || (self.bytes[1] & 0x40) != 0
    }

    /// Returns true if global deletion is granted.
    pub const fn may_global_delete(self) -> bool {
        self.developer_open || (self.bytes[1] & 0x10) != 0
    }

    /// Returns true if global-registry access is granted.
    pub const fn may_global_registry(self) -> bool {
        self.developer_open || (self.bytes[1] & 0x04) != 0
    }

    /// Returns true if the current kernel-side management plane may be used.
    pub const fn may_manage_security_domain_plane(self) -> bool {
        self.developer_open || self.has_delegated_management() || self.has_authorized_management()
    }

    /// Returns true if the current kernel-side registry plane may be used.
    pub const fn may_access_registry_plane(self) -> bool {
        self.developer_open || self.has_delegated_management() || self.may_global_registry()
    }

    /// Returns true if `self` grants every currently implemented privilege bit
    /// requested by `other`.
    ///
    /// The current comparison interprets the whole first GlobalPlatform
    /// privilege byte and compares extension bytes conservatively as raw bits.
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

/// `INSTALL [for load]` request decoded by the kernel.
pub struct InstallForLoad<'a> {
    pub package_aid: Aid,
    pub load_parameters: &'a [u8],
}

/// `INSTALL [for install]` request decoded by the kernel.
pub struct InstallForInstall<'a> {
    pub package_aid: Aid,
    pub applet_aid: Aid,
    pub instance_aid: Aid,
    pub privilege_bytes: &'a [u8],
    pub privileges: SecurityDomainPrivileges,
    pub install_parameters: &'a [u8],
}

/// `PUT KEY` request decoded by the kernel.
pub struct PutKey<'a> {
    pub key_version: u8,
    pub key_id: u8,
    pub key_data: &'a [u8],
}

/// `STORE DATA` request decoded by the kernel.
pub struct StoreData<'a> {
    pub tag: u16,
    pub data: &'a [u8],
}

/// `SET STATUS` request decoded by the kernel.
pub struct SetStatus {
    pub target_kind: u8,
    pub target_state: u8,
    pub target_aid: Aid,
}

/// `GET DATA` tag requested from a Security Domain.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GetDataTag(pub u16);

/// Secure channel level requested or active for a Security Domain session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecurityLevel {
    bits: u8,
}

impl SecurityLevel {
    pub const NONE: Self = Self { bits: 0x00 };
    pub const C_MAC: Self = Self { bits: 0x01 };
    pub const C_ENC: Self = Self { bits: 0x02 };
    pub const R_MAC: Self = Self { bits: 0x10 };
    pub const R_ENC: Self = Self { bits: 0x20 };

    /// Creates a security level from its raw GP-style bit representation.
    pub const fn from_bits(bits: u8) -> Self {
        Self { bits }
    }

    /// Returns the raw bit representation.
    pub const fn bits(self) -> u8 {
        self.bits
    }

    /// Returns true if every bit from `other` is present.
    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }
}

/// `INITIALIZE UPDATE` request decoded by the kernel.
pub struct InitializeUpdate<'a> {
    pub key_version: u8,
    pub key_id: u8,
    pub host_challenge: &'a [u8],
}

/// `INITIALIZE UPDATE` response produced by a Security Domain.
pub struct InitializeUpdateResponse<'a> {
    pub data: &'a [u8],
}

/// `EXTERNAL AUTHENTICATE` request decoded by the kernel.
pub struct ExternalAuthenticate<'a> {
    pub cla: u8,
    pub security_level: SecurityLevel,
    pub p2: u8,
    /// Profile-sized host cryptogram followed by the transmitted C-MAC.
    pub authentication_data: &'a [u8],
}

/// Header offered to a Rustlet Security Domain when the kernel does not own
/// the corresponding secure-channel protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegatedSecureChannelHeader {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub p3: u8,
}

/// Opaque establishment command claimed by a Rustlet Security Domain.
pub struct DelegatedSecureChannelCommand<'a> {
    pub header: DelegatedSecureChannelHeader,
    pub data: &'a [u8],
}

/// SCP11 OCE certificate material verified and staged by the kernel proxy.
pub struct Scp11OceCertificate<'a> {
    pub ca_key_version: u8,
    pub ca_key_id: u8,
    pub public_key: &'a [u8],
    pub subject_id: &'a [u8],
    pub discretionary_data: &'a [u8],
}

/// SCP11a `MUTUAL AUTHENTICATE` request decoded by the kernel proxy.
pub struct Scp11aMutualAuthenticate<'a> {
    pub ecka_key_version: u8,
    pub ecka_key_id: u8,
    pub include_identifiers: bool,
    pub key_usage_qualifier: u8,
    pub key_type: u8,
    pub key_length: u8,
    pub host_id: &'a [u8],
    pub host_ephemeral_public: &'a [u8],
}

/// SCP11b `INTERNAL AUTHENTICATE` request decoded by the kernel proxy.
pub struct Scp11bInternalAuthenticate<'a> {
    pub ecka_key_version: u8,
    pub ecka_key_id: u8,
    pub include_identifiers: bool,
    pub key_usage_qualifier: u8,
    pub key_type: u8,
    pub key_length: u8,
    pub host_id: &'a [u8],
    pub host_ephemeral_public: &'a [u8],
}

/// SCP11c `MUTUAL AUTHENTICATE` request decoded by the kernel proxy.
pub struct Scp11cMutualAuthenticate<'a> {
    pub ecka_key_version: u8,
    pub ecka_key_id: u8,
    pub include_identifiers: bool,
    pub key_usage_qualifier: u8,
    pub key_type: u8,
    pub key_length: u8,
    pub host_id: &'a [u8],
    pub host_ephemeral_public: &'a [u8],
}

/// Protected command bytes after APDU-level parsing.
pub struct WrappedCommand<'a> {
    pub authenticated: &'a [u8],
    pub data: &'a [u8],
    pub mac: &'a [u8],
}

/// Plain command bytes returned by secure-channel unwrapping.
pub struct UnwrappedCommand<'a> {
    pub data: &'a [u8],
}

/// Plain response bytes before secure-channel wrapping.
pub struct PlainResponse<'a> {
    pub data: &'a [u8],
    pub status: ApduStatus,
}

/// Wrapped response bytes returned by a Security Domain.
pub struct WrappedResponse<'a> {
    pub data: &'a [u8],
    pub mac: &'a [u8],
}

/// User-land Security Domain interface implemented by privileged Rustlets.
///
/// A Security Domain Rustlet remains a normal selectable Rustlet through
/// `Rustlet::process_apdu`, but it also exposes management and secure-channel
/// hooks that the kernel can call through the dedicated Security Domain proxy.
pub trait RustletSecurityDomain: Rustlet {
    /// Returns the standard administrative state carried by this instance.
    fn administrative_state(&self) -> SecurityDomainAdministrativeState {
        SecurityDomainAdministrativeState::empty()
    }

    /// Returns the privilege set granted to this Security Domain.
    fn privileges(&self) -> SecurityDomainPrivileges {
        self.administrative_state().privileges()
    }

    /// Returns the current lifecycle of this Security Domain instance.
    fn lifecycle(&self) -> SecurityDomainLifecycle {
        self.administrative_state().lifecycle()
    }

    /// Authorizes `INSTALL [for load]`.
    fn install_for_load(&mut self, _command: &InstallForLoad<'_>) -> Result<(), ApduStatus> {
        if self.lifecycle().may_manage() && self.privileges().may_install_for_load() {
            Ok(())
        } else {
            Err(ApduStatus::conditions_not_satisfied())
        }
    }

    /// Authorizes `INSTALL [for install]`.
    fn install_for_install(&mut self, command: &InstallForInstall<'_>) -> Result<(), ApduStatus> {
        // Invariant: the proxy already enforced non-escalation before this hook runs.
        if !self.privileges().contains(command.privileges) {
            Err(ApduStatus::conditions_not_satisfied())
        } else if self.lifecycle().may_manage() && self.privileges().may_install_for_install() {
            Ok(())
        } else {
            Err(ApduStatus::conditions_not_satisfied())
        }
    }

    /// Authorizes deletion of one managed object.
    fn delete_aid(&mut self, _aid: &Aid) -> Result<(), ApduStatus> {
        if self.lifecycle().may_manage() && self.privileges().may_delete_managed_content() {
            Ok(())
        } else {
            Err(ApduStatus::conditions_not_satisfied())
        }
    }

    /// Authorizes one `PUT KEY`.
    fn put_key(&mut self, _command: &PutKey<'_>) -> Result<(), ApduStatus> {
        if self.lifecycle().may_manage() && self.privileges().may_put_key() {
            Ok(())
        } else {
            Err(ApduStatus::conditions_not_satisfied())
        }
    }

    /// Authorizes one `STORE DATA` mutation.
    fn store_data(&mut self, _command: &StoreData<'_>) -> Result<(), ApduStatus> {
        if self.lifecycle().may_manage() && self.privileges().may_access_registry_plane() {
            Ok(())
        } else {
            Err(ApduStatus::conditions_not_satisfied())
        }
    }

    /// Authorizes one `SET STATUS` lifecycle transition.
    fn set_status(&mut self, _command: &SetStatus) -> Result<(), ApduStatus> {
        if self.lifecycle().may_manage() && self.privileges().may_access_registry_plane() {
            Ok(())
        } else {
            Err(ApduStatus::conditions_not_satisfied())
        }
    }

    /// Writes `GET DATA` response bytes into `out`.
    fn get_data(&mut self, tag: GetDataTag, out: &mut [u8]) -> Result<usize, ApduStatus> {
        // Invariant: GP discovery objects are derived from the same protocol
        // hooks used by establishment dispatch, so a Rustlet SD cannot
        // accidentally advertise a kernel-only protocol.
        let capabilities = crate::gp::SecurityDomainCapabilities {
            scp03_s8: self.supports_scp03_s8(),
            scp03_s16: self.supports_scp03_s16(),
            scp11a: self.supports_scp11a(),
            scp11b: self.supports_scp11b(),
            scp11c: self.supports_scp11c(),
        };
        match tag.0 {
            0x0066 => crate::gp::write_card_recognition_data(capabilities, out)
                .map_err(|_| ApduStatus::wrong_length()),
            0x0067 if capabilities.has_secure_channel() => {
                crate::gp::write_card_capability_information(capabilities, out)
                    .map_err(|_| ApduStatus::wrong_length())
            }
            0x0067 => Err(ApduStatus::referenced_data_not_found()),
            0x9f70 => self.administrative_state().write_lifecycle_data(out),
            _ => Err(ApduStatus::instruction_not_supported()),
        }
    }

    /// Returns whether this Security Domain may manage the target applet.
    fn may_manage_applet(
        &self,
        _package_aid: &Aid,
        _applet_aid: &Aid,
        _instance_aid: &Aid,
    ) -> bool {
        self.lifecycle().may_manage() && self.privileges().may_manage_applet()
    }

    /// Returns whether this Security Domain may make the target selectable.
    fn may_make_selectable(&self, _instance_aid: &Aid) -> bool {
        self.lifecycle().may_manage() && self.privileges().may_make_selectable()
    }

    /// Returns whether this Security Domain may use the current kernel-side
    /// management plane once the proxy base filter passed.
    fn may_manage_security_domain_plane(&self) -> bool {
        self.lifecycle().may_manage() && self.privileges().may_manage_security_domain_plane()
    }

    /// Returns whether this Security Domain may use the current kernel-side
    /// registry plane once the proxy base filter passed.
    fn may_access_registry_plane(&self) -> bool {
        self.lifecycle().may_manage() && self.privileges().may_access_registry_plane()
    }

    /// Returns whether this Security Domain supports SCP03.
    fn supports_scp03(&self) -> bool {
        false
    }

    /// Returns whether this Security Domain supports SCP03 in S8 mode.
    fn supports_scp03_s8(&self) -> bool {
        self.supports_scp03()
    }

    /// Returns whether this Security Domain supports SCP03 in S16 mode.
    fn supports_scp03_s16(&self) -> bool {
        self.supports_scp03()
    }

    /// Returns whether this Security Domain supports SCP11a.
    fn supports_scp11a(&self) -> bool {
        false
    }

    /// Returns whether this Security Domain supports SCP11b.
    fn supports_scp11b(&self) -> bool {
        false
    }

    /// Returns whether this Security Domain supports SCP11c.
    fn supports_scp11c(&self) -> bool {
        false
    }

    /// Claims an establishment APDU that the configured kernel profile does
    /// not recognize.
    ///
    /// The claim is intentionally header-only so the transport does not
    /// consume command data before one Security Domain accepts ownership.
    fn claims_delegated_secure_channel_command(
        &self,
        _header: DelegatedSecureChannelHeader,
    ) -> bool {
        false
    }

    /// Advances one establishment protocol owned entirely by this Security
    /// Domain rather than by the kernel profile matrix.
    ///
    /// The default implementation adapts SCP03 to the existing family APIs.
    /// A future supplementary Security Domain may override this method to
    /// implement another GP-compatible establishment sequence.
    fn handle_delegated_secure_channel_command(
        &mut self,
        ctx: &mut RustletCtx,
        command: &DelegatedSecureChannelCommand<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        match command.header.ins {
            0x50 => self.initialize_update(
                ctx,
                &InitializeUpdate {
                    key_version: command.header.p1,
                    key_id: command.header.p2,
                    host_challenge: command.data,
                },
                out,
            ),
            0x82 if command.header.p2 == 0x00 => {
                self.external_authenticate(
                    ctx,
                    &ExternalAuthenticate {
                        cla: command.header.cla,
                        security_level: SecurityLevel::from_bits(command.header.p1),
                        p2: command.header.p2,
                        authentication_data: command.data,
                    },
                )?;
                Ok(0)
            }
            _ => Err(ApduStatus::instruction_not_supported()),
        }
    }

    /// Stages one verified OCE certificate for a future SCP11 exchange.
    fn scp11_stage_oce_certificate(
        &mut self,
        _ctx: &mut RustletCtx,
        _certificate: &Scp11OceCertificate<'_>,
    ) -> Result<(), ApduStatus> {
        Err(ApduStatus::instruction_not_supported())
    }

    /// Completes one SCP11a mutual authentication.
    fn scp11a_mutual_authenticate(
        &mut self,
        _ctx: &mut RustletCtx,
        _command: &Scp11aMutualAuthenticate<'_>,
        _out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        Err(ApduStatus::instruction_not_supported())
    }

    /// Completes one SCP11b internal authentication.
    fn scp11b_internal_authenticate(
        &mut self,
        _ctx: &mut RustletCtx,
        _command: &Scp11bInternalAuthenticate<'_>,
        _out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        Err(ApduStatus::instruction_not_supported())
    }

    /// Completes one SCP11c mutual authentication.
    fn scp11c_mutual_authenticate(
        &mut self,
        _ctx: &mut RustletCtx,
        _command: &Scp11cMutualAuthenticate<'_>,
        _out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        Err(ApduStatus::instruction_not_supported())
    }

    /// Starts one `INITIALIZE UPDATE` exchange.
    fn initialize_update(
        &mut self,
        _ctx: &mut RustletCtx,
        _command: &InitializeUpdate<'_>,
        _out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        Err(ApduStatus::instruction_not_supported())
    }

    /// Completes one `EXTERNAL AUTHENTICATE` exchange.
    fn external_authenticate(
        &mut self,
        _ctx: &mut RustletCtx,
        _command: &ExternalAuthenticate<'_>,
    ) -> Result<SecurityLevel, ApduStatus> {
        Err(ApduStatus::instruction_not_supported())
    }

    /// Returns the current secure messaging level.
    fn current_security_level(&self) -> SecurityLevel {
        SecurityLevel::NONE
    }

    /// Returns whether a secure channel is currently open.
    fn secure_channel_open(&self) -> bool {
        false
    }

    /// Returns the expected protected-command MAC length.
    fn current_mac_len(&self) -> usize {
        0
    }

    /// Unwraps one protected command.
    fn unwrap_command(
        &mut self,
        _ctx: &mut RustletCtx,
        _command: &WrappedCommand<'_>,
        _out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        Err(ApduStatus::instruction_not_supported())
    }

    /// Wraps one response.
    fn wrap_response(
        &mut self,
        _ctx: &mut RustletCtx,
        _response: &PlainResponse<'_>,
        _out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        Err(ApduStatus::instruction_not_supported())
    }

    /// Clears the current secure-channel state.
    fn reset_secure_channel(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileges_decode_first_byte_and_preserve_extensions() {
        let privileges = SecurityDomainPrivileges::from_install_bytes(&[0xA0, 0x12, 0x34])
            .expect("decode privileges");
        assert!(privileges.is_security_domain());
        assert!(privileges.has_delegated_management());
        assert_eq!(privileges.encoded_bytes(), [0xA0, 0x12, 0x34]);
        assert!(privileges.has_unimplemented_extension_bytes());
    }

    #[test]
    fn lifecycle_get_data_response_matches_gp_tag() {
        let state = SecurityDomainAdministrativeState::from_parts(
            SecurityDomainPrivileges::empty(),
            SecurityDomainLifecycle::Locked,
        );
        let mut out = [0u8; 4];
        let len = state
            .write_lifecycle_data(&mut out)
            .expect("write lifecycle data");
        assert_eq!(len, 4);
        assert_eq!(
            out,
            [0x9f, 0x70, 0x01, SecurityDomainLifecycle::Locked.as_byte()]
        );
    }
}
