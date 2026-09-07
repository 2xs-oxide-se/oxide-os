#![no_std]
#![no_main]

use rustlet_runtime::{
    declare_security_domain, Aid, Apdu, ApduStatus, Rustlet, RustletCtx, RustletSecurityDomain,
};

declare_security_domain!(SimpleSecurityDomain);

/// Example AID for the minimal Security Domain skeleton.
///
/// This value is intentionally distinct from `complete_security_domain` so both
/// crates can coexist in the workspace without colliding.
const SIMPLE_SECURITY_DOMAIN_AID: Aid =
    Aid::from_array([0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x11]);

/// Minimal Security Domain skeleton.
///
/// This Rustlet deliberately relies on the default `RustletSecurityDomain`
/// behavior implemented by the runtime. It is meant to be copied and refined
/// when building a custom user-land Security Domain.
#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct SimpleSecurityDomain;

impl Rustlet for SimpleSecurityDomain {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);
        if apdu.is_select() {
            return self.handle_select(apdu);
        }

        match apdu.ins() {
            0x00 => apdu.accept(),
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}

impl RustletSecurityDomain for SimpleSecurityDomain {
    // Default management hooks available for refinement:
    //
    // fn install_for_load(&mut self, command: &InstallForLoad<'_>) -> Result<(), ApduStatus>
    // Default: accepts only when the runtime administrative state is manageable
    // and the delegated-management privilege authorizes content loading.
    //
    // fn install_for_install(&mut self, command: &InstallForInstall<'_>) -> Result<(), ApduStatus>
    // Default: enforces privilege containment locally, then accepts only when
    // lifecycle and delegated-management privilege allow instance installation.
    //
    // fn delete_aid(&mut self, aid: &Aid) -> Result<(), ApduStatus>
    // Default: accepts only when lifecycle and delegated-management privilege
    // authorize deletion of managed content.
    //
    // fn put_key(&mut self, command: &PutKey<'_>) -> Result<(), ApduStatus>
    // Default: accepts only when lifecycle and delegated-management privilege
    // authorize `PUT KEY`.
    //
    // fn get_data(&mut self, tag: GetDataTag, out: &mut [u8]) -> Result<usize, ApduStatus>
    // Default: serves `GET DATA 9F70` from the runtime administrative state and
    // rejects other tags.
    //
    // fn may_manage_applet(&self, package_aid: &Aid, applet_aid: &Aid, instance_aid: &Aid) -> bool
    // fn may_make_selectable(&self, instance_aid: &Aid) -> bool
    // Default: derive the answer from lifecycle plus delegated-management privilege.
    //
    // Default secure-channel hooks:
    //
    // fn supports_scp03(&self) -> bool
    // Default: false.
    //
    // fn initialize_update(...)
    // fn external_authenticate(...)
    // fn unwrap_command(...)
    // fn wrap_response(...)
    // Default: reject with `instruction_not_supported`.
    //
    // fn current_security_level(&self) -> SecurityLevel
    // fn secure_channel_open(&self) -> bool
    // fn current_mac_len(&self) -> usize
    // fn reset_secure_channel(&mut self)
    // Default: no active secure channel, no MAC, and no-op reset.
}

impl SimpleSecurityDomain {
    fn handle_select(&mut self, apdu: Apdu<'_, rustlet_runtime::Command>) -> ApduStatus {
        let fci = [
            0x6F,
            0x10,
            0x84,
            SIMPLE_SECURITY_DOMAIN_AID.len,
            SIMPLE_SECURITY_DOMAIN_AID.bytes[0],
            SIMPLE_SECURITY_DOMAIN_AID.bytes[1],
            SIMPLE_SECURITY_DOMAIN_AID.bytes[2],
            SIMPLE_SECURITY_DOMAIN_AID.bytes[3],
            SIMPLE_SECURITY_DOMAIN_AID.bytes[4],
            SIMPLE_SECURITY_DOMAIN_AID.bytes[5],
            SIMPLE_SECURITY_DOMAIN_AID.bytes[6],
            SIMPLE_SECURITY_DOMAIN_AID.bytes[7],
            0xA5,
            0x04,
            0x9F,
            0x65,
            0x01,
            0x01,
        ];
        apdu.as_sending().send(&fci)
    }
}
