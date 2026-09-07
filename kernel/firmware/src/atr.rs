use crate::core::scp11::Scp11Profile;
use crate::core::target::{self, DefaultSecurityDomainKind, KernelScp03Profile};

/// Oxide SE version 0.9 beta, advertised in the proprietary ATR payload.
pub const OXIDE_SE_VERSION: u8 = 0x09;

const CATEGORY_COMPACT_TLV: u8 = 0x80;
const COMPACT_TLV_ISSUER_DATA_LEN_6: u8 = 0x56;
const COMPACT_TLV_CARD_CAPABILITIES_LEN_3: u8 = 0x73;
const OXIDE_SE_ATR_MARKER: [u8; 4] = [0x09, 0xC1, 0xDE, 0x5E];
const ISO_CARD_CAPABILITIES_SELECT_BY_FULL_DF_NAME: [u8; 3] = [0x80, 0x00, 0x00];

/// Builds the ISO compact-TLV historical bytes advertised in the ATR.
///
/// The proprietary issuer-data TLV is intentionally small: it identifies the
/// Oxide SE kernel, carries the OS version, and exposes only build
/// capabilities that are true before any APDU exchange has occurred.
pub fn historical_bytes() -> [u8; 12] {
    [
        CATEGORY_COMPACT_TLV,
        COMPACT_TLV_ISSUER_DATA_LEN_6,
        OXIDE_SE_ATR_MARKER[0],
        OXIDE_SE_ATR_MARKER[1],
        OXIDE_SE_ATR_MARKER[2],
        OXIDE_SE_ATR_MARKER[3],
        OXIDE_SE_VERSION,
        capability_byte(),
        COMPACT_TLV_CARD_CAPABILITIES_LEN_3,
        ISO_CARD_CAPABILITIES_SELECT_BY_FULL_DF_NAME[0],
        ISO_CARD_CAPABILITIES_SELECT_BY_FULL_DF_NAME[1],
        ISO_CARD_CAPABILITIES_SELECT_BY_FULL_DF_NAME[2],
    ]
}

fn capability_byte() -> u8 {
    let mut yy = 0u8;

    if !matches!(
        target::default_security_domain_kind(),
        DefaultSecurityDomainKind::NullSecurityDomain
    ) {
        yy |= 0x80;
    }

    let scp11_profiles = target::scp11_profiles();
    if scp11_profiles.supports(Scp11Profile::A) {
        yy |= 0x40;
    }
    if scp11_profiles.supports(Scp11Profile::B) {
        yy |= 0x20;
    }
    if scp11_profiles.supports(Scp11Profile::C) {
        yy |= 0x10;
    }

    if target::secure_channel_mode().supports_scp03() {
        yy |= match target::kernel_scp03_profile() {
            KernelScp03Profile::S8 => 0b10,
            KernelScp03Profile::S16 => 0b11,
        };
    }

    yy
}
