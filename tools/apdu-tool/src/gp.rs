//! Shared GlobalPlatform command builders and response decoders.

use crate::{ApduToolError, ErrorKind, OwnedT0Command, ToolResult};

pub const CLA_GP: u8 = 0x80;
pub const INS_INITIALIZE_UPDATE: u8 = 0x50;
pub const INS_GET_DATA: u8 = 0xCA;
pub const INS_STORE_DATA: u8 = 0xE2;
pub const INS_DELETE: u8 = 0xE4;
pub const INS_INSTALL: u8 = 0xE6;
pub const INS_LOAD: u8 = 0xE8;
pub const INS_PUT_KEY: u8 = 0xD8;
pub const INS_SET_STATUS: u8 = 0xF0;
pub const INS_GET_STATUS: u8 = 0xF2;
pub const SW_MORE_STATUS_DATA: (u8, u8) = (0x63, 0x10);
pub const SET_STATUS_KIND_PACKAGE: u8 = 0x20;
pub const SET_STATUS_KIND_APPLICATION: u8 = 0x40;
pub const SET_STATUS_KIND_SECURITY_DOMAIN: u8 = 0x80;
pub const SET_STATUS_STATE_UNLOCKED: u8 = 0x00;
pub const SET_STATUS_STATE_LOCKED: u8 = 0x80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusCategory {
    IssuerSecurityDomain,
    Applications,
    Packages,
    Modules,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryObjectKind {
    Package,
    Application,
    SecurityDomain,
}

impl RegistryObjectKind {
    pub const fn p1(self) -> u8 {
        match self {
            Self::Package => SET_STATUS_KIND_PACKAGE,
            Self::Application => SET_STATUS_KIND_APPLICATION,
            Self::SecurityDomain => SET_STATUS_KIND_SECURITY_DOMAIN,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryState {
    Unlocked,
    Locked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUsage {
    Scp03Enc,
    Scp03Mac,
    Scp11SdEcka,
    Scp11CaKloc,
}

impl KeyUsage {
    pub const fn byte(self) -> u8 {
        match self {
            Self::Scp03Enc => 0x01,
            Self::Scp03Mac => 0x02,
            Self::Scp11SdEcka => 0x11,
            Self::Scp11CaKloc => 0x12,
        }
    }

    pub const fn material_len(self) -> usize {
        match self {
            Self::Scp03Enc | Self::Scp03Mac => 16,
            Self::Scp11SdEcka => 32,
            Self::Scp11CaKloc => 65,
        }
    }

    pub const fn key_type(self) -> u8 {
        match self {
            Self::Scp03Enc | Self::Scp03Mac => 0x88,
            Self::Scp11SdEcka => 0xB1,
            Self::Scp11CaKloc => 0xB0,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct KeyEntry {
    pub usage: KeyUsage,
    pub material: Vec<u8>,
}

impl core::fmt::Debug for KeyEntry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KeyEntry")
            .field("usage", &self.usage)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl RegistryState {
    pub const fn p2(self) -> u8 {
        match self {
            Self::Unlocked => SET_STATUS_STATE_UNLOCKED,
            Self::Locked => SET_STATUS_STATE_LOCKED,
        }
    }
}

impl StatusCategory {
    pub const fn p1(self) -> u8 {
        match self {
            Self::IssuerSecurityDomain => 0x80,
            Self::Applications => 0x40,
            Self::Packages => 0x20,
            Self::Modules => 0x10,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::IssuerSecurityDomain => "Issuer Security Domain",
            Self::Applications => "Application/Security Domain",
            Self::Packages => "Executable Load File",
            Self::Modules => "Executable Load File/module",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusRecord {
    pub aid: Vec<u8>,
    pub lifecycle: Option<u8>,
    pub privileges: Vec<u8>,
    pub package_aid: Vec<u8>,
    pub module_aid: Vec<u8>,
    pub parent_security_domain_aid: Vec<u8>,
}

/// A GP exchange result retaining wire data, status word, and decoded fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultData<T> {
    pub data: Vec<u8>,
    pub status_word: (u8, u8),
    pub decoded: T,
}

pub fn command(ins: u8, p1: u8, p2: u8, data: &[u8], le: u8) -> ToolResult<OwnedT0Command> {
    let lc = u8::try_from(data.len()).map_err(|_| {
        ApduToolError::new(
            ErrorKind::InvalidInput,
            "GP short APDU data exceeds 255 bytes",
        )
    })?;
    OwnedT0Command::from_wire_fields(CLA_GP, ins, p1, p2, lc, le, data.to_vec())
}

pub fn get_data(tag: u16, le: u8) -> ToolResult<OwnedT0Command> {
    command(INS_GET_DATA, (tag >> 8) as u8, tag as u8, &[], le)
}

pub fn get_status(
    category: StatusCategory,
    next_occurrence: bool,
    aid_filter: &[u8],
) -> ToolResult<OwnedT0Command> {
    if aid_filter.len() > 16 {
        return Err(ApduToolError::new(
            ErrorKind::InvalidInput,
            "GET STATUS AID filter cannot exceed 16 bytes",
        ));
    }
    let mut data = Vec::with_capacity(2 + aid_filter.len());
    push_tlv(&mut data, &[0x4F], aid_filter)?;
    command(
        INS_GET_STATUS,
        category.p1(),
        if next_occurrence { 0x03 } else { 0x02 },
        &data,
        0,
    )
}

pub fn get_status_with_p1(p1: u8, next: bool, aid_filter: &[u8]) -> ToolResult<OwnedT0Command> {
    let category = match p1 {
        0x80 => StatusCategory::IssuerSecurityDomain,
        0x40 => StatusCategory::Applications,
        0x20 => StatusCategory::Packages,
        0x10 => StatusCategory::Modules,
        _ => {
            return Err(ApduToolError::new(
                ErrorKind::InvalidInput,
                "invalid GET STATUS P1",
            ))
        }
    };
    get_status(category, next, aid_filter)
}

pub fn store_data(tag: u16, data: &[u8]) -> ToolResult<OwnedT0Command> {
    if tag == 0 {
        return Err(ApduToolError::new(
            ErrorKind::InvalidInput,
            "GP data tag 0000 is invalid",
        ));
    }
    let tag_bytes = if tag <= 0xFF {
        vec![tag as u8]
    } else {
        vec![(tag >> 8) as u8, tag as u8]
    };
    let mut encoded = Vec::new();
    push_tlv(&mut encoded, &tag_bytes, data)?;
    // Last command, BER-TLV data structure, no encryption at STORE DATA level.
    command(INS_STORE_DATA, 0xA0, 0x00, &encoded, 0)
}

pub fn delete_aid(aid: &[u8]) -> ToolResult<OwnedT0Command> {
    delete_aid_with_related(aid, false)
}

pub fn delete_aid_with_related(aid: &[u8], delete_related: bool) -> ToolResult<OwnedT0Command> {
    validate_aid(aid)?;
    let mut data = Vec::with_capacity(2 + aid.len());
    push_tlv(&mut data, &[0x4F], aid)?;
    command(
        INS_DELETE,
        0,
        if delete_related { 0x80 } else { 0 },
        &data,
        0,
    )
}

pub fn delete_data(tag: u16) -> ToolResult<OwnedT0Command> {
    if tag == 0 {
        return Err(ApduToolError::new(
            ErrorKind::InvalidInput,
            "GP data tag 0000 is invalid",
        ));
    }
    delete_aid(&[b'D', b'A', b'T', b'A', (tag >> 8) as u8, tag as u8])
}

pub fn set_status(
    kind: RegistryObjectKind,
    aid: &[u8],
    state: RegistryState,
) -> ToolResult<OwnedT0Command> {
    validate_aid(aid)?;
    let mut data = Vec::with_capacity(2 + aid.len());
    push_tlv(&mut data, &[0x4F], aid)?;
    command(INS_SET_STATUS, kind.p1(), state.p2(), &data, 0)
}

pub fn put_key(version: u8, first_id: u8, entries: &[KeyEntry]) -> ToolResult<OwnedT0Command> {
    if version > 0x7F || first_id > 0x7F || entries.is_empty() {
        return Err(ApduToolError::new(
            ErrorKind::InvalidInput,
            "PUT KEY version/id must fit 7 bits and at least one key is required",
        ));
    }
    for (index, entry) in entries.iter().enumerate() {
        let valid_scp03_position = match entry.usage {
            KeyUsage::Scp03Enc => index == 0,
            KeyUsage::Scp03Mac => index == 1 && entries[0].usage == KeyUsage::Scp03Enc,
            KeyUsage::Scp11SdEcka | KeyUsage::Scp11CaKloc => true,
        };
        if !valid_scp03_position {
            return Err(ApduToolError::new(
                ErrorKind::InvalidInput,
                "SCP03 PUT KEY requires ENC as the first entry and MAC as the second entry of the same command",
            ));
        }
    }
    let mut data = vec![version];
    for entry in entries {
        if entry.material.len() != entry.usage.material_len() {
            return Err(ApduToolError::new(
                ErrorKind::InvalidInput,
                format!(
                    "PUT KEY {:?} material must contain {} bytes",
                    entry.usage,
                    entry.usage.material_len()
                ),
            ));
        }
        data.push(entry.usage.key_type());
        push_lv(&mut data, &entry.material)?;
        // No KCV is supplied by the development tooling.
        data.push(0x00);
    }
    command(
        INS_PUT_KEY,
        0x00,
        first_id | if entries.len() > 1 { 0x80 } else { 0 },
        &data,
        0,
    )
}

fn validate_aid(aid: &[u8]) -> ToolResult<()> {
    if !(5..=16).contains(&aid.len()) {
        return Err(ApduToolError::new(
            ErrorKind::InvalidInput,
            format!("AID must contain 5 to 16 bytes, got {}", aid.len()),
        ));
    }
    Ok(())
}

pub fn install_for_load(
    package: &[u8],
    domain: &[u8],
    total: u32,
    hash: &[u8],
) -> ToolResult<OwnedT0Command> {
    install_for_load_with_parameters(package, domain, hash, total.to_be_bytes().as_slice(), &[])
}

pub fn install_for_load_with_parameters(
    package: &[u8],
    domain: &[u8],
    hash: &[u8],
    load_parameters: &[u8],
    token: &[u8],
) -> ToolResult<OwnedT0Command> {
    validate_aid(package)?;
    if !domain.is_empty() {
        validate_aid(domain)?;
    }
    let mut data = Vec::new();
    for value in [package, domain, hash, load_parameters, token] {
        push_lv(&mut data, value)?;
    }
    command(INS_INSTALL, 0x02, 0, &data, 0)
}

pub fn load_block(number: u8, last: bool, data: &[u8]) -> ToolResult<OwnedT0Command> {
    command(INS_LOAD, if last { 0x80 } else { 0 }, number, data, 0)
}

/// Encodes one unencrypted GlobalPlatform Load File Data Block (`C4`).
pub fn encode_load_file_data_block(load_file: &[u8]) -> ToolResult<Vec<u8>> {
    let mut encoded = Vec::new();
    push_tlv(&mut encoded, &[0xC4], load_file)?;
    Ok(encoded)
}

pub fn install_for_install(
    package: &[u8],
    module: &[u8],
    instance: &[u8],
    privileges: &[u8],
    parameters: &[u8],
) -> ToolResult<OwnedT0Command> {
    install_application(0x04, package, module, instance, privileges, parameters)
}

pub fn install_and_make_selectable(
    package: &[u8],
    module: &[u8],
    instance: &[u8],
    privileges: &[u8],
    parameters: &[u8],
) -> ToolResult<OwnedT0Command> {
    install_application(0x0c, package, module, instance, privileges, parameters)
}

fn install_application(
    p1: u8,
    package: &[u8],
    module: &[u8],
    instance: &[u8],
    privileges: &[u8],
    parameters: &[u8],
) -> ToolResult<OwnedT0Command> {
    validate_aid(package)?;
    validate_aid(module)?;
    validate_aid(instance)?;
    if privileges.len() > 3 {
        return Err(ApduToolError::new(
            ErrorKind::InvalidInput,
            "INSTALL privileges cannot exceed three bytes",
        ));
    }
    let mut data = Vec::new();
    for value in [package, module, instance, privileges, parameters] {
        push_lv(&mut data, value)?;
    }
    // INSTALL Token LV is mandatory in the command data even when no token is
    // present for the current Security Domain policy.
    push_lv(&mut data, &[])?;
    command(INS_INSTALL, p1, 0, &data, 0)
}

pub fn push_lv(out: &mut Vec<u8>, value: &[u8]) -> ToolResult<()> {
    let len = u8::try_from(value.len()).map_err(|_| {
        ApduToolError::new(ErrorKind::InvalidInput, "GP LV value exceeds 255 bytes")
    })?;
    out.push(len);
    out.extend_from_slice(value);
    Ok(())
}

pub fn push_tlv(out: &mut Vec<u8>, tag: &[u8], value: &[u8]) -> ToolResult<()> {
    if tag.is_empty() {
        return Err(ApduToolError::new(ErrorKind::InvalidInput, "empty TLV tag"));
    }
    out.extend_from_slice(tag);
    match value.len() {
        len @ 0..=0x7F => out.push(len as u8),
        len @ 0x80..=0xFF => out.extend_from_slice(&[0x81, len as u8]),
        len @ 0x100..=0xFFFF => {
            out.push(0x82);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            return Err(ApduToolError::new(
                ErrorKind::InvalidInput,
                "BER-TLV value exceeds 65535 bytes",
            ))
        }
    }
    out.extend_from_slice(value);
    Ok(())
}

pub fn read_tlv<'a>(data: &'a [u8], offset: &mut usize) -> Option<(u32, &'a [u8])> {
    let first = *data.get(*offset)?;
    *offset += 1;
    let mut tag = u32::from(first);
    if first & 0x1F == 0x1F {
        loop {
            let byte = *data.get(*offset)?;
            *offset += 1;
            tag = (tag << 8) | u32::from(byte);
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    let first_len = *data.get(*offset)?;
    *offset += 1;
    let len = if first_len & 0x80 == 0 {
        usize::from(first_len)
    } else {
        let count = usize::from(first_len & 0x7F);
        if !(1..=2).contains(&count) {
            return None;
        }
        let mut len = 0;
        for _ in 0..count {
            len = (len << 8) | usize::from(*data.get(*offset)?);
            *offset += 1;
        }
        len
    };
    let end = (*offset).checked_add(len)?;
    let value = data.get(*offset..end)?;
    *offset = end;
    Some((tag, value))
}

pub fn decode_status(data: &[u8]) -> ToolResult<Vec<StatusRecord>> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let (tag, value) = read_tlv(data, &mut offset).ok_or_else(|| {
            ApduToolError::new(ErrorKind::T0Protocol, "malformed GET STATUS response")
        })?;
        if tag != 0xE3 {
            return Err(ApduToolError::new(
                ErrorKind::T0Protocol,
                format!("expected E3 record, got {tag:X}"),
            ));
        }
        let mut record = StatusRecord {
            aid: Vec::new(),
            lifecycle: None,
            privileges: Vec::new(),
            package_aid: Vec::new(),
            module_aid: Vec::new(),
            parent_security_domain_aid: Vec::new(),
        };
        let mut field_offset = 0;
        while field_offset < value.len() {
            let (tag, field) = read_tlv(value, &mut field_offset).ok_or_else(|| {
                ApduToolError::new(ErrorKind::T0Protocol, "malformed GET STATUS record")
            })?;
            match tag {
                0x4F => record.aid = field.to_vec(),
                0x9F70 if field.len() == 1 => record.lifecycle = Some(field[0]),
                0xC5 => record.privileges = field.to_vec(),
                0xC4 => record.package_aid = field.to_vec(),
                0x84 => record.module_aid = field.to_vec(),
                0xCC => record.parent_security_domain_aid = field.to_vec(),
                _ => {}
            }
        }
        records.push(record);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builders_match_existing_qemu_vectors() {
        assert_eq!(
            get_data(0x0066, 0).unwrap().display_bytes(),
            [0x80, 0xCA, 0, 0x66, 0, 0]
        );
        assert_eq!(
            get_status(StatusCategory::IssuerSecurityDomain, false, &[])
                .unwrap()
                .display_bytes(),
            [0x80, 0xF2, 0x80, 0x02, 0x02, 0, 0x4F, 0]
        );
    }

    #[test]
    fn status_decoder_reads_modern_e3_records() {
        let data = [
            0xE3, 0x0D, 0x4F, 2, 0xA0, 1, 0x9F, 0x70, 1, 7, 0xC5, 3, 0xA0, 0, 0,
        ];
        let decoded = decode_status(&data).unwrap();
        assert_eq!(decoded[0].aid, [0xA0, 1]);
        assert_eq!(decoded[0].lifecycle, Some(7));
    }

    #[test]
    fn shared_tlv_encoder_uses_ber_length_forms() {
        let mut encoded = Vec::new();
        push_tlv(&mut encoded, &[0x7F, 0x21], &[0xAA; 128]).unwrap();
        assert_eq!(&encoded[..4], &[0x7F, 0x21, 0x81, 0x80]);
        assert_eq!(encoded.len(), 132);
    }
}
