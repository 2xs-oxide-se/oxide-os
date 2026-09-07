/// Errors returned while decoding GlobalPlatform command payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// One LV or TLV field is structurally malformed.
    Malformed,
    /// The payload contains trailing bytes after one complete structure.
    TrailingBytes,
    /// The payload uses one unsupported BER-TLV encoding form.
    Unsupported,
}

/// Errors returned while encoding short GlobalPlatform BER-TLV objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The destination cannot hold the complete encoded object.
    BufferTooSmall,
    /// One TLV value exceeds the short-form BER length supported by APDUs.
    ValueTooLong,
    /// Constructed TLVs were closed in a different order than they were opened.
    InvalidNesting,
}

/// SCP03 option values advertised through GlobalPlatform discovery objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scp03Option {
    /// Legacy S8 challenge, cryptogram and MAC lengths.
    S8,
    /// S16 challenge, cryptogram and MAC lengths.
    S16,
}

impl Scp03Option {
    /// Returns the Amendment D parameter `i` for random challenges without
    /// R-MAC or R-ENCRYPTION support.
    pub const fn parameter_i(self) -> u8 {
        match self {
            Self::S8 => 0x00,
            Self::S16 => 0x01,
        }
    }
}

/// Security-channel capabilities published by one Security Domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityDomainCapabilities {
    pub scp03_s8: bool,
    pub scp03_s16: bool,
    pub scp11a: bool,
    pub scp11b: bool,
    pub scp11c: bool,
}

impl SecurityDomainCapabilities {
    /// Builds a capability set that advertises no secure-channel protocol.
    pub const fn none() -> Self {
        Self {
            scp03_s8: false,
            scp03_s16: false,
            scp11a: false,
            scp11b: false,
            scp11c: false,
        }
    }

    /// Returns true when at least one secure-channel protocol is advertised.
    pub const fn has_secure_channel(self) -> bool {
        self.scp03_s8 || self.scp03_s16 || self.scp11a || self.scp11b || self.scp11c
    }

    /// Returns the SCP11 parameter `i` bitmap for the selected S16 profiles.
    pub const fn scp11_parameter_i(self) -> Option<u8> {
        let mut parameter = 0x40;
        let mut present = false;
        if self.scp11a {
            parameter |= 0x01;
            present = true;
        }
        if self.scp11b {
            parameter |= 0x02;
            present = true;
        }
        if self.scp11c {
            parameter |= 0x10;
            present = true;
        }
        if present {
            Some(parameter)
        } else {
            None
        }
    }
}

/// Marker returned when opening one constructed BER-TLV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BerTlvMarker {
    length_offset: usize,
    value_offset: usize,
}

/// Allocation-free writer for BER-TLV objects carried by short APDUs.
///
/// GlobalPlatform discovery and registry records produced by Oxide SE are
/// individually shorter than 128 bytes, so their BER lengths use the canonical
/// one-byte short form. The writer deliberately rejects larger individual
/// values rather than introducing an intermediate buffer.
pub struct BerTlvWriter<'a> {
    out: &'a mut [u8],
    offset: usize,
}

impl<'a> BerTlvWriter<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, offset: 0 }
    }

    /// Returns the number of bytes written so far.
    pub const fn len(&self) -> usize {
        self.offset
    }

    /// Returns whether no bytes have been written yet.
    pub const fn is_empty(&self) -> bool {
        self.offset == 0
    }

    /// Returns the unused tail of the destination.
    pub fn remaining_mut(&mut self) -> &mut [u8] {
        &mut self.out[self.offset..]
    }

    /// Opens one constructed TLV and reserves its short-form length byte.
    pub fn start(&mut self, tag: &[u8]) -> Result<BerTlvMarker, EncodeError> {
        if tag.is_empty() || self.out.len().saturating_sub(self.offset) < tag.len() + 1 {
            return Err(EncodeError::BufferTooSmall);
        }
        let tag_end = self.offset + tag.len();
        self.out[self.offset..tag_end].copy_from_slice(tag);
        self.out[tag_end] = 0;
        self.offset = tag_end + 1;
        Ok(BerTlvMarker {
            length_offset: tag_end,
            value_offset: self.offset,
        })
    }

    /// Closes the most recently opened TLV.
    pub fn finish(&mut self, marker: BerTlvMarker) -> Result<(), EncodeError> {
        if marker.value_offset > self.offset
            || marker.length_offset + 1 != marker.value_offset
            || marker.length_offset >= self.out.len()
        {
            return Err(EncodeError::InvalidNesting);
        }
        let value_len = self.offset - marker.value_offset;
        if value_len > 0x7f {
            return Err(EncodeError::ValueTooLong);
        }
        self.out[marker.length_offset] = value_len as u8;
        Ok(())
    }

    /// Appends one primitive TLV.
    pub fn primitive(&mut self, tag: &[u8], value: &[u8]) -> Result<(), EncodeError> {
        if value.len() > 0x7f {
            return Err(EncodeError::ValueTooLong);
        }
        let required = tag
            .len()
            .checked_add(1)
            .and_then(|len| len.checked_add(value.len()))
            .ok_or(EncodeError::BufferTooSmall)?;
        if tag.is_empty() || self.out.len().saturating_sub(self.offset) < required {
            return Err(EncodeError::BufferTooSmall);
        }
        let tag_end = self.offset + tag.len();
        self.out[self.offset..tag_end].copy_from_slice(tag);
        self.out[tag_end] = value.len() as u8;
        let value_end = tag_end + 1 + value.len();
        self.out[tag_end + 1..value_end].copy_from_slice(value);
        self.offset = value_end;
        Ok(())
    }
}

const GLOBAL_PLATFORM_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xfc, 0x6b];
const GLOBAL_PLATFORM_RECOGNITION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xfc, 0x6b, 0x01];
const GLOBAL_PLATFORM_MANAGEMENT_V23_OID: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xfc, 0x6b, 0x02, 0x02, 0x03];
const GLOBAL_PLATFORM_IDENTIFICATION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xfc, 0x6b, 0x03];

fn write_scp_oid(
    writer: &mut BerTlvWriter<'_>,
    scp: u8,
    parameter_i: u8,
) -> Result<(), EncodeError> {
    let template = writer.start(&[0x64])?;
    let mut oid = [0u8; 9];
    oid[..GLOBAL_PLATFORM_OID.len()].copy_from_slice(GLOBAL_PLATFORM_OID);
    oid[6] = 0x04;
    oid[7] = scp;
    oid[8] = parameter_i;
    writer.primitive(&[0x06], &oid)?;
    writer.finish(template)
}

/// Writes the GP Card Recognition Data object (`66`) for one Security Domain.
///
/// A capability set without SCPs remains a well-formed recognition structure
/// but omits tag `64`. This is used by the development Null Security Domain;
/// a production Issuer Security Domain is expected to advertise at least one
/// SCP as required by the GP Card Specification.
pub fn write_card_recognition_data(
    capabilities: SecurityDomainCapabilities,
    out: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut writer = BerTlvWriter::new(out);
    let card_data = writer.start(&[0x66])?;
    let recognition = writer.start(&[0x73])?;
    writer.primitive(&[0x06], GLOBAL_PLATFORM_RECOGNITION_OID)?;

    let management = writer.start(&[0x60])?;
    writer.primitive(&[0x06], GLOBAL_PLATFORM_MANAGEMENT_V23_OID)?;
    writer.finish(management)?;

    let identification = writer.start(&[0x63])?;
    writer.primitive(&[0x06], GLOBAL_PLATFORM_IDENTIFICATION_OID)?;
    writer.finish(identification)?;

    if capabilities.scp03_s8 {
        write_scp_oid(&mut writer, 0x03, Scp03Option::S8.parameter_i())?;
    }
    if capabilities.scp03_s16 {
        write_scp_oid(&mut writer, 0x03, Scp03Option::S16.parameter_i())?;
    }
    if let Some(parameter_i) = capabilities.scp11_parameter_i() {
        write_scp_oid(&mut writer, 0x11, parameter_i)?;
    }

    writer.finish(recognition)?;
    writer.finish(card_data)?;
    Ok(writer.len())
}

fn write_scp_capability(
    writer: &mut BerTlvWriter<'_>,
    scp: u8,
    options: &[u8],
    supported_keys: Option<u8>,
) -> Result<(), EncodeError> {
    let template = writer.start(&[0xa0])?;
    writer.primitive(&[0x80], &[scp])?;
    writer.primitive(&[0x81], options)?;
    if let Some(keys) = supported_keys {
        writer.primitive(&[0x82], &[keys])?;
    }
    writer.finish(template)
}

/// Writes the optional GP Card Capability Information object (`67`).
///
/// The current profile reports AES-128 for SCP03, SHA-256 for the load-file
/// data block hash, and exactly the privilege bits interpreted by the kernel.
pub fn write_card_capability_information(
    capabilities: SecurityDomainCapabilities,
    out: &mut [u8],
) -> Result<usize, EncodeError> {
    if !capabilities.has_secure_channel() {
        return Err(EncodeError::ValueTooLong);
    }

    let mut writer = BerTlvWriter::new(out);
    let card_capabilities = writer.start(&[0x67])?;

    let mut scp03_options = [0u8; 2];
    let mut scp03_options_len = 0usize;
    if capabilities.scp03_s8 {
        scp03_options[scp03_options_len] = Scp03Option::S8.parameter_i();
        scp03_options_len += 1;
    }
    if capabilities.scp03_s16 {
        scp03_options[scp03_options_len] = Scp03Option::S16.parameter_i();
        scp03_options_len += 1;
    }
    if scp03_options_len != 0 {
        write_scp_capability(
            &mut writer,
            0x03,
            &scp03_options[..scp03_options_len],
            Some(0x01),
        )?;
    }

    if let Some(parameter_i) = capabilities.scp11_parameter_i() {
        write_scp_capability(&mut writer, 0x11, &[parameter_i], None)?;
    }

    writer.primitive(&[0x82], &[0xff, 0x54, 0x00])?;
    writer.primitive(&[0x83], &[0x02])?;
    writer.finish(card_capabilities)?;
    Ok(writer.len())
}

/// One LV-decoded view of `INSTALL [for install]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallForInstallData<'a> {
    pub package_aid: &'a [u8],
    pub applet_aid: &'a [u8],
    pub instance_aid: &'a [u8],
    pub privileges: &'a [u8],
    pub install_parameters: &'a [u8],
    pub install_token: &'a [u8],
}

/// One BER-TLV item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BerTlv<'a> {
    pub tag: u32,
    pub tag_len: u8,
    pub value: &'a [u8],
}

/// Sequential reader for one byte-length-value encoding.
pub struct LvReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> LvReader<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn next_value(&mut self) -> Result<Option<&'a [u8]>, DecodeError> {
        if self.offset == self.data.len() {
            return Ok(None);
        }

        let len = *self.data.get(self.offset).ok_or(DecodeError::Malformed)? as usize;
        let start = self.offset.checked_add(1).ok_or(DecodeError::Malformed)?;
        let end = start.checked_add(len).ok_or(DecodeError::Malformed)?;
        let value = self.data.get(start..end).ok_or(DecodeError::Malformed)?;
        self.offset = end;
        Ok(Some(value))
    }

    pub const fn offset(&self) -> usize {
        self.offset
    }

    pub fn finish(self) -> Result<(), DecodeError> {
        if self.offset == self.data.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

/// Sequential reader for one BER-TLV stream.
pub struct BerTlvReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> BerTlvReader<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn next_tlv(&mut self) -> Result<Option<BerTlv<'a>>, DecodeError> {
        if self.offset == self.data.len() {
            return Ok(None);
        }

        let first = *self.data.get(self.offset).ok_or(DecodeError::Malformed)?;
        let mut tag = first as u32;
        let mut tag_len = 1usize;

        if (first & 0x1f) == 0x1f {
            tag = 0;
            loop {
                let byte = *self
                    .data
                    .get(self.offset + tag_len - 1)
                    .ok_or(DecodeError::Malformed)?;
                if tag_len == 1 {
                    tag = byte as u32;
                } else {
                    tag = (tag << 8) | (byte as u32);
                }
                if tag_len > 1 && (byte & 0x80) == 0 {
                    break;
                }
                tag_len = tag_len.checked_add(1).ok_or(DecodeError::Malformed)?;
                if tag_len > 4 {
                    return Err(DecodeError::Unsupported);
                }
                if self.offset + tag_len > self.data.len() {
                    return Err(DecodeError::Malformed);
                }
            }
        }

        let len_offset = self
            .offset
            .checked_add(tag_len)
            .ok_or(DecodeError::Malformed)?;
        let first_len = *self.data.get(len_offset).ok_or(DecodeError::Malformed)?;
        let (value_len, len_len) = if (first_len & 0x80) == 0 {
            (first_len as usize, 1usize)
        } else {
            let byte_count = (first_len & 0x7f) as usize;
            if byte_count == 0 {
                return Err(DecodeError::Unsupported);
            }
            if byte_count > 2 {
                return Err(DecodeError::Unsupported);
            }
            let mut len = 0usize;
            let mut index = 0usize;
            while index < byte_count {
                let byte = *self
                    .data
                    .get(len_offset + 1 + index)
                    .ok_or(DecodeError::Malformed)?;
                len = (len << 8) | byte as usize;
                index += 1;
            }
            (len, 1 + byte_count)
        };

        let value_offset = len_offset
            .checked_add(len_len)
            .ok_or(DecodeError::Malformed)?;
        let value_end = value_offset
            .checked_add(value_len)
            .ok_or(DecodeError::Malformed)?;
        let value = self
            .data
            .get(value_offset..value_end)
            .ok_or(DecodeError::Malformed)?;
        self.offset = value_end;

        Ok(Some(BerTlv {
            tag,
            tag_len: tag_len as u8,
            value,
        }))
    }

    pub fn finish(self) -> Result<(), DecodeError> {
        if self.offset == self.data.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

/// Parses the six LV fields of `INSTALL [for install]`.
pub fn parse_install_for_install_data(
    data: &[u8],
) -> Result<InstallForInstallData<'_>, DecodeError> {
    let mut reader = LvReader::new(data);
    let package_aid = reader.next_value()?.ok_or(DecodeError::Malformed)?;
    let applet_aid = reader.next_value()?.ok_or(DecodeError::Malformed)?;
    let instance_aid = reader.next_value()?.ok_or(DecodeError::Malformed)?;
    let privileges = reader.next_value()?.ok_or(DecodeError::Malformed)?;
    let install_parameters = reader.next_value()?.ok_or(DecodeError::Malformed)?;
    let install_token = reader.next_value()?.ok_or(DecodeError::Malformed)?;
    if reader.next_value()?.is_some() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(InstallForInstallData {
        package_aid,
        applet_aid,
        instance_aid,
        privileges,
        install_parameters,
        install_token,
    })
}

/// Parses `INSTALL [for install]` directly from one runtime context.
pub fn parse_install_for_install_ctx(
    ctx: &crate::RustletCtx,
) -> Result<InstallForInstallData<'_>, DecodeError> {
    parse_install_for_install_data(crate::SEApdu::incoming_data(ctx))
}

#[cfg(test)]
mod tests {
    use super::{
        parse_install_for_install_data, write_card_capability_information,
        write_card_recognition_data, BerTlvReader, DecodeError, LvReader,
        SecurityDomainCapabilities,
    };

    #[test]
    fn install_for_install_extracts_parameters_and_token() {
        let payload = [
            0x02, 0xAA, 0xBB, 0x01, 0xCC, 0x01, 0xDD, 0x01, 0xEE, 0x02, 0x11, 0x22, 0x01, 0x33,
        ];
        let decoded = parse_install_for_install_data(&payload).unwrap();
        assert_eq!(decoded.package_aid, &[0xAA, 0xBB]);
        assert_eq!(decoded.applet_aid, &[0xCC]);
        assert_eq!(decoded.instance_aid, &[0xDD]);
        assert_eq!(decoded.privileges, &[0xEE]);
        assert_eq!(decoded.install_parameters, &[0x11, 0x22]);
        assert_eq!(decoded.install_token, &[0x33]);
    }

    #[test]
    fn install_for_install_requires_the_token_lv() {
        let legacy_five_fields = [0x01, 0xAA, 0x01, 0xBB, 0x01, 0xCC, 0x00, 0x01, 0x2A];
        assert_eq!(
            parse_install_for_install_data(&legacy_five_fields),
            Err(DecodeError::Malformed)
        );
    }

    #[test]
    fn lv_reader_rejects_truncated_value() {
        let mut reader = LvReader::new(&[0x02, 0xAA]);
        assert_eq!(reader.next_value(), Err(DecodeError::Malformed));
    }

    #[test]
    fn ber_tlv_reader_reads_one_and_two_byte_tags() {
        let mut reader = BerTlvReader::new(&[0xC9, 0x01, 0x2A, 0x5F, 0x20, 0x01, 0x99]);
        let first = reader.next_tlv().unwrap().unwrap();
        assert_eq!(first.tag, 0xC9);
        assert_eq!(first.value, &[0x2A]);
        let second = reader.next_tlv().unwrap().unwrap();
        assert_eq!(second.tag, 0x5F20);
        assert_eq!(second.value, &[0x99]);
        assert!(reader.next_tlv().unwrap().is_none());
    }

    #[test]
    fn ber_tlv_reader_rejects_indefinite_length() {
        let mut reader = BerTlvReader::new(&[0xC9, 0x80]);
        assert_eq!(reader.next_tlv(), Err(DecodeError::Unsupported));
    }

    #[test]
    fn null_security_domain_recognition_data_is_well_formed_without_scp_oid() {
        let mut out = [0u8; 128];
        let len = write_card_recognition_data(SecurityDomainCapabilities::none(), &mut out)
            .expect("recognition data");
        assert_eq!(
            &out[..len],
            &[
                0x66, 0x23, 0x73, 0x21, 0x06, 0x07, 0x2a, 0x86, 0x48, 0x86, 0xfc, 0x6b, 0x01, 0x60,
                0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xfc, 0x6b, 0x02, 0x02, 0x03, 0x63, 0x09,
                0x06, 0x07, 0x2a, 0x86, 0x48, 0x86, 0xfc, 0x6b, 0x03,
            ]
        );
    }

    #[test]
    fn recognition_data_encodes_scp03_s16_and_scp11ac() {
        let capabilities = SecurityDomainCapabilities {
            scp03_s8: false,
            scp03_s16: true,
            scp11a: true,
            scp11b: false,
            scp11c: true,
        };
        let mut out = [0u8; 128];
        let len = write_card_recognition_data(capabilities, &mut out).expect("recognition data");
        let mut reader = BerTlvReader::new(&out[..len]);
        let card_data = reader.next_tlv().unwrap().unwrap();
        let mut recognition_reader = BerTlvReader::new(card_data.value);
        let recognition = recognition_reader.next_tlv().unwrap().unwrap();
        let mut fields = BerTlvReader::new(recognition.value);
        let mut scp_oids = [[0u8; 9]; 2];
        let mut scp_oid_count = 0usize;
        while let Some(field) = fields.next_tlv().unwrap() {
            if field.tag != 0x64 {
                continue;
            }
            let mut oid_reader = BerTlvReader::new(field.value);
            let oid = oid_reader.next_tlv().unwrap().unwrap();
            scp_oids[scp_oid_count].copy_from_slice(oid.value);
            scp_oid_count += 1;
        }
        assert_eq!(scp_oid_count, 2);
        assert_eq!(&scp_oids[0][7..], &[0x03, 0x01]);
        assert_eq!(&scp_oids[1][7..], &[0x11, 0x51]);
    }

    #[test]
    fn capability_information_reports_protocol_options_and_sha256() {
        let capabilities = SecurityDomainCapabilities {
            scp03_s8: true,
            scp03_s16: true,
            scp11a: false,
            scp11b: false,
            scp11c: false,
        };
        let mut out = [0u8; 128];
        let len = write_card_capability_information(capabilities, &mut out).expect("capabilities");
        assert_eq!(
            &out[..len],
            &[
                0x67, 0x14, 0xa0, 0x0a, 0x80, 0x01, 0x03, 0x81, 0x02, 0x00, 0x01, 0x82, 0x01, 0x01,
                0x82, 0x03, 0xff, 0x54, 0x00, 0x83, 0x01, 0x02,
            ]
        );
    }
}
