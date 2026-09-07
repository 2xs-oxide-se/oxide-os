//! Local validation of Oxide SE FAE 1.0 images before GP mutation.

use crate::{ApduToolError, ErrorKind, ToolResult};

const FOOTER_SIZE: usize = 28;
const MAGIC: u32 = 0xFAEC_0D10;
const ABI: u32 = 0xAC1D_A992;
const APPLICATION_PROFILE: u32 = 0xA99;
const SECURITY_DOMAIN_PROFILE: u32 = 0x5DC;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaeProfile {
    Application,
    SecurityDomain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaeMetadata {
    pub size: u32,
    pub isa: u32,
    pub profile: FaeProfile,
    pub minimum_abi_version: u32,
}

pub fn validate(bytes: &[u8]) -> ToolResult<FaeMetadata> {
    if bytes.len() < FOOTER_SIZE {
        return Err(invalid("FAE is too small to contain a FAE 1.0 footer"));
    }
    let size =
        u32::try_from(bytes.len()).map_err(|_| invalid("FAE exceeds the GP 32-bit size field"))?;
    let requirements = word_from_end(bytes, 28)?;
    let profile_word = word_from_end(bytes, 24)?;
    let stored_crc = word_from_end(bytes, 20)?;
    let extra = word_from_end(bytes, 16)?;
    let abi = word_from_end(bytes, 12)?;
    let isa = word_from_end(bytes, 8)?;
    let magic = word_from_end(bytes, 4)?;
    if magic != MAGIC {
        return Err(invalid(format!(
            "unsupported FAE magic/version {magic:08X}"
        )));
    }
    if abi != ABI {
        return Err(invalid(format!("unsupported FAE ABI descriptor {abi:08X}")));
    }
    if extra != 0 {
        return Err(invalid("unsupported FAE extra footer fields"));
    }
    let family = (isa >> 24) as u8;
    let subgroup = (isa >> 16) as u8;
    if family != 0x01 || !matches!(subgroup, 0x02 | 0x03) || isa & 0x0f != 0 {
        return Err(invalid(format!(
            "unsupported Oxide SE FAE ISA descriptor {isa:08X}"
        )));
    }
    if crc32(bytes) != stored_crc {
        return Err(invalid("FAE CRC32 verification failed"));
    }
    let profile = match profile_word >> 20 {
        APPLICATION_PROFILE => FaeProfile::Application,
        SECURITY_DOMAIN_PROFILE => FaeProfile::SecurityDomain,
        value => return Err(invalid(format!("unsupported FAE profile {value:03X}"))),
    };
    let minimum_abi_version = profile_word & 0x000f_ffff;
    if minimum_abi_version > 0x1000 {
        return Err(invalid("FAE requires an unsupported Oxide SE ABI version"));
    }
    let stack_units = requirements & 0xffff;
    if stack_units > 64 {
        return Err(invalid(
            "FAE stack requirement exceeds the Oxide SE application stack",
        ));
    }
    Ok(FaeMetadata {
        size,
        isa,
        profile,
        minimum_abi_version,
    })
}

fn word_from_end(bytes: &[u8], distance: usize) -> ToolResult<u32> {
    let start = bytes
        .len()
        .checked_sub(distance)
        .ok_or_else(|| invalid("truncated FAE footer"))?;
    Ok(u32::from_le_bytes(
        bytes[start..start + 4].try_into().unwrap(),
    ))
}

fn crc32(bytes: &[u8]) -> u32 {
    let crc_start = bytes.len() - 20;
    let mut crc = 0xffff_ffffu32;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let byte = if (crc_start..crc_start + 4).contains(&index) {
            0
        } else {
            byte
        };
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn invalid(message: impl Into<String>) -> ApduToolError {
    ApduToolError::new(ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(size: usize) -> Vec<u8> {
        let mut bytes = vec![0x55; size - FOOTER_SIZE];
        bytes.extend_from_slice(&0x0001_0001u32.to_le_bytes());
        bytes.extend_from_slice(&0xA99_00001u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&ABI.to_le_bytes());
        bytes.extend_from_slice(&0x0103_0000u32.to_le_bytes());
        bytes.extend_from_slice(&MAGIC.to_le_bytes());
        let crc = crc32(&bytes);
        let at = bytes.len() - 20;
        bytes[at..at + 4].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    #[test]
    fn validates_fae_footer_and_rejects_corruption() {
        let valid = image(256);
        assert_eq!(validate(&valid).unwrap().profile, FaeProfile::Application);
        let mut corrupt = valid;
        corrupt[0] ^= 1;
        assert!(validate(&corrupt)
            .unwrap_err()
            .to_string()
            .contains("CRC32"));
        assert!(validate(&[]).is_err());
    }
}
