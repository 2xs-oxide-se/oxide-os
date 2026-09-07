/// Storage reserved for one in-progress secure-messaging transformation.
///
/// This is a workspace capacity, not the usable command payload. GlobalPlatform
/// Amendment D secure messaging carries encrypted command data followed directly
/// by its C-MAC; it does not use ISO 7816 secure-messaging data objects.
pub const PROTECTED_TRANSFORM_CAPACITY: usize = 256;

/// Maximum size of the data field encoded by one short APDU `Lc`.
pub const SHORT_APDU_DATA_FIELD_CAPACITY: usize = u8::MAX as usize;

const AES_BLOCK_SIZE: usize = 16;
const SCP03_S8_MAC_LEN: usize = 8;
const SCP03_S16_MAC_LEN: usize = 16;
const SCP11_MAC_LEN: usize = 16;

/// Returns the maximum plaintext payload that fits in one encrypted SCP03 S8
/// short command followed by its eight-byte C-MAC.
pub const fn scp03_s8_short_apdu_payload_budget() -> usize {
    encrypted_short_apdu_payload_budget(SCP03_S8_MAC_LEN)
        .expect("SCP03 S8 has a valid short-APDU payload budget")
}

/// Returns the maximum plaintext payload that fits in one encrypted SCP03 S16
/// short command followed by its sixteen-byte C-MAC.
pub const fn scp03_s16_short_apdu_payload_budget() -> usize {
    encrypted_short_apdu_payload_budget(SCP03_S16_MAC_LEN)
        .expect("SCP03 S16 has a valid short-APDU payload budget")
}

/// Returns the maximum plaintext payload that fits in one encrypted SCP11
/// short command followed by its sixteen-byte C-MAC.
pub const fn scp11_short_apdu_payload_budget() -> usize {
    encrypted_short_apdu_payload_budget(SCP11_MAC_LEN)
        .expect("SCP11 has a valid short-APDU payload budget")
}

/// Computes the maximum encrypted plaintext payload for an Amendment D short
/// command. The returned payload excludes ISO9797-M2 padding and the C-MAC.
pub const fn encrypted_short_apdu_payload_budget(mac_len: usize) -> Option<usize> {
    let mut plaintext_len = SHORT_APDU_DATA_FIELD_CAPACITY;
    loop {
        if encrypted_command_data_field_len(plaintext_len, mac_len).is_some() {
            return Some(plaintext_len);
        }
        if plaintext_len == 0 {
            return None;
        }
        plaintext_len -= 1;
    }
}

/// Returns the encrypted data plus trailing C-MAC length when it fits in one
/// short APDU data field.
pub const fn encrypted_command_data_field_len(
    plaintext_len: usize,
    mac_len: usize,
) -> Option<usize> {
    if mac_len == 0 {
        return None;
    }
    let encrypted_len = match iso9797_m2_padded_len(plaintext_len) {
        Some(len) => len,
        None => return None,
    };
    let encoded_len = match encrypted_len.checked_add(mac_len) {
        Some(len) => len,
        None => return None,
    };
    if encoded_len <= SHORT_APDU_DATA_FIELD_CAPACITY {
        Some(encoded_len)
    } else {
        None
    }
}

/// Returns the AES-block-aligned length after ISO9797-M2 padding.
pub const fn iso9797_m2_padded_len(plaintext_len: usize) -> Option<usize> {
    let with_marker = match plaintext_len.checked_add(1) {
        Some(len) => len,
        None => return None,
    };
    let with_rounding = match with_marker.checked_add(AES_BLOCK_SIZE - 1) {
        Some(len) => len,
        None => return None,
    };
    Some((with_rounding / AES_BLOCK_SIZE) * AES_BLOCK_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_helpers_report_exact_amendment_d_short_apdu_budgets() {
        assert_eq!(scp03_s8_short_apdu_payload_budget(), 239);
        assert_eq!(scp03_s16_short_apdu_payload_budget(), 223);
        assert_eq!(scp11_short_apdu_payload_budget(), 223);
    }

    #[test]
    fn encrypted_short_apdu_budget_rejects_the_next_plaintext_block() {
        assert_eq!(
            encrypted_command_data_field_len(239, SCP03_S8_MAC_LEN),
            Some(248)
        );
        assert_eq!(
            encrypted_command_data_field_len(240, SCP03_S8_MAC_LEN),
            None
        );
        assert_eq!(
            encrypted_command_data_field_len(223, SCP03_S16_MAC_LEN),
            Some(240)
        );
        assert_eq!(
            encrypted_command_data_field_len(224, SCP03_S16_MAC_LEN),
            None
        );
    }
}
