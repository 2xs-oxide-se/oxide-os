use std::collections::BTreeMap;

const SCP03_S8_VECTORS: &str = include_str!("fixtures/scp03_s8_independently_reproduced.txt");
const SCP03_S16_VECTORS: &str = include_str!("fixtures/scp03_s16_independently_reproduced.txt");
const SAMSUNG_SCP03_S16_LEVEL_33: &str =
    include_str!("fixtures/scp03_aes128_s16_level_33_samsung.txt");

#[test]
fn independently_reproduced_scp03_s8_vectors_match_host_crypto() {
    verify_independently_reproduced_scp03_vectors(SCP03_S8_VECTORS, "S8", 8);
}

#[test]
fn independently_reproduced_scp03_s16_vectors_match_host_crypto() {
    verify_independently_reproduced_scp03_vectors(SCP03_S16_VECTORS, "S16", 16);
}

#[test]
fn samsung_scp03_aes128_s16_level_33_establishment_matches_host_crypto() {
    let vector = VectorFile::parse(SAMSUNG_SCP03_S16_LEVEL_33);
    let static_enc_key = vector.hex("static_enc_key");
    let static_mac_key = vector.hex("static_mac_key");
    let host_challenge = vector.hex("host_challenge");
    let card_challenge = vector.hex("card_challenge");
    let context = [host_challenge.as_slice(), card_challenge.as_slice()].concat();

    let initialize_update = vector.hex("initialize_update_response");
    assert_eq!(&initialize_update[13..29], card_challenge);
    assert_eq!(&initialize_update[29..45], vector.hex("card_cryptogram"));

    let session_enc_key = scp03_kdf(&static_enc_key, 0x04, &context, 16);
    let session_mac_key = scp03_kdf(&static_mac_key, 0x06, &context, 16);
    let session_rmac_key = scp03_kdf(&static_mac_key, 0x07, &context, 16);
    assert_eq!(session_enc_key, vector.hex("session_enc_key"));
    assert_eq!(session_mac_key, vector.hex("session_mac_key"));
    assert_eq!(session_rmac_key, vector.hex("session_rmac_key"));
    assert_eq!(
        scp03_kdf(&session_mac_key, 0x00, &context, 16),
        vector.hex("card_cryptogram")
    );

    let host_cryptogram = scp03_kdf(&session_mac_key, 0x01, &context, 16);
    assert_eq!(host_cryptogram, vector.hex("host_cryptogram"));
    let mut external_authenticate = decode_hex("8482330020");
    external_authenticate.extend_from_slice(&host_cryptogram);
    let full_cmac =
        chained_truncated_aes_cmac(&session_mac_key, &mut [0u8; 16], &external_authenticate, 16);
    external_authenticate.extend_from_slice(&full_cmac);
    assert_eq!(external_authenticate, vector.hex("external_authenticate"));
}

fn verify_independently_reproduced_scp03_vectors(
    input: &'static str,
    profile: &str,
    mac_len: usize,
) {
    let vector = VectorFile::parse(input);
    assert_eq!(vector.text("profile"), profile);

    let static_enc_key = vector.hex("static_enc_key");
    let static_mac_key = vector.hex("static_mac_key");
    let host_challenge = vector.hex("host_challenge");
    let card_challenge = vector.hex("card_challenge");
    let context = [host_challenge.as_slice(), card_challenge.as_slice()].concat();

    assert_eq!(context, vector.hex("context"));
    let session_enc_key = scp03_kdf(&static_enc_key, 0x04, &context, 16);
    let session_mac_key = scp03_kdf(&static_mac_key, 0x06, &context, 16);
    let session_rmac_key = scp03_kdf(&static_mac_key, 0x07, &context, 16);
    assert_eq!(session_enc_key, vector.hex("session_enc_key"));
    assert_eq!(session_mac_key, vector.hex("session_mac_key"));
    assert_eq!(session_rmac_key, vector.hex("session_rmac_key"));
    let expected_card_cryptogram = vector.hex("card_cryptogram");
    let expected_host_cryptogram = vector.hex("host_cryptogram");
    assert_eq!(
        scp03_kdf(
            &session_mac_key,
            0x00,
            &context,
            expected_card_cryptogram.len()
        ),
        expected_card_cryptogram
    );
    assert_eq!(
        scp03_kdf(
            &session_mac_key,
            0x01,
            &context,
            expected_host_cryptogram.len()
        ),
        expected_host_cryptogram
    );

    let external_authenticate_header = vector.hex("external_authenticate_header");
    let external_authenticate_cmac = chained_truncated_aes_cmac(
        &session_mac_key,
        &mut [0u8; 16],
        &[
            external_authenticate_header.as_slice(),
            expected_host_cryptogram.as_slice(),
        ]
        .concat(),
        16,
    );
    assert_eq!(
        external_authenticate_cmac,
        vector.hex("external_authenticate_cmac")
    );

    let mut command_mac_chain = [0u8; 16];
    let mut response_mac_chain = [0u8; 16];
    command_mac_chain.copy_from_slice(&external_authenticate_cmac);
    response_mac_chain.copy_from_slice(&external_authenticate_cmac);
    let protected_get_data_header = vector.hex("protected_get_data_header");
    let protected_get_data_cmac = chained_truncated_aes_cmac(
        &session_mac_key,
        &mut command_mac_chain,
        &protected_get_data_header,
        mac_len,
    );
    assert_eq!(
        protected_get_data_cmac,
        vector.hex("protected_get_data_cmac")
    );

    let protected_get_data_response = vector.hex("protected_get_data_response");
    let protected_get_data_rmac = chained_truncated_aes_cmac(
        &session_rmac_key,
        &mut response_mac_chain,
        &[protected_get_data_response.as_slice(), &[0x90, 0x00]].concat(),
        mac_len,
    );
    assert_eq!(
        protected_get_data_rmac,
        vector.hex("protected_get_data_rmac")
    );

    let mut command_enc_counter = 0u32;
    let mut response_enc_counter = 0u32;
    command_mac_chain.copy_from_slice(&external_authenticate_cmac);
    response_mac_chain.copy_from_slice(&external_authenticate_cmac);
    assert_eq!(
        chained_truncated_aes_cmac(
            &session_mac_key,
            &mut command_mac_chain,
            &protected_get_data_header,
            mac_len,
        ),
        vector.hex("protected_get_data_cmac")
    );

    let response_iv = scp03_encryption_iv(&session_enc_key, &mut response_enc_counter, 0x02);
    assert_eq!(response_iv, vector.hex("response_enc_iv_1"));
    let encrypted_lifecycle_response =
        aes_cbc_encrypt_iso9797_m2(&session_enc_key, &response_iv, &protected_get_data_response);
    assert_eq!(
        encrypted_lifecycle_response,
        vector.hex("encrypted_lifecycle_response")
    );
    let encrypted_lifecycle_rmac = chained_truncated_aes_cmac(
        &session_rmac_key,
        &mut response_mac_chain,
        &[encrypted_lifecycle_response.as_slice(), &[0x90, 0x00]].concat(),
        mac_len,
    );
    assert_eq!(
        encrypted_lifecycle_rmac,
        vector.hex("encrypted_lifecycle_rmac")
    );

    let store_plaintext = vector.hex("store_plaintext");
    let store_iv = scp03_encryption_iv(&session_enc_key, &mut command_enc_counter, 0x01);
    assert_eq!(store_iv, vector.hex("store_enc_iv_1"));
    let store_encrypted_data =
        aes_cbc_encrypt_iso9797_m2(&session_enc_key, &store_iv, &store_plaintext);
    assert_eq!(store_encrypted_data, vector.hex("store_encrypted_data"));
    let store_header = [
        0x84,
        0xE2,
        0x00,
        0x00,
        u8::try_from(store_encrypted_data.len() + mac_len).unwrap(),
    ];
    let store_cmac = chained_truncated_aes_cmac(
        &session_mac_key,
        &mut command_mac_chain,
        &[store_header.as_slice(), store_encrypted_data.as_slice()].concat(),
        mac_len,
    );
    assert_eq!(store_cmac, vector.hex("store_cmac"));

    let install_plain_data = vector.hex("install_plain_data");
    let install_iv = scp03_encryption_iv(&session_enc_key, &mut command_enc_counter, 0x01);
    assert_eq!(install_iv, vector.hex("install_enc_iv_2"));
    let install_encrypted_data =
        aes_cbc_encrypt_iso9797_m2(&session_enc_key, &install_iv, &install_plain_data);
    assert_eq!(install_encrypted_data, vector.hex("install_encrypted_data"));
    let install_header = [
        0x84,
        0xE6,
        0x0C,
        0x00,
        u8::try_from(install_encrypted_data.len() + mac_len).unwrap(),
    ];
    let install_cmac = chained_truncated_aes_cmac(
        &session_mac_key,
        &mut command_mac_chain,
        &[install_header.as_slice(), install_encrypted_data.as_slice()].concat(),
        mac_len,
    );
    assert_eq!(install_cmac, vector.hex("install_cmac"));
}

struct VectorFile {
    values: BTreeMap<&'static str, &'static str>,
}

impl VectorFile {
    fn parse(input: &'static str) -> Self {
        let mut values = BTreeMap::new();
        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                panic!("invalid vector line: {line}");
            };
            values.insert(key.trim(), value.trim());
        }
        Self { values }
    }

    fn text(&self, key: &str) -> &str {
        self.values
            .get(key)
            .unwrap_or_else(|| panic!("missing vector key: {key}"))
    }

    fn hex(&self, key: &str) -> Vec<u8> {
        decode_hex(self.text(key))
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex value must have even length");
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).unwrap())
        .collect()
}

fn scp03_kdf(key: &[u8], derivation_constant: u8, context: &[u8], out_len: usize) -> Vec<u8> {
    assert!(matches!(out_len, 8 | 16 | 24 | 32));
    let output_len_bits = ((out_len as u16) * 8).to_be_bytes();
    let mut out = Vec::with_capacity(out_len);
    let mut counter = 1u8;
    while out.len() < out_len {
        let mut input = vec![0u8; 11];
        input.push(derivation_constant);
        input.push(0x00);
        input.extend_from_slice(&output_len_bits);
        input.push(counter);
        input.extend_from_slice(context);
        let block = aes_cmac(key, &input);
        let take_len = usize::min(block.len(), out_len - out.len());
        out.extend_from_slice(&block[..take_len]);
        counter = counter.checked_add(1).unwrap();
    }
    out
}

fn chained_truncated_aes_cmac(
    key: &[u8],
    chain: &mut [u8; 16],
    input: &[u8],
    mac_len: usize,
) -> Vec<u8> {
    let mac = aes_cmac(key, &[chain.as_slice(), input].concat());
    chain.copy_from_slice(&mac);
    mac[..mac_len].to_vec()
}

fn aes_cmac(key: &[u8], input: &[u8]) -> [u8; 16] {
    use cmac::{Cmac, Mac};

    let mut mac = <Cmac<aes::Aes128> as Mac>::new_from_slice(key).unwrap();
    mac.update(input);
    mac.finalize().into_bytes().into()
}

fn scp03_encryption_iv(key: &[u8], counter: &mut u32, direction: u8) -> Vec<u8> {
    *counter = counter.checked_add(1).unwrap();
    let mut block = [0u8; 16];
    block[0] = direction;
    block[12..16].copy_from_slice(&counter.to_be_bytes());
    aes_ecb_encrypt(key, &block)
}

fn aes_ecb_encrypt(key: &[u8], input: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit};

    let cipher = aes::Aes128::new_from_slice(key).unwrap();
    let mut buffer = input.to_vec();
    for block in buffer.chunks_exact_mut(16) {
        cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
            block,
        ));
    }
    buffer
}

fn aes_cbc_encrypt_iso9797_m2(key: &[u8], iv: &[u8], input: &[u8]) -> Vec<u8> {
    use aes::cipher::{block_padding::Iso7816, BlockEncryptMut, KeyIvInit};

    let mut buffer = [0u8; 128];
    buffer[..input.len()].copy_from_slice(input);
    let encrypted = cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
        .unwrap()
        .encrypt_padded_mut::<Iso7816>(&mut buffer, input.len())
        .unwrap();
    encrypted.to_vec()
}
