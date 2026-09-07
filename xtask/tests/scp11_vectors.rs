use std::collections::BTreeMap;

use aes::cipher::{
    block_padding::{Iso7816, NoPadding},
    BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit,
};
use cmac::{Cmac, Mac};
use oxi_core::core::scp11::{
    compute_mutual_authenticate_receipt, derive_scp11a_session_keys,
    parse_scp11a_mutual_authenticate_request, Scp11Profile, Scp11aSharedInfo,
};
use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};

const SAMSUNG_SCP11A_P256_AES128_S16: &str =
    include_str!("fixtures/scp11a_p256_aes128_s16_samsung.txt");

#[test]
fn samsung_scp11a_p256_aes128_s16_matches_kernel_establishment_crypto() {
    let vector = VectorFile::parse(SAMSUNG_SCP11A_P256_AES128_S16);
    assert_eq!(vector.text("profile"), "SCP11a");
    assert_eq!(vector.text("curve"), "P-256");
    assert_eq!(vector.text("session_keys"), "AES-128");
    assert_eq!(vector.text("mac_mode"), "S16");

    let capdu = vector.hex("mutual_authenticate_capdu");
    assert_eq!(&capdu[..5], &[0x80, 0x82, 0x03, 0x11, 0x53]);
    assert_eq!(capdu.last(), Some(&0x00));
    let command_data = &capdu[5..capdu.len() - 1];
    assert_eq!(command_data, vector.hex("mutual_authenticate_command_data"));

    let request = parse_scp11a_mutual_authenticate_request(command_data).unwrap();
    assert_eq!(request.parameters.profile, Scp11Profile::A);
    assert!(!request.parameters.include_identifiers);
    assert_eq!(
        request.host_ephemeral_public,
        vector.hex("host_ephemeral_public")
    );

    let shsee = p256_shared_secret(
        &vector.hex("host_ephemeral_private"),
        &vector.hex("card_ephemeral_public"),
    );
    let shsss = p256_shared_secret(
        &vector.hex("host_static_private"),
        &vector.hex("card_static_public"),
    );
    assert_eq!(shsee, vector.hex("shsee"));
    assert_eq!(shsss, vector.hex("shsss"));

    let shared_info = Scp11aSharedInfo::new(
        request.key_usage_qualifier,
        request.key_type,
        request.key_length,
        &[],
        &[],
        &[],
    )
    .unwrap();
    let keys = derive_scp11a_session_keys(&shsee, &shsss, &shared_info).unwrap();
    assert_eq!(keys.receipt().as_slice(), vector.hex("receipt_key"));
    assert_eq!(keys.enc().as_slice(), vector.hex("s_enc"));
    assert_eq!(keys.mac().as_slice(), vector.hex("s_mac"));
    assert_eq!(keys.rmac().as_slice(), vector.hex("s_rmac"));
    assert_eq!(keys.dek().as_slice(), vector.hex("s_dek"));

    let mut receipt = [0u8; 16];
    compute_mutual_authenticate_receipt(
        &keys,
        command_data,
        &vector.hex("card_ephemeral_public"),
        &mut receipt,
    )
    .unwrap();
    assert_eq!(receipt.as_slice(), vector.hex("receipt"));

    let rapdu = vector.hex("mutual_authenticate_rapdu");
    assert_eq!(&rapdu[..3], &[0x5F, 0x49, 0x41]);
    assert_eq!(&rapdu[3..68], vector.hex("card_ephemeral_public"));
    assert_eq!(&rapdu[68..70], &[0x86, 0x10]);
    assert_eq!(&rapdu[70..86], receipt);
    assert_eq!(&rapdu[86..], &[0x90, 0x00]);

    let (protected, command_mac_chain) = samsung_scp11_protect_first_command(
        keys.enc(),
        keys.mac(),
        &receipt,
        [0x84, 0xF2, 0x20, 0x00],
        &vector.hex("protected_get_status_plain_data"),
    );
    assert_eq!(protected, vector.hex("protected_get_status_capdu"));
    let plain_response = samsung_scp11_unprotect_first_response(
        keys.enc(),
        keys.rmac(),
        &command_mac_chain,
        &vector.hex("protected_get_status_rapdu"),
    );
    assert_eq!(
        plain_response,
        vector.hex("protected_get_status_plain_response")
    );
}

fn p256_shared_secret(private: &[u8], public: &[u8]) -> Vec<u8> {
    let private = SecretKey::from_slice(private).unwrap();
    let public = PublicKey::from_sec1_bytes(public).unwrap();
    diffie_hellman(private.to_nonzero_scalar(), public.as_affine())
        .raw_secret_bytes()
        .to_vec()
}

fn samsung_scp11_protect_first_command(
    enc_key: &[u8; 16],
    mac_key: &[u8; 16],
    receipt: &[u8; 16],
    header: [u8; 4],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let cipher = aes::Aes128::new_from_slice(enc_key).unwrap();
    let mut counter = [0u8; 16];
    counter[12..].copy_from_slice(&1u32.to_be_bytes());
    cipher.encrypt_block((&mut counter).into());

    let mut padded = vec![0u8; plaintext.len() + 16];
    padded[..plaintext.len()].copy_from_slice(plaintext);
    let encrypted = cbc::Encryptor::<aes::Aes128>::new_from_slices(enc_key, &counter)
        .unwrap()
        .encrypt_padded_mut::<Iso7816>(&mut padded, plaintext.len())
        .unwrap()
        .to_vec();

    let lc = u8::try_from(encrypted.len() + 16).unwrap();
    let mut authenticated = Vec::from(header);
    authenticated.push(lc);
    authenticated.extend_from_slice(&encrypted);

    let mut mac = <Cmac<aes::Aes128> as Mac>::new_from_slice(mac_key).unwrap();
    mac.update(receipt);
    mac.update(&authenticated);
    let command_mac = mac.finalize().into_bytes();
    let mut command_mac_chain = [0u8; 16];
    command_mac_chain.copy_from_slice(&command_mac);

    authenticated.extend_from_slice(&command_mac_chain);
    (authenticated, command_mac_chain)
}

fn samsung_scp11_unprotect_first_response(
    enc_key: &[u8; 16],
    rmac_key: &[u8; 16],
    command_mac_chain: &[u8; 16],
    rapdu: &[u8],
) -> Vec<u8> {
    assert!(rapdu.len() >= 18);
    let sw = &rapdu[rapdu.len() - 2..];
    assert_eq!(sw, [0x90, 0x00]);
    let protected = &rapdu[..rapdu.len() - 2];
    let (encrypted, received_rmac) = protected.split_at(protected.len() - 16);

    let mut mac = <Cmac<aes::Aes128> as Mac>::new_from_slice(rmac_key).unwrap();
    mac.update(command_mac_chain);
    mac.update(encrypted);
    mac.update(sw);
    assert_eq!(mac.finalize().into_bytes().as_slice(), received_rmac);

    let cipher = aes::Aes128::new_from_slice(enc_key).unwrap();
    let mut counter = [0u8; 16];
    counter[0] = 0x80;
    counter[12..].copy_from_slice(&1u32.to_be_bytes());
    cipher.encrypt_block((&mut counter).into());

    let mut padded = encrypted.to_vec();
    let decrypted = cbc::Decryptor::<aes::Aes128>::new_from_slices(enc_key, &counter)
        .unwrap()
        .decrypt_padded_mut::<NoPadding>(&mut padded)
        .unwrap();
    let marker = decrypted
        .iter()
        .rposition(|byte| *byte == 0x80)
        .expect("ISO 7816-4 padding marker");
    assert!(decrypted[marker + 1..].iter().all(|byte| *byte == 0));
    decrypted[..marker].to_vec()
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
