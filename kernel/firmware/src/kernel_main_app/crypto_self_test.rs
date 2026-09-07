use super::{ApduFilter, KernelAppModule};
use crate::apdu_manager::ApduStatus;
use rustlet_runtime::SEApdu;

const INS_CRYPTO_RANDOM: u8 = 0x80;
const INS_CRYPTO_AES128_CBC: u8 = 0x82;
const INS_CRYPTO_P256_KEYGEN: u8 = 0x84;
const INS_CRYPTO_BENCH_FILL_RANDOM: u8 = 0x85;
const INS_CRYPTO_BENCH_AES_CBC: u8 = 0x86;
const INS_CRYPTO_BENCH_AES_ECB: u8 = 0x87;
const INS_CRYPTO_BENCH_AES_ISO9797_M2: u8 = 0x88;
const INS_CRYPTO_BENCH_CMAC: u8 = 0x89;
const INS_CRYPTO_BENCH_HKDF: u8 = 0x8a;
const INS_CRYPTO_BENCH_X963: u8 = 0x8b;
const INS_CRYPTO_BENCH_P256_KEYGEN: u8 = 0x8c;
const INS_CRYPTO_BENCH_P256_ECDH: u8 = 0x8d;

const BENCH_MAX_KDF_INPUT_LEN: usize = 64;
const BENCH_MAX_KDF_OUTPUT_LEN: usize = 64;
const BENCH_MAX_ISO9797_INPUT_LEN: usize = 128;

const AES128_NIST_KEY: [u8; crate::core::crypto::AES128_KEY_SIZE] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const AES128_NIST_IV: [u8; crate::core::crypto::AES_BLOCK_SIZE] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const AES128_NIST_PLAINTEXT: [u8; crate::core::crypto::AES_BLOCK_SIZE] = [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
];
const AES128_NIST_CIPHERTEXT: [u8; crate::core::crypto::AES_BLOCK_SIZE] = [
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
];

pub(crate) struct Module;

impl KernelAppModule for Module {
    fn initialize() {}
}

pub(crate) const APDU_FILTER: ApduFilter = ApduFilter {
    matches: matches,
    process: process,
};

fn matches(apdu: &dyn SEApdu) -> bool {
    matches!(
        apdu.ins(),
        INS_CRYPTO_RANDOM
            | INS_CRYPTO_AES128_CBC
            | INS_CRYPTO_P256_KEYGEN
            | INS_CRYPTO_BENCH_FILL_RANDOM
            | INS_CRYPTO_BENCH_AES_CBC
            | INS_CRYPTO_BENCH_AES_ECB
            | INS_CRYPTO_BENCH_AES_ISO9797_M2
            | INS_CRYPTO_BENCH_CMAC
            | INS_CRYPTO_BENCH_HKDF
            | INS_CRYPTO_BENCH_X963
            | INS_CRYPTO_BENCH_P256_KEYGEN
            | INS_CRYPTO_BENCH_P256_ECDH
    )
}

fn process(apdu: &mut dyn SEApdu) -> ApduStatus {
    match apdu.ins() {
        INS_CRYPTO_RANDOM => process_random(apdu),
        INS_CRYPTO_AES128_CBC => process_aes128_cbc(apdu),
        INS_CRYPTO_P256_KEYGEN => process_p256_keygen(apdu),
        INS_CRYPTO_BENCH_FILL_RANDOM => process_bench_fill_random(apdu),
        INS_CRYPTO_BENCH_AES_CBC => process_bench_aes_cbc(apdu),
        INS_CRYPTO_BENCH_AES_ECB => process_bench_aes_ecb(apdu),
        INS_CRYPTO_BENCH_AES_ISO9797_M2 => process_bench_aes_iso9797_m2(apdu),
        INS_CRYPTO_BENCH_CMAC => process_bench_cmac(apdu),
        INS_CRYPTO_BENCH_HKDF => process_bench_kdf(apdu, true),
        INS_CRYPTO_BENCH_X963 => process_bench_kdf(apdu, false),
        INS_CRYPTO_BENCH_P256_KEYGEN => process_bench_p256_keygen(apdu),
        INS_CRYPTO_BENCH_P256_ECDH => process_bench_p256_ecdh(apdu),
        _ => ApduStatus::instruction_not_supported(),
    }
}

fn process_random(apdu: &mut dyn SEApdu) -> ApduStatus {
    let mut random = [0u8; 16];
    if crate::core::crypto::fill_random(&mut random).is_err() {
        return internal_error();
    }
    let _ = apdu.set_outgoing();
    apdu.buffer_mut()[..random.len()].copy_from_slice(&random);
    apdu.set_outgoing_length(random.len());
    ApduStatus::success()
}

fn process_aes128_cbc(apdu: &mut dyn SEApdu) -> ApduStatus {
    let key = match crate::core::crypto::AesKey::from_bytes(&AES128_NIST_KEY) {
        Ok(key) => key,
        Err(_) => return internal_error(),
    };
    let mut block = AES128_NIST_PLAINTEXT;
    if crate::core::crypto::aes_cbc_encrypt_in_place(&key, &AES128_NIST_IV, &mut block).is_err()
        || block != AES128_NIST_CIPHERTEXT
    {
        return internal_error();
    }
    let _ = apdu.set_outgoing();
    apdu.buffer_mut()[..block.len()].copy_from_slice(&block);
    apdu.set_outgoing_length(block.len());
    ApduStatus::success()
}

fn process_p256_keygen(apdu: &mut dyn SEApdu) -> ApduStatus {
    if !receive_keygen_transport_request(apdu) {
        return ApduStatus::wrong_data();
    }
    let mut private_key = [0u8; crate::core::crypto::P256_PRIVATE_KEY_SIZE];
    let mut public_key = [0u8; crate::core::crypto::P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
    let result = crate::core::crypto::p256_generate_keypair(&mut private_key, &mut public_key);
    if result.is_err() {
        return internal_error();
    }
    let _ = apdu.set_outgoing();
    apdu.buffer_mut()[..public_key.len()].copy_from_slice(&public_key);
    apdu.set_outgoing_length(public_key.len());
    ApduStatus::success()
}

fn process_bench_fill_random(apdu: &mut dyn SEApdu) -> ApduStatus {
    let output_len = apdu.p1() as usize;
    if output_len == 0 || output_len > apdu.buffer_mut().len() {
        return ApduStatus::wrong_data();
    }
    if crate::core::crypto::fill_random(&mut apdu.buffer_mut()[..output_len]).is_err() {
        return internal_error();
    }
    let _ = apdu.set_outgoing();
    apdu.set_outgoing_length(output_len);
    ApduStatus::success()
}

fn process_bench_aes_cbc(apdu: &mut dyn SEApdu) -> ApduStatus {
    let incoming_len = apdu.set_incoming_and_receive();
    let key_len = apdu.p1() as usize;
    if key_len != crate::core::crypto::AES128_KEY_SIZE
        && key_len != crate::core::crypto::AES256_KEY_SIZE
    {
        return ApduStatus::wrong_data();
    }
    let header_len = key_len + crate::core::crypto::AES_BLOCK_SIZE;
    if incoming_len < header_len {
        return ApduStatus::wrong_data();
    }
    let payload_len = incoming_len - header_len;
    if payload_len == 0 || payload_len % crate::core::crypto::AES_BLOCK_SIZE != 0 {
        return ApduStatus::wrong_data();
    }

    let mut iv = [0u8; crate::core::crypto::AES_BLOCK_SIZE];
    let key = match crate::core::crypto::AesKey::from_bytes(&apdu.buffer_mut()[..key_len]) {
        Ok(key) => key,
        Err(_) => return ApduStatus::wrong_data(),
    };
    iv.copy_from_slice(&apdu.buffer_mut()[key_len..header_len]);
    apdu.buffer_mut().copy_within(header_len..incoming_len, 0);
    if crate::core::crypto::aes_cbc_encrypt_in_place(
        &key,
        &iv,
        &mut apdu.buffer_mut()[..payload_len],
    )
    .is_err()
    {
        return internal_error();
    }
    let _ = apdu.set_outgoing();
    apdu.set_outgoing_length(payload_len);
    ApduStatus::success()
}

fn process_bench_aes_ecb(apdu: &mut dyn SEApdu) -> ApduStatus {
    let incoming_len = apdu.set_incoming_and_receive();
    let key_len = apdu.p1() as usize;
    if key_len != crate::core::crypto::AES128_KEY_SIZE
        && key_len != crate::core::crypto::AES256_KEY_SIZE
    {
        return ApduStatus::wrong_data();
    }
    if incoming_len <= key_len {
        return ApduStatus::wrong_data();
    }
    let payload_len = incoming_len - key_len;
    if payload_len % crate::core::crypto::AES_BLOCK_SIZE != 0 {
        return ApduStatus::wrong_data();
    }
    let key = match crate::core::crypto::AesKey::from_bytes(&apdu.buffer_mut()[..key_len]) {
        Ok(key) => key,
        Err(_) => return ApduStatus::wrong_data(),
    };
    apdu.buffer_mut().copy_within(key_len..incoming_len, 0);
    if crate::core::crypto::aes_ecb_encrypt_in_place(&key, &mut apdu.buffer_mut()[..payload_len])
        .is_err()
    {
        return internal_error();
    }
    let _ = apdu.set_outgoing();
    apdu.set_outgoing_length(payload_len);
    ApduStatus::success()
}

fn process_bench_aes_iso9797_m2(apdu: &mut dyn SEApdu) -> ApduStatus {
    let incoming_len = apdu.set_incoming_and_receive();
    let key_len = apdu.p1() as usize;
    if key_len != crate::core::crypto::AES128_KEY_SIZE
        && key_len != crate::core::crypto::AES256_KEY_SIZE
    {
        return ApduStatus::wrong_data();
    }
    let header_len = key_len + crate::core::crypto::AES_BLOCK_SIZE;
    if incoming_len < header_len {
        return ApduStatus::wrong_data();
    }
    let payload_len = incoming_len - header_len;
    if payload_len > BENCH_MAX_ISO9797_INPUT_LEN {
        return ApduStatus::wrong_data();
    }

    let mut input = [0u8; BENCH_MAX_ISO9797_INPUT_LEN];
    let mut iv = [0u8; crate::core::crypto::AES_BLOCK_SIZE];
    let key = match crate::core::crypto::AesKey::from_bytes(&apdu.buffer_mut()[..key_len]) {
        Ok(key) => key,
        Err(_) => return ApduStatus::wrong_data(),
    };
    iv.copy_from_slice(&apdu.buffer_mut()[key_len..header_len]);
    input[..payload_len].copy_from_slice(&apdu.buffer_mut()[header_len..incoming_len]);
    let output_len = match crate::core::crypto::aes_cbc_encrypt_iso9797_m2(
        &key,
        &iv,
        &input[..payload_len],
        apdu.buffer_mut(),
    ) {
        Ok(output_len) => output_len,
        Err(_) => return internal_error(),
    };
    let _ = apdu.set_outgoing();
    apdu.set_outgoing_length(output_len);
    ApduStatus::success()
}

fn process_bench_cmac(apdu: &mut dyn SEApdu) -> ApduStatus {
    let incoming_len = apdu.set_incoming_and_receive();
    let key_len = apdu.p1() as usize;
    if key_len != crate::core::crypto::AES128_KEY_SIZE
        && key_len != crate::core::crypto::AES256_KEY_SIZE
    {
        return ApduStatus::wrong_data();
    }
    if incoming_len < key_len {
        return ApduStatus::wrong_data();
    }
    let key = match crate::core::crypto::AesKey::from_bytes(&apdu.buffer_mut()[..key_len]) {
        Ok(key) => key,
        Err(_) => return ApduStatus::wrong_data(),
    };
    let mut mac = [0u8; crate::core::crypto::AES_CMAC_SIZE];
    if crate::core::crypto::aes_cmac(&key, &apdu.buffer_mut()[key_len..incoming_len], &mut mac)
        .is_err()
    {
        return internal_error();
    }
    apdu.buffer_mut()[..mac.len()].copy_from_slice(&mac);
    let _ = apdu.set_outgoing();
    apdu.set_outgoing_length(mac.len());
    ApduStatus::success()
}

fn process_bench_kdf(apdu: &mut dyn SEApdu, hkdf: bool) -> ApduStatus {
    let incoming_len = apdu.set_incoming_and_receive();
    let output_len = apdu.p1() as usize;
    if output_len == 0 || output_len > BENCH_MAX_KDF_OUTPUT_LEN {
        return ApduStatus::wrong_data();
    }

    let mut cursor = 0usize;
    let Some((first, first_len)) = copy_next_lv(apdu.buffer_mut(), incoming_len, &mut cursor)
    else {
        return ApduStatus::wrong_data();
    };
    let Some((second, second_len)) = copy_next_lv(apdu.buffer_mut(), incoming_len, &mut cursor)
    else {
        return ApduStatus::wrong_data();
    };
    if cursor != incoming_len {
        return ApduStatus::wrong_data();
    }

    let out = &mut apdu.buffer_mut()[..output_len];
    let result = if hkdf {
        crate::core::crypto::hkdf_sha256(&first[..first_len], &second[..second_len], &[], out)
    } else {
        crate::core::crypto::x963_sha256_kdf(&first[..first_len], &second[..second_len], out)
    };
    if result.is_err() {
        return internal_error();
    }
    let _ = apdu.set_outgoing();
    apdu.set_outgoing_length(output_len);
    ApduStatus::success()
}

fn process_bench_p256_keygen(apdu: &mut dyn SEApdu) -> ApduStatus {
    if !receive_keygen_transport_request(apdu) {
        return ApduStatus::wrong_data();
    }
    let mut private_key = [0u8; crate::core::crypto::P256_PRIVATE_KEY_SIZE];
    let mut public_key = [0u8; crate::core::crypto::P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
    let result = crate::core::crypto::p256_generate_keypair(&mut private_key, &mut public_key);
    if result.is_err() {
        return internal_error();
    }
    apdu.buffer_mut()[..private_key.len()].copy_from_slice(&private_key);
    apdu.buffer_mut()[private_key.len()..private_key.len() + public_key.len()]
        .copy_from_slice(&public_key);
    let _ = apdu.set_outgoing();
    apdu.set_outgoing_length(private_key.len() + public_key.len());
    ApduStatus::success()
}

// P1=1 plus one zero input byte selects case 4: the existing APDU manager
// retains the result in its shared buffer for bounded GET RESPONSE requests.
// P1=0 keeps the original case-2 interface. Never regenerate a key per chunk.
fn receive_keygen_transport_request(apdu: &mut dyn SEApdu) -> bool {
    match apdu.p1() {
        0 => true,
        1 => {
            apdu.set_incoming_and_receive();
            apdu.incoming_data() == [0]
        }
        _ => false,
    }
}

fn process_bench_p256_ecdh(apdu: &mut dyn SEApdu) -> ApduStatus {
    let incoming_len = apdu.set_incoming_and_receive();
    let expected_len = crate::core::crypto::P256_PRIVATE_KEY_SIZE
        + crate::core::crypto::P256_PUBLIC_KEY_UNCOMPRESSED_SIZE;
    if incoming_len != expected_len {
        return ApduStatus::wrong_data();
    }

    let mut private_key = [0u8; crate::core::crypto::P256_PRIVATE_KEY_SIZE];
    let mut peer_public = [0u8; crate::core::crypto::P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
    private_key.copy_from_slice(&apdu.buffer_mut()[..crate::core::crypto::P256_PRIVATE_KEY_SIZE]);
    peer_public.copy_from_slice(
        &apdu.buffer_mut()[crate::core::crypto::P256_PRIVATE_KEY_SIZE..expected_len],
    );
    let result = crate::core::crypto::p256_ecdh(
        &private_key,
        &peer_public,
        &mut apdu.buffer_mut()[..crate::core::crypto::P256_SHARED_SECRET_SIZE],
    );
    if result.is_err() {
        return internal_error();
    }
    let _ = apdu.set_outgoing();
    apdu.set_outgoing_length(crate::core::crypto::P256_SHARED_SECRET_SIZE);
    ApduStatus::success()
}

fn copy_next_lv(
    buffer: &[u8],
    total_len: usize,
    cursor: &mut usize,
) -> Option<([u8; BENCH_MAX_KDF_INPUT_LEN], usize)> {
    if *cursor >= total_len {
        return None;
    }
    let len = buffer[*cursor] as usize;
    *cursor += 1;
    if len > BENCH_MAX_KDF_INPUT_LEN || *cursor + len > total_len {
        return None;
    }
    let mut out = [0u8; BENCH_MAX_KDF_INPUT_LEN];
    out[..len].copy_from_slice(&buffer[*cursor..*cursor + len]);
    *cursor += len;
    Some((out, len))
}

fn internal_error() -> ApduStatus {
    ApduStatus {
        sw1: 0x6f,
        sw2: 0x00,
    }
}
