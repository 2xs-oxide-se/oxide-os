//! rustlets scenario operations and assertions, shared by individual tests and campaigns.
use super::*;

pub(crate) fn run_single_rustlet_case(
    client: &mut ApduClient,
    spec: SingleRustletSpec,
) -> Result<(), Box<dyn Error>> {
    run_rustlet_scenario(
        client,
        spec.name,
        rustlet_scenario_aids(spec.name)?,
        "rustlet-single",
    )
}

pub(crate) fn run_rustlet_functional_scenarios(
    client: &mut ApduClient,
) -> Result<usize, Box<dyn Error>> {
    let mut total = 0;
    for spec in rustlet_functional_specs()? {
        run_rustlet_scenario(
            client,
            spec.name,
            rustlet_scenario_aids(spec.name)?,
            "rustlet-test",
        )?;
        total += spec.total;
    }
    Ok(total)
}

pub(crate) fn run_rustlet_scenario(
    client: &mut ApduClient,
    name: &str,
    aids: RustletScenarioAids,
    log_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    let aid = aids.instance_aid;
    match name {
        "minimal_valid_test" => {
            eprintln!("{log_prefix}: install minimal_valid_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "install minimal_valid_test",
            )?;
            eprintln!("{log_prefix}: select minimal_valid_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "select minimal_valid_test",
            )?;
            run_minimal_valid_post_select_apdus(client, log_prefix, false)?;
        }
        "getting_started_test" => {
            eprintln!("{log_prefix}: install getting_started_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "install getting_started_test",
            )?;
            eprintln!("{log_prefix}: select getting_started_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "select getting_started_test",
            )?;
            run_getting_started_post_select_apdus(client, log_prefix)?;
        }
        "apdus_test" => {
            eprintln!("{log_prefix}: install apdus_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "install apdus_test",
            )?;
            eprintln!("{log_prefix}: select apdus_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "select apdus_test",
            )?;
            eprintln!("{log_prefix}: apdus case 1");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data(0x70))?,
                &[],
                (0x90, 0x00),
                "apdus case 1",
            )?;
            eprintln!("{log_prefix}: apdus case 3");
            expect_status(
                client.exchange(&CommandBuilder::process_with_data(
                    0x72,
                    &[0x01, 0x02, 0x03],
                ))?,
                (0x90, 0x00),
                "apdus case 3",
            )?;
            eprintln!("{log_prefix}: apdus case 2");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x74, 0x04))?,
                &[0x04, 0xA1, 0xA2, 0xA3],
                (0x90, 0x00),
                "apdus case 2",
            )?;
            eprintln!("{log_prefix}: apdus case 4");
            expect_response(
                client.exchange(&CommandBuilder::process_with_data_and_le(
                    0x76,
                    &[0xCA, 0xFE, 0xBA, 0xBE],
                    0x04,
                ))?,
                &[0xCA, 0xFE, 0xBA, 0xBE],
                (0x90, 0x00),
                "apdus case 4",
            )?;
            eprintln!("{log_prefix}: apdus send_with");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x78, 0x04))?,
                &[0x78, 0x01, 0x02, 0x03],
                (0x90, 0x00),
                "apdus send_with",
            )?;
            eprintln!("{log_prefix}: apdus lc view");
            expect_response(
                client.exchange(&CommandBuilder::process_with_data_and_le(
                    0x7A,
                    &[0x10, 0x11, 0x12, 0x13, 0x14],
                    0x01,
                ))?,
                &[0x05],
                (0x90, 0x00),
                "apdus lc view",
            )?;
        }
        "crypto_test" => {
            const INS_SET_KEY: u8 = 0x80;
            const INS_CYPHER_PAYLOAD: u8 = 0x82;
            const INS_DECYPHER_PAYLOAD: u8 = 0x84;
            const INS_CYPHER_CONTENT: u8 = 0x86;
            const INS_SET_MASTER_KEY128: u8 = 0x88;
            const INS_SET_MASTER_KEY256: u8 = 0x8A;
            const INS_RANDOM: u8 = 0x8C;
            const INS_SET_AUTH_KEY: u8 = 0x50;
            const INS_CMAC_PAYLOAD: u8 = 0x52;
            const INS_VERIFY_CMAC_PAYLOAD: u8 = 0x54;
            const AES_BLOCK_SIZE: usize = 16;
            const INTERNAL_CONTENT: &[u8] = b"hello aes cyphered world!.......";
            let iv = [0u8; 16];
            let key128 = [0x10u8; 16];
            let key256 = [0x20u8; 32];
            let auth_key128 = [0x30u8; 16];
            let auth_key256 = [0x40u8; 32];
            let master_key128 = *b"master key 128!!";
            let master_key256 = *b"master key 256!!master key 256!!";
            let payload = *b"0123456789ABCDEFfedcba9876543210";
            let mac_payload = b"authenticated payload";
            let padded_payload = b"ISO9797-M2 payload";

            eprintln!("{log_prefix}: install crypto_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "install crypto_test",
            )?;
            eprintln!("{log_prefix}: select crypto_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "select crypto_test",
            )?;

            eprintln!("{log_prefix}: crypto set AES-128 key");
            expect_status(
                client.exchange(&CommandBuilder::process_with_data(INS_SET_KEY, &key128))?,
                (0x90, 0x00),
                "crypto set AES-128 key",
            )?;
            let encrypted128_len = AES_BLOCK_SIZE
                + host_aes_cbc_encrypt(&key128, &iv, &payload, HostCbcPadding::None)?.len();
            eprintln!("{log_prefix}: crypto AES-128 cypher payload");
            let encrypted128 = expect_cbc_encrypted_response(
                client.exchange(&CommandBuilder::process_with_data_and_le(
                    INS_CYPHER_PAYLOAD,
                    &payload,
                    encrypted128_len as u8,
                ))?,
                &key128,
                &payload,
                HostCbcPadding::None,
                "crypto AES-128 cypher payload",
            )?;
            eprintln!("{log_prefix}: crypto AES-128 decypher payload");
            expect_response(
                client.exchange(&CommandBuilder::process_with_data_and_le(
                    INS_DECYPHER_PAYLOAD,
                    &encrypted128,
                    payload.len() as u8,
                ))?,
                &payload,
                (0x90, 0x00),
                "crypto AES-128 decypher payload",
            )?;
            let internal128_len = AES_BLOCK_SIZE
                + host_aes_cbc_encrypt(&key128, &iv, INTERNAL_CONTENT, HostCbcPadding::None)?.len();
            eprintln!("{log_prefix}: crypto AES-128 cypher content");
            let _ = expect_cbc_encrypted_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(
                    INS_CYPHER_CONTENT,
                    internal128_len as u8,
                ))?,
                &key128,
                INTERNAL_CONTENT,
                HostCbcPadding::None,
                "crypto AES-128 cypher content",
            )?;
            let padded128_len = AES_BLOCK_SIZE
                + host_aes_cbc_encrypt(&key128, &iv, padded_payload, HostCbcPadding::Iso9797M2)?
                    .len();
            eprintln!("{log_prefix}: crypto AES-128 ISO9797-M2 cypher payload");
            let padded128 = expect_cbc_encrypted_response(
                client.exchange(&CommandBuilder::process_with_p1_data_and_le(
                    INS_CYPHER_PAYLOAD,
                    0x01,
                    padded_payload,
                    padded128_len as u8,
                ))?,
                &key128,
                padded_payload,
                HostCbcPadding::Iso9797M2,
                "crypto AES-128 ISO9797-M2 cypher payload",
            )?;
            eprintln!("{log_prefix}: crypto AES-128 ISO9797-M2 decypher payload");
            expect_response(
                client.exchange(&CommandBuilder::process_with_p1_data_and_le(
                    INS_DECYPHER_PAYLOAD,
                    0x01,
                    &padded128,
                    padded_payload.len() as u8,
                ))?,
                padded_payload,
                (0x90, 0x00),
                "crypto AES-128 ISO9797-M2 decypher payload",
            )?;
            let internal128_padded_len = AES_BLOCK_SIZE
                + host_aes_cbc_encrypt(&key128, &iv, INTERNAL_CONTENT, HostCbcPadding::Iso9797M2)?
                    .len();
            eprintln!("{log_prefix}: crypto AES-128 ISO9797-M2 cypher content");
            let _ = expect_cbc_encrypted_response(
                client.exchange(&CommandBuilder::process_no_data_with_p1_and_le(
                    INS_CYPHER_CONTENT,
                    0x01,
                    internal128_padded_len as u8,
                ))?,
                &key128,
                INTERNAL_CONTENT,
                HostCbcPadding::Iso9797M2,
                "crypto AES-128 ISO9797-M2 cypher content",
            )?;
            let ecb128 = host_aes_ecb_encrypt(&key128, &payload)?;
            eprintln!("{log_prefix}: crypto AES-128 ECB cypher payload");
            expect_response(
                client.exchange(&CommandBuilder::process_with_p1_data_and_le(
                    INS_CYPHER_PAYLOAD,
                    0x02,
                    &payload,
                    ecb128.len() as u8,
                ))?,
                &ecb128,
                (0x90, 0x00),
                "crypto AES-128 ECB cypher payload",
            )?;
            eprintln!("{log_prefix}: crypto AES-128 ECB decypher payload");
            expect_response(
                client.exchange(&CommandBuilder::process_with_p1_data_and_le(
                    INS_DECYPHER_PAYLOAD,
                    0x02,
                    &ecb128,
                    payload.len() as u8,
                ))?,
                &payload,
                (0x90, 0x00),
                "crypto AES-128 ECB decypher payload",
            )?;
            eprintln!("{log_prefix}: crypto set master AES-128 key");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(INS_SET_MASTER_KEY128))?,
                (0x90, 0x00),
                "crypto set master AES-128 key",
            )?;
            let master128_len = AES_BLOCK_SIZE
                + host_aes_cbc_encrypt(
                    &master_key128,
                    &iv,
                    INTERNAL_CONTENT,
                    HostCbcPadding::None,
                )?
                .len();
            eprintln!("{log_prefix}: crypto master AES-128 cypher content");
            let _ = expect_cbc_encrypted_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(
                    INS_CYPHER_CONTENT,
                    master128_len as u8,
                ))?,
                &master_key128,
                INTERNAL_CONTENT,
                HostCbcPadding::None,
                "crypto master AES-128 cypher content",
            )?;

            eprintln!("{log_prefix}: crypto set AES-256 key");
            expect_status(
                client.exchange(&CommandBuilder::process_with_data(INS_SET_KEY, &key256))?,
                (0x90, 0x00),
                "crypto set AES-256 key",
            )?;
            let encrypted256_len = AES_BLOCK_SIZE
                + host_aes_cbc_encrypt(&key256, &iv, &payload, HostCbcPadding::None)?.len();
            eprintln!("{log_prefix}: crypto AES-256 cypher payload");
            let encrypted256 = expect_cbc_encrypted_response(
                client.exchange(&CommandBuilder::process_with_data_and_le(
                    INS_CYPHER_PAYLOAD,
                    &payload,
                    encrypted256_len as u8,
                ))?,
                &key256,
                &payload,
                HostCbcPadding::None,
                "crypto AES-256 cypher payload",
            )?;
            eprintln!("{log_prefix}: crypto AES-256 decypher payload");
            expect_response(
                client.exchange(&CommandBuilder::process_with_data_and_le(
                    INS_DECYPHER_PAYLOAD,
                    &encrypted256,
                    payload.len() as u8,
                ))?,
                &payload,
                (0x90, 0x00),
                "crypto AES-256 decypher payload",
            )?;
            let internal256_len = AES_BLOCK_SIZE
                + host_aes_cbc_encrypt(&key256, &iv, INTERNAL_CONTENT, HostCbcPadding::None)?.len();
            eprintln!("{log_prefix}: crypto AES-256 cypher content");
            let _ = expect_cbc_encrypted_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(
                    INS_CYPHER_CONTENT,
                    internal256_len as u8,
                ))?,
                &key256,
                INTERNAL_CONTENT,
                HostCbcPadding::None,
                "crypto AES-256 cypher content",
            )?;
            let padded256_len = AES_BLOCK_SIZE
                + host_aes_cbc_encrypt(&key256, &iv, padded_payload, HostCbcPadding::Iso9797M2)?
                    .len();
            eprintln!("{log_prefix}: crypto AES-256 ISO9797-M2 cypher payload");
            let padded256 = expect_cbc_encrypted_response(
                client.exchange(&CommandBuilder::process_with_p1_data_and_le(
                    INS_CYPHER_PAYLOAD,
                    0x01,
                    padded_payload,
                    padded256_len as u8,
                ))?,
                &key256,
                padded_payload,
                HostCbcPadding::Iso9797M2,
                "crypto AES-256 ISO9797-M2 cypher payload",
            )?;
            eprintln!("{log_prefix}: crypto AES-256 ISO9797-M2 decypher payload");
            expect_response(
                client.exchange(&CommandBuilder::process_with_p1_data_and_le(
                    INS_DECYPHER_PAYLOAD,
                    0x01,
                    &padded256,
                    padded_payload.len() as u8,
                ))?,
                padded_payload,
                (0x90, 0x00),
                "crypto AES-256 ISO9797-M2 decypher payload",
            )?;
            let ecb256 = host_aes_ecb_encrypt(&key256, &payload)?;
            eprintln!("{log_prefix}: crypto AES-256 ECB cypher payload");
            expect_response(
                client.exchange(&CommandBuilder::process_with_p1_data_and_le(
                    INS_CYPHER_PAYLOAD,
                    0x02,
                    &payload,
                    ecb256.len() as u8,
                ))?,
                &ecb256,
                (0x90, 0x00),
                "crypto AES-256 ECB cypher payload",
            )?;
            eprintln!("{log_prefix}: crypto AES-256 ECB decypher payload");
            expect_response(
                client.exchange(&CommandBuilder::process_with_p1_data_and_le(
                    INS_DECYPHER_PAYLOAD,
                    0x02,
                    &ecb256,
                    payload.len() as u8,
                ))?,
                &payload,
                (0x90, 0x00),
                "crypto AES-256 ECB decypher payload",
            )?;
            eprintln!("{log_prefix}: crypto set master AES-256 key");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(INS_SET_MASTER_KEY256))?,
                (0x90, 0x00),
                "crypto set master AES-256 key",
            )?;
            let master256_len = AES_BLOCK_SIZE
                + host_aes_cbc_encrypt(
                    &master_key256,
                    &iv,
                    INTERNAL_CONTENT,
                    HostCbcPadding::None,
                )?
                .len();
            eprintln!("{log_prefix}: crypto master AES-256 cypher content");
            let _ = expect_cbc_encrypted_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(
                    INS_CYPHER_CONTENT,
                    master256_len as u8,
                ))?,
                &master_key256,
                INTERNAL_CONTENT,
                HostCbcPadding::None,
                "crypto master AES-256 cypher content",
            )?;
            eprintln!("{log_prefix}: crypto random data");
            let random =
                client.exchange(&CommandBuilder::process_no_data_with_le(INS_RANDOM, 0x10))?;
            if random.status != (0x90, 0x00) || random.data.len() != 16 {
                return Err(format!(
                    "crypto random data: expected 16 bytes and status 9000, got data {:02X?} and status ({:02X}, {:02X})",
                    random.data, random.status.0, random.status.1
                )
                .into());
            }
            eprintln!("{log_prefix}: crypto set CMAC AES-128 key");
            expect_status(
                client.exchange(&CommandBuilder::process_with_data(
                    INS_SET_AUTH_KEY,
                    &auth_key128,
                ))?,
                (0x90, 0x00),
                "crypto set CMAC AES-128 key",
            )?;
            let cmac128_cmd =
                CommandBuilder::process_with_data_and_le(INS_CMAC_PAYLOAD, mac_payload, 16);
            let cmac128_expected = host_aes_cmac_for_command(&auth_key128, &cmac128_cmd)?;
            eprintln!("{log_prefix}: crypto AES-128 CMAC payload");
            expect_response(
                client.exchange(&cmac128_cmd)?,
                &cmac128_expected,
                (0x90, 0x00),
                "crypto AES-128 CMAC payload",
            )?;
            let verify128_expected = host_aes_cmac_for_header_and_payload(
                &auth_key128,
                INS_VERIFY_CMAC_PAYLOAD,
                mac_payload,
            )?;
            let mut verify128_data = verify128_expected.clone();
            verify128_data.extend_from_slice(mac_payload);
            eprintln!("{log_prefix}: crypto AES-128 CMAC verify true");
            expect_response(
                client.exchange(&CommandBuilder::process_with_data_and_le(
                    INS_VERIFY_CMAC_PAYLOAD,
                    &verify128_data,
                    1,
                ))?,
                &[1],
                (0x90, 0x00),
                "crypto AES-128 CMAC verify true",
            )?;
            verify128_data[0] ^= 0x01;
            eprintln!("{log_prefix}: crypto AES-128 CMAC verify false");
            expect_response(
                client.exchange(&CommandBuilder::process_with_data_and_le(
                    INS_VERIFY_CMAC_PAYLOAD,
                    &verify128_data,
                    1,
                ))?,
                &[0],
                (0x90, 0x00),
                "crypto AES-128 CMAC verify false",
            )?;
            eprintln!("{log_prefix}: crypto set CMAC AES-256 key");
            expect_status(
                client.exchange(&CommandBuilder::process_with_data(
                    INS_SET_AUTH_KEY,
                    &auth_key256,
                ))?,
                (0x90, 0x00),
                "crypto set CMAC AES-256 key",
            )?;
            let cmac256_cmd =
                CommandBuilder::process_with_data_and_le(INS_CMAC_PAYLOAD, mac_payload, 16);
            let cmac256_expected = host_aes_cmac_for_command(&auth_key256, &cmac256_cmd)?;
            eprintln!("{log_prefix}: crypto AES-256 CMAC payload");
            expect_response(
                client.exchange(&cmac256_cmd)?,
                &cmac256_expected,
                (0x90, 0x00),
                "crypto AES-256 CMAC payload",
            )?;
        }
        "ecdh_test" => {
            eprintln!("{log_prefix}: install ecdh_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "install ecdh_test",
            )?;
            eprintln!("{log_prefix}: select ecdh_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "select ecdh_test",
            )?;
            eprintln!("{log_prefix}: derive P-256 shared secret");
            let host_secret = SecretKey::from_slice(&[
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                0xF0, 0x01, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
                0xD0, 0xE0, 0xF0, 0x01,
            ])
            .map_err(|_| "ecdh_test: invalid fixed host private key")?;
            let host_public = host_secret.public_key();
            let response = client.exchange(&CommandBuilder::process_with_data_and_le(
                0x40,
                host_public.to_encoded_point(false).as_bytes(),
                97,
            ))?;
            let response = expect_host_ecdh_response(&response, 97, "ecdh_test")?;
            let expected = host_p256_shared_secret(&host_secret, response.public_key, "ecdh_test")?;
            if response.payload != expected {
                return Err("ecdh_test: shared secret mismatch".into());
            }

            eprintln!("{log_prefix}: derive P-256 HKDF-SHA256 output");
            let response = client.exchange(&CommandBuilder::process_with_data_and_le(
                0x42,
                host_public.to_encoded_point(false).as_bytes(),
                97,
            ))?;
            let response = expect_host_ecdh_response(&response, 97, "ecdh_test hkdf")?;
            let shared =
                host_p256_shared_secret(&host_secret, response.public_key, "ecdh_test hkdf")?;
            let mut expected = [0u8; 32];
            host_hkdf_sha256(
                &shared,
                b"oxide-se-ecdh-test-salt",
                b"oxide-se-ecdh-test-info",
                &mut expected,
                "ecdh_test hkdf",
            )?;
            if response.payload != expected {
                return Err("ecdh_test hkdf: derived key mismatch".into());
            }

            eprintln!("{log_prefix}: derive SCP11c session material");
            let response = client.exchange(&CommandBuilder::process_with_data_and_le(
                0x44,
                host_public.to_encoded_point(false).as_bytes(),
                113,
            ))?;
            let response = expect_host_ecdh_response(&response, 113, "ecdh_test scp11c")?;
            let expected_material = derive_host_ecdh_hkdf_triplet(
                &host_secret,
                host_public.to_encoded_point(false).as_bytes(),
                response.public_key,
                "ecdh_test scp11c",
            )?;
            let response_material =
                parse_ecdh_derived_triplet(response.payload, "ecdh_test scp11c response")?;
            if response_material != expected_material {
                return Err("ecdh_test scp11c: session material mismatch".into());
            }
            if !response_material.all_distinct() {
                return Err("ecdh_test scp11c: derived subkeys should remain distinct".into());
            }

            eprintln!("{log_prefix}: derive SCP11c session material again");
            let second_response = client.exchange(&CommandBuilder::process_with_data_and_le(
                0x44,
                host_public.to_encoded_point(false).as_bytes(),
                113,
            ))?;
            let second_response =
                expect_host_ecdh_response(&second_response, 113, "ecdh_test scp11c second")?;
            let second_expected = derive_host_ecdh_hkdf_triplet(
                &host_secret,
                host_public.to_encoded_point(false).as_bytes(),
                second_response.public_key,
                "ecdh_test scp11c second",
            )?;
            let second_material = parse_ecdh_derived_triplet(
                second_response.payload,
                "ecdh_test scp11c second response",
            )?;
            if second_material != second_expected {
                return Err("ecdh_test scp11c second: session material mismatch".into());
            }
            if second_response.public_key == response.public_key {
                return Err(
                    "ecdh_test scp11c second: expected a fresh card ephemeral public key".into(),
                );
            }
            if second_material == response_material {
                return Err("ecdh_test scp11c second: expected distinct session material".into());
            }
            if !second_material.all_distinct() {
                return Err(
                    "ecdh_test scp11c second: derived subkeys should remain distinct".into(),
                );
            }
        }
        "state_test" => {
            let instance_a = aid;
            let instance_b = aids
                .alternate_instance_aid
                .ok_or("state_test requires a second instance AID")?;

            eprintln!("{log_prefix}: install state_test instance A");
            expect_status(
                client.exchange(&CommandBuilder::install_with_aids_and_data(
                    aids.package_aid,
                    aids.applet_aid,
                    instance_a,
                    &[0x2A],
                ))?,
                (0x90, 0x00),
                "install state_test instance A",
            )?;
            eprintln!("{log_prefix}: select state_test instance A");
            expect_status(
                client.exchange(&CommandBuilder::select(instance_a))?,
                (0x90, 0x00),
                "select state_test instance A",
            )?;
            eprintln!("{log_prefix}: state A counter 1");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x10, 0x01))?,
                &[0x2A],
                (0x90, 0x00),
                "state A first counter",
            )?;
            eprintln!("{log_prefix}: state A counter 2");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x10, 0x01))?,
                &[0x2B],
                (0x90, 0x00),
                "state A second counter",
            )?;
            eprintln!("{log_prefix}: state A abi version");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x12, 0x01))?,
                &[0x01],
                (0x90, 0x00),
                "state A abi version",
            )?;
            eprintln!("{log_prefix}: install state_test instance B");
            expect_status(
                client.exchange(&CommandBuilder::install_with_aids_and_data(
                    aids.package_aid,
                    aids.applet_aid,
                    instance_b,
                    &[0x80],
                ))?,
                (0x90, 0x00),
                "install state_test instance B",
            )?;
            eprintln!("{log_prefix}: select state_test instance B");
            expect_status(
                client.exchange(&CommandBuilder::select(instance_b))?,
                (0x90, 0x00),
                "select state_test instance B",
            )?;
            eprintln!("{log_prefix}: state B counter 1");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x10, 0x01))?,
                &[0x80],
                (0x90, 0x00),
                "state B first counter",
            )?;
            eprintln!("{log_prefix}: reselect state_test instance A");
            expect_status(
                client.exchange(&CommandBuilder::select(instance_a))?,
                (0x90, 0x00),
                "reselect state_test instance A",
            )?;
            eprintln!("{log_prefix}: state A counter after reload");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x10, 0x01))?,
                &[0x2C],
                (0x90, 0x00),
                "state A counter after reload",
            )?;
            eprintln!("{log_prefix}: reselect state_test instance B");
            expect_status(
                client.exchange(&CommandBuilder::select(instance_b))?,
                (0x90, 0x00),
                "reselect state_test instance B",
            )?;
            eprintln!("{log_prefix}: state B counter after reload");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x10, 0x01))?,
                &[0x81],
                (0x90, 0x00),
                "state B counter after reload",
            )?;
        }
        "serialization_test" => {
            const INS_INCREMENT: u8 = 0x40;
            const INS_DUMP: u8 = 0x42;

            let instance_a = aid;
            let instance_b = aids
                .alternate_instance_aid
                .ok_or("serialization_test requires a second instance AID")?;

            eprintln!("{log_prefix}: install serialization_test instance A");
            expect_status(
                client.exchange(&CommandBuilder::install_with_aids_and_data(
                    aids.package_aid,
                    aids.applet_aid,
                    instance_a,
                    &[0x10, 0x40, 0x70, 0xA0],
                ))?,
                (0x90, 0x00),
                "install serialization_test instance A",
            )?;
            eprintln!("{log_prefix}: select serialization_test instance A");
            expect_status(
                client.exchange(&CommandBuilder::select(instance_a))?,
                (0x90, 0x00),
                "select serialization_test instance A",
            )?;
            eprintln!("{log_prefix}: serialization A initial dump");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(INS_DUMP, 0x04))?,
                &[0x10, 0x40, 0x00, 0x00],
                (0x90, 0x00),
                "serialization A initial dump",
            )?;
            eprintln!("{log_prefix}: serialization A increment 1");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(INS_INCREMENT))?,
                (0x90, 0x00),
                "serialization A increment 1",
            )?;
            eprintln!("{log_prefix}: serialization A dump after increment 1");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(INS_DUMP, 0x04))?,
                &[0x11, 0x41, 0x00, 0x00],
                (0x90, 0x00),
                "serialization A dump after increment 1",
            )?;
            eprintln!("{log_prefix}: serialization A increment 2");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(INS_INCREMENT))?,
                (0x90, 0x00),
                "serialization A increment 2",
            )?;
            eprintln!("{log_prefix}: serialization A dump after increment 2");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(INS_DUMP, 0x04))?,
                &[0x12, 0x42, 0x00, 0x00],
                (0x90, 0x00),
                "serialization A dump after increment 2",
            )?;
            eprintln!("{log_prefix}: reselect serialization_test instance A");
            expect_status(
                client.exchange(&CommandBuilder::select(instance_a))?,
                (0x90, 0x00),
                "reselect serialization_test instance A",
            )?;
            eprintln!("{log_prefix}: serialization A after same-instance reselect");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(INS_DUMP, 0x04))?,
                &[0x12, 0x42, 0x00, 0x00],
                (0x90, 0x00),
                "serialization A same-instance reselect",
            )?;
            eprintln!("{log_prefix}: install serialization_test instance B");
            expect_status(
                client.exchange(&CommandBuilder::install_with_aids_and_data(
                    aids.package_aid,
                    aids.applet_aid,
                    instance_b,
                    &[0x80, 0x90, 0xE0, 0xF0],
                ))?,
                (0x90, 0x00),
                "install serialization_test instance B",
            )?;
            eprintln!("{log_prefix}: select serialization_test instance B");
            expect_status(
                client.exchange(&CommandBuilder::select(instance_b))?,
                (0x90, 0x00),
                "select serialization_test instance B",
            )?;
            eprintln!("{log_prefix}: serialization B initial dump");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(INS_DUMP, 0x04))?,
                &[0x80, 0x90, 0x00, 0x00],
                (0x90, 0x00),
                "serialization B initial dump",
            )?;
            eprintln!("{log_prefix}: serialization B increment 1");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(INS_INCREMENT))?,
                (0x90, 0x00),
                "serialization B increment 1",
            )?;
            eprintln!("{log_prefix}: serialization B dump after increment 1");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(INS_DUMP, 0x04))?,
                &[0x81, 0x91, 0x00, 0x00],
                (0x90, 0x00),
                "serialization B dump after increment 1",
            )?;
            eprintln!("{log_prefix}: reselect serialization_test instance A after B");
            expect_status(
                client.exchange(&CommandBuilder::select(instance_a))?,
                (0x90, 0x00),
                "reselect serialization_test instance A after B",
            )?;
            eprintln!("{log_prefix}: serialization A after B reload");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(INS_DUMP, 0x04))?,
                &[0x12, 0x42, 0x00, 0x00],
                (0x90, 0x00),
                "serialization A after B reload",
            )?;
            eprintln!("{log_prefix}: serialization A increment after reload");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(INS_INCREMENT))?,
                (0x90, 0x00),
                "serialization A increment after reload",
            )?;
            eprintln!("{log_prefix}: serialization A dump after reload increment");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(INS_DUMP, 0x04))?,
                &[0x13, 0x43, 0x00, 0x00],
                (0x90, 0x00),
                "serialization A dump after reload increment",
            )?;
            eprintln!("{log_prefix}: reselect serialization_test instance B after A");
            expect_status(
                client.exchange(&CommandBuilder::select(instance_b))?,
                (0x90, 0x00),
                "reselect serialization_test instance B after A",
            )?;
            eprintln!("{log_prefix}: serialization B after A reload");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(INS_DUMP, 0x04))?,
                &[0x81, 0x91, 0x00, 0x00],
                (0x90, 0x00),
                "serialization B after A reload",
            )?;
        }
        "stack_overflow_test" => {
            eprintln!("{log_prefix}: install stack_overflow_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "install stack_overflow_test",
            )?;
            eprintln!("{log_prefix}: select stack_overflow_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "select stack_overflow_test",
            )?;
            eprintln!("{log_prefix}: stack_overflow_test liveness");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(0x00))?,
                (0x90, 0x00),
                "stack_overflow_test liveness",
            )?;
            eprintln!("{log_prefix}: stack_overflow_test out-of-window write");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(0x54))?,
                (0x6F, 0x00),
                "stack_overflow_test out-of-window write",
            )?;
            eprintln!("{log_prefix}: reinstall stack_overflow_test after out-of-window write");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "reinstall stack_overflow_test after out-of-window write",
            )?;
            eprintln!("{log_prefix}: reselect stack_overflow_test after out-of-window write");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "reselect stack_overflow_test after out-of-window write",
            )?;
            eprintln!("{log_prefix}: stack_overflow_test overflow");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(0x52))?,
                (0x6F, 0x00),
                "stack_overflow_test overflow",
            )?;
            eprintln!("{log_prefix}: reinstall stack_overflow_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "reinstall stack_overflow_test",
            )?;
            eprintln!("{log_prefix}: reselect stack_overflow_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "reselect stack_overflow_test",
            )?;
            eprintln!("{log_prefix}: stack_overflow_test liveness after overflow");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(0x00))?,
                (0x90, 0x00),
                "stack_overflow_test liveness after overflow",
            )?;
        }
        "stack_overflow_recursive_test" => {
            eprintln!("{log_prefix}: install stack_overflow_recursive_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "install stack_overflow_recursive_test",
            )?;
            eprintln!("{log_prefix}: select stack_overflow_recursive_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "select stack_overflow_recursive_test",
            )?;
            eprintln!("{log_prefix}: stack_overflow_recursive_test liveness");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(0x00))?,
                (0x90, 0x00),
                "stack_overflow_recursive_test liveness",
            )?;
            eprintln!("{log_prefix}: stack_overflow_recursive_test recursive overflow");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(0x53))?,
                (0x6F, 0x00),
                "stack_overflow_recursive_test recursive overflow",
            )?;
            eprintln!("{log_prefix}: reinstall stack_overflow_recursive_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "reinstall stack_overflow_recursive_test",
            )?;
            eprintln!("{log_prefix}: reselect stack_overflow_recursive_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "reselect stack_overflow_recursive_test",
            )?;
            eprintln!("{log_prefix}: stack_overflow_recursive_test liveness after overflow");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(0x00))?,
                (0x90, 0x00),
                "stack_overflow_recursive_test liveness after overflow",
            )?;
        }
        "alloc_free_test" => {
            eprintln!("{log_prefix}: install alloc_free_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "install alloc_free_test",
            )?;
            eprintln!("{log_prefix}: select alloc_free_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "select alloc_free_test",
            )?;
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x30, 0x03))?,
                &[0x2A, 32, 240],
                (0x90, 0x00),
                "alloc free",
            )?;
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x32, 0x01))?,
                &[8],
                (0x90, 0x00),
                "alloc tiny granule",
            )?;
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x34, 0x01))?,
                &[7],
                (0x90, 0x00),
                "alloc requested alignments",
            )?;
        }
        "heap_form_test" => {
            eprintln!("{log_prefix}: install heap_form_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "install heap_form_test",
            )?;
            eprintln!("{log_prefix}: select heap_form_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "select heap_form_test",
            )?;
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x30, 0x01))?,
                &[64],
                (0x90, 0x00),
                "heap form alloc",
            )?;
        }
        "string_test" => {
            eprintln!("{log_prefix}: install string_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "install string_test",
            )?;
            eprintln!("{log_prefix}: select string_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "select string_test",
            )?;
            expect_response(
                client.exchange(&CommandBuilder::process_with_data_and_le(0x40, b"abc", 14))?,
                b"Oxide SE:abc!",
                (0x90, 0x00),
                "string",
            )?;
        }
        "termination_test" => run_termination_fault_sequence(client, log_prefix)?,
        "isolation_fault_test" => run_isolation_fault_sequence(client, log_prefix)?,
        "complete_security_domain" => {
            eprintln!("{log_prefix}: install complete_security_domain instance");
            expect_status(
                client.exchange(&CommandBuilder::install_with_aids_privileges_and_data(
                    complete_security_domain_aid(),
                    complete_security_domain_aid(),
                    complete_security_domain_instance_aid(),
                    &SECURITY_DOMAIN_INSTALL_PRIVILEGES,
                    &[],
                ))?,
                (0x90, 0x00),
                "install complete_security_domain instance",
            )?;
            eprintln!("{log_prefix}: select complete_security_domain instance");
            expect_response(
                client.exchange(&CommandBuilder::select(
                    complete_security_domain_instance_aid(),
                ))?,
                complete_security_domain_select_fci(),
                (0x90, 0x00),
                "select complete_security_domain instance",
            )?;
            expect_response(
                client.exchange(&CommandBuilder::process_with_data_and_le(
                    0x02,
                    &[0x00, 0x01, 0x02, 0x03],
                    0x04,
                ))?,
                &[0x00, 0x01, 0x02, 0x03],
                (0x90, 0x00),
                "complete_security_domain echo",
            )?;
        }
        _ => return Err(format!("missing Rustlet scenario for {name}").into()),
    }
    Ok(())
}

/// Runs the broad Rustlet APDU regression campaign on one target board.
///
/// The campaign boots the GP kernel with the `config_rustlet_test_all`
/// predeployment manifest, checks baseline dispatch errors, then installs and
/// exercises every canonical Rustlet scenario. `check_stack` derives a
/// manifest containing both stack-monitor modules so this same APDU sequence
/// can measure the kernel and Rustlet stacks as a regression test.
pub(crate) fn run_rustlet_functional_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
    check_stack: bool,
) -> Result<TestReport, Box<dyn Error>> {
    testing::with_stack_observer(
        ctx,
        check_stack,
        StackBaselineKey::new("rustlet_all", board, image_format, None),
        true,
        |ctx| {
            let board = board_spec(board)?;
            let total = testing::target::run_apdu(
                ctx,
                board,
                image_format,
                "rustlet-test",
                APDU_RESPONSE_TIMEOUT,
                |client| {
                    eprintln!("rustlet-test: no-app no-data");
                    expect_status(
                        client.exchange(&CommandBuilder::process_no_data(0x00))?,
                        (0x69, 0x85),
                        "no selected app no-data",
                    )?;

                    eprintln!("rustlet-test: unknown select");
                    expect_status(
                        client.exchange(&CommandBuilder::select(&[
                            0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x7F,
                        ]))?,
                        (0x6A, 0x82),
                        "unknown select",
                    )?;

                    let functional_total = run_rustlet_functional_scenarios(client)?;
                    Ok(2 + functional_total)
                },
            )?;
            Ok(TestReport::passed(total))
        },
    )
}

pub(crate) fn run_minimal_valid_post_select_apdus(
    client: &mut ApduClient,
    log_prefix: &str,
    include_panic_path: bool,
) -> Result<usize, Box<dyn Error>> {
    eprintln!("{log_prefix}: minimal process");
    expect_response(
        client.exchange(&CommandBuilder::process_no_data(0x00))?,
        &[],
        (0x90, 0x00),
        "minimal process",
    )?;

    eprintln!("{log_prefix}: minimal inbound");
    expect_status(
        client.exchange(&CommandBuilder::process_with_data(
            0x02,
            &[0xAA, 0xBB, 0xCC],
        ))?,
        (0x90, 0x00),
        "minimal inbound",
    )?;

    eprintln!("{log_prefix}: minimal outbound");
    expect_response(
        client.exchange(&CommandBuilder::process_no_data_with_le(0x04, 0x02))?,
        &[0x10, 0x11, 0x12],
        (0x90, 0x00),
        "minimal outbound",
    )?;

    eprintln!("{log_prefix}: minimal in/out");
    expect_response(
        client.exchange(&CommandBuilder::process_with_data_and_le(
            0x06,
            &[0xAA, 0xBB, 0xCC],
            0x03,
        ))?,
        &[0xAA, 0xBB, 0xCC],
        (0x90, 0x00),
        "minimal in/out",
    )?;

    let mut total = 4;
    if include_panic_path {
        eprintln!("{log_prefix}: minimal panic path");
        expect_status(
            client.exchange(&CommandBuilder::process_no_data(0x01))?,
            (0x6F, 0x00),
            "minimal panic path",
        )?;
        total += 1;
    }

    Ok(total)
}

pub(crate) fn run_getting_started_post_select_apdus(
    client: &mut ApduClient,
    log_prefix: &str,
) -> Result<usize, Box<dyn Error>> {
    eprintln!("{log_prefix}: getting-started process");
    expect_response(
        client.exchange(&CommandBuilder::process_no_data(0x00))?,
        &[],
        (0x90, 0x00),
        "getting-started process",
    )?;

    eprintln!("{log_prefix}: getting-started inbound");
    expect_status(
        client.exchange(&CommandBuilder::process_with_data(
            0x02,
            &[0xAA, 0xBB, 0xCC],
        ))?,
        (0x90, 0x00),
        "getting-started inbound",
    )?;

    eprintln!("{log_prefix}: getting-started fixed outbound");
    expect_response(
        client.exchange(&CommandBuilder::process_no_data_with_le(0x04, 0x03))?,
        &[0x10, 0x11, 0x12],
        (0x90, 0x00),
        "getting-started fixed outbound",
    )?;

    eprintln!("{log_prefix}: getting-started fixed in/out");
    expect_response(
        client.exchange(&CommandBuilder::process_with_data_and_le(
            0x06,
            &[0xAA, 0xBB, 0xCC],
            0x03,
        ))?,
        &[0xAA, 0xBB, 0xCC],
        (0x90, 0x00),
        "getting-started fixed in/out",
    )?;

    eprintln!("{log_prefix}: getting-started echo");
    expect_response(
        client.exchange(&CommandBuilder::process_with_data_and_le(
            0x08,
            &[0xCA, 0xFE, 0xBA, 0xBE],
            0x04,
        ))?,
        &[0xCA, 0xFE, 0xBA, 0xBE],
        (0x90, 0x00),
        "getting-started echo",
    )?;

    Ok(5)
}

pub(crate) fn run_minimal_valid_install_select_and_process(
    client: &mut ApduClient,
    log_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    eprintln!("{log_prefix}: minimal valid install");
    expect_status(
        client.exchange(&CommandBuilder::install(
            crate_rustlet_minimal_valid_test_aid(),
        ))?,
        (0x90, 0x00),
        "install rustlet_minimal_valid_test",
    )?;
    eprintln!("{log_prefix}: minimal valid select");
    expect_status(
        client.exchange(&CommandBuilder::select(
            crate_rustlet_minimal_valid_test_aid(),
        ))?,
        (0x90, 0x00),
        "select rustlet_minimal_valid_test",
    )?;
    eprintln!("{log_prefix}: minimal valid process");
    expect_response(
        client.exchange(&CommandBuilder::process_no_data(0x00))?,
        &[],
        (0x90, 0x00),
        "rustlet_minimal_valid_test process",
    )
}

pub(crate) fn run_termination_fault_sequence(
    client: &mut ApduClient,
    log_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    let aid = crate_rustlet_termination_test_aid();
    eprintln!("{log_prefix}: install termination_test");
    expect_status(
        client.exchange(&CommandBuilder::install(aid))?,
        (0x90, 0x00),
        "install termination_test",
    )?;
    eprintln!("{log_prefix}: select termination_test");
    expect_status(
        client.exchange(&CommandBuilder::select(aid))?,
        (0x90, 0x00),
        "select termination_test",
    )?;
    eprintln!("{log_prefix}: termination normal return");
    expect_status(
        client.exchange(&CommandBuilder::process_no_data(0x24))?,
        (0x90, 0x00),
        "termination normal return",
    )?;
    eprintln!("{log_prefix}: termination exit before incoming receive");
    expect_status(
        client.exchange(&CommandBuilder::process_with_data(
            0x20,
            &[0xAA, 0xBB, 0xCC],
        ))?,
        (0x91, 0x23),
        "termination exit before incoming receive",
    )?;
    eprintln!("{log_prefix}: reinstall termination_test");
    expect_status(
        client.exchange(&CommandBuilder::install(aid))?,
        (0x90, 0x00),
        "reinstall termination_test",
    )?;
    eprintln!("{log_prefix}: reselect termination_test");
    expect_status(
        client.exchange(&CommandBuilder::select(aid))?,
        (0x90, 0x00),
        "reselect termination_test",
    )?;
    eprintln!("{log_prefix}: termination panic before incoming receive");
    expect_status(
        client.exchange(&CommandBuilder::process_with_data(
            0x22,
            &[0x11, 0x22, 0x33],
        ))?,
        (0x6F, 0x00),
        "termination panic before incoming receive",
    )?;
    eprintln!("{log_prefix}: reinstall termination_test after panic");
    expect_status(
        client.exchange(&CommandBuilder::install(aid))?,
        (0x90, 0x00),
        "reinstall termination_test after panic",
    )?;
    eprintln!("{log_prefix}: reselect termination_test after panic");
    expect_status(
        client.exchange(&CommandBuilder::select(aid))?,
        (0x90, 0x00),
        "reselect termination_test after panic",
    )?;
    eprintln!("{log_prefix}: termination normal return after panic");
    expect_status(
        client.exchange(&CommandBuilder::process_no_data(0x24))?,
        (0x90, 0x00),
        "termination normal return after panic",
    )
}

fn run_watchdog_fault_sequence(
    client: &mut ApduClient,
    log_prefix: &str,
) -> Result<Duration, Box<dyn Error>> {
    let aid = crate_rustlet_termination_test_aid();
    eprintln!("{log_prefix}: termination watchdog timeout");
    let started = Instant::now();
    expect_status(
        client.exchange(&CommandBuilder::process_no_data(0x26))?,
        (0x6F, 0x00),
        "termination watchdog timeout",
    )?;
    let watchdog_elapsed = started.elapsed();
    eprintln!("{log_prefix}: reinstall termination_test after watchdog");
    expect_status(
        client.exchange(&CommandBuilder::install(aid))?,
        (0x90, 0x00),
        "reinstall termination_test after watchdog",
    )?;
    expect_status(
        client.exchange(&CommandBuilder::select(aid))?,
        (0x90, 0x00),
        "reselect termination_test after watchdog",
    )?;
    expect_status(
        client.exchange(&CommandBuilder::process_no_data(0x24))?,
        (0x90, 0x00),
        "termination liveness after watchdog",
    )?;
    Ok(watchdog_elapsed)
}

/// Runs the focused non-returning Rustlet watchdog regression.
///
/// The command deliberately spins forever. Success requires a watchdog fault
/// near the configured ten-second deadline, status `6F00`, and a subsequent
/// successful Rustlet invocation proving that the kernel remained live.
pub(crate) fn run_rustlet_watchdog_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    testing::target::run_apdu(
        ctx,
        board,
        LayoutImageFormat::Elf,
        "rustlet-watchdog",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let aid = crate_rustlet_termination_test_aid();
            eprintln!("rustlet-watchdog: install termination_test");
            expect_status(
                client.exchange(&CommandBuilder::install(aid))?,
                (0x90, 0x00),
                "install termination_test for watchdog",
            )?;
            eprintln!("rustlet-watchdog: select termination_test");
            expect_status(
                client.exchange(&CommandBuilder::select(aid))?,
                (0x90, 0x00),
                "select termination_test for watchdog",
            )?;

            let elapsed = run_watchdog_fault_sequence(client, "rustlet-watchdog")?;
            if elapsed < Duration::from_secs(9) || elapsed > Duration::from_secs(15) {
                return Err(format!(
                    "Rustlet watchdog completed after {:.3}s instead of approximately 10s",
                    elapsed.as_secs_f64()
                )
                .into());
            }
            eprintln!(
                "rustlet-watchdog: timeout and recovery validated after {:.3}s",
                elapsed.as_secs_f64()
            );
            Ok(())
        },
    )?;
    Ok(TestReport::passed(6))
}

pub(crate) fn run_isolation_fault_sequence(
    client: &mut ApduClient,
    log_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    let aid = crate_rustlet_isolation_fault_test_aid();
    eprintln!("{log_prefix}: install isolation_fault_test");
    expect_status(
        client.exchange(&CommandBuilder::install(aid))?,
        (0x90, 0x00),
        "install isolation_fault_test",
    )?;
    eprintln!("{log_prefix}: select isolation_fault_test");
    expect_status(
        client.exchange(&CommandBuilder::select(aid))?,
        (0x90, 0x00),
        "select isolation_fault_test",
    )?;
    eprintln!("{log_prefix}: isolation_fault_test read violation");
    expect_status(
        client.exchange(&CommandBuilder::process_no_data(0x50))?,
        (0x6F, 0x00),
        "isolation_fault_test read violation",
    )?;
    eprintln!("{log_prefix}: reinstall isolation_fault_test");
    expect_status(
        client.exchange(&CommandBuilder::install(aid))?,
        (0x90, 0x00),
        "reinstall isolation_fault_test",
    )?;
    eprintln!("{log_prefix}: reselect isolation_fault_test");
    expect_status(
        client.exchange(&CommandBuilder::select(aid))?,
        (0x90, 0x00),
        "reselect isolation_fault_test",
    )?;
    eprintln!("{log_prefix}: isolation_fault_test write violation");
    expect_status(
        client.exchange(&CommandBuilder::process_no_data(0x51))?,
        (0x6F, 0x00),
        "isolation_fault_test write violation",
    )?;
    eprintln!("{log_prefix}: reinstall isolation_fault_test after invalid memory write");
    expect_status(
        client.exchange(&CommandBuilder::install(aid))?,
        (0x90, 0x00),
        "reinstall isolation_fault_test after invalid memory write",
    )?;
    eprintln!("{log_prefix}: reselect isolation_fault_test after invalid memory write");
    expect_status(
        client.exchange(&CommandBuilder::select(aid))?,
        (0x90, 0x00),
        "reselect isolation_fault_test after invalid memory write",
    )?;
    eprintln!("{log_prefix}: isolation_fault_test invalid instruction");
    expect_status(
        client.exchange(&CommandBuilder::process_no_data(0x52))?,
        (0x6F, 0x00),
        "isolation_fault_test invalid instruction",
    )?;
    eprintln!("{log_prefix}: reinstall isolation_fault_test after invalid instruction");
    expect_status(
        client.exchange(&CommandBuilder::install(aid))?,
        (0x90, 0x00),
        "reinstall isolation_fault_test after invalid instruction",
    )?;
    eprintln!("{log_prefix}: reselect isolation_fault_test after invalid instruction");
    expect_status(
        client.exchange(&CommandBuilder::select(aid))?,
        (0x90, 0x00),
        "reselect isolation_fault_test after invalid instruction",
    )
}

pub(crate) fn run_minimal_valid_liveness_after_faults(
    client: &mut ApduClient,
    log_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    eprintln!("{log_prefix}: liveness reinstall minimal");
    expect_status(
        client.exchange(&CommandBuilder::install(
            crate_rustlet_minimal_valid_test_aid(),
        ))?,
        (0x90, 0x00),
        "reinstall rustlet_minimal_valid_test after faults",
    )?;
    eprintln!("{log_prefix}: liveness reselect minimal");
    expect_status(
        client.exchange(&CommandBuilder::select(
            crate_rustlet_minimal_valid_test_aid(),
        ))?,
        (0x90, 0x00),
        "reselect rustlet_minimal_valid_test after faults",
    )?;
    eprintln!("{log_prefix}: liveness process minimal");
    expect_response(
        client.exchange(&CommandBuilder::process_no_data(0x00))?,
        &[],
        (0x90, 0x00),
        "rustlet_minimal_valid_test still alive",
    )
}

/// Runs one canonical Rustlet scenario on one target board.
///
/// The generated predeployment manifest embeds only the requested package.
/// This is the fastest way to debug one Rustlet scenario in either native ELF
/// or bootable FAE mode.
pub(crate) fn run_rustlet_single_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
    rustlet: &str,
    check_stack: bool,
) -> Result<TestReport, Box<dyn Error>> {
    testing::with_stack_observer(
        ctx,
        check_stack,
        StackBaselineKey::new("rustlet", board, image_format, Some(rustlet)),
        true,
        |ctx| {
            let board = board_spec(board)?;
            let spec = single_rustlet_spec(rustlet)?;
            testing::target::run_apdu(
                ctx,
                board,
                image_format,
                "rustlet-single",
                APDU_RESPONSE_TIMEOUT,
                |client| run_single_rustlet_case(client, spec),
            )?;
            Ok(TestReport::passed(spec.total))
        },
    )
}

/// Runs the multi-Rustlet isolation and post-fault liveness campaign.
///
/// This is intentionally separate from `test rustlet`: it installs
/// several Rustlets in one boot, triggers exit/panic/memory faults, then proves
/// that an unrelated minimal Rustlet can still be installed, selected, and
/// executed afterwards.
pub(crate) fn run_rustlet_isolation_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    let test_result = testing::target::run_apdu(
        ctx,
        board,
        LayoutImageFormat::Elf,
        "rustlet-isolation",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            run_minimal_valid_install_select_and_process(client, "rustlet-isolation")?;
            run_termination_fault_sequence(client, "rustlet-isolation")?;
            let _ = run_watchdog_fault_sequence(client, "rustlet-isolation")?;
            run_isolation_fault_sequence(client, "rustlet-isolation")?;
            run_minimal_valid_liveness_after_faults(client, "rustlet-isolation")?;

            Ok(())
        },
    );
    test_result?;

    Ok(TestReport::passed(21))
}

/// Builds the compile-time Rustlet declaration macro fixture crate.
///
/// This is a host-side regression for the supported `declare_app!` forms; it
/// catches macro API breakage without starting QEMU or loading a Rustlet.
pub(crate) fn run_rustlet_macro_build_tests_with_context(
    ctx: &TestContext,
) -> Result<TestReport, Box<dyn Error>> {
    let repo_root = repo_root()?;
    let tool_manifest = repo_root.join("tooling/build-fae/Cargo.toml");
    let board = board_spec(DEFAULT_BOARD)?;

    let test_cases = [
        (
            "rustlets/tests/declare_macro_forms",
            "implicit_default_rustlet",
        ),
        (
            "rustlets/tests/declare_macro_forms",
            "implicit_heap_rustlet",
        ),
        (
            "rustlets/tests/declare_macro_forms",
            "explicit_custom_install_rustlet",
        ),
    ];

    for (crate_dir, bin_name) in test_cases {
        build_embedded_app(
            &ctx.build,
            &tool_manifest,
            crate_dir,
            bin_name,
            RustletFaeAbi::Application,
            board,
            "qemu",
        )?;
    }

    Ok(TestReport::passed(test_cases.len()))
}
