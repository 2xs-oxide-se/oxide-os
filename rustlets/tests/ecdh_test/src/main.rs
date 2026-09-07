#![no_std]
#![no_main]

use rustlet_runtime::{
    Apdu, ApduStatus, EcCurve, EcKeyPair, KeyAgreement, Rustlet, RustletCtx, declare_app,
};

const INS_P256_ECDH: u8 = 0x40;
const INS_P256_ECDH_HKDF: u8 = 0x42;
const INS_SCP11C_STEP1: u8 = 0x44;
const P256_PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
const P256_SHARED_SECRET_SIZE: usize = 32;
const HKDF_OUTPUT_SIZE: usize = 32;
const OXIDE_SE_HKDF_SALT: &[u8] = b"oxide-se-ecdh-test-salt";
const OXIDE_SE_HKDF_INFO: &[u8] = b"oxide-se-ecdh-test-info";
const OXIDE_SE_SCP11C_SALT: &[u8] = b"oxide-se-scp11c-session-salt";
const OXIDE_SE_SCP11C_INFO_PREFIX: &[u8] = b"oxide-se-scp11c-session";
const SCP11C_S_ENC_SIZE: usize = 16;
const SCP11C_S_MAC_SIZE: usize = 16;
const SCP11C_S_RMAC_SIZE: usize = 16;
const SCP11C_SESSION_MATERIAL_SIZE: usize =
    SCP11C_S_ENC_SIZE + SCP11C_S_MAC_SIZE + SCP11C_S_RMAC_SIZE;

declare_app!(EcdhTestRustlet);

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct EcdhTestRustlet;

fn derive_scp11c_session_material(
    agreement: &mut KeyAgreement<'_, rustlet_runtime::Ready>,
    peer_public: &[u8],
    card_public: &[u8],
    out: &mut [u8; SCP11C_SESSION_MATERIAL_SIZE],
) -> Result<(), ()> {
    let mut info = [0u8; OXIDE_SE_SCP11C_INFO_PREFIX.len() + 2 * P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
    let prefix_len = OXIDE_SE_SCP11C_INFO_PREFIX.len();
    info[..prefix_len].copy_from_slice(OXIDE_SE_SCP11C_INFO_PREFIX);
    info[prefix_len..prefix_len + P256_PUBLIC_KEY_UNCOMPRESSED_SIZE].copy_from_slice(peer_public);
    info[prefix_len + P256_PUBLIC_KEY_UNCOMPRESSED_SIZE..].copy_from_slice(card_public);
    agreement
        .derive_hkdf_sha256(peer_public, OXIDE_SE_SCP11C_SALT, &info, out)
        .map(|_| ())
        .map_err(|_| ())
}

impl Rustlet for EcdhTestRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let mut crypto = ctx.crypto();
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            INS_P256_ECDH => {
                let rx = apdu.as_receiving();
                let peer_public = rx.data();
                if peer_public.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE {
                    return rx.reject(ApduStatus::wrong_length());
                }

                let keypair = match EcKeyPair::generate(&mut crypto, EcCurve::P256) {
                    Ok(keypair) => keypair,
                    Err(_) => return rx.reject(ApduStatus::internal_error()),
                };
                let mut agreement =
                    match KeyAgreement::new(&mut crypto).init(&keypair.private_key()) {
                        Ok(agreement) => agreement,
                        Err(_) => return rx.reject(ApduStatus::internal_error()),
                    };
                let mut response =
                    [0u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE + P256_SHARED_SECRET_SIZE];
                response[..P256_PUBLIC_KEY_UNCOMPRESSED_SIZE]
                    .copy_from_slice(keypair.public_key().as_bytes());
                if agreement
                    .generate_secret(
                        peer_public,
                        &mut response[P256_PUBLIC_KEY_UNCOMPRESSED_SIZE..],
                    )
                    .is_err()
                {
                    return rx.reject(ApduStatus::internal_error());
                }
                rx.accept_and_send(&response)
            }
            INS_P256_ECDH_HKDF => {
                let rx = apdu.as_receiving();
                let peer_public = rx.data();
                if peer_public.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE {
                    return rx.reject(ApduStatus::wrong_length());
                }

                let keypair = match EcKeyPair::generate(&mut crypto, EcCurve::P256) {
                    Ok(keypair) => keypair,
                    Err(_) => return rx.reject(ApduStatus::internal_error()),
                };
                let mut agreement =
                    match KeyAgreement::new(&mut crypto).init(&keypair.private_key()) {
                        Ok(agreement) => agreement,
                        Err(_) => return rx.reject(ApduStatus::internal_error()),
                    };
                let mut response = [0u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE + HKDF_OUTPUT_SIZE];
                response[..P256_PUBLIC_KEY_UNCOMPRESSED_SIZE]
                    .copy_from_slice(keypair.public_key().as_bytes());
                if agreement
                    .derive_hkdf_sha256(
                        peer_public,
                        OXIDE_SE_HKDF_SALT,
                        OXIDE_SE_HKDF_INFO,
                        &mut response[P256_PUBLIC_KEY_UNCOMPRESSED_SIZE..],
                    )
                    .is_err()
                {
                    return rx.reject(ApduStatus::internal_error());
                }
                rx.accept_and_send(&response)
            }
            INS_SCP11C_STEP1 => {
                let rx = apdu.as_receiving();
                let peer_public = rx.data();
                if peer_public.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE {
                    return rx.reject(ApduStatus::wrong_length());
                }

                let keypair = match EcKeyPair::generate(&mut crypto, EcCurve::P256) {
                    Ok(keypair) => keypair,
                    Err(_) => return rx.reject(ApduStatus::internal_error()),
                };
                let mut agreement =
                    match KeyAgreement::new(&mut crypto).init(&keypair.private_key()) {
                        Ok(agreement) => agreement,
                        Err(_) => return rx.reject(ApduStatus::internal_error()),
                    };
                let mut response =
                    [0u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE + SCP11C_SESSION_MATERIAL_SIZE];
                response[..P256_PUBLIC_KEY_UNCOMPRESSED_SIZE]
                    .copy_from_slice(keypair.public_key().as_bytes());
                let session_material = &mut response[P256_PUBLIC_KEY_UNCOMPRESSED_SIZE..];
                let session_material =
                    <&mut [u8; SCP11C_SESSION_MATERIAL_SIZE]>::try_from(session_material)
                        .map_err(|_| ())
                        .and_then(|session_material| {
                            derive_scp11c_session_material(
                                &mut agreement,
                                peer_public,
                                keypair.public_key().as_bytes(),
                                session_material,
                            )
                        });
                if session_material.is_err() {
                    return rx.reject(ApduStatus::internal_error());
                }
                rx.accept_and_send(&response)
            }
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}
