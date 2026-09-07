use ::core::fmt;
use ::core::sync::atomic::{AtomicBool, Ordering};

pub const AES_BLOCK_SIZE: usize = 16;
pub const AES_CMAC_SIZE: usize = 16;
pub const AES128_KEY_SIZE: usize = 16;
pub const AES192_KEY_SIZE: usize = 24;
pub const AES256_KEY_SIZE: usize = 32;
pub const P256_PRIVATE_KEY_SIZE: usize = 32;
pub const P256_PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
pub const P256_SHARED_SECRET_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidBufferLength,
    InvalidOutputLength,
    Unsupported,
    EntropyUnavailable,
}

pub type CryptoResult<T> = Result<T, CryptoError>;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcCurve {
    P256 = 1,
}

#[cfg_attr(test, allow(dead_code))]
static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub struct AesKey {
    #[allow(dead_code)]
    bytes: [u8; AES256_KEY_SIZE],
    len: u8,
}

impl AesKey {
    pub fn from_bytes(key_bytes: &[u8]) -> CryptoResult<Self> {
        match key_bytes.len() {
            AES128_KEY_SIZE | AES192_KEY_SIZE | AES256_KEY_SIZE => {}
            _ => return Err(CryptoError::InvalidKeyLength),
        }

        let mut bytes = [0u8; AES256_KEY_SIZE];
        bytes[..key_bytes.len()].copy_from_slice(key_bytes);

        Ok(Self {
            bytes,
            len: key_bytes.len() as u8,
        })
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        false
    }

    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }
}

impl fmt::Debug for AesKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesKey")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn initialize() {
    if INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    INITIALIZED.store(true, Ordering::Release);
    crate::core::target::crypto_initialize();
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn fill_random(buf: &mut [u8]) -> CryptoResult<()> {
    match crate::core::target::crypto_fill_random(buf) {
        Err(CryptoError::Unsupported) => soft::fill_random(buf),
        result => result,
    }
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn aes_cbc_encrypt_in_place(
    key: &AesKey,
    iv: &[u8; AES_BLOCK_SIZE],
    buf: &mut [u8],
) -> CryptoResult<()> {
    validate_block_aligned(buf)?;
    match crate::core::target::crypto_aes_cbc_encrypt_in_place(key, iv, buf) {
        Err(CryptoError::Unsupported) => soft::aes_cbc_encrypt_in_place(key, iv, buf),
        result => result,
    }
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn aes_cbc_decrypt_in_place(
    key: &AesKey,
    iv: &[u8; AES_BLOCK_SIZE],
    buf: &mut [u8],
) -> CryptoResult<()> {
    validate_block_aligned(buf)?;
    match crate::core::target::crypto_aes_cbc_decrypt_in_place(key, iv, buf) {
        Err(CryptoError::Unsupported) => soft::aes_cbc_decrypt_in_place(key, iv, buf),
        result => result,
    }
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn aes_ecb_encrypt_in_place(key: &AesKey, buf: &mut [u8]) -> CryptoResult<()> {
    validate_block_aligned(buf)?;
    soft::aes_ecb_encrypt_in_place(key, buf)
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn aes_ecb_decrypt_in_place(key: &AesKey, buf: &mut [u8]) -> CryptoResult<()> {
    validate_block_aligned(buf)?;
    soft::aes_ecb_decrypt_in_place(key, buf)
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn aes_cbc_encrypt_iso9797_m2(
    key: &AesKey,
    iv: &[u8; AES_BLOCK_SIZE],
    input: &[u8],
    out: &mut [u8],
) -> CryptoResult<usize> {
    soft::aes_cbc_encrypt_iso9797_m2(key, iv, input, out)
}

/// Pads and encrypts the first `plaintext_len` bytes of `buf` in place.
///
/// The caller must provide enough tail capacity for the ISO9797-M2 marker and
/// AES block rounding. No second plaintext or ciphertext buffer is allocated.
#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn aes_cbc_encrypt_iso9797_m2_in_place(
    key: &AesKey,
    iv: &[u8; AES_BLOCK_SIZE],
    buf: &mut [u8],
    plaintext_len: usize,
) -> CryptoResult<usize> {
    soft::aes_cbc_encrypt_iso9797_m2_in_place(key, iv, buf, plaintext_len)
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn aes_cbc_decrypt_iso9797_m2(
    key: &AesKey,
    iv: &[u8; AES_BLOCK_SIZE],
    input: &[u8],
    out: &mut [u8],
) -> CryptoResult<usize> {
    soft::aes_cbc_decrypt_iso9797_m2(key, iv, input, out)
}

/// Decrypts and removes ISO9797-M2 padding from `buf` in place.
///
/// The returned length identifies the plaintext prefix. Bytes after that
/// prefix remain transient workspace and must not be exposed as APDU data.
#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn aes_cbc_decrypt_iso9797_m2_in_place(
    key: &AesKey,
    iv: &[u8; AES_BLOCK_SIZE],
    buf: &mut [u8],
) -> CryptoResult<usize> {
    soft::aes_cbc_decrypt_iso9797_m2_in_place(key, iv, buf)
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn aes_cmac(key: &AesKey, input: &[u8], out: &mut [u8; AES_CMAC_SIZE]) -> CryptoResult<()> {
    match crate::core::target::crypto_aes_cmac(key, input, out) {
        Err(CryptoError::Unsupported) => soft::aes_cmac(key, input, out),
        result => result,
    }
}

/// Computes one AES-CMAC over a sequence of disjoint byte slices.
///
/// This is the zero-copy form used by secure messaging for inputs such as
/// `chain || APDU header || protected data`. The slices are consumed in order and
/// are never concatenated into an APDU-sized temporary buffer.
#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn aes_cmac_parts(
    key: &AesKey,
    parts: &[&[u8]],
    out: &mut [u8; AES_CMAC_SIZE],
) -> CryptoResult<()> {
    if parts.len() == 1 {
        return aes_cmac(key, parts[0], out);
    }
    soft::aes_cmac_parts(key, parts, out)
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn scp03_kdf(
    key: &AesKey,
    derivation_constant: u8,
    context: &[u8],
    out: &mut [u8],
) -> CryptoResult<()> {
    validate_scp03_output_length(out.len())?;

    match crate::core::target::crypto_scp03_kdf(key, derivation_constant, context, out) {
        Err(CryptoError::Unsupported) => soft::scp03_kdf(key, derivation_constant, context, out),
        result => result,
    }
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn p256_generate_keypair(private_out: &mut [u8], public_out: &mut [u8]) -> CryptoResult<()> {
    if private_out.len() != P256_PRIVATE_KEY_SIZE {
        return Err(CryptoError::InvalidOutputLength);
    }
    if public_out.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE {
        return Err(CryptoError::InvalidOutputLength);
    }

    match crate::core::target::crypto_p256_generate_keypair(private_out, public_out) {
        Err(CryptoError::Unsupported) => soft::p256_generate_keypair(private_out, public_out),
        result => result,
    }
}

/// Derives an uncompressed SEC1 public key from one P-256 private scalar.
pub fn p256_public_from_private(private_key: &[u8], public_out: &mut [u8]) -> CryptoResult<()> {
    if private_key.len() != P256_PRIVATE_KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength);
    }
    if public_out.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE {
        return Err(CryptoError::InvalidOutputLength);
    }
    soft::p256_public_from_private(private_key, public_out)
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn p256_ecdh(private_key: &[u8], peer_public: &[u8], out: &mut [u8]) -> CryptoResult<()> {
    if private_key.len() != P256_PRIVATE_KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength);
    }
    if out.len() != P256_SHARED_SECRET_SIZE {
        return Err(CryptoError::InvalidOutputLength);
    }

    match crate::core::target::crypto_p256_ecdh(private_key, peer_public, out) {
        Err(CryptoError::Unsupported) => soft::p256_ecdh(private_key, peer_public, out),
        result => result,
    }
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> CryptoResult<()> {
    if out.is_empty() {
        return Err(CryptoError::InvalidOutputLength);
    }

    soft::hkdf_sha256(ikm, salt, info, out)
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
#[inline(never)]
pub fn x963_sha256_kdf(
    shared_secret: &[u8],
    shared_info: &[u8],
    out: &mut [u8],
) -> CryptoResult<()> {
    if out.is_empty() {
        return Err(CryptoError::InvalidOutputLength);
    }

    soft::x963_sha256_kdf(shared_secret, shared_info, out)
}

fn validate_block_aligned(buf: &[u8]) -> CryptoResult<()> {
    if !buf.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(CryptoError::InvalidBufferLength);
    }

    Ok(())
}

fn validate_scp03_output_length(len: usize) -> CryptoResult<()> {
    match len {
        8 | 16 | 24 | 32 => Ok(()),
        _ => Err(CryptoError::InvalidOutputLength),
    }
}

mod soft {
    use super::{
        AesKey, CryptoError, CryptoResult, AES_BLOCK_SIZE, AES_CMAC_SIZE, P256_PRIVATE_KEY_SIZE,
        P256_PUBLIC_KEY_UNCOMPRESSED_SIZE, P256_SHARED_SECRET_SIZE,
    };
    use aes::{Aes128, Aes192, Aes256};
    use cmac::{Cmac, Mac};
    use hkdf::Hkdf;
    use p256::ecdh::diffie_hellman;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::{PublicKey, SecretKey};
    use sha2::{Digest, Sha256};

    pub fn fill_random(_buf: &mut [u8]) -> CryptoResult<()> {
        Err(CryptoError::EntropyUnavailable)
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn p256_generate_keypair(
        private_out: &mut [u8],
        public_out: &mut [u8],
    ) -> CryptoResult<()> {
        if private_out.len() != P256_PRIVATE_KEY_SIZE {
            return Err(CryptoError::InvalidOutputLength);
        }
        if public_out.len() != P256_PUBLIC_KEY_UNCOMPRESSED_SIZE {
            return Err(CryptoError::InvalidOutputLength);
        }

        let mut candidate = [0u8; P256_PRIVATE_KEY_SIZE];
        let secret = loop {
            super::fill_random(&mut candidate)?;
            if let Ok(secret) = SecretKey::from_slice(&candidate) {
                break secret;
            }
        };
        let public = secret.public_key();
        private_out.copy_from_slice(&candidate);
        public_out.copy_from_slice(public.to_encoded_point(false).as_bytes());
        Ok(())
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn p256_ecdh(private_key: &[u8], peer_public: &[u8], out: &mut [u8]) -> CryptoResult<()> {
        if private_key.len() != P256_PRIVATE_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength);
        }
        if out.len() != P256_SHARED_SECRET_SIZE {
            return Err(CryptoError::InvalidOutputLength);
        }
        let secret =
            SecretKey::from_slice(private_key).map_err(|_| CryptoError::InvalidKeyLength)?;
        let peer = PublicKey::from_sec1_bytes(peer_public)
            .map_err(|_| CryptoError::InvalidBufferLength)?;
        let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        out.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Ok(())
    }

    pub fn p256_public_from_private(private_key: &[u8], public_out: &mut [u8]) -> CryptoResult<()> {
        let secret =
            SecretKey::from_slice(private_key).map_err(|_| CryptoError::InvalidKeyLength)?;
        let public = secret.public_key();
        public_out.copy_from_slice(public.to_encoded_point(false).as_bytes());
        Ok(())
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> CryptoResult<()> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
        hkdf.expand(info, out)
            .map_err(|_| CryptoError::InvalidOutputLength)
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn x963_sha256_kdf(
        shared_secret: &[u8],
        shared_info: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()> {
        let mut counter = 1u32;
        let mut offset = 0;
        while offset < out.len() {
            let mut hasher = Sha256::new();
            hasher.update(shared_secret);
            hasher.update(counter.to_be_bytes());
            hasher.update(shared_info);
            let block = hasher.finalize();
            let take_len = core::cmp::min(block.len(), out.len() - offset);
            out[offset..offset + take_len].copy_from_slice(&block[..take_len]);
            offset += take_len;
            counter = counter
                .checked_add(1)
                .ok_or(CryptoError::InvalidOutputLength)?;
        }
        Ok(())
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn aes_cbc_encrypt_in_place(
        key: &AesKey,
        iv: &[u8; AES_BLOCK_SIZE],
        buf: &mut [u8],
    ) -> CryptoResult<()> {
        match key.len() {
            super::AES128_KEY_SIZE => {
                encrypt_with::<Aes128>(key, iv, buf)?;
                Ok(())
            }
            super::AES192_KEY_SIZE => {
                encrypt_with::<Aes192>(key, iv, buf)?;
                Ok(())
            }
            super::AES256_KEY_SIZE => {
                encrypt_with::<Aes256>(key, iv, buf)?;
                Ok(())
            }
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn aes_cbc_decrypt_in_place(
        key: &AesKey,
        iv: &[u8; AES_BLOCK_SIZE],
        buf: &mut [u8],
    ) -> CryptoResult<()> {
        match key.len() {
            super::AES128_KEY_SIZE => {
                decrypt_with::<Aes128>(key, iv, buf)?;
                Ok(())
            }
            super::AES192_KEY_SIZE => {
                decrypt_with::<Aes192>(key, iv, buf)?;
                Ok(())
            }
            super::AES256_KEY_SIZE => {
                decrypt_with::<Aes256>(key, iv, buf)?;
                Ok(())
            }
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn aes_ecb_encrypt_in_place(key: &AesKey, buf: &mut [u8]) -> CryptoResult<()> {
        match key.len() {
            super::AES128_KEY_SIZE => {
                ecb_encrypt_with::<Aes128>(key, buf)?;
                Ok(())
            }
            super::AES256_KEY_SIZE => {
                ecb_encrypt_with::<Aes256>(key, buf)?;
                Ok(())
            }
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn aes_ecb_decrypt_in_place(key: &AesKey, buf: &mut [u8]) -> CryptoResult<()> {
        match key.len() {
            super::AES128_KEY_SIZE => {
                ecb_decrypt_with::<Aes128>(key, buf)?;
                Ok(())
            }
            super::AES256_KEY_SIZE => {
                ecb_decrypt_with::<Aes256>(key, buf)?;
                Ok(())
            }
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn aes_cbc_encrypt_iso9797_m2(
        key: &AesKey,
        iv: &[u8; AES_BLOCK_SIZE],
        input: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize> {
        if input.len() > out.len() {
            return Err(CryptoError::InvalidOutputLength);
        }
        out[..input.len()].copy_from_slice(input);
        match key.len() {
            super::AES128_KEY_SIZE => encrypt_padded_with::<Aes128>(key, iv, input.len(), out),
            super::AES192_KEY_SIZE => encrypt_padded_with::<Aes192>(key, iv, input.len(), out),
            super::AES256_KEY_SIZE => encrypt_padded_with::<Aes256>(key, iv, input.len(), out),
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn aes_cbc_encrypt_iso9797_m2_in_place(
        key: &AesKey,
        iv: &[u8; AES_BLOCK_SIZE],
        buf: &mut [u8],
        plaintext_len: usize,
    ) -> CryptoResult<usize> {
        if plaintext_len > buf.len() {
            return Err(CryptoError::InvalidOutputLength);
        }
        match key.len() {
            super::AES128_KEY_SIZE => encrypt_padded_with::<Aes128>(key, iv, plaintext_len, buf),
            super::AES192_KEY_SIZE => encrypt_padded_with::<Aes192>(key, iv, plaintext_len, buf),
            super::AES256_KEY_SIZE => encrypt_padded_with::<Aes256>(key, iv, plaintext_len, buf),
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn aes_cbc_decrypt_iso9797_m2(
        key: &AesKey,
        iv: &[u8; AES_BLOCK_SIZE],
        input: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<usize> {
        if input.len() > out.len() {
            return Err(CryptoError::InvalidOutputLength);
        }
        out[..input.len()].copy_from_slice(input);
        match key.len() {
            super::AES128_KEY_SIZE => decrypt_padded_with::<Aes128>(key, iv, input.len(), out),
            super::AES192_KEY_SIZE => decrypt_padded_with::<Aes192>(key, iv, input.len(), out),
            super::AES256_KEY_SIZE => decrypt_padded_with::<Aes256>(key, iv, input.len(), out),
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn aes_cbc_decrypt_iso9797_m2_in_place(
        key: &AesKey,
        iv: &[u8; AES_BLOCK_SIZE],
        buf: &mut [u8],
    ) -> CryptoResult<usize> {
        match key.len() {
            super::AES128_KEY_SIZE => decrypt_padded_with::<Aes128>(key, iv, buf.len(), buf),
            super::AES192_KEY_SIZE => decrypt_padded_with::<Aes192>(key, iv, buf.len(), buf),
            super::AES256_KEY_SIZE => decrypt_padded_with::<Aes256>(key, iv, buf.len(), buf),
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn aes_cmac(key: &AesKey, input: &[u8], out: &mut [u8; AES_CMAC_SIZE]) -> CryptoResult<()> {
        match key.len() {
            super::AES128_KEY_SIZE => {
                let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key.as_bytes())
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                mac.update(input);
                let tag = mac.finalize().into_bytes();
                out.copy_from_slice(&tag);
                Ok(())
            }
            super::AES192_KEY_SIZE => {
                let mut mac = <Cmac<Aes192> as Mac>::new_from_slice(key.as_bytes())
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                mac.update(input);
                let tag = mac.finalize().into_bytes();
                out.copy_from_slice(&tag);
                Ok(())
            }
            super::AES256_KEY_SIZE => {
                let mut mac = <Cmac<Aes256> as Mac>::new_from_slice(key.as_bytes())
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                mac.update(input);
                let tag = mac.finalize().into_bytes();
                out.copy_from_slice(&tag);
                Ok(())
            }
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn aes_cmac_parts(
        key: &AesKey,
        parts: &[&[u8]],
        out: &mut [u8; AES_CMAC_SIZE],
    ) -> CryptoResult<()> {
        macro_rules! compute {
            ($cipher:ty) => {{
                let mut mac = <Cmac<$cipher> as Mac>::new_from_slice(key.as_bytes())
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                for part in parts {
                    mac.update(part);
                }
                let tag = mac.finalize().into_bytes();
                out.copy_from_slice(&tag);
                Ok(())
            }};
        }

        match key.len() {
            super::AES128_KEY_SIZE => compute!(Aes128),
            super::AES192_KEY_SIZE => compute!(Aes192),
            super::AES256_KEY_SIZE => compute!(Aes256),
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    #[cfg_attr(
        all(not(test), oxide_se_board_raspi_pico),
        unsafe(link_section = ".critical.kernel.fct")
    )]
    #[inline(never)]
    pub fn scp03_kdf(
        key: &AesKey,
        derivation_constant: u8,
        context: &[u8],
        out: &mut [u8],
    ) -> CryptoResult<()> {
        super::validate_scp03_output_length(out.len())?;

        let output_len_bits = ((out.len() as u16) * 8).to_be_bytes();
        let mut generated = 0usize;
        let mut counter = 1u8;

        while generated < out.len() {
            let mut block = [0u8; AES_CMAC_SIZE];
            aes_cmac_scp03_input(
                key,
                derivation_constant,
                output_len_bits,
                counter,
                context,
                &mut block,
            )?;

            let chunk_len = usize::min(AES_CMAC_SIZE, out.len() - generated);
            out[generated..generated + chunk_len].copy_from_slice(&block[..chunk_len]);
            generated += chunk_len;
            counter = counter
                .checked_add(1)
                .ok_or(CryptoError::InvalidOutputLength)?;
        }

        Ok(())
    }

    fn aes_cmac_scp03_input(
        key: &AesKey,
        derivation_constant: u8,
        output_len_bits: [u8; 2],
        counter: u8,
        context: &[u8],
        out: &mut [u8; AES_CMAC_SIZE],
    ) -> CryptoResult<()> {
        match key.len() {
            super::AES128_KEY_SIZE => {
                let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key.as_bytes())
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                mac.update(&[0u8; 11]);
                mac.update(&[derivation_constant]);
                mac.update(&[0x00]);
                mac.update(&output_len_bits);
                mac.update(&[counter]);
                mac.update(context);
                let tag = mac.finalize().into_bytes();
                out.copy_from_slice(&tag);
                Ok(())
            }
            super::AES192_KEY_SIZE => {
                let mut mac = <Cmac<Aes192> as Mac>::new_from_slice(key.as_bytes())
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                mac.update(&[0u8; 11]);
                mac.update(&[derivation_constant]);
                mac.update(&[0x00]);
                mac.update(&output_len_bits);
                mac.update(&[counter]);
                mac.update(context);
                let tag = mac.finalize().into_bytes();
                out.copy_from_slice(&tag);
                Ok(())
            }
            super::AES256_KEY_SIZE => {
                let mut mac = <Cmac<Aes256> as Mac>::new_from_slice(key.as_bytes())
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                mac.update(&[0u8; 11]);
                mac.update(&[derivation_constant]);
                mac.update(&[0x00]);
                mac.update(&output_len_bits);
                mac.update(&[counter]);
                mac.update(context);
                let tag = mac.finalize().into_bytes();
                out.copy_from_slice(&tag);
                Ok(())
            }
            _ => Err(CryptoError::InvalidKeyLength),
        }
    }

    fn encrypt_with<C>(key: &AesKey, iv: &[u8; AES_BLOCK_SIZE], buf: &mut [u8]) -> CryptoResult<()>
    where
        C: aes::cipher::BlockCipher + aes::cipher::BlockEncrypt + aes::cipher::KeyInit,
    {
        if !buf.len().is_multiple_of(AES_BLOCK_SIZE) {
            return Err(CryptoError::InvalidBufferLength);
        }

        let cipher =
            C::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidKeyLength)?;
        let mut previous = *iv;
        for block in buf.chunks_exact_mut(AES_BLOCK_SIZE) {
            for (byte, prev) in block.iter_mut().zip(previous.iter()) {
                *byte ^= *prev;
            }
            cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
                block,
            ));
            previous.copy_from_slice(block);
        }
        Ok(())
    }

    fn decrypt_with<C>(key: &AesKey, iv: &[u8; AES_BLOCK_SIZE], buf: &mut [u8]) -> CryptoResult<()>
    where
        C: aes::cipher::BlockCipher + aes::cipher::BlockDecrypt + aes::cipher::KeyInit,
    {
        if !buf.len().is_multiple_of(AES_BLOCK_SIZE) {
            return Err(CryptoError::InvalidBufferLength);
        }

        let cipher =
            C::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidKeyLength)?;
        let mut previous = *iv;
        let mut current = [0u8; AES_BLOCK_SIZE];
        for block in buf.chunks_exact_mut(AES_BLOCK_SIZE) {
            current.copy_from_slice(block);
            cipher.decrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
                block,
            ));
            for (byte, prev) in block.iter_mut().zip(previous.iter()) {
                *byte ^= *prev;
            }
            previous.copy_from_slice(&current);
        }
        Ok(())
    }

    fn encrypt_padded_with<C>(
        key: &AesKey,
        iv: &[u8; AES_BLOCK_SIZE],
        len: usize,
        buf: &mut [u8],
    ) -> CryptoResult<usize>
    where
        C: aes::cipher::BlockCipher + aes::cipher::BlockEncrypt + aes::cipher::KeyInit,
    {
        let padded_len = ((len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        if padded_len > buf.len() {
            return Err(CryptoError::InvalidOutputLength);
        }

        buf[len] = 0x80;
        for byte in &mut buf[len + 1..padded_len] {
            *byte = 0;
        }
        encrypt_with::<C>(key, iv, &mut buf[..padded_len])?;
        Ok(padded_len)
    }

    fn ecb_encrypt_with<C>(key: &AesKey, buf: &mut [u8]) -> CryptoResult<()>
    where
        C: aes::cipher::BlockCipher + aes::cipher::BlockEncrypt + aes::cipher::KeyInit,
    {
        let cipher =
            C::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidKeyLength)?;
        for block in buf.chunks_exact_mut(AES_BLOCK_SIZE) {
            cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
                block,
            ));
        }
        Ok(())
    }

    fn ecb_decrypt_with<C>(key: &AesKey, buf: &mut [u8]) -> CryptoResult<()>
    where
        C: aes::cipher::BlockCipher + aes::cipher::BlockDecrypt + aes::cipher::KeyInit,
    {
        let cipher =
            C::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidKeyLength)?;
        for block in buf.chunks_exact_mut(AES_BLOCK_SIZE) {
            cipher.decrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(
                block,
            ));
        }
        Ok(())
    }

    fn decrypt_padded_with<C>(
        key: &AesKey,
        iv: &[u8; AES_BLOCK_SIZE],
        len: usize,
        buf: &mut [u8],
    ) -> CryptoResult<usize>
    where
        C: aes::cipher::BlockCipher + aes::cipher::BlockDecrypt + aes::cipher::KeyInit,
    {
        if len == 0 || !len.is_multiple_of(AES_BLOCK_SIZE) {
            return Err(CryptoError::InvalidBufferLength);
        }

        decrypt_with::<C>(key, iv, &mut buf[..len])?;
        let Some(padding_start) = buf[..len].iter().rposition(|byte| *byte == 0x80) else {
            return Err(CryptoError::InvalidBufferLength);
        };
        if buf[padding_start + 1..len].iter().any(|byte| *byte != 0) {
            return Err(CryptoError::InvalidBufferLength);
        }
        Ok(padding_start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(bytes: [u8; N]) -> [u8; N] {
        bytes
    }

    #[test]
    fn aes128_cbc_matches_nist_vector() {
        let key = AesKey::from_bytes(&hex([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]))
        .expect("AES-128 key");
        let iv = hex([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        let mut block = hex([
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ]);
        let expected = hex([
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d,
        ]);

        aes_cbc_encrypt_in_place(&key, &iv, &mut block).expect("encrypt");
        assert_eq!(block, expected);
        aes_cbc_decrypt_in_place(&key, &iv, &mut block).expect("decrypt");
        assert_eq!(
            block,
            hex([
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ])
        );
    }

    #[test]
    fn aes256_cbc_matches_nist_vector() {
        let key = AesKey::from_bytes(&hex([
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ]))
        .expect("AES-256 key");
        let iv = hex([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        let mut block = hex([
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ]);
        let expected = hex([
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b,
            0xfb, 0xd6,
        ]);

        aes_cbc_encrypt_in_place(&key, &iv, &mut block).expect("encrypt");
        assert_eq!(block, expected);
        aes_cbc_decrypt_in_place(&key, &iv, &mut block).expect("decrypt");
        assert_eq!(
            block,
            hex([
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ])
        );
    }

    #[test]
    fn aes_cbc_iso9797_m2_roundtrips_and_rejects_bad_padding() {
        let key = AesKey::from_bytes(&[0x11; AES256_KEY_SIZE]).expect("AES-256 key");
        let iv = [0x22; AES_BLOCK_SIZE];
        let input = b"kernel zero-copy crypto path";
        let mut encrypted = [0u8; 64];
        let encrypted_len =
            aes_cbc_encrypt_iso9797_m2(&key, &iv, input, &mut encrypted).expect("encrypt");
        assert_eq!(encrypted_len % AES_BLOCK_SIZE, 0);

        let mut decrypted = [0u8; 64];
        let decrypted_len =
            aes_cbc_decrypt_iso9797_m2(&key, &iv, &encrypted[..encrypted_len], &mut decrypted)
                .expect("decrypt");
        assert_eq!(&decrypted[..decrypted_len], input);

        encrypted[encrypted_len - 1] ^= 0x01;
        assert_eq!(
            aes_cbc_decrypt_iso9797_m2(&key, &iv, &encrypted[..encrypted_len], &mut decrypted),
            Err(CryptoError::InvalidBufferLength)
        );
    }

    #[test]
    fn aes_cbc_iso9797_m2_in_place_matches_copying_form() {
        let key = AesKey::from_bytes(&[0x44; AES128_KEY_SIZE]).expect("AES-128 key");
        let iv = [0x55; AES_BLOCK_SIZE];
        let input = b"in-place secure messaging";
        let mut copied = [0u8; 48];
        let mut in_place = [0u8; 48];
        in_place[..input.len()].copy_from_slice(input);

        let copied_len =
            aes_cbc_encrypt_iso9797_m2(&key, &iv, input, &mut copied).expect("copying encrypt");
        let in_place_len =
            aes_cbc_encrypt_iso9797_m2_in_place(&key, &iv, &mut in_place, input.len())
                .expect("in-place encrypt");
        assert_eq!(&in_place[..in_place_len], &copied[..copied_len]);

        let plaintext_len =
            aes_cbc_decrypt_iso9797_m2_in_place(&key, &iv, &mut in_place[..in_place_len])
                .expect("in-place decrypt");
        assert_eq!(&in_place[..plaintext_len], input);
    }

    #[test]
    fn aes_cmac_parts_matches_contiguous_input() {
        let key = AesKey::from_bytes(&[0x33; AES128_KEY_SIZE]).expect("AES-128 key");
        let input = b"chain-header-and-gp-do";
        let mut contiguous = [0u8; AES_CMAC_SIZE];
        let mut vectored = [0u8; AES_CMAC_SIZE];

        aes_cmac(&key, input, &mut contiguous).expect("contiguous CMAC");
        aes_cmac_parts(
            &key,
            &[&input[..5], &input[5..11], &input[11..]],
            &mut vectored,
        )
        .expect("vectored CMAC");

        assert_eq!(vectored, contiguous);
    }

    #[test]
    fn aes128_cmac_matches_nist_single_block_vector() {
        let key = AesKey::from_bytes(&hex([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]))
        .expect("AES-128 key");
        let input = hex([
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ]);
        let expected = hex([
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ]);
        let mut mac = [0u8; AES_CMAC_SIZE];

        aes_cmac(&key, &input, &mut mac).expect("AES-CMAC");
        assert_eq!(mac, expected);
    }
}
