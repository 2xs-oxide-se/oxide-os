use core::marker::PhantomData;

use crate::syscall_abi::{
    CryptoCipherDoFinalParams, CryptoEcGenerateKeypairParams, CryptoEcdhDoFinalParams,
    CryptoErrorCode, CryptoHkdfSha256Params, CryptoMacDoFinalParams, CryptoMacOperation,
    CryptoRandomGenerateParams, CryptoX963Sha256Params, CRYPTO_RESULT_ERROR_FLAG,
};

const AES_BLOCK_SIZE: usize = 16;
const AES128_KEY_SIZE: usize = 16;
const AES256_KEY_SIZE: usize = 32;
const MAC_TAG_SIZE: usize = 16;
const MAC_INPUT_CAPACITY: usize = 256;
const P256_PRIVATE_KEY_SIZE: usize = 32;
const P256_PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
const P256_SHARED_SECRET_SIZE: usize = 32;

/// Cipher object has not been configured yet.
pub struct Uninitialized;

/// Cipher object has a key, algorithm, and mode.
pub struct Ready;

/// Cipher object is in a streaming operation.
pub struct Processing;

/// Symmetric cipher direction.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherMode {
    Encrypt = 1,
    Decrypt = 2,
}

/// Symmetric cipher algorithm.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Aes128CbcNoPadding = 1,
    Aes256CbcNoPadding = 2,
    Aes128CbcIso9797M2 = 3,
    Aes256CbcIso9797M2 = 4,
    Aes128EcbNoPadding = 5,
    Aes256EcbNoPadding = 6,
}

/// Message authentication algorithm.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacAlgorithm {
    AesCmac = 1,
}

/// Random generator algorithm.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomAlgorithm {
    SecureRandom = 1,
}

/// Supported elliptic curves for Rustlet-facing asymmetric crypto.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcCurve {
    P256 = 1,
}

/// Error returned by Rustlet-facing crypto operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidBufferLength,
    InvalidOutputLength,
    Unsupported,
    PermissionDenied,
    NotInitialized,
    NotFound,
}

/// Fixed-size AES-CMAC authentication tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacTag(pub [u8; MAC_TAG_SIZE]);

impl AsRef<[u8]> for MacTag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl CryptoError {
    pub const fn from_code(code: usize) -> Self {
        match code as u8 {
            value if value == CryptoErrorCode::InvalidKeyLength as u8 => Self::InvalidKeyLength,
            value if value == CryptoErrorCode::InvalidBufferLength as u8 => {
                Self::InvalidBufferLength
            }
            value if value == CryptoErrorCode::InvalidOutputLength as u8 => {
                Self::InvalidOutputLength
            }
            value if value == CryptoErrorCode::PermissionDenied as u8 => Self::PermissionDenied,
            value if value == CryptoErrorCode::NotInitialized as u8 => Self::NotInitialized,
            value if value == CryptoErrorCode::NotFound as u8 => Self::NotFound,
            _ => Self::Unsupported,
        }
    }
}

/// Backend used by typed cipher sessions.
///
/// Runtime code normally uses [`SyscallCryptoBackend`]. Tests may provide a
/// local backend to exercise the typestate API without entering the kernel.
pub trait CryptoBackend {
    /// Configure the backend for a symmetric cipher operation.
    fn setup(
        &mut self,
        key: &[u8],
        iv: &[u8],
        mode: CipherMode,
        algorithm: Algorithm,
    ) -> Result<(), CryptoError>;

    /// Complete one cipher operation.
    fn do_final(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError>;

    /// Compute one complete MAC operation.
    fn mac_compute(
        &mut self,
        key: &[u8],
        algorithm: MacAlgorithm,
        input: &[u8],
        output: &mut [u8; MAC_TAG_SIZE],
    ) -> Result<(), CryptoError>;

    /// Verify one complete MAC operation using kernel-side comparison.
    fn mac_verify(
        &mut self,
        key: &[u8],
        algorithm: MacAlgorithm,
        input: &[u8],
        expected_tag: &[u8],
    ) -> Result<bool, CryptoError>;
}

/// Kernel-backed crypto provider returned by [`crate::RustletCtx::crypto`].
pub struct CryptoProvider {
    backend: SyscallCryptoBackend,
}

impl CryptoProvider {
    pub(crate) const fn new() -> Self {
        Self {
            backend: SyscallCryptoBackend::new(),
        }
    }

    /// Derive key material with the ANSI X9.63 SHA-256 KDF.
    pub fn derive_x963_sha256(
        &mut self,
        shared_secret: &[u8],
        shared_info: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.x963_sha256(shared_secret, shared_info, output)
    }

    /// Compute a MAC over one already assembled message.
    ///
    /// This one-shot form avoids the 256-byte accumulation buffer carried by
    /// [`Mac`]. It is useful when a Rustlet already owns a contiguous message,
    /// especially on targets with small application stacks.
    pub fn compute_mac(
        &mut self,
        key: &[u8],
        algorithm: MacAlgorithm,
        input: &[u8],
    ) -> Result<MacTag, CryptoError> {
        let mut tag = [0u8; MAC_TAG_SIZE];
        self.backend.mac_compute(key, algorithm, input, &mut tag)?;
        Ok(MacTag(tag))
    }

    fn ec_generate_keypair(
        &mut self,
        curve: EcCurve,
        private_key: &mut [u8; P256_PRIVATE_KEY_SIZE],
        public_key: &mut [u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE],
    ) -> Result<(), CryptoError> {
        let params = CryptoEcGenerateKeypairParams {
            curve: curve as u8,
            reserved0: 0,
            reserved1: 0,
            reserved2: 0,
            private_key_ptr: private_key.as_mut_ptr(),
            private_key_capacity: private_key.len(),
            public_key_ptr: public_key.as_mut_ptr(),
            public_key_capacity: public_key.len(),
        };
        let result = crate::syscall::runtime::crypto::ec_generate_keypair::trigger(&params);
        if result & CRYPTO_RESULT_ERROR_FLAG == 0 {
            Ok(())
        } else {
            Err(CryptoError::from_code(result & !CRYPTO_RESULT_ERROR_FLAG))
        }
    }

    fn ecdh_do_final(
        &mut self,
        curve: EcCurve,
        private_key: &[u8; P256_PRIVATE_KEY_SIZE],
        peer_public_key: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let params = CryptoEcdhDoFinalParams {
            curve: curve as u8,
            reserved0: 0,
            reserved1: 0,
            reserved2: 0,
            private_key_ptr: private_key.as_ptr(),
            private_key_len: private_key.len(),
            peer_public_key_ptr: peer_public_key.as_ptr(),
            peer_public_key_len: peer_public_key.len(),
            output_ptr: output.as_mut_ptr(),
            output_capacity: output.len(),
        };
        let result = crate::syscall::runtime::crypto::ecdh_do_final::trigger(&params);
        if result & CRYPTO_RESULT_ERROR_FLAG == 0 {
            Ok(result)
        } else {
            Err(CryptoError::from_code(result & !CRYPTO_RESULT_ERROR_FLAG))
        }
    }

    fn hkdf_sha256(
        &mut self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let params = CryptoHkdfSha256Params {
            ikm_ptr: ikm.as_ptr(),
            ikm_len: ikm.len(),
            salt_ptr: salt.as_ptr(),
            salt_len: salt.len(),
            info_ptr: info.as_ptr(),
            info_len: info.len(),
            output_ptr: output.as_mut_ptr(),
            output_capacity: output.len(),
        };
        let result = crate::syscall::runtime::crypto::hkdf_sha256::trigger(&params);
        if result & CRYPTO_RESULT_ERROR_FLAG == 0 {
            Ok(result)
        } else {
            Err(CryptoError::from_code(result & !CRYPTO_RESULT_ERROR_FLAG))
        }
    }

    fn x963_sha256(
        &mut self,
        shared_secret: &[u8],
        shared_info: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let params = CryptoX963Sha256Params {
            shared_secret_ptr: shared_secret.as_ptr(),
            shared_secret_len: shared_secret.len(),
            shared_info_ptr: shared_info.as_ptr(),
            shared_info_len: shared_info.len(),
            output_ptr: output.as_mut_ptr(),
            output_capacity: output.len(),
        };
        let result = crate::syscall::runtime::crypto::x963_sha256::trigger(&params);
        if result & CRYPTO_RESULT_ERROR_FLAG == 0 {
            Ok(result)
        } else {
            Err(CryptoError::from_code(result & !CRYPTO_RESULT_ERROR_FLAG))
        }
    }
}

impl CryptoBackend for CryptoProvider {
    fn setup(
        &mut self,
        key: &[u8],
        iv: &[u8],
        mode: CipherMode,
        algorithm: Algorithm,
    ) -> Result<(), CryptoError> {
        self.backend.setup(key, iv, mode, algorithm)
    }

    fn do_final(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        self.backend.do_final(input, output)
    }

    fn mac_compute(
        &mut self,
        key: &[u8],
        algorithm: MacAlgorithm,
        input: &[u8],
        output: &mut [u8; MAC_TAG_SIZE],
    ) -> Result<(), CryptoError> {
        self.backend.mac_compute(key, algorithm, input, output)
    }

    fn mac_verify(
        &mut self,
        key: &[u8],
        algorithm: MacAlgorithm,
        input: &[u8],
        expected_tag: &[u8],
    ) -> Result<bool, CryptoError> {
        self.backend.mac_verify(key, algorithm, input, expected_tag)
    }
}

struct SyscallCryptoBackend {
    key_ptr: *const u8,
    key_len: usize,
    iv_ptr: *const u8,
    iv_len: usize,
    mode: CipherMode,
    algorithm: Algorithm,
    initialized: bool,
}

impl SyscallCryptoBackend {
    const fn new() -> Self {
        Self {
            key_ptr: core::ptr::null(),
            key_len: 0,
            iv_ptr: core::ptr::null(),
            iv_len: 0,
            mode: CipherMode::Encrypt,
            algorithm: Algorithm::Aes128CbcNoPadding,
            initialized: false,
        }
    }
}

impl CryptoBackend for SyscallCryptoBackend {
    fn setup(
        &mut self,
        key: &[u8],
        iv: &[u8],
        mode: CipherMode,
        algorithm: Algorithm,
    ) -> Result<(), CryptoError> {
        if iv.len() != AES_BLOCK_SIZE {
            return Err(CryptoError::InvalidBufferLength);
        }
        if !key_len_matches_algorithm(key.len(), algorithm) {
            return Err(CryptoError::InvalidKeyLength);
        }

        // Key and IV stay Rustlet-side until the atomic doFinal syscall.
        self.key_ptr = key.as_ptr();
        self.key_len = key.len();
        self.iv_ptr = iv.as_ptr();
        self.iv_len = iv.len();
        self.mode = mode;
        self.algorithm = algorithm;
        self.initialized = true;
        Ok(())
    }

    fn do_final(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        if !self.initialized {
            return Err(CryptoError::NotInitialized);
        }

        // Input and output may be APDU-backed or Rustlet-RAM-backed, but nowhere else.
        let params = CryptoCipherDoFinalParams {
            algorithm: self.algorithm as u8,
            mode: self.mode as u8,
            key_ptr: self.key_ptr,
            key_len: self.key_len,
            iv_ptr: self.iv_ptr,
            iv_len: self.iv_len,
            input_ptr: input.as_ptr(),
            input_len: input.len(),
            output_ptr: output.as_mut_ptr(),
            output_capacity: output.len(),
        };
        self.initialized = false;
        let result = crate::syscall::runtime::crypto::cipher_do_final::trigger(&params);
        self.key_ptr = core::ptr::null();
        self.key_len = 0;
        self.iv_ptr = core::ptr::null();
        self.iv_len = 0;
        if result & CRYPTO_RESULT_ERROR_FLAG == 0 {
            Ok(result)
        } else {
            Err(CryptoError::from_code(result & !CRYPTO_RESULT_ERROR_FLAG))
        }
    }

    fn mac_compute(
        &mut self,
        key: &[u8],
        algorithm: MacAlgorithm,
        input: &[u8],
        output: &mut [u8; MAC_TAG_SIZE],
    ) -> Result<(), CryptoError> {
        if !mac_key_len_matches_algorithm(key.len(), algorithm) {
            return Err(CryptoError::InvalidKeyLength);
        }

        let params = CryptoMacDoFinalParams {
            algorithm: algorithm as u8,
            operation: CryptoMacOperation::Compute as u8,
            key_ptr: key.as_ptr(),
            key_len: key.len(),
            input_ptr: input.as_ptr(),
            input_len: input.len(),
            expected_tag_ptr: core::ptr::null(),
            expected_tag_len: 0,
            output_ptr: output.as_mut_ptr(),
            output_capacity: output.len(),
        };
        let result = crate::syscall::runtime::crypto::mac_do_final::trigger(&params);
        if result & CRYPTO_RESULT_ERROR_FLAG == 0 {
            if result == MAC_TAG_SIZE {
                Ok(())
            } else {
                Err(CryptoError::InvalidOutputLength)
            }
        } else {
            Err(CryptoError::from_code(result & !CRYPTO_RESULT_ERROR_FLAG))
        }
    }

    fn mac_verify(
        &mut self,
        key: &[u8],
        algorithm: MacAlgorithm,
        input: &[u8],
        expected_tag: &[u8],
    ) -> Result<bool, CryptoError> {
        if !mac_key_len_matches_algorithm(key.len(), algorithm) {
            return Err(CryptoError::InvalidKeyLength);
        }

        let params = CryptoMacDoFinalParams {
            algorithm: algorithm as u8,
            operation: CryptoMacOperation::Verify as u8,
            key_ptr: key.as_ptr(),
            key_len: key.len(),
            input_ptr: input.as_ptr(),
            input_len: input.len(),
            expected_tag_ptr: expected_tag.as_ptr(),
            expected_tag_len: expected_tag.len(),
            output_ptr: core::ptr::null_mut(),
            output_capacity: 0,
        };
        let result = crate::syscall::runtime::crypto::mac_do_final::trigger(&params);
        if result & CRYPTO_RESULT_ERROR_FLAG == 0 {
            Ok(result != 0)
        } else {
            Err(CryptoError::from_code(result & !CRYPTO_RESULT_ERROR_FLAG))
        }
    }
}

fn key_len_matches_algorithm(len: usize, algorithm: Algorithm) -> bool {
    match algorithm {
        Algorithm::Aes128CbcNoPadding | Algorithm::Aes128CbcIso9797M2 => len == AES128_KEY_SIZE,
        Algorithm::Aes256CbcNoPadding | Algorithm::Aes256CbcIso9797M2 => len == AES256_KEY_SIZE,
        Algorithm::Aes128EcbNoPadding => len == AES128_KEY_SIZE,
        Algorithm::Aes256EcbNoPadding => len == AES256_KEY_SIZE,
    }
}

fn mac_key_len_matches_algorithm(len: usize, algorithm: MacAlgorithm) -> bool {
    match algorithm {
        MacAlgorithm::AesCmac => len == AES128_KEY_SIZE || len == AES256_KEY_SIZE,
    }
}

/// Java Card-style random data facade.
pub struct RandomData {
    algorithm: RandomAlgorithm,
}

impl RandomData {
    /// Create a random generator instance for the requested algorithm.
    pub fn get_instance(algorithm: RandomAlgorithm) -> Result<Self, CryptoError> {
        Ok(Self { algorithm })
    }

    /// Fill the provided output buffer with random bytes.
    pub fn generate_data(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
        // The kernel validates that the destination is writable Rustlet memory.
        let params = CryptoRandomGenerateParams {
            algorithm: self.algorithm as u8,
            output_ptr: output.as_mut_ptr(),
            output_len: output.len(),
        };
        let result = crate::syscall::runtime::crypto::random_generate::trigger(&params);
        if result & CRYPTO_RESULT_ERROR_FLAG == 0 {
            Ok(())
        } else {
            Err(CryptoError::from_code(result & !CRYPTO_RESULT_ERROR_FLAG))
        }
    }
}

/// Typestate cipher session.
///
/// Methods are only exposed in protocol states where they are valid. A cipher
/// must be initialized before data can be processed, and `finish` consumes the
/// ready session to avoid accidental reuse without a fresh initialization.
pub struct Cipher<'a, State> {
    backend: &'a mut dyn CryptoBackend,
    _state: PhantomData<State>,
}

impl<'a> Cipher<'a, Uninitialized> {
    /// Create a new unconfigured cipher session.
    pub fn new(backend: &'a mut dyn CryptoBackend) -> Self {
        Self {
            backend,
            _state: PhantomData,
        }
    }

    /// Configure the cipher with a key, IV, direction, and algorithm.
    pub fn init(
        self,
        key: &[u8],
        iv: &[u8],
        mode: CipherMode,
        algorithm: Algorithm,
    ) -> Result<Cipher<'a, Ready>, CryptoError> {
        self.backend.setup(key, iv, mode, algorithm)?;
        Ok(Cipher {
            backend: self.backend,
            _state: PhantomData,
        })
    }
}

/// Typestate MAC session.
///
/// Data is accumulated Rustlet-side with `update`. The kernel sees only one
/// final MAC syscall when `compute` or `verify` consumes the ready session.
pub struct Mac<'a, State> {
    backend: &'a mut dyn CryptoBackend,
    key: [u8; AES256_KEY_SIZE],
    key_len: usize,
    algorithm: MacAlgorithm,
    input: [u8; MAC_INPUT_CAPACITY],
    input_len: usize,
    _state: PhantomData<State>,
}

impl<'a> Mac<'a, Uninitialized> {
    /// Create a new unconfigured MAC session.
    pub fn new(backend: &'a mut dyn CryptoBackend) -> Self {
        Self {
            backend,
            key: [0; AES256_KEY_SIZE],
            key_len: 0,
            algorithm: MacAlgorithm::AesCmac,
            input: [0; MAC_INPUT_CAPACITY],
            input_len: 0,
            _state: PhantomData,
        }
    }

    /// Configure the MAC session with a key and algorithm.
    pub fn init(
        mut self,
        key: &[u8],
        algorithm: MacAlgorithm,
    ) -> Result<Mac<'a, Ready>, CryptoError> {
        if !mac_key_len_matches_algorithm(key.len(), algorithm) {
            return Err(CryptoError::InvalidKeyLength);
        }

        self.key[..key.len()].copy_from_slice(key);
        Ok(Mac {
            backend: self.backend,
            key: self.key,
            key_len: key.len(),
            algorithm,
            input: self.input,
            input_len: 0,
            _state: PhantomData,
        })
    }
}

impl Mac<'_, Ready> {
    /// Append bytes to the authenticated message.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let Some(end) = self.input_len.checked_add(data.len()) else {
            return Err(CryptoError::InvalidBufferLength);
        };
        if end > self.input.len() {
            return Err(CryptoError::InvalidBufferLength);
        }

        self.input[self.input_len..end].copy_from_slice(data);
        self.input_len = end;
        Ok(())
    }

    /// Finalize the MAC and return the computed tag.
    pub fn compute(self) -> Result<MacTag, CryptoError> {
        let mut tag = [0u8; MAC_TAG_SIZE];
        self.backend.mac_compute(
            &self.key[..self.key_len],
            self.algorithm,
            &self.input[..self.input_len],
            &mut tag,
        )?;
        Ok(MacTag(tag))
    }

    /// Finalize the MAC and compare the tag in the kernel.
    pub fn verify(self, expected_tag: &[u8]) -> Result<bool, CryptoError> {
        self.backend.mac_verify(
            &self.key[..self.key_len],
            self.algorithm,
            &self.input[..self.input_len],
            expected_tag,
        )
    }
}

impl<'a> Cipher<'a, Ready> {
    /// Streaming update is reserved for a later stateful backend.
    pub fn update(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Complete one cipher operation and consume the ready session.
    pub fn finish(self, input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        self.backend.do_final(input, output)
    }
}

/// Fixed-size Rustlet-owned P-256 private key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcPrivateKey {
    curve: EcCurve,
    bytes: [u8; P256_PRIVATE_KEY_SIZE],
}

impl EcPrivateKey {
    /// Build a P-256 private key wrapper from raw scalar bytes.
    pub const fn p256_from_bytes(bytes: [u8; P256_PRIVATE_KEY_SIZE]) -> Self {
        Self {
            curve: EcCurve::P256,
            bytes,
        }
    }

    /// Return the encoded private key bytes.
    pub fn as_bytes(&self) -> &[u8; P256_PRIVATE_KEY_SIZE] {
        &self.bytes
    }

    /// Return the curve carried by this key.
    pub fn curve(&self) -> EcCurve {
        self.curve
    }
}

/// Fixed-size Rustlet-owned P-256 public key encoded as SEC1 uncompressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcPublicKey {
    curve: EcCurve,
    bytes: [u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE],
}

impl EcPublicKey {
    /// Return the SEC1 public key bytes.
    pub fn as_bytes(&self) -> &[u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE] {
        &self.bytes
    }

    /// Return the curve carried by this key.
    pub fn curve(&self) -> EcCurve {
        self.curve
    }
}

/// Freshly generated EC key pair kept entirely in Rustlet memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcKeyPair {
    private_key: EcPrivateKey,
    public_key: EcPublicKey,
}

impl EcKeyPair {
    /// Generate a new key pair for the requested curve.
    pub fn generate(crypto: &mut CryptoProvider, curve: EcCurve) -> Result<Self, CryptoError> {
        match curve {
            EcCurve::P256 => {
                let mut private = [0u8; P256_PRIVATE_KEY_SIZE];
                let mut public = [0u8; P256_PUBLIC_KEY_UNCOMPRESSED_SIZE];
                crypto.ec_generate_keypair(curve, &mut private, &mut public)?;
                Ok(Self {
                    private_key: EcPrivateKey {
                        curve,
                        bytes: private,
                    },
                    public_key: EcPublicKey {
                        curve,
                        bytes: public,
                    },
                })
            }
        }
    }

    /// Return the private key.
    pub fn private_key(&self) -> EcPrivateKey {
        self.private_key
    }

    /// Return the public key.
    pub fn public_key(&self) -> EcPublicKey {
        self.public_key
    }
}

/// Java Card-style key agreement object backed by one atomic kernel syscall.
pub struct KeyAgreement<'a, State> {
    crypto: &'a mut CryptoProvider,
    curve: EcCurve,
    private_key: [u8; P256_PRIVATE_KEY_SIZE],
    _state: PhantomData<State>,
}

impl<'a> KeyAgreement<'a, Uninitialized> {
    /// Create a new unconfigured key agreement object.
    pub fn new(crypto: &'a mut CryptoProvider) -> Self {
        Self {
            crypto,
            curve: EcCurve::P256,
            private_key: [0; P256_PRIVATE_KEY_SIZE],
            _state: PhantomData,
        }
    }

    /// Load the private key used for the next agreement.
    pub fn init(
        mut self,
        private_key: &EcPrivateKey,
    ) -> Result<KeyAgreement<'a, Ready>, CryptoError> {
        self.curve = private_key.curve();
        self.private_key.copy_from_slice(private_key.as_bytes());
        Ok(KeyAgreement {
            crypto: self.crypto,
            curve: self.curve,
            private_key: self.private_key,
            _state: PhantomData,
        })
    }
}

impl KeyAgreement<'_, Ready> {
    /// Derive one raw shared secret from the peer public key.
    pub fn generate_secret(
        &mut self,
        peer_public_key: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if output.len() < P256_SHARED_SECRET_SIZE {
            return Err(CryptoError::InvalidOutputLength);
        }
        self.crypto
            .ecdh_do_final(self.curve, &self.private_key, peer_public_key, output)
    }

    /// Derive one HKDF-SHA256 output from the P-256 shared secret.
    pub fn derive_hkdf_sha256(
        &mut self,
        peer_public_key: &[u8],
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let mut shared_secret = [0u8; P256_SHARED_SECRET_SIZE];
        let shared_len = self.generate_secret(peer_public_key, &mut shared_secret)?;
        let result = self
            .crypto
            .hkdf_sha256(&shared_secret[..shared_len], salt, info, output);
        shared_secret.fill(0);
        result
    }
}
