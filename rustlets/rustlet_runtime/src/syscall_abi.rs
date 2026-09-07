/// Machine word used for Rustlet SVC arguments and return registers.
pub type SyscallWord = usize;

/// Immediate value encoded in the ARM `svc #imm8` instruction.
pub type SyscallNumber = u8;

/// Runtime-owned Rustlet syscall numbers.
///
/// The same values are used by the Rustlet runtime wrappers and by the kernel
/// syscall dispatch table. Keep all numbering changes in this enum so both
/// sides evolve together.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeSyscall {
    /// Enter app mode from kernel code.
    ///
    /// Kernel-side gate only.
    ///
    /// Inputs:
    /// - `r0`: reserved by the target gate.
    /// - `r1`: reserved by the target gate.
    /// - `r2`: reserved by the target gate.
    ///
    /// Returns:
    /// - `r0`: redirected app return value when the SVC is rewritten inline.
    /// - `r1`: reserved.
    EnterApp = 0,

    /// Return from a Rustlet handler, explicit Rustlet exit, or bootstrap.
    ///
    /// Inputs:
    /// - `r0`: status `SW1`, or descriptor pointer for bootstrap returns.
    /// - `r1`: status `SW2`, or unused for bootstrap returns.
    /// - `r2`: [`RuntimeReturnKind`] discriminant.
    ///
    /// Returns:
    /// - `r0`: kernel-side acknowledgement only; the app does not resume.
    /// - `r1`: reserved.
    ReturnToKernel = 1,

    /// Allocate memory from the currently active Rustlet heap.
    ///
    /// Inputs:
    /// - `r0`: requested allocation size in bytes.
    /// - `r1`: requested alignment in bytes.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: allocated pointer, or `0` on failure.
    /// - `r1`: reserved.
    Alloc = 3,

    /// Free memory previously allocated from the active Rustlet heap.
    ///
    /// Inputs:
    /// - `r0`: pointer to free.
    /// - `r1`: allocation size in bytes.
    /// - `r2`: allocation alignment in bytes.
    ///
    /// Returns:
    /// - `r0`: currently unused, always `0`.
    /// - `r1`: reserved.
    Dealloc = 4,

    /// Receive the incoming APDU payload for the active command.
    ///
    /// Inputs:
    /// - `r0`: unused.
    /// - `r1`: unused.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: number of incoming bytes received.
    /// - `r1`: reserved.
    ApduSetIncomingAndReceive = 6,

    /// Declare that the current APDU has an outgoing phase.
    ///
    /// Inputs:
    /// - `r0`: unused.
    /// - `r1`: unused.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: current requested `Le` value.
    /// - `r1`: reserved.
    ApduSetOutgoing = 7,

    /// Declare the outgoing APDU payload length.
    ///
    /// Inputs:
    /// - `r0`: outgoing payload length in bytes.
    /// - `r1`: unused.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: currently unused, always `0`.
    /// - `r1`: reserved.
    ApduSetOutgoingLength = 8,

    /// Run one symmetric cipher `doFinal` operation.
    ///
    /// All parameter pointers must target either the shared APDU page or the
    /// active Rustlet RAM windows validated by the kernel.
    ///
    /// Inputs:
    /// - `r0`: pointer to [`CryptoCipherDoFinalParams`].
    /// - `r1`: unused.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: produced byte length on success, otherwise
    ///   [`CRYPTO_RESULT_ERROR_FLAG`] ORed with a [`CryptoErrorCode`] value.
    /// - `r1`: reserved.
    CryptoCipherDoFinal = 9,

    /// Fill a Rustlet-owned output buffer with random bytes.
    ///
    /// Inputs:
    /// - `r0`: pointer to [`CryptoRandomGenerateParams`].
    /// - `r1`: unused.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: `0` on success, otherwise [`CRYPTO_RESULT_ERROR_FLAG`] ORed
    ///   with a [`CryptoErrorCode`] value.
    /// - `r1`: reserved.
    CryptoRandomGenerate = 10,

    /// Run one message authentication `doFinal` operation.
    ///
    /// This is an application-facing MAC service. SCP03 secure channel MACs are
    /// a separate kernel protocol concern.
    ///
    /// Inputs:
    /// - `r0`: pointer to [`CryptoMacDoFinalParams`].
    /// - `r1`: unused.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: produced tag length for compute, `1` or `0` for verify,
    ///   otherwise [`CRYPTO_RESULT_ERROR_FLAG`] ORed with a
    ///   [`CryptoErrorCode`] value.
    /// - `r1`: reserved.
    CryptoMacDoFinal = 11,

    /// Load one SCP03 static key object for the currently active Security Domain.
    ///
    /// Inputs:
    /// - `r0`: pointer to [`Scp03LoadKeyParams`].
    /// - `r1`: unused.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: loaded byte length on success, otherwise
    ///   [`CRYPTO_RESULT_ERROR_FLAG`] ORed with a [`CryptoErrorCode`] value.
    /// - `r1`: reserved.
    SecurityDomainLoadScp03Key = 12,

    /// Generate one fresh EC key pair for the requested curve.
    ///
    /// Inputs:
    /// - `r0`: pointer to [`CryptoEcGenerateKeypairParams`].
    /// - `r1`: unused.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: `0` on success, otherwise [`CRYPTO_RESULT_ERROR_FLAG`] ORed
    ///   with a [`CryptoErrorCode`] value.
    /// - `r1`: reserved.
    CryptoEcGenerateKeypair = 13,

    /// Compute one EC Diffie-Hellman shared secret.
    ///
    /// Inputs:
    /// - `r0`: pointer to [`CryptoEcdhDoFinalParams`].
    /// - `r1`: unused.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: produced shared secret byte length on success, otherwise
    ///   [`CRYPTO_RESULT_ERROR_FLAG`] ORed with a [`CryptoErrorCode`] value.
    /// - `r1`: reserved.
    CryptoEcdhDoFinal = 14,

    /// Derive one output key from caller-provided input keying material using HKDF-SHA256.
    ///
    /// Inputs:
    /// - `r0`: pointer to [`CryptoHkdfSha256Params`].
    /// - `r1`: unused.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: produced output byte length on success, otherwise
    ///   [`CRYPTO_RESULT_ERROR_FLAG`] ORed with a [`CryptoErrorCode`] value.
    /// - `r1`: reserved.
    CryptoHkdfSha256 = 15,

    /// Derive key material with the ANSI X9.63 SHA-256 KDF used by SCP11.
    ///
    /// Inputs:
    /// - `r0`: pointer to [`CryptoX963Sha256Params`].
    /// - `r1`: unused.
    /// - `r2`: unused.
    ///
    /// Returns:
    /// - `r0`: produced output byte length on success, otherwise
    ///   [`CRYPTO_RESULT_ERROR_FLAG`] ORed with a [`CryptoErrorCode`] value.
    /// - `r1`: reserved.
    CryptoX963Sha256 = 16,
}

impl RuntimeSyscall {
    pub const fn number(self) -> SyscallNumber {
        self as SyscallNumber
    }
}

/// Kind value passed in `r2` to [`RuntimeSyscall::ReturnToKernel`].
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeReturnKind {
    /// Normal handler return; `r0/r1` contain `SW1/SW2`.
    HandlerReturn = 0,
    /// Explicit Rustlet exit; `r0/r1` contain `SW1/SW2`.
    Exit = 1,
    /// Bootstrap return; `r0` contains the selected-app descriptor pointer.
    Descriptor = 2,
}

impl RuntimeReturnKind {
    pub const fn word(self) -> SyscallWord {
        self as SyscallWord
    }

    pub const fn from_word(word: SyscallWord) -> Self {
        match word {
            0 => Self::HandlerReturn,
            1 => Self::Exit,
            _ => Self::Descriptor,
        }
    }
}

pub const ENTER_APP: SyscallNumber = RuntimeSyscall::EnterApp.number();
pub const RETURN_TO_KERNEL: SyscallNumber = RuntimeSyscall::ReturnToKernel.number();
pub const ALLOC: SyscallNumber = RuntimeSyscall::Alloc.number();
pub const DEALLOC: SyscallNumber = RuntimeSyscall::Dealloc.number();
pub const APDU_SET_INCOMING_AND_RECEIVE: SyscallNumber =
    RuntimeSyscall::ApduSetIncomingAndReceive.number();
pub const APDU_SET_OUTGOING: SyscallNumber = RuntimeSyscall::ApduSetOutgoing.number();
pub const APDU_SET_OUTGOING_LENGTH: SyscallNumber = RuntimeSyscall::ApduSetOutgoingLength.number();
pub const CRYPTO_CIPHER_DO_FINAL: SyscallNumber = RuntimeSyscall::CryptoCipherDoFinal.number();
pub const CRYPTO_RANDOM_GENERATE: SyscallNumber = RuntimeSyscall::CryptoRandomGenerate.number();
pub const CRYPTO_MAC_DO_FINAL: SyscallNumber = RuntimeSyscall::CryptoMacDoFinal.number();
pub const SECURITY_DOMAIN_LOAD_SCP03_KEY: SyscallNumber =
    RuntimeSyscall::SecurityDomainLoadScp03Key.number();
pub const CRYPTO_EC_GENERATE_KEYPAIR: SyscallNumber =
    RuntimeSyscall::CryptoEcGenerateKeypair.number();
pub const CRYPTO_ECDH_DO_FINAL: SyscallNumber = RuntimeSyscall::CryptoEcdhDoFinal.number();
pub const CRYPTO_HKDF_SHA256: SyscallNumber = RuntimeSyscall::CryptoHkdfSha256.number();
pub const CRYPTO_X963_SHA256: SyscallNumber = RuntimeSyscall::CryptoX963Sha256.number();

pub const CRYPTO_RESULT_ERROR_FLAG: SyscallWord = 1usize << (usize::BITS - 1);

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoErrorCode {
    InvalidKeyLength = 1,
    InvalidBufferLength = 2,
    InvalidOutputLength = 3,
    Unsupported = 4,
    PermissionDenied = 5,
    NotInitialized = 6,
    NotFound = 7,
}

impl CryptoErrorCode {
    pub const fn word(self) -> SyscallWord {
        self as SyscallWord
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoCipherDoFinalParams {
    /// [`crate::Algorithm`] discriminant.
    pub algorithm: u8,
    /// [`crate::CipherMode`] discriminant.
    pub mode: u8,
    /// Pointer to the key bytes.
    pub key_ptr: *const u8,
    /// Key length in bytes.
    pub key_len: usize,
    /// Pointer to the IV bytes.
    pub iv_ptr: *const u8,
    /// IV length in bytes.
    pub iv_len: usize,
    /// Pointer to input bytes.
    pub input_ptr: *const u8,
    /// Input length in bytes.
    pub input_len: usize,
    /// Pointer to the output buffer.
    pub output_ptr: *mut u8,
    /// Output capacity in bytes.
    pub output_capacity: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoRandomGenerateParams {
    /// [`crate::RandomAlgorithm`] discriminant.
    pub algorithm: u8,
    /// Pointer to the output buffer.
    pub output_ptr: *mut u8,
    /// Output length in bytes.
    pub output_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Scp03LoadKeyParams {
    /// Requested key set version.
    pub key_version: u8,
    /// Requested key identifier.
    pub key_id: u8,
    /// Requested key usage.
    pub usage: u8,
    /// Reserved for future extensions. Must be zero.
    pub reserved: u8,
    /// Pointer to the output buffer.
    pub output_ptr: *mut u8,
    /// Output capacity in bytes.
    pub output_capacity: usize,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoEcCurve {
    P256 = 1,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoEcGenerateKeypairParams {
    /// [`CryptoEcCurve`] discriminant.
    pub curve: u8,
    /// Reserved for future extensions. Must be zero.
    pub reserved0: u8,
    /// Reserved for future extensions. Must be zero.
    pub reserved1: u8,
    /// Reserved for future extensions. Must be zero.
    pub reserved2: u8,
    /// Pointer to the private key output buffer.
    pub private_key_ptr: *mut u8,
    /// Output capacity in bytes for the private key.
    pub private_key_capacity: usize,
    /// Pointer to the public key output buffer.
    pub public_key_ptr: *mut u8,
    /// Output capacity in bytes for the public key.
    pub public_key_capacity: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoEcdhDoFinalParams {
    /// [`CryptoEcCurve`] discriminant.
    pub curve: u8,
    /// Reserved for future extensions. Must be zero.
    pub reserved0: u8,
    /// Reserved for future extensions. Must be zero.
    pub reserved1: u8,
    /// Reserved for future extensions. Must be zero.
    pub reserved2: u8,
    /// Pointer to the private key bytes.
    pub private_key_ptr: *const u8,
    /// Private key length in bytes.
    pub private_key_len: usize,
    /// Pointer to the peer public key bytes.
    pub peer_public_key_ptr: *const u8,
    /// Peer public key length in bytes.
    pub peer_public_key_len: usize,
    /// Pointer to the output shared secret buffer.
    pub output_ptr: *mut u8,
    /// Output capacity in bytes.
    pub output_capacity: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoHkdfSha256Params {
    /// Pointer to the input keying material.
    pub ikm_ptr: *const u8,
    /// Input keying material length in bytes.
    pub ikm_len: usize,
    /// Pointer to the optional salt bytes.
    pub salt_ptr: *const u8,
    /// Salt length in bytes.
    pub salt_len: usize,
    /// Pointer to the optional info/context bytes.
    pub info_ptr: *const u8,
    /// Info/context length in bytes.
    pub info_len: usize,
    /// Pointer to the output buffer.
    pub output_ptr: *mut u8,
    /// Output capacity in bytes.
    pub output_capacity: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoX963Sha256Params {
    /// Pointer to the shared secret bytes.
    pub shared_secret_ptr: *const u8,
    /// Shared secret length in bytes.
    pub shared_secret_len: usize,
    /// Pointer to the shared info/context bytes.
    pub shared_info_ptr: *const u8,
    /// Shared info/context length in bytes.
    pub shared_info_len: usize,
    /// Pointer to the output buffer.
    pub output_ptr: *mut u8,
    /// Output capacity in bytes.
    pub output_capacity: usize,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoMacOperation {
    Compute = 1,
    Verify = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoMacDoFinalParams {
    /// [`crate::MacAlgorithm`] discriminant.
    pub algorithm: u8,
    /// [`CryptoMacOperation`] discriminant.
    pub operation: u8,
    /// Pointer to the key bytes.
    pub key_ptr: *const u8,
    /// Key length in bytes.
    pub key_len: usize,
    /// Pointer to authenticated input bytes.
    pub input_ptr: *const u8,
    /// Authenticated input length in bytes.
    pub input_len: usize,
    /// Pointer to expected tag bytes for verify operations.
    pub expected_tag_ptr: *const u8,
    /// Expected tag length in bytes.
    pub expected_tag_len: usize,
    /// Pointer to output tag bytes for compute operations.
    pub output_ptr: *mut u8,
    /// Output tag capacity in bytes.
    pub output_capacity: usize,
}
