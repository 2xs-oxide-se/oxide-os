//! Shared ABI description between the kernel and Rustlets.
//!
//! These types define the runtime contract only. Kernel and Rustlet code are
//! compiled separately, so every field in this module is part of the stable
//! binary interface between both sides.
//!
//! The shared page is deliberately fixed to 512 bytes and split into two
//! 256-byte halves:
//! - the first half is the control/secondary buffer;
//! - the second half is the APDU payload buffer.
//!
//! Invariants:
//! - the APDU payload buffer is never copied into a larger Rustlet ABI buffer;
//! - short APDU payload lengths are capped at 255 bytes because the ABI length
//!   field is one byte, even though the physical APDU buffer reserves 256 bytes;
//! - the APDU payload length is stored in the control half (`data_len`), not in
//!   `data[0]`: byte zero of the payload buffer is still the first APDU byte;
//! - the control/secondary half may be used by the kernel as scratch space
//!   before entering a Rustlet, but it must be reinitialized before Rustlet code
//!   observes it.

use core::ffi::c_void;

pub const ABI_VERSION: u32 = 1;

/// Physical APDU buffer capacity inside [`RustletCtx`].
///
/// The extra byte over [`APDU_PAYLOAD_LENGTH_MAX`] keeps the region naturally
/// sized as one 256-byte half of the shared page. It is not an invitation to
/// encode a 256-byte short APDU payload.
pub const APDU_BUFFER_CAPACITY: usize = 256;

/// Maximum useful APDU payload length currently represented by the ABI.
///
/// Short APDU `Lc`/`Le` values are represented as one byte here, so the largest
/// representable payload length is 255 bytes. The length byte lives in
/// [`RustletControl::data_len`]; it is not stored inside the APDU payload
/// buffer itself.
pub const APDU_PAYLOAD_LENGTH_MAX: usize = 255;

/// Size of the control/secondary half of [`RustletCtx`].
///
/// This half carries APDU metadata and serialized state when a Rustlet is
/// entered. Kernel protocol code may reuse it as temporary scratch space before
/// that point, provided it is reset before user code observes the ABI page.
pub const RUSTLET_CONTROL_BUFFER_CAPACITY: usize = 256;

/// Maximum serialized Rustlet state carried in the secondary buffer.
///
/// The remaining bytes of the 256-byte control half are consumed by the ABI
/// version, command/status bytes, flags, APDU length and the state length byte.
pub const STATE_BUFFER_CAPACITY: usize = 244;

/// Total shared ABI page size mapped between kernel and the active Rustlet.
pub const APDU_SHARED_REGION_SIZE: usize = 512;
pub const INS_SELECT: u8 = 0xa4;
pub const INS_INSTALL: u8 = 0xe6;
const APDU_BUFFER_FLAG_OUTGOING: u8 = 1;
const APDU_BUFFER_FLAG_STATUS_VALID: u8 = 2;

pub const SDDISPATCH_CLA: u8 = 0x80;
pub const SDDISPATCH_BOOL_FALSE: u8 = 0x00;
pub const SDDISPATCH_BOOL_TRUE: u8 = 0x01;

/// Stable operation numbers used by the Security Domain dispatch ABI.
pub struct SddispatchOpcode;

impl SddispatchOpcode {
    pub const INSTALL_FOR_LOAD: u8 = 0x10;
    pub const INSTALL_FOR_INSTALL: u8 = 0x11;
    pub const DELETE_AID: u8 = 0x12;
    pub const GET_DATA: u8 = 0x13;
    pub const PUT_KEY: u8 = 0x14;
    pub const STORE_DATA: u8 = 0x15;
    pub const SET_STATUS: u8 = 0x16;
    pub const MAY_MANAGE_APPLET: u8 = 0x20;
    pub const MAY_MAKE_SELECTABLE: u8 = 0x21;
    pub const GET_ADMINISTRATIVE_STATE: u8 = 0x22;
    pub const SUPPORTS_SCP03: u8 = 0x30;
    pub const INITIALIZE_UPDATE: u8 = 0x31;
    pub const EXTERNAL_AUTHENTICATE: u8 = 0x32;
    pub const CURRENT_SECURITY_LEVEL: u8 = 0x33;
    pub const SECURE_CHANNEL_OPEN: u8 = 0x34;
    pub const CURRENT_MAC_LEN: u8 = 0x35;
    pub const RESET_SECURE_CHANNEL: u8 = 0x36;
    pub const SUPPORTS_SCP11A: u8 = 0x37;
    pub const SCP11_STAGE_OCE_CERTIFICATE: u8 = 0x38;
    pub const SCP11A_MUTUAL_AUTHENTICATE: u8 = 0x39;
    pub const SUPPORTS_SCP11C: u8 = 0x3A;
    pub const SCP11C_MUTUAL_AUTHENTICATE: u8 = 0x3B;
    pub const SUPPORTS_SCP11B: u8 = 0x3C;
    pub const SCP11B_INTERNAL_AUTHENTICATE: u8 = 0x3D;
    pub const UNWRAP_COMMAND: u8 = 0x40;
    pub const WRAP_RESPONSE: u8 = 0x41;
    pub const CLAIM_DELEGATED_SECURE_CHANNEL: u8 = 0x42;
    pub const HANDLE_DELEGATED_SECURE_CHANNEL: u8 = 0x43;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RustletHeapRegion {
    pub storage_start: *mut u8,
    pub storage_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Aid {
    pub bytes: [u8; 16],
    pub len: u8,
}

impl Aid {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; 16],
            len: 0,
        }
    }

    pub const fn from_array<const N: usize>(data: [u8; N]) -> Self {
        let mut bytes = [0u8; 16];
        let mut index = 0;
        let len = if N < 16 { N } else { 16 };
        // In const contexts, we cannot use iterators (for loops) or `copy_from_slice`.
        // We use a manual while loop and const generics to allow compile-time AID construction.
        while index < len {
            bytes[index] = data[index];
            index += 1;
        }
        Self {
            bytes,
            len: len as u8,
        }
    }

    pub fn new(data: &[u8]) -> Self {
        let mut bytes = [0u8; 16];
        let len = data.len().min(16) as u8;
        bytes[..len as usize].copy_from_slice(&data[..len as usize]);
        Self { bytes, len }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RustletApduHeader {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub lc: u8,
    pub le: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StateSlice {
    len: u8,
    pub bytes: [u8; STATE_BUFFER_CAPACITY],
}

impl StateSlice {
    pub const fn new() -> Self {
        Self {
            len: 0,
            bytes: [0; STATE_BUFFER_CAPACITY],
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub fn clear(&mut self) {
        secure_zero(&mut self.bytes);
        self.len = 0;
    }

    pub fn stage(&mut self, state: &[u8]) -> bool {
        if state.len() > self.bytes.len() {
            return false;
        }
        self.bytes[..state.len()].copy_from_slice(state);
        secure_zero(&mut self.bytes[state.len()..]);
        self.len = state.len() as u8;
        true
    }

    pub fn set_len(&mut self, len: usize) -> bool {
        if len > self.bytes.len() {
            return false;
        }
        self.len = len as u8;
        true
    }
}

fn secure_zero(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

impl Default for StateSlice {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RustletControlBuffer {
    // Invariant: this structure is exactly one 256-byte half of RustletCtx.
    // Keep the compile-time assertion below in sync with any field change.
    abi_version: u32,
    // Command entry: CLA, INS, P1, P2, P3. Return path: SW1, SW2, 0, 0, 0.
    command_status: [u8; 5],
    flags: u8,
    // Incoming or outgoing APDU data length. It is a short-APDU u8 length, so
    // values above 255 are deliberately unrepresentable in this ABI version.
    data_len: u8,
    state: StateSlice,
}

impl RustletControlBuffer {
    const fn new() -> Self {
        Self {
            abi_version: 0,
            command_status: [0; 5],
            flags: 0,
            data_len: 0,
            state: StateSlice::new(),
        }
    }

    fn set_command_header(&mut self, header: RustletApduHeader) {
        self.command_status = [
            header.cla,
            header.ins,
            header.p1,
            header.p2,
            if header.lc != 0 { header.lc } else { header.le },
        ];
        self.flags &= !APDU_BUFFER_FLAG_STATUS_VALID;
    }

    fn command_header(&self) -> RustletApduHeader {
        let p3 = self.command_status[4];
        RustletApduHeader {
            cla: self.command_status[0],
            ins: self.command_status[1],
            p1: self.command_status[2],
            p2: self.command_status[3],
            lc: p3,
            le: p3,
        }
    }

    fn set_status(&mut self, status: ApduStatus) {
        self.command_status = [status.sw1, status.sw2, 0, 0, 0];
        self.flags |= APDU_BUFFER_FLAG_STATUS_VALID;
    }

    fn status(&self) -> ApduStatus {
        if self.flags & APDU_BUFFER_FLAG_STATUS_VALID == 0 {
            return ApduStatus { sw1: 0, sw2: 0 };
        }
        ApduStatus {
            sw1: self.command_status[0],
            sw2: self.command_status[1],
        }
    }
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct RustletCtx {
    // Invariant: the control half comes first so kernel secure-channel code can
    // temporarily reuse this 256-byte region without touching APDU payload
    // bytes. Every Rustlet entry path must reinitialize it before user code.
    control: RustletControlBuffer,
    /// Shared APDU payload buffer.
    ///
    /// Before outgoing mode starts, the first `data_len` bytes hold incoming
    /// command data. After outgoing mode starts, the same bytes hold response
    /// data. This in-place ownership switch is the core zero-copy APDU invariant
    /// of the Rustlet ABI.
    pub data: [u8; APDU_BUFFER_CAPACITY],
}

impl RustletCtx {
    pub const fn new() -> Self {
        Self {
            control: RustletControlBuffer::new(),
            data: [0; APDU_BUFFER_CAPACITY],
        }
    }

    pub fn version(&self) -> u32 {
        self.control.abi_version
    }

    /// Create a kernel-backed crypto provider for this Rustlet call.
    pub fn crypto(&mut self) -> crate::CryptoProvider {
        crate::CryptoProvider::new()
    }

    /// Load one SCP03 static key object owned by the currently active Security Domain.
    pub fn load_scp03_key_material(
        &mut self,
        key_version: u8,
        key_id: u8,
        usage: u8,
        out: &mut [u8],
    ) -> Result<usize, crate::CryptoError> {
        let params = crate::Scp03LoadKeyParams {
            key_version,
            key_id,
            usage,
            reserved: 0,
            output_ptr: out.as_mut_ptr(),
            output_capacity: out.len(),
        };
        let result = crate::syscall::runtime::crypto::load_scp03_key::trigger(&params);
        if result & crate::syscall_abi::CRYPTO_RESULT_ERROR_FLAG == 0 {
            Ok(result)
        } else {
            Err(crate::CryptoError::from_code(
                result & !crate::syscall_abi::CRYPTO_RESULT_ERROR_FLAG,
            ))
        }
    }

    pub fn set_version(&mut self, version: u32) {
        self.control.abi_version = version;
    }

    /// Reinitializes only the control half of the shared ABI page.
    ///
    /// The APDU payload half is deliberately left untouched so the kernel can
    /// carry one command from transport reception to Rustlet entry without a
    /// copy. Callers must publish a fresh `data_len` before user code observes
    /// the payload.
    pub fn reset_control(&mut self) {
        self.control = RustletControlBuffer::new();
    }

    pub(crate) fn lc(&self) -> u8 {
        self.header().lc
    }

    pub(crate) fn le(&self) -> u8 {
        self.header().le
    }

    pub(crate) fn header(&self) -> RustletApduHeader {
        self.control.command_header()
    }

    pub fn stage_command(&mut self, header: RustletApduHeader, incoming: &[u8]) -> bool {
        if incoming.len() > APDU_PAYLOAD_LENGTH_MAX {
            return false;
        }

        self.control.set_command_header(header);
        self.control.flags &= !(APDU_BUFFER_FLAG_OUTGOING | APDU_BUFFER_FLAG_STATUS_VALID);
        self.control.data_len = incoming.len() as u8;
        if !incoming.is_empty() {
            self.data[..incoming.len()].copy_from_slice(incoming);
        }
        self.clear_apdu_tail(incoming.len());
        true
    }

    pub fn stage_preencoded_command(
        &mut self,
        header: RustletApduHeader,
        incoming_len: usize,
    ) -> bool {
        if incoming_len > APDU_PAYLOAD_LENGTH_MAX {
            return false;
        }

        self.control.set_command_header(header);
        self.control.flags &= !(APDU_BUFFER_FLAG_OUTGOING | APDU_BUFFER_FLAG_STATUS_VALID);
        self.control.data_len = incoming_len as u8;
        self.clear_apdu_tail(incoming_len);
        true
    }

    pub fn stage_existing_command(
        &mut self,
        header: RustletApduHeader,
        incoming_len: usize,
    ) -> bool {
        self.stage_preencoded_command(header, incoming_len)
    }

    pub fn stage_incoming_data(&mut self, incoming: &[u8]) -> bool {
        if incoming.len() > APDU_PAYLOAD_LENGTH_MAX {
            return false;
        }

        self.control.flags &= !(APDU_BUFFER_FLAG_OUTGOING | APDU_BUFFER_FLAG_STATUS_VALID);
        self.control.data_len = incoming.len() as u8;
        if !incoming.is_empty() {
            self.data[..incoming.len()].copy_from_slice(incoming);
        }
        self.clear_apdu_tail(incoming.len());
        true
    }

    pub fn stage_incoming_len(&mut self, incoming_len: usize) -> bool {
        if incoming_len > APDU_PAYLOAD_LENGTH_MAX {
            return false;
        }

        // Invariant: callers have already placed exactly `incoming_len` bytes
        // in `data`; this only publishes the APDU view to Rustlet code.
        self.control.flags &= !(APDU_BUFFER_FLAG_OUTGOING | APDU_BUFFER_FLAG_STATUS_VALID);
        self.control.data_len = incoming_len as u8;
        self.clear_apdu_tail(incoming_len);
        true
    }

    fn clear_apdu_tail(&mut self, used_len: usize) {
        if used_len < APDU_BUFFER_CAPACITY {
            secure_zero(&mut self.data[used_len..]);
        }
    }

    pub(crate) fn incoming_len(&self) -> usize {
        if self.outgoing_started() {
            0
        } else {
            self.control.data_len as usize
        }
    }

    pub(crate) fn incoming_data(&self) -> &[u8] {
        &self.data[..self.incoming_len()]
    }

    pub fn state_bytes(&self) -> &[u8] {
        self.control.state.as_bytes()
    }

    pub fn state_bytes_mut(&mut self) -> &mut [u8] {
        self.control.state.as_mut_bytes()
    }

    pub fn stage_state(&mut self, state: &[u8]) -> bool {
        self.control.state.stage(state)
    }

    pub fn clear_state(&mut self) {
        self.control.state.clear();
    }

    pub fn set_state_len(&mut self, len: usize) -> bool {
        self.control.state.set_len(len)
    }

    pub(crate) fn clear_response(&mut self) {
        self.control.flags &= !APDU_BUFFER_FLAG_STATUS_VALID;
        if self.outgoing_started() {
            self.control.flags &= !APDU_BUFFER_FLAG_OUTGOING;
            self.control.data_len = 0;
        }
    }

    pub fn outgoing_started(&self) -> bool {
        (self.control.flags & APDU_BUFFER_FLAG_OUTGOING) != 0
    }

    fn begin_outgoing(&mut self) {
        self.control.flags |= APDU_BUFFER_FLAG_OUTGOING;
        self.control.data_len = 0;
    }

    pub(crate) fn set_incoming_and_receive(&mut self) -> usize {
        #[cfg(feature = "runtime")]
        {
            let received = crate::syscall::runtime::apdu::set_incoming_and_receive::trigger();
            if received > APDU_PAYLOAD_LENGTH_MAX {
                return 0;
            }
            self.control.data_len = received as u8;
            received
        }

        #[cfg(not(feature = "runtime"))]
        {
            self.incoming_len()
        }
    }

    pub(crate) fn set_outgoing(&mut self) {
        #[cfg(feature = "runtime")]
        {
            crate::syscall::runtime::apdu::set_outgoing::trigger();
        }
        self.begin_outgoing();
    }

    fn declare_outgoing_length(&mut self, len: usize) {
        if len > APDU_PAYLOAD_LENGTH_MAX {
            panic!("APDU outgoing payload exceeds fixed buffer");
        }
        self.begin_outgoing();
        self.control.data_len = len as u8;
    }

    pub(crate) fn set_outgoing_length(&mut self, len: usize) {
        #[cfg(feature = "runtime")]
        {
            crate::syscall::runtime::apdu::set_outgoing_length::trigger(len);
        }
        self.declare_outgoing_length(len);
    }

    pub fn outgoing_len(&self) -> usize {
        if self.outgoing_started() {
            self.control.data_len as usize
        } else {
            0
        }
    }

    pub fn outgoing_data(&self) -> &[u8] {
        &self.data[..self.outgoing_len()]
    }

    pub fn set_status(&mut self, status: ApduStatus) {
        self.control.set_status(status);
    }

    pub fn status(&self) -> ApduStatus {
        self.control.status()
    }

    pub fn exit(&mut self, status: ApduStatus) -> ! {
        self.set_status(status);
        #[cfg(feature = "runtime")]
        crate::syscall::runtime::exit::trigger(status);

        #[cfg(not(feature = "runtime"))]
        loop {
            core::hint::spin_loop();
        }
    }

    pub fn sddispatch_opcode(&self) -> u8 {
        self.header().ins
    }

    pub fn sddispatch_request(&self) -> &[u8] {
        self.incoming_data()
    }

    pub fn set_sddispatch_empty_result(&mut self) -> ApduStatus {
        self.declare_outgoing_length(0);
        let status = ApduStatus::success();
        self.set_status(status);
        status
    }

    pub fn set_sddispatch_bool_result(&mut self, value: bool) -> ApduStatus {
        self.declare_outgoing_length(1);
        self.data[0] = if value {
            SDDISPATCH_BOOL_TRUE
        } else {
            SDDISPATCH_BOOL_FALSE
        };
        let status = ApduStatus::success();
        self.set_status(status);
        status
    }

    pub fn set_sddispatch_u8_result(&mut self, value: u8) -> ApduStatus {
        self.declare_outgoing_length(1);
        self.data[0] = value;
        let status = ApduStatus::success();
        self.set_status(status);
        status
    }

    pub fn set_sddispatch_u16_result(&mut self, value: u16) -> ApduStatus {
        self.declare_outgoing_length(2);
        self.data[0] = (value >> 8) as u8;
        self.data[1] = value as u8;
        let status = ApduStatus::success();
        self.set_status(status);
        status
    }

    pub fn set_sddispatch_bytes_result(&mut self, value: &[u8]) -> ApduStatus {
        if value.len() > APDU_PAYLOAD_LENGTH_MAX {
            let status = ApduStatus::wrong_length();
            self.set_status(status);
            return status;
        }
        self.declare_outgoing_length(value.len());
        self.data[..value.len()].copy_from_slice(value);
        let status = ApduStatus::success();
        self.set_status(status);
        status
    }

    pub fn publish_sddispatch_staged_bytes(&mut self, len: usize) -> ApduStatus {
        if len > APDU_PAYLOAD_LENGTH_MAX {
            let status = ApduStatus::wrong_length();
            self.set_status(status);
            return status;
        }
        self.declare_outgoing_length(len);
        let status = ApduStatus::success();
        self.set_status(status);
        status
    }

    pub fn reject_sddispatch(&mut self, status: ApduStatus) -> ApduStatus {
        self.clear_response();
        self.set_status(status);
        status
    }
}

impl Default for RustletCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ApduStatus {
    pub sw1: u8,
    pub sw2: u8,
}

impl ApduStatus {
    // `90 00` means the command completed successfully.
    pub const fn success() -> Self {
        Self {
            sw1: 0x90,
            sw2: 0x00,
        }
    }

    // `69 85` means the current state does not allow this command yet.
    // Typical examples are "no selected application" or "already installed".
    pub const fn conditions_not_satisfied() -> Self {
        Self {
            sw1: 0x69,
            sw2: 0x85,
        }
    }

    // `69 82` means the command's required security proof is absent or invalid.
    pub const fn security_status_not_satisfied() -> Self {
        Self {
            sw1: 0x69,
            sw2: 0x82,
        }
    }

    // `63 00` reports failure of the authentication value carried by a
    // protocol command such as SCP03 EXTERNAL AUTHENTICATE.
    pub const fn authentication_failed() -> Self {
        Self {
            sw1: 0x63,
            sw2: 0x00,
        }
    }

    // `66 00` is the SCP11 certificate-verification failure status.
    pub const fn certificate_verification_failed() -> Self {
        Self {
            sw1: 0x66,
            sw2: 0x00,
        }
    }

    // `6D 00` means the INS byte does not designate a supported command.
    pub const fn instruction_not_supported() -> Self {
        Self {
            sw1: 0x6d,
            sw2: 0x00,
        }
    }

    // `6A 80` means the payload content is syntactically valid but semantically
    // unacceptable for the command.
    pub const fn wrong_data() -> Self {
        Self {
            sw1: 0x6a,
            sw2: 0x80,
        }
    }

    // `6A 82` means the referenced object does not exist.
    // In current flows this is typically used for an unknown AID on SELECT.
    pub const fn file_not_found() -> Self {
        Self {
            sw1: 0x6a,
            sw2: 0x82,
        }
    }

    // `6A 88` means the requested referenced data object does not exist.
    pub const fn referenced_data_not_found() -> Self {
        Self {
            sw1: 0x6a,
            sw2: 0x88,
        }
    }

    // `6A 86` means that P1/P2 are not valid for the command.
    pub const fn incorrect_p1_p2() -> Self {
        Self {
            sw1: 0x6a,
            sw2: 0x86,
        }
    }

    // `67 00` means the APDU length is not acceptable for the command.
    pub const fn wrong_length() -> Self {
        Self {
            sw1: 0x67,
            sw2: 0x00,
        }
    }

    // `6F 00` is a generic internal failure.
    // We use it as the default status for unexpected runtime or Rustlet errors.
    pub const fn internal_error() -> Self {
        Self {
            sw1: 0x6f,
            sw2: 0x00,
        }
    }

    pub const fn to_word(self) -> u32 {
        (self.sw1 as u32) | ((self.sw2 as u32) << 8)
    }

    pub const fn from_word(word: u32) -> Self {
        Self {
            sw1: (word & 0xff) as u8,
            sw2: ((word >> 8) & 0xff) as u8,
        }
    }
}

pub type AppHandler = unsafe extern "C" fn(state: *mut c_void, buffer: *mut RustletCtx) -> u32;

#[repr(C)]
pub struct SelectedAppVtable {
    pub install: AppHandler,
    pub process_apdu: AppHandler,
}

unsafe impl Sync for SelectedAppVtable {}

#[repr(C)]
pub struct SelectedSecurityDomainVtable {
    pub sddispatch: AppHandler,
}

unsafe impl Sync for SelectedSecurityDomainVtable {}

#[repr(C)]
pub struct SelectedAppDescriptor {
    pub state: *mut c_void,
    pub vtable: *const SelectedAppVtable,
    pub security_domain_vtable: *const SelectedSecurityDomainVtable,
    pub heap: RustletHeapRegion,
}

unsafe impl Sync for SelectedAppDescriptor {}

const _: () =
    assert!(core::mem::size_of::<RustletControlBuffer>() == RUSTLET_CONTROL_BUFFER_CAPACITY);
const _: () = assert!(core::mem::size_of::<RustletCtx>() == APDU_SHARED_REGION_SIZE);

#[cfg(test)]
mod memory_scrubbing_tests {
    use super::{StateSlice, STATE_BUFFER_CAPACITY};

    #[test]
    fn clearing_state_scrubs_the_complete_capacity() {
        let mut state = StateSlice::new();
        state.bytes.fill(0xa5);
        assert!(state.set_len(STATE_BUFFER_CAPACITY));

        state.clear();

        assert!(state.is_empty());
        assert!(state.bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn staging_shorter_state_scrubs_the_old_tail() {
        let mut state = StateSlice::new();
        assert!(state.stage(&[0xa5; STATE_BUFFER_CAPACITY]));

        assert!(state.stage(&[0x11, 0x22]));

        assert_eq!(state.as_bytes(), &[0x11, 0x22]);
        assert!(state.bytes[2..].iter().all(|byte| *byte == 0));
    }
}
