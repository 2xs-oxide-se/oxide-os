use core::marker::PhantomData;
#[cfg(test)]
use rustlet_runtime::RustletCtx;
use rustlet_runtime::{SEApdu, SEApduHeader, APDU_PAYLOAD_LENGTH_MAX};

use crate::transport_layer::TransportLayer;
use core::ptr::NonNull;

const ATR_TS_DIRECT_CONVENTION: u8 = 0x3b;
const ATR_T0_TA1_PRESENT: u8 = 0x10;
const ATR_TA1_DEFAULT_SERIAL_RATE: u8 = 0x11;
const APDU_BUFFER_CAPACITY: usize = 256;
const INS_GET_RESPONSE: u8 = 0xc0;
const LAYER_FLAG_SECURE_RESPONSE_REQUIRED: u8 = 1 << 0;

type TransportHandle = NonNull<dyn TransportLayer>;

/// Base T=0 APDU manager built on top of a byte transport.
///
/// This object owns the T=0 transport state machine, including pending
/// response handling and byte-level completion rules.
pub struct T0ApduManager<T: TransportLayer + 'static> {
    transport: T,
    pending_response: PendingResponse,
    #[cfg(test)]
    pending_response_test_buffer: [u8; APDU_BUFFER_CAPACITY],
}

#[derive(Clone, Copy)]
pub struct ApduHeader {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub ln: u8,
}

/// Transport-owned APDU session.
///
/// Invariant: this object remains kernel-owned even when command logic receives
/// an `SEApdu` view over it.
#[allow(dead_code)]
pub struct TransportApdu {
    transport: Option<TransportHandle>,
    header: ApduHeader,
    #[cfg(test)]
    buffer: [u8; APDU_BUFFER_CAPACITY],
    #[cfg(not(test))]
    buffer: *mut u8,
    buffer_len: usize,
    incoming_received: bool,
    outgoing_expected: bool,
    // Invariant: layer-private flags are reset for every received APDU.
    layer_flags: u8,
    outgoing_len: usize,
}

pub struct Apdu<'a> {
    transport: &'a mut TransportApdu,
}

/// Typestate marker for an unassigned secondary buffer.
pub(crate) struct SecondaryAvailable;

/// Typestate marker for a secondary buffer owned by secure messaging.
pub(crate) struct SecondaryCryptoScratch;

/// Exclusive typed view over the secondary half of the shared Rustlet page.
///
/// The state marker is zero-sized. It prevents protocol code from treating an
/// ABI-state view as cryptographic scratch without an explicit transition.
pub(crate) struct SecondaryBuffer<State> {
    ptr: *mut u8,
    _state: PhantomData<State>,
}

impl SecondaryBuffer<SecondaryAvailable> {
    /// Assigns the currently available secondary half to secure messaging.
    #[inline(always)]
    pub(crate) fn begin_crypto(self) -> SecondaryBuffer<SecondaryCryptoScratch> {
        SecondaryBuffer {
            ptr: self.ptr,
            _state: PhantomData,
        }
    }
}

impl SecondaryBuffer<SecondaryCryptoScratch> {
    /// Returns the bytes while the buffer is owned by secure messaging.
    #[inline(always)]
    pub(crate) fn bytes_mut(
        &mut self,
    ) -> &mut [u8; rustlet_runtime::RUSTLET_CONTROL_BUFFER_CAPACITY] {
        unsafe { &mut *(self.ptr as *mut [u8; rustlet_runtime::RUSTLET_CONTROL_BUFFER_CAPACITY]) }
    }

    /// Releases secure-messaging ownership after the transform result is used.
    #[inline(always)]
    pub(crate) fn finish(self) {}
}

/// Assigns a dedicated static buffer to the same crypto-scratch typestate.
///
/// Rustlet-backed Security Domains use this constructor because SDDISPATCH
/// owns the actual shared page while the secure-channel proxy is executing.
pub(crate) fn acquire_proxy_crypto_scratch(
    bytes: &'static mut [u8; rustlet_runtime::RUSTLET_CONTROL_BUFFER_CAPACITY],
) -> SecondaryBuffer<SecondaryCryptoScratch> {
    SecondaryBuffer {
        ptr: bytes.as_mut_ptr(),
        _state: PhantomData,
    }
}

// Invariant: pending metadata refers to bytes left in the shared APDU payload.
// Only GET RESPONSE may consume them before the payload is scrubbed.
struct PendingResponse {
    offset: usize,
    len: usize,
    completion_status: ApduStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApduStatus {
    pub sw1: u8,
    pub sw2: u8,
}

#[allow(dead_code)]
impl ApduStatus {
    pub const fn success() -> Self {
        Self {
            sw1: 0x90,
            sw2: 0x00,
        }
    }

    pub const fn conditions_not_satisfied() -> Self {
        Self {
            sw1: 0x69,
            sw2: 0x85,
        }
    }

    /// Returns `69 82`, used when the command's security proof is absent or invalid.
    pub const fn security_status_not_satisfied() -> Self {
        Self {
            sw1: 0x69,
            sw2: 0x82,
        }
    }

    pub const fn authentication_failed() -> Self {
        Self {
            sw1: 0x63,
            sw2: 0x00,
        }
    }

    /// Returns `66 00`, the SCP11 certificate-verification failure status.
    pub const fn certificate_verification_failed() -> Self {
        Self {
            sw1: 0x66,
            sw2: 0x00,
        }
    }

    pub const fn instruction_not_supported() -> Self {
        Self {
            sw1: 0x6d,
            sw2: 0x00,
        }
    }

    pub const fn wrong_data() -> Self {
        Self {
            sw1: 0x6a,
            sw2: 0x80,
        }
    }

    pub const fn file_not_found() -> Self {
        Self {
            sw1: 0x6a,
            sw2: 0x82,
        }
    }

    pub const fn referenced_data_not_found() -> Self {
        Self {
            sw1: 0x6a,
            sw2: 0x88,
        }
    }

    pub const fn incorrect_p1_p2() -> Self {
        Self {
            sw1: 0x6a,
            sw2: 0x86,
        }
    }

    pub const fn more_data_available() -> Self {
        Self {
            sw1: 0x63,
            sw2: 0x10,
        }
    }

    pub const fn wrong_length() -> Self {
        Self {
            sw1: 0x67,
            sw2: 0x00,
        }
    }

    pub const fn correct_length(len: usize) -> Self {
        Self {
            sw1: 0x6c,
            sw2: if len >= APDU_BUFFER_CAPACITY {
                0
            } else {
                len as u8
            },
        }
    }

    pub const fn response_bytes_available(len: usize) -> Self {
        Self {
            sw1: 0x61,
            sw2: if len >= APDU_BUFFER_CAPACITY {
                0
            } else {
                len as u8
            },
        }
    }
}

impl<T: TransportLayer + 'static> T0ApduManager<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            pending_response: PendingResponse::new(),
            #[cfg(test)]
            pending_response_test_buffer: [0; APDU_BUFFER_CAPACITY],
        }
    }

    pub fn send_atr(&mut self, historical_bytes: &[u8]) {
        send_apdu_atr(&mut self.transport, historical_bytes);
    }

    pub fn receive_command(&mut self) -> Option<TransportApdu> {
        let transport_apdu = self.read_apdu();
        if !is_valid_t0_instruction(transport_apdu.ins()) {
            // T=0 uses 6X and 9X as status-byte classes. Such an INS cannot
            // be acknowledged without making the data phase ambiguous.
            send_apdu_status(&mut self.transport, ApduStatus::instruction_not_supported());
            return None;
        }
        if self.handle_get_response(&transport_apdu) {
            return None;
        }
        if self.pending_response.is_active() {
            send_apdu_status(&mut self.transport, ApduStatus::conditions_not_satisfied());
            return None;
        }
        // The timer exclusively emits the first and subsequent NULL bytes.
        crate::time_manager::arm_null_bytes();
        Some(transport_apdu)
    }

    pub fn complete_command(&mut self, transport_apdu: &mut TransportApdu, status: ApduStatus) {
        // Invariant: handlers never emit wire bytes directly. They only mutate
        // APDU session state, and completion policy is decided here.
        if transport_apdu.has_outgoing_data() {
            if transport_apdu.incoming_was_received() {
                let outgoing = transport_apdu.outgoing_data();
                #[cfg(test)]
                self.pending_response_test_buffer[..outgoing.len()].copy_from_slice(outgoing);
                self.pending_response.store(outgoing.len(), status);
                let pending_len = self.pending_response.remaining_len();
                send_apdu_status(
                    &mut self.transport,
                    ApduStatus::response_bytes_available(pending_len),
                );
                #[cfg(test)]
                transport_apdu.clear_payload_storage();
                return;
            }

            let requested_len = transport_apdu.requested_outgoing_len();
            if requested_len != transport_apdu.outgoing_length() {
                send_apdu_status(
                    &mut self.transport,
                    ApduStatus::correct_length(transport_apdu.outgoing_length()),
                );
                transport_apdu.clear_payload_storage();
                return;
            }

            if transport_apdu.outgoing_length() != 0 {
                send_procedure_byte(&mut self.transport, transport_apdu.ins());
                transport_apdu.send_bytes();
            }
        }

        send_apdu_status(&mut self.transport, status);
        transport_apdu.clear_payload_storage();
    }

    fn handle_get_response(&mut self, apdu: &TransportApdu) -> bool {
        if !is_get_response(apdu) {
            return false;
        }

        if !self.pending_response.is_active() {
            send_apdu_status(&mut self.transport, ApduStatus::conditions_not_satisfied());
            return true;
        }

        let requested_len = if apdu.ln() == 0 {
            APDU_BUFFER_CAPACITY
        } else {
            apdu.ln() as usize
        };
        send_procedure_byte(&mut self.transport, INS_GET_RESPONSE);
        let Some((range, status)) = self.pending_response.take_next_chunk(requested_len) else {
            send_apdu_status(&mut self.transport, ApduStatus::conditions_not_satisfied());
            return true;
        };
        #[cfg(not(test))]
        let pending_bytes =
            unsafe { &*(transport_apdu_backing_buffer() as *const [u8; APDU_BUFFER_CAPACITY]) };
        #[cfg(test)]
        let pending_bytes = &self.pending_response_test_buffer;
        send_buffer(&mut self.transport, &pending_bytes[range]);
        let response_complete = !self.pending_response.is_active();
        send_apdu_status(&mut self.transport, status);
        if response_complete {
            #[cfg(not(test))]
            oxi_core::core::secure_zero(unsafe {
                &mut *(transport_apdu_backing_buffer() as *mut [u8; APDU_BUFFER_CAPACITY])
            });
            #[cfg(test)]
            oxi_core::core::secure_zero(&mut self.pending_response_test_buffer);
        }
        true
    }

    fn read_apdu(&mut self) -> TransportApdu {
        // Only the 5-byte header is read here. Incoming data is received later
        // only if the command logic requests it.
        let transport_handle = NonNull::from(&mut self.transport as &mut dyn TransportLayer);
        let header = ApduHeader {
            cla: self.transport.receive_byte(),
            ins: self.transport.receive_byte(),
            p1: self.transport.receive_byte(),
            p2: self.transport.receive_byte(),
            ln: self.transport.receive_byte(),
        };

        TransportApdu::new(header, Some(transport_handle))
    }
}

#[allow(dead_code)]
impl TransportApdu {
    fn new(header: ApduHeader, transport: Option<TransportHandle>) -> Self {
        Self {
            transport,
            header,
            #[cfg(test)]
            buffer: [0u8; APDU_BUFFER_CAPACITY],
            #[cfg(not(test))]
            buffer: transport_apdu_backing_buffer(),
            buffer_len: 0,
            incoming_received: false,
            outgoing_expected: false,
            layer_flags: 0,
            outgoing_len: 0,
        }
    }

    pub(crate) fn set_secure_response_required(&mut self, required: bool) {
        if required {
            self.layer_flags |= LAYER_FLAG_SECURE_RESPONSE_REQUIRED;
        } else {
            self.layer_flags &= !LAYER_FLAG_SECURE_RESPONSE_REQUIRED;
        }
    }

    pub(crate) const fn secure_response_required(&self) -> bool {
        (self.layer_flags & LAYER_FLAG_SECURE_RESPONSE_REQUIRED) != 0
    }

    fn buffer(&self) -> &[u8; APDU_BUFFER_CAPACITY] {
        #[cfg(test)]
        {
            &self.buffer
        }
        #[cfg(not(test))]
        {
            // Invariant: firmware APDU transport uses the APDU half of the
            // Rustlet shared page as its backing store. Command handlers must
            // not keep slices across a later operation that republishes this
            // page for a different Rustlet call.
            unsafe { &*(self.buffer as *const [u8; APDU_BUFFER_CAPACITY]) }
        }
    }

    fn buffer_mut(&mut self) -> &mut [u8; APDU_BUFFER_CAPACITY] {
        #[cfg(test)]
        {
            &mut self.buffer
        }
        #[cfg(not(test))]
        {
            // Invariant: one APDU command is processed at a time, and the page
            // is scrubbed after T=0 completion.
            unsafe { &mut *(self.buffer as *mut [u8; APDU_BUFFER_CAPACITY]) }
        }
    }

    pub fn as_apdu(&mut self) -> Apdu<'_> {
        Apdu { transport: self }
    }

    pub fn cla(&self) -> u8 {
        self.header.cla
    }

    pub fn ins(&self) -> u8 {
        self.header.ins
    }

    pub fn p1(&self) -> u8 {
        self.header.p1
    }

    pub fn p2(&self) -> u8 {
        self.header.p2
    }

    pub fn ln(&self) -> u8 {
        self.header.ln
    }

    fn set_incoming_and_receive(&mut self) -> usize {
        if self.incoming_received {
            return self.buffer_len;
        }

        // The header is already present. This transition performs the incoming
        // data phase and makes the payload visible to command logic.
        let incoming_len = self.header.ln as usize;
        if incoming_len > APDU_PAYLOAD_LENGTH_MAX {
            panic!("APDU incoming payload exceeds fixed buffer");
        }

        self.send_transport_byte(self.header.ins);
        for offset in 0..incoming_len {
            let byte = self.receive_transport_byte();
            self.buffer_mut()[offset] = byte;
        }

        self.buffer_len = incoming_len;
        self.incoming_received = true;
        crate::time_manager::arm_null_bytes();
        incoming_len
    }

    pub fn incoming_was_received(&self) -> bool {
        self.incoming_received
    }

    pub fn incoming_len(&self) -> usize {
        self.buffer_len
    }

    pub fn incoming_data(&self) -> &[u8] {
        &self.buffer()[..self.buffer_len]
    }

    pub(crate) fn replace_incoming_for_layer(&mut self, data: &[u8]) -> bool {
        if !self.incoming_received || data.len() > APDU_PAYLOAD_LENGTH_MAX {
            return false;
        }
        self.buffer_mut()[..data.len()].copy_from_slice(data);
        self.buffer_len = data.len();
        true
    }

    pub fn outgoing_started(&self) -> bool {
        self.outgoing_expected
    }

    pub fn requested_outgoing_len(&self) -> usize {
        if self.header.ln == 0 {
            APDU_BUFFER_CAPACITY
        } else {
            self.header.ln as usize
        }
    }

    fn set_outgoing(&mut self) -> usize {
        // From this point on, the buffer is treated as response storage and
        // `ln` is interpreted as the requested outgoing length hint.
        self.outgoing_expected = true;
        self.outgoing_len = 0;
        self.buffer_len = 0;
        self.header.ln as usize
    }

    fn set_outgoing_length(&mut self, len: usize) {
        if !self.outgoing_expected {
            panic!("set_outgoing_length called before set_outgoing");
        }
        // This transition only fixes the logical outgoing length. The actual
        // wire behavior is still decided by the transport manager.
        if len > APDU_PAYLOAD_LENGTH_MAX {
            panic!("APDU outgoing payload exceeds fixed buffer");
        }
        self.outgoing_len = len;
        self.buffer_len = len;
    }

    pub fn has_outgoing_data(&self) -> bool {
        self.outgoing_expected && self.outgoing_len != 0
    }

    pub fn outgoing_data(&self) -> &[u8] {
        &self.buffer()[..self.outgoing_len]
    }

    pub fn outgoing_length(&self) -> usize {
        self.outgoing_len
    }

    pub(crate) fn append_outgoing_for_layer(&mut self, data: &[u8]) -> bool {
        if !self.outgoing_expected {
            return data.is_empty();
        }
        let new_len = self.outgoing_len.saturating_add(data.len());
        if new_len > APDU_PAYLOAD_LENGTH_MAX {
            return false;
        }
        let start = self.outgoing_len;
        self.buffer_mut()[start..new_len].copy_from_slice(data);
        self.outgoing_len = new_len;
        self.buffer_len = new_len;
        true
    }

    pub(crate) fn replace_outgoing_for_layer(&mut self, data: &[u8]) -> bool {
        if !self.outgoing_expected || data.len() > APDU_PAYLOAD_LENGTH_MAX {
            return false;
        }
        self.buffer_mut()[..data.len()].copy_from_slice(data);
        self.outgoing_len = data.len();
        self.buffer_len = data.len();
        true
    }

    pub(crate) fn receive_incoming_for_runtime(&mut self) -> usize {
        self.set_incoming_and_receive()
    }

    pub(crate) fn receive_incoming_into_for_runtime(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.incoming_received {
            let incoming_len = self.buffer_len;
            if out.len() < incoming_len {
                return None;
            }
            out[..incoming_len].copy_from_slice(self.incoming_data());
            return Some(incoming_len);
        }

        let incoming_len = self.header.ln as usize;
        if incoming_len > APDU_PAYLOAD_LENGTH_MAX || out.len() < incoming_len {
            return None;
        }

        // Invariant: this is the zero-copy Rustlet path. Incoming T=0 bytes are
        // written directly into the user-visible APDU half of RustletCtx, so
        // the transport APDU does not stage a second payload copy.
        self.send_transport_byte(self.header.ins);
        for slot in out.iter_mut().take(incoming_len) {
            *slot = self.receive_transport_byte();
        }
        self.buffer_len = incoming_len;
        self.incoming_received = true;
        crate::time_manager::arm_null_bytes();
        Some(incoming_len)
    }

    pub(crate) fn begin_outgoing_for_runtime(&mut self) -> usize {
        self.set_outgoing()
    }

    pub(crate) fn set_outgoing_length_for_runtime(&mut self, len: usize) {
        self.set_outgoing_length(len);
    }

    /// Abandons an interrupted command while keeping the T=0 byte stream aligned.
    ///
    /// An unread incoming phase is consumed and discarded. If the Rustlet had
    /// already selected the outgoing phase, the advertised response length is
    /// completed with zero bytes. The normal APDU completion path remains
    /// responsible for sending the final status word.
    pub(crate) fn abort_remaining_io(&mut self) {
        if self.header.ln == 0 {
            return;
        }

        if self.outgoing_expected {
            for _ in 0..self.header.ln {
                self.send_transport_byte(0x00);
            }
            oxi_core::core::secure_zero(self.buffer_mut());
            self.buffer_len = 0;
            self.outgoing_len = 0;
            self.outgoing_expected = false;
            return;
        }

        if !self.incoming_received {
            self.send_transport_byte(self.header.ins);
            for _ in 0..self.header.ln {
                let _ = self.receive_transport_byte();
            }
            oxi_core::core::secure_zero(self.buffer_mut());
            self.buffer_len = 0;
            self.incoming_received = true;
        }
    }

    pub(crate) fn clear_payload_storage(&mut self) {
        oxi_core::core::secure_zero(self.buffer_mut());
        self.buffer_len = 0;
        self.incoming_received = false;
        self.outgoing_expected = false;
        self.outgoing_len = 0;
    }

    pub fn send_bytes(&self) {
        if !self.outgoing_expected {
            panic!("send_bytes called before set_outgoing");
        }

        for &byte in &self.buffer()[..self.outgoing_len] {
            self.send_transport_byte(byte);
        }
    }

    fn send_transport_byte(&self, byte: u8) {
        let Some(mut transport) = self.transport else {
            panic!("transport byte send attempted without an attached transport");
        };
        unsafe {
            crate::time_manager::before_response_byte();
            transport.as_mut().send_byte(byte);
        }
    }

    fn receive_transport_byte(&self) -> u8 {
        let Some(mut transport) = self.transport else {
            panic!("transport byte receive attempted without an attached transport");
        };
        unsafe { transport.as_mut().receive_byte() }
    }
}

#[cfg(not(test))]
fn transport_apdu_backing_buffer() -> *mut u8 {
    let Some(region) = oxi_core::core::target::isolated_app_gate_region() else {
        panic!("target does not expose an APDU backing region");
    };
    let data_base = region.base + rustlet_runtime::RUSTLET_CONTROL_BUFFER_CAPACITY;
    let data_end = data_base + APDU_BUFFER_CAPACITY;
    if data_end > region.base + region.size {
        panic!("APDU backing region is smaller than RustletCtx");
    }
    data_base as *mut u8
}

/// Acquires the secondary half of the shared APDU page as an available token.
///
/// Invariant: the single-threaded APDU loop may create this root token only
/// before a Rustlet entry or after its returned state has been copied into the
/// registry. All safe operations after acquisition are typestate transitions.
#[cfg(not(test))]
pub(crate) fn acquire_secondary_buffer() -> SecondaryBuffer<SecondaryAvailable> {
    let Some(region) = oxi_core::core::target::isolated_app_gate_region() else {
        panic!("target does not expose an APDU transform workspace");
    };
    if region.size < rustlet_runtime::APDU_SHARED_REGION_SIZE {
        panic!("APDU backing region is smaller than RustletCtx");
    }
    SecondaryBuffer {
        ptr: region.base as *mut u8,
        _state: PhantomData,
    }
}

#[cfg(test)]
pub(crate) fn acquire_secondary_buffer() -> SecondaryBuffer<SecondaryAvailable> {
    static mut WORKSPACE: RustletCtx = RustletCtx::new();
    SecondaryBuffer {
        ptr: core::ptr::addr_of_mut!(WORKSPACE).cast::<u8>(),
        _state: PhantomData,
    }
}

impl PendingResponse {
    const fn new() -> Self {
        Self {
            offset: 0,
            len: 0,
            completion_status: ApduStatus::success(),
        }
    }

    fn is_active(&self) -> bool {
        self.offset < self.len
    }

    fn store(&mut self, len: usize, completion_status: ApduStatus) {
        if len > APDU_PAYLOAD_LENGTH_MAX {
            panic!("pending response exceeds T=0 buffer");
        }

        self.offset = 0;
        self.len = len;
        self.completion_status = completion_status;
    }

    fn remaining_len(&self) -> usize {
        self.len.saturating_sub(self.offset)
    }

    fn take_next_chunk(
        &mut self,
        requested_len: usize,
    ) -> Option<(core::ops::Range<usize>, ApduStatus)> {
        let remaining_len = self.remaining_len();
        if remaining_len == 0 {
            return None;
        }

        let chunk_len = remaining_len.min(requested_len);
        let end = self.offset + chunk_len;
        let range = self.offset..end;
        self.offset = end;

        let status = if self.remaining_len() == 0 {
            self.len = 0;
            self.offset = 0;
            self.completion_status
        } else {
            ApduStatus::response_bytes_available(self.remaining_len())
        };
        Some((range, status))
    }
}

#[allow(dead_code)]
impl Apdu<'_> {
    pub fn incoming_was_received(&self) -> bool {
        self.transport.incoming_was_received()
    }

    pub fn transport_ptr(&mut self) -> *mut TransportApdu {
        self.transport as *mut TransportApdu
    }

    pub fn outgoing_length(&self) -> usize {
        self.transport.outgoing_len
    }

    pub fn is_outgoing(&self) -> bool {
        self.transport.outgoing_expected
    }
}

impl SEApdu for Apdu<'_> {
    fn header(&self) -> SEApduHeader {
        SEApduHeader {
            cla: self.transport.cla(),
            ins: self.transport.ins(),
            p1: self.transport.p1(),
            p2: self.transport.p2(),
            p3: self.transport.ln(),
        }
    }

    fn buffer_mut(&mut self) -> &mut [u8] {
        self.transport.buffer_mut()
    }

    fn incoming_data(&self) -> &[u8] {
        &self.transport.buffer()[..self.transport.buffer_len]
    }

    fn set_incoming_and_receive(&mut self) -> usize {
        self.transport.set_incoming_and_receive()
    }

    fn set_outgoing(&mut self) -> usize {
        self.transport.set_outgoing()
    }

    fn set_outgoing_length(&mut self, len: usize) {
        self.transport.set_outgoing_length(len);
    }
}

fn send_apdu_atr(transport: &mut dyn TransportLayer, historical_bytes: &[u8]) {
    if historical_bytes.len() > 0x0f {
        panic!("ATR historical bytes exceed T=0 envelope");
    }

    // Oxide SE currently emits a compact direct-convention ATR with one TA1.
    send_transport_byte(transport, ATR_TS_DIRECT_CONVENTION);
    send_transport_byte(transport, ATR_T0_TA1_PRESENT | historical_bytes.len() as u8);
    send_transport_byte(transport, ATR_TA1_DEFAULT_SERIAL_RATE);

    for &byte in historical_bytes {
        send_transport_byte(transport, byte);
    }
}

fn is_get_response(apdu: &TransportApdu) -> bool {
    apdu.ins() == INS_GET_RESPONSE && apdu.p1() == 0x00 && apdu.p2() == 0x00
}

/// Returns whether an instruction byte is unambiguous on a T=0 transport.
pub(crate) const fn is_valid_t0_instruction(ins: u8) -> bool {
    !matches!(ins & 0xf0, 0x60 | 0x90)
}

fn send_apdu_status(transport: &mut dyn TransportLayer, status: ApduStatus) {
    // Status words are always appended by the transport layer.
    send_transport_byte(transport, status.sw1);
    send_transport_byte(transport, status.sw2);
}

fn send_buffer(transport: &mut dyn TransportLayer, buf: &[u8]) {
    // This is the raw transport send path used for deferred response bytes.
    for &byte in buf {
        send_transport_byte(transport, byte);
    }
}

fn send_procedure_byte(transport: &mut dyn TransportLayer, byte: u8) {
    send_transport_byte(transport, byte);
}

fn send_transport_byte(transport: &mut dyn TransportLayer, byte: u8) {
    crate::time_manager::before_response_byte();
    transport.send_byte(byte);
}

#[cfg(test)]
mod tests {
    use super::{
        is_valid_t0_instruction, ApduHeader, ApduStatus, PendingResponse, SecondaryAvailable,
        SecondaryBuffer, SecondaryCryptoScratch, T0ApduManager, TransportApdu, TransportHandle,
    };
    use crate::transport_layer::TransportLayer;
    use core::ptr::NonNull;
    use std::boxed::Box;
    use std::collections::VecDeque;
    use std::vec::Vec;

    #[derive(Default)]
    struct TestTransport {
        sent: Vec<u8>,
        incoming: VecDeque<u8>,
    }

    impl TransportLayer for TestTransport {
        fn send_byte(&mut self, byte: u8) {
            self.sent.push(byte);
        }

        fn receive_byte(&mut self) -> u8 {
            self.incoming.pop_front().expect("test incoming byte")
        }
    }

    #[test]
    fn secondary_buffer_typestate_is_pointer_sized() {
        assert_eq!(
            core::mem::size_of::<SecondaryBuffer<SecondaryAvailable>>(),
            core::mem::size_of::<*mut u8>()
        );
        assert_eq!(
            core::mem::size_of::<SecondaryBuffer<SecondaryCryptoScratch>>(),
            core::mem::size_of::<*mut u8>()
        );
    }

    #[test]
    fn pending_response_keeps_only_metadata() {
        assert!(core::mem::size_of::<PendingResponse>() < super::APDU_BUFFER_CAPACITY);
    }

    #[test]
    fn t0_instruction_validation_rejects_status_byte_classes() {
        for ins in 0x60..=0x6f {
            assert!(!is_valid_t0_instruction(ins));
        }
        for ins in 0x90..=0x9f {
            assert!(!is_valid_t0_instruction(ins));
        }
        for ins in [0x00, 0x5f, 0x70, 0x8f, 0xa0, 0xff] {
            assert!(is_valid_t0_instruction(ins));
        }
    }

    #[test]
    fn ambiguous_t0_instruction_is_rejected_before_dispatch() {
        let transport = TestTransport {
            sent: Vec::new(),
            incoming: [0x80, 0x90, 0x00, 0x00, 0x10].into_iter().collect(),
        };
        let mut manager = T0ApduManager::new(transport);

        assert!(manager.receive_command().is_none());
        assert_eq!(manager.transport.sent, [0x6d, 0x00]);
    }

    #[test]
    fn secure_response_policy_is_scoped_to_one_transport_apdu() {
        let header = ApduHeader {
            cla: 0x84,
            ins: 0xCA,
            p1: 0x00,
            p2: 0x00,
            ln: 0x00,
        };
        let mut protected = TransportApdu::new(header, None);
        assert!(!protected.secure_response_required());
        protected.set_secure_response_required(true);
        assert!(protected.secure_response_required());

        let next = TransportApdu::new(header, None);
        assert!(!next.secure_response_required());
    }

    #[test]
    fn get_response_reads_the_deferred_payload_and_scrubs_it_afterward() {
        let transport = TestTransport {
            sent: Vec::new(),
            incoming: [0x80, 0xDA, 0x00, 0x00, 0x02, 0x11, 0x22]
                .into_iter()
                .collect(),
        };
        let mut manager = T0ApduManager::new(transport);
        let mut command = manager.receive_command().expect("initial command");
        assert_eq!(command.set_incoming_and_receive(), 2);
        command.set_outgoing();
        command.buffer_mut()[..3].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        command.set_outgoing_length(3);

        manager.complete_command(&mut command, ApduStatus::success());
        manager
            .transport
            .incoming
            .extend([0x00, 0xC0, 0x00, 0x00, 0x03]);

        assert!(manager.receive_command().is_none());
        assert_eq!(
            manager.transport.sent,
            [0xDA, 0x61, 0x03, 0xC0, 0xAA, 0xBB, 0xCC, 0x90, 0x00]
        );
        assert!(!manager.pending_response.is_active());
        assert!(manager
            .pending_response_test_buffer
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn immediate_response_scrubs_the_apdu_payload_after_transmission() {
        let transport = TestTransport {
            sent: Vec::new(),
            incoming: [0x80, 0xCA, 0x00, 0x00, 0x03].into_iter().collect(),
        };
        let mut manager = T0ApduManager::new(transport);
        let mut command = manager.receive_command().expect("command");
        command.set_outgoing();
        command.buffer_mut()[..3].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        command.set_outgoing_length(3);

        manager.complete_command(&mut command, ApduStatus::success());

        assert_eq!(manager.transport.sent, [0xCA, 0xAA, 0xBB, 0xCC, 0x90, 0x00]);
        assert!(command.buffer.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn get_response_can_consume_the_same_payload_in_multiple_chunks() {
        let transport = TestTransport {
            sent: Vec::new(),
            incoming: [0x80, 0xDA, 0x00, 0x00, 0x01, 0x11].into_iter().collect(),
        };
        let mut manager = T0ApduManager::new(transport);
        let mut command = manager.receive_command().expect("initial command");
        assert_eq!(command.set_incoming_and_receive(), 1);
        command.set_outgoing();
        command.buffer_mut()[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        command.set_outgoing_length(5);
        manager.complete_command(&mut command, ApduStatus::success());

        manager
            .transport
            .incoming
            .extend([0x00, 0xC0, 0x00, 0x00, 0x02]);
        assert!(manager.receive_command().is_none());
        assert!(manager.pending_response.is_active());

        manager
            .transport
            .incoming
            .extend([0x00, 0xC0, 0x00, 0x00, 0x03]);
        assert!(manager.receive_command().is_none());
        assert_eq!(
            manager.transport.sent,
            [0xDA, 0x61, 0x05, 0xC0, 1, 2, 0x61, 0x03, 0xC0, 3, 4, 5, 0x90, 0x00,]
        );
        assert!(!manager.pending_response.is_active());
    }

    fn transport_apdu(header: ApduHeader, incoming: &[u8]) -> (TransportApdu, *mut TestTransport) {
        let transport = Box::leak(Box::new(TestTransport {
            sent: Vec::new(),
            incoming: incoming.iter().copied().collect(),
        }));
        let transport_ptr = transport as *mut TestTransport;
        let handle: TransportHandle = NonNull::from(transport as &mut dyn TransportLayer);
        (TransportApdu::new(header, Some(handle)), transport_ptr)
    }

    #[test]
    fn abort_drains_unread_incoming_payload() {
        let (mut apdu, transport_ptr) = transport_apdu(
            ApduHeader {
                cla: 0x80,
                ins: 0xE6,
                p1: 0,
                p2: 0,
                ln: 3,
            },
            &[0xAA, 0xBB, 0xCC],
        );

        apdu.abort_remaining_io();

        let transport = unsafe { &*transport_ptr };
        assert_eq!(transport.sent, [0xE6]);
        assert!(transport.incoming.is_empty());
        assert!(apdu.incoming_was_received());
        assert_eq!(apdu.incoming_len(), 0);
        assert!(apdu.buffer.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn abort_completes_started_outgoing_payload_with_zeroes() {
        let (mut apdu, transport_ptr) = transport_apdu(
            ApduHeader {
                cla: 0x80,
                ins: 0xCA,
                p1: 0,
                p2: 0,
                ln: 4,
            },
            &[],
        );
        apdu.set_outgoing();

        apdu.abort_remaining_io();

        let transport = unsafe { &*transport_ptr };
        assert_eq!(transport.sent, [0, 0, 0, 0]);
        assert!(!apdu.outgoing_started());
        assert_eq!(apdu.outgoing_length(), 0);
    }

    #[test]
    fn abort_is_a_noop_after_incoming_payload_was_received() {
        let (mut apdu, transport_ptr) = transport_apdu(
            ApduHeader {
                cla: 0x80,
                ins: 0xE6,
                p1: 0,
                p2: 0,
                ln: 2,
            },
            &[0x11, 0x22],
        );
        assert_eq!(apdu.set_incoming_and_receive(), 2);
        let sent_before_abort = unsafe { (&*transport_ptr).sent.clone() };

        apdu.abort_remaining_io();

        assert_eq!(unsafe { &*transport_ptr }.sent, sent_before_abort);
        assert_eq!(apdu.incoming_data(), &[0x11, 0x22]);
    }
}
