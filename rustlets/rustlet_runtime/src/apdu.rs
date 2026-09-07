use core::marker::PhantomData;

use crate::{ApduStatus, RustletCtx, APDU_PAYLOAD_LENGTH_MAX};

/// Clean command header exposed to Rustlet command logic.
///
/// The fifth APDU byte is intentionally not exposed here: it becomes `Lc` once
/// the command enters [`Receiving`], or `Le` once it enters [`Sending`].
#[derive(Clone, Copy)]
pub struct ApduHeader {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
}

/// Initial APDU command state.
pub enum Command {}

/// APDU state after the incoming phase has been accepted.
pub enum Receiving {}

/// APDU state after the outgoing phase has been declared.
pub enum Sending {}

/// APDU state after the command has completed.
pub enum Done {}

/// Typed APDU session exposed to Rustlet code.
///
/// Methods are available only on the states where the APDU protocol allows
/// them. The raw shared ABI buffer remains hidden behind this state machine.
pub struct Apdu<'a, State> {
    raw: &'a mut RustletCtx,
    _state: PhantomData<State>,
}

impl<'a> Apdu<'a, Command> {
    pub fn new(raw: &'a mut RustletCtx) -> Self {
        raw.clear_response();
        Self {
            raw,
            _state: PhantomData,
        }
    }

    pub fn header(&self) -> ApduHeader {
        let header = self.raw.header();
        ApduHeader {
            cla: header.cla,
            ins: header.ins,
            p1: header.p1,
            p2: header.p2,
        }
    }

    pub fn cla(&self) -> u8 {
        self.header().cla
    }

    pub fn ins(&self) -> u8 {
        self.header().ins
    }

    pub fn p1(&self) -> u8 {
        self.header().p1
    }

    pub fn p2(&self) -> u8 {
        self.header().p2
    }

    pub fn is_select(&self) -> bool {
        let header = self.header();
        header.cla == 0x00 && header.ins == crate::INS_SELECT && header.p1 == 0x04
    }

    pub fn has_incoming(&self) -> bool {
        self.raw.lc() != 0
    }

    pub fn accept(self) -> ApduStatus {
        ApduStatus::success()
    }

    pub fn as_receiving(self) -> Apdu<'a, Receiving> {
        let _ = self.raw.set_incoming_and_receive();
        Apdu {
            raw: self.raw,
            _state: PhantomData,
        }
    }

    pub fn as_sending(self) -> Apdu<'a, Sending> {
        self.raw.set_outgoing();
        Apdu {
            raw: self.raw,
            _state: PhantomData,
        }
    }

    pub fn reject(self, status: ApduStatus) -> ApduStatus {
        status
    }
}

impl Apdu<'_, Receiving> {
    pub fn lc(&self) -> usize {
        self.raw.lc() as usize
    }

    pub fn data(&self) -> &[u8] {
        self.raw.incoming_data()
    }

    pub fn accept(self) -> ApduStatus {
        ApduStatus::success()
    }

    pub fn accept_and_send(self, data: &[u8]) -> ApduStatus {
        stage_response(self.raw, data)
    }

    pub fn reject(self, status: ApduStatus) -> ApduStatus {
        status
    }
}

impl Apdu<'_, Sending> {
    pub fn le(&self) -> usize {
        self.raw.le() as usize
    }

    pub fn send(self, data: &[u8]) -> ApduStatus {
        stage_response(self.raw, data)
    }

    pub fn send_with(self, f: impl FnOnce(&mut [u8]) -> usize) -> ApduStatus {
        self.raw.set_outgoing();
        let len = f(&mut self.raw.data);
        if len > APDU_PAYLOAD_LENGTH_MAX {
            return ApduStatus::wrong_length();
        }
        self.raw.set_outgoing_length(len);
        ApduStatus::success()
    }

    pub fn reject(self, status: ApduStatus) -> ApduStatus {
        status
    }
}

impl Apdu<'_, Done> {
    pub fn status(self, status: ApduStatus) -> ApduStatus {
        status
    }
}

fn stage_response(raw: &mut RustletCtx, data: &[u8]) -> ApduStatus {
    if data.len() > APDU_PAYLOAD_LENGTH_MAX {
        return ApduStatus::wrong_length();
    }
    raw.set_outgoing();
    raw.data[..data.len()].copy_from_slice(data);
    raw.set_outgoing_length(data.len());
    ApduStatus::success()
}

/// Logical APDU header as seen by card-side command logic.
///
/// Under the current short APDU model, `p3` is the fifth command byte and is
/// interpreted as either `Lc` or `Le` depending on how the command later drives
/// the APDU session.
#[derive(Clone, Copy)]
pub struct SEApduHeader {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub p3: u8,
}

/// Common card-side APDU processing interface.
///
/// This trait is the normalization point between kernel-side APDU handlers and
/// Rustlet-side APDU handlers. It intentionally models the APDU as seen by the
/// secure element while one command is being processed:
///
/// - the command header is already known;
/// - command logic may decide to receive incoming bytes;
/// - command logic may decide to prepare outgoing bytes.
///
/// In other words, `SEApdu` is not the low-level `T=0` transport object. The
/// transport loop remains responsible for procedure bytes, `6Cxx`, `61xx`,
/// `GET RESPONSE`, and final `SW1/SW2` emission. The trait only exposes the
/// command-processing surface shared by:
///
/// - the kernel-side APDU wrapper;
/// - the Rustlet ABI buffer;
/// - the kernel bridge object used while a Rustlet call is active.
///
/// The three primitive APDU transitions are:
///
/// - [`SEApdu::set_incoming_and_receive`], which performs the incoming data
///   phase;
/// - [`SEApdu::set_outgoing`], which declares an outgoing exchange and returns
///   the current `Le` interpretation;
/// - [`SEApdu::set_outgoing_length`], which declares how many response bytes
///   are available.
///
pub trait SEApdu {
    /// Returns the logical APDU header currently being processed.
    fn header(&self) -> SEApduHeader;

    /// Returns the mutable APDU payload buffer used for incoming or outgoing
    /// data staging.
    fn buffer_mut(&mut self) -> &mut [u8];

    /// Returns the incoming payload currently visible to command logic.
    fn incoming_data(&self) -> &[u8];

    /// Performs the incoming data phase and returns the number of bytes
    /// received.
    fn set_incoming_and_receive(&mut self) -> usize;

    /// Declares that the current command is an outgoing exchange and returns
    /// the current `Le` interpretation.
    fn set_outgoing(&mut self) -> usize;

    /// Declares how many outgoing bytes have been prepared in the APDU buffer.
    fn set_outgoing_length(&mut self, len: usize);

    /// Returns the `CLA` byte of the current command.
    fn cla(&self) -> u8 {
        self.header().cla
    }

    /// Returns the `INS` byte of the current command.
    fn ins(&self) -> u8 {
        self.header().ins
    }

    /// Returns the `P1` byte of the current command.
    fn p1(&self) -> u8 {
        self.header().p1
    }

    /// Returns the `P2` byte of the current command.
    fn p2(&self) -> u8 {
        self.header().p2
    }

    /// Returns the fifth command byte (`P3`), interpreted later as either
    /// `Lc` or `Le` depending on the APDU case.
    fn p3(&self) -> u8 {
        self.header().p3
    }
}

impl SEApdu for RustletCtx {
    fn header(&self) -> SEApduHeader {
        let header = self.header();
        SEApduHeader {
            cla: header.cla,
            ins: header.ins,
            p1: header.p1,
            p2: header.p2,
            p3: header.lc,
        }
    }

    fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn incoming_data(&self) -> &[u8] {
        self.incoming_data()
    }

    fn set_incoming_and_receive(&mut self) -> usize {
        self.set_incoming_and_receive()
    }

    fn set_outgoing(&mut self) -> usize {
        self.set_outgoing();
        self.le() as usize
    }

    fn set_outgoing_length(&mut self, len: usize) {
        self.set_outgoing_length(len);
    }
}
