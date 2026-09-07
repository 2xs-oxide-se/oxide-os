use crate::apdu_manager::{ApduStatus, T0ApduManager, TransportApdu};
use crate::transport_layer::TransportLayer;
use rustlet_runtime::SEApduHeader;

/// Protocol-layer interface above byte transport.
///
/// Implementors own command reception and command completion policy for one
/// APDU layer. Higher layers may wrap lower ones without exposing transport
/// details to the kernel dispatcher.
pub trait ApduLayer {
    fn send_atr(&mut self, historical_bytes: &[u8]);
    fn receive_command(&mut self) -> Option<ApduCommand>;
    fn complete_command(&mut self, completion: ApduCompletion<'_>);
}

/// APDU command view exposed by `ApduLayer`.
///
/// This object hides the concrete transport-owned APDU representation while
/// still allowing the dispatcher to inspect the header and to obtain an
/// `SEApdu` session view for command processing.
pub struct ApduCommand {
    transport_apdu: TransportApdu,
}

/// APDU completion object returned to an `ApduLayer`.
///
/// This keeps completion metadata grouped as one boundary object instead of
/// leaking transport-owned session details into the dispatcher.
pub struct ApduCompletion<'a> {
    pub(crate) command: &'a mut ApduCommand,
    pub(crate) status: ApduStatus,
}

impl ApduCommand {
    #[allow(dead_code)]
    pub fn header(&self) -> SEApduHeader {
        SEApduHeader {
            cla: self.transport_apdu.cla(),
            ins: self.transport_apdu.ins(),
            p1: self.transport_apdu.p1(),
            p2: self.transport_apdu.p2(),
            p3: self.transport_apdu.ln(),
        }
    }

    pub fn cla(&self) -> u8 {
        self.transport_apdu.cla()
    }

    pub fn ins(&self) -> u8 {
        self.transport_apdu.ins()
    }

    pub fn p1(&self) -> u8 {
        self.transport_apdu.p1()
    }

    pub fn p2(&self) -> u8 {
        self.transport_apdu.p2()
    }

    pub fn p3(&self) -> u8 {
        self.transport_apdu.ln()
    }

    pub fn incoming_was_received(&self) -> bool {
        self.transport_apdu.incoming_was_received()
    }

    pub fn outgoing_length(&self) -> usize {
        self.transport_apdu.outgoing_length()
    }

    pub fn as_apdu(&mut self) -> crate::apdu_manager::Apdu<'_> {
        self.transport_apdu.as_apdu()
    }

    pub fn complete(&mut self, status: ApduStatus) -> ApduCompletion<'_> {
        ApduCompletion {
            command: self,
            status,
        }
    }

    pub(crate) fn transport_apdu_mut(&mut self) -> &mut TransportApdu {
        &mut self.transport_apdu
    }

    pub(crate) fn receive_incoming_for_layer(&mut self) -> usize {
        self.transport_apdu.receive_incoming_for_runtime()
    }

    pub(crate) fn incoming_data_for_layer(&self) -> &[u8] {
        self.transport_apdu.incoming_data()
    }

    pub(crate) fn replace_incoming_for_layer(&mut self, data: &[u8]) -> bool {
        self.transport_apdu.replace_incoming_for_layer(data)
    }

    pub(crate) fn outgoing_data_for_layer(&self) -> &[u8] {
        self.transport_apdu.outgoing_data()
    }

    pub(crate) fn replace_outgoing_for_layer(&mut self, data: &[u8]) -> bool {
        self.transport_apdu.replace_outgoing_for_layer(data)
    }

    pub(crate) fn set_secure_response_required(&mut self, required: bool) {
        self.transport_apdu.set_secure_response_required(required);
    }

    pub(crate) const fn secure_response_required(&self) -> bool {
        self.transport_apdu.secure_response_required()
    }
}

impl From<TransportApdu> for ApduCommand {
    fn from(transport_apdu: TransportApdu) -> Self {
        Self { transport_apdu }
    }
}

impl ApduCompletion<'_> {
    pub const fn command(&self) -> &ApduCommand {
        self.command
    }

    pub(crate) fn command_mut(&mut self) -> &mut ApduCommand {
        self.command
    }

    pub fn incoming_was_received(&self) -> bool {
        self.command.incoming_was_received()
    }

    pub fn outgoing_length(&self) -> usize {
        self.command.outgoing_length()
    }
}

/// Identity layer used to make the APDU stack explicit.
pub struct PassthroughApduLayer<Inner> {
    inner: Inner,
}

/// Debug layer that logs APDU-layer transitions.
///
/// It is currently enabled only for the scripted APDU environment.
pub struct TracingApduLayer<Inner> {
    inner: Inner,
    enabled: bool,
}

impl<Inner> PassthroughApduLayer<Inner> {
    pub const fn new(inner: Inner) -> Self {
        Self { inner }
    }

    #[allow(dead_code)]
    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut Inner {
        &mut self.inner
    }
}

impl<Inner> TracingApduLayer<Inner> {
    pub const fn new(inner: Inner, enabled: bool) -> Self {
        Self { inner, enabled }
    }

    #[allow(dead_code)]
    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut Inner {
        &mut self.inner
    }
}

impl<T: TransportLayer + 'static> ApduLayer for T0ApduManager<T> {
    fn send_atr(&mut self, historical_bytes: &[u8]) {
        T0ApduManager::send_atr(self, historical_bytes);
    }

    fn receive_command(&mut self) -> Option<ApduCommand> {
        T0ApduManager::receive_command(self).map(ApduCommand::from)
    }

    fn complete_command(&mut self, completion: ApduCompletion<'_>) {
        T0ApduManager::complete_command(
            self,
            completion.command.transport_apdu_mut(),
            completion.status,
        );
    }
}

impl<Inner: ApduLayer> ApduLayer for PassthroughApduLayer<Inner> {
    fn send_atr(&mut self, historical_bytes: &[u8]) {
        self.inner.send_atr(historical_bytes);
    }

    fn receive_command(&mut self) -> Option<ApduCommand> {
        self.inner.receive_command()
    }

    fn complete_command(&mut self, completion: ApduCompletion<'_>) {
        self.inner.complete_command(completion);
    }
}

impl<Inner: ApduLayer> ApduLayer for TracingApduLayer<Inner> {
    fn send_atr(&mut self, historical_bytes: &[u8]) {
        if self.enabled {
            oxi_core::consoleln!("apdu-layer: tx atr len={}", historical_bytes.len());
        }
        self.inner.send_atr(historical_bytes);
    }

    fn receive_command(&mut self) -> Option<ApduCommand> {
        let command = self.inner.receive_command()?;
        if self.enabled {
            oxi_core::consoleln!(
                "apdu-layer: rx cla={:02x} ins={:02x} p1={:02x} p2={:02x} p3={:02x}",
                command.cla(),
                command.ins(),
                command.p1(),
                command.p2(),
                command.p3()
            );
        }
        Some(command)
    }

    fn complete_command(&mut self, completion: ApduCompletion<'_>) {
        if self.enabled {
            oxi_core::consoleln!(
                "apdu-layer: tx sw={:02x}{:02x} outgoing={} incoming={}",
                completion.status.sw1,
                completion.status.sw2,
                completion.outgoing_length(),
                completion.incoming_was_received()
            );
        }
        self.inner.complete_command(completion);
    }
}
