/// Byte-oriented card I/O backend.
///
/// This trait is intentionally smaller than an APDU interface. It only models
/// the half-duplex byte stream seen by the kernel transport loop.
pub trait TransportLayer {
    fn send_byte(&mut self, byte: u8);
    fn receive_byte(&mut self) -> u8;
}

/// Transport backend backed by the target serial peripheral.
pub struct SerialTransport;

impl TransportLayer for SerialTransport {
    fn send_byte(&mut self, byte: u8) {
        crate::core::serial::send_byte(byte);
    }

    fn receive_byte(&mut self) -> u8 {
        crate::core::serial::receive_byte()
    }
}

/// Transport backend backed by the scripted in-kernel simulator.
pub struct SimulatedTransport;

impl TransportLayer for SimulatedTransport {
    fn send_byte(&mut self, byte: u8) {
        crate::apdu_debug_mod::send_byte(byte);
    }

    fn receive_byte(&mut self) -> u8 {
        crate::apdu_debug_mod::receive_byte()
    }
}

/// Runtime-selected transport backend.
///
/// The kernel chooses the concrete backend once at boot and builds higher
/// protocol layers on top of that decision.
pub enum CurrentTransport {
    Serial(SerialTransport),
    Simulated(SimulatedTransport),
}

impl TransportLayer for CurrentTransport {
    fn send_byte(&mut self, byte: u8) {
        match self {
            Self::Serial(transport) => transport.send_byte(byte),
            Self::Simulated(transport) => transport.send_byte(byte),
        }
    }

    fn receive_byte(&mut self) -> u8 {
        match self {
            Self::Serial(transport) => transport.receive_byte(),
            Self::Simulated(transport) => transport.receive_byte(),
        }
    }
}

/// Select the transport backend for the current execution environment.
pub fn current_transport() -> CurrentTransport {
    match crate::core::target::execution_env() {
        "simulate_apdu" | "simulate_apdu_scp11c" => CurrentTransport::Simulated(SimulatedTransport),
        _ => CurrentTransport::Serial(SerialTransport),
    }
}
