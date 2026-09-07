/// Error returned by streaming persistence adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistenceError {
    /// The destination buffer cannot accept more bytes.
    CapacityFull,
    /// The backing store failed while reading.
    ReadError,
    /// The backing store failed while writing.
    WriteError,
    /// The serialized data is malformed or unsupported.
    InvalidData,
}

/// Byte sink used by future Rustlet state persistence support.
pub trait StateWriter {
    fn push_byte(&mut self, byte: u8) -> Result<(), PersistenceError>;
}

/// Byte source used by future Rustlet state persistence support.
pub trait StateReader {
    fn pop_byte(&mut self) -> Result<u8, PersistenceError>;
}

/// Placeholder write-side adapter for future streaming serialization.
///
/// The full postcard-backed implementation is intentionally deferred until the
/// persistence ABI is stabilized and the dependency is wired into the runtime.
pub struct WriteFlavor<'a>(&'a mut dyn StateWriter);

impl<'a> WriteFlavor<'a> {
    pub fn new(writer: &'a mut dyn StateWriter) -> Self {
        Self(writer)
    }

    pub fn writer(&mut self) -> &mut dyn StateWriter {
        self.0
    }
}

/// Placeholder read-side adapter for future streaming deserialization.
///
/// The full postcard-backed implementation is intentionally deferred until the
/// persistence ABI is stabilized and the dependency is wired into the runtime.
pub struct ReadFlavor<'a>(&'a mut dyn StateReader);

impl<'a> ReadFlavor<'a> {
    pub fn new(reader: &'a mut dyn StateReader) -> Self {
        Self(reader)
    }

    pub fn reader(&mut self) -> &mut dyn StateReader {
        self.0
    }
}

#[cfg(test)]
mod tests {
    #[derive(Default, serde::Serialize, serde::Deserialize)]
    struct VolatileSession {
        state: u8,
        session_key: [u8; 16],
        mac_chain: [u8; 16],
        counter: u32,
    }

    #[derive(Default, serde::Serialize, serde::Deserialize)]
    struct PersistentView {
        // Invariant: an active secure-channel session belongs to RAM, never to
        // the Postcard representation stored by the registry.
        #[serde(skip)]
        session: VolatileSession,
    }

    #[test]
    fn skipped_session_is_absent_from_postcard_state() {
        let state = PersistentView {
            session: VolatileSession {
                state: 2,
                session_key: [0xA5; 16],
                mac_chain: [0x5A; 16],
                counter: 7,
            },
        };
        let mut encoded = [0u8; 64];
        let serialized = postcard::to_slice(&state, &mut encoded).expect("serialize state");

        assert!(serialized.is_empty());
    }

    #[test]
    fn skipped_session_defaults_when_loading_legacy_trailing_bytes() {
        let legacy = VolatileSession {
            state: 2,
            session_key: [0xA5; 16],
            mac_chain: [0x5A; 16],
            counter: 7,
        };
        let mut encoded = [0u8; 64];
        let serialized = postcard::to_slice(&legacy, &mut encoded).expect("serialize legacy");
        let loaded: PersistentView =
            postcard::from_bytes(serialized).expect("deserialize persistent view");

        assert_eq!(loaded.session.state, 0);
        assert_eq!(loaded.session.session_key, [0; 16]);
        assert_eq!(loaded.session.mac_chain, [0; 16]);
        assert_eq!(loaded.session.counter, 0);
    }
}
