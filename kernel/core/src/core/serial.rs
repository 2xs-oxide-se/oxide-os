pub fn send_byte(byte: u8) {
    crate::core::target::send_byte(byte);
}

/// Attempts one interrupt-safe byte write without waiting for transport space.
pub fn try_send_byte(byte: u8) -> bool {
    crate::core::target::try_send_byte(byte)
}

pub fn receive_byte() -> u8 {
    crate::core::target::receive_byte()
}

pub fn write_str(s: &str) {
    for byte in s.bytes() {
        send_byte(byte);
    }
}

pub fn write_line(s: &str) {
    write_str(s);
    send_byte(b'\n');
}
