#![no_std]
#![no_main]

use rustlet_runtime::{declare_app, Apdu, ApduStatus, Rustlet, RustletCtx};

declare_app!(GettingStartedRustlet, 256);

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct GettingStartedRustlet;

impl Rustlet for GettingStartedRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            0x00 => apdu.accept(),
            0x02 => apdu.as_receiving().accept(),
            0x04 => apdu.as_sending().send(&[0x10, 0x11, 0x12]),
            0x06 => apdu.as_receiving().accept_and_send(&[0xAA, 0xBB, 0xCC]),
            0x08 => {
                let rx = apdu.as_receiving();
                let mut echo = [0u8; 16];
                let len = rx.data().len();
                if len > echo.len() {
                    return rx.reject(ApduStatus::wrong_length());
                }
                echo[..len].copy_from_slice(rx.data());
                rx.accept_and_send(&echo[..len])
            }
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}
