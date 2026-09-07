#![no_std]
#![no_main]

use rustlet_runtime::{declare_app, Apdu, ApduStatus, Rustlet, RustletCtx};

declare_app!(ApdusTestRustlet);

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct ApdusTestRustlet;

impl Rustlet for ApdusTestRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            0x70 => apdu.accept(),
            0x72 => {
                let rx = apdu.as_receiving();
                if rx.lc() == rx.data().len() {
                    rx.accept()
                } else {
                    rx.reject(ApduStatus::wrong_length())
                }
            }
            0x74 => {
                let tx = apdu.as_sending();
                let le = tx.le() as u8;
                tx.send(&[le, 0xA1, 0xA2, 0xA3])
            }
            0x76 => {
                let rx = apdu.as_receiving();
                let mut echo = [0u8; 16];
                let len = rx.data().len();
                if len > echo.len() {
                    return rx.reject(ApduStatus::wrong_length());
                }
                echo[..len].copy_from_slice(rx.data());
                rx.accept_and_send(&echo[..len])
            }
            0x78 => apdu.as_sending().send_with(|out| {
                out[..4].copy_from_slice(&[0x78, 0x01, 0x02, 0x03]);
                4
            }),
            0x7A => {
                let rx = apdu.as_receiving();
                let lc = rx.lc() as u8;
                rx.accept_and_send(&[lc])
            }
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}
