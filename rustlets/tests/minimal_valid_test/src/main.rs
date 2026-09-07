#![no_std]
#![no_main]

use alloc::boxed::Box;
use rustlet_runtime::{declare_app, Apdu, ApduStatus, Rustlet, RustletCtx};

declare_app!(MinimalValidRustlet, 256);

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct MinimalValidRustlet;

impl Rustlet for MinimalValidRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            0x00 => apdu.accept(),
            0x02 => apdu.as_receiving().accept(),
            0x04 => apdu.as_sending().send(&[0x10, 0x11, 0x12]),
            0x06 => apdu.as_receiving().accept_and_send(&[0xAA, 0xBB, 0xCC]),
            0x01 => {
                let value = Box::new(0x5Au8);
                drop(value);
                panic!("minimal alloc/dealloc/panic");
            }
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}
