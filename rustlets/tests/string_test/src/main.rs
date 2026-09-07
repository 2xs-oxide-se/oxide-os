#![no_std]
#![no_main]

use alloc::string::String;
use rustlet_runtime::{declare_app, Apdu, ApduStatus, Rustlet, RustletCtx};

declare_app!(StringRustlet);

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct StringRustlet;

impl Rustlet for StringRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            0x40 => {
                let rx = apdu.as_receiving();
                let mut value = String::from("Oxide SE:");
                for byte in rx.data() {
                    value.push(*byte as char);
                }
                value.push('!');

                let bytes = value.as_bytes();
                rx.accept_and_send(bytes)
            }
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}
