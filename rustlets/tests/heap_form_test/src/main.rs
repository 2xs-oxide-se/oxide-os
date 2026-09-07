#![no_std]
#![no_main]

use rustlet_runtime::{declare_app, Apdu, ApduStatus, Rustlet, RustletCtx};

declare_app!(HeapFormRustlet, 2048usize);

use alloc::vec::Vec;

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct HeapFormRustlet;

impl Rustlet for HeapFormRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            0x30 => {
                let mut values = Vec::with_capacity(64);
                for value in 0u8..64 {
                    values.push(value);
                }

                apdu.as_sending().send(&[values.len() as u8])
            }
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}
