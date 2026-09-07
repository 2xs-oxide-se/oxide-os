#![no_std]
#![no_main]

use rustlet_runtime::{declare_app, Apdu, ApduStatus, Rustlet, RustletCtx};

declare_app!(TemplateRustlet, 256);

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct TemplateRustlet;

impl Rustlet for TemplateRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            0x00 => apdu.accept(),
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}
