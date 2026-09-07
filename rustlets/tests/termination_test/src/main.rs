#![no_std]
#![no_main]

use rustlet_runtime::{declare_app, Apdu, ApduStatus, Rustlet, RustletCtx};
declare_app!(TerminationTestRustlet);

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct TerminationTestRustlet;

impl Rustlet for TerminationTestRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let ins = Apdu::new(ctx).ins();

        match ins {
            0x20 => ctx.exit(ApduStatus {
                sw1: 0x91,
                sw2: 0x23,
            }),
            0x22 => panic!("termination test panic"),
            0x24 => ApduStatus::success(),
            0x26 => loop {
                core::hint::spin_loop();
            },
            _ => ApduStatus::instruction_not_supported(),
        }
    }
}
