#![no_std]
#![no_main]

use rustlet_runtime::{declare_app, Apdu, ApduStatus, Rustlet, RustletCtx};

declare_app!(IsolationFaultRustlet);

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct IsolationFaultRustlet;

impl Rustlet for IsolationFaultRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            0x50 => {
                let _ = unsafe { core::ptr::read_volatile(0 as *const u32) };
                ApduStatus::success()
            }
            0x51 => {
                unsafe { core::ptr::write_volatile(0 as *mut u32, 0x1122_3344) };
                ApduStatus::success()
            }
            0x52 => invalid_instruction(),
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}

#[inline(never)]
fn invalid_instruction() -> ApduStatus {
    unsafe {
        core::arch::asm!(".hword 0xde00", options(noreturn));
    }
}
