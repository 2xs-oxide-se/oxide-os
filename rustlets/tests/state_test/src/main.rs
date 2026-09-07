#![no_std]
#![no_main]

use rustlet_runtime::{declare_app, gp, Apdu, ApduStatus, Rustlet, RustletCtx};
declare_app!(StateTestRustlet, 256usize, install_state_test);

#[derive(rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct StateTestRustlet {
    counter: u8,
}

impl Default for StateTestRustlet {
    fn default() -> Self {
        Self { counter: 0 }
    }
}

fn install_state_test(ctx: &mut RustletCtx) -> Result<StateTestRustlet, ApduStatus> {
    let counter = gp::parse_install_for_install_ctx(ctx)
        .ok()
        .and_then(|install| install.install_parameters.first().copied())
        .unwrap_or(0);

    Ok(StateTestRustlet { counter })
}

impl Rustlet for StateTestRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let abi_version = ctx.version();
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            0x10 => {
                let status = apdu.as_sending().send(&[self.counter]);
                self.counter = self.counter.wrapping_add(1);
                status
            }
            0x12 => apdu.as_sending().send(&[(abi_version & 0xff) as u8]),
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}
