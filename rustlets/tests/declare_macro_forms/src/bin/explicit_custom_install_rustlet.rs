#![no_std]
#![no_main]

use rustlet_runtime::{declare_app, Apdu, ApduStatus, Rustlet, RustletCtx};

declare_app!(ExplicitCustomInstallRustlet, 2048usize, install_custom);

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct ExplicitCustomInstallRustlet;

fn install_custom(ctx: &mut RustletCtx) -> Result<ExplicitCustomInstallRustlet, ApduStatus> {
    let _ = Apdu::new(ctx).accept();
    Ok(ExplicitCustomInstallRustlet)
}

impl Rustlet for ExplicitCustomInstallRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        Apdu::new(ctx).accept()
    }
}
