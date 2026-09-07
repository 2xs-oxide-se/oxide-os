#![no_std]
#![no_main]

use rustlet_runtime::{declare_app, gp, Apdu, ApduStatus, Rustlet, RustletCtx};

declare_app!(
    SerializationTestRustlet,
    1024usize,
    install_serialization_test
);

const INS_INCREMENT: u8 = 0x40;
const INS_DUMP: u8 = 0x42;

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct NestedCounters {
    persistent: u8,
    #[serde(skip, default)]
    transient: u8,
}

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct SerializationTestRustlet {
    persistent: u8,
    nested: NestedCounters,
    #[serde(skip, default)]
    transient: u8,
}

fn install_serialization_test(
    ctx: &mut RustletCtx,
) -> Result<SerializationTestRustlet, ApduStatus> {
    let mut install_data = [0u8; 4];
    let data_len = gp::parse_install_for_install_ctx(ctx)
        .ok()
        .map(|install| {
            let len = install.install_parameters.len().min(install_data.len());
            install_data[..len].copy_from_slice(&install.install_parameters[..len]);
            len
        })
        .unwrap_or(0);
    let data = &install_data[..data_len];

    Ok(SerializationTestRustlet {
        persistent: data.first().copied().unwrap_or(0),
        nested: NestedCounters {
            persistent: data.get(1).copied().unwrap_or(0),
            transient: data.get(3).copied().unwrap_or(0),
        },
        transient: data.get(2).copied().unwrap_or(0),
    })
}

impl Rustlet for SerializationTestRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            INS_INCREMENT => {
                self.persistent = self.persistent.wrapping_add(1);
                self.nested.persistent = self.nested.persistent.wrapping_add(1);
                self.transient = self.transient.wrapping_add(1);
                self.nested.transient = self.nested.transient.wrapping_add(1);
                apdu.accept()
            }
            INS_DUMP => apdu.as_sending().send(&[
                self.persistent,
                self.nested.persistent,
                self.transient,
                self.nested.transient,
            ]),
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}
