# Rustlets Getting Started

This guide walks through the smallest useful Rustlet authoring flow:

1. start from the Rustlet template;
2. write one tiny APDU handler;
3. build the Rustlet as a FAE application payload;
4. embed it into a kernel image through a predeployment config;
5. boot that image under QEMU;
6. select the Rustlet and call the custom APDU.

It intentionally stays close to Cargo, QEMU, and `apdu_tool`. There are
no project-specific shell wrappers in this walkthrough.

## What We Build

The tutorial Rustlet accepts a few simple instructions:

- `INS = 00`: return success with no data.
- `INS = 02`: accept incoming data and return success.
- `INS = 04`: return a fixed payload `10 11 12`.
- `INS = 06`: return the fixed payload `AA BB CC`.
- `INS = 08`: echo the incoming APDU payload.

The repository contains the finished tutorial Rustlet here:

```text
rustlets/tests/getting_started_test/src/main.rs
```

This checked-in copy keeps the guide reproducible. When you create your
own Rustlet later, start from `rustlets/rustlet_template` and apply the
same shape.

## 1. Start From The Template

The standalone template lives here:

```text
rustlets/rustlet_template/
```

Its structure is deliberately small:

- `src/main.rs`: the embedded `no_std` Rustlet payload.
- `Cargo.toml`: the Rustlet package.
- `.cargo/config.toml`: a local Cargo alias for `cargo build-fae`.
- `xtask/`: the host-side helper used by that alias.
- `build/`: generated ELF, FAE, and debug artifacts.

For a new Rustlet, copy the template and rename the package:

```bash
cp -R rustlets/rustlet_template rustlets/my_first_rustlet
```

Then edit `rustlets/my_first_rustlet/Cargo.toml`:

```toml
[package]
name = "my_first_rustlet"
```

The rest of this guide uses the checked-in tutorial copy,
`rustlets/tests/getting_started_test`, so every command can be run from a
fresh repository checkout.

## 2. Write A Minimal Rustlet

The tutorial Rustlet source is:

```rust
#![no_std]
#![no_main]

use rustlet_runtime::{declare_app, Apdu, ApduStatus, Rustlet, RustletCtx};

declare_app!(GettingStartedRustlet, 256);

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct GettingStartedRustlet;

impl Rustlet for GettingStartedRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            0x00 => apdu.accept(),
            0x02 => apdu.as_receiving().accept(),
            0x04 => apdu.as_sending().send(&[0x10, 0x11, 0x12]),
            0x06 => apdu.as_receiving().accept_and_send(&[0xAA, 0xBB, 0xCC]),
            0x08 => {
                let rx = apdu.as_receiving();
                let mut echo = [0u8; 16];
                let len = rx.data().len();
                if len > echo.len() {
                    return rx.reject(ApduStatus::wrong_length());
                }
                echo[..len].copy_from_slice(rx.data());
                rx.accept_and_send(&echo[..len])
            }
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}
```

The important pieces are:

- `#![no_std]` and `#![no_main]`: Rustlets are embedded payloads, not
  host executables.
- `declare_app!(GettingStartedRustlet, 256)`: declares the Rustlet entry
  points and reserves 256 bytes for the Rustlet runtime heap.
- `process_apdu()`: receives APDUs routed to the selected Rustlet
  instance.
- `Apdu::new(ctx)`: exposes the APDU helper API from the Rustlet runtime.

## 3. Build The Rustlet FAE Payload

Build the tutorial Rustlet for the `mps2-an385` QEMU target:

```bash
cd rustlets/tests
RUSTLET_TARGET=thumbv7m-none-eabi cargo run build-fae getting_started_test
cd ../..
```

This produces:

```text
rustlets/tests/getting_started_test/build/rustlet_getting_started_test.fae
```

`RUSTLET_TARGET=thumbv7m-none-eabi` selects the ARM Thumb v7-M target
used by the `mps2-an385` board. The generated `.fae` file is the Rustlet
application payload that the kernel can load or predeploy.

If you are inside a standalone template copy, the equivalent local form is:

```bash
cd rustlets/my_first_rustlet
RUSTLET_TARGET=thumbv7m-none-eabi cargo build-fae
cd ../..
```

## 4. Declare A Minimal Predeployment Config

A Rustlet FAE payload can be loaded later through management APDUs, but
it can also be predeployed into the kernel image. Predeployment means the
kernel build embeds the Rustlet package, and optionally declares an
instance that is installed during the first kernel initialization.

The tutorial config is:

```text
configs/config_rustlet_getting_started_test.toml
```

Its content is:

```toml
[root.package]
name = "NullSecurityDomain"
aid = "A0:00:00:47:50:4F:53:01"

[root.instance]
aid = "A0:00:00:47:50:4F:53:01"
install_bytes = "FF:FF:FF"

[[root.packages]]
path = "./rustlets/tests/getting_started_test"

[[root.packages.instances]]
aid = "A0:00:00:47:50:4F:53:20"
install_bytes = ""
```

For this first Rustlet, we use the development `NullSecurityDomain` root
authority. The Rustlet package and its instance are predeployed under
that root Security Domain. The instance AID is:

```text
A0 00 00 47 50 4F 53 20
```

That AID is the value we will later SELECT.

## 5. Build The Kernel Image

Build the kernel with the tutorial predeployment config:

```bash
cargo run build --config configs/config_rustlet_getting_started_test.toml mps2-an385
```

The generated kernel image is:

```text
target/kernel/firmware/kernel.elf
```

The build also rebuilds the referenced Rustlet FAE if needed.

## 6. Boot Under QEMU

Start QEMU manually:

```bash
qemu-system-arm \
  -machine mps2-an385 \
  -nographic \
  -monitor none \
  -serial tcp:127.0.0.1:4444,server=on,wait=on \
  -semihosting-config enable=on,target=native \
  -kernel target/kernel/firmware/kernel.elf
```

Keep this terminal open. QEMU waits for an APDU client on TCP port
`4444`. The `-semihosting-config` option only makes QEMU semihosting services
available; kernel console traces stay disabled unless the kernel was built with
`--trace=semihosting`.

## 7. Select And Call The Rustlet

In a second terminal, read the ATR:

```bash
cargo run -p apdu_tool --
```

Select the predeployed Rustlet instance:

```bash
cargo run -p apdu_tool -- \
  00 A4 04 00 08 00 \
  A0 00 00 47 50 4F 53 20
```

The expected response is:

```text
SW: 90 00
```

Call the fixed outbound command:

```bash
cargo run -p apdu_tool -- 00 04 00 00 00 03
```

The expected response is:

```text
DATA OUT (3): 10 11 12
SW: 90 00
```

Call the echo command:

```bash
cargo run -p apdu_tool -- 00 08 00 00 04 04 DE AD BE EF
```

This APDU means:

- `00`: application CLA.
- `08`: custom Rustlet instruction.
- `00 00`: `P1/P2`, unused by this example.
- `04`: four incoming bytes.
- `04`: request four response bytes.
- `DE AD BE EF`: incoming payload.

The expected response is:

```text
DATA OUT (4): DE AD BE EF
SW: 90 00
```

> /!\ Congratulations! You have now copied the Rustlet template shape,
> built a Rustlet FAE payload, embedded it into a kernel image, booted
> that image under QEMU, selected the Rustlet instance, and executed your
> first custom APDU.

## Next Step

Continue with
[`rustlet.developper.guide.md`](rustlet.developper.guide.md).

That guide explains the Rustlet runtime API in more detail: APDU helpers,
installation hooks, persistent state, serialization, allocation, crypto
helpers, and the current validation pipeline.
