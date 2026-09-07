# Rustlet Developer Guide

This guide describes what an ordinary Rustlet is in Oxide SE today.

If you have not built a Rustlet yet, start with
[rustlets.getting.started.md](rustlets.getting.started.md).

It intentionally does not cover Security Domains. Those are documented in
[security.domain.developper.guide.md](security.domain.developper.guide.md).

## Scope

At the current project stage, a Rustlet is:

- a `no_std`, `no_main` FAE payload;
- built against `rustlets/rustlet_runtime`;
- loaded by the kernel and executed behind the Rustlet ABI boundary;
- stateful across installation and later APDU processing;
- isolated from the kernel by the current Rustlet runtime and MPU model.

An ordinary Rustlet is an application object. It is not an administrative
authority. It processes APDUs routed to its selected instance.

## Mental Model

The current model is:

1. the kernel installs one Rustlet instance;
2. installation creates the resident object state;
3. later, `SELECT` activates one installed instance;
4. `process_apdu()` is called on that selected instance;
5. the persistent subset of the Rustlet state is saved and restored by the
   runtime.

From the author's point of view:

- `install()` is the constructor path;
- `process_apdu()` is the command-processing path;
- the Rustlet object is the application state.

## Minimal Rustlet

```rust
#![no_std]
#![no_main]

use rustlet_runtime::{declare_rustlet, Apdu, ApduStatus, Rustlet, RustletCtx};

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct MyRustlet;

declare_rustlet!(MyRustlet);

impl Rustlet for MyRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);
        match apdu.ins() {
            0x00 => apdu.accept(),
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}
```

This is the current normal shape:

- one Rust state object;
- one declaration macro;
- one `process_apdu()` entry point;
- optional persistent fields serialized by the runtime.

## Declaring The Rustlet

The normal declaration macro is:

```rust
declare_rustlet!(MyRustlet);
declare_rustlet!(MyRustlet, 2048usize);
declare_rustlet!(MyRustlet, 2048usize, install_custom);
```

The forms mean:

- default heap, implicit install;
- explicit heap, implicit install;
- explicit heap, explicit install function.

`declare_app!` is an alias for `declare_rustlet!`; application code should use
`declare_rustlet!`.

## The `Rustlet` Trait

The core trait is defined in
[rt.rs](../rustlets/rustlet_runtime/src/rt.rs).

Today it exposes:

- `process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus`
- `load_state(&mut self, state: &[u8]) -> Result<(), ApduStatus>`
- `save_state(&self, out: &mut [u8]) -> Result<usize, ApduStatus>`

In normal code:

- `process_apdu()` is mandatory;
- `load_state()` and `save_state()` may be left to the runtime defaults if the
  Rustlet has no custom persistence logic;
- if the Rustlet type implements `serde::{Serialize, Deserialize}`, the runtime
  relay can already use postcard-based persistence.

## Installation

If no explicit install function is provided, the Rustlet must implement
`Default`.

```rust
#[derive(Default)]
struct MyRustlet;

declare_rustlet!(MyRustlet);
```

If installation needs parameters or custom construction logic, use an explicit
install function:

```rust
fn install(ctx: &mut RustletCtx) -> Result<MyRustlet, ApduStatus> {
    let _ = ctx.abi_version();
    Ok(MyRustlet {})
}

declare_rustlet!(MyRustlet, 1024usize, install);
```

The install function runs inside the Rustlet runtime. It returns the resident
Rust object that will later receive APDUs.

## Parsing GP Install Data

When one Rustlet uses a custom install function, it should not parse the raw
`INSTALL [for install]` APDU payload by hand.

The Oxide SE runtime exposes one small helper module:

- [gp.rs](../rustlets/rustlet_runtime/src/gp.rs)

The two entry points to know are:

- `gp::parse_install_for_install_ctx(&RustletCtx)`
- `gp::parse_install_for_install_data(&[u8])`

They decode the current GlobalPlatform envelope used by the kernel:

1. `package AID`
2. `applet AID`
3. `instance AID`
4. `privileges`
5. `install parameters`

That outer structure is an `LV` sequence, not a flat application payload.
Reading `ctx` as if it directly contained only application bytes is therefore
incorrect.

Minimal example for an ordinary Rustlet:

```rust
use rustlet_runtime::{declare_rustlet, gp, ApduStatus, Rustlet, RustletCtx};

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct CounterRustlet {
    initial_counter: u8,
}

fn install(ctx: &mut RustletCtx) -> Result<CounterRustlet, ApduStatus> {
    let initial_counter = gp::parse_install_for_install_ctx(ctx)
        .ok()
        .and_then(|install| install.install_parameters.first().copied())
        .unwrap_or(0);

    Ok(CounterRustlet { initial_counter })
}

declare_rustlet!(CounterRustlet, 1024usize, install);
```

This is the right level of abstraction for ordinary Rustlets:

- let the runtime parse the GP `LV` envelope;
- read only `install.install_parameters` for your application payload;
- ignore the administrative fields unless your application genuinely needs
  them.

The current regression examples using this helper are:

- [state_test/src/main.rs](../rustlets/tests/state_test/src/main.rs)
- [serialization_test/src/main.rs](../rustlets/tests/serialization_test/src/main.rs)

## BER-TLV Helper

The same runtime module also exposes:

- `gp::BerTlvReader`

This helper is intentionally small:

- it reads one BER-TLV stream sequentially;
- it validates tag and length structure;
- it rejects unsupported forms such as indefinite length;
- it does not allocate.

Typical usage:

```rust
use rustlet_runtime::gp::{BerTlvReader, DecodeError};

fn read_first_tag(data: &[u8]) -> Result<Option<(u32, &[u8])>, DecodeError> {
    let mut reader = BerTlvReader::new(data);
    match reader.next()? {
        Some(tlv) => Ok(Some((tlv.tag, tlv.value))),
        None => Ok(None),
    }
}
```

For an ordinary Rustlet, this is useful when `install_parameters` themselves
use one TLV structure agreed with the host toolchain.

For a Security Domain Rustlet, this becomes even more relevant, because
GlobalPlatform expects BER-TLV content in some administrative payloads,
especially for Security-Domain-specific configuration carried through install
parameters. In that case, the recommended shape is:

1. parse the outer `INSTALL [for install]` envelope with
   `gp::parse_install_for_install_ctx(ctx)`;
2. extract `install.install_parameters`;
3. iterate over those bytes with `gp::BerTlvReader`.

Minimal illustration:

```rust
use rustlet_runtime::{gp, ApduStatus, RustletCtx};

fn parse_sd_install_data(ctx: &RustletCtx) -> Result<(), ApduStatus> {
    let install = gp::parse_install_for_install_ctx(ctx)
        .map_err(|_| ApduStatus::wrong_data())?;

    let mut tlvs = gp::BerTlvReader::new(install.install_parameters);
    while let Some(tlv) = tlvs.next().map_err(|_| ApduStatus::wrong_data())? {
        match tlv.tag {
            0xC9 => {
                let _application_specific = tlv.value;
            }
            _ => {}
        }
    }
    Ok(())
}
```

This guide stops there on purpose. The full administrative meaning of those
tags belongs to the Security Domain framework, which is documented separately.

## APDU Programming Model

The Rustlet-side APDU API is intentionally typed. It is documented in
[apdu.rs](../rustlets/rustlet_runtime/src/apdu.rs).

The main object is:

- `Apdu<Command>`
- `Apdu<Receiving>`
- `Apdu<Sending>`

The intent is:

- create `Apdu::new(ctx)` when command processing starts;
- inspect the header in `Command`;
- move to `Receiving` only if the command really has incoming data;
- move to `Sending` only if the command really produces outgoing data.

Example:

```rust
fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
    let apdu = Apdu::new(ctx);
    match apdu.ins() {
        0x02 => {
            let rx = apdu.as_receiving();
            rx.accept_and_send(rx.data())
        }
        0x04 => apdu.as_sending().send(&[0x11, 0x22, 0x33, 0x44]),
        _ => apdu.reject(ApduStatus::instruction_not_supported()),
    }
}
```

This is the preferred current API. A Rustlet should not manipulate the raw APDU
shared buffer directly unless the framework leaves no better option.

## `RustletCtx`

`RustletCtx` is the shared ABI region between kernel and Rustlet.

For an ordinary Rustlet, it is mainly used to:

- construct the typed `Apdu`;
- access the ABI version;
- access the crypto provider;
- access persistence staging indirectly through the runtime.

The Rustlet should treat `RustletCtx` as framework-owned shared state, not as a
general-purpose raw buffer.

## Persistence

The runtime treats the serialized representation of an ordinary Rustlet as the
authoritative state between APDUs. After a normal handler return, it serializes
the instance, destroys the in-memory object, and the kernel scrubs the complete
Rustlet heap. The next APDU reconstructs the object and loads that serialized
state.

Current practical rules:

- serializable Rustlets should derive `serde::Serialize` and
  `serde::Deserialize`;
- postcard is the current default serialization backend;
- fields excluded from serialization with serde attributes are transient only
  within the current APDU execution. They are reconstructed from their default
  value for the next APDU and must not be used for cross-command state;
- a Rustlet Security Domain is the explicit exception to this ordinary-Rustlet
  lifecycle: its non-serialized secure-channel session remains resident while
  the Security Domain is active and is cleared when the channel or loaded
  Security Domain is torn down.

The persistence backing store is still evolving, but the Rustlet-side object
model is already in place.

## Crypto

The runtime exposes card-side cryptographic services through `ctx.crypto()`.

The Rustlet can already use:

- typed `Cipher`
- typed `Mac`
- random generation

Those services are kernel-mediated. The Rustlet uses them through the runtime
API, not by linking a separate crypto stack of its own into the kernel address
space.

## Packaging And Validation

Today the practical pipeline is:

1. build the Rustlet crate;
2. package it as a `.fae`;
3. embed or load it through the current test path;
4. validate it through `xtask`.

The current repository already contains Rustlet examples and regression tests
under:

- [tests](../rustlets/tests)

The current end-to-end validation path typically uses:

- `cargo run test rustlet --elf mps2-an385 <rustlet>`
- `cargo run test rustlet_all --elf mps2-an385`

## What This Guide Deliberately Does Not Cover

This guide does not describe:

- Security Domain authority;
- SCP03 session handling;
- management APDUs such as `INSTALL`, `DELETE`, or `GET DATA` as administrative
  operations;
- the `sddispatch` framework call.

Those topics belong to the dedicated Security Domain guide:

- [security.domain.developper.guide.md](security.domain.developper.guide.md)
