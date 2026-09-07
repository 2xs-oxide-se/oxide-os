# Oxide SE Bootstrap and Workspace Notes

This document describes the current bootstrap path of the repository and
how the different crates fit together.

## Goal

The repository is split into two layers:

- the Oxide SE repository hosts the project-owned sources and the Rust workspace;
- `tooling/build-fae` stays a separate Git submodule used as external FAE
  build and packaging tooling, including the board-specific bootable
  firmware profiles used by the bootstrap.

The bootstrap uses a small multi-crate workspace architecture:

- `kernel/core`: reusable embedded library crate (`oxi_core`)
- `kernel/firmware`: production firmware crate
- `core_test`: QEMU-oriented embedded test firmware
- `xtask`: local orchestration commands

This lets the project keep the runtime and hardware services reusable,
while still supporting multiple firmware entry points above the same
embedded core.

## Prerequisites

The current flow expects these tools to be available:

- `cargo`
- `rustup`
- a nightly Rust toolchain with `rust-src`
- `arm-none-eabi-gcc`
- `qemu-system-arm`

## Repository Layout

- `kernel/core/`: reusable embedded library crate (`oxi_core`)
- `kernel/firmware/`: production firmware crate
- `core_test/`: embedded test firmware crate
- `rustlets/rustlet_runtime/`: shared runtime crate and ABI definitions for Rustlets
- `rustlets/complete_security_domain/`: full embedded administrative Rustlet
- `rustlets/tests/`: Rustlet functional test applications
- `xtask/`: local orchestration commands
- `tools/apdu-tool/`: host-side APDU client
- `tooling/build-fae/`: external FAE toolchain kept as a Git submodule

Within `kernel/core/src/`, the reusable layer is split as follows:

- `lib.rs`: crate root
- `core/mod.rs`: top-level wiring and public runtime-facing API
- `core/runtime.rs`: runtime initialization and low-level support
- `core/allocator.rs`: first-fit linked-list allocator used as the Rust
  global allocator
- `core/semihosting.rs`: semihosting support
- `core/serial.rs`: minimal synchronous serial API (`send_byte`,
  `receive_byte`)
- `core/crypto.rs`: low-level crypto facade and target dispatch
- `core/flash.rs`: flash service API
- `core/target/`: target-specific implementations

The production APDU loop lives in `kernel/firmware/src/`, while
`core_test/src/main.rs` provides a distinct
firmware entry point dedicated to QEMU-backed embedded testing.

## Entry Model

The FAE startup calls an exported `start()` symbol owned by the firmware
crate.

The shared pattern is:

1. the firmware `start()` calls `oxi_core::core::initialize()`;
2. the firmware executes its own logic;
3. the firmware returns through `oxi_core::core::shutdown(exit_code)`.

This keeps the ABI-facing entry point out of the reusable library while
still centralizing runtime initialization and shutdown policy.

## Runtime Split

The current runtime split is:

- APDU traffic uses the target UART;
- kernel console/debug traces are disabled by default and can be enabled with
  `--trace=semihosting` for QEMU or `--trace=jtag` on supported hardware
  targets;
- cryptographic services are provided by `oxi_core`, with board-aware
  routing between hardware support and fallback logic;
- QEMU-backed entropy uses semihosting file access, while real hardware
  keeps its target RNG path.

## Commands

Build only the default production native ELF:

```bash
cargo run build --elf
```

Build the default bootable production `.fae`:

```bash
cargo run build --fae
```

Build a bootable production firmware for `mps2-an385`:

```bash
cargo run build --fae mps2-an385
```

Build a bootable production firmware for `olimex-stm32-h405`:

```bash
cargo run build --fae olimex-stm32-h405
```

Build a bootable production firmware for `b-l475e-iot01a`:

```bash
cargo run build --fae b-l475e-iot01a
```

Run the kernel-local APDU ping check under QEMU:

```bash
cargo run test kernel_ping mps2-an385
```

Run the kernel-local T=0 APDU transcript check under QEMU:

```bash
cargo run test kernel_t0 mps2-an385
cargo run test kernel_t0 olimex-stm32-h405
```

Run the Rustlet functional campaign on one board:

```bash
cargo run test rustlet_all mps2-an385
```

Run the Rustlet functional campaign on all functional APDU/QEMU boards:

```bash
cargo run test rustlet_all
```

This means `mps2-an385` and `olimex-stm32-h405`. The
`b-l475e-iot01a` target remains available for firmware builds and layout
validation, but is excluded from interactive APDU campaigns until its QEMU UART
path is reliable.

Run the default workspace test entry point:

```bash
cargo test --offline
```

This last command is intentionally tied to the QEMU-backed embedded test
path through the workspace default members.

## Generated Artifacts

Production firmware artifacts are written under:

- `target/kernel/firmware/kernel.elf`
- `target/kernel/firmware/kernel.fae`
- `target/kernel/firmware/kernel.gdbinit`

Embedded test firmware artifacts are written under:

- `target/kernel/firmware/core_test.elf`
- `target/kernel/firmware/core_test.fae`
- `target/kernel/firmware/core_test.gdbinit`

## Validation Notes

The current bootstrap has been validated along two main paths.

Production path:

- `cargo run build --fae mps2-an385`
- `./tools/bin/run-qemu-serial.sh`
- `cargo run -p apdu_tool -- 00 06 00 00 04 04 12 34 56 78`

Embedded test path:

- `cargo run test rustlet_all`
- `cargo test --offline`

The current embedded test path executes the `core_test` firmware on:

- `mps2-an385`
- `olimex-stm32-h405`
- `b-l475e-iot01a`

and verifies its semihosting trace markers from the host side.

Those low-level markers require an explicit semihosting trace/debug build; the
normal kernel build remains `--trace=none`.

The production APDU validation path uses the `kernel/firmware` firmware and
the serial-over-TCP host tooling.

`build_fae` may emit heuristic warnings about possible absolute pointers in
readonly sections. Treat these warnings seriously; they do not prevent the
validated local QEMU flows from working.
