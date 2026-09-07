# Oxide SE

> **Public release repository.** Development started on 3 April 2026 and
> continues in the 2XS GitLab at the University of Lille. This GitHub-facing
> repository contains curated release snapshots rather than the complete
> development history.

Oxide SE is an open source project exploring a GlobalPlatform-oriented
platform OS in Rust.

The repository is an active implementation and experimentation workspace
centered on:

- a reusable embedded core library;
- a production-oriented kernel firmware with an APDU loop;
- a dedicated embedded test firmware run under QEMU;
- a Rustlet runtime and the first Rustlet applications;
- local tooling for FAE packaging, QEMU execution, and APDU exercising.

## Status

Oxide SE is a bootstrap-stage implementation and research system.

The current tree includes working firmware builds, QEMU-backed test
flows, a Rustlet runtime ABI, and early isolation mechanisms. It should
still be read as an implementation and research workspace rather than as
a finished industrial platform or a conformance claim.

## Start Here

Begin with [`docs/getting-started.md`](docs/getting-started.md).

That guide starts with a Quickstart covering the first successful local flow:

- initialize the required submodule;
- build the QEMU-oriented kernel image;
- launch QEMU;
- connect with the APDU tool;
- run `cargo run test rustlet_all`;
- and understand what `cargo test --offline` actually validates.

## Documentation Map

Read according to your goal:

- First run and local workflow:
  [`docs/getting-started.md`](docs/getting-started.md)
- Core architecture and reusable services:
  [`docs/core.md`](docs/core.md)
- Workspace bootstrap and build notes:
  [`docs/core-bootstrap.md`](docs/core-bootstrap.md)
- Kernel build, platform, QEMU, and xtask workflow:
  [`docs/kernel.getting.started.md`](docs/kernel.getting.started.md)
- Adding or porting a board target:
  [`docs/newboard.porting.guide.md`](docs/newboard.porting.guide.md)
- First Rustlet authoring walkthrough:
  [`docs/rustlets.getting.started.md`](docs/rustlets.getting.started.md)
- Kernel-side Rustlet execution model:
  [`docs/kernel.developer.guide.md`](docs/kernel.developer.guide.md)
- Rustlet authoring model and current validation pipeline:
  [`docs/rustlet.developper.guide.md`](docs/rustlet.developper.guide.md)
- Low-level isolated-app and exception debugging:
  [`docs/isolated-app-debugging.md`](docs/isolated-app-debugging.md)
- Draft manual and longer-form reference material:
  [`docs/manual/manual.tex`](docs/manual/manual.tex)
- Open documentation and architecture debt:
  [`docs/TODO.md`](docs/TODO.md)

## Component Map

- `kernel/core/`: reusable embedded services exposed as the `oxi_core`
  crate
- `kernel/firmware/`: production-oriented firmware with the APDU transport
  loop and current Rustlet activation path
- `core_test/`: dedicated embedded test firmware executed under QEMU
- `rustlets/rustlet_runtime/`: shared runtime crate and ABI definitions
  used by Rustlets
- `rustlets/tests/`: Rustlet test applications and macro-shape coverage
- `xtask/`: local orchestration for builds, packaging, and QEMU-backed
  test flows
- `tools/apdu-tool/`: host-side APDU client for the serial-over-TCP QEMU
  path
- `tooling/build-fae/`: external FAE toolchain kept as a Git submodule

Run `cargo run test --help` for the test catalogue and board support matrix.
Each test's help lists its supported options and default board.

To add another board target, follow
[`docs/newboard.porting.guide.md`](docs/newboard.porting.guide.md).

## Rust Tooling

The repository ships a root `rust-toolchain.toml` so that nightly,
`rustfmt`, `clippy`, and `rust-src` are selected consistently.

Useful entry points:

- `cargo fmt --all`
- `cargo clippy -p xtask --all-targets`
- `cargo run build`
- `cargo run test --help`
- `cargo run test kernel_ping mps2-an385 --on qemu`
- `cargo run test rustlet mps2-an385 minimal_valid_test --check_stack`
- `cargo run test gp_all mps2-an385`
- `cargo run test rustlet_all mps2-an385`
- `cargo test --offline`

`cargo run test <name>` selects a target scenario, independently of its
execution backend. Native kernel ELF is the default; QEMU is selected when
the board supports it, otherwise OpenOCD. The initial OpenOCD scenarios are
kernel ping, T=0, kernel crypto, kernel flash, kernel registry and the minimal Rustlet. The unique USB serial link is
auto-detected; use `--serial` when several ports are present. Explicit consent
to erase the board FLASH (`--allow-destructive`) remains required. See the
[hardware runner recipe](docs/kernel.developer.guide.md#openocd-execution)
before connecting a physical target.
The centralized OpenOCD runner passed `kernel_ping`, `kernel_t0` and an
AES-128-CBC known-answer check on physical Pico2. Pico2 also passes the
`fill_random 24` benchmark using the SDK-style TRNG/PRNG adaptation (not a
cryptographic security guarantee). The complete crypto scenario passes on
Pico2 using 24-byte GET RESPONSE chunks for the P-256 result.

`cargo test --offline` runs the workspace's Rust test harnesses, including
host unit tests and configured integration tests. It is distinct from the
target scenario catalogue. See [`docs/getting-started.md`](docs/getting-started.md)
for the exact scope.

## Working Conventions

Repository materials are written in English by default.

## Licensing

This repository is licensed under CeCILL v2.1.

The project also carries a repository-specific syscall interface
exception: software that merely runs on the platform and uses its public
system calls does not become subject to CeCILL v2.1 for that reason
alone, provided it does not modify the code base in this repository and
does not link to it except through those public system calls.

See:

- `LICENSE`
- `LICENSE_EXCEPTION`
- `LICENSES/CECILL-2.1-fr.html`
- `LICENSES/CECILL-2.1-en.html`

## Author

First author: Gilles Grimaud
