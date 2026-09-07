# Contributing to Oxide SE

## Language Policy

Repository content should be written in English by default, including
README files, contributor-facing documentation, code comments, commit
messages when possible, and newly added project materials.

## Low-Level Debugging Discipline

When debugging Rustlet entry, return, exception, or ABI-transition
issues, use the documented proof-first workflow in
`docs/isolated-app-debugging.md`.

In particular:

- start from the minimal scripted `simulate_apdu` path before using the
  interactive APDU transport;
- prove one transition at a time instead of changing several low-level
  layers at once;
- move to QEMU + GDB early for assembly, privilege, PSP/MSP, SVC, and
  vector-table issues;
- keep Thumb branch/vector addresses distinct from the even memory
  addresses used for breakpoints and disassembly.

## Rust Tooling

Use the repository toolchain defaults when working on Rust code.

The repository root provides:

- `rust-toolchain.toml` for the expected nightly toolchain and required
  components;
- `rustfmt.toml` for formatting;
- `clippy.toml` for baseline lint configuration.

Prefer running:

- `cargo fmt --manifest-path core/Cargo.toml`
- `cargo clippy --manifest-path xtask/Cargo.toml --all-targets`

Target-specific clippy runs for the `core` payload may also be used when
appropriate.

## Workspace Conventions

Rustlets live under `rustlets/`.

The current layout is:

- `rustlets/rustlet_runtime`: shared runtime crate and ABI definitions for Rustlets
- `rustlets/complete_security_domain`: full embedded administrative Rustlet
- `rustlets/tests/`: functional Rustlet test applications
