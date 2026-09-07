# Rustlets Workspace

This directory groups the application-side crates of the Oxide SE workspace.

Current layout:

- `rustlet_runtime/`: shared runtime crate and ABI definitions used by Rustlets
- `complete_security_domain/`: full embedded administrative Rustlet
- `simple_security_domain/`: minimal Security Domain skeleton relying on runtime defaults
- `tests/`: Rustlet crates used by the functional QEMU campaign

The intent is to keep the repository root focused on:

- `kernel/core/`: reusable embedded services
- `kernel/firmware/`: kernel firmware
- `core_test/`: embedded core-level test firmware
- `tooling/` and `xtask/`: build and packaging support

Rustlet build artifacts are intentionally ignored from version control.

See also:

- `docs/rustlet.developper.guide.md`
