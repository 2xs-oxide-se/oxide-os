# Rustlet Template

This template shows the intended standalone structure for a Rustlet:

- `src/` contains only the embedded `no_std` payload.
- `xtask/` contains a small host-side Cargo tool.
- `build/` is created on demand and receives `*.elf`, `*.fae`, and `*.gdbinit`.

Typical usage from this directory:

```bash
cargo build-fae
```

Behavior:

1. the local Cargo alias dispatches to `xtask/`
2. the local `xtask` asks `build_fae_rust` to rebuild the embedded ELF in `build/`
3. `build_fae_rust --fae` packages the Rustlet with the XiPFS Rust runtime
4. the `.fae` and `.gdbinit` are emitted next to the ELF in `build/`

If you want the explicit form instead of the alias:

```bash
cargo run --manifest-path xtask/Cargo.toml -- build-fae
```

Note:

- `cargo run build-fae` cannot work with this tree shape.
- Cargo interprets that form as “run the current package and pass `build-fae` as a runtime argument”.
- Since the current package is the embedded `no_std` payload, that command tries to build the Rustlet itself as a host executable.

Environment variables:

- `RUSTLET_TARGET`: optional target triple, default `thumbv7em-none-eabi`
