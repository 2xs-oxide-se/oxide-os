# Isolated App Debugging

This guide captures the current debugging discipline for Rustlet entry,
return, and exception transitions.

Use it when:

- a Rustlet boots but crashes during `start()`, `install()`, or
  `process_apdu()`;
- the FAE `crt0` ABI changes;
- the isolated entry/return assembly changes;
- SVC, MemManage, PSP/MSP, or vector-table behavior becomes suspect.

## Start With a Proof Plan

Do not start by patching multiple layers at once.

First define which exact control-flow facts still need proof.

The current recommended sequence is:

1. `run_isolated_app` is reached.
2. The Rustlet `crt0` entry is reached.
3. The relocated payload entrypoint is reached.
4. The payload returns to the kernel return gate.
5. The return gate executes `svc #0xff`.
6. The kernel SVC handler is entered.
7. The kernel resume path completes and returns to normal kernel code.

Until one step is proven, avoid changing the next layer.

## Use the Smallest Reproducer First

Start with the minimal scripted path before using the interactive APDU
flow.

Current baseline:

- execution environment: `simulate_apdu`
- first Rustlet under test: `rustlet_minimal_valid_test`

That path removes UART timing and richer Rustlet behavior from the
equation and isolates the ABI transition itself.

The full Rustlet campaign also starts with
`rustlet_minimal_valid_test` for the same reason.

## Address Rules That Matter

Three address forms appear in this workflow and must not be mixed:

- runtime code addresses in flash or RAM;
- Thumb-tagged branch targets and vector entries;
- actual memory addresses used by GDB breakpoints and disassembly.

Rule of thumb:

- use the odd Thumb form (`addr | 1`) for function pointers, exception
  vectors, and `bx`/`blx` targets;
- use the real even address for `break *...`, `x/i ...`, and raw memory
  inspection in GDB.

Example:

- branch/vector target: `0x200007c1`
- actual instruction address: `0x200007c0`

## Firmware Address Hygiene

Do not assume a Rust symbol value is already the final runtime address
inside a firmware FAE image.

For low-level exception work, always distinguish:

- the ELF section-relative symbol value;
- the runtime flash address after firmware packaging;
- the Thumb-tagged variant of that runtime address.

Use the generated `target/kernel/firmware/kernel.gdbinit` helper to load
symbols at their real runtime locations before trusting symbol names in
GDB.

## QEMU + GDB Workflow

Build the kernel in the scripted debug mode:

```bash
OXIDE_SE_BOARD=mps2-an385 \
OXIDE_SE_EXECUTION_ENV=simulate_apdu \
cargo run --manifest-path tooling/build-fae/Cargo.toml --bin build_fae_rust -- \
  --manifest-path kernel/firmware/Cargo.toml \
  --bin kernel \
  bootable mps2-an385
```

Run QEMU frozen at reset with a GDB stub:

```bash
qemu-system-arm \
  -machine mps2-an385 \
  -nographic \
  -monitor none \
  -serial none \
  -semihosting-config enable=on,target=native \
  -S \
  -gdb tcp::33338 \
  -kernel target/kernel/firmware/kernel.fae
```

Attach GDB from `target/kernel/firmware/`:

```bash
arm-none-eabi-gdb -q
```

Then in GDB:

```gdb
source kernel.gdbinit
file kernel.elf
target remote :33338
```

## Recommended First Breakpoints

Prefer runtime-address breakpoints over name-only breakpoints when both
the startup firmware and the kernel image expose similarly named code.

Useful starting points:

```gdb
break *0x378
```

This is the current runtime address of `gpos_core_run_isolated_app` on
the default `mps2-an385` firmware build and should be revalidated after
layout changes.

When the return gate is suspect:

```gdb
break *0x200007c0
```

This is the actual instruction address of the `svc #0xff` return gate in
the current RAM gate layout.

When the RAM exception trampolines are suspect:

```gdb
break *0x200007a8
break *0x200007b4
```

These must be set after the kernel has initialized the RAM gate region,
otherwise early startup may overwrite them before they become relevant.

## What To Inspect at Each Stage

At the isolated-app launch point:

```gdb
info registers sp msp psp control r4 r8
x/10wx $r4
```

Interpretation:

- `sp == msp` and `control == 0` means the kernel is still running on
  the privileged MSP;
- `psp == 0` before the gate switch is expected;
- `r8` carries the future Rustlet stack top;
- the `TargetAppEntry` pointed to by `r4` contains the future entry PC,
  RAM base, return PC, and entry gate PC.

During exception-entry debugging, inspect:

```gdb
info registers pc lr sp msp psp xpsr control
x/16wx 0xE000ED24
x/16wx 0x20006d80
```

This gives:

- active stack choice and privilege mode;
- fault-status registers (`SHCSR`, `CFSR`, `MMFAR`, ...);
- the current RAM vector-table contents.

If the RAM vector table points to odd addresses in the gate region but
execution still lands in the firmware fault loop, the failure is likely
occurring during exception entry or vector fetch rather than later in
the Rustlet payload.

## Current Failure Pattern To Recognize

One known failure shape is:

1. `run_isolated_app` is reached.
2. The payload returns to the gate.
3. The saved stacked PC points to the instruction after `svc #0xff`.
4. The CPU escalates to `HardFault_Handler` or the firmware
   `MemManage_Handler` loop instead of entering the kernel SVC or
   MemManage redirect path.

That pattern means the issue is in exception entry, vector resolution,
or privilege/stack state, not in the higher-level APDU logic.

## Discipline Rules

- Make one low-level change at a time, then re-run the same proof plan.
- Prefer a scripted APDU scenario before a transport-backed scenario.
- Do not trust symbol names until their runtime addresses are validated.
- Record whether an address is: ELF-relative, runtime, or Thumb-tagged.
- For assembly/exception bugs, move to GDB early instead of relying on
  semihosting logs alone.
