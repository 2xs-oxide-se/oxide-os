# New Board Porting Guide

This guide explains how to add a new board target to Oxide SE.

It is written for someone who knows the target board and can write bare-metal
Rust, but who should not need to understand the whole Oxide SE kernel
architecture before starting.

Before using this guide, you should already know:

- how to build `no_std` Rust code for your bare-metal target;
- the memory map, startup requirements, UART/debug facilities, and optional
  flash/RNG peripherals of your board;
- how to use Oxide SE as a user. If not, start with
  [`getting-started.md`](getting-started.md). For kernel build commands, see
  [`kernel.getting.started.md`](kernel.getting.started.md).

## Porting Model

A board port provides a small hardware contract to Oxide SE:

- where RAM and executable storage are located;
- how the CPU starts the kernel image;
- how the kernel sends and receives APDU bytes;
- how debug output and shutdown work;
- which optional services exist, such as flash persistence and hardware
  entropy.

Most of the kernel does not need board-specific knowledge. Your job is to add
the board-facing pieces, register the board name in the build tooling, and
raise the declared support level only when the matching tests pass.

Follow the steps in order. Each step validates one subsystem and deliberately
avoids depending on the next subsystem:

1. create the board target file and implement the board-facing hardware
   contract;
2. fill in the board memory layout;
3. add the native startup file and, when required, the bootable FAE startup
   file;
4. register the board in the kernel build;
5. register the board in `xtask` at the `BuildOnly` support level;
6. boot the kernel and observe the ATR on QEMU or real hardware;
7. validate the kernel-local APDU tests on an available validation
   environment;
8. validate GlobalPlatform first without SCP, then with kernel-owned SCP,
   without executing Rustlets;
9. validate Rustlet execution step by step before raising the board to
   `Rustlet`;
10. measure kernel and Rustlet stack high-water marks;
11. implement flash persistence, validate recovery, then test post-issuance
    Rustlet loading;
12. document the real-hardware build, flashing, wiring, and debug workflow;
13. update the user-facing board and support-level documentation.

The five functional phases are: kernel only; GP without SCP; GP with
kernel-owned SCP; Rustlet execution; persistence and post-issuance validation.
Implement entropy before the crypto checks in step 7 and the SCP checks in
step 8. The aggregate GP campaign comes at the end of step 11. Until then, a
new port can expose zero persistence pages and keep the registry in RAM.

Commands containing `<board>` or `<serial-device>` are templates: replace
those placeholders before running them. QEMU examples require a QEMU-capable
board; do not substitute `raspi-pico2`, which uses OpenOCD. Native ELF is the
default image format. Hardware tests require an explicit board and erase
consent; use disposable hardware contents throughout this guide.

Do not skip directly from “the ELF boots” to “run every Rustlet test”. If a
later step fails, go back to the last passing step and debug only the subsystem
introduced by the failing step.

Each step below is written as a small recipe:

- what must be made true at this stage;
- which file or directory you normally edit;
- which existing board is a useful model;
- which command proves that this stage is good enough to move on.

If a validation command fails, do not widen the investigation immediately. The
point of the sequence is to keep the debug surface small: a failure in the ATR
step is still a boot or UART problem, not a Rustlet, SCP, registry, or
persistence problem.

## Porting Level And Validation Environments

The board support level is declared in `xtask/src/lib.rs`, inside the
`BOARD_CATALOG` entry for the board.

- `BuildOnly`: the board metadata, target file, generated linkers, and startup
  files compile far enough for layout inspection.
- `KernelApdu`: the kernel boots, emits its ATR, and passes the kernel-local
  APDU checks.
- `GlobalPlatformApdu`: simple GlobalPlatform management APDUs work without
  requiring Rustlet execution.
- `Rustlet`: the selected-app and Rustlet entry/return path is validated.

Start with `BoardSupportLevel::BuildOnly`, then raise the level as each step
below is validated.

The validation environment is recorded independently in the same catalog
entry:

- `qemu_support: true` means the declared level is reproducible under QEMU;
- `board_support: true` means the declared level is reproducible on a physical
  board using its documented flash/reset runner and APDU transport;
- both flags may be `true` when both paths pass;
- both flags remain `false` while no execution runner is validated.

A true flag is a claim about the current `support_level`, not merely a claim
that the runner can start an older image. If hardware has reached `Rustlet`
but QEMU has reached only `KernelApdu`, declare the level/flags conservatively
or keep separate evidence until both environments reach the advertised level.
Only entries with `support_level: Rustlet` and `qemu_support: true` participate
in `cargo run test rustlet_all` when no board is specified.

Promotion rule: change the support level only after the validation command for
that level passes reproducibly. A board that builds but does not yet boot stays
`BuildOnly`; a board that passes kernel APDUs but not GlobalPlatform management
stays `KernelApdu`, regardless of whether that validation ran on QEMU or a
physical board.

## Running Examples: Pico 1 And Pico 2

The examples below use Raspberry Pi Pico boards as a guide. They are examples
of where code belongs and which questions to ask during a port; they are not a
statement that the corresponding support level is already reached.

For Pico 2, use the RP2350 Cortex-M33 port as a concrete example:
`raspi_pico2.rs` supplies UART0, clock, TRNG and flash operations, and selects
`armv8m_profile` for CPU primitives. When creating a similar port, implement
these peripherals progressively rather than enabling all of them for the first
boot. The optional RISC-V cores require a different CPU profile.

For Pico 1, the target chip is RP2040. It is a Cortex-M0+ part, so it is a
more constrained port than the existing Cortex-M3/M4 QEMU boards. A first
Oxide SE image can still target `--elf`, boot through a `raspi-pico` QEMU
machine, and exchange APDU bytes over UART. Its `armv6m_profile` supplies
Rustlet entry, MPU isolation and HardFault recovery without assuming that a
separate MemManage exception exists. Do not substitute the M3/M4 profile.

Before reusing this port, read the [RP2040 porting caveats](porting-caveats/rp2040.md)
for its entropy limitations, MPU-based stack protection, XIP flash constraints,
and the distinction between QEMU and physical-board validation.

Keep this separation in mind:

- board hardware code goes in `kernel/core/src/core/target/<board>.rs`;
- startup assembly goes under `kernel/native/<board>/` and optionally
  `kernel/bootable/<board>/`;
- build/run metadata goes in `xtask/src/lib.rs`;
- compile-time board selection goes in `kernel/core/build.rs` and
  `kernel/core/src/core/target/mod.rs`.

There are also two different compilation domains:

- the kernel is compiled by the root workspace build path selected by `xtask`;
- Rustlet payloads are compiled separately as FAE applications, with their own
  Rust target and their own FAE runtime startup code.

Do not assume that a board is fully ported only because the kernel ELF boots.
For example, a Cortex-M0+ board needs a Cortex-M0+ kernel build and also
Cortex-M0+-compatible Rustlet FAE startup code. These are related decisions,
but they are configured in different places.

## 1. Create The Board Target File

For a board named `<board>`, copy:

```text
kernel/core/src/core/target/board_template.rs
```

to:

```text
kernel/core/src/core/target/<board_module>.rs
```

Replace the placeholder values and implement the functions described in the
template.

The board file is the only place that should directly touch board registers for
basic target services. It must provide:

- `MEMORY_LAYOUT`
- `initialize()`
- `timer_clock_hz()`
- `send_byte()`
- `receive_byte()`
- `debug_write_byte()`
- `shutdown()`
- `flash_initialize()`
- `flash_persistence_area()`
- `flash_logical_page_size()`
- `flash_erase_sector_size()`
- `flash_erase_sector()`
- `flash_write_page()`
- `flash_flush_page()`
- `flash_write_page_atomic()`
- `crypto_initialize()`
- `crypto_fill_random()`

If a service does not exist yet, return the explicit unsupported error rather
than pretending that it works. For example, flash functions can return
`FlashError::Unsupported`, and `crypto_fill_random()` can return
`CryptoError::EntropyUnavailable`.

Recipe for this step:

1. Copy `board_template.rs` to the new board module path.
2. Fill only the memory layout and the minimal functions needed to build.
3. Return explicit unsupported errors for flash and entropy until they are
   intentionally implemented.
4. Register and compile the module in steps 4 and 5; copying an unregistered
   file does not make Cargo compile it.

For a Pico 2-style port, this file is where you would write the RP2350
register code that:

- configures the system clocks needed by the UART and kernel timing
  assumptions;
- selects the GPIO alternate functions for the UART pins used as the APDU
  transport;
- initializes the UART baud/divider/FIFO state used by `send_byte()` and
  `receive_byte()`;
- optionally initializes a debug channel, such as a second UART, ITM-like
  trace path if available, or a no-op fallback;
- optionally enables the TRNG clock/state before `crypto_fill_random()`;
- optionally prepares QSPI flash access for persistence, once persistence is
  part of the port.

Do not put this hardware initialization in `xtask`. `xtask` runs on the host
machine and only builds, configures, or launches the firmware. The code that
touches RP2350 UART, clock, GPIO, TRNG, or flash registers belongs in the board
target module copied from `board_template.rs`.

`timer_clock_hz()` must report the frequency feeding architectural SysTick
after `initialize()` has configured the clock tree. The common ARM M-profile
code derives its 1 ms hardware tick from this value; boards do not duplicate
the SysTick register driver. Validate the value with:

```sh
cargo run test kernel_timer <board> --on qemu
```

The scenario requests a 10 ms callback, waits on the host, then compares the
top-half and bottom-half counters returned by the target. A count far above or
below the expected order of magnitude usually means that `timer_clock_hz()`
does not describe the effective CPU clock.

Use existing boards as examples:

- `mps2-an385`: small QEMU Cortex-M3 target;
- `olimex-stm32-h405`: Cortex-M4 QEMU target with RNG setup;
- `b-l475e-iot01a`: known build/layout board that is not part of the Rustlet
  QEMU campaign by default.
- `raspi-pico1`: Cortex-M0+ QEMU target with a board-specific startup/linker
  shape, UART pin muxing, and flash persistence work.
- `raspi-pico2`: Cortex-M33 hardware target with an ARMv8-M MPU profile,
  UART0, TRNG and ROM-backed flash operations.

Watchpoints:

- The Rust target triple, assembler `-mcpu`, startup `.arch`, and actual CPU
  profile must agree. A Cortex-M0+ board is not a smaller Cortex-M3 from the
  compiler's point of view.
- Keep unsupported services explicit. A blocking stub or silent fake backend
  makes later failures look like APDU, SCP, or persistence bugs.
- If a board has no usable entropy yet, SCP profiles that require freshness
  should not be claimed as validated.

## 2. Fill In The Memory Layout

The `MEMORY_LAYOUT` constant tells Oxide SE where the board memory is:

```rust
pub const MEMORY_LAYOUT: crate::core::target::layout::TargetMemoryLayout = ...
```

Fill in:

- `name`: the board name used by build commands;
- `ram_base` and `ram_size`: RAM available to the kernel image;
- `flash_base` and `flash_size`: executable or persistent storage window;
- `kernel_heap_min_size`: minimum heap budget expected after static data and
  stack placement;
- `kernel_stack_size`: kernel stack size.

`xtask` generates the board linker wrappers from `MEMORY_LAYOUT`. The wrapper
declares the board `FLASH`, `RAM`, and `__STACK_SIZE_CPU0` values, then includes
one linker body.

The firmware calls `core::kernel_stack_overflow_protection()` at the start of
the Rust entry sequence. On targets that advertise ARMv8-M stack-limit
registers, the core programs `MSPLIM` from the declared kernel stack window.
Other CPU profiles implement the same hook as a no-op; startup assembly must
not duplicate this policy.

Rustlet stack protection follows the same rule. The loader retains the full
`AppMemoryWindow` for each Rustlet stack, the isolation layer programs
`PSPLIM` before entering the Rustlet, and the common return/fault cleanup clears
it. This hardware bound is independent of the MPU stack guard and of the
optional `kernel-stack-monitor` and `rustlet-stack-monitor` modules, which only
measure high-water marks.

Recipe for this step:

1. Edit `MEMORY_LAYOUT` in `kernel/core/src/core/target/<board_module>.rs`.
2. Do not edit linker scripts for plain RAM/flash/stack-size changes.
3. Keep `kernel_stack_size` conservative during bring-up.
4. Set `kernel_heap_min_size` to the minimum heap you expect after `.data`,
   `.bss`, stack, boot ABI, and runtime windows are placed.
5. Validate the accounting with `cargo run dump_kernel_layout --elf <board>`
   once the board is registered in `xtask`.

Most Cortex-M boards use the shared linker bodies:

```text
kernel/native/generic-cortex-m/link.ld
kernel/bootable/generic-cortex-m/link.ld
```

Do not create a board-specific linker body only to change RAM size, flash size,
or kernel stack size. If those values change, update only `MEMORY_LAYOUT`; the
generated wrapper will carry the corresponding `__STACK_SIZE_CPU0`, `RAM`, and
`FLASH` values.

Create a board-specific native linker body only when the section layout itself
must differ from the shared Cortex-M shape. Both Pico ports provide examples:

```text
kernel/native/raspi-pico/link.ld
kernel/native/raspi-pico2/link.ld
```

`linker_script_include()` in `xtask/src/lib.rs` selects these bodies for
`raspi-pico1` and `raspi-pico2` respectively. Extend that selection when adding
a board that needs a special layout. They keep the generated `MEMORY` wrapper
and add the Pico-specific
`.critical.kernel.fct` section whose load address is in XIP flash and whose run
address is in SRAM, as well as a reserved persistence window. Other boards include
`kernel/native/generic-cortex-m/link.ld` and do not copy critical functions to
RAM by default.

The isolation layer recycles the last MPU region slots for kernel-phase RAM
execute-never windows. While a Rustlet runs, those slots may be used as normal
Rustlet text/RAM regions. While the kernel runs, the same slots may be
reprogrammed as `Privileged RW + XN` over mutable RAM. A board gets that
protection automatically when its mutable RAM can be described as one or two
strict MPU windows that do not cover code that must execute from RAM. If a port
adds a RAM-resident critical section like `.critical.kernel.fct`, place it
outside the RAM-XN windows and keep the heap/runtime mutable area below the same
limit used by `kernel_heap_end()`.

For a Pico 2-style port, the first memory-layout question is not “how much RAM
is on the chip?” but “which contiguous RAM window do we give to the kernel
image, stack, heap, Rustlet allocations, and registry objects?” RP2350 has
multiple SRAM banks; the first simple port can expose one conservative
contiguous RAM window, then refine placement later if bank-aware layout becomes
useful. The flash window should describe the executable storage view used by
the chosen boot mode; persistence can remain unsupported even if executable
flash is present.

For Pico 1/RP2040, a typical first layout uses XIP flash at `0x1000_0000` and
SRAM at `0x2000_0000`. RP2040 SRAM is split into banks, so a conservative
single contiguous SRAM window is usually easier for a first build than a
bank-aware layout. The support level can stay `BuildOnly` while this layout is
being checked.

Watchpoints:

- The linker script consumes `MEMORY_LAYOUT`; do not hard-code a second RAM or
  FLASH map in startup assembly unless the board genuinely needs special boot
  glue.
- Kernel stack, boot ABI, `.data`, `.bss`, kernel heap, Rustlet allocations,
  and registry objects all compete for the same RAM budget.
- A board can have executable flash without having persistence support. Do not
  wire `flash_write_page*()` until the erase/program/atomicity contract is
  understood.

## 3. Add Startup Files

Create the native startup file:

```text
kernel/native/<board>/native_rt0.s
```

The native startup file is used when generating a fixed-address kernel ELF,
that is the `--elf` build mode. This is the ordinary board image path when the
loader expects an ELF-shaped firmware.

Create a bootable FAE startup file if the board should support bootable FAE
images:

```text
kernel/bootable/<board>/boot_rt0.s
```

The bootable startup file is used only when generating a bootable FAE image,
that is the `--fae` build mode. This path is useful when the kernel must be
packaged as a FAE payload, for example for an execution environment or
hypervisor that expects this bootable packaging format.

If your board can reuse the generic Cortex-M startup shape, copy from
`kernel/native/generic-cortex-m/` and `kernel/bootable/generic-cortex-m/`, then
adjust only the board-specific `.arch`, vector table, and `board_name` values.

Recipe for this step:

1. Create `kernel/native/<board>/native_rt0.s`.
2. Decide whether the generic Cortex-M reset body is compatible with your CPU.
3. If it is compatible, provide the board vector table and include
   `kernel/native/generic-cortex-m/native_rt0.s`.
4. If it is not compatible, write a complete board-specific reset body with the
   same responsibilities.
5. Add `kernel/bootable/<board>/boot_rt0.s` only if the board must support the
   `--fae` kernel image mode.

For a Pico 2-style `--elf` port, inspect the existing RP2350 startup:

```text
kernel/native/raspi-pico2/native_rt0.s
```

It is a complete board-specific startup, not a wrapper around the generic
file. Keep these responsibilities when adapting it:

- `.arch armv8-m.main` and `.thumb` match the Cortex-M33 build;
- `.vectors` defines `__Vectors`, its alignment, the initial `__StackTop`
  word and `Reset_Handler`;
- `.picobin_block` supplies RP2350 boot-ROM image metadata, retained by the
  board linker; this is separate from the vector table and from a Rustlet FAE;
- HardFault, MemManage, UsageFault and SVC vectors point at real handlers;
  in particular, UsageFault is needed for MSPLIM/PSPLIM overflow;
- reset sets VTOR, copies `.critical.kernel.fct` and `.data`, clears `.bss`,
  and calls `start()`;
- exception stubs forward through the kernel boot ABI once initialized, or
  provide a fatal diagnostic before that point.

For a board without those RP2350-specific requirements, the smaller
`kernel/native/mps2-an385/native_rt0.s` illustrates the alternative: a vector
table and board name followed by an include of the generic reset/exception
body. Do not include that body as well as defining your own handlers.

The include is therefore not there because `start()` has a complicated ABI. It
is there when the board wants to reuse the common reset and exception
implementation. `start()` itself is simply:

```rust
extern "C" fn start() -> !
```

It takes no arguments and does not return. The include is useful because it
provides the common reset and exception-handler implementation that prepares a
valid Rust/no-std world before calling `start()`. If a board does not include
the generic file, it must still provide an equivalent sequence:

- set `sp` from `__StackTop`;
- install the vector table if the CPU/loader path requires it;
- copy every RAM-executed initialized section required by the linker body;
- copy `.data`;
- zero `.bss`;
- call `start` with no arguments;
- provide observable fatal handling if `start` ever returns or a fatal fault is
  raised before `oxi_core` installs its handlers.

For RP2350/Cortex-M33, explicitly decide what happens to Armv8-M security
features during this first `--elf` port. If TrustZone/SecureFault is not used,
keep that path disabled at boot and leave the unused vectors as zero. If the
board boot ROM or image format enters Oxide SE in a security state where a
SecureFault handler is required, add the matching vector intentionally rather
than relying on the generic Cortex-M3/M4 table by accident.

Do not duplicate linker logic only to change RAM or flash sizes. Those values
should come from `MEMORY_LAYOUT` and the generated linker wrapper. Likewise,
do not initialize UART, clocks, GPIO, TRNG, or flash in `native_rt0.s` unless
the CPU cannot reach Rust code without that tiny setup. Ordinary board
initialization belongs in `kernel/core/src/core/target/raspi_pico2.rs`
inside `initialize()`.

If the board uses a board-specific linker body with extra RAM-executed
sections, the startup file must copy those sections before calling `start`.
For example, both Pico native startups copy `.critical.kernel.fct` from its
flash load address to its SRAM run address before copying `.data` and zeroing
`.bss`. Do not add that copy to the generic Cortex-M startup unless every board
that includes the generic linker also defines the same section and needs the
same runtime policy.

For a Pico 1/RP2040 `--elf` first port, do not blindly include the generic
Cortex-M startup if it emits instructions or exception assumptions that do not
fit Cortex-M0+. A minimal native startup may need to be board-specific while
still following the same responsibilities:

- define `__Vectors` at the flash/XIP load address;
- set `sp` from `__StackTop`;
- set `SCB_VTOR` if the CPU and loader path support it;
- leave kernel FAE/static-base register setup out of the native ELF path unless
  a future audited compiler/runtime contract explicitly reintroduces it;
- copy `.data` from flash to RAM;
- zero `.bss`;
- call `start`;
- provide a minimal hard-fault/shutdown path that the selected QEMU or hardware
  runner can observe.

Watchpoints:

- Startup code is the earliest place where a CPU-profile mismatch appears:
  Thumb-2 instructions that work on M3/M4 may be illegal on M0+.
- The generic Cortex-M startup is a reset/exception implementation, not just a
  convenient way to call `start()`.
- The native ELF path does not need the kernel FAE/static-base register setup
  before `start()`. FAE packaging has its own startup contract.
- QEMU loaders are not all equivalent. Some machines load an ELF directly into
  the executable flash window; others go through a ROM or firmware path.
- Keep hardware initialization out of startup unless Rust cannot be reached
  without it. UART pins, UART baud rate, clocks, RNG, and flash controller
  setup should normally live in the board target module.

## 4. Register The Board In The Kernel Build

Update:

```text
kernel/core/build.rs
```

Add:

- one `cargo:rustc-check-cfg=cfg(oxide_se_board_<board_cfg>)` line;
- one `OXIDE_SE_BOARD` match arm that emits
  `cargo:rustc-cfg=oxide_se_board_<board_cfg>`.

This lets the Rust compiler select your board module when the build command
sets `OXIDE_SE_BOARD=<board>`.

Recipe for this step:

1. Add the board cfg in `kernel/core/build.rs`.
2. Add the board module in `kernel/core/src/core/target/mod.rs`.
3. Add the board to the target-dispatch macros in the same file.
4. Add the board memory-layout mapping.
5. Add `mpu_region_policy()` only as far as the MPU backend is really
   implemented. Use `unsupported()` during bring-up if needed.
6. Add the board `FAE_STATIC_BASE` constant following the existing pattern.
7. Run `cargo test -p xtask --lib` after the `xtask` catalog entry exists.

### Choose The CPU Profile Before Writing Peripheral Code

In your copied `kernel/core/src/core/target/<board>.rs`, select one of:

| CPU | Profile | MPU model |
| --- | --- | --- |
| Cortex-M0+ (Pico1) | `armv6m_profile` | Power-of-two windows, HardFault recovery |
| Cortex-M3/M4 | `armv7m_profile` | Power-of-two windows, MemManage |
| Cortex-M33 (Pico2) | `armv8m_profile` | 32-byte-granular base/limit, MemManage, stack-limit registers |

For Pico2, the board declaration is:

```rust
#[cfg(oxide_se_board_raspi_pico2)]
pub(crate) use super::armv8m_profile as cpu;
```

In `kernel/core/build.rs`, add your board to the `profile` match so it emits
`oxide_se_target_armv8m` for this example. In `target/mod.rs`, follow the
existing board-specific alias:

```rust
#[cfg(all(not(test), target_arch = "arm", oxide_se_board_raspi_pico2))]
use raspi_pico2::cpu as app_target_profile;
```

These two selections must agree. The architectural cfg decides which source
and assembly files compile; the board alias chooses the implementation used
by the facade. Host tests continue to use `generic` instead of hardware MMIO.

You do not need to implement the MPU or exception entry again for another
board using an existing profile. Keep UART, clocks, RNG and flash in the board
file. Keep RAM/flash sizes in `MEMORY_LAYOUT`; review the derived stack,
boot ABI and RAM-XN windows in `target/mod.rs` for your layout. Never insert
your board name or peripheral addresses into the CPU profile.

`common_arm_m_profile.rs` contains only shared mechanisms. Its `mainline.rs`
submodule supplies the identical v7-M/v8-M exception path; v6-M has separate
assembly and fault recovery. Profile files explicitly re-export their shared
functions, so they also show which functions are architecture-specific.

After registration in step 5, validate the selection with
`cargo run build --config configs/config_kernel_ping.toml <board>`. An unsupported
assembly instruction or missing `cpu` alias is a registration/profile problem,
not a UART problem. Later, at the isolation stage, validate RAM-NX and Rustlet
fault recovery before claiming MPU support. On v8-M, NoAccess cannot be encoded
as a region permission: MSPLIM protects kernel stack growth and PSPLIM protects
the Rustlet stack. Do not copy the v7-M guard-region implementation.

For Pico2, inspect `.critical.kernel.fct` in `kernel/native/raspi-pico2/link.ld`.
The final 16 KiB (`0x2007e000..0x20082000`) are reserved for RAM-executed code,
outside the heap. The first 504 KiB are kernel RW/XN in region 6; the kernel
stack stays at the RAM base. Keep this boundary consistent with
`PICO2_EXECUTABLE_RAM_SIZE` in `target/mod.rs`, and ensure startup copies the
executable section. The linker rejects an overflowing section.

ARMv8-M cannot overlay the kernel NX region on user RAM regions. Its profile
disables conflicting windows during kernel execution; the isolation layer
restores the gate and application windows from the existing plan before user
entry. Do not copy the ARMv7-M overlapping-region assumption into a new port.

Do not run Rustlet or flash tests at this registration stage. Step 7 validates
the kernel protections; step 9 validates application isolation; step 11
validates flash programming and recovery.

Then update:

```text
kernel/core/src/core/target/mod.rs
```

Add:

- the real board module declaration;
- the host/test fallback module that re-exports `generic`;
- one line in `dispatch_target_board!`;
- one line in `target_board_memory_layout!`;
- one line in `mpu_region_policy()`;
- one `FAE_STATIC_BASE` constant for your board.
- the board's `cpu` alias as `app_target_profile`, as shown above.

The two macros are deliberately small. They only prevent repeated
`match board()` blocks for ordinary target hooks.

`mpu_region_policy()` and `FAE_STATIC_BASE` stay explicit because they are
compile-time or hardware-policy decisions. When porting a board, copy the
pattern used by an existing board unless your MPU or memory layout requires a
different rule.

For Pico 2, keep the naming aligned with the existing Pico 1 port. A sensible
mapping is:

- command-line board name / `OXIDE_SE_BOARD`: `raspi-pico2`;
- Rust module: `raspi_pico2.rs`;
- cfg name: `oxide_se_board_raspi_pico2`;
- startup directory: `kernel/native/raspi-pico2/`;
- optional bootable directory to create only for a future FAE boot port:
  `kernel/bootable/raspi-pico2/` (not provided by the native ELF port);
- human-facing description: Raspberry Pi Pico 2 / RP2350.

The exact spelling is less important than keeping the same mapping everywhere:
`OXIDE_SE_BOARD` value, `BOARD_CATALOG.env_name`, target module name,
generated startup directory, and `kernel/core/build.rs` cfg arm.

Watchpoints:

- The board name appears in several forms: command-line board name, Rust module
  name, cfg name, startup directory, QEMU machine name, and linker-output
  stamps. Keep a deliberate mapping and avoid “nearly identical” spellings.
- Select the architectural cfg and board CPU alias consistently. A profile
  must not compile another architecture's exception assembly accidentally.
- `mpu_region_policy()` is a capability statement. Use `unsupported()` until
  the MPU model and exception recovery path are actually wired.

The kernel compiler configuration is split between these files:

- `xtask/src/lib.rs`: host-side board catalog, QEMU machine name, Rust target
  triple, assembler flags, startup directory, and support level.
- `xtask/src/testing/target.rs`: QEMU command construction, serial connection,
  ATR synchronization and target cleanup. Keep board-specific launch details
  here, not inside the APDU scenarios in `xtask/src/testing/scenarios/`.
- `kernel/core/build.rs`: converts `OXIDE_SE_BOARD=<board>` into the
  board cfg and the architectural `oxide_se_target_armvXm` cfg used by core.
- `kernel/core/src/core/target/mod.rs`: selects the board module and the
  target backend code compiled into `oxi_core`.
- `kernel/native/<board>/native_rt0.s`: native kernel ELF startup assembly.
- `kernel/bootable/<board>/boot_rt0.s`: optional bootable-kernel FAE startup
  assembly, used only by `--fae`.

The normal `--elf` kernel path does not use the Rustlet FAE runtime startup.
It uses `kernel/native/<board>/native_rt0.s`.

If a validation failure mentions an unknown cfg, unknown board, missing module,
or missing startup directory, stay in this step. Do not debug QEMU yet; the
host build graph is not complete.

## 5. Register The Board As `BuildOnly`

Update:

```text
xtask/src/lib.rs
```

Add one `BoardCatalogEntry` to `BOARD_CATALOG`.

Fill in:

- `machine`: QEMU `-machine` name, if QEMU supports the board;
- `env_name`: Oxide SE board name, also passed as `OXIDE_SE_BOARD`;
- `startup_dir`: directory name under `kernel/native/` and `kernel/bootable/`;
- `rust_target`: Rust target triple;
- `target_source`: path to your board target file;
- `compiler_flags`: assembler flags for the startup file;
- `support_level`: initially `BoardSupportLevel::BuildOnly`.
- `qemu_support`: initially `false` until the declared level is reproducible
  under QEMU;
- `board_support`: initially `false` until the declared level is reproducible
  on physical hardware.
- `openocd_target`: `None` without a debugger recipe, or an installed OpenOCD
  target script such as `Some("target/rp2350.cfg")`. This does not promote
  the support level or mark hardware validation as completed.

This catalog is only for host-side `cargo run ...` commands. It does not
configure firmware behaviour at runtime.

Recipe for this step:

1. Add one `BoardCatalogEntry` in `xtask/src/lib.rs`.
2. Set `support_level: BoardSupportLevel::BuildOnly`.
3. Set `qemu_support: false` and `board_support: false`.
4. Point `target_source` to the board module created in step 1.
5. Point `startup_dir` to the native startup directory created in step 3.
6. Use assembler flags and Rust target triple that match the real CPU.
7. Validate with the commands below before raising the support level or an
   environment flag.

For the kernel, `rust_target` and `compiler_flags` are the main
compiler-facing values in the catalog. They must describe the CPU that
executes the kernel image. For example, a Cortex-M0+ board should use a
Thumbv6-M Rust target such as `thumbv6m-none-eabi` and assembler flags such as
`-mcpu=cortex-m0plus -mthumb`; a Cortex-M3/M4 board must not reuse those flags
blindly.

For a Pico 2-style first entry, use the Arm Rust target that matches the
chosen core profile. If the port targets the Cortex-M33 side, that is expected
to be a Thumbv8-M target rather than the existing Cortex-M3/M4 targets used by
`mps2-an385` and `olimex-stm32-h405`. The assembler flags must match the same
CPU choice. If no QEMU machine is available, fill the catalog for build/layout
commands, keep the support level at `BuildOnly`, and leave `qemu_support`
false. Set `board_support` only after the real-hardware path is reproducible.

For a Pico 1-style QEMU port, `machine` is `raspi-pico`, `env_name` should be
the Oxide SE board name such as `raspi-pico1`, and the Rust target is expected
to be a Cortex-M0+ target such as `thumbv6m-none-eabi`. If the required QEMU
support comes from a dedicated external QEMU tree, teach `xtask` where to find
that `qemu-system-arm` binary instead of assuming the system QEMU supports the
board.

Validate the `BuildOnly` stage:

```sh
cargo test -p xtask --lib
cargo run dump_kernel_layout --elf <board>
```

If both commands pass, keep the board at `BoardSupportLevel::BuildOnly` and
move to the boot stage in whichever validation environment is available.

At this point, success means only “the host can build and inspect the image”.
It says nothing yet about reset vectors, UART, APDUs, Rustlets, SCP, flash, or
fault recovery.

Watchpoints:

- `cargo test -p xtask --lib` should catch catalog/linker consistency. Run it
  before chasing QEMU behavior.
- `dump_kernel_layout --elf <board>` validates the build path and memory
  accounting without requiring UART, QEMU, or APDU behavior.
- Keep the support level at `BuildOnly` even if the ELF builds, until the boot
  command itself is reproducible.

## 6. Boot The Kernel And Observe The ATR

Implement only enough startup, linker-layout, shutdown, debug output, and
serial transmit behaviour for the kernel to boot and emit its ATR. At this
point, do not run Rustlets, SCP or persistence scenarios.

The CPU profile selected in step 4 must already be wired: even a kernel-only
boot initializes runtime services and kernel stack protection. This does not
require a successful Rustlet entry/return or application MPU test. Those are
separate acceptance checks in step 9.

Recipe for this step:

1. Make `native_rt0.s` reach `start()`.
2. Make `initialize()` configure only the hardware needed to send bytes.
3. Make `send_byte()` transmit one byte reliably.
4. Make `shutdown()` observable by the runner, or document that QEMU/hardware
   must be stopped externally during bring-up.
5. Build and boot the image in one available validation environment: QEMU,
   real hardware, or both.

Use the existing `configs/config_kernel_ping.toml`, which contains only:

```toml
[kernel-image]
mode = "kernel-only"
kernel-app-modules = ["ping"]
```

```sh
cargo run build --config configs/config_kernel_ping.toml <board>
```

The output is `target/kernel/firmware/kernel.elf`. No Rustlet instance or
GlobalPlatform hierarchy is installed by this image. The first checkpoint is
simply receiving its ATR. The automated `kernel_ping` command below builds
this same configuration and continues with APDUs; only that second part needs
working serial reception as well as transmission.

The test catalogue checks the board's declared capabilities before launching
anything. To try this next stage locally, provisionally set
`support_level: BoardSupportLevel::KernelApdu` and `qemu_support: true`
once your emulator can run the machine. Keep those settings only after the
test passes; if it fails, restore the last validated level before publishing
the port. Use the same candidate-then-validation procedure for
`GlobalPlatformApdu` and `Rustlet` below. A hardware-only board cannot use
`--on qemu`. The runner defaults to OpenOCD for such a board; when QEMU is
available it remains the default. No failed test switches backend implicitly.

For a CMSIS-DAP/SWD port, set `openocd_target` in its `BoardCatalog` entry
to the target script supplied by OpenOCD. Pico1 uses `target/rp2040.cfg`;
Pico2 uses `target/rp2350.cfg` and needs an OpenOCD installation supporting
RP2350. This setting describes how to connect, not proof that the port works.
The APDU UART bridge is a separate connection from the debug probe.

In `raspi_pico2.rs::send_byte`, every write checks UARTFR.TXFF (bit 5), and
every 32nd byte first waits for UARTFR.BUSY to clear so both FIFO and shift
register are drained. This is peripheral backpressure, not a fixed-duration
delay. Match the actual UART clock, baud rate and 8N1 framing at both ends;
do not confuse TXFF with RXFF. Step 7 tests long responses against the bridge.

**Hardware recipe (destructive):** replace the serial device below, then run:

```sh
cargo run test kernel_ping raspi-pico1 --on openocd \
  --serial /dev/cu.usbmodemXXXX:115200 --allow-destructive
```

The command announces and erases the entire declared FLASH window, including
persistent objects. Omit `--allow-destructive` to see the affected range
without touching the device. Add `--probe-serial ID` if several CMSIS-DAP
adapters are connected. Serial is 115200 8N1 here, with no flow control.
Use the board's configured UART baud rate if different.

The runner programs and verifies the ELF while halted, opens and drains the
serial link, **then** releases reset and receives the ATR. It halts the target
at the end, also on failure. Expected result: a validated ATR, one successful
echo/response-length campaign (34 assertions), and `KERNEL-PING-DONE`. Diagnose `stage=launch` against the
OpenOCD installation/probe, `stage=program/reset` against flash/boot setup,
and `stage=ATR` against UART/clock/reset initialization.
On Pico2, use `raspi-pico2`; `--on openocd` can be omitted.
With one USB UART bridge connected, `--serial` can also be omitted: the runner
selects the unique USB serial port at 115200 baud. With several USB ports, it
lists the available links and commands to choose one explicitly. For example:

```sh
cargo run test kernel_ping raspi-pico2 --on openocd --allow-destructive
```

For a QEMU-capable board, use:

```sh
cargo run test kernel_ping <board> --on qemu
```

This command boots the kernel-only ping image, opens the QEMU serial transport,
reads the ATR, then checks a kernel-local echo and a no-data response. It also
checks deterministic payloads of 16, 32, ..., 240 and 255 bytes, both as direct
responses driven by Le and as echoes retrieved with a single GET RESPONSE.
Success reports `KERNEL-PING-DONE ... total=34`. Each length is logged before
its exchange, so a timeout identifies the failing direction and size. This
scenario uses no bridge-specific GET RESPONSE chunk limit.
The separate no-data command has no Le: short Le=00 would mean 256 bytes,
which exceeds the current 255-byte payload limit.

For a hardware-only port, build the native ELF, convert or package it in the
board's boot format when necessary, flash it, connect `apdu_tool` to the
physical serial device, and reset the board while the tool is waiting for the
ATR. Record the exact build, conversion, flashing, serial-device, and reset
commands in the board documentation. Do not require a QEMU machine merely to
complete this stage.

If either path fails before the ATR is printed, debug only startup and serial
transmit:

- reset vector and initial stack pointer;
- `.data` copy and `.bss` zeroing;
- `SCB_VTOR` or equivalent vector-table setup;
- board `initialize()`;
- UART clock, pin mux, baud rate, and transmit-ready polling;
- QEMU serial command line.

For a profile that preinstalls instances, also inspect the initialization work
before ATR emission: Rustlet installation and persistent registry commits run
before the APDU loop. The target test client separates its five-second socket
connection deadline from a 120-second firmware-initialization allowance, and
logs `ATR validated after ...s`. These are host wall-clock test deadlines, not
ISO reset-to-ATR timing guarantees. A slow first boot must be measured before
being mistaken for a broken UART; use a kernel-only ping image to isolate the
serial port from predeployment work. APDU byte and frame-idle timeouts remain
independent.

If the ATR is received but the ping APDU fails, keep working in this step: the
board can transmit bytes but the receive path or APDU byte pacing is not yet
reliable.

For a Pico 1/RP2040 QEMU path, the runner selects `-machine raspi-pico`, passes
the ELF with `-kernel`, and connects a serial socket. Leave `flash-file` and
reboots without `-kernel` to the persistence validation in step 11.

Watchpoints:

- Kernel console/debug traces are disabled by default. Use
  `--trace=semihosting` when a QEMU bring-up step needs semihosting logs, and
  keep `--trace=none` for hardware-oriented images that must not execute
  semihosting breakpoints. `--trace=jtag` is currently accepted only for
  `raspi-pico1`; a new board should reject it until a real target debug trace
  hook is implemented.
- Semihosting is not universal. If the QEMU board has a synthetic shutdown or
  debug mechanism, wire `shutdown()` and `debug_write_byte()` to that path or
  document that the test must be killed externally.
- A successful ELF build does not prove that the reset vector, VTOR, stack
  pointer, `.data`, or `.bss` startup sequence is correct.
- If QEMU has stricter peripheral modeling than older boards, unimplemented
  MMIO logs are often more useful than kernel-side guesses.

## 7. Validate Kernel-Local APDUs

Build a kernel-only image containing the `ping` `KernelAppModule`. This avoids
GlobalPlatform predeployment and Rustlet loading, so failures remain limited
to startup, the transport, T=0 framing, and the kernel APDU dispatcher.

Keep the `configs/config_kernel_ping.toml` configuration from step 6:

```toml
[kernel-image]
mode = "kernel-only"
kernel-app-modules = ["ping"]
```

Build the image for the board:

```sh
cargo run build --elf --config configs/config_kernel_ping.toml <board>
```

The configured modules are statically linked into the kernel image. They are
not Rustlets and are not dynamically installed applications. `xtask` forwards
the ordered names without knowing individual modules. The firmware build
resolves them through
`kernel/firmware/src/kernel_app_modules_registry.inc.rs`, then generates one
static slice per hook type. There is no runtime registration or allocation.

The mapping is direct: `"ping"` selects
`kernel/firmware/src/kernel_main_app/ping.rs`. The order in
`kernel-app-modules` is significant: the first APDU filter that recognizes a
command handles it. Observer hooks run in the same declared order.

`global-platform` is the default image mode for existing manifests and still
requires `[root]`. A `kernel-only` manifest must omit `[root]`,
`[[security_domains]]`, and secure-channel configuration. The current names
are `ping`, `t0-test`, `crypto-self-test`, `flash-probe`, `registry-test`,
`kernel-stack-monitor`, and `rustlet-stack-monitor`. Generic malformed names
and duplicates are rejected by `xtask`; names absent from the central registry
are rejected by the firmware build.

### QEMU validation

When a QEMU machine exists for the board, run:

```sh
cargo run test kernel_ping <board> --on qemu
```

Then build a kernel-only image containing the T=0 diagnostic module and run
the complete kernel-local transcript:

```sh
cargo run test kernel_t0 <board> --on qemu
```

### Hardware validation

With a configured OpenOCD target, the next automated step is:

```sh
cargo run test kernel_t0 raspi-pico1 --on openocd \
  --serial /dev/cu.usbmodemXXXX:115200 --allow-destructive
```

Expect `KERNEL-T0-DONE` with four checks: empty command, incoming data,
outgoing data with a `6C` length retry, and bidirectional transfer.
Each hardware test starts from erased FLASH, not the preceding command's state.
See [OpenOCD execution](kernel.developer.guide.md#openocd-execution) for the
shared runner's reset, serial and cleanup contract.

When the port is validated on real hardware, flash the same kernel-only image,
start `apdu_tool` on the physical serial link, then reset the board so that the
tool receives the ATR. For example:

```sh
cargo run -p apdu_tool -- \
  --serial /dev/<serial-device>:115200 \
  80 FE 00 00 04 04 12 34 56 78
```

The expected response echoes the four input bytes and ends in success:

```text
DATA OUT (4): 12 34 56 78
SW: 90 00
```

Use the actual serial-device path and baud rate selected by the board port.
Start the tool before resetting the target when the ATR is emitted only once
at boot.

After ping succeeds, repeat the build with both kernel diagnostic modules:

```toml
[kernel-image]
mode = "kernel-only"
kernel-app-modules = ["ping", "t0-test"]
```

Run the same T=0 cases as the QEMU campaign through `apdu_tool`:

- ATR delivery;
- no-data APDU;
- inbound APDU data;
- outbound data with `6C` retry;
- in/out APDU.

Passing in one environment proves the kernel APDU level in that environment.
Passing on hardware does not imply QEMU support, and passing under QEMU does
not imply that clocks, pin muxing, UART wiring, or flashing work on hardware.
Record each environment independently. A port may have no validation runner
during its initial build-only stage, one runner, or both runners.

After the transcript is reproducible, set:

```rust
support_level: BoardSupportLevel::KernelApdu,
qemu_support: true,  // only when the QEMU path passed
board_support: true, // only when the physical-board path passed
```

Use `false` for either environment that has not passed this level.

The transport checks do not prove GlobalPlatform management or Rustlet
execution. Validate the kernel protections next, and add entropy before the
optional crypto check below.

If the transcript fails after ping passes, look at `receive_byte()`, byte
pacing, APDU procedure-byte handling, and the selected host transport. Do not
change registry, Rustlet loading, or secure-channel code for a failure at this
level.

### Validate Kernel Protection Before Entering A Rustlet

Inspect the CPU profile selected in step 4 and the protection windows derived
in `kernel/core/src/core/target/mod.rs`. The kernel stack stays at the RAM
base; RAM-executed code must remain outside the mutable RAM-XN window. These
tests exercise kernel faults, not application fault recovery:

```sh
cargo run test kernel_ram_nx <board> --on qemu
cargo run test kernel_stack_guard <board> --on qemu
```

Use those commands only for a supported QEMU board. The hardware observation
backend for these two diagnostics is currently enabled only for Pico2:

```sh
cargo run test kernel_ram_nx raspi-pico2 --on openocd --allow-destructive
cargo run test kernel_stack_guard raspi-pico2 --on openocd --allow-destructive
```

The RAM-NX test uses OpenOCD vector catch, not an APDU response. Expect
`RAM-NX-EVIDENCE CFSR=00000001 HFSR=00000000`, a stacked PC in mutable RAM
pointing at `BX LR`, and `KERNEL-RAM-NX-DONE ... total=1`.

The ARMv8-M stack probe saves the initial MSPLIM, raises it to the current MSP,
then executes a PUSH. OpenOCD stops at the UsageFault entry before the handler
uses the exhausted stack. Expect `STACK-GUARD-EVIDENCE CFSR=00100000
HFSR=00000000` and `KERNEL-STACK-GUARD-DONE ... total=1`. The runner also checks
the initial limit against the declared kernel stack base. This proves
stack-limit enforcement, not recovery from a kernel overflow. Wire the
UsageFault vector even when MemManage already works.

Both hardware probes halt the target afterward; unrelated faults and timeouts
fail the test. For another physical board, port the observation mechanism in
`xtask/src/testing/openocd.rs` before claiming an automated fault-test result.

### Add Entropy Before Testing Crypto

Implement `crypto_initialize()` and `crypto_fill_random()` in the board target
file. For Pico2, inspect the RP2350 TRNG code in `raspi_pico2.rs`. Until a
trustworthy source is ready, return `CryptoError::EntropyUnavailable` rather
than manufacturing production randomness. Deterministic QEMU-only entropy
must remain explicitly separated from the physical-board path.

You do not need new AES, CMAC, KDF or P-256 implementations: the common crypto
backend supplies them. Test it independently of Rustlets:

```sh
cargo run test kernel_crypto <board> --on qemu
cargo run test kernel_crypto raspi-pico2 --on openocd --allow-destructive
```

Choose the available backend, not both commands indiscriminately. The default
crypto scenario is a smoke test, not every primitive. Consult
`cargo run test kernel_crypto --help` and run individual `--bench` operations
when diagnosing a specific primitive. Step 8 uses a restricted SCP scenario
scope without Rustlets; the full integration scenarios wait until step 9.

## 8. Validate GlobalPlatform Without Rustlets

### 8.1 Start Without A Secure Channel

Oxide SE expects a simple byte stream for APDU exchange. By this point, the
kernel-local T=0 transcript should already have passed in the selected
environment. This step moves one layer up: it checks that GlobalPlatform
management APDUs work over the same transport, still without requiring
Rustlet application code to run.

In the board file:

- `send_byte(byte)` must block until one byte is accepted by the board
  transport;
- `receive_byte()` must block until one byte is available and return it;
- bytes must not be reordered, dropped, or synthesized.

For QEMU boards this is normally a UART connected to the host test process. For
hardware boards this is whatever physical link you expose to the APDU tool.

Do not add buffering unless the board hardware requires it. If buffering is
required, make the ordering and blocking behaviour equivalent to a byte stream.

Recipe for this step:

1. Keep using the same UART/APDU transport as in the kernel-local T=0 test.
2. Under QEMU, run `cargo run test gp_noscp <board> --on qemu`.
3. On Pico2 hardware, use the OpenOCD command below for the same scenario.
4. Check discovery and clear-command rejection, not application execution.
5. Raise the board to `GlobalPlatformApdu` only after the selected environment
   is reproducible.
6. Proceed to the kernel SCP checks below; leave Rustlet execution to step 9.

Kernel application modules are not restricted to `kernel-only` images. For
optional kernel-stack evidence during this GlobalPlatform stage, add the
following section to the complete GlobalPlatform manifest used by the port;
keep its existing `[root]` and other predeployment sections unchanged:

```toml
[kernel-image]
kernel-app-modules = ["kernel-stack-monitor"]
```

The ordinary GlobalPlatform dispatcher remains active when no selected module
claims an APDU. At this stage, before any Rustlet execution, only the kernel
measurement is expected to become nonzero. `gp_noscp` does not accept
`--check_stack`; use the explicit module configuration for this optional
diagnostic. Step 10 describes the instrumented Rustlet scenarios.
On hardware, query its four-byte big-endian high-water mark over the same
serial link after replaying the management transcript:

```sh
cargo run -p apdu_tool -- \
  --serial /dev/<serial-device>:115200 \
  80 CA DF 71 00 04
```

This diagnostic strengthens the evidence for the port but is not a condition
for claiming `GlobalPlatformApdu`. Remove the module from production images
that do not need the measurement.

For Pico 2, a minimal hardware path would typically choose one RP2350 UART and
wire it to the host through a USB-UART adapter. In `initialize()`, configure
the selected TX/RX GPIO pins for UART function and program the UART baud rate.
In `send_byte()`, wait on the UART transmit-ready condition before writing one
byte. In `receive_byte()`, wait on the UART receive-ready condition before
reading one byte. These functions are the only APDU transport hooks the kernel
needs at this layer; T=0 framing and APDU parsing stay in common kernel code.

For Pico 1/RP2040 under `raspi-pico`, UART0 is connected to the host serial
backend only after the GPIO function select for GPIO0/GPIO1 is set to UART when
strict UART pin checking is enabled. That pin mux belongs in `initialize()`.
After that, `send_byte()` and `receive_byte()` can poll the PL011-style UART
flag register.

Watchpoints:

- Do not debug APDU framing before verifying that one raw byte can actually
  cross the UART in each direction.
- Some emulators model pin muxing. A UART register write may be accepted while
  no byte reaches the host because the GPIO alternate function is wrong.
- `debug_write_byte()` and APDU transport may share a UART only during bring-up
  if that does not corrupt the APDU byte stream. Once APDU tests start, debug
  output on the same serial link can look like protocol corruption.

Validate the QEMU path, when available:

```sh
cargo run test gp_noscp <board> --on qemu
```

Or validate the hardware path:

```sh
cargo run test gp_noscp raspi-pico2 --on openocd --allow-destructive
```

The scenario uses `configs/config_noscp_test.toml`: a NullSecurityDomain,
no SCP and no Rustlet package. Expect `NO-SCP-DONE`, including GP discovery
and rejection of INITIALIZE UPDATE. The `qemu` in the config filename does not
restrict its use to QEMU. Do not run `gp_security_domain` yet: that campaign
also invokes Rustlets.

If this scenario passes, update the board catalog entry:

```rust
support_level: BoardSupportLevel::GlobalPlatformApdu,
qemu_support: true,
```

For a hardware validation, use `BoardSupportLevel::GlobalPlatformApdu` with
`board_support: true` and keep `qemu_support: false`. This level still does not
mean that Rustlet entry, FAE runtime startup, syscall forwarding, entropy, or
fault recovery work.

### 8.2 Add Kernel-Owned Secure Channels

Prerequisites: clear GP works, the kernel crypto checks in step 7 pass, and
`crypto_fill_random()` provides the appropriate entropy for this backend.
Application MPU entry and Rustlet execution are not required for this scope.

Use `--without-rustlets` on the existing SCP scenarios:

```sh
cargo run test gp_scp03 <board> --on qemu --scp03=all --without-rustlets
cargo run test gp_scp11a <board> --on qemu --without-rustlets
cargo run test gp_scp11b <board> --on qemu --without-rustlets
cargo run test gp_scp11c <board> --on qemu --without-rustlets
```

Or on physical Pico2:

```sh
cargo run test gp_scp03 raspi-pico2 --on openocd --allow-destructive --scp03=all --without-rustlets
cargo run test gp_scp11a raspi-pico2 --on openocd --allow-destructive --without-rustlets
cargo run test gp_scp11b raspi-pico2 --on openocd --allow-destructive --without-rustlets
cargo run test gp_scp11c raspi-pico2 --on openocd --allow-destructive --without-rustlets
```

This option derives a manifest containing only the root KernelSecurityDomain,
its keys and the selected SCP configuration. Root Rustlet packages and all
child SD declarations are removed, including SCP11b's preinstalled test
instance. The generated manifest path is printed. No Rustlet payload is built,
embedded or installed. The firmware remains a **GlobalPlatform image**, not
`[kernel-image] mode = "kernel-only"`, which would remove the GP dispatcher.

The shared scenarios check discovery, authentication, protected GET DATA,
error/replay handling and final root-SD liveness. SCP03 also exercises
encrypted STORE DATA and key rotation. SCP11b checks rejection of management
operations without owner authentication; rejected INSTALL/LOAD commands do
not execute a Rustlet. Expect the ordinary `SCP03-DONE` / `SCP11x-DONE`
completion markers together with the `scope=kernel-scp` build message.

Use `--scp03=s8` or `--scp03=s16` for a focused run. `--without-rustlets` is
accepted only by these four SCP commands. It cannot be combined with
`--check_stack` or `--update_stack_baseline`: those baselines describe the
full workload and must not be replaced by a smaller bring-up measurement.

After this step, the kernel authority can communicate securely without relying
on application code. The result does not validate a Rustlet-backed SD,
application installation, userland isolation or persistence across reset.

## 9. Validate Rustlet Execution Step By Step

### Wire Application Isolation Before The First INSTALL

Before any command in this step, inspect these files in order:

1. `kernel/core/src/core/target/<board_module>.rs`: select the appropriate
   `cpu` profile, as in step 4. Peripheral functions remain in this file.
2. `kernel/core/src/core/target/mod.rs`: check `mpu_region_policy()`, the gate
   and application memory windows, and the kernel RAM-XN boundary against the
   board layout. An `unsupported()` policy is not sufficient for this step.
3. `kernel/core/src/core/target/armv6m_profile.rs`, `armv7m_profile.rs` or
   `armv8m_profile.rs`: reuse the profile's MPU, app entry/return and fault
   primitives. For a new CPU architecture, implement these before running a
   Rustlet; successful kernel ping is not a substitute.
4. `kernel/native/<startup_dir>/native_rt0.s`: wire SVC and the profile's
   fault forwarding. Cortex-M33 also needs UsageFault for stack limits;
   Cortex-M0+ uses its recoverable HardFault path rather than MemManage.

`kernel/core/src/core/isolation.rs` is the common caller: it installs the
application MPU plan, switches to unprivileged execution, then restores kernel
protection on return or fault. Normally no board-specific code belongs there.
Inspect that flow to check your profile contract, not to duplicate it.

On ARMv8-M, validate recursive overflow as well as out-of-window accesses.
`PSPLIM` violations produce `UsageFault.STKOF`, not MemManage. The shared
Mainline handler recovers a pure STKOF only from an active Rustlet in Thread
mode using PSP. It must not read the possibly incomplete exception frame or
resume the failed PSP: recovery uses the saved kernel context and reports
`6F00`. Kernel/MSP overflow remains fatal. See the ARMv8-M Architecture Reference
Manual, section B3.21, for stack-limit checks during exception entry.

The minimum requirement is a valid entry/return and isolation configuration.
The deliberate fault probes below validate its enforcement afterward. Never
disable isolation just to obtain a passing INSTALL.

### Exercise One Capability At A Time

Validate Rustlets one capability at a time. Do not start with
`test rustlet_all`; it intentionally mixes many subsystems and is a poor first
debug target.

The commands below without `--on openocd` are QEMU recipes. First enable the
candidate `Rustlet` level locally as described in step 6, then retain it only
after validation. For Pico2, the runner permits the following narrow hardware
probe without promoting the catalogue level:

```sh
cargo run test rustlet raspi-pico2 minimal_valid_test --on openocd --allow-destructive
```

Expect `RUSTLET-SINGLE-DONE`: installation, selection and ordinary application
commands must pass. This is the first Rustlet execution test in this guide,
not an ATR/serial bring-up test. Pico1 also supports this narrow OpenOCD
scenario with an explicit serial port if needed.

Pico1 and Pico2 also expose the other standalone Rustlet scenarios and the
aggregate campaigns without promoting the catalogue support level. Use
`raspi-pico1` instead of `raspi-pico2` below for an RP2040 board:

```sh
cargo run test rustlet raspi-pico2 apdus_test --on openocd --allow-destructive
cargo run test rustlet_isolation raspi-pico2 --on openocd --allow-destructive
cargo run test rustlet_all raspi-pico2 --on openocd --allow-destructive
```

Follow the progression below before running the aggregate campaigns. Each
command erases firmware and persistent registry data. Hardware and QEMU reuse
the APDU scenarios in `xtask/src/testing/scenarios/rustlets.rs`: a fault test
requires the expected error response and subsequent successful execution, not
a timeout. Other hardware boards remain limited to the minimal Rustlet probe;
extend their runner support only when the corresponding observation path is
available.

Recipe for this step:

1. Build and run `minimal_valid_test`.
2. Only then test ordinary APDU exchange with `apdus_test`.
3. Only then test state serialization.
4. Only then test crypto/randomness.
5. Only then test intentional faults and full Rustlet campaigns.

First validate that the kernel can install a Rustlet package, jump to the FAE
entrypoint, let the Rustlet runtime start, and receive a normal return:

```sh
cargo run test rustlet <board> minimal_valid_test --on qemu
```

This proves the minimum Rustlet entry/return path. It does not prove complex
APDU buffering, persistent state, crypto, random generation, or fault recovery.

Then validate ordinary Rustlet APDU input/output:

```sh
cargo run test rustlet <board> apdus_test --on qemu
```

This isolates application APDU cases from state and crypto. If this fails
after `minimal_valid_test` passes, debug APDU shared-buffer handling and the
Rustlet syscall path before touching MPU or crypto.

Then validate serialized Rustlet state and reload:

```sh
cargo run test rustlet <board> state_test --on qemu
cargo run test rustlet <board> serialization_test --on qemu
```

These tests prove that instances can keep and reload serialized state within
one boot; they do not yet prove flash persistence across reset. If they
fail while `apdus_test` passes, focus on registry/object state, instance
selection, and serialization buffers.

Then validate crypto and random generation:

```sh
cargo run test rustlet <board> crypto_test --on qemu
```

This test requires a deliberate `crypto_fill_random()` policy. On real
hardware, use a trustworthy entropy source or return
`CryptoError::EntropyUnavailable`. In QEMU, a deterministic test-only stream is
acceptable if it is clearly limited to the QEMU execution environment. If this
test fails while the state tests pass, debug the target entropy path and crypto
syscalls before changing Rustlet isolation.

Then validate fault recovery and stack/MPU behaviour:

```sh
cargo run test rustlet <board> stack_overflow_test --on qemu
```

This test is the first one that deliberately expects a Rustlet fault to be
contained. On Cortex-M3/M4/M33 targets this normally goes through MemManage
or the configured stack-limit exception. On
Cortex-M0+ targets, the equivalent recovery path may need to inspect HardFault
context because there is no separate MemManage exception. Do not claim this
step until the kernel survives the fault and can keep processing APDUs.

Finally validate the broader Rustlet campaign:

```sh
cargo run test rustlet_all <board> --on qemu
```

If these commands pass, update the board catalog entry:

```rust
support_level: BoardSupportLevel::Rustlet,
qemu_support: true,  // only when the QEMU path passed
board_support: true, // only when the physical-board path passed
```

Only boards at the `Rustlet` level with `qemu_support: true` are selected by
`cargo run test rustlet_all` when no board is specified.
Use `false` for either environment that has not passed the complete Rustlet
sequence; the maturity level and the validation environments remain separate.

Watchpoints:

- Rustlet execution is a stronger claim than kernel APDU execution. It needs
  app entry/return, syscall forwarding, memory isolation, and fault recovery.
- Do not mark a board `Rustlet` only because management APDUs pass.
- On constrained CPU profiles, an initial board port may intentionally stop at
  `GlobalPlatformApdu` while a dedicated isolation backend is designed.

Rustlet compilation has its own configuration path. Test Rustlets are built by
the grouped Rustlet test xtask under:

```text
rustlets/tests/xtask/
```

The target CPU for Rustlet payloads is selected with `RUSTLET_TARGET` when a
non-default target is needed. The generated payload is a `.fae` file, and the
FAE packaging tool chooses the Rustlet runtime startup that matches that
target. The low-level Rustlet runtime assembly lives in the external FAE
tooling:

```text
tooling/build-fae/rt0/arm-thumb/
```

For a Cortex-M0+ board, make sure the Rustlet FAE runtime startup is also
Cortex-M0+-compatible. A kernel built for Thumbv6-M cannot safely execute a
Rustlet payload whose FAE rt0 contains Thumb-2 instructions.

This is separate from the kernel startup assembly:

```text
kernel/native/<board>/native_rt0.s
```

Use the kernel startup to bring up the operating system. Use the FAE runtime
startup to enter Rustlet payloads after the kernel has loaded them.

### Reuse The SCP Scenarios With Rustlet Integration

Once Rustlet entry, APDUs and crypto work, rerun the same SCP commands **without**
`--without-rustlets`. The default full scenarios now additionally install or
select a minimal application and exercise its APDUs; their existing coverage
and stack baseline identities are retained.

```sh
cargo run test gp_scp03 <board> --on qemu --scp03=all
cargo run test gp_scp11a <board> --on qemu
cargo run test gp_scp11b <board> --on qemu
cargo run test gp_scp11c <board> --on qemu
```

The corresponding Pico2 hardware commands are:

```sh
cargo run test gp_scp03 raspi-pico2 --on openocd --allow-destructive --scp03=all
cargo run test gp_scp11a raspi-pico2 --on openocd --allow-destructive
cargo run test gp_scp11b raspi-pico2 --on openocd --allow-destructive
cargo run test gp_scp11c raspi-pico2 --on openocd --allow-destructive
```

SCP11b uses a preinstalled instance because card authentication alone does not
authorize installation. The other profiles exercise their authorized INSTALL
path. These tests use embedded code; loading a new FAE over APDUs and recovering
it across reboot are the separate post-issuance checks in step 11.

## 10. Measure Kernel And Rustlet Stack Heights

Perform this step after `minimal_valid_test` passes in step 9. The purpose is
to measure the maximum observed use of both stack domains under a known
workload:

- the privileged kernel stack, reported by `GET DATA DF71`;
- the selected Rustlet stack, reported by `GET DATA DF72`.

Both values are unsigned 32-bit big-endian byte counts. The monitors measure
high-water marks by painting and scanning stack memory; they do not enforce a
limit and do not replace MSPLIM/PSPLIM or MPU-based fault containment.

### 10.1 Build A Focused Instrumented Image

Use a complete GlobalPlatform/Rustlet manifest that already passes
`minimal_valid_test`, then add the two diagnostic modules:

```toml
[kernel-image]
kernel-app-modules = ["kernel-stack-monitor", "rustlet-stack-monitor"]
```

Do not use a `kernel-only` image for this measurement: the second monitor
needs an actual Rustlet entry and return. Keep every other setting identical
to the previously validated image so the comparison remains meaningful.

For the canonical Rustlet scenario, use the versioned manifest already provided
by the repository:

```text
configs/config_rustlet_minimal_valid_stack_test.toml
```

Run the focused measurement with:

```sh
cargo run test rustlet --on qemu --check_stack \
  --config configs/config_rustlet_minimal_valid_stack_test.toml \
  <board> minimal_valid_test
```

`--check_stack` derives the instrumented build input, ensures that both stack
monitor modules are present, runs the APDU scenario, reads DF71 and DF72, and
compares the kernel result with the baseline identified by the command, board,
image format, execution environment, scenario, and monitor profile. A growth
against an existing reference fails the check; a reduction and a missing
reference are reported without rewriting the baseline.

### 10.2 Run The Same Measurement On Hardware

Once `kernel_ping` works on the board, exercise the kernel stack instrumentation
through the same runner and APDU observer used by QEMU:

```sh
cargo run test kernel_ping <board> --on openocd \
  --allow-destructive --check_stack
```

The runner builds the instrumented ELF, programs and resets the target, runs the
ping APDU, queries DF71 through the active serial session, and checks the
hardware-specific baseline. Use `--serial <endpoint>:115200` when automatic
serial-port selection is ambiguous. Replace `--check_stack` with
`--update_stack_baseline` only after the measurement has been reviewed and the
tracked worktree is clean.

At the later Rustlet validation level, a stack-capable Rustlet scenario can be
run in exactly the same way. Until that scenario is supported by the board,
the following manual method remains useful for inspecting DF71 and DF72.

Build the instrumented manifest through the normal board image path:

```sh
cargo run build --elf --config <stack-test-config.toml> <board>
```

Use `--fae` instead of `--elf` if that is the boot format validated for the
board. Flash the image, start `apdu_tool` on the real serial link, reset the
board so the tool receives the ATR, and replay the successful
`minimal_valid_test` install/select/process transcript from step 9.

Keep the same boot and APDU session alive after the Rustlet returns, then query
both high-water marks. The APDUs are:

```sh
cargo run -p apdu_tool -- \
  --serial /dev/<serial-device>:115200 \
  80 CA DF 71 00 04

cargo run -p apdu_tool -- \
  --serial /dev/<serial-device>:115200 \
  80 CA DF 72 00 04
```

Each command must return four data bytes followed by `9000`. Decode the four
bytes as one big-endian `u32`. DF72 must be nonzero after the Rustlet ran; a
zero value means that no Rustlet stack sample has been recorded in the current
boot.

`apdu_tool` sends one APDU and exits. On reconnect it first waits for an ATR;
if none arrives before its read timeout, it prints `ATR: <none>` and still
sends the command. The two invocations can therefore query the same boot, as
long as opening the serial port does not reset the device (check the adapter's
DTR/RTS wiring). For automated measurements, prefer one open serial descriptor
for the install/select/process sequence and both probes. Do not reset between
Rustlet execution and DF72: reset clears the recorded high-water mark.

### 10.3 Check The Result Against The Declared Stacks

Record, for each result, the board, execution environment, image format,
configuration file, tested commit, compiler version, declared stack size, and
observed high-water mark. Accept this step only when:

1. DF71 is nonzero and does not exceed either the declared kernel stack size or
   the project's 6144-byte high-water budget;
2. DF72 is nonzero and remains below the stack window allocated to the tested
   Rustlet with the required safety margin;
3. repeated cold boots and representative APDU exchanges give coherent
   results; and
4. the board still processes an APDU after the measured Rustlet returns.

The runners enforce a global 6144-byte kernel high-water budget, capped by the
declared stack size of the target. Treat that as an automated regression limit,
not as proof that the remaining space is sufficient for every hardware
interrupt pattern or production workload. Exercise representative hardware
interrupts and the longest expected APDU paths before selecting a final stack
size.

Once the focused scenario passes, run the broader QEMU campaign when the board
has QEMU support:

```sh
cargo run test rustlet_all <board> --on qemu --check_stack
```

If a scenario exceeds its hard budget, fix the additional stack use or make a
reviewed, deliberate stack-size change. Do not turn an overflow into a passing
test merely by recording the larger observation as a new baseline.

### 10.4 Update A Reviewed Baseline

Only after reviewing a stable measurement and confirming that it remains
inside the hard stack budget, update the focused baseline with:

```sh
cargo run test rustlet --on qemu --update_stack_baseline \
  --config configs/config_rustlet_minimal_valid_stack_test.toml \
  <board> minimal_valid_test
```

Baseline updates require clean tracked sources and record the measured commit.
Use `--on openocd --allow-destructive` instead for a hardware baseline; it is
stored separately from the QEMU result even for the same board and scenario.
Update mode enforces the absolute stack budget but intentionally replaces the
matching reference without rejecting an increase against its old value. Review
the resulting diff: accepting that diff is the approval of the new measurement.
Commit the resulting `xtask/stack-baselines.toml` change separately enough that
the workload, stack-size, or compiler change which justified it can be
reviewed. Re-run the corresponding `--check_stack` command afterward.

Watchpoints:

- Measure kernel and Rustlet stacks in the same image, but keep their values
  and acceptance budgets separate.
- A nonzero DF72 proves that the Rustlet lifecycle hooks ran; it does not prove
  Rustlet isolation or fault recovery.
- Validate MSPLIM/PSPLIM or MPU protection through their dedicated fault tests,
  not through these high-water values.
- Stack observations depend on the workload and compiler. Re-measure after
  changing optimization, logging, APDU paths, interrupt use, or kernel app
  modules.

This measurement supplies evidence for the `Rustlet` validation reached in
step 9; it does not add another `BoardSupportLevel`. Set `qemu_support` and
`board_support` only for environments in which the corresponding functional
and stack-validation sequences were actually run.

## 11. Implement And Validate Flash Persistence

The goal is to preserve registry objects and dynamically loaded Rustlet code
across reset. Follow this order: configure storage, implement erase/program,
test raw flash, test registry recovery, then test post-issuance installation.
Do not begin with a secure-channel loading campaign to debug a flash driver.

Steps 6 to 10 can use a RAM-only registry on a new port. Until this step is
ready, return `FlashPersistenceArea { start: 0, page_count: 0 }` from the board's
`flash_persistence_area()` and explicit unsupported errors for writes. A
nonzero area enables real persistence work during registry initialization;
do not advertise one while its erase/program hooks are still stubs.

### 11.1 Reserve Storage And Declare Its Geometry

Edit `kernel/core/src/core/target/<board_module>.rs` and, for a layout with
reserved flash, `kernel/native/<startup_dir>/link.ld`. The selection of a
board linker body is in `linker_script_include()` in `xtask/src/lib.rs`.
`MEMORY_LAYOUT.flash_size` describes the actual physical flash capacity, not
just the registry reservation. Check it against the fitted device before
allowing an erase.

Use the Pico2 port as a worked example:

| Location | Setting | Pico2 value / meaning |
|---|---|---|
| `kernel/core/src/core/target/raspi_pico2.rs` | `MEMORY_LAYOUT.flash_base`, `flash_size` | `0x10000000`, 4 MiB physical flash |
| Same board file | `FLASH_PAGE_SIZE` | 256 bytes per programming page |
| Same board file | `FLASH_SECTOR_SIZE` | 4096 bytes per erase sector |
| `kernel/native/raspi-pico2/link.ld` | `__registry_persistence_page_size` | `0x100`, must match the board page size |
| Same linker body | `__registry_persistence_erase_sector_size` | `0x1000`, must match the board sector size |
| Same linker body | `__registry_persistence_page_count` | 1024 programming pages, not 1024 sectors |

The linker derives the reserved size as page size times page count and places
it at the end of flash: `0x103C0000..0x10400000` in this example (256 KiB).
`__registry_persistence_start` and `__registry_persistence_page_count` are
absolute linker symbols; `raspi_pico2.rs::flash_persistence_area()` takes their
addresses as integer values, not bytes to dereference. Keep the linker
assertion that `__flash_image_end` does not overlap this reservation.

The sector size must be a multiple of the programming page size. Reserve
whole sectors, with a sector-aligned start and end. A registry object may span
several contiguous programming pages; its first byte starts at a page boundary.
The initialization marker page and live records also consume space, so the
declared capacity is not all available as object payload. Erase protection
operates on their containing sectors, not just on individual live pages.

Build and inspect before executing any write:

```sh
cargo run build --config configs/config_kernel_flash_probe.toml <board>
cargo run dump_kernel_layout --config configs/config_kernel_flash_probe.toml <board>
```

Also inspect the linker symbols in the generated ELF. With the GNU Arm tools
used for the Pico ports:

```sh
arm-none-eabi-nm -n target/kernel/firmware/kernel.elf | grep __registry_persistence
```

Compare the start/end, page size, sector size and page count with the table.
For other toolchains, use their `nm`/`readelf` equivalent. The linker symbols
are authoritative for special reservations; the general layout summary is
not a substitute for checking them. A successful link only proves internal
consistency, not that the physical chip has the declared capacity.

### 11.2 Implement Sector Erase And Page Programming

Implement the following hooks in the board target file. The common interface
is `kernel/core/src/core/flash.rs`, dispatched through `target/mod.rs`; register
the board there as in step 4 if a hook is not forwarded yet.

| Hook | Required behaviour |
|---|---|
| `flash_initialize()` | Prepare the controller; it must not erase or reformat storage on every boot. |
| `flash_persistence_area()` | Return the reserved start and count of programming pages. |
| `flash_logical_page_size()` | Return the programming page size in bytes. |
| `flash_erase_sector_size()` | Return the erase sector size in bytes. |
| `flash_erase_sector(address)` | Check bounds/alignment, erase exactly one sector to `FF`, wait for completion and report errors. |
| `flash_write_page(address, bytes)` | Check bounds/alignment and a full-page buffer; program only permitted `1 -> 0` transitions, without an implicit erase. Return only when the contents are readable by the registry. |
| `flash_flush_page(address)` | Complete pending writes and make their contents observable, or explicitly do nothing when page programming is already synchronous. |
| `flash_write_page_atomic(address, bytes)` | Provide the documented board-local operation; never imply power-failure atomicity that the hardware cannot guarantee. |

Inspect `flash_write_persistence_page()` and `flash_erase_persistence_sector()`
in `raspi_pico2.rs`, or the corresponding Pico1 code in `raspi_pico.rs`.
Pico2 uses the boot-ROM flash functions. Code that must execute while XIP is
unavailable belongs in `.critical.kernel.fct`, copied by native startup and
excluded from the mutable RAM-XN window. Audit callees, literals and interrupt
handlers as well as the outer function: no flash fetch may depend on the
disabled XIP path. Finish controller/cache synchronization before returning.

**Transaction invariant:** never erase a sector containing the latest valid
registry or an object it still references. Write replacement objects first,
then publish a new registry record with its integrity check. Until publication
succeeds, the previous registry and its objects remain recoverable. Page writes
and sector erases may be interrupted by loss of power; a function named
`atomic` cannot remove that failure mode on Pico flash.

The common allocator in `kernel/firmware/src/object_registry_persistence.rs`
finds erased pages or sectors whose contents are obsolete. It scans the whole
circular window, including holes. The board driver must not maintain a second
allocation cursor or erase neighbouring pages opportunistically. Unused pages
after a sector erase remain `FF` and will be discovered by subsequent scans.
See Chapter 6 of the [manual](manual/Chapter_6.tex) for the record/commit model.

### 11.3 Validate Raw Flash With `flash-probe`

Choose one of these automated paths:

```sh
cargo run test kernel_flash raspi-pico1 --on qemu
cargo run test kernel_flash raspi-pico2 --on openocd --allow-destructive
```

For another board, the QEMU backend must implement persistent flash, or the
OpenOCD backend must support its flash/reset sequence. Merely excluding
`mps2-an385` is not a sufficient capability check. The existing persistent
QEMU runner uses Pico1's `flash-file` machine property.

The scenario performs geometry/write/reset/read/rewrite/reset/read checks
over three boots. It programs the image only on the first boot. Under QEMU,
the runner creates a temporary flash file, boots once with `-kernel`, then
reuses the same file without `-kernel`. On hardware it programs once, opens
serial before releasing reset, and performs the later resets without reflash.

`--allow-destructive` authorizes the OpenOCD runner's **initial whole-flash
erase**, including the registry; it is not limited to the diagnostic sector.
Without it the command reports the affected address range and stops without
touching the board. Add `--serial /dev/<serial-device>:115200` or
`--probe-serial ID` if automatic selection is ambiguous. QEMU does not accept
`--allow-destructive`; it uses a disposable backing file instead.

`flash-probe` explicitly declares a 4096-byte block at the end of the physical
persistence window. During module initialization, before registry startup,
`core::flash::reserve_persistence_tail()` removes that block from the area
exposed to the registry. Registry initialization remains enabled. For Pico2,
the probe is at `0x103FF000`, with 16 pages of 256 bytes; the registry retains
the preceding 1008 pages. Use a disposable test layout, not an existing
production registry: enabling this module changes its available capacity.

`flash-probe` uses one private command family, `CLA=80, INS=8E`. `P1` is the
operation selector because the three operations exercise one service and share
the same framing; `P2` is then free to carry the caller-selected byte written
by the destructive probe. This is a Oxide SE diagnostic convention, not a
GlobalPlatform command assignment:

| `P1` | Operation | Success response |
|---|---|---|
| `00` | Report persistence geometry | 12 data bytes followed by `9000` |
| `01` | Erase, write and read back one diagnostic page | 16 data bytes followed by `9000` |
| `02` | Read the first 16 persistent bytes without modifying flash | 16 data bytes followed by `9000` |

Any other `P1` returns `6A80`. `P1=01` or `P1=02` returns `6985` when no
persistence area is configured; `P1=01` also returns `6985` when the logical
page size is not the 256 bytes required by the current probe. The destructive
operation uses two private diagnostic statuses to identify the failing
primitive:

| Status | Meaning |
|---|---|
| `6F01` | `flash_erase_sector()` failed; no page-program operation was attempted |
| `6F02` | erase succeeded, but `flash_write_page()` returned an error, including any verification error reported by the backend |

These `6Fxx` values are local to the bring-up module. They deliberately refine
the otherwise generic `6F00` diagnosis and must not be treated as new general
ISO/IEC 7816 status words.

For manual diagnosis, the same steps can be reproduced through APDUs:

1. Use `configs/config_kernel_flash_probe.toml`, a kernel-only image containing
   no other module:

```toml
[kernel-image]
mode = "kernel-only"
kernel-app-modules = ["flash-probe"]
```

2. Build the image in the format already validated during the earlier boot
   steps. For a native ELF:

```sh
cargo run build --elf \
  --config configs/config_kernel_flash_probe.toml \
  <board>
```

Use `--fae` instead of `--elf` when the board port boots the packaged FAE
image. Convert or wrap that output only through the board's already validated
boot-image path.

3. Flash the resulting dedicated image, connect the normal APDU serial link,
   and start `apdu_tool` before resetting the board so it receives the ATR:

```sh
cargo run -p apdu_tool -- \
  --serial /dev/<serial-device>:115200 \
  80 8E 00 00 00 0C
```

On success, the 12 returned bytes are three little-endian `u32` values followed
by `9000`:

```text
offset 0..3   reserved diagnostic-block start address
offset 4..7   logical page count
offset 8..11  logical page size in bytes
SW            90 00
```

Compare all three values with the target implementation before attempting an
erase. A value may be internally self-consistent yet physically wrong: for
example, an incorrect total flash size moves the diagnostic block beyond the
real device even though the returned page count and page size look plausible.

4. Confirm that the persistence contents may be destroyed. Start a fresh
   `apdu_tool` invocation, reset the board for its ATR, then erase the reserved
   diagnostic sector and write the diagnostic page:

```sh
cargo run -p apdu_tool -- \
  --serial /dev/<serial-device>:115200 \
  80 8E 01 A5 00 10
```

The command must return the following 16 data bytes and then `9000`:

```text
52 4C 4F 53 46 4C 53 48 A5 8E <page-count-low> <page-count-high> A5 FF FF FF
```

The first eight bytes spell `RLOSFLSH`; byte 8 is the selected `P2=A5` marker,
byte 9 records `INS=8E`, bytes 10 and 11 encode the reserved block's page
count as a little-endian `u16`, and byte 12 is the fixed probe marker `A5`.
For the 4096-byte diagnostic block, these three bytes are `10 00 A5`.
Bytes 13 through 15 remain
erased (`FF`). A `6F01` response localizes the failure in sector erase; `6F02`
means erase completed but page programming, or a verification performed by the
backend, failed. Even after `9000`, compare all 16 returned bytes with the
expected pattern to detect a backend that reports success without preserving
the requested contents.

5. Power-cycle or reset the board. Start `apdu_tool` again before reset, then
   read the first 16 bytes without rewriting them:

```sh
cargo run -p apdu_tool -- \
  --serial /dev/<serial-device>:115200 \
  80 8E 02 00 00 10
```

The response must reproduce exactly the same 16 data bytes, followed by
`9000`. A `6985` response means that no diagnostic block could be reserved.
This reset between write and read is what distinguishes persistent storage
from a RAM-backed or incompletely flushed implementation.

6. Repeat the write/read cycle with another `P2` marker, for example `5A`, and
   verify that byte 8 changes accordingly after another reset.

The APDU sequence, independently of the shell invocations, is therefore:

1. send `80 8E 00 00 00 0C` and verify that the returned start address, page
   count, and logical page size match the reserved diagnostic block;
2. only on persistence contents that may be destroyed, send
   `80 8E 01 A5 00 10` to erase the reserved diagnostic sector and write the
   diagnostic page;
3. send `80 8E 02 00 00 10` and verify the returned prefix;
4. reset or power-cycle the board, reconnect, and repeat the read command to
   prove that the bytes actually persisted;
5. only after this probe is repeatable, validate registry publication and
   recovery across reboot with a complete GlobalPlatform image.

The probe does not exercise `flash_flush_page()` or establish power-failure
atomicity. Follow it with registry publication/recovery tests; controlled
resets alone are not evidence for every interrupted erase/program case.
The current probe requires 256-byte pages and 4096-byte erase sectors. If
reservation fails, its information operation reports an empty block and
read/write operations return `6985`; it never reuses the registry's first
sector. The diagnostic block is excluded from registry formatting, but loading
the test image is destructive and changes the layout. Never run it on
persistence data that must be preserved. The complete operational reference
for the module is in [`kernel.getting.started.md`](kernel.getting.started.md).

### 11.4 Validate Registry Recovery Without SCP

Once the raw probe passes, use the normal registry allocation instead of the
private diagnostic sector:

```sh
cargo run test kernel_registry raspi-pico1 --on qemu
cargo run test kernel_registry raspi-pico2 --on openocd --allow-destructive
```

Choose the appropriate backend. This selects
`configs/config_kernel_registry_test.toml` and its `registry-test` module,
with no Rustlet. Eighteen objects are written and compared byte-for-byte,
recovered after reset, then one is replaced with a shorter value and recovered
after another reset. Expect `KERNEL-REGISTRY-DONE`; only the first boot may
erase/reprogram the image. Each object is read in one complete response.

The initial payloads total 4165 bytes. Seventeen 244-byte objects each occupy
two 256-byte pages after headers and CRC: this checks page-spanning records,
not arbitrarily large Data objects. A failure here after a passing raw probe
points toward geometry, registry allocation/publication or recovery, rather
than SCP. Inspect `kernel/firmware/src/object_registry_persistence.rs` and
`xtask/src/testing/scenarios/kernel.rs` before broadening the test.

Then exercise clear GP registry operations with a NullSecurityDomain:

```sh
cargo run test gp_registry raspi-pico1 --on qemu
cargo run test gp_registry raspi-pico2 --on openocd --allow-destructive
```

Expect `REGISTRY-DONE`: STORE/GET, key operations and deletion must return the
expected data/status, not merely avoid crashing. This scenario checks runtime
mutations; the following campaign checks their durability and application use.

### 11.5 Validate Post-Issuance Loading And Full GP Persistence

At this point, steps 8 and 9 have independently validated kernel SCP and its
application integration. The raw flash and registry checks above have passed.
Now run the focused post-issuance LOAD scenarios, without the restricted
bring-up option. Positive encrypted loading uses SCP03 or SCP11a, not the
card-authentication-only SCP11b profile:

```sh
cargo run test gp_scp03_install_load raspi-pico1 --on qemu
cargo run test gp_scp11a_install_load raspi-pico1 --on qemu
cargo run test gp_scp11a_install_load raspi-pico2 --on openocd --allow-destructive
```

The standalone SCP03 loading command is QEMU-only; its sequence is also
included in the broader hardware persistence coverage. These tests build a
Rustlet `.fae` for the board CPU, send INSTALL [for load], transmit consecutive
LOAD blocks through the protected channel, then INSTALL [for install], SELECT
and invoke the new instance. The SCP11a test additionally reboots without
reprogramming and executes the persisted instance again. Look for the
`SCP03-INSTALL-LOAD-DONE` or `SCP11A-INSTALL-LOAD-DONE` result, not only a
successful file conversion or `9000` on the first LOAD block.

Complete the GP validation with these QEMU commands:

```sh
cargo run test gp_predeployment raspi-pico1 --on qemu
cargo run test gp_security_domain raspi-pico1 --on qemu
cargo run test gp_persistence raspi-pico1 --on qemu
cargo run test gp_all raspi-pico1 --on qemu
```

Run the persistence campaign on Pico1 hardware with:

```sh
cargo run test gp_persistence raspi-pico1 --on openocd --allow-destructive
```

The remaining aggregate hardware validation is currently exposed on Pico2:

```sh
cargo run test gp_predeployment raspi-pico2 --on openocd --allow-destructive
cargo run test gp_security_domain raspi-pico2 --on openocd --allow-destructive
cargo run test gp_persistence raspi-pico2 --on openocd --allow-destructive
cargo run test gp_all raspi-pico2 --on openocd --allow-destructive
```

`gp_persistence` starts with the clear NullSD path, including installation of
a new instance from predeployed code and loading new code over APDUs. It then
checks key rotation/deletion, protected loading and recovery with kernel and
Rustlet-backed Security Domains. In each configuration, the first boot may
program the image; later boots must preserve flash. Expect `PERSISTENCE-DONE`.
`gp_all` aggregates the GP scenarios; it does not replace `rustlet_all` or the
kernel protection tests.

Do not reset by rerunning a build-and-flash command: that would erase the very
state this test is meant to recover. Do not infer physical power-loss safety
solely from a QEMU flash file or orderly reset. Fault-injection and interrupted
erase/write tests remain a separate durability requirement. Record the backend,
flash geometry and actual scenarios validated before advertising persistence.

## 12. Document Hardware Support

Set `board_support: true` when the declared `support_level` is reproducible on
real hardware through the documented host runner and APDU transport.

This flag should be used only after the hardware execution path is documented
well enough for another developer to reproduce the build, flashing, and APDU
connection steps.

Watchpoints:

- Hardware-only means `board_support: true` and `qemu_support: false`; it does
  not mean untested.
- Document the exact probe, serial adapter, baud rate, flashing command, reset
  sequence, and expected first ATR or debug output.
- Do not let a hardware-only target be selected implicitly by QEMU campaigns.

## 13. Update User-Facing Documentation

After the board builds and its support level is known, update:

```text
docs/getting-started.md
docs/kernel.getting.started.md
docs/kernel.developer.guide.md
```

Document the support level plainly:

- build/layout only;
- kernel-local APDU/T=0 validation;
- GP/SCP tests;
- Rustlet campaign tests;
- `qemu_support`, `board_support`, or both.

Once the board has a `BOARD_CATALOG` entry, it appears in `cargo run --help`.

Watchpoints:

- User-facing docs should state what is supported now, not what the board will
  eventually support.
- If the board depends on a non-standard QEMU tree, document how to build it
  and which binary path `xtask` expects.
- Keep TODOs about missing isolation, flash persistence, entropy, or hardware
  validation centralized in `docs/TODO.md` rather than scattering future work
  across the porting guide.
