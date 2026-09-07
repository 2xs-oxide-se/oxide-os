# Oxide SE Core Notes

This document captures the current role of `oxi_core` inside the
workspace and the service boundaries that are expected to stabilize
first.

## Scope

`oxi_core` is a reusable embedded library crate.

Its role is to provide:

- target-oriented early initialization;
- runtime initialization and shutdown support;
- minimal semihosting support;
- minimal serial I/O services;
- runtime allocation services for Rust `alloc`;
- low-level flash page services;
- low-level cryptographic services and target dispatch.

`oxi_core` is intentionally low-level. It should expose small and
stable service boundaries, while keeping board-specific details hidden
behind target implementations.

It is currently consumed by:

- `kernel/firmware`, the production firmware crate;
- `core_test`, the QEMU-oriented embedded test firmware crate.

## Current Structure

The current `kernel/core/src/` layout is:

- `lib.rs`: crate root exporting the reusable embedded library
- `core/mod.rs`: top-level wiring and public runtime-facing API
- `core/runtime.rs`: runtime initialization and shutdown
- `core/semihosting.rs`: semihosting helpers
- `core/serial.rs`: byte-oriented serial API
- `core/syscall.rs`: architecture-facing syscall facade
- `core/allocator.rs`: first-fit allocator used as Rust global allocator
- `core/crypto.rs`: low-level crypto facade and target/software routing
- `core/flash.rs`: flash service API
- `core/mpu.rs`: low-level MPU facade
- `core/target/`: board-specific implementations

For the practical sequence used to add a new board target, see
[`newboard.porting.guide.md`](newboard.porting.guide.md).

Application-facing firmware entry points belong to their firmware crates.
Each firmware crate provides an exported `start()` symbol and
delegates initialization and shutdown to `oxi_core`.

## Entry and Shutdown Model

The FAE startup code calls an exported `start()` symbol owned by the
firmware crate.

The current model is:

1. firmware `start()` calls `oxi_core::core::initialize()`;
2. the firmware runs its own `main` logic;
3. the firmware terminates through `oxi_core::core::shutdown(exit_code)`.

The same shutdown path is also used by Rust panics inside the embedded
runtime.

Current target behavior is:

- on QEMU-supported paths, request emulator exit via semihosting;
- otherwise, emit `tbd` on the serial line and freeze in a spin loop.

## Serial API

The current serial service is deliberately minimal and synchronous.

Public surface:

- `send_byte(byte: u8)`
- `receive_byte() -> u8`

Current assumptions:

- polling-based operation;
- no buffering;
- no interrupt-driven API;
- no DMA-facing abstraction yet.

This is sufficient for the APDU transport path used by `kernel/firmware`.

## Syscall Boundary

The syscall boundary should remain a dedicated low-level module of
`oxi_core`.

The current direction is intentionally split in two layers:

- `oxi_core` owns the kernel-facing syscall table and trap handling;
- application-facing syscall emission should live in an ABI/runtime layer
  such as `rustlets/rustlet_runtime`, not in the kernel crate itself;
- the ARM M-profile machine backend is shared through
  `core::target::common_arm_m_profile`.

Current ARM kernel policy:

- `core::syscall::initialize()` delegates machine setup to the target
  layer and installs builtin bindings;
- Rust code registers syscall handlers through
  `core::syscall::install_handler()` or `core::syscall::install_bindings()`;
- the `SVCall` trampoline:
  - determines the caller stack frame;
  - saves the caller `r9`;
  - rebases `r9` to the kernel RAM base;
  - decodes the `svc #imm8` immediate as the syscall number;
  - dispatches the corresponding Rust handler;
  - writes the return value back to stacked `r0`;
  - restores the caller `r9` before exception return.

This is still intentionally low-level. It establishes the machine-level
trap and rebasing discipline without freezing the higher-level kernel
service table.

The current registration strategy is intentionally simple:

- syscall numbers live in `rustlets/rustlet_runtime::syscall_abi`;
- kernel-side code groups handlers as `SyscallBinding` tables;
- `core::syscall::install_bindings()` installs a whole table at once.

This keeps the numbering shared with the application ABI while letting
the kernel organize handlers across multiple modules without centralizing
all logic in a single giant match statement.

The machine-specific SVC implementation lives in the target layer as a
shared ARM service. The kernel-facing `core::syscall` facade therefore
contains no architecture-specific dispatch logic.

The main runtime-owned syscall values are:

- `SVC 0`: enter application mode from the kernel;
- `SVC 1`: return from a Rustlet handler or explicit Rustlet exit;
- `SVC 3`: allocate from the active Rustlet heap;
- `SVC 4`: deallocate from the active Rustlet heap;
- `SVC 6`: `setIncomingAndReceive`;
- `SVC 7`: `setOutgoing`;
- `SVC 8`: `setOutgoingLength`;
- `SVC 0xff`: bootstrap-only `start()` descriptor return.

The `ReturnToKernel` syscall uses `r2` to carry a
`RuntimeReturnKind`, while `r0/r1` carry `SW1/SW2` for APDU-style
completion. The exact register contract is documented in
`rustlets/rustlet_runtime/src/syscall_abi.rs`.

## Semihosting

Semihosting is a dedicated debug and development channel,
distinct from the APDU serial link.

Current uses include:

- debug output under QEMU;
- selected development-only host services, such as the QEMU-side
  entropy path.

This channel is convenient for bring-up and testing, but it is not part
of any security boundary and should not be confused with a hardened
production path.

## Allocator

The current allocator is intentionally simple:

- linked free list;
- first-fit policy;
- local merge on deallocation;
- fixed heap reservation of `8 KiB`.

This allocator is only meant to unlock early use of Rust `alloc`.

## Crypto Service

The crypto layer is intentionally kept low-level and buffer-oriented.

Current responsibilities include:

- AES key loading through an opaque `AesKey`;
- AES-CBC encrypt/decrypt fallback;
- AES-CMAC fallback;
- SCP03-specific KDF support;
- entropy routing between target hardware and the QEMU development path.

The target policy is:

- use hardware support when a credible target backend exists;
- otherwise use the software fallback where appropriate;
- fail explicitly for entropy if no credible source is available.

## Flash Service

The low-level flash service is exposed at a page-oriented logical level,
not at the raw flash-controller level.

Flash remains directly readable through normal memory addressing. The
core service does not need to wrap reads into page-copying helpers.

### Intended Public API

The first public API is built around logical pages:

- `write_page(page_addr, page_buf)`
- `flush_page(page_addr)`
- `write_page_atomic(page_addr, page_buf)`
- `logical_page_size()`

Expected contract:

- `page_addr` is aligned on the logical page size;
- `page_buf` has exactly one logical page of data;
- `write_page` is non-atomic and best-effort;
- `flush_page` upgrades pending work for that page to
  all-or-nothing-except-power-loss semantics;
- `write_page_atomic` guarantees that, after boot-time recovery, either
  the previous page contents or the new page contents are preserved, but
  never a validated mixed state.

Backend note:

- a purely synchronous backend may treat `write_page` as an implicit
  flush and implement `flush_page` as a no-op.

Backend availability is target-specific; unsupported targets return
`Unsupported`.

### Recovery

Recovery from interrupted atomic writes is an internal core concern.
There is no need to expose a public `resume_*` API.

In the current implementation, recovery is triggered when the flash
service is first used. This keeps normal QEMU bring-up working while the
flash-controller path itself is still hardware-oriented.

### Minimal Metadata Direction

The current metadata direction for the first STM32L4-oriented atomic
scheme is deliberately small:

- `magic`
- logical page address or `0xFFFF_FFFF` for empty
- shadow checksum or `0xFFFF_FFFF` for empty
- `sequence_number`

If `magic` is missing, the core initializes the metadata page before
using the service.

### First Target Strategy

For the current STM32L475 direction, the first implementation uses only
flash `bank 2` as the managed region:

- total managed bank size: `512 KiB`
- reserved tail area: `16 * 2 KiB = 32 KiB`
- usable logical space: `480 KiB`

The last `16` pages of `bank 2` are reserved:

- the last `8` pages are rolling metadata pages;
- the preceding `8` pages are their associated rolling shadow pages.

The metadata/shadow pairing is:

- `-1 -> -9`
- `-2 -> -10`
- `...`
- `-8 -> -16`

The rolling metadata pages reduce the flash stress on any single page by
a factor of eight compared with a single fixed metadata page.

Selection policy:

- each metadata page carries a `sequence_number`;
- the next atomic write reuses the metadata slot with the smallest
  sequence number;
- the latest metadata slot is the one with the greatest sequence
  number;
- metadata is not invalidated after a successful atomic write.

Atomic-write policy:

- the selected shadow page is programmed with the desired post-write
  page image;
- that shadow is fully verified before metadata is written;
- metadata records the target page and the CRC of the shadow image;
- the target page is then erased and reprogrammed from the caller
  buffer.

Recovery policy:

- at flash-service startup, the implementation examines only the latest
  metadata slot;
- if that slot is empty, there is no recovery work;
- if the target page already matches the associated shadow page, the
  previous atomic write is considered complete;
- otherwise the target page is rewritten from the shadow image;
- old metadata entries remain as rolling history until reused.

Operational policy:

- `write_page` is currently synchronous on STM32L475 and performs an
  erase plus full page programming;
- `flush_page` is currently a no-op on STM32L475;
- `write_page_atomic` uses shadow-copying plus rolling metadata;
- the metadata page is not erased again after a successful commit, which
  removes one metadata burn per atomic write cycle;
- the implementation does not rely on `1 -> 0` rewrites as a software
  contract.

## Design Rule

The public core API should stay stable, small, and logical.
Target-specific constraints such as:

- erase granularity;
- program granularity;
- read-while-write limitations;
- need for RAM-resident routines;
- optional `1 -> 0` rewrite optimizations

should remain implementation details of the target backend whenever
possible.
