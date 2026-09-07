# Kernel Getting Started

This document is the practical entry point for contributing to the Oxide SE
kernel firmware.

The standard beginner path builds and runs a native fixed-address kernel ELF.
Do not pass an image-format option when starting with the project: the default
is the ELF path, and that is the normal QEMU oracle for kernel development.

This guide complements [`getting-started.md`](getting-started.md). The general
getting-started guide shows a first end-to-end use of the system. This guide
focuses on the kernel contributor workflow: target layout, predeployment
configuration, QEMU campaigns, host-based tests, and stack-budget checks.

## Prerequisites

Install or make available:

- the Rust nightly selected by `rust-toolchain.toml`;
- `cargo`;
- `qemu-system-arm`;
- `arm-none-eabi-gcc` and `arm-none-eabi-ld`;
- the `tooling/build-fae` submodule.

Initialize submodules from the repository root:

```bash
git submodule update --init tooling/build-fae tooling/qemu-rp2040-pico
```

The kernel build uses `tooling/build-fae` for FAE payload handling. Even when the
kernel image itself is built as an ELF, embedded Rustlets remain FAE payloads.
The Pico QEMU fork is used only by the `raspi-pico1` QEMU workflows; its own
upstream submodules are not needed for the normal Oxide SE kernel workflow.

## Supported Boards

The kernel `xtask` board selector currently accepts:

- `mps2-an385`;
- `olimex-stm32-h405`;
- `b-l475e-iot01a`;
- `raspi-pico1`.

If no board is provided, `xtask` defaults to `mps2-an385`.

The board name selects one entry in the `xtask` board catalogue. That entry
defines:

- the QEMU machine name;
- the Rust target triple used for Rustlets and firmware;
- the startup and linker-script wrapper used by the firmware build;
- the target source file that declares RAM, FLASH, stack, heap and persistence
  policy.

It also records the independent porting level (`BuildOnly`, `KernelApdu`,
`GlobalPlatformApdu`, or `Rustlet`) and whether that level is reproducible
under QEMU, on physical hardware, or both.

For porting a new board, follow
[`newboard.porting.guide.md`](newboard.porting.guide.md). It is written as a
step-by-step path from `BuildOnly` to `Rustlet`, with QEMU and physical-board
validation recorded independently.

## Build The Kernel

Build the default kernel:

```bash
cargo run build
```

Build the kernel for one explicit board:

```bash
cargo run build mps2-an385
cargo run build olimex-stm32-h405
cargo run build b-l475e-iot01a
cargo run build raspi-pico1
```

The standard kernel artifact is:

```text
target/kernel/firmware/kernel.elf
```

By default, kernel console/debug traces are disabled:

```bash
cargo run build --trace=none
```

Use an explicit trace mode only for a debug image:

```bash
cargo run build mps2-an385 --trace=semihosting
cargo run build raspi-pico1 --trace=jtag
```

`--trace=semihosting` is intended for QEMU/debug runs. `--trace=jtag` is
currently supported only for `raspi-pico1`; other boards reject it at build
time.

The build also writes:

```text
target/kernel/firmware/kernel.gdbinit
```

Use `cargo clean` from the repository root when you want to remove normal Cargo
build outputs. Rustlet-local FAE artifacts under individual Rustlet
directories are intentionally managed by those Rustlet builds.

## Configure Memory Layout

Target RAM/FLASH policy is declared in the board target files:

- `kernel/core/src/core/target/mps2_an385.rs`;
- `kernel/core/src/core/target/olimex_stm32_h405.rs`;
- `kernel/core/src/core/target/b_l475e_iot01a.rs`;
- `kernel/core/src/core/target/raspi_pico.rs`.

Each target exposes a `MEMORY_LAYOUT` constant. It defines, at minimum:

- RAM base and size;
- FLASH base and size;
- minimum kernel heap size;
- kernel stack size;
- optional persistence-area policy when the target supports mutable flash.

The firmware consumes this layout at boot. `xtask` reads the same source files
for host-side layout checks, so the build report and the kernel should agree on
the same RAM/FLASH budget.

Inspect the current layout before changing memory policy or embedding a large
Rustlet set:

```bash
cargo run dump_kernel_layout
cargo run dump_kernel_layout mps2-an385
cargo run dump_kernel_layout raspi-pico1
cargo run dump_kernel_layout mps2-an385 minimal
cargo run dump_kernel_layout mps2-an385 kernel-main
```

The optional profile selects the embedded set used for the report:

- `default` or `all`: normal embedded Rustlet set;
- `minimal`: only `minimal_valid_test`;
- `kernel-main`: no embedded Rustlet, kernel debug app only;
- any canonical Rustlet name: only that Rustlet.

The report shows the target RAM/FLASH budget, allocated ELF sections, kernel
stack, firmware RAM footprint, allocator metadata, derived heap window, and
embedded Rustlet FAE subtotal. It prints explicit overflow diagnostics when an
image does not fit.

## Configure Predeployment

The kernel image is configured by a predeployment manifest. The default
manifest is:

```text
config.toml
```

It is intentionally a development image: a root `NullSecurityDomain` with no
pre-installed Rustlet packages. That image is useful when you want a minimal
kernel ready for dynamic loading.

Build with another manifest when you need initial Security Domains, Rustlets,
instances, or keys:

```bash
cargo run build --config=configs/config_rustlet_minimal_valid_test.toml
cargo run build raspi-pico1 --config=configs/config_scp11c_test.toml
```

The manifest structure uses explicit package and instance sections:

```toml
[root.package]
name = "NullSecurityDomain"
aid = "A0:00:00:47:50:4F:53:01"

[root.instance]
aid = "A0:00:00:47:50:4F:53:01"
install_bytes = "FF:FF:FF"
```

Rustlet packages can be predeployed under that root Security Domain:

```toml
[[root.packages]]
path = "./rustlets/tests/minimal_valid_test"

[[root.packages.instances]]
aid = "A0:00:00:47:50:4F:53:16"
install_bytes = ""
```

Initial SCP03 keys are also manifest objects owned by the Security Domain in
which they are declared:

```toml
[[root.keys]]
type = "Scp03Static"
version = 1
id = 3
usage = "Enc"
material = "40:41:42:43:44:45:46:47:48:49:4A:4B:4C:4D:4E:4F"
```

At first initialization, the kernel executes the manifest plan and commits the
resulting registry. On persistent targets such as `raspi-pico1`, later boots
recover the latest valid registry snapshot from flash instead of replaying the
manifest.

### One schema, four useful compositions

The manifest does not classify an image as a devkit, a test image, or a
production image. It declares a technical root, optional child Security
Domains, their parent relationships, policies, keys, and predeployed packages.
The intended use follows from that concrete composition:

1. A **kernel APDU processor** uses `kernel-image.mode = "kernel-only"` and an
   ordered list of `kernel-app-modules`. It declares no predeployment root or
   child domains. The build materializes the kernel's technical registry root,
   but omits GlobalPlatform/Rustlet dispatch; this is the degenerate form used
   to isolate kernel APDU services such as `ping`, `registry-test`, or
   `crypto-self-test`.
2. A **Rustlet-loading devkit** declares a `NullSecurityDomain` technical root,
   no child Security Domain, no predeployed Rustlet, and no Secure Channel.
   Clear GlobalPlatform management APDUs can therefore load arbitrary valid FAE
   images for development. This is `configs/config_rustlet_devkit.toml`.
3. A **Security-Domain test devkit** starts from the same permissive root and
   adds the child domains, keys, and packages needed by the test. It may mark
   one direct child with `role = "issuer"` when the scenario needs an Issuer
   Security Domain. The hierarchy is real; only its clear, permissive root
   policy makes it a development/test composition.
4. A **production-oriented SE hierarchy** declares the technical root, one
   direct child with `role = "issuer"`, the remaining parent/child domain
   relationships, and the required Secure Channel policies and keys. Other
   domains may be attached directly to the root to form trees disjoint from
   the issuer subtree. Production suitability depends on those policies and
   credentials, not on a special TOML mode.

The structural rules are common to all four compositions. `[root]` is the only
parentless Security Domain. Each `[[security_domains]]` entry names its parent
by instance AID. No `role = "issuer"` means that the image has no distinct
Issuer Security Domain; exactly one declares the conventional Issuer hierarchy;
more than one is rejected because Oxide SE supports only one Issuer Security
Domain. The Issuer, when present, must be a direct child of the technical root.
Children cannot receive privileges absent from their parent, and cycles,
duplicate instance AIDs, and missing parents are rejected.

Declaration order has no semantic effect. The build derives a first-boot plan
that materializes the technical root first, then the optional Issuer Security
Domain, then every other domain in parent-before-child order. The original
manifest order is retained only as a deterministic tie-breaker between
independent domains that are ready at the same time.

## Build Rustlet Payloads

Kernel test commands build the Rustlet FAEs they need before building the
kernel image. In normal kernel work, you usually do not build test Rustlets by
hand.

For Rustlet-local work, the Rustlet test workspace can build one payload or all
test payloads:

```bash
cd rustlets/tests
cargo build-fae minimal_valid_test
cargo build-fae
```

The generated test FAE files live under each Rustlet test directory, for
example:

```text
rustlets/tests/minimal_valid_test/build/rustlet_minimal_valid_test.fae
```

The Rustlet template documents the standalone structure expected from a new
Rustlet:

```text
rustlets/rustlet_template/
```

## Run The Kernel Manually

For quick APDU work, build the kernel and launch QEMU with the serial helper:

```bash
cargo run build mps2-an385
./tools/bin/run-qemu-serial.sh mps2-an385
```

The helper serves the target UART on `127.0.0.1:4444`, using:

```text
target/kernel/firmware/kernel.elf
```

From another terminal, connect with the APDU tool:

```bash
cargo run -p apdu_tool -- 00 00 00 00 00 00
```

For decoded APDU/ATR output:

```bash
cargo run -p apdu_tool -- -v 00 00 00 00 00 00
cargo run -p apdu_tool -- -vv 00 00 00 00 00 00
```

## Host-Based Tests

Use host-based tests for fast feedback on pure logic, parsers, registry
encoding, SCP engines, layout helpers, and xtask behavior:

```bash
cargo fmt --all
cargo test -p kernel object_registry --offline
cargo test -p kernel scp03 --offline
cargo test -p kernel scp11 --offline
cargo test -p xtask board --offline
cargo test --offline
```

`cargo test --offline` is the broad workspace check. It includes host unit
tests and the repository integration tests that drive small QEMU-backed core
checks where appropriate.

Prefer host tests first when changing code that does not require real APDU
transport, MPU behavior, or target startup. They are much faster and they make
debugging less noisy.

## Target Test Commands

All target scenarios use one entry point:

```bash
cargo run test --help
cargo run test kernel_ping --help
cargo run test rustlet --help
cargo run test gp_scp03 mps2-an385 --on qemu --scp03=s8
```

The syntax is `cargo run test <name> [board] [options] [test arguments]`.
The name describes the scenario: `kernel_*`, `gp_*`, `rustlet`,
`rustlet_isolation`, or `rustlet_all`. A native kernel ELF is the default.
QEMU is selected when the board supports it; otherwise OpenOCD is selected.
Common options can appear before or after scenario arguments:

- `--on qemu` or `--on openocd` explicitly selects the backend. Hardware
  currently supports `kernel_ping`, `kernel_t0`, `kernel_crypto`, `kernel_flash`, `kernel_registry` and `rustlet minimal_valid_test`
  on eligible boards. It automatically selects the unique USB serial port at
  115200 baud; use `--serial ENDPOINT` to override it. With multiple USB ports,
  it lists choices and commands instead of guessing. It still requires
  `--allow-destructive`: the entire declared FLASH range, including the
  registry, is erased. Follow the
  [hardware runner recipe](kernel.developer.guide.md#openocd-execution)
  before using a physical device. `kernel_ping` and `kernel_t0` passed on
  physical Pico2; random generation now has an SDK-style backend, while the
  full crypto test passes with its P-256 response split into GET RESPONSE chunks.
- `--elf` explicitly selects the default image.
- `--check_stack` and `--update_stack_baseline` are available where the
  scenario's help advertises stack measurements, with either QEMU or OpenOCD.
  Baselines are kept separately for each execution environment.
- `--config <path>` overrides the scenario's predeployment manifest.
- `--trace=none|semihosting|jtag` selects debug traces.

Unknown options, repeated/conflicting options, and unsupported board/backend
combinations fail explicitly. In particular, an unsupported stack check is
never silently ignored. Most tests default to `mps2-an385`; persistence tests
default to `raspi-pico1`, while `rustlet_all` without a board selects all
functional Rustlet/QEMU boards. Per-test help gives the applicable rule.

## QEMU Kernel Tests

Use kernel-local QEMU tests to validate transport, T=0, debug APDUs, and core
kernel services:

```bash
cargo run test kernel_ping mps2-an385 --on qemu
cargo run test kernel_t0 mps2-an385
cargo run test kernel_crypto mps2-an385
cargo run test kernel_stack_guard mps2-an385
cargo run test kernel_ram_nx mps2-an385
```

These runners build `kernel-only` images from an ordered set of statically
selected `KernelAppModule` extensions. The equivalent manifest form is:

```toml
[kernel-image]
mode = "kernel-only"
kernel-app-modules = ["ping", "t0-test"]
```

`ping` maps to `kernel/firmware/src/kernel_main_app/ping.rs`; `t0-test` maps to
`kernel/firmware/src/kernel_main_app/t0_test.rs`. The central module registry
defines those mappings, and the TOML order is the APDU-filter priority order.
The T=0 runner is useful when you want to isolate transport behavior from
GlobalPlatform and Rustlet dispatch.

### Available Kernel Application Modules

The modules currently provided by the firmware are:

| TOML name | Purpose | Normal validation entry point |
| --- | --- | --- |
| `ping` | Echo one APDU payload to validate startup and transport | `cargo run test kernel_ping <board>` |
| `t0-test` | Exercise the four short T=0 APDU cases | `cargo run test kernel_t0 <board>` |
| `crypto-self-test` | Exercise or benchmark kernel crypto primitives without entering a Rustlet | `cargo run test kernel_crypto <board>` |
| `flash-probe` | Reserve and test a flash block outside the registry allocation | `cargo run test kernel_flash <board>` |
| `registry-test` | Write, retrieve and replace registry Data objects across resets | `cargo run test kernel_registry <board>` |
| `kernel-stack-monitor` | Measure the privileged stack high-water mark | `--check_stack` and `GET DATA DF71` |
| `rustlet-stack-monitor` | Measure the selected Rustlet stack high-water mark | `--check_stack` and `GET DATA DF72` |

This table documents how to use the modules shipped by the repository. Their
implementation contracts remain defined by their source files under
`kernel/firmware/src/kernel_main_app/` and by the central registry in
`kernel/firmware/src/kernel_app_modules_registry.inc.rs`.

### Kernel Crypto Self-Test

Run the default QEMU regression with:

```bash
cargo run test kernel_crypto mps2-an385
```

It checks random generation, AES-128 CBC against a known answer, and P-256 key
generation through kernel-local APDUs. To benchmark one primitive, consult the
command's current operation list and arguments:

```bash
cargo run test kernel_crypto --help
cargo run test kernel_crypto raspi-pico1 --bench p256_generate_keypair
```

The same scenario and its individual benchmarks can use OpenOCD:

```sh
cargo run test kernel_t0 raspi-pico2 --on openocd --allow-destructive
cargo run test kernel_crypto raspi-pico2 --on openocd --allow-destructive
```

Random generation can be checked independently with a full short response:

```sh
cargo run test kernel_crypto raspi-pico2 --on openocd --allow-destructive \
  --bench fill_random 255
```

This passes on physical Pico2. `crypto_initialize()` configures the TRNG
during core startup. `raspi_pico2_random.rs` adapts the TRNG-only path of
Raspberry Pi pico-sdk 2.2.0 `pico_rand`: raw samples, splitmix64 mixing and
xoroshiro128** output, with bounded waits and no stale-state fallback.
The source attribution, license and security caveats are beside the code.
This is NOT a cryptographic DRBG or a claim of certified entropy; hardware
health checks are bypassed as in the SDK. Its use for cryptographic purposes
must be revisited. No 16-byte/16-generation reseeding schedule is used.

The default crypto smoke test covers random, AES and P-256 on physical Pico2.
For key generation, the runner selects the module's case-4 interface (`P1=1`,
one zero input byte); one GET RESPONSE retrieves the complete result.
The key is generated once, and its result stays in the existing shared APDU
buffer. The original case-2 interface remains available with `P1=0`.

Measure asymmetric operations independently:

```sh
cargo run test kernel_crypto raspi-pico2 --on openocd --allow-destructive \
  --bench p256_generate_keypair
cargo run test kernel_crypto raspi-pico2 --on openocd --allow-destructive \
  --bench p256_ecdh
```

`elapsed_ms` is host-observed APDU round-trip time, including command transfer,
computation and chunked response retrieval, but excluding image loading and
boot. ECDH uses the benchmark's fixed test key pair by default and verifies
the shared secret against the host implementation. Key generation verifies
the returned private/public pair; these are disposable diagnostic keys, and
the benchmark prints them. This is not an on-device CPU-cycle measurement.

Physical Pico2 measurements on 2026-08-30, OpenOCD HEAD d9b957f35,
CMSIS-DAP and 115200-baud serial, three independent boots per benchmark:

| Operation | APDU times (ms) | Median (ms) |
| --- | --- | --- |
| P-256 key-pair generation, 97-byte result | 156, 156, 157 | 156 |
| P-256 ECDH, fixed benchmark keys | 259, 266, 260 | 260 |

Every result passed host-side verification. The full three-check crypto
scenario also passed on Pico2 and Pico1 QEMU; its public-key-only generation
exchange measured 137 ms on Pico2. Do not compare these as pure computation
times: keygen and ECDH transfer different input/output sizes, and the runner
paces incoming bytes. No ECDSA signing/verification timing is implied.

AES can be checked independently:

```sh
cargo run test kernel_crypto raspi-pico2 --on openocd --allow-destructive \
  --bench aes_cbc 2b7e151628aed2a6abf7158809cf4f3c \
  000102030405060708090a0b0c0d0e0f 6bc1bee22e409f96e93d7e117393172a
```

This passed on Pico2, returning `7649ABAC8119B246CEE98E9B12E9197D`, verified
by the host. Each hardware invocation erases and reprograms the device.

For a dedicated hardware image, select only the module:

```toml
[kernel-image]
mode = "kernel-only"
kernel-app-modules = ["crypto-self-test"]
```

Build and flash that image, then use `apdu_tool` on the board serial link. The
basic self-test commands are `INS=80` for 16 random bytes, `INS=82` for the
AES-128 CBC known-answer test, and `INS=84` for a generated uncompressed P-256
public key:

```text
80 80 00 00 00 10
80 82 00 00 00 10
80 84 00 00 00 41
```

The QEMU runner remains the reference transcript for their expected contents.

### Registry Persistence Test

Run a kernel-only image with `registry-test`, using the normal registry APIs
and recovery path, without a Rustlet or a GlobalPlatform management session:

```sh
cargo run test kernel_registry raspi-pico2 --on openocd --allow-destructive
cargo run test kernel_registry raspi-pico1 --on qemu
```

The manifest is `configs/config_kernel_registry_test.toml`. The hardware
runner erases the entire flash on the first boot only: use disposable data.
Three boots check an initially absent object, write 18 distinct objects,
compare every returned byte, recover them after reset, replace one object
with a shorter value, and recover the new value and unchanged neighbors
after another reset (75 APDU assertions with complete-object responses).
No image is reprogrammed between boots.

The initial payloads total 4165 bytes: one 17-byte object and seventeen
244-byte objects. With the current 12-byte header and 8-byte CRC, a maximum
size object occupies two 256-byte logical pages. The aggregate exceeds one
4-KiB sector. This tests multiple pages and objects, not a single arbitrarily
large object: Data objects currently have a 244-byte maximum.

The private diagnostic APDU is `CLA=80, INS=A0`: `P1=01` writes incoming
bytes, `P1=02` reads the complete object (up to 244 bytes),
and `P2` selects a tag `D000 | P2` under the root
domain identity. A missing object returns `6985`. There is no extra page
buffer: the module uses the APDU buffer and the existing registry APIs.
Write status reports RAM acceptance; re-reading after reset is the durability
check. This is not a power-loss, deletion or interrupted-write test.

Each read checks every stored byte in one response, including after both
complete resets without reflashing.

### Flash Persistence Probe

`flash-probe` declares a 4096-byte diagnostic block (`FLASH_PROBE_BLOCK_SIZE`)
at the end of the target's physical persistence area. Its boot initializer
reserves that block through `core::flash::reserve_persistence_tail()` before
the registry starts. The registry remains active and receives only the prefix;
it cannot overwrite the probe during initialization. Build a dedicated image:

```toml
[kernel-image]
mode = "kernel-only"
kernel-app-modules = ["flash-probe"]
```

Run the automated five-check, three-boot scenario:

```sh
cargo run test kernel_flash raspi-pico2 --on openocd --allow-destructive
cargo run test kernel_flash raspi-pico1 --on qemu
```

It checks geometry, writes/reads A5, reboots without reflashing, reads A5 and
erases/rewrites 5A, then reboots again and reads 5A. Both paths passed on
2026-08-30. Pico2 reserves `0x103FF000..0x10400000` (16 pages); its registry
receives 1008 pages instead of 1024. The initial hardware boot erases the full
flash, as for the other hardware runners; subsequent boots are reset-only.
This validates reset retention, not power-loss atomicity or power cycling.

The private command family uses `CLA=80, INS=8E`. `P1` selects the operation so
that `P2` remains available as the caller-controlled write marker. This is a
diagnostic convention local to Oxide SE, not a GlobalPlatform command. The
supported `P1` operations are:

- `00`: return the reserved diagnostic-block start address, page count, and logical
  page size as three little-endian 32-bit values;
- `01`: erase the reserved diagnostic sector, write
  one diagnostic page, and return its first 16 bytes;
- `02`: read and return the first 16 bytes currently stored in that area.

For example, after connecting `apdu_tool` to the board serial link, the short
T=0 commands are:

```text
80 8E 00 00 00 0C
80 8E 01 A5 00 10
80 8E 02 00 00 10
```

`P2=A5` in the write example is an arbitrary marker copied into the diagnostic
page. `P1=01` erases only the reserved block, never the registry prefix.
Selecting this module changes the registry layout: do not enable it over a
production registry whose data may already occupy that tail. Use disposable
storage and back up existing contents before flashing the test image.

Expected status words are:

- `9000`: operation completed; `P1=00` returns 12 geometry bytes, while
  `P1=01` and `P1=02` return 16 diagnostic bytes;
- `6985`: no block was reserved (unsupported geometry or reservation too late);
  `P1=00` reports an empty block in that case. The module requires 256-byte
  pages and 4096-byte erase sectors and never falls back to the registry area;
- `6A80`: unsupported `P1` operation;
- `6F01`: private probe diagnosis for sector-erase failure;
- `6F02`: private probe diagnosis for page-program or write-verification
  failure after a successful erase.

`6F01` and `6F02` belong only to this bring-up module; they refine `6F00` for
debugging and are not general ISO/IEC 7816 status assignments.

Use GlobalPlatform QEMU tests for Security Domain and secure-channel work:

```bash
cargo run test gp_noscp mps2-an385
cargo run test gp_scp03 all mps2-an385
cargo run test gp_scp11a mps2-an385
cargo run test gp_scp11b mps2-an385
cargo run test gp_scp11c mps2-an385
cargo run test gp_security_domain mps2-an385
cargo run test gp_predeployment mps2-an385
```

Use persistence tests on `raspi-pico1`, because that QEMU target provides the
flash-file behavior used by the persistent registry oracle:

```bash
cargo run test gp_scp03_install_load raspi-pico1
```

Keep the Pico SCP11 persistence/load campaigns outside the quick
getting-started validation loop. They exercise the same persistence machinery
with public-key secure-channel setup, but RP2040/QEMU P-256 operations are slow
enough to make them poor first-line smoke tests.

Use Rustlet QEMU tests for selected-app, runtime, heap, state, and isolation
work:

```bash
cargo run test rustlet mps2-an385 minimal_valid_test
cargo run test rustlet mps2-an385 state_test
cargo run test rustlet_isolation mps2-an385
cargo run test rustlet_all mps2-an385
```

Without a board argument, `test rustlet_all` runs every board whose support
level is `Rustlet` and whose `qemu_support` flag is true. Today that means:

- `mps2-an385`;
- `olimex-stm32-h405`;
- `raspi-pico1`.

`b-l475e-iot01a` remains a build/layout target only until its QEMU UART/APDU
path is reliable enough for interactive campaigns.

## Stack-Budget Checks

When changing APDU dispatch, secure messaging, Rustlet activation, crypto, or
registry persistence, run the stack monitor on at least one relevant campaign:

```bash
cargo run test rustlet --check_stack mps2-an385 minimal_valid_test
cargo run test rustlet_all --check_stack mps2-an385
```

During hardware bring-up, `kernel_ping` provides the minimal equivalent:

```bash
cargo run test kernel_ping raspi-pico2 --on openocd \
  --allow-destructive --check_stack
```

`--check_stack` derives an instrumented manifest from the manifest that the
command would normally use. It adds both `kernel-stack-monitor` and
`rustlet-stack-monitor`, writes the complete derived TOML under
`target/xtask/generated-configs`, and builds that manifest normally. There is
no hidden module-selection environment variable.

The command probes the kernel high-water mark through `GET DATA DF71` after
APDU checkpoints and, when the campaign enters userland, the Rustlet high-water
mark through `GET DATA DF72`. It fails if the 6144-byte kernel budget (or the
smaller physical stack) is exceeded, if a versioned kernel checkpoint
regresses, or if a Rustlet campaign produces no Rustlet-stack measurement. A
missing baseline is only reported as a warning; the absolute budget remains
enforced.

To measure the userland stack of a Rustlet, select the independent
`rustlet-stack-monitor` module in the manifest used to build the image:

```toml
[kernel-image]
kernel-app-modules = ["kernel-stack-monitor", "rustlet-stack-monitor"]
```

It paints the Rustlet stack window immediately before entry, measures it after
return or fault recovery, and exposes the maximum as `GET DATA DF72`. These
diagnostic modules are optional and do not replace MSPLIM/PSPLIM or MPU stack
guards.

The focused QEMU runner uses a supplied manifest rather than an environment
override:

```bash
cargo run test rustlet --elf --check_stack \
  --config configs/config_rustlet_minimal_valid_stack_test.toml \
  mps2-an385 minimal_valid_test
```

Such a `--check_stack` regression is a useful result, not a transport error:
either reduce the stack usage before continuing, or explicitly accept and
record the new high-watermark after review.

For secure-channel or Rustlet Security Domain refactors, use the corresponding
SCP stack-monitored QEMU campaign as the focused regression oracle. Those runs
are intentionally outside the quick getting-started checklist.

Baselines live in:

```text
xtask/stack-baselines.toml
```

When you have reviewed the measurement and want to accept its checkpoint set,
whether it increases, reduces, or preserves stack usage, run:

```bash
cargo run test rustlet_all --update_stack_baseline mps2-an385
```

Baseline updates require a clean tracked worktree. The recorded entry includes
the measured commit so stack-history remains reproducible. Update mode still
enforces the absolute stack budget, but intentionally replaces the previous
campaign without treating an increase as an error. The Git diff is the review
surface for that decision. Baselines also carry the execution environment and
monitor profile, so QEMU and hardware builds or differently instrumented images
use distinct references.

## Suggested Workflow

For day-to-day kernel work:

```bash
cargo fmt --all
cargo test -p kernel object_registry --offline
cargo test -p kernel scp11 --offline
cargo run test kernel_ping mps2-an385
cargo run test rustlet mps2-an385 minimal_valid_test
```

Before considering an APDU, secure-channel, registry, or isolation refactor
stable:

```bash
cargo test --offline
cargo run test kernel_t0 mps2-an385
cargo run test gp_security_domain mps2-an385
cargo run test rustlet_all --check_stack mps2-an385
```

For persistence work on the Pico oracle:

```bash
cargo run test gp_scp03_install_load raspi-pico1
```

Run the broader Pico SCP11 persistence campaigns only when the change actually
touches SCP11 or Rustlet Security Domain persistence.

## Advanced Image Formats

The kernel build system can also produce a bootable kernel FAE image. That path
is useful for experiments where the kernel itself is packaged as a FAE payload,
or when targeting an external hypervisor such as PIP-MPU.

That image format is deliberately outside this getting-started path. Start with
the default ELF workflow above; use `cargo run build --help` only when you
explicitly need the non-ELF image modes.
