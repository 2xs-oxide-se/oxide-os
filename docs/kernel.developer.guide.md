# Kernel Developer Guide

This guide describes the current kernel-side Rustlet execution model in
`kernel/firmware`.

It focuses on the boundary between:

- the APDU transport and secure-channel loop in `kernel/firmware`;
- the shared services hosted in `oxi_core`;
- the standalone FAE images embedded into the kernel;
- the Rustlet runtime ABI used by those images.

## Scope

The current design is still an incremental GlobalPlatform implementation.

It now has a kernel-managed object registry, explicit Security Domain
authorities, SCP03/SCP11 secure-channel profiles, dynamic package loading, and
selected-Rustlet isolation. It does not yet implement the complete
GlobalPlatform lifecycle matrix, multi-channel model, or production-grade
registry/key-store policy.

What it does implement is a complete end-to-end path for:

- embedding one or more privileged Rustlet FAEs into the kernel image;
- selecting a Rustlet by AID;
- loading and relocating that FAE through the XiPFS startup path;
- executing the Rustlet in a distinct non-privileged context;
- routing later clear or protected APDUs to the selected Rustlet through a
  stable ABI;
- recovering cleanly from normal return, `exit`, `panic`, and MPU
  faults.

The important ownership rule is still:

- `kernel/firmware` owns transport, `SELECT`, deferred `GET RESPONSE`, and the
  selected Rustlet slot;
- `kernel/firmware/src/secure_channel.rs` owns the secure-channel APDU
  façade: SCP03/SCP11 establishment APDUs are consumed there, protected
  commands are unwrapped before dispatch, and protected responses are wrapped
  during completion;
- the selected Rustlet owns only its command semantics once selected.

There is also a deliberately separate, statically composed kernel-local path:

- `kernel/firmware/src/kernel_main_app.rs` owns the typed hook chains used by
  privileged `KernelAppModule` extensions;
- each selected module lives in its own file under
  `kernel/firmware/src/kernel_main_app/` and is part of the image TCB;
- APDU filters are one possible hook, not the definition of a module. Modules
  may instead observe kernel or Rustlet lifecycle events.

## Build and Embedding Pipeline

The current pipeline is explicit on purpose.

1. Each Rustlet is built as an independent FAE image.
2. `xtask` builds those FAEs before building `kernel/firmware`.
3. `kernel/firmware/build.rs` exports the generated FAE paths through
   environment variables.
4. `kernel/firmware/src/embedded_apps.rs` embeds the resulting files through
   Rust-native byte inclusion based on the selected build manifest.
5. At first initialization, the generated predeployment plan inserts package,
   instance, Security Domain, and key objects into the kernel-managed object
   registry.

Kernel application modules use a shorter parallel pipeline:

1. `[kernel-image].kernel-app-modules` carries an ordered list of names.
2. `xtask` validates only generic syntax and duplicates, then forwards that
   ordered list to the firmware build.
3. `kernel/firmware/build.rs` resolves every name through the single registry
   in `kernel/firmware/src/kernel_app_modules_registry.inc.rs`.
4. The build script generates one static slice per hook type in `OUT_DIR`.
   Only modules that implement a hook occur in that hook's slice.
5. `kernel_main_app.rs` walks those slices at the corresponding lifecycle
   points. There is no runtime registration, allocation, symbol lookup, or
   mutable module table.

The TOML order is the priority order for every filtering chain: the first APDU
filter that claims a command handles it. Observer hooks run in the same order.

Important current implementation details:

- embedded FAEs are aligned on 2 KiB boundaries in flash;
- the object registry is fixed-capacity in RAM while the firmware runs, and
  targets with a persistence area rebuild it from the latest valid persistent
  `BOSS` block at boot;
- live registry objects occupy stable runtime slots. Deletion leaves a
  tombstone instead of compacting later objects, and the next insertion may
  reuse the first tombstone;
- selected applications, selected Rustlet Security Domains, the active
  Security Domain, and exceptionally displaced contexts retain slot numbers rather
  than copied AIDs or object payloads. Every such optional reference must be
  cleared or consumed before its slot can be reused;
- embedded package code remains compile-time data selected by the manifest,
  while dynamically loaded packages can be committed as persistent `C0DE`
  blocks;
- the kernel embeds only the Security Domains and Rustlet packages declared by
  the selected configuration.

The normal build embeds the registry entries declared by the selected build
manifest. The user-facing entry point is `cargo run build --config=...`;
internally, `xtask` forwards that path to Cargo through
`OXIDE_SE_BUILD_CONFIG` because Cargo build scripts do not have their own
command-line option channel.

Trace output is a build/run option, not part of the predeployment manifest.
Use `--trace=none`, `--trace=semihosting`, or `--trace=jtag` on the `cargo run`
xtask command:

- `--trace=none` is the default and compiles kernel `consoleln!` traces as
  no-ops.
- `--trace=semihosting` enables QEMU/debug semihosting console traces.
- `--trace=jtag` enables the target debug trace hook and is currently accepted
  only for `raspi-pico1`.

QEMU runners may still enable semihosting services for test control or
target-provided entropy; `--trace` controls kernel console/debug traces.

For targeted Rustlet debugging, `xtask` either selects an existing
`configs/config_rustlet_*.toml` manifest or generates a small manifest
under `target/xtask/generated-configs`. The important invariant is that
single-Rustlet tests must not remap AIDs: a Rustlet uses the same AIDs in
`test rustlet` and in the full `test rustlet_all` image.

Target tests are selected through `cargo run test <name> [board] [options]`.
`xtask/src/testing/catalog.rs` owns the `TestCatalog`: each entry specifies the
scenario name, description, manifest, supported image/stack options, argument
kind, and required board capabilities. The catalogue drives parsing, help,
and configuration selection; add a scenario there rather than duplicating
command lists in `lib.rs`.

The host test code separates protocol assertions from target execution:

```text
xtask/src/testing/
  mod.rs          command dispatch, campaigns and stack-check scopes
  catalog.rs      scenario descriptions, help and capabilities
  options.rs      argument parsing and validation
  context.rs      explicit build inputs shared by a campaign
  target.rs       image preparation, QEMU lifetime and ATR synchronization
  openocd.rs      owned debugger, hardware programming/reset and serial ordering
  scenarios/
    kernel.rs     core and kernel-module assertions
    gp.rs         management and secure-channel assertions
    rustlets.rs   canonical application scenarios
    persistence.rs  multi-boot registry transactions
```

To add a test, register it in the catalogue, then put its APDU operations and
assertions in the relevant scenario module. Use `target::run_apdu` for a fresh
image/target session; do not assemble a QEMU command or repeat connection and
cleanup code in the scenario. The runner validates the ATR against the effective
manifest before calling the scenario. Errors identify the scenario, board,
backend, elapsed time and stage; APDU transport failures include the command
header without dumping payload secrets. Target output is drained while QEMU
runs and attached to failure reports.

The client distinguishes connection setup (`TARGET_CONNECTION_TIMEOUT`, five
seconds) from firmware initialization before the first ATR byte
(`TARGET_INITIALIZATION_TIMEOUT`, 120 seconds). Predeployment installs and
flash commits can outlast connection setup, notably under Pico1 QEMU. The
`ATR validated after ...s` log records the complete ATR observation time,
including frame-idle detection. This host allowance is not an ISO reset-to-ATR
timing guarantee and does not relax APDU byte deadlines or the 200 ms frame-idle
limit. Both constants live in `xtask/src/lib.rs`.

`BuildContext::with_config` derives another profile without changing the
process environment. Instrumentation and trace settings survive that change.
Only child compilation commands receive the variables consumed by `build.rs`;
disabled options explicitly clear inherited values. Keep source files and
payload inputs unchanged during a campaign. Within that invocation, identical
effective image configurations reuse an immutable image snapshot, not a running
QEMU process. Snapshots cannot be overwritten by a subsequent profile build
and are removed when the campaign ends.

For persistence, keep one `target::FlashFile` owner across boots and call
`target::run_boot`: supply the image only for the initial boot, then `None`
for resets against the same flash file. Target teardown kills and reaps QEMU,
collects its output and removes its socket even after a failed connection or
assertion. Flash-file and image owners also clean up on early returns.

`--on qemu` is the default when the selected board has QEMU support.
Otherwise the default is OpenOCD; an explicit board remains mandatory for
hardware. Without `--serial`, the unique USB serial port is selected at 115200
baud; ambiguous or absent USB links require an explicit choice. A failed QEMU
test never falls back to hardware.
ELF is the default; unsupported formats or stack options are rejected before
building. Stack baseline identifiers use
scenario names independently of CLI syntax; renaming a command must preserve
its measured commits, checkpoints, and limits.

### OpenOCD Execution

**Validation status:** the centralized runner is implemented and covered by
host tests, including mocked reset/serial ordering and failure cleanup.
Its Tcl RPC framing has been checked against OpenOCD without a probe.
On 2026-08-30, `kernel_ping raspi-pico2 --on openocd --allow-destructive`
passed end-to-end with automatic serial selection, OpenOCD HEAD d9b957f35
and a CMSIS-DAP probe: flash programming/verification, ATR and one echo
assertion. `kernel_t0` also passed all four checks, and the `kernel_crypto`
AES-128-CBC benchmark passed with a known vector. Pico2 now also passes the
`fill_random 24` benchmark through its SDK-style raw-TRNG/PRNG backend;
this is functional validation, not a cryptographic security guarantee.
The default crypto smoke scenario passes on Pico2, with P-256 returned through
one GET RESPONSE using the existing shared APDU buffer.
Other boards/scenarios and hardware failure cleanup still require
validation; successful QEMU runs and builds do not establish it.
The physical acceptance checklist is tracked in
[`TODO.md`](TODO.md#board-porting-and-hardware-validation).

`testing/openocd.rs` controls a private OpenOCD process over its loopback
[Tcl RPC interface](https://openocd.org/doc/html/Tcl-Scripting-API.html).
It uses the installed `openocd` executable, `interface/cmsis-dap.cfg` and the
board catalogue's `openocd_target` script (`target/rp2040.cfg` for Pico1,
`target/rp2350.cfg` for Pico2). The installed OpenOCD must provide that
script and its flash driver. `--probe-serial ID` selects the debug adapter
when several are attached; it does not select the APDU serial port.

With one USB UART bridge attached, the short hardware command is:

```sh
cargo run test kernel_ping raspi-pico2 --on openocd --allow-destructive
```

Without `--serial`, the runner enumerates ports without opening them and
selects the unique USB serial interface at 115200 baud. Bluetooth and platform
console ports are not automatic candidates. On macOS, `cu.*` is preferred over
the matching `tty.*` alias. If several USB interfaces exist, it stops and
lists ports, USB metadata and commands using `--serial` to select one.
An explicit `--serial` bypasses discovery, including for non-USB ports or
another baud rate. USB discovery identifies an adapter, not proof that its
UART is wired to the selected board; ATR/APDU validation still checks that.

The first hardware scenarios to validate are `kernel_ping`, `kernel_t0`,
and `rustlet minimal_valid_test` on a Rustlet-capable board. `kernel_crypto`
and its `--bench` operations also use the same OpenOCD/APDU path; the complete
crypto scenario requires working target entropy. Run the first three in
that order, expecting respectively 34, 4 and 6 successful assertions:

```sh
cargo run test kernel_ping raspi-pico1 --on openocd \
  --serial /dev/cu.usbmodemXXXX:115200 --allow-destructive
cargo run test kernel_t0 raspi-pico1 --on openocd \
  --serial /dev/cu.usbmodemXXXX:115200 --allow-destructive
cargo run test rustlet raspi-pico1 minimal_valid_test --on openocd \
  --serial /dev/cu.usbmodemXXXX:115200 --allow-destructive
```

Replace the serial path with the APDU UART bridge, not a debug-control port.
The shared `apdu_tool` transport also accepts `COM3:115200`, a TCP endpoint
or a Unix socket. Physical serial uses 8 data bits, no parity, one stop bit
and no flow control. No second APDU protocol implementation is introduced.

**Destructive:** each invocation erases the board's declared FLASH range,
including the persistent registry, before programming and verifying the ELF.
Without `--allow-destructive`, the command reports the affected range and
stops before touching the target. Use only a dedicated test device.

The ordered boot contract is:

1. Reset and halt; erase, program, verify; reset and halt again.
2. Open the APDU link and discard stale input while the target is halted.
3. Release reset with `reset run`; never purge the link after this point.
4. Receive and check the ATR, then run the same assertions as under QEMU.
5. Halt the target and stop the owned debugger, including after a test failure.

Builds use `hardware`, not the QEMU configuration, and the image-cache key
includes this distinction. The default trace is `none`; Pico1 can use
`--trace=jtag` through OpenOCD's semihosting support. Hardware rejects
`--trace=semihosting`, which denotes the QEMU build mode.

The internal reset-only path takes no image and issues no erase/program
commands. `kernel_flash` uses this reset-only path to test the block reserved
by `flash-probe` across three complete boots (five checks, validated on Pico2
and Pico1 QEMU). The module reserves the tail before the first registry access;
later or conflicting reservations are rejected. `kernel_registry` uses the
same reset-only path with the normal registry APIs: 18 Data objects, 4165
initial payload bytes, replacement and byte-for-byte recovery (75 APDU checks
with complete-object responses up to 244 bytes).
Broader GlobalPlatform persistence campaigns remain unavailable on hardware;
so do fault-diagnostic scenarios, FAE images and stack baseline checks/updates.
Adding an OpenOCD script does not by itself promote `board_support`.

Relevant files:

- `kernel/firmware/build.rs`
- `kernel/firmware/src/kernel_app_modules_registry.inc.rs`
- `kernel/firmware/src/kernel_main_app.rs`
- `kernel/firmware/src/kernel_main_app/*.rs`
- `kernel/firmware/src/embedded_apps.rs`
- `kernel/firmware/src/embedded_apps_registry.inc.rs`
- `xtask/src/lib.rs`
- `rustlets/*`

The functional Rustlet scenarios in `xtask/src/testing/scenarios/rustlets.rs` are shared:
`test rustlet` runs one canonical scenario, while
`test rustlet_all` embeds the normal test set and chains those same
scenarios in one QEMU session.
`test gp_all` calls the same GP scenario functions as individual commands,
using a fresh target for each independent scenario. Neither campaign launches
another xtask process.

## Security Domain Profile

The kernel resolves one Security Domain authority for each management command.
The root Security Domain backend is selected by the build manifest, not by
board code. Clear out-of-channel management uses the root Security Domain
authority; protected management uses the Security Domain instance bound to the
active secure-channel session.

The three selectable backends are:

- `NullSecurityDomain`
- `KernelSecurityDomain`
- `RustletSecurityDomainProxy`

The default is still:

- `NullSecurityDomain`

This profile authorizes management operations and does not implement a secure
channel. It is the no-security/debug profile used to keep the embedded Rustlet
flow available without a user-space Security Domain.

For kernel-owned GP/SCP bootstrap work, build with one dedicated manifest:

```sh
cargo run build --config=configs/config_scp03_test.toml
```

This selects:

- `KernelSecurityDomain`
- SCP03 profile `S8`

Use a manifest with `secure_channel.scp03_profile = "S16"` when the build
must exercise the explicit SCP03 S16 profile. The SCP03 profile is only valid
when the manifest enables SCP03 explicitly:

```toml
[secure_channel]
protocols = ["SCP03"]
scp03_profile = "S16"
```

For SCP11 builds, the manifest selects one or more establishment variants
without carrying an SCP03 profile:

```toml
[secure_channel]
protocols = ["SCP11"]
scp11_profiles = ["A", "B", "C"]
```

The implementation then applies one explicit security-level profile:

- SCP03 accepts `EXTERNAL AUTHENTICATE P1=00`, `01`, and `03`. It rejects
  response-protection levels `11`, `13`, and `33`; selected SCP03 responses
  therefore remain plain.
- SCP11a/b/c accept only CRT key-usage qualifier `95=3C`, which selects
  C-MAC/C-ENC/R-MAC/R-ENC. Other GP-defined qualifiers are rejected before
  authentication.
- `BEGIN R-MAC SESSION` (`INS=7A`) and `END R-MAC SESSION` (`INS=78`) are
  deliberately unsupported and return `6D00`. They are optional SCP03
  companion commands and do not apply to SCP11.

Host tests exhaustively validate the selected byte values. The dedicated
`test gp_scp03` and `test gp_scp11a/b/c` campaigns verify representative accepted
and profiled-out values through the firmware APDU boundary.

The ATR reflects that effective build configuration. Oxide SE emits compact
TLV historical bytes ending in:

```text
80 56 09 C1 DE 5E xx yy 73 80 00 00
```

`09 C1 DE 5E` identifies Oxide SE, `xx` is the OS version byte (`09`, meaning
0.9 beta, in the current tree), and `yy` summarizes the root Security Domain
posture plus enabled SCP03/SCP11 profiles. The ISO `73 80 00 00` Card
Capabilities object is intentionally minimal: it only announces selection by
full DF name/AID, not an ISO file system, extended APDUs, or logical-channel
management.

For a user-space Security Domain backed by one embedded Rustlet Security
Domain, use the Rustlet Security Domain QEMU commands:

```sh
cargo run test gp_rustlet_security_domain_scp03 --elf mps2-an385
cargo run test gp_rustlet_security_domain_scp11a --elf mps2-an385
cargo run test gp_rustlet_security_domain_scp11b --elf mps2-an385
cargo run test gp_rustlet_security_domain_scp11c --elf mps2-an385
```

This selects:

- `RustletSecurityDomainProxy`
- the dedicated Rustlet Security Domain predeployment manifest

The kernel profile routes `INSTALL [for load]`, `LOAD`,
`INSTALL [for install]`, `GET DATA`, `STORE DATA`, `PUT KEY`, `DELETE`, and
secure-channel establishment commands through the same
`SecurityDomainManagement` and `SecurityDomainSecureChannel` traits. Its SCP03
handshake delegates KDF, cryptograms, C-MAC/R-MAC, and C-ENC/R-ENC to the pure
`core::scp03` engine; its SCP11a/b/c handshakes delegate profile-specific
establishment to the shared `core::scp11` / `core::scp11c` code and then reuse
the common secure-messaging path. The S8 and S16 variants are SCP03
secure-channel profiles selected separately from the authority itself. SCP11
builds always use the SCP11 secure-messaging profile implied by the selected
SCP11 establishment variant, and do not carry an `scp03_profile`.

The management policy is authority-based:

- a clear management APDU is interpreted under the root Security Domain
  authority;
- a protected management APDU is interpreted under the Security Domain
  instance bound to the active secure-channel session.

From there, each backend applies its own policy. `NullSecurityDomain` accepts
out-of-channel clear management for bring-up and debug. `KernelSecurityDomain`
rejects that out-of-channel path and only accepts mutating management
operations through a valid secure channel. `test gp_security_domain`
exercises this boundary across the kernel Security Domain SCP03 and SCP11
profiles by rejecting clear mutating management, opening protected sessions,
installing `minimal_valid_test`, selecting it, and then running its minimal
APDU scenario.

The proxy profile routes the same kernel-side management and secure-channel
operations through `sddispatch` into the selected Rustlet Security Domain
instance. The kernel still owns:

- APDU parsing;
- registry insertion and lookup;
- privilege non-escalation checks;
- the active Security Domain context;
- secure-channel attachment to the active Security Domain instance.

The Rustlet Security Domain refines management policy and performs its own
SCP03/SCP11 cryptography through the runtime APIs exposed in
`rustlet_runtime`. The kernel still performs APDU-layer framing, DO parsing,
registry mutation, and transaction publication; the Rustlet Security Domain
answers the policy and cryptographic hooks exposed by `sddispatch`.

Kernel-native SCP03 static communication keys are typed registry objects
owned by a Security Domain. They are declared by the build
manifest or created later through `PUT KEY`, then stored as typed registry
objects attached to the owning Security Domain instance through
`parent_sd_aid`. In the current subset, each object stores raw AES-128 SCP03
`ENC` or `MAC` material keyed by `(key_version, key_id, usage)`, and
`INITIALIZE UPDATE` resolves those objects back into `core::scp03::StaticKeys`
before deriving one session.

This object model is shared by both secure profiles:

- `KernelSecurityDomain` reads its SCP03 static keys from those registry
  objects directly in the kernel;
- `RustletSecurityDomainProxy` exposes runtime syscalls so the Rustlet Security
  Domain instance can load its own SCP03 key material from the same registry.

`PUT KEY` uses one coherent storage model:

- keys are managed objects in the global registry;
- each key object belongs to one Security Domain instance through
  `parent_sd_aid`;
- identical `(key_version, key_id, usage)` tuples may exist in multiple
  Security Domain subtrees because they are parent-qualified resources;
- session establishment always resolves keys relative to the active Security
  Domain instance, not from a process-global key table.

Both profiles use the root Security Domain AID declared by the selected
predeployment manifest. The default development manifest keeps
`A0000047504F5301`.

At boot, the kernel always creates one technical root Security Domain instance
in the global registry. The root is not implicitly the Issuer Security Domain:
an Issuer exists only when one direct child is declared with
`role = "issuer"`. The selected backend defines how the technical root behaves:

- `NullSecurityDomain` acts as a debug/development root authority. It
  owns a root administrative identity in the registry, serves the same minimal
  `GET DATA` administrative view as the kernel-native profile, but does not
  implement secure-channel establishment.
- `KernelSecurityDomain` acts as a kernel-native root Security Domain
  profile. It bootstraps the root administrative-state object and consumes any
  initial SCP03 key objects explicitly declared for that instance in the build
  manifest.
- `RustletSecurityDomainProxy` bootstraps one root Rustlet Security Domain
  instance in that same registry. The proxy remains the kernel-side authority,
  but the selected Rustlet Security Domain instance owns its higher-level
  policy and SCP03 state.

The kernel uses one build-time mechanism for the initial administrative
topology:

- choose the backend, root package/instance AIDs, instance install bytes, and
  pre-installed objects in one
  manifest;
- keep [config.toml](../config.toml) for
  the empty development image;
- use `cargo run build --config=...` for richer
  topologies.

The manifest format is structured around `package.*` and `instance.*`
sections. The minimal development image looks like this:

```toml
[root.package]
name = "NullSecurityDomain"
aid = "A0:00:00:47:50:4F:53:01"

[root.instance]
aid = "A0:00:00:47:50:4F:53:01"
install_bytes = "FF:FF:FF"
```

Initial keys are owned by the Security Domain section in which they are
declared. The current key type is the AES-128 material used by SCP03:

```toml
[[root.keys]]
type = "Scp03Static"
version = 1
id = 3
usage = "Enc"
material = "40:41:42:43:44:45:46:47:48:49:4A:4B:4C:4D:4E:4F"

[[root.keys]]
type = "Scp03Static"
version = 1
id = 3
usage = "Mac"
material = "50:51:52:53:54:55:56:57:58:59:5A:5B:5C:5D:5E:5F"
```

The same `[[security_domains.keys]]` form attaches initial keys to a
supplementary Security Domain. Images that do not declare keys do not receive
fallback development keys from the firmware.

For a rustlet package loaded inside one Security Domain, the package is
selected by path and each declared instance carries one explicit AID plus its
installation payload:

```toml
[[root.packages]]
path = "./rustlets/tests/minimal_valid_test"

[[root.packages.instances]]
aid = "A0:00:00:47:50:4F:53:16"
install_bytes = ""
```

Supplementary Security Domains use the same package/instance structure and
name their parent instance explicitly:

```toml
[[security_domains]]

[security_domains.parent]
aid = "A0:00:00:47:50:4F:53:01"

[security_domains.package]
name = "NullSecurityDomain"
aid = "A0:00:00:47:50:4F:53:02"

[security_domains.instance]
aid = "A0:00:00:47:50:4F:53:03"
install_bytes = "80:00:00"

[[security_domains.packages]]
path = "./rustlets/tests/minimal_valid_test"

[[security_domains.packages.instances]]
aid = "A0:00:00:47:50:4F:53:27"
install_bytes = ""
```

The dedicated regression command validates that this child Security Domain and
its contained instance are installed during first-boot initialization, and
that the child cannot escape its registry subtree:

```bash
cargo run test gp_predeployment mps2-an385
```

The practical bootstrap rule is:

- the technical root is the only Security Domain recorded with
  `parent_sd_aid = None`;
- zero or one direct child may be marked `role = "issuer"`; absence means that
  the composition has no distinct Issuer Security Domain, while a second
  declaration is a configuration error;
- every other Security Domain or applet instance is created under its declared
  Security Domain and therefore receives that instance as `parent_sd_aid`;
- manifest order is irrelevant: the generated plan installs the root, the
  optional Issuer, then all remaining domains in parent-before-child order.

This is also the rule used by `PUT KEY`:

- a clear `PUT KEY` is authorized, or rejected, by the root Security Domain;
- a protected `PUT KEY` is authorized, or rejected, by the Security Domain
  instance bound to the secure channel;
- the resulting key objects are inserted under that authority instance;
- later `INITIALIZE UPDATE` lookups resolve against that same parent-qualified
  scope.

## Runtime Ownership Model

The runtime is split into a few small layers with different
responsibilities.

### 1. Byte transport and T=0 manager

`kernel/firmware/src/main.rs` owns the APDU loop through the abstract
`TransportLayer` interface.

The current stack starts with two explicit layers:

- `kernel/firmware/src/transport_layer.rs`
- `kernel/firmware/src/apdu_manager.rs`

`TransportLayer` owns only byte I/O:

- `send_byte`
- `receive_byte`

The current concrete backends are:

- `SerialTransport` for the normal UART path;
- `SimulatedTransport` for scripted APDU runs;
- `CurrentTransport` as the runtime-selected sum type.

`T0ApduManager<T>` is built on top of one `TransportLayer` instance and is
responsible for:

- ATR emission;
- reading the APDU header;
- retaining only deferred-response metadata, leaving the response bytes in the
  shared APDU payload, and emitting `61xx`;
- recognizing and serving `GET RESPONSE`;
- emitting procedure bytes;
- handling pure-outgoing `6Cxx`;
- emitting final `SW1/SW2`.

The selected Rustlet never owns the transport directly.

`kernel/firmware/src/kernel_main_app.rs` sits next to this loop on purpose. It
does not own transport either. Before conventional kernel dispatch, the loop
offers each command to the statically selected APDU-filter slice. The first
filter that claims the command returns its final status. If no filter claims
it, a `global-platform` image continues through normal management or selected
Rustlet dispatch, while a `kernel-only` image returns instruction-not-supported.

This behavior is selected by `[kernel-image].mode`; it is not an embedded-
Rustlet boolean. Kernel application modules may also be present in a
`global-platform` image, for example to measure stack use while the ordinary
GlobalPlatform and Rustlet paths remain active.

### 2. APDU protocol-layer composition

Above the base `T0ApduManager`, the kernel uses a separate protocol
boundary defined in `kernel/firmware/src/apdu_layer.rs`.

The central trait is:

- `ApduLayer`

Its job is deliberately narrow:

- emit ATR when relevant;
- receive one `ApduCommand`;
- complete one `ApduCompletion`.

This is the composition point for protocol wrappers above the base
`T=0` manager. At the time of writing, the stack instantiated in
`main.rs` is:

1. `CurrentTransport`
2. `T0ApduManager<CurrentTransport>`
3. `PassthroughApduLayer<_>`
4. `SecureChannelLayer<_>`
5. `TracingApduLayer<_>`

The two wrapper layers are intentionally small:

- `TracingApduLayer` logs APDU-layer transitions for scripted runs;
- `SecureChannelLayer` consumes SCP03 and SCP11a/b/c establishment APDUs,
  calls the active `SecurityDomainSecureChannel`, separates the raw protected
  command payload from its trailing C-MAC, and emits protected response data
  followed by R-MAC when secure messaging is active.

`SecureChannelLayer` is profile-neutral at the APDU-wrapper boundary. It
recognizes the GlobalPlatform establishment command families:

- `INITIALIZE UPDATE` and `EXTERNAL AUTHENTICATE` for SCP03;
- `PERFORM SECURITY OPERATION`, `INTERNAL AUTHENTICATE`, and
  profile-specific `MUTUAL AUTHENTICATE` forms for SCP11a/b/c.

For each protected command, the layer snapshots whether the authenticated
session requires response protection before dispatching the clear command.
That boolean is stored in the current `ApduCommand` and consumed during
completion; it cannot leak into the next APDU because it has the same lifetime
as the command. This ordering is an ABI invariant for a Rustlet-backed
Security Domain: querying its session state uses `sddispatch` and therefore
reuses the shared APDU page, so the kernel must not query that state again
after the selected application has produced its response.

SCP11 establishment parameters are bound before session derivation:

- the common parser rejects reserved SCP parameter bits and requires tag `84`
  exactly when parameter bit `b3` includes identities in `SharedInfo`;
- `P1`/`P2` select the ECKA key version and identifier owned by the active
  Security Domain; unsupported selectors are never replaced implicitly;
- SIN/SDIN for SCP11a/b and Card Group ID for SCP11c come from the active
  Security Domain, not from host-controlled CRT fields;
- `SecureChannelLayer` reassembles PSO command blocks selected by `P1.b8`
  before delegating the verified certificate to either backend. The current
  bounded development profile accepts 256 certificate bytes and rejects
  intermediate certificate chains selected by `P2.b8` with `6A86`.

The selected Security Domain owns the profile-specific state machine, keys,
cryptograms, replay counters, MAC chain, and encryption policy. The APDU layer
owns only the boundary transformation:

- establishment APDUs are consumed and completed before generic dispatch;
- protected command APDUs are authenticated/decrypted into a logical clear
  command before dispatch;
- protected responses are wrapped during `ApduCompletion`;
- SCP03 clear commands remain clear and are dispatched according to the active
  authority policy;
- while SCP11 secure messaging is active, a clear `SELECT` terminates the
  session and continues normally, whereas any other clear command aborts the
  session and returns `6985`.

Secure-channel failures use one explicit status contract at this boundary:

- `6700` reports an invalid profile-dependent length or a protected field that
  cannot fit its bounded destination;
- `6A80` reports malformed SCP11 CRTs or another malformed command data
  structure;
- `6A86` reports an invalid `P1`/`P2` selector or a deliberately profiled-out
  command option;
- `6A88` reports a referenced SCP03 keyset or SCP11 ECKA/CA key that cannot be
  resolved by the active Security Domain;
- `6600` reports SCP11 certificate verification failure;
- `6300` reports failed SCP03 host authentication;
- `6982` reports a secure-messaging cryptographic failure, including an
  invalid MAC chain, stale receipt, or replay;
- `6985` reports a valid command received in the wrong protocol state, such as
  `EXTERNAL AUTHENTICATE` before `INITIALIZE UPDATE`;
- `6D00` reports an establishment instruction not implemented by the selected
  build profile.

The SCP03 and SCP11 engines calculate candidate MAC chains and encryption
counters locally. They publish those values only after the complete unwrap or
wrap operation succeeds, so malformed APDUs, short output buffers, invalid
padding, and replays cannot partially advance session state. Structural
protected-APDU errors retain an authenticated session so a corrected command
can be sent. A cryptographic secure-messaging error returns `6982`, clears the
session, and makes every subsequent protected command fail with `6985` until a
new establishment sequence completes. Failed host authentication similarly
requires a new `INITIALIZE UPDATE`.

After unwrapping, the dispatcher applies a protocol-level management matrix
before consulting the selected Security Domain hooks:

- SCP03 and owner-authenticated SCP11a permit the implemented management
  families;
- card-authentication-only SCP11b permits read-only `GET DATA`, but no registry
  mutation;
- owner-authenticated SCP11c forbids `PUT KEY`, `SET STATUS`, and deletion of
  key objects, while allowing its other implemented management families;
- SCP11c `ANY_AUTH` is limited to `GET DATA` because the current profile does
  not implement the `BF20` authorization object.

This first gate is not overridable. Hierarchy checks, privileges, and
`SecurityDomainManagement` hooks are still evaluated for every accepted
command, so a native or Rustlet-backed backend may further restrict a request
but may never widen the protocol matrix. The dispatcher reads the active
kernel-owned session binding for this gate; it must not call a Rustlet
Security Domain's `session_state()` after unwrapping because that call reuses
the shared APDU page.

There is one deliberate fallback for supplementary protocols. A protocol
enabled by the build manifest is always recognized and filtered by the kernel
matrix above. If no compiled profile claims an establishment header, the active
Rustlet Security Domain may claim it through
`CLAIM_DELEGATED_SECURE_CHANNEL`, consume the raw establishment command through
`HANDLE_DELEGATED_SECURE_CHANNEL`, and own the resulting session policy. The
kernel records that ownership without pretending to know a protocol number.
Its protected-payload framing and memory bounds still apply, and registry reachability,
privilege non-escalation, lifecycle guards, and every management-family hook
remain mandatory. Only the unknown protocol's establishment, cryptographic
state, and profile-specific authorization matrix are delegated.

The regression command
`cargo run test gp_rustlet_security_domain_delegated_scp03 mps2-an385`
builds with `secure_channel.protocols = []`: the ATR advertises no kernel SCP
profile, while `complete_security_domain` claims SCP03 and passes the S8, S16,
`0x33`, key-rotation, replay, and protected-install scenarios. Native engine
entry points are constant stubs in this build profile, allowing release
dead-code elimination to remove the SCP03/SCP11 engines from `kernel.elf`; the
Rustlet FAE remains the sole SCP implementation in that image.

The layer must preserve the kernel zero-copy discipline. Protected bytes are
received in the transport-owned APDU buffer. Temporary authenticated strings,
clear payloads, and response MAC bytes use explicit kernel scratch buffers with
APDU-sized bounds, not unbounded stack arrays. After a successful unwrap, the
transport APDU buffer is rewritten in place with the logical clear payload that
management handlers or a selected Rustlet will see.

The important design rule is:

- higher protocol layers should be expressed as `ApduLayer`
  implementations;
- they should not need to know the concrete `TransportApdu` type.

### 3. APDU command and completion boundary

`ApduLayer` does not expose `TransportApdu` directly.

Instead it uses:

- `ApduCommand`
- `ApduCompletion`

`ApduCommand` is the APDU-layer view of the current command. It exposes:

- the APDU header;
- lightweight header accessors;
- `as_apdu()` to derive the kernel-side `SEApdu` view.

It also carries layer-private, per-command metadata such as the response
protection decision captured before application dispatch. Higher layers do not
expose that metadata to application code.

`ApduCompletion` groups:

- the command being completed;
- the final `ApduStatus`.

This split prevents the kernel dispatcher from depending on the
transport-owned APDU representation. The dispatcher sees:

- one command object on the way in;
- one completion object on the way out.

### 4. Selection path

`SELECT` is recognized before generic dispatch.

The kernel:

1. receives the command data as an AID;
2. resolves the visible instance and package objects in the kernel registry;
3. loads the embedded FAE image referenced by the package object;
4. executes the Rustlet `start()` entry point in isolated mode;
5. validates the returned descriptor;
6. stores the resulting selected context.

If the AID is unknown, the kernel returns `6A82`.

Semantic rule:

- `SELECT` establishes the selected execution context;
- it does not call `install()`.

`install()` is called later only if the routed APDU uses
`INS = E6`.

### 5. FAE loading and activation

`kernel/firmware/src/fae_runtime.rs` owns the activation boundary.

The kernel does not reimplement the XiPFS startup loader. Instead, it
enters the embedded FAE at offset `0`, so the existing XiPFS runtime
startup code remains responsible for relocation.

The current activation path is:

1. `load(fae)` enters the embedded image loader with an application RAM
   arena;
2. the loader relocates the image and yields the Rustlet entry point and
   application `gp` value;
3. the kernel derives an explicit memory layout:
   - executable flash window;
   - one power-of-two writable RAM block containing the execution stack first,
     followed immediately by relocated data and the Rustlet heap;
4. the kernel asks `oxi_core::core::isolation` to build an MPU plan for
   that layout;
5. `call_start()` or `call_handler()` enters the Rustlet through the
   isolation layer.

The kernel stores only the minimum state needed to re-enter the
application later:

- `app_gp`;
- the returned `state` pointer;
- the returned `vtable`;
- the Rustlet memory layout and MPU plan.

### 6. Isolated execution

Rustlets execute as isolated unprivileged application sessions.

`oxi_core::core::isolation` owns the generic execution-session
model:

- session state for the active Rustlet call;
- MPU plan programming;
- distinction between `start` and `handler` calls;
- return-value policy for normal and faulty exits;
- runtime exit hook wiring.

The board module selects its CPU implementation through a `cpu` module alias.
`target/mod.rs` uses that alias as `app_target_profile`; no runtime dispatch or
trait object is involved. `kernel/core/build.rs` emits exactly one architectural
cfg (`oxide_se_target_armv6m`, `oxide_se_target_armv7m`, or
`oxide_se_target_armv8m`) so incompatible assembly is not compiled.

- `armv6m_profile.rs` owns Thumb-1 entry/return, PMSAv6 and HardFault recovery.
- `armv7m_profile.rs` owns PMSAv7 and the external MPU stack guard.
- `armv8m_profile.rs` owns PMSAv8 and MSPLIM/PSPLIM. Its MPU has no NoAccess
  encoding: requests for it fail rather than silently granting privileged RW.
- `common_arm_m_profile.rs` owns the identical exception-frame/entry layouts,
  SVC immediate decoding, barriers and RAM-XN window programming. Compile-time
  assertions preserve the offsets consumed by assembly.
- `common_arm_m_profile/mainline.rs` shares the identical v7-M/v8-M Mainline
  exception machinery. ARMv6-M keeps its distinct exception path.

The selected profile and these shared mechanisms provide:

- `SVC` dispatch;
- `MemManage` dispatch;
- entry into isolated application context;
- return to the kernel;
- the RAM gate region that contains the shared ABI buffer and the entry
  and return trampolines.

Board modules retain clocks, UART, flash, RNG and `MEMORY_LAYOUT`. CPU profiles
never import a named board. The target facade derives stack, boot ABI and RAM-XN
windows from that layout; the shared NX helper receives an explicit borrowed
window list and statically selected MPU operations, with no heap allocation.
Architectural SysTick is also implemented once in `common_arm_m_profile.rs`;
each board supplies only the effective core frequency through
`timer_clock_hz()`. Kernel code installs the single periodic callback with
`core::timer::set_periodic_handler()`. The callback starts as a non-preemptible
top-half and may call `core::timer::begin_bottom_half()` once its shared-state
updates are complete, allowing higher-priority interrupts to preempt the
remaining work. The dispatcher always restores interrupt delivery on return.
Oxide SE configures this callback at 100 ms. Independent saturating counters
emit T=0 NULL bytes every ten ticks while an APDU is being processed and expire
an active Rustlet after one hundred ticks. The T=0 path arms NULL delivery only
after all currently expected host bytes have arrived; every real response byte
clears that state immediately before touching the transport. Rustlet entry and
the common return/fault cleanup respectively arm and clear the watchdog.

SysTick intentionally remains below SVC priority. Consequently this first
watchdog is best-effort: neither its timeout nor NULL cadence advances during a
long syscall. Direct Rustlet execution is recoverable through the same redirect
used by MPU and CPU faults; the timer entry restores the kernel static base and
execution MPU phase before running Rust code. Flash backends that suspend XIP
must preserve and mask interrupts across that exact interval. A pending tick is
served only after XIP and the previous PRIMASK state have been restored.
The architectural encodings are checked in `armv8m_mpu.rs` by host tests.
MSPLIM guards kernel stack growth on v8-M; a direct memory write below the stack
is not the same test. The v8-M stack-guard diagnostic deliberately crosses
MSPLIM. Recovery of other UsageFault classes is not implied by this refactoring.

Pico2's `kernel/native/raspi-pico2/link.ld` reserves the last 16 KiB of RAM for
`.critical.kernel.fct`, including RAM-executed flash-programming routines:

- `0x20000000..0x2007e000`: 504 KiB mutable RAM, privileged RW/XN in region 6
  during kernel execution. The 8-KiB kernel stack starts at the RAM base;
  `.data`, `.bss`, allocator metadata, heap and Rustlet RAM remain below this end.
- `0x2007e000..0x20082000`: executable RAM reservation, excluded from the heap
  and NX mapping. The boot code copies `.critical.kernel.fct` here before use.

The linker asserts that both areas fit. `__ram_end` follows `.bss`, not the
executable section; the allocator stops at the mutable/executable boundary.
The 16-KiB reservation must match `PICO2_EXECUTABLE_RAM_SIZE` in `target/mod.rs`.
It is a reserved capacity, not the current code size.

PMSAv8 does not use the overlapping-region priority rule of PMSAv7. Before
installing kernel NX, `armv8m_profile` disables overlapping application regions.
During kernel execution, attempted user RAM mappings are deferred. Immediately
before user entry/resume, the isolation layer removes kernel NX and restores
the gate and application mappings from the existing isolation plan. There is
no second MPU-plan snapshot or per-transition allocation. A failed NX transition
terminates execution rather than continuing without protection.

`cargo run test kernel_ram_nx raspi-pico2 --on openocd --allow-destructive`
validates this on hardware: OpenOCD vector catch must stop at MemManage with
IACCVIOL, privileged MSP context, and stacked PC at a RAM `BX LR` instruction.
An APDU timeout or an unrelated HardFault is not success. Semihosting services
the core diagnostic's startup messages, but the verdict uses fault registers,
not console text. Flash, crypto and minimal Rustlet tests additionally check
that the executable tail and user transitions remain usable. This does not
establish complete Rustlet fault recovery.

`cargo run test kernel_stack_guard raspi-pico2 --on openocd --allow-destructive`
independently checks MSPLIM enforcement. The diagnostic saves the boot limit
in r2, raises MSPLIM to MSP and executes a PUSH. OpenOCD stops at the
UsageFault entry before handler stack use, checking STKOF alone
(`CFSR=00100000`, `HFSR=00000000`), privileged MSP context and the original
limit equal to the stack base. Kernel overflow remains fatal; this test does
not claim recovery or execution of a diagnostic handler on an exhausted stack.
The core-test build tracks the native-startup fingerprint so edits to its
external vector/startup object trigger a relink.

The [profile integration validation report](reports/arm-profile-integration-2026-08-31.md)
records tested targets, stack measurements and the remaining hardware checks.

Pico2 UART output waits for UARTFR.BUSY to clear before every 32nd byte,
without an artificial delay. Only the synchronous kernel transport writes
UARTDR; BUSY clears after the final stop bit. Each write checks TXFF at bit 5;
bit 6 is RXFF and cannot provide transmit backpressure. All 34 hardware ping
assertions through 255 bytes pass with this policy, including unfragmented
GET RESPONSE. Crypto diagnostics also retrieve their complete short response
without a bridge-specific chunk limit.

The current execution mode for a Rustlet is:

- thread mode;
- non-privileged;
- `PSP` for the Rustlet execution stack;
- MPU enabled with privileged default mapping still available to the
  kernel;
- `MSP` and privileged state restored on kernel return.

The return path is deliberately mediated:

- a normal Rustlet return does not jump directly back into privileged
  kernel code;
- it returns through a RAM return gate that raises a reserved `SVC`;
- `SVC`, `exit`, `panic`, and recoverable `MemManage` faults all
  converge toward the same kernel-resume mechanism.

## Rustlet Memory Model

The current Rustlet memory model is intentionally simple and bounded by
the Cortex-M MPU constraints.

### Target RAM policy

Board-level memory budgets are declared as `MEMORY_LAYOUT` constants in
the target implementation files:

- `kernel/core/src/core/target/mps2_an385.rs`
- `kernel/core/src/core/target/olimex_stm32_h405.rs`
- `kernel/core/src/core/target/b_l475e_iot01a.rs`
- `kernel/core/src/core/target/raspi_pico.rs`

The core runtime consumes these constants directly. `xtask` reads the same
constants from the target source files for host-side diagnostics, so
heap/stack sizing and layout validation share the same target values.

Each entry defines:

- RAM base and size;
- FLASH base and size;
- minimum kernel heap size;
- kernel stack size.

`xtask` generates the native ELF and bootable FAE board linker wrappers from
`MEMORY_LAYOUT`, then includes the shared generic Cortex-M linker scripts under
`kernel/native/generic-cortex-m/link.ld` and
`kernel/bootable/generic-cortex-m/link.ld`. Both generated layouts place the
kernel stack first, then a 32-byte boot ABI slot, then the firmware RAM window.
The kernel heap is not a fixed linker section anymore; it is carved from the
remaining RAM at runtime.

When changing RAM, FLASH, or `kernel_stack_size`, update only the board
`MEMORY_LAYOUT`. The generated linker wrapper will carry the corresponding
`PROVIDE(__STACK_SIZE_CPU0 = ...)`, `RAM`, and `FLASH` values. If those values
were ever to diverge, the kernel and startup code would disagree on the boot
ABI address, and early SVC forwarding could fail before the kernel syscall
table is initialized. The host-side `xtask` test suite checks every known board
against its generated linker wrappers; run `cargo test -p xtask --lib` after
changing a target memory layout.

Test commands that accept `--check_stack` derive a complete manifest from the
selected source manifest, add both `kernel-stack-monitor` and
`rustlet-stack-monitor`, and write the resulting input under
`target/xtask/generated-configs`. The firmware is then built through the normal
manifest path; no module-selection environment override is involved. The same
observer runs over QEMU and OpenOCD transports.

The kernel monitor initialization hook paints the unused privileged stack
before the main loop, its post-APDU hook records the maximum consumed height,
and its APDU filter exposes that value. The command fails above the smaller of
the target's declared stack size and the 6144-byte project budget, or if no
kernel measurement can be obtained. This applies to the
Rustlet campaigns and the dedicated SCP11 and Rustlet-backed SCP03 Security
Domain campaigns; the floor is a regression budget, not a target to consume.

The monitor query is the debug-only `GET DATA DF71` command. When that module
is selected, its secure-channel observation hook lets the probe observe an
active SCP11 session without treating it as the clear application command
that would normally abort that session. The exception and measurement code
are absent from images that do not select the module.

The `rustlet-stack-monitor` module paints the selected Rustlet stack
window immediately before userland entry, records its high-water mark after
return or fault recovery, and exposes the maximum through `GET DATA DF72`.
When the campaign executes a Rustlet, `--check_stack` reports this second
measurement as well. These diagnostics are independent from mandatory
MSPLIM/PSPLIM and MPU guard policy: those mechanisms bound a stack, while the
modules measure its observed use.

The same command also compares the observed high-watermark checkpoints against
the versioned references in
[`xtask/stack-baselines.toml`](../xtask/stack-baselines.toml). A checkpoint is
recorded only when one tested functionality raises the consumed-stack maximum;
later labels on the same plateau are not duplicated. Baselines are qualified by
command, board, image format, execution environment, optional Rustlet scenario,
and monitor profile.
The current baseline file contains only `apdu-observer-v2` campaigns. The
profile remains part of the identity so differently instrumented binaries
cannot accidentally be compared if another profile is introduced later.

The comparison policy is intentionally asymmetric:

- `--check_stack` fails when a known checkpoint grows or when a new checkpoint
  exceeds the previous campaign maximum;
- `--check_stack` reports a lower height as a gain without rewriting the
  reference;
- when no matching baseline exists, `--check_stack` warns and still applies
  the absolute stack budget, but does not fail merely because the reference is
  missing;
- `--update_stack_baseline` deliberately does not compare against the previous
  reference. It validates the measurement and absolute budget, then replaces
  the campaign with the new checkpoints and measured `HEAD` commit. Reviewing
  that change is the explicit act of accepting an increase or decrease;
- baseline updates require a clean tracked worktree, so the recorded commit
  identifies the exact measured sources.

The target catalogue distinguishes maturity from the validated runner:

- `mps2-an385`: `Rustlet`, with QEMU validation;
- `olimex-stm32-h405`: `Rustlet`, with QEMU validation;
- `raspi-pico1`: `Rustlet`, with QEMU validation and a persistent flash
  oracle;
- `raspi-pico2`: `KernelApdu` on physical hardware; QEMU support is not
  currently claimed;
- `b-l475e-iot01a`: `BuildOnly`, with no execution runner currently claimed.

Consequently, `cargo run test rustlet_all` without a board runs every target
whose level is `Rustlet` and whose `qemu_support` flag is true. Supplying a
board runs that one functional QEMU target explicitly.

Use this command before running expensive QEMU campaigns:

```bash
cargo run dump_kernel_layout --fae mps2-an385 minimal
cargo run dump_kernel_layout --elf mps2-an385 minimal
```

It prints either the packaged FAE footer or the ELF allocated-section
footprint, the kernel stack, the effective firmware RAM footprint, the
derived kernel heap metadata/heap partition, embedded Rustlet FAE sizes,
and explicit overflow diagnostics when the image exceeds the selected
board's memory budget.

The same report is used by `xtask` as a post-packaging build gate. Bootable
firmware generation validates the final FAE against the selected target
before writing a fresh stamp or reusing a cached image. If the image does
not fit, generation fails with the full layout report instead of allowing a
later QEMU or hardware boot crash.

### Kernel RAM layout

The current kernel RAM layout is deliberately linear and target-driven:

```text
RAM base
  [ kernel stack ]
  [ boot ABI, 32 bytes ]
  [ firmware FAE RAM: GOT + ROM-RAM + RAM ]
  [ kernel allocator metadata ]
  [ kernel heap ]
RAM end
```

The stack is placed at the beginning of RAM. This makes stack underflow
diagnostics simpler on Cortex-M targets: the MPU guard can protect the
large address window immediately below RAM instead of consuming an
additional in-RAM guard slot.

The boot ABI is a tiny fixed region used by the boot/startup code to pass
exception and periodic-timer forwarding hooks to the loaded firmware. It is intentionally
outside the shared Rustlet ABI region. It belongs to the bootable kernel
image layout, not to one selected Rustlet.

The FAE RAM window starts immediately after the boot ABI. Its effective
runtime footprint is not just the footer `ram` field. The loader must also
reserve RAM for:

- relocated GOT data;
- ROM data copied into RAM;
- normal writable RAM.

`xtask` therefore validates the FAE footprint as `got + rom.ram + ram`.
This is the same budget the runtime startup path consumes.

The kernel heap starts after the FAE runtime footprint, but its metadata
also needs RAM. This creates a small fixed-point problem: the metadata size
depends on the heap it describes, while the heap starts after the metadata.
The allocator solves this by deterministic convergence:

1. align the first free byte after the FAE RAM footprint;
2. reserve a candidate metadata size;
3. place the heap after that candidate metadata block;
4. compute the exact metadata size needed for that heap window;
5. repeat until the reserved metadata block covers the required size.

The stopping condition is:

```text
required_metadata_len <= reserved_metadata_len
```

This is intentionally not strict equality. Moving the heap start can change
the virtual buddy-tree alignment, so exact equality can oscillate. The
kernel only needs the reserved metadata window to be large enough for the
heap it will manage.

The same partitioning algorithm exists in two places:

- `kernel/core/src/core/allocator.rs`, used by the kernel at boot;
- `xtask/src/lib.rs`, used by host-side image validation and layout dumps.

Keep these two implementations behaviorally identical. If they diverge,
the build report can claim an image is valid while the kernel fails to
initialize its heap, or the reverse.

Example minimal `mps2-an385` shape:

```text
kernel stack       0x20000000..0x20002c00 11 KiB
boot ABI           0x20002c00..0x20002c20 32 B
FAE runtime window 0x20002c20..0x20005db0 12688 B
kernel heap meta   0x20005db0..0x200061b0 1 KiB
kernel heap        0x200061b0..0x20008000 7760 B
kernel heap min    6 KiB
```

### Region packing

`oxi_core::core::isolation` currently packs executable text and keeps writable
RAM in one allocator-aligned MPU region:

- flash text starts from 2 KiB units and merges aligned adjacent units into
  larger power-of-two regions;
- one power-of-two RW/XN region covers the complete Rustlet RAM block;
- the first 2 KiB of that block are the downward-growing execution stack;
- relocated data and heap occupy the remainder immediately above the stack;
- one 512-byte gate region in MPU region 0.

The application budget is currently:

- MPU region 0 for the shared ABI / app-entry gate;
- MPU regions 1 through 6 for Rustlet text/RAM/stack while Rustlet code runs;
- MPU region 6 recycled for kernel RAM execute-never protection while kernel
  code runs, when the selected target can express the protected RAM window as
  one MPU region;
- MPU region 7 reserved for the kernel stack-overflow guard.

If the Rustlet does not fit, loading fails. The isolation planner returns a
structured diagnostic containing the required and available region counts,
plus the original text/RAM windows and each window's slot contribution, rather
than crashing.

### Execute-never phase transitions

Rustlet text is executable only while the processor is running the
unprivileged Rustlet thread. The isolation layer keeps one immutable MPU plan
per loaded Rustlet, then varies only the `XN` bit of its text regions:

- before entering the Rustlet thread, its text regions are restored to
  read-only executable mappings;
- on every Rustlet-originated SVC or recoverable MemManage entry, the
  trampoline reprograms those same regions as read-only execute-never before
  dispatching any Rust kernel code;
- a syscall that resumes the Rustlet restores execution immediately before
  exception return;
- `exit`, panic, fault recovery, and normal completion keep the text regions
  execute-never while control returns to the kernel;
- after the session ends, the last Rustlet text mapping remains explicitly
  read-only and execute-never rather than falling back to the privileged
  default map.

This transition consumes no additional MPU region. It is invoked directly by
the exception trampolines before their Rust dispatchers and reads only a compact
bitmask of the active text-region numbers; it never copies the complete
isolation plan onto the kernel stack. On `mps2-an385`, the measured high-water
mark cost is four bytes on the current global and Rustlet Security Domain
campaigns.

The kernel also recycles the last MPU region slots for phase-dependent RAM
execute-never mappings. When the selected target exposes representable mutable
RAM windows, those slots are enabled as `Privileged RW + XN` while the kernel is
running. Immediately before entering unprivileged Rustlet code, the isolation
layer disables those kernel mappings and restores any overwritten Rustlet
text/RAM mappings if the active Rustlet plan uses them. This prevents kernel
control-flow bugs from branching into RAM data such as Rustlet stacks, Rustlet
heap/data blocks, registry state, APDU buffers, or other mutable kernel data
without permanently reducing the Rustlet MPU budget.

On ordinary strict-power-of-two targets such as `mps2-an385`, one recycled
region covers the complete RAM window. Pico splits its low mutable RAM into two
strict MPU windows, 32 KiB plus 16 KiB, while `.critical.kernel.fct` is placed
outside those windows in SRAM for XIP-performance and flash-safety reasons. The
`cargo run test kernel_ram_nx <board>` regression validates the positive case by
attempting to execute a RAM-resident instruction while the kernel is active; a
supported target must fault before that instruction returns.

MPU region 7 is deliberately not recycled in the same way. It remains the
kernel stack guard because exception and fault entry can return to privileged
code through MSP at any point during Rustlet execution.

The current vector tables do not install recoverable external IRQ or SysTick
handlers while a Rustlet runs. Any future interrupt path that returns to a
Rustlet must join this same XN/X transition protocol. On ARMv6-M targets such
as Pico, recoverable Rustlet MPU faults are routed through HardFault because
there is no separate MemManage exception; fatal HardFaults remain
bootstrap-owned reporting paths.

### Heap allocation

Heap allocation is handled by the buddy/pruning allocator in
`kernel/core/src/core/allocator.rs`. The same allocator implementation backs both
the kernel heap and each Rustlet heap, but the backing storage is different
for each case.

The allocator works with two separate regions:

- a heap region that stores user data;
- a metadata region that stores the buddy tree outside the managed heap.

Important invariants:

- allocator metadata is never stored inside the heap it manages;
- heap corruption may damage user data, but should not directly corrupt
  allocator bookkeeping;
- every allocation is rounded up to an integer number of 8-byte granules;
- every supported alignment must be a power-of-two multiple of 8;
- deallocation relies on the `Layout` passed back by Rust, so the
  allocator does not write per-allocation headers into the heap.

The tree is virtual and may be larger than the physical heap. Nodes outside
the physical heap window are pruned and marked unavailable. This allows the
allocator to support non-power-of-two heap sizes and heap bases that are
only granule-aligned.

This matters for the kernel/Rustlet split:

- the kernel heap metadata is placed in the free RAM tail immediately
  before the kernel heap;
- each Rustlet heap bytes live in the Rustlet RAM allocation;
- each Rustlet allocator metadata block lives in kernel-owned
  selected-application state;
- the kernel resets and selects that allocator state before entering a
  Rustlet handler.

### Gate region

The gate region is the first MPU region mapped for the Rustlet.

It contains:

- the shared APDU ABI buffer;
- the RAM entry gate;
- the RAM return gate.

Important security rule:

- those gates execute on behalf of the Rustlet, not with kernel rights.

Current limitation:

- the whole gate region is still mapped `RW + X` for the Rustlet,
  because the current generic MPU facade cannot yet express a finer
  split between the ABI buffer and the trampolines.

The entry trampoline is rewritten before every Rustlet entry. A Rustlet may
therefore corrupt its own current gate, but it cannot persistently alter the
gate used by a later Rustlet.

## Shared ABI

`rustlets/rustlet_runtime` defines the kernel/Rustlet ABI.

The current ABI is intentionally smaller than the earlier
`SelectionContext` / `ApduCommand` / `ApduResponse` model.

Today the important shared types are:

- `ABI_VERSION`;
- `RustletApduHeader`;
- `RustletCtx`;
- `ApduStatus`;
- `RustletHeapRegion`;
- `SelectedAppVtable`;
- `SelectedAppDescriptor`.

### `RustletCtx`

The current shared APDU contract is centered on one fixed-size
`RustletCtx`. Its binary layout is part of the kernel/Rustlet ABI and must not
be changed casually.

The shared page is exactly 512 bytes:

- bytes `0x000..0x100`: control/secondary buffer;
- bytes `0x100..0x200`: APDU payload buffer.

The control/secondary half contains:

- `abi_version`;
- five command/status bytes, interpreted as `CLA INS P1 P2 P3` on entry and
  `SW1 SW2 00 00 00` on return;
- flags;
- one short-APDU data-length byte;
- one serialized-state length byte;
- 244 bytes of serialized-state storage.

The APDU payload half is physically 256 bytes long, but the useful payload
limit is 255 bytes in this ABI version because the length field is one byte.
Do not treat the physical 256-byte reservation as an extended-APDU mechanism.

Its semantics are:

- before `set_outgoing()`, the payload is the incoming command data;
- after `set_outgoing()`, the same payload buffer becomes the outgoing
  response area;
- at the end of execution, the Rustlet writes its status word into
  `SW1/SW2`.

The shared payload is modeled as one directional `RustletCtx` buffer rather
than separate `ApduCommand` and `ApduResponse` structures.

The control/secondary half also has a kernel-side implementation role. Before
entering a Rustlet, secure-channel or dispatch code may use that half as an
explicit scratch area for bounded APDU-sized transformations. The invariant is
strict: every Rustlet entry path must reset and reinitialize the control half
before user code observes it. This prevents decrypted data, MAC material,
serialized state, or stale status bytes from leaking across calls.

### Zero-copy ownership rules

Zero-copy in this kernel is primarily a stack- and RAM-usage rule. It does not
mean that every type owns a different payload array, and it does not forbid a
copy when an algorithm genuinely requires stable, non-overlapping input and
output.

The firmware APDU path has one physical 256-byte payload store. It is the APDU
half of the gate-region `RustletCtx`:

- `TransportApdu` owns the T=0 session metadata, but its payload pointer refers
  to that shared store;
- `ApduCommand`, `Apdu`, and `RunningSEApdu` are temporary views over the same
  command and must not retain payload slices after the current operation;
- the active Rustlet receives that same store as `RustletCtx::data`;
- the incoming-to-outgoing transition changes the logical meaning and length
  of the bytes; it does not allocate a response buffer.

The bridge helpers are alias-aware. Staging an already received command only
publishes its header and length when the source is the shared APDU store.
Likewise, returning a Rustlet response updates the transport's outgoing state
without copying when source and destination are the same store.

A T=0 response deferred through `61xx` remains in that store until the final
`GET RESPONSE` chunk is sent; `PendingResponse` contains only offset, length,
and completion status. Secure-channel establishment follows the same rule for
a Rustlet-backed Security Domain: SDDISPATCH publishes its response directly
in the shared payload and returns only its length. Native Security Domains use
the explicit auxiliary scratch and copy once into the payload because they do
not execute through the shared Rustlet ABI.

The first 256-byte half of `RustletCtx` has two mutually exclusive roles:

- while kernel protocol code is running, it may be borrowed as bounded
  secondary scratch;
- immediately before Rustlet entry, it contains only the initialized ABI
  control fields and the selected instance's serialized state.

No Rustlet entry may occur while kernel scratch data remains in that half.
`SharedRustletCtx::stage_state_from_registry()` is the mandatory ownership
transition: it clears the complete control half, restores `ABI_VERSION`, then
copies only the selected object's current serialized state. The APDU payload
length is published only after the payload is valid. Unused APDU-tail bytes are
zeroed before entry. Normal T=0 completion scrubs the payload store, while
panic, explicit exit, and recovered fault paths scrub the complete shared page.

### Secondary-buffer ownership phases

The secondary half has exactly one logical owner at a time. Its bytes have no
stable meaning outside the current phase:

1. **Kernel transform scratch.** Before a native Security Domain or ordinary
   Rustlet is entered, secure-messaging code may use all 256 bytes as temporary
   plaintext, ciphertext, authenticated Amendment D framing, or another bounded
   APDU transform result. SCP03 authenticates the command header and protected
   APDU as separate slices, so it does not build a second contiguous CMAC input
   there. The final CMAC value uses the dedicated 16-byte MAC scratch.
2. **ABI input.** `stage_state_from_registry()` ends transform ownership,
   clears all 256 bytes, publishes the ABI version, and copies the serialized
   state read from the registry. Command staging then publishes
   `CLA INS P1 P2 P3`, flags, and the incoming APDU length. From this point
   until return, kernel protocol code must not borrow the half as scratch.
3. **Rustlet execution.** The Rustlet reads its deserialization input through
   `state_bytes()`. It may replace those bytes with a new serialized state and
   publish the new state length. The same rule applies to an ordinary Rustlet
   and to a Rustlet Security Domain entered through SDDISPATCH.
4. **Returned state pending publication.** After a normal return, the control
   half contains `SW1/SW2`, response flags and the newly serialized state.
   `save_selected_instance_state()` or
   `save_selected_security_domain_state()` copies the declared state bytes into
   the polymorphic registry, then synchronously publishes the new persistent
   registry image. The control half is the source of that transaction, not the
   Flash page-programming buffer, and must not be reused until the copy
   completes.
5. **Released and scrubbed.** Once returned state has been copied and the
   persistent registry has been published, the serialized-state capacity is
   overwritten. Normal T=0 completion overwrites the shared APDU payload after
   its last response byte, or after the final `GET RESPONSE` chunk for a
   deferred response. For an ordinary Rustlet, the runtime has also destroyed
   the in-memory instance and the kernel overwrites its complete heap; its stack
   is overwritten after the stack observer runs. Abrupt return paths clear the
   complete shared page, so no state or cryptographic intermediate is accepted
   from a failed Rustlet call.

For a Rustlet Security Domain, “serialized state” excludes the active SCP
session. Derived keys, expected cryptograms, receipts, MAC chains, counters,
and staged handshake bytes live in a `#[serde(skip)]` field of the loaded
Rustlet value. They remain available across consecutive SDDISPATCH calls while
that value is loaded, but they are absent from both the secondary-buffer state
view and the persistent registry. `reset_secure_channel()` explicitly
overwrites that field; unloading is not used as a substitute for zeroization.
The active Rustlet Security Domain remains loaded in its dedicated firmware
slot while an ordinary selected Rustlet occupies the application slot, so
`unwrap`, application dispatch, and `wrap` share one live volatile session
without registry round-trips.

Rustlet-backed secure-channel operations need one additional constraint:
SDDISPATCH itself takes ownership of both halves of `RustletCtx`. A slice into
either half cannot survive such a call. Data that must remain stable across
SDDISPATCH therefore lives in the explicitly named static proxy/auxiliary
scratch, never in a stack array and never in the secondary half. SCP11 also
uses the auxiliary scratch when its authenticated input must be contiguous.

### Compile-time ownership with typestate

The firmware represents the preceding ownership phases with the Rust typestate
pattern. Phase markers are zero-sized `PhantomData` parameters and therefore
have no runtime representation:

- secure messaging consumes
  `SecondaryBuffer<SecondaryAvailable>` to obtain
  `SecondaryBuffer<SecondaryCryptoScratch>`, then releases it only after the
  transform result has been consumed;
- a Rustlet handler call consumes
  `SharedRustletCall<AbiInput>`, stages a command to produce
  `SharedRustletCall<AbiReady>`, and obtains
  `SharedRustletCall<ReturnedState>` only after `invoke_app()` returns.

The transaction types are not `Copy` or `Clone`, and each transition consumes
the previous value. Methods exposing cryptographic scratch exist only on the
crypto state; methods reading status or returned serialized state exist only
on the returned-state side. Consequently, safe kernel code cannot pass
serialized Rustlet state to a CMAC transform, inspect returned state before an
invocation, or reuse a transform token after release without an explicit,
reviewable transition.

Typestate does not replace the physical-memory invariants. Constructing the
root `SecondaryAvailable` token still relies on the single-threaded APDU loop
and the rule that only one Rustlet invocation may own the shared page. Raw
pointer construction remains confined to the shared-buffer implementation.
Fault handling must still validate or scrub bytes written by user code. The
purpose of typestate is to make ordering and semantic ownership compiler-
checked once that unique root token has been acquired.

Long-lived secure-channel session material belongs to the selected Security
Domain's session state. Temporary secure-messaging values belong to explicit,
APDU-bounded kernel scratch storage whose lifetime ends before another
transformation or Rustlet-SD dispatch can reuse the shared page. In particular:

- do not place APDU-sized arrays in a kernel stack frame;
- do not retain a slice into the shared page across a call that can dispatch a
  Rustlet Security Domain;
- if input and output overlap unsafely, use one documented scratch region and
  copy back into the shared APDU store as soon as the transformation completes;
- preserve a management payload only when an authorization hook can republish
  the shared page;
- keep `unsafe` limited to constructing views over the statically reserved gate
  region or single-thread-owned scratch; protocol code should consume ordinary
  bounded slices.

Copies are therefore expected only at explicit ownership boundaries: T=0
pending responses, transforms that cannot safely operate in place, payloads
parked across Rustlet-SD calls, and persistence/registry storage. A new copy on
the hot APDU path should identify which of these lifetimes requires it and must
not be implemented as an APDU-sized local stack array.

### Descriptor boundary

The selected application is still represented through:

- a `repr(C)` descriptor;
- a `repr(C)` vtable;
- explicit kernel trampolines.

It is intentionally **not** represented as a native Rust trait object
across the kernel/application boundary.

That would be incorrect for this design because kernel and FAE are
separate binaries with separate relocation contexts and distinct runtime
state requirements.

Preserve this rule while evolving the ABI.

## Selected-Application Dispatch

Once a Rustlet is selected, later APDUs are routed through
`kernel/firmware/src/selected_app.rs`.

The current dispatch rule is:

- `INS = E6` routes to `install`;
- every other command routes to `process_apdu`.

Before the call, the kernel stages the logical APDU into the shared
`RustletCtx`. If the command arrived through secure messaging, the
`SecureChannelLayer` has already verified and unwrapped it; selected-app code
does not parse the external payload-and-MAC framing itself.

After the call, the kernel:

- reads `SW1/SW2` from the shared buffer;
- publishes the outgoing length in the transport-owned APDU session; the
  alias-aware bridge copies bytes only if a non-shared backing is used;
- lets `SecureChannelLayer` protect the response data, append R-MAC when
  required, and authenticate the actual status word if the command was protected;
- resumes the normal `T=0` completion path.

This is an ownership boundary, not normally a payload-copy boundary:

- the transport session and T=0 state remain kernel-owned;
- the firmware transport payload and `RustletCtx::data` normally alias the
  same gate-region storage;
- host-based unit tests may use independent backing storage, so bridge helpers
  retain an alias-aware copy fallback.

The current object composition around one command is therefore:

1. `ApduLayer` yields one `ApduCommand`;
2. the dispatcher derives one kernel-side `Apdu` view from that command;
3. the selected-app bridge may derive one `RunningSEApdu` view while a
   Rustlet call is active;
4. Rustlet code sees the shared `RustletCtx` through the common
   `SEApdu` trait;
5. command completion returns through one `ApduCompletion`.

The kernel has three distinct APDU-facing object families:

- transport-owned session state (`TransportApdu`);
- APDU-layer command/completion objects (`ApduCommand`,
  `ApduCompletion`);
- card-side command-processing views (`Apdu`, `RunningSEApdu`,
  `RustletCtx` through `SEApdu`).

Keep these roles distinct when extending the code.

## Exit and Fault Handling

Application exits are centralized in `oxi_core::core::isolation`.

The main exit classes are:

- normal handler return through the runtime `handler_return` syscall;
- explicit `exit(sw1, sw2)`;
- `panic`;
- recoverable `MemManage` faults.

The current flow is:

1. the target backend captures the machine event (`SVC` or
   `MemManage`);
2. `core::isolation` computes the kernel-visible return semantics;
3. an optional kernel-side observer is notified;
4. the target backend resumes the kernel through the common resume path.

Normal handler return, explicit exit, and panic all use the single
`RETURN_TO_KERNEL` runtime syscall. Its return-kind argument distinguishes a
normal completion from an early exit; there is no separate exit syscall or
second kernel handler.

`kernel/firmware/src/selected_app.rs` observes those exit events and:

- drain and discard an unread T=0 incoming phase after advertising the
  procedure byte;
- complete an already-started T=0 outgoing phase with zero bytes;
- clear the complete shared `RustletCtx` page after explicit exit, panic, or
  recoverable fault;
- log memory-fault diagnostics;
- keep APDU completion policy in the kernel.

These rules are deliberately independent of Rustlet behavior. An interrupted
Rustlet cannot leave unread transport bytes or command, response, status, and
serialized-state bytes in the shared page for the next invocation. Normal
handler returns keep the page only until the kernel has consumed the response
and persisted the instance state.

Fatal `MemManage` cases still shut the system down explicitly instead of
trying to recover through an inconsistent exception state.

## Syscall and Allocator Integration

The Rustlet-facing syscall numbers live in
`rustlets/rustlet_runtime::syscall_abi`.

On the kernel side:

- `oxi_core::core::syscall` owns the registration table and builtin
  bindings;
- the selected CPU profile owns the `SVC` trap and machine dispatch, sharing
  the Mainline implementation between ARMv7-M and ARMv8-M;
- `core::isolation` installs the runtime hooks needed for `handler_return`
  and mediated Rustlet exit handling.

The current builtin syscall set includes:

- enter application mode;
- Rustlet handler return / explicit exit;
- heap allocate;
- heap deallocate.

APDU-specific syscalls are registered by `kernel/firmware/src/selected_app.rs`
from the same shared ABI constants.

The allocator state used by a Rustlet is selected by the kernel before
entering that Rustlet handler.

Important current invariant:

- Rustlet allocator metadata is kernel-owned selected-app state, while the
  Rustlet heap bytes remain inside the Rustlet RAM allocation.

## Kernel-Local Application Path

`KernelAppModule` is the common abstraction for optional privileged extensions
that are statically linked into one kernel image. It is intentionally separate
from the Rustlet ABI: modules run in privileged mode, belong to the TCB, and
are selected only when a new kernel image is built.

The trait currently requires one boot-phase entry point:

```rust
pub(crate) trait KernelAppModule {
    fn initialize();
}
```

`initialize()` runs after core initialization and before the main APDU loop.
It is not a reset handler. Event integration is explicit and typed rather than
represented by optional trait methods. The generated image contains distinct
slices for:

- module initializers;
- APDU filters;
- post-APDU observers;
- pre- and post-Rustlet hooks;
- clear-command secure-session preservation predicates.

Keeping a slice per hook means a module that does not implement an event adds
no default call to that event path. It also keeps filter contracts separate
from observer contracts. APDU filters expose a read-only recognition function
and a processing function; recognition order is exactly the module order in
the TOML.

For example:

```toml
[kernel-image]
mode = "kernel-only"
kernel-app-modules = ["ping", "t0-test"]
```

maps `ping` directly to
`kernel/firmware/src/kernel_main_app/ping.rs` and `t0-test` to
`kernel/firmware/src/kernel_main_app/t0_test.rs` through
`kernel_app_modules_registry.inc.rs`. The build script rejects any name absent
from that registry and generates slices in the declared order.

To add a module:

1. create its source file under `kernel/firmware/src/kernel_main_app/`;
2. implement `KernelAppModule` explicitly and define only the hook functions
   it actually needs;
3. add one name/module/path/hook declaration to
   `kernel_app_modules_registry.inc.rs`;
4. select the name in the relevant image manifests.

Neither `xtask`, the central dispatcher, nor a list of per-module `cfg` names
needs another edit. The current registry includes `ping`, `t0-test`,
`crypto-self-test`, `flash-probe`, `registry-test`, `kernel-stack-monitor`, and
`rustlet-stack-monitor`.

## Current Limitations

Several limits are still intentional at this stage:

- only one selected Rustlet context is modeled at a time;
- the kernel-managed object registry is still fixed-capacity in RAM, even when
  it is recovered from and published back to persistent flash;
- the transport loop still owns deferred response and `GET RESPONSE`;
- the Rustlet MPU packing strategy is intentionally simple rather than
  optimal;
- the gate region is still `RW + X` rather than split more finely;
- the ABI remains fixed-size and buffer-oriented.

## Practical Rules for Kernel Work

When extending this area, keep the following rules in mind.

- Do not move `SELECT` ownership out of the kernel.
- Do not move `GET RESPONSE` ownership out of the transport loop.
- Do not replace the ABI boundary with a native Rust trait object.
- Do not rewrite the XiPFS startup path just to simplify the current
  Rustlet activation model.
- Treat the kernel/Rustlet boundary as a real ABI boundary: version it,
  validate it, and keep it explicit.
- Keep the transport hot path in `kernel/firmware/src/main.rs` short and free
  of unrelated work.
- Keep byte I/O concerns in `TransportLayer`, not in protocol wrappers.
- Keep `T=0` completion rules in `T0ApduManager`, not in the dispatcher.
- Add future secure-messaging or tracing features as `ApduLayer`
  wrappers, not as ad-hoc branches inside `main.rs`.
- Keep SCP03 and SCP11 profile differences behind `SecurityDomainSecureChannel`
  and the shared `SecureChannelLayer`; do not add one APDU wrapper per SCP
  profile unless the APDU boundary itself genuinely changes.
- Do not leak `TransportApdu` back across the `ApduLayer` boundary.
- Do not stage protected or clear APDU payload mirrors on the kernel stack;
  use the transport APDU buffer and explicit bounded scratch regions.
- Keep each `KernelAppModule` local to one source file and declare only its
  real hooks in the central registry.
- Treat TOML module order as executable priority, especially for filters.
- Do not add dynamic registration or mutable hook tables to this path.
- Treat the gate region as a security-sensitive object, even though its
  current protection is still a draft compromise.

## Work Tracking

Keep open work in [`TODO.md`](TODO.md). Do not add local TODO lists to this
guide; it should describe the current architecture, invariants, and supported
workflows.
