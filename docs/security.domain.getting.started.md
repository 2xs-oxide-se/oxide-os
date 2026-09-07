# Security Domain Getting Started

This tutorial builds and validates a Rustlet-backed Security Domain. The
kernel image deliberately contains no native secure-channel protocol: the
Rustlet Security Domain advertises, establishes, and operates SCP03 itself.

Before starting, you should know how to build Rust `no_std` code and how to use
Oxide SE. If necessary, first follow
[getting-started.md](getting-started.md)
and
[rustlets.getting.started.md](rustlets.getting.started.md).

## 1. Understand The Two Roles

A Rustlet Security Domain has two entry paths:

- `Rustlet::process_apdu()` handles ordinary APDUs when the instance itself is
  selected.
- `RustletSecurityDomain` supplies management policy, discovery data,
  secure-channel establishment, and protected-APDU transforms when the kernel
  invokes the instance as an administrative authority.

The kernel still owns APDU transport, registry mutation, object ancestry,
lifecycle checks, and the three-byte base privilege field. The Rustlet
Security Domain may reject an operation allowed by those checks, but cannot
weaken them.

## 2. Create A Working Security Domain

The smallest example is
[simple_security_domain](../rustlets/simple_security_domain).
Create a separate working crate so the reference examples remain unchanged:

```bash
mkdir -p rustlets/my_security_domain/.cargo
mkdir -p rustlets/my_security_domain/src
mkdir -p rustlets/my_security_domain/xtask/src
cp rustlets/simple_security_domain/.cargo/config.toml rustlets/my_security_domain/.cargo/
cp rustlets/simple_security_domain/Cargo.toml rustlets/my_security_domain/
cp rustlets/simple_security_domain/src/main.rs rustlets/my_security_domain/src/
cp rustlets/simple_security_domain/xtask/Cargo.toml rustlets/my_security_domain/xtask/
cp rustlets/simple_security_domain/xtask/src/main.rs rustlets/my_security_domain/xtask/src/
```

Change the package names in the two copied `Cargo.toml` files to
`my_security_domain` and `my_security_domain_xtask`. The essential source form
is:

```rust
#![no_std]
#![no_main]

use rustlet_runtime::{
    declare_security_domain, Apdu, ApduStatus, Rustlet, RustletCtx,
    RustletSecurityDomain,
};

declare_security_domain!(SimpleSecurityDomain);

#[derive(
    Default,
    rustlet_runtime::serde::Serialize,
    rustlet_runtime::serde::Deserialize,
)]
#[serde(crate = "rustlet_runtime::serde")]
struct SimpleSecurityDomain;

impl Rustlet for SimpleSecurityDomain {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);
        if apdu.is_select() {
            return self.handle_select(apdu);
        }
        apdu.reject(ApduStatus::instruction_not_supported())
    }
}

impl RustletSecurityDomain for SimpleSecurityDomain {}
```

The empty `RustletSecurityDomain` implementation is intentional. Runtime
defaults reject secure-channel establishment and advertise no SCP, while still
providing conservative management-policy behavior.

Build this neutral starting point:

```bash
cd rustlets/my_security_domain
cargo build-fae
cd ../..
```

The first checkpoint succeeds when this file exists:

```text
rustlets/my_security_domain/build/my_security_domain.fae
```

At this stage the FAE is a valid Security Domain application, but it advertises
no SCP and rejects every establishment command. That is the secure default from
which the rest of the exercise proceeds.

## 3. Configure A Kernel With No Native SCP

Create a working build manifest from the validated delegated-SCP03 profile:

```bash
cp configs/config_rustlet_security_domain_delegated_scp03_test.toml \
  configs/config_my_security_domain.toml
```

In the copied file, replace:

```toml
path = "./rustlets/complete_security_domain"
```

with:

```toml
path = "./rustlets/my_security_domain"
```

Keep the package AID, instance AID, installation bytes, static SCP03 keys and
`protocols = []` unchanged. The complete resulting structure can always be
compared with
[config_rustlet_security_domain_delegated_scp03_test.toml](../configs/config_rustlet_security_domain_delegated_scp03_test.toml).

`protocols = []` means that the kernel contains no SCP03 or SCP11
establishment profile. The root package is nevertheless a Security Domain
Rustlet, and its instance receives the kernel-owned base privileges from the
first three installation bytes.

The same manifest provisions the SCP03 static ENC and MAC keys as registry
objects owned by that root Security Domain. The Rustlet obtains them through
the restricted Security Domain runtime interface; it does not rely on hidden
kernel fallback keys.

Build the configured kernel:

```bash
cargo run build \
  --config configs/config_my_security_domain.toml \
  mps2-an385
```

The resulting bootable image is:

```text
target/kernel/firmware/kernel.elf
```

The expected image advertises no kernel-native SCP in its firmware capability
bitmap. SCP03 will become visible only after the predeployed Rustlet Security
Domain is selected and queried.

## 4. Start The Neutral Security Domain

Start the generated image in one terminal:

```bash
qemu-system-arm \
  -machine mps2-an385 \
  -nographic \
  -monitor none \
  -serial tcp:127.0.0.1:4444,server=on,wait=on \
  -semihosting-config enable=on,target=native \
  -kernel target/kernel/firmware/kernel.elf
```

Select your root Security Domain from a second terminal:

```bash
cargo run -p apdu_tool -- \
  00 A4 04 00 08 00 A0 00 00 47 50 4F 53 04
```

The expected status is `9000`. Querying optional Card Capability Information
at this neutral checkpoint must report that the object is unavailable:

```bash
cargo run -p apdu_tool -- 80 CA 00 67 00 00
```

The expected status is `6A88`. Stop QEMU before rebuilding the next checkpoint.
This proves that the empty trait implementation does not accidentally inherit
SCP support from the kernel.

## 5. Discover The Selected Security Domain

Before attempting a handshake, a GP host can discover the selected authority:

```text
80 CA 00 66 00
```

`GET DATA 0066` returns Card Recognition Data. Its `73` template contains one
or more `64` templates whose OIDs identify the SCP and option byte `i`.

```text
80 CA 00 67 00
```

`GET DATA 0067` returns optional Card Capability Information, including
supported SCP options, key types, privilege width, and the load-file hash
algorithm. A Security Domain with no advertised protocol returns `6A88`.

```text
80 F2 80 02 02 4F 00 00
```

`GET STATUS` asks for the Issuer Security Domain in modern TLV form. Its `E3`
record includes the root AID, lifecycle, and three-byte privilege field.

These responses describe the selected Security Domain. A Rustlet Security
Domain does not inherit the kernel's protocol advertisement when it reports no
support.

## 6. Implement Delegated SCP03 Incrementally

Add the following blocks to `rustlets/my_security_domain/src/main.rs`. Build
the FAE and kernel again after each numbered checkpoint:

```bash
cd rustlets/my_security_domain
cargo build-fae
cd ../..
cargo run build --config configs/config_my_security_domain.toml mps2-an385
```

The bodies below define the integration boundary. The complete cryptographic
helpers are documented in
[security.domain.developper.guide.md](security.domain.developper.guide.md)
and implemented in the final reference
[main.rs](../rustlets/complete_security_domain/src/main.rs).
Consult that implementation after writing each hook rather than replacing the
exercise with its whole `impl` block.

### 6.1 Advertise The Profiles

Start by reporting SCP03 support:

```rust
fn supports_scp03(&self) -> bool {
    true
}

fn supports_scp03_s8(&self) -> bool {
    true
}

fn supports_scp03_s16(&self) -> bool {
    true
}
```

Restart QEMU, select the same root AID, and issue `GET DATA 0066` and `0067`.
Both responses must now identify SCP03 S8 and S16. If these methods return
`false`, discovery must not claim those profiles even if helper code happens
to be present in the Rustlet binary. This is checkpoint 2.

### 6.2 Claim Only SCP03 Establishment

The kernel has `protocols = []`, so the Rustlet must claim the two SCP03
establishment headers:

```rust
fn claims_delegated_secure_channel_command(
    &self,
    header: DelegatedSecureChannelHeader,
) -> bool {
    matches!(
        (header.cla, header.ins, header.p2),
        (0x80, 0x50, _) | (0x84, 0x82, 0x00)
    )
}
```

The claim receives only the header. The APDU payload remains untouched until
the Rustlet returns `true`. Do not use a broad claim such as “every
`CLA=80/84` command”: it would steal unrelated GP establishment commands.

Rebuild after adding the claim. The final campaign introduced in Section 7
must now pass header ownership and reach `initialize_update()`; it is expected
to stop at establishment until the next checkpoint is implemented.

### 6.3 Establish The Session

Implement real session establishment rather than leaving the runtime defaults:

```rust
fn initialize_update(
    &mut self,
    ctx: &mut RustletCtx,
    command: &InitializeUpdate<'_>,
    out: &mut [u8],
) -> Result<usize, ApduStatus>;

fn external_authenticate(
    &mut self,
    ctx: &mut RustletCtx,
    command: &ExternalAuthenticate<'_>,
) -> Result<SecurityLevel, ApduStatus>;
```

The runtime's default `handle_delegated_secure_channel_command()` maps
`INS=50` and `INS=82` to these methods. `initialize_update()` uses
`ctx.crypto()` to derive the session keys and writes its response directly to
`out`. `external_authenticate()` verifies the host cryptogram and command MAC
before marking the session open.

Keep this state RAM-only:

```rust
#[derive(Default, Serialize, Deserialize)]
struct MySecurityDomain {
    #[serde(skip)]
    secure_channel: VolatileSecureChannelState,
}
```

The skipped field contains session keys, expected cryptograms, MAC chains,
counters, receipts, and staged handshake data. It survives consecutive calls
while the Security Domain stays loaded, but it is never written into the
registry. `reset_secure_channel()` must still overwrite it immediately:

```rust
fn reset_secure_channel(&mut self) {
    self.secure_channel = VolatileSecureChannelState::default();
}
```

At the end of this step, a valid `INITIALIZE UPDATE` followed by
`EXTERNAL AUTHENTICATE` succeeds. A bad cryptogram or repeated stale
authentication value is rejected and does not open a session. In the dedicated
campaign, the S8 and S16 `INITIALIZE UPDATE` and `EXTERNAL AUTHENTICATE` lines
must pass before the first protected `GET DATA`. This is checkpoint 3.

### 6.4 Transform Protected APDUs

Finally implement:

```rust
fn unwrap_command(
    &mut self,
    ctx: &mut RustletCtx,
    command: &WrappedCommand<'_>,
    out: &mut [u8],
) -> Result<usize, ApduStatus>;

fn wrap_response(
    &mut self,
    ctx: &mut RustletCtx,
    response: &PlainResponse<'_>,
    out: &mut [u8],
) -> Result<usize, ApduStatus>;
```

Verify the complete MAC before publishing clear bytes, update the command chain
only after successful verification, and decrypt directly into `out`. For the
response, encrypt directly into `out`, calculate the response MAC over the
normative GP-DO view, and return the exact valid length. Never retain
`command`, `response`, `out`, or an APDU pointer after the method returns.

The kernel binds a successful delegated session to the exact Security Domain
instance that claimed it. It continues to enforce object ancestry, lifecycle,
base privileges, APDU bounds, and management-family hooks. The Rustlet owns the
unknown protocol's cryptographic state and protocol-specific policy.

After rebuilding, the dedicated campaign must pass protected `GET DATA`, key
rotation, protected installation, replay rejection and selection of the
installed Rustlet. This is checkpoint 4 and completes the implementation
exercise.

## 7. Run The End-To-End Validation

Run the dedicated campaign:

```bash
cargo run test gp_rustlet_security_domain_delegated_scp03 \
  --config configs/config_my_security_domain.toml \
  mps2-an385
```

This single command builds the selected manifest, starts QEMU, and validates:

- Card Recognition Data and Card Capability Information;
- the root `GET STATUS` record;
- delegated SCP03 S8 and S16 establishment;
- protected command and response MACs;
- command and response encryption;
- replay rejection;
- protected management operations under the Rustlet Security Domain.

The command ends with a summary similar to:

```text
RUSTLET-SECURITY-DOMAIN-DELEGATED-SCP03-DONE board=mps2-an385 total=<n>
```

The exact total may evolve as assertions are added; the `DONE` marker and a
zero process status are the stable success criteria.

For the kernel-native comparison, run:

```bash
cargo run test gp_rustlet_security_domain_scp03 mps2-an385
```

In that profile, the kernel recognizes SCP03 before any Rustlet claim. A
compiled kernel protocol always takes precedence over delegated handling.

The repository-owned reference campaign remains available independently:

```bash
cargo run test gp_rustlet_security_domain_delegated_scp03 mps2-an385
```

## 8. Extend The Policy

To create your own Security Domain, copy
[simple_security_domain](../rustlets/simple_security_domain)
and override only the operation families you need:

- `get_data()` for domain-specific discovery or administrative objects;
- `install_for_load()` and `install_for_install()` for deployment policy;
- `delete_aid()`, `put_key()`, `store_data()`, and `set_status()` for
  management authorization;
- secure-channel establishment and messaging hooks for a delegated protocol.

Do not replace the runtime defaults with unconditional acceptance. The proxy
will retain kernel-owned invariants, but the Security Domain remains
responsible for its finer policy and cryptographic state.

> **Congratulations!** You have built a Security Domain Rustlet, embedded it
> as the root administrative authority of a kernel with no native SCP, and
> validated a complete delegated SCP03 session.

The complete API, call flow, buffer ownership rules, and extension boundaries
are described in
[security.domain.developper.guide.md](security.domain.developper.guide.md).
