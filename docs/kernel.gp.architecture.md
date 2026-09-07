# Kernel GlobalPlatform Architecture

This note describes a proposed kernel-side architecture for
GlobalPlatform support in Oxide SE.

It focuses on ownership and layering:

- what the kernel must own directly;
- what a root Security Domain is responsible for;
- how additional Security Domains fit in the model;
- how management APDUs relate to the internal kernel services.

This document is intentionally architectural.

It is not a statement that every part described here is already fully
implemented.

## Scope

In Oxide SE, GlobalPlatform support should not be modeled as a normal
Rustlet parsing management APDUs by itself.

The kernel must remain the owner of:

- the APDU transport loop;
- the APDU registry and instance lookup;
- the current selection state;
- package and instance lifecycle state;
- secure channel state;
- the privileged execution of management operations.

Security Domains are first-class managed entities, but they are
not the low-level APDU router of the platform.

## Core idea

The guiding rule is:

- `SELECT` is kernel-owned;
- GlobalPlatform management commands execute in a Security Domain
  context;
- the kernel provides the actual management engine.

In other words, a Security Domain is an authority and a context, not
the place where the platform stops being system-owned.

## Why GlobalPlatform changes the kernel

Once GlobalPlatform is present, the kernel must expose more than a
single "selected app" slot.

At minimum it must model:

- one selected Security Domain context;
- one selected application context;
- a registry of known package and instance identifiers;
- a management engine executing commands in the authority of the
  selected Security Domain.

This is a stronger model than a bootstrap kernel that only maps
`AID -> embedded FAE bytes -> fresh instance`.

GlobalPlatform implies durable kernel-side concepts:

- package identity;
- applet identity;
- instance identity;
- management authority;
- secure session state;
- lifecycle status.

## Kernel-owned services

The kernel should own the following services directly.

### 1. Registry service

The registry resolves identifiers and stores lifecycle state.

It must at least track:

- package AID;
- applet AID;
- instance AID;
- implementation image or load-file reference;
- whether the instance is selectable;
- whether the instance is a Security Domain;
- whether the instance is the root Security Domain.

This registry is the authoritative source for:

- `SELECT by AID`;
- `INSTALL [for install]`;
- `DELETE`;
- later persistence and deserialization.

### 2. Selection service

The kernel owns application selection.

It must resolve a `SELECT` APDU against the registry and decide:

- whether the target exists;
- whether the target is selectable;
- whether the target is a Security Domain or an application;
- which runtime slot becomes current.

The important rule is:

- the Security Domain does not own the generic `SELECT` lookup path;
- the kernel does.

The selected Security Domain and the selected application are separate
concepts.

There may be no current application selection while a Security Domain
context already exists.

### 3. Management engine

The kernel owns the execution semantics of GlobalPlatform management
commands.

This engine interprets and executes:

- `INITIALIZE UPDATE`;
- `EXTERNAL AUTHENTICATE`;
- `INSTALL [for load]`;
- `LOAD`;
- `INSTALL [for install]`;
- `DELETE`;
- `GET DATA`;
- later `PUT KEY`, `STORE DATA`, and related commands if needed.

The engine executes those commands under a Security Domain context.

This means:

- the selected Security Domain provides authority, privileges, and
  secure channel scope;
- the kernel performs the actual system mutation.

### 4. Secure channel service

Secure messaging belongs to the kernel protocol stack.

It should sit above the base APDU manager and below the management
engine.

Architecturally, the stack should remain:

- `TransportLayer`
- `T0ApduManager`
- `Scp03ApduLayer`
- kernel dispatcher / management engine

Security Domains own keys, trust anchors, and policy.

The kernel owns:

- APDU unwrap and wrap;
- session counters;
- command security level enforcement;
- rejection of unauthenticated management commands.

## Role of the root Security Domain

The root Security Domain is the platform management authority that
exists before any ordinary application lifecycle can happen.

In practical Oxide SE terms, it should be modeled as:

- a privileged managed instance;
- present from system startup;
- known to the kernel by a dedicated registry role;
- available even before ordinary applet installation and persistence are
  complete.

Its responsibilities are:

- act as the default management domain;
- host the initial secure channel endpoint;
- authorize installation and deletion flows;
- answer management queries that belong to the issuer or card manager
  role.

The root Security Domain does not own generic AID lookup.

It is the owner of management authority.

## Role of additional Security Domains

Additional Security Domains can be modeled as ordinary managed
instances with extra privileges.

They should differ from the root Security Domain by policy, not by
special transport rules.

Each non-root Security Domain may own:

- a delegated privilege set;
- a secure channel context;
- a subset of manageable content;
- a local administrative scope.

The kernel should still provide one common management engine.

Different Security Domains then act as different authorities over the
same engine.

## What `SELECT` means in this model

`SELECT` remains a kernel-owned operation.

Its steps are:

1. parse the requested AID;
2. resolve the AID in the kernel registry;
3. determine whether the target is:
   - a Security Domain;
   - an application instance;
4. switch the current selection slot accordingly;
5. invoke the selected target so it may answer the `SELECT` itself.

The final point matters:

- the kernel owns selection routing;
- the selected Rustlet or Security Domain may still generate its own
  FCI response.

That is why a Security Domain may need a real installed instance before
returning a correct `SELECT` response.

## What `INSTALL` means in this model

`INSTALL` is not a normal applet command.

It is a management command executed by the kernel in the context of the
selected Security Domain.

The selected Security Domain does not need to parse and implement the
full system mutation by itself.

Instead, the kernel should expose management operations such as:

- instance creation;
- package association;
- privilege checks;
- state registration.

The Security Domain contributes:

- authorization;
- management context;
- later secure channel state and policy.

The kernel contributes:

- registry mutation;
- allocator and storage decisions;
- runtime activation;
- persistence and recovery once available.

## Security Domain-facing kernel traits

The kernel should not require a Security Domain Rustlet to implement the
full APDU grammar of GlobalPlatform.

Instead, the kernel should expose a small internal trait boundary that
lets a Security Domain contribute:

- authority;
- privileges;
- secure channel state;
- policy decisions;
- management-scoped data.

The kernel should still keep the management engine and the APDU parser.

This matches the observed GlobalPlatform model in secondary references:

- the Card Manager executes card services and exposes them through APDUs
  and an internal API;
- the Issuer Security Domain and additional Security Domains define the
  active authority and secure channel scope;
- the Oracle simulator treats the ISD as the default selected
  management endpoint after startup and gives ISD and SSD instances
  SCP03 capability and management privileges.

The proposed trait surface is also intentionally close to the command
and service split visible in secondary implementation references such as
OpenSCDP's `SecurityDomainCardService`, which exposes methods such as:

- `initializeUpdate`
- `externalAuthenticate`
- `installForInstall`
- `deleteAID`

Those names are useful because they reflect what the management layer
actually needs from a Security Domain context.

### 1. Management engine trait

The first trait should define what the kernel needs from a Security
Domain in order to execute management commands.

A suitable shape is:

```rust
pub trait SecurityDomainManagement {
    fn aid(&self) -> Aid;
    fn is_root_security_domain(&self) -> bool;
    fn privileges(&self) -> SecurityDomainPrivileges;

    fn install_for_load(
        &self,
        command: &InstallForLoadCommand,
    ) -> Result<(), ManagementError>;

    fn install_for_install(
        &self,
        command: &InstallForInstallCommand,
    ) -> Result<(), ManagementError>;

    fn delete_aid(
        &self,
        aid: &Aid,
    ) -> Result<(), ManagementError>;

    fn get_data(
        &self,
        tag: GetDataTag,
        out: &mut [u8]
    ) -> Result<usize, ManagementError>;

    fn may_manage_applet(
        &self,
        package_aid: &Aid,
        applet_aid: &Aid,
        instance_aid: &Aid,
    ) -> bool;

    fn may_make_selectable(&self, instance_aid: &Aid) -> bool;
}
```

The intent is:

- the kernel parses `INSTALL`, `LOAD`, `DELETE`, `GET DATA`, and other
  GP commands;
- the Security Domain trait validates whether the operation is
  authorized in the current management context;
- the kernel performs the actual mutation.

The Security Domain therefore does not own:

- package storage;
- applet instantiation;
- registry mutation;
- deletion side effects.

It owns:

- management authority;
- privilege expression;
- policy checks;
- management-scoped metadata answers.

This matches the practical GP split:

- `INSTALL`, `LOAD`, `DELETE`, and related commands are management
  commands of the Card Manager;
- they execute in the authority of the selected Security Domain.

### 2. Secure channel trait

The second trait should define what the kernel needs from the Security
Domain to run SCP03 or a future secure channel.

A suitable shape is:

```rust
pub trait SecurityDomainSecureChannel {
    fn supports_scp03(&self) -> bool;

    fn initialize_update(
        &mut self,
        command: &InitializeUpdateCommand,
    ) -> Result<InitializeUpdateContext, SecureChannelError>;

    fn external_authenticate(
        &mut self,
        command: &ExternalAuthenticateCommand,
    ) -> Result<SecurityLevel, SecureChannelError>;

    fn current_security_level(&self) -> SecurityLevel;
    fn secure_channel_open(&self) -> bool;

    fn unwrap_command(
        &mut self,
        apdu: &WrappedCommandApdu,
    ) -> Result<UnwrappedCommandApdu, SecureChannelError>;

    fn wrap_response(
        &mut self,
        response: &PlainResponseApdu,
    ) -> Result<WrappedResponseApdu, SecureChannelError>;

    fn reset_secure_channel(&mut self);
}
```

The intent is:

- the kernel owns the SCP03 APDU sequencing and the protocol-layer
  dispatch;
- the Security Domain owns the active keyset, sequence context, and
  security policy;
- the kernel may ask the current Security Domain to derive or validate
  secure channel state, then apply it in `Scp03ApduLayer`.

This matches the reference behavior described by Oracle for the
simulator:

- the ISD implements SCP03;
- SSDs can also implement SCP03;
- secure channel scope belongs to the active Security Domain context.

This also mirrors the operation split used by secondary service
implementations, where `initializeUpdate` and
`externalAuthenticate` are distinct secure-channel entry points.

### 3. One combined trait

In Oxide SE, the most practical shape is probably one combined trait:

```rust
pub trait SecurityDomain:
    SecurityDomainManagement + SecurityDomainSecureChannel
{
}
```

This avoids artificial splitting at call sites while still preserving a
clean conceptual separation in the design.

## What this implies for the current kernel

If Oxide SE adopts the traits above, the current kernel must evolve in
specific ways.

### 1. The kernel must stay the GP engine

The current kernel must not delegate raw GP APDU handling to ordinary
Rustlet `process_apdu()` logic.

Instead it should:

- parse GP APDUs in the kernel;
- resolve the current Security Domain context;
- call the `SecurityDomain` trait for management authorization and
  secure channel state;
- execute lifecycle mutation in the kernel.

This is the largest architectural consequence.

### 2. `SELECT` stays kernel-owned

The current AID resolution path should remain in the kernel registry.

The Security Domain trait should not own:

- generic AID lookup;
- current-instance routing;
- normal application selection.

It should only influence:

- whether the current management context is valid;
- what the selected management authority is;
- what secure channel and management rights are active.

### 3. Two live slots become intentional

The current kernel should move explicitly to:

- one selected Security Domain instance;
- one selected application instance;
- one current selection marker.

This is necessary because:

- management commands target the Security Domain context;
- application commands target the selected applet context;
- both may need to remain alive at the same time.

### 4. `INSTALL` should stop being routed as a normal applet APDU

The current kernel experiments route `INSTALL` toward whichever Rustlet
is acting as the selected Security Domain.

Under the trait model, that must tighten into:

- parse `INSTALL` in the kernel;
- validate through `SecurityDomainManagement::install_for_load()` or
  `SecurityDomainManagement::install_for_install()`;
- create or update instances in kernel-owned state;
- only call into the Security Domain Rustlet for explicit policy hooks,
  not for raw APDU ownership.

### 5. `Scp03ApduLayer` owns the SCP03 boundary

`Scp03ApduLayer` is the kernel protocol consumer of
`SecurityDomainSecureChannel`.

That means:

- the layer remains kernel-owned;
- the selected Security Domain provides the key and session context
  through `initialize_update()` and `external_authenticate()`;
- unwrap and wrap are coordinated by the layer, not by ordinary applet
  code.

The current implementation already routes `INITIALIZE UPDATE` and
`EXTERNAL AUTHENTICATE` through this layer. After authentication, protected
commands are unwrapped by validating their truncated C-MAC before ordinary
dispatch sees the payload. At the encrypted security level, the layer also
decrypts the command payload before dispatch. Protected responses are wrapped
by optionally encrypting the response payload, then appending a truncated
R-MAC.

### 6. Root Security Domain bootstrap becomes a trait-backed context

The root Security Domain needs an early bootstrap path.

Under the proposed trait model, bootstrap should produce:

- a resident root Security Domain instance;
- kernel-visible management privileges;
- an initial secure channel authority.

But bootstrap should not change the ownership rule:

- the kernel still owns selection, registry mutation, and lifecycle
  execution.

## References

Primary product documentation used for the model:

- Oracle Java Card SDK GlobalPlatform overview:
  [docs.oracle.com](https://docs.oracle.com/en/java/javacard/3.2/jcrns/globalplatform.html)
- Oracle simulator supported GP features:
  [docs.oracle.com](https://docs.oracle.com/en/java/javacard/3.2/jcdksu/supported-globalplatform-features.html)

Secondary implementation-oriented references:

- OpenSCDP `SecurityDomainCardService` API:
  [openscdp.org](https://www.openscdp.org/ocf/api/de/cardcontact/opencard/service/globalplatform/SecurityDomainCardService.html)
- GlobalPlatform C library and specification notes:
  [kaoh.github.io](https://kaoh.github.io/globalplatform/globalPlatformSpecification.html)
- GlobalPlatform SourceForge specification summary:
  [sourceforge.net](https://sourceforge.net/p/globalplatform/wiki/GlobalPlatform%20Card%20Specification/)

## Proposed runtime slots

For the current Oxide SE scope, two live slots are enough:

- `selected_security_domain`
- `selected_app`

Those two slots should be independent.

The current selection should be an explicit state:

- none;
- security domain;
- application.

This avoids conflating:

- "there is a root Security Domain resident";
- "the current APDU selection is the root Security Domain";
- "an application is currently selected".

## Proposed internal APIs

The following internal kernel services are the right abstraction
boundary.

### Registry

- `lookup_instance(aid) -> InstanceRef`
- `lookup_install_target(package_aid, applet_aid) -> InstallTargetRef`
- `register_instance(...)`
- `delete_instance(...)`

### Selection

- `select_security_domain(instance_ref)`
- `select_application(instance_ref)`
- `current_selection()`
- `current_security_domain()`
- `current_application()`

### Management engine

- `install_for_install(security_domain, command)`
- `install_for_load(security_domain, command)`
- `load_package(security_domain, block)`
- `delete_object(security_domain, command)`
- `get_data(security_domain, tag)`

### Secure channel

- `initialize_update(security_domain, apdu)`
- `external_authenticate(security_domain, apdu)`
- `secure_channel_state(security_domain)`

## Current Kernel Security Domain Profiles

The kernel currently exposes one selector for the active management authority:

- `NullSecurityDomain`
- `KernelSecurityDomain`

`NullSecurityDomain` is the default profile. It is a no-security bootstrap
authority that authorizes management operations and leaves secure-channel APDUs
unsupported. This keeps Oxide SE usable without requiring a user-space root
Security Domain.

The kernel-native Security Domain is selected with a manifest whose root
backend is `KernelSecurityDomain`, plus an explicit secure-channel protocol
set:

```toml
[secure_channel]
protocols = ["SCP03"]
scp03_profile = "S8"
```

SCP11 is selected as a protocol family with one or more enabled variants:

```toml
[secure_channel]
protocols = ["SCP11"]
scp11_profiles = ["A", "C"]
```

The selected predeployment manifest declares the root Security Domain AID,
which defaults to `A0000047504F5301`.

It is kernel-native, not a Rustlet. It implements the same
`SecurityDomainManagement` and `SecurityDomainSecureChannel` traits as the null
profile, but it also accepts the GP secure-channel entry commands:

- `INITIALIZE UPDATE`
- `EXTERNAL AUTHENTICATE`

At this stage, `KernelSecurityDomain` owns the policy boundary and SCP03
session lifecycle, while `core::scp03` owns the pure cryptographic engine.
The selected SCP03 profile defines the session shape: S8 uses 8-byte
challenges, 8-byte cryptograms, and 8-byte truncated C-MAC/R-MAC values; S16
uses 16-byte challenges, 16-byte cryptograms, and 16-byte C-MAC/R-MAC values.
`INITIALIZE UPDATE` returns a deterministic development card challenge and a
card cryptogram derived from explicit test keys. `EXTERNAL AUTHENTICATE`
verifies the host cryptogram and the mandatory initial C-MAC before opening the
requested security level.
Mutating management operations require the encrypted security level; clear
management APDUs are rejected by the kernel-native profile.

The current secure messaging step covers integrity and a minimal encrypted
transport profile:

- protected commands carry a profile-sized C-MAC at the end of the APDU data field;
- `Scp03ApduLayer` validates that C-MAC, then strips it before dispatching the
  command;
- protected responses append a profile-sized R-MAC computed over response data
  and the final status word.
- the encrypted level decrypts command data before dispatch and encrypts
  response data before R-MAC computation.
- the kernel Security Domain maintains command and response MAC chains plus
  command and response encryption counters for the active session.

The remaining SCP03 secure messaging work is validation against published
GlobalPlatform vectors. The current path is structured and testable, but should
still be treated as pre-certification until the exact GP ICV/chaining details,
key-set handling, and error behavior are cross-checked with reference vectors.

The important architectural invariant is already in place:

- the APDU dispatcher parses GP commands;
- the current Security Domain trait object authorizes or rejects them;
- `NullSecurityDomain` authorizes debug/no-security management;
- `KernelSecurityDomain` requires an encrypted SCP03 session for mutating
  management;
- the kernel performs registry mutation and response staging;
- the global registry stays kernel-owned.

## Interaction with Rustlets

Rustlets should not become the low-level GP engine.

Instead:

- application Rustlets remain focused on applet semantics;
- Security Domain Rustlets represent managed authorities;
- the kernel remains the executor of lifecycle mutation.

This implies that a Security Domain Rustlet may still expose:

- FCI for `SELECT`;
- management-related status reporting;
- policy hooks;
- later delegated services.

But the kernel must still remain the source of truth for:

- instance creation;
- package registration;
- object deletion;
- secure session enforcement.

## Bootstrap implications

The root Security Domain creates a bootstrap problem:

- ordinary managed instances usually appear through installation;
- but management itself requires an authority to exist first.

The kernel therefore needs a bootstrap rule.

One acceptable approach is:

- mark one embedded Rustlet as the root Security Domain;
- instantiate it during startup through a reserved internal install
  path;
- keep it available as the default management authority.

This bootstrap path should stay inside the same conceptual model as
ordinary installation, even if it uses a reserved internal marker.

## Consequences for current Oxide SE code

The following direction is recommended for the current kernel:

- keep registry lookup kernel-owned;
- keep `SELECT` kernel-owned;
- separate the selected Security Domain slot from the selected
  application slot;
- route management APDUs through the selected Security Domain context;
- keep the actual lifecycle mutation kernel-owned;
- later add persistence and deserialization behind the registry.

This gives a clean model:

- the kernel is the GlobalPlatform engine;
- the root Security Domain is the default management authority;
- other Security Domains are delegated authorities;
- applets remain payload applications selected and invoked by the
  runtime.

## Summary

GlobalPlatform support in Oxide SE should not be read as "the Security
Domain owns the platform".

It should be read as:

- the kernel owns the platform;
- Security Domains provide authority and context;
- management commands are executed by the kernel under that authority;
- selection remains a kernel service;
- application execution remains separate from management execution.
