# Oxide SE Critical Component Model

This document records the abstract model used to reason about critical
Oxide SE components. It is not an implementation guide. It defines the
state, operations, failure events, and proof obligations that the
implementation must preserve.

The model covers the architectural properties announced in Chapter 1 of the
manual: APDU transport and dispatch, the GlobalPlatform managed-object model,
Security Domain authority, lifecycle control, the privileged kernel-service
boundary, application isolation, secure-channel processing, key and
cryptographic services, audit traceability, and flash-backed transactional
persistence.

These are specification-level obligations. Their presence here does not, by
itself, claim that every obligation has been mechanically proved or that every
optional mechanism is enabled in every build. Concrete implementation and test
evidence remain separate from the abstract model.

## Hoare Triple Notation

Oxide SE model properties are written as Hoare triples:

```text
{ P }  op(args)  { Q }
```

where:

- `P` is the precondition that must hold before the operation starts.
- `op(args)` is the operation being modeled.
- `Q` is the postcondition that must hold if the operation returns normally.

Informally, the triple says: if `P` is true before executing `op(args)` and
the operation completes without a modeled failure, then `Q` is true
afterwards.

For operations that may fail because of power loss or flash interruption, this
document uses an extended failure-aware form:

```text
{ P }  op(args)  { Qsuccess | F -> Qfailure }
```

where:

- `Qsuccess` is the postcondition when the operation completes normally.
- `F` is a modeled failure event.
- `Qfailure` is the postcondition after reboot/recovery from that failure.

The notation is intentionally lightweight. It is meant to expose invariants
clearly before any mechanized proof effort.

### State Predicates

The following predicates are used throughout the document.

- `ValidBlock(b)`: block `b` has a known magic, a valid aligned total length,
  an in-range extent, and a valid final checksum.
- `ValidRegistry(b)`: `b` is a valid `BOSS` registry block.
- `LatestRegistry(F) = b`: among all valid registry blocks in flash state `F`,
  `b` has the highest mutation counter.
- `ReferencedBy(R, x)`: registry `R` contains an entry whose data reference
  names persistent object block `x`.
- `Protected(F, x)`: block or page range `x` must not be erased because it is
  required to recover the latest committed registry state.
- `Erased(p)`: every byte in flash page `p` is `0xFF`.
- `SectorFreeForErase(F, s, R)`: every page in sector `s` is either erased or
  not protected by latest registry `R`.
- `ObjectPayload(o)`: bytes associated with one registry object.
- `RegistryImage(R)`: serialized representation of registry state `R`.
- `Recover(F)`: registry state reconstructed by scanning flash state `F`.
- `WellFormedApdu(c)`: command `c` has a valid ISO/IEC 7816 representation and
  all declared lengths are consistent with its bytes.
- `KernelCommand(c)`: `c` is a context-defining or platform-management command
  whose semantics remain kernel-owned.
- `Selected(S, a)`: application or Security Domain instance `a` is the selected
  context in system state `S`.
- `Selectable(R, a)`: registry object `a` exists, is an instance or Security
  Domain, and its lifecycle permits selection.
- `Authority(S, sd)`: Security Domain `sd` is the authority for the current
  clear or authenticated command context.
- `DescendantOf(R, x, sd)`: registry object `x` belongs to the administrative
  subtree rooted at Security Domain `sd`.
- `SessionBoundTo(S, sc, sd)`: secure-channel session `sc` is active and bound
  to Security Domain `sd`.
- `Isolated(S, a)`: application `a` can access only its assigned memory,
  instance state, validated APDU view, and explicitly granted services.
- `ValidKeyRef(R, sd, k)`: key reference `k` resolves to a valid key object
  owned by Security Domain `sd` and permitted for the requested operation.
- `Traceable(E, op)`: audit trace `E` contains the security-relevant outcome of
  operation `op` without exposing secret material.

## Global System State

The properties below use the following abstract state:

```text
SystemState = {
  transport_state,
  selected_context,
  registry,
  secure_channel_state,
  application_runtime_state,
  audit_trace
}
```

The registry is the persistent source of truth. Selection, in-flight transport,
secure-channel sessions, and active application execution are volatile unless a
later rule explicitly commits state through the registry persistence model.

### Validation Environment Is Not A Security Property

```text
ExecutionEnvironment = Hardware | QemuDevelopment
```

```text
{ execute image I in QemuDevelopment and functional test T passes }
validate(I, T)
{ FunctionalBehaviorObserved(I, T) and
  not SecurityEquivalenceEstablished(I, Hardware) }
```

Semihosting and other host/guest development services are outside the secure
element boundary. A QEMU result may validate functional APDU behavior, but it
cannot establish resistance to hardware attacks, hardware-backed entropy,
physical isolation, or equivalence with a production deployment.

### Operational Responsibility

```text
LifecycleStage = Fabricated | PlatformActivated | IssuerPersonalized |
                 ServiceProvisioned | InField
```

```text
{ CurrentAuthority(S) = actor and AuthorizedHandover(actor, next, stage) }
advance_lifecycle(S, stage, next)
{ CurrentAuthority(S') = next and trust anchors, configuration, and deployed
  objects accepted at the transition are attributable to the authorizing actor }
```

The industrial roles described in Chapter 1 may be combined in one
organization, but a lifecycle transition does not implicitly grant an actor
more technical authority than the trust anchors and privileges installed for
it.

### Layer Dependency Invariant

```text
Application -> RuntimeServices -> ModelAndSecurity -> Administration -> APDUTransport
```

This notation describes service dependence, not command-flow direction.
Application code cannot bypass the runtime and privileged-service boundaries to
reach registry, secure-channel, or transport internals. Lower layers do not
depend on application-specific command semantics; application-originated
effects are mediated through their documented interfaces.

## APDU Communication And Dispatch

### Transport Integrity

```text
{ TransportReady(T) and frame contains exactly bytes }
receive_apdu(T, frame)
{ result = command(bytes) or TransportError and
  no byte is inserted, removed, reordered, or silently reused }
```

```text
{ not WellFormedApdu(c) }
parse_and_dispatch(S, c)
{ result = ProtocolError and PersistentState(S') = PersistentState(S) and
  no application or Security Domain handler was invoked }
```

Informal reading: the transport preserves the APDU byte sequence, and malformed
lengths or encodings are rejected before they reach privileged or application
logic. Bytes left from a previous command are never part of the next command.

Every supported physical or emulated transport backend must refine this same
APDU-level contract. Replacing the medium may change timing and framing
mechanics, but not the parsed command bytes or dispatch semantics.

### Kernel-Owned Selection

```text
{ WellFormedApdu(select(a)) and Selectable(S.registry, a) }
dispatch(S, select(a))
{ Selected(S', a) and result = Success }
```

```text
{ WellFormedApdu(select(a)) and not Selectable(S.registry, a) }
dispatch(S, select(a))
{ SelectedContext(S') = SelectedContext(S) and result = SelectionError }
```

Informal reading: `SELECT` is resolved and validated by the kernel. A failed
selection cannot leave a partially updated selected context.

### Command Routing

```text
{ WellFormedApdu(c) and KernelCommand(c) }
dispatch(S, c)
{ exactly one kernel management path handles c, or c is rejected }
```

```text
{ WellFormedApdu(c) and not KernelCommand(c) and Selected(S, a) }
dispatch(S, c)
{ exactly the selected application a handles c, or c is rejected }
```

```text
{ WellFormedApdu(c) and not KernelCommand(c) and no application is selected }
dispatch(S, c)
{ result = NoSelectedApplication and PersistentState(S') = PersistentState(S) }
```

No command may be executed both as a kernel command and as an ordinary
application command. Platform-management commands are interpreted under the
active Security Domain authority defined below.

## GlobalPlatform Managed Objects

### AID Uniqueness And Resolution

```text
WellFormed(R) implies
  forall x, y in dom(R), x.object_aid = y.object_aid -> x = y
```

```text
{ WellFormed(R) }
resolve_aid(R, aid, view)
{ result is the unique visible object identified by aid, or None }
```

Informal reading: an AID identifies at most one managed object in a registry,
and lookup cannot expose an object outside the caller's authorized view.

### Object Relationships

```text
WellFormed(R) implies
  every non-root object has an existing parent Security Domain and
  the parent relation is acyclic and terminates at the root Security Domain
```

Packages, application instances, Security Domains, keys, and data remain
distinct object kinds even when they participate in the same deployment flow.
References between them must name an object of the expected kind.

### Lifecycle Control

```text
{ WellFormed(R) and Authorized(sd, set_status, x) and
  AllowedTransition(kind(x), state(x), requested_state) }
set_status(R, x, requested_state)
{ state(R'[x]) = requested_state and OneDelta(R, R') }
```

```text
{ not AllowedTransition(kind(x), state(x), requested_state) }
set_status(R, x, requested_state)
{ result = LifecycleError and R' = R }
```

A lifecycle state gates every operation for which it is relevant. In
particular, a non-selectable instance cannot become the selected context, a
locked Security Domain cannot authorize management, and an unusable key cannot
be resolved for a secure-channel operation.

### Deployment And Personalization

```text
{ Authorized(sd, load, package) and ValidLoadDescriptor(package) }
load(R, package)
{ package is either installed completely with its declared owner and state,
  or R' = R }
```

```text
{ Authorized(sd, install, instance) and
  ValidPackageReference(R, instance.package) }
install(R, instance)
{ instance is either created completely under sd with a legal lifecycle state,
  or R' = R }
```

```text
{ Authorized(sd, delete, x) and DeletionClosureValid(R, x) }
delete_managed_object(R, x)
{ x and exactly the objects required by the selected deletion mode are absent,
  and every surviving reference remains valid }
```

Informal reading: `LOAD`, `INSTALL`, personalization, lifecycle changes, and
`DELETE` are authenticated registry transactions, not unrelated opcode side
effects. Validation and authorization precede publication.

## Security Domains And Administrative Authority

### Authority Selection

```text
{ no authenticated secure channel is active }
authority_for(S, c)
{ result = root Security Domain }
```

```text
{ SessionBoundTo(S, sc, sd) and command c is accepted by sc }
authority_for(S, c)
{ result = sd }
```

An authenticated command cannot borrow authority from a Security Domain other
than the one to which its secure-channel session is bound.

### Visibility And Delegation

```text
{ Authority(S, sd) }
visible(S.registry, sd, x)
{ result = DescendantOf(S.registry, x, sd) or x = sd }
```

```text
{ Authorized(parent, create_sd, child) }
create_security_domain(R, parent, child)
{ privileges(child) subseteq privileges(parent) }
```

```text
{ not DescendantOf(R, x, sd) and x != sd }
authorize(sd, operation, x)
{ result = Denied }
```

Informal reading: Security Domains are first-class managed objects. They define
administrative subtrees and may delegate only authority they already possess;
delegation cannot amplify privileges.

## Privileged Kernel-Service Boundary

Applications, including administrative applications, request kernel-managed
effects through an explicit service boundary. They do not directly mutate the
registry, flash, transport state, isolation configuration, or kernel-owned key
metadata.

```text
{ Isolated(S, caller) and ValidServiceRequest(caller, request) and
  Authorized(authority, request.operation, request.target) }
kernel_service(S, caller, request)
{ exactly the documented effect is committed, or no effect is committed and
  a defined error is returned }
```

```text
{ not ValidServiceRequest(caller, request) or
  not Authorized(authority, request.operation, request.target) }
kernel_service(S, caller, request)
{ result = DeniedOrInvalid and PersistentState(S') = PersistentState(S) }
```

Every pointer, slice, handle, AID, length, object kind, lifecycle state, and
authority used by a privileged request must be validated at the boundary. An
administrative application supplies policy decisions only within the authority
granted to its Security Domain; the kernel retains structural invariants and
the final mediation of privileged effects.

## Application Execution And Isolation

### Memory And State Isolation

```text
{ Isolated(S, a) and execute(a, c) returns normally }
execute_application(S, a, c)
{ kernel memory and every other application's private memory and state are
  unchanged, except for effects explicitly committed through kernel_service }
```

```text
{ Isolated(S, a) and a faults, exits, panics, overruns its stack, or exceeds its
  execution budget }
execute_application(S, a, c)
{ control returns to the kernel, a is terminated or rejected according to
  policy, and KernelInvariant(S') holds }
```

The command and response buffers exposed to an application are bounded views.
Incoming bytes are immutable except through an explicitly documented mutable
view, and only the returned response extent may be copied back to the transport.

### Instance-State Separation

```text
{ a != b and both instances use the same executable package }
mutate_instance_state(S, a, value)
{ state(S', a) = value and state(S', b) = state(S, b) }
```

Informal reading: executable code may be shared, but selected context and
serialized application state belong to individual instances.

## Secure-Channel Processing

### Establishment And Binding

```text
{ Authority(S, sd) and ValidEstablishmentRequest(sd, request) }
establish_secure_channel(S, sd, request)
{ success -> SessionBoundTo(S', sc, sd) and AuthenticatedPeer(sc) is defined
| failure -> no authenticated session created and no management command run }
```

### Protected Command Processing

```text
{ SessionBoundTo(S, sc, sd) and ProtectedCommand(c) }
unwrap_and_dispatch(S, sc, c)
{ authentication and replay checks occur before clear-command dispatch;
  success dispatches exactly one validated clear command under Authority(sd),
  while failure performs no managed-object mutation }
```

```text
{ SessionBoundTo(S, sc, sd) and clear response r was produced under sc }
wrap_response(S, sc, r)
{ response authentication and encryption match the negotiated security level,
  or a secure-channel error is returned }
```

Session counters, chaining values, pending establishment material, negotiated
security level, and replay state belong to one Security Domain session. A
failed establishment, reset, explicit termination, or protocol-defined fatal
error cannot leave stale authenticated authority usable by a later command.

## Key Management And Cryptographic Services

### Key Ownership And Resolution

```text
{ Authority(S, sd) and ValidKeyRef(S.registry, sd, k) }
resolve_key(S, sd, k, usage)
{ result designates exactly k for usage, without granting access to a sibling
  Security Domain's key material }
```

```text
{ not ValidKeyRef(S.registry, sd, k) }
resolve_key(S, sd, k, usage)
{ result = KeyUnavailable and no cryptographic operation is performed }
```

Key replacement and deletion follow the same authorization, lifecycle, and
transactional-publication rules as other registry mutations. Key bytes must not
be returned through ordinary application or audit interfaces.

### Cryptographic Operation Contract

```text
{ ValidCryptoRequest(operation, key, input, output) }
crypto_service(operation, key, input, output)
{ success -> output is exactly the result defined by the selected primitive
| failure -> no partial output is exposed as a successful result }
```

```text
{ request asks for random bytes }
fill_random(output)
{ success -> every requested byte is filled from the configured entropy path
| entropy failure -> result = EntropyUnavailable }
```

The model requires explicit failure when the selected hardware or development
backend cannot provide its configured entropy source. A QEMU development source
is not evidence of equivalent hardware entropy or isolation.

## Logging And Audit Traceability

Security-relevant operations produce an outcome event at the configured audit
boundary. At minimum, the abstract event identifies the operation class,
subject or authority, target identifier when applicable, and success or failure.

```text
{ AuditRelevant(op) and audit trace E }
complete_operation(S, op, outcome)
{ Traceable(E', op) and E is a prefix of E' and
  E' contains no secret key, plaintext protected payload, or private
  application memory }
```

```text
{ E is an audit trace }
append_audit_event(E, event)
{ existing events are not modified or reordered }
```

Audit failure must not silently turn a denied operation into an authorized one.
Where a build cannot provide durable audit storage, the implementation must
state the resulting traceability boundary; debug output alone does not satisfy
a claim of persistent tamper-resistant audit.

## Chapter 1 Model Coverage

The architectural elements announced in Chapter 1 map to this document as
follows:

| Chapter 1 element | Abstract model |
| --- | --- |
| Secure-element lifecycle and transfer of responsibility | Operational responsibility |
| QEMU development limitation | Validation environment is not a security property |
| APDU transport | Transport integrity |
| APDU parsing and dispatch | Transport integrity, command routing |
| SCP and protected messaging | Secure-channel processing |
| Managed objects and AIDs | GlobalPlatform managed objects |
| Lifecycle and deployment | Lifecycle control, deployment and personalization |
| Registry | Persistent object registry |
| Secure persistence | Flash operation, journal, atomicity and failure models |
| Security Domains and privileges | Administrative authority |
| Privileged application/kernel boundary | Privileged kernel-service boundary |
| Application invocation and isolation | Application execution and isolation |
| Key management and cryptography | Key management and cryptographic services |
| Logging and audit | Logging and audit traceability |
| Layering and dependency direction | Layer dependency invariant |

## Persistent Object Registry

### Abstract Registry State

The logical registry is modeled as one finite map:

```text
Registry = Map<ObjectAid, RegistryEntry>
```

Each `RegistryEntry` has a common part:

```text
RegistryEntry = {
  object_aid: Aid,
  parent_sd_aid: Aid,
  kind: KindWord,
  data_ref: PersistentRef
}
```

The `kind` selects one of the managed object families:

- `SecurityDomain`
- `Package`
- `Instance`
- `Key`
- `Data`

The `data_ref` points either into immutable firmware/predeployment storage or
into the mutable registry flash area.

Informal reading: the registry is the single kernel-owned catalog of managed
objects. Security Domains define authority and visibility over registry
entries; they do not own separate physical registries.

### Logical Registry Operations

#### Insert Or Replace Object

```text
{ WellFormed(R) and Authorized(sd, upsert, e) }
upsert(R, e)
{ WellFormed(R') and R'[e.object_aid] = e and
  forall a != e.object_aid, R'[a] = R[a] }
```

Informal reading: a registry upsert changes exactly one object entry and
preserves the rest of the registry.

#### Delete Object

```text
{ WellFormed(R) and e = R[aid] and Authorized(sd, delete, e) }
delete(R, aid)
{ WellFormed(R') and aid notin dom(R') and
  forall a != aid, R'[a] = R[a] }
```

Informal reading: deletion is represented by absence from the committed
registry. It does not need a tombstone in the logical model.

#### Lookup Object

```text
{ WellFormed(R) }
lookup(R, aid)
{ result = Some(R[aid]) if aid in dom(R),
  otherwise result = None }
```

Informal reading: lookup is a pure operation. It must not mutate registry
state or persistent storage.

#### Mutate Object Payload

```text
{ WellFormed(R) and e = R[aid] and Authorized(sd, mutate_payload, e) }
mutate_payload(R, aid, payload')
{ WellFormed(R') and R'[aid].data_ref refers to ObjectPayload(payload') and
  forall a != aid, R'[a] = R[a] }
```

Informal reading: changing serialized state, replacing key material, or
storing generic `Data` is logically one object mutation.

## Flash Operation Model

The flash backend is modeled as an array of erasable sectors, each composed of
one or more programmable pages.

```text
Flash = Sector[0..n)
Sector = Page[0..m)
Page = Byte[0..page_size)
```

The Pico1-style concrete intuition is:

- erase granularity: one sector;
- write granularity: one page;
- erased byte value: `0xFF`;
- programming is not treated as atomic at registry level.

### Erase Sector

```text
{ InRange(s) }
erase_sector(F, s)
{ forall p in pages(s), Erased(p) }
```

Informal reading: a successful erase turns the whole sector into `0xFF`.
The model does not permit erasing a single page unless the hardware actually
supports that as its erase granularity.

### Program Page

```text
{ InRange(p) and Erased(p) and len(data) = page_size }
write_page(F, p, data)
{ F'[p] = data and forall q != p, F'[q] = F[q] }
```

Informal reading: Oxide SE writes persistent blocks page by page. A page is
directly writable only when it is currently erased.

### Flush Page

```text
{ PageWriteIssued(p) }
flush_page(F, p)
{ PageDurable(p) or FlashError }
```

Informal reading: if a board distinguishes staging from durability, `flush`
is the point where the backend must make the write durable or report failure.
Boards without such distinction may implement it as a no-op.

## Persistent Registry Block Model

The mutable persistence area is a circular flash journal. It contains:

- one area marker page;
- zero or more `BOSS` registry blocks;
- zero or more object blocks.

Known block families are:

- `BOSS = 0x600DB055`: serialized registry snapshot;
- `C0DE = 0x600DC0DE`: executable package payload;
- `BA5E = 0x600DBA5E`: generic data or key payload;
- `FACE = 0x600DFACE`: serialized instance or Security Domain state.

Every block starts at a flash page boundary and has:

```text
Block = {
  magic: u32,
  total_len: u32,
  body: bytes,
  crc64: u64
}
```

`total_len` is aligned to the flash write page size. `crc64` is stored at the
end so that a partially written block is unlikely to validate accidentally.

### Scan And Recover

```text
{ FlashArea(F) }
scan(F)
{ result = set of all b such that ValidBlock(b) }
```

```text
{ FlashArea(F) and exists b, ValidRegistry(b) }
recover(F)
{ Recover(F) = decode(LatestRegistry(F)) }
```

```text
{ FlashArea(F) and not exists b, ValidRegistry(b) }
recover(F)
{ Recover(F) = Unpersonalized }
```

Informal reading: erased pages are valid free space, not end markers. Recovery
must scan the whole circular area because valid blocks may exist after erased
holes.

### Protected Ranges

```text
{ R = Recover(F) and R != Unpersonalized }
protected_ranges(F, R)
{ Protected(F, latest BOSS(R)) and
  forall x, ReferencedBy(R, x) -> Protected(F, x) }
```

Informal reading: the latest registry block and every object block referenced
by it are needed to recover the committed state. They must not be erased or
reused.

## Translating Registry Operations To Flash

The persistence layer implements each logical registry mutation by appending
new flash blocks. The existing committed registry is not overwritten in place.

### Publish Initial Registry

```text
{ PersistenceMarkerAbsent(F) and R0 = predeployment_registry() }
personalize(F, R0)
{ Recover(F') = R0 and PersistenceMarkerPresent(F') }
```

Informal reading: first boot erases the mutable registry area, builds the
predeployment registry in RAM, writes its object blocks, writes the first
`BOSS`, and finally leaves the area in a personalized state.

### Publish One Registry Mutation

Let `mutate` be one logical registry mutation:

```text
{ Recover(F) = R and mutate(R) = R' and OneDelta(R, R') }
publish_mutation(F, R, R')
{ Recover(F') = R' }
```

The implementation sequence is:

```text
1. write every new or changed object payload block;
2. verify or flush those object blocks;
3. encode RegistryImage(R') with mutation_counter(R) + 1;
4. write the new BOSS block;
5. verify or flush the new BOSS block.
```

Informal reading: the object data becomes durable first, but it is not
committed until a valid newer `BOSS` references it.

### Find Writable Space

```text
{ FlashArea(F) and R = Recover(F) and needed_len > 0 }
find_writable_span(F, R, needed_len)
{ result = Some(span) implies
  Aligned(span) and len(span) >= needed_len and
  forall p in pages(span), Erased(p) }
```

If no erased page span is available, the allocator may recycle a sector:

```text
{ FlashArea(F) and R = Recover(F) and SectorFreeForErase(F, s, R) }
erase_for_reuse(F, s)
{ forall p in pages(s), Erased(p) and Recover(F') = R }
```

Informal reading: the writer may program erased pages directly. It may erase a
non-empty sector only when no page in that sector is protected by the latest
valid registry.

## Atomicity Invariant

The central invariant is:

```text
AtomicRegistry(F):
  either Recover(F) = Unpersonalized
  or Recover(F) = decode(b) where b = LatestRegistry(F)
  and every data_ref in b points to a ValidBlock or immutable firmware object.
```

The commit point is the final valid checksum of the new `BOSS` block.

For every registry mutation:

```text
{ AtomicRegistry(F) and Recover(F) = R }
publish_mutation(F, R, R')
{ AtomicRegistry(F') and Recover(F') = R' }
```

For every interruption before the new `BOSS` validates:

```text
{ AtomicRegistry(F) and Recover(F) = R }
publish_mutation(F, R, R')
{ PowerLossBeforeValidBoss -> AtomicRegistry(Freboot) and Recover(Freboot) = R }
```

For every interruption after the new `BOSS` validates:

```text
{ AtomicRegistry(F) and Recover(F) = R }
publish_mutation(F, R, R')
{ PowerLossAfterValidBoss -> AtomicRegistry(Freboot) and Recover(Freboot) = R' }
```

Informal reading: after reboot, the system sees either the old complete
registry or the new complete registry. It must never recover a half-mutated
registry.

## Failure Event Model

Power loss may occur during erase, page write, flush, or between two
operations. The model deliberately does not assume a friendly flash backend.

### Power Loss During Erase

```text
{ AtomicRegistry(F) and SectorFreeForErase(F, s, Recover(F)) }
erase_sector(F, s)
{ success -> AtomicRegistry(F') and Recover(F') = Recover(F)
| PowerLoss -> AtomicRegistry(Freboot) and Recover(Freboot) = Recover(F) }
```

Informal reading: an erase can fail halfway, but Oxide SE only erases sectors
that are not needed by the latest committed registry. Therefore recovery must
not depend on the erased sector.

### Power Loss During Object Write

```text
{ AtomicRegistry(F) and Recover(F) = R }
write_object_block(F, object)
{ success -> AtomicRegistry(F') and Recover(F') = R
| PowerLoss -> AtomicRegistry(Freboot) and Recover(Freboot) = R }
```

Informal reading: a newly written object block is not visible until a later
`BOSS` references it. If power is lost while writing the object, recovery
still selects the old registry.

### Power Loss During BOSS Write

```text
{ AtomicRegistry(F) and Recover(F) = R and
  all object blocks referenced by R' are durable }
write_boss_block(F, R')
{ success -> AtomicRegistry(F') and Recover(F') = R'
| PowerLossBeforeValidBoss -> AtomicRegistry(Freboot) and Recover(Freboot) = R
| PowerLossAfterValidBoss -> AtomicRegistry(Freboot) and Recover(Freboot) = R' }
```

Informal reading: writing the registry block is the only committing action.
The CRC at the end decides whether recovery sees the new transaction.

### Power Loss Between Operations

```text
{ AtomicRegistry(F) }
idle_or_between_steps(F)
{ PowerLoss -> AtomicRegistry(Freboot) }
```

Informal reading: there is no hidden in-RAM state that is required to recover
the persistent registry after reboot.

## What Must Be Proven

To prove transactional atomicity for the Oxide SE persistent registry, we
must prove the following properties.

### Block Validity

Every block accepted by the scanner is either:

- a fully written block produced by Oxide SE; or
- a collision that satisfies magic, length, range and CRC checks.

The implementation proof obligation is to make the collision case
cryptographically or operationally negligible for the selected checksum.

### Complete Scan

The scanner must visit the whole circular persistence area. Erased pages must
be treated as free pages, not as the end of the log.

### Latest Registry Selection

If at least one valid `BOSS` exists, recovery must select exactly the valid
`BOSS` with the highest mutation counter.

### Reference Closure

For the selected `BOSS`, every registry entry with a mutable flash reference
must point to a valid object block of the expected family.

### Commit Ordering

For every mutation, all new object blocks must be written before the new
`BOSS` block is written.

### Protected Erase

No erase operation may target a sector containing:

- the latest valid `BOSS`;
- an object block referenced by the latest valid `BOSS`;
- an old object block still required by the previous `BOSS` while a one-delta
  replacement transaction is in flight.

### Single-Delta Publication

The implementation must publish at most one logical registry mutation per new
`BOSS`. This keeps the old-only protected payload set bounded and prevents the
allocator from confusing "not referenced by the new registry" with "safe to
erase before the new registry commits".

### Reboot Independence

After reboot, recovery must depend only on persistent flash bytes and immutable
firmware/predeployment bytes. Volatile load contexts, transient APDU buffers,
and in-RAM registry caches must not be required to recover a committed state.

### Transactional Atomicity Theorem

The final theorem to establish is:

```text
For any valid flash state F with AtomicRegistry(F),
for any authorized logical registry mutation R -> R',
and for any single power-loss event occurring during the flash sequence that
publishes R',
Recover(Freboot) is either R or R'.
```

Informal reading: Oxide SE registry persistence is transactionally atomic if
every reboot observes either the old committed registry or the new committed
registry, never a torn mixture of both.
