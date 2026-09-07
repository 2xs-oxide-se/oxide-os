# TODO

This file tracks open technical work for the current implementation. Design
history belongs in the lab journal.

## QEMU Validation Failures

Required:

Evidence and the complete 80-command inventory are recorded in the
[2026-08-30 validation report](reports/qemu-validation-2026-08-30.md).
The Pico1 functional failures from that campaign were revalidated through
2026-09-04: the focused Rustlet scenarios, all Security Domain variants,
SCP11a/b/c, ECDH, predeployment, dynamic loading, persistence,
`gp_security_domain` (143 assertions), and `gp_all` (626 assertions) pass.
Only the independently reported stack-budget failure below remains.

- [ ] Resolve the remaining Pico1 kernel stack-budget failure after the
  per-scenario instrumentation comparison tracked under Board Porting:
  `rustlet_all` reaches 6576 bytes with the current APDU observer, against the
  6144-byte budget.
  The observed mps2 `rustlet_all` value (6016) and Pico1 `gp_scp03` value
  (6108) now fit that budget, but remain close enough to warrant inspection.
  Inspect the kernel frames at AES-256 CMAC if excess remains with comparable
  monitoring. Preserve the budget; do not transfer temporary buffers to heap
  or change external crypto implementations merely to make measurements pass.
  The controlled mps2 comparison on 2026-08-30 measured 6024 bytes twice with
  `kernel-only-v1`, versus 6016 with `kernel-and-rustlet-v1`; the latter is
  not the cause of the historical +184-byte difference from 5832. Both runs
  used the same firmware sources/toolchain and byte-identical Rustlet FAE
  payloads; manifests differed only by the Rustlet monitor module. Also ruled
  out: the tranche-2 scenario/runner extraction (tranche 1 already measured
  6016), a baseline-value change (only identifiers were migrated), and changed
  Rustlet payloads as an explanation of this A/B difference. No specific new
  APDU buffer or crypto frame has been identified as the historical cause.

Possible Improvements:

None at this stage.

## Security Domain And Secure Channel

Required:

- [ ] Add ISO/IEC 7816-4 / GlobalPlatform logical-channel support after the
  beta, including `MANAGE CHANNEL` and independent per-channel application
  selection and secure-channel state. Multiple logical channels are planned,
  not deliberately excluded from the oXiDe SE profile.

Possible Improvements:

- Extend Rustlet Security Domain QEMU coverage so every management hook has
  positive and negative tests where the hook has one meaningful policy branch.
- Add Rustlet-SD-authorized dynamic `LOAD` scenarios beyond the current
  kernel-authorized persistence path.
- Add richer lifecycle-management flows on top of the current package,
  instance, Security Domain, and key state guards.
- Refine certification-grade key-purpose and key-diversification policy on top
  of the current GP-style SCP03 key object model.
- Add optional key-information and Security-Domain metadata fields beyond the
  current `GET DATA 0066/0067` and mandatory `GET STATUS` records.

## Rustlet Fault Isolation

Required:

None at this stage.

Possible Improvements:

- Normalize fault diagnostics across `MemManage`, `BusFault`, `UsageFault`, and
  recovered `HardFault` paths once all supported ARM profiles expose enough
  context.

## SCP03/SCP11

Required:

None at this stage.

Possible Improvements:

- Account for long-running SVC execution in Rustlet watchdog and T=0 NULL
  timing. The initial low-priority SysTick design deliberately does not
  preempt SVC handlers, notably slow asymmetric crypto on Pico1.

- Validate secure-channel operations against official GlobalPlatform
  certification vectors if such vectors become available to the project.
- Import the remaining reusable Samsung OpenSCP-Java references: SCP11a
  P-256/AES-128 S8, P-256/AES-192 S8, P-256/AES-256 S8, P-384/AES-128 S8,
  Brainpool-P256/AES-128 S8, GP-certificate P-256/AES-128 S8, SCP11c
  P-256/AES-128 S8, and the X.509/GP certificate-bundle `GET DATA` cases.
  Record explicitly that the current Samsung suite provides no SCP11b vector.
- Decide whether deployment manifests should prefer SCP03 S16, SCP11, or a
  dual SCP03+SCP11 protocol set once production policy is ready.
- Define diversification policy for static Security Domain key material,
  separately from SCP03 session-key derivation.
- Support additional SCP11 algorithm and curve variants beyond the current
  P-256/AES development profile.
- Generalize certificate-chain handling beyond the embedded-CA development
  profile if production deployment needs a fuller GP PKI model.
- Map currently modeled but unused privilege families to kernel operations when
  those operations exist: `Trusted Path`, `Token Verification`, `Global Lock`,
  `Final Application`, `Global Service`, `Receipt Generation`,
  `Ciphered Load File Data Block`, `Contactless Activation`,
  `Contactless Self-Activation`, `DAP Verification`,
  `Mandated DAP Verification`, `Card Lock`, `Card Terminate`, `Card Reset`,
  and `CVM Management`.

## Rustlet Isolation And MPU Packing

Required:

- [ ] Replace the kernel-wide fixed Rustlet stack size with the stack
  requirement declared by each Rustlet FAE ABI footer, and propagate that
  value through RAM allocation, MPU layout, entry validation, and stack
  monitoring.

Possible Improvements:

- Extend kernel RAM-XN coverage to future targets whose mutable RAM cannot be
  represented as one or two strict MPU windows.
- Split the tiny app-entry trampoline out of the mixed RW+X gate/shared region
  only if a stricter attack model requires it. The current invariant is that
  the trampoline is rewritten before every Rustlet entry, so one Rustlet cannot
  persistently alter the gate used by the next one.
- Distinguish executable Rustlet code from read-only Rustlet metadata only if a
  future threat model requires metadata to be XN instead of merely RX.
- Consider a dedicated shared ABI buffer MPU window instead of relying on the
  writable Rustlet RAM window.
- Improve MPU region packing for larger Rustlets under tight hardware-region
  budgets.

## Board Porting And Hardware Validation

Required:

- [ ] Revisit the Pico2 SDK-style random backend before relying on it for
  cryptographic security. It deliberately uses raw TRNG samples with health
  checks bypassed, splitmix64 and xoroshiro128**, matching the selected
  `pico_rand` approach rather than a cryptographic DRBG. Characterize entropy,
  choose health checks and conditioning, define prediction/backtracking
  resistance and recovery policy, and validate a suitable replacement.
  Successful random APDU tests establish functionality only.

Possible Improvements:

- Extend the hardware campaigns validated on Pico2 to other supported boards,
  including persistence across reset without reflashing and fault observation;
  record hardware-specific stack baselines for each validated campaign.
- Map each maturity level to reproducible validation commands before
  `qemu_support` or `board_support` is enabled.

## Documentation Cleanup

Required:

- [ ] Resume systematic `///` source documentation for `kernel` / `core` public
  interfaces, especially around the secure-channel boundary and registry
  authority model.

## Persistent Registry And Flash Backend

Required:

- [ ] Complete flash validation with a physical power-cycle test (no reflash).
  `kernel_flash` now reserves a separate 4-KiB diagnostic tail through
  `flash-probe`, leaves registry initialization enabled, and passes two-marker
  write/read across complete resets on Pico2 hardware and Pico1 QEMU. Actual
  power cycling and interrupted writes remain unvalidated. Keep explicit
  destructive-test consent and backup of existing data.

Possible Improvements:

- Extend `registry-test` / `kernel_registry` beyond basic creation, lookup,
  replacement and reboot persistence: cover deletion, interrupted writes,
  power loss and recovery. Keep using the normal registry APIs without
  requiring GlobalPlatform or Rustlet execution.
- Define and implement a syscall API through which an authorized Rustlet can
  read, write, replace, and remove AID-qualified registry `Data` objects
  without exposing kernel-managed `Key` semantics. Specify the associated
  Security Domain access checks and the atomicity/transaction model for
  multi-page or multi-call mutations, including interruption, rollback, and
  power-loss behavior.
- Use DMA where the target can provide it to optimize flash programming and CRC
  calculation for persistent registry blocks.
- Optimize flash-space management beyond the current first-fit append/recycle
  strategy, including compaction policy, wear distribution, and stronger
  fault-injection coverage.

## INSTALL [for load] / LOAD

Required:

- [ ] Add a QEMU management regression that rejects a final `LOAD` carrying a
  FAE built for an incompatible CPU or ABI and checks the explicit
  inappropriate-format status word. Host tests already cover the parser, and
  final `LOAD` now validates `FAEC0D10` ISA and Oxide SE ABI descriptors before
  publishing the persistent `C0DE` package.
Possible Improvements:

- Use DMA where the target can provide it for large `LOAD` writes, hash/CRC
  calculation, and flash programming.
- Extend `apdu-tool` with high-level commands for SCP03, SCP11a, SCP11b,
  SCP11c, `SELECT`, `PUT KEY`, `STORE DATA`, `INSTALL [for load]`, `LOAD`, and
  `INSTALL [for install]`.

## Porting Pico-2

Required:

None beyond the Pico2 entropy qualification tracked under Board Porting And
Hardware Validation.

Possible Improvements:

- Replace the software-based SHA-256 implementation with the hardware SHA-256
  accelerator on the Pico 2. This would reduce CPU cycles spent on hashing and
  improve efficiency.
- Use spinlocks to protect hardware peripherals such as the TRNG if concurrent
  execution or similar use cases are introduced.
