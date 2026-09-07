# Complete Security Domain

`CompleteSecurityDomain` is a privileged Rustlet used to demonstrate that a
Security Domain can own a secure-channel implementation in application space.
It is not limited to authorizing kernel operations: the kernel proxy forwards
SCP establishment and secure-messaging operations to this Rustlet.

The SCP03 example deliberately includes security level `33`:

- command encryption (`C-ENC`);
- command authentication (`C-MAC`);
- response encryption (`R-ENC`);
- response authentication (`R-MAC`).

`KernelSecurityDomain` does not select SCP03 level `33`. Loading this Rustlet
Security Domain therefore illustrates the intended extension model: when a
deployment needs a protocol fragment that the kernel profile does not provide,
implement it in a Security Domain Rustlet and load that Security Domain rather
than adding a proprietary path to the kernel.

The same model can host future GlobalPlatform Supplementary Security Domains.
This keeps optional or deployment-specific protocol policy in the application
environment instead of making internal, proprietary kernel implementations the
only extension mechanism, as is common in Java Card ecosystems.

## Validation

The Oxide SE QEMU campaign exercises SCP03 S16 at security level `33`,
including encrypted commands, encrypted and authenticated responses, and replay
rejection:

```text
cargo run test gp_rustlet_security_domain_scp03 mps2-an385
```

The host-side SCP03 vector tests also reproduce the public Samsung
OpenSCP-Java AES-128/S16 exchange. Samsung selects `EXTERNAL AUTHENTICATE`
security level `33` and currently publishes no equivalent `11` or `13`
scenario. The Samsung transcript is independent regression evidence, not a
GlobalPlatform certification vector.
