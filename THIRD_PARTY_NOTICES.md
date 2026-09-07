# Third-Party Notices

This repository is distributed under the terms of the CeCILL v2.1
license. Some parts of the project may depend on third-party open source
components with their own licenses.

At the current stage, the cryptographic backend design work has
identified two families of RustCrypto crates:

- components already used or directly aligned with the current
  symmetric software fallback path of the `core` cryptographic layer;
- components under consideration for a future asymmetric extension,
  primarily to support GlobalPlatform SCP11 / SCP11c.

This notice intentionally distinguishes "currently used" from "planned"
dependencies. Some crates listed below are not integrated in the code
base yet; they are recorded here because they are explicit candidates in
the architectural roadmap.

## RustCrypto Components Used Or Directly Aligned With The Current Symmetric Layer

### `aes`

- Upstream project: RustCrypto block ciphers
- Source: <https://docs.rs/aes/latest/aes/>
- Expected role in this project: software AES backend for the `core`
  cryptographic layer
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

### `cipher`

- Upstream project: RustCrypto traits and buffer abstractions
- Source: <https://docs.rs/cipher/latest/cipher/>
- Expected role in this project: common block-cipher traits and in-place
  buffer handling helpers
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

### `cmac`

- Upstream project: RustCrypto message authentication codes
- Source: <https://docs.rs/cmac/latest/cmac/>
- Expected role in this project: AES-CMAC implementation for SCP03
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

### `cbc`

- Upstream project: RustCrypto block modes
- Source: <https://docs.rs/cbc/latest/cbc/>
- Expected role in this project: CBC-mode helper for AES-based secure
  messaging paths
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

### `hkdf`

- Upstream project: RustCrypto key derivation functions
- Source: <https://docs.rs/hkdf/latest/hkdf/>
- Expected role in this project: HKDF-SHA256 derivation over shared
  secrets produced by asymmetric key agreement
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

### `sha2`

- Upstream project: RustCrypto hash functions
- Source: <https://docs.rs/sha2/latest/sha2/>
- Expected role in this project: SHA-256 backend used by HKDF and future
  SCP11-oriented derivation steps
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

## RustCrypto Components Under Consideration For SCP11 / SCP11c

The current roadmap keeps SCP03 as the symmetric secure-channel base and
targets SCP11 / SCP11c as the next asymmetric step. The crates below are
the primary `no_std` candidates currently considered for that work.

### `p256`

- Upstream project: RustCrypto elliptic-curve implementations
- Source: <https://docs.rs/p256/latest/p256/>
- Expected role in this project: P-256 / secp256r1 key handling,
  ephemeral key generation, ECDH, and possibly ECDSA verification
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

### `elliptic-curve`

- Upstream project: RustCrypto generic elliptic-curve traits and types
- Source: <https://docs.rs/elliptic-curve/latest/elliptic_curve/>
- Expected role in this project: generic ECC abstractions used by
  `p256` and related crates
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

### `sec1`

- Upstream project: RustCrypto SEC1 encodings
- Source: <https://docs.rs/sec1/latest/sec1/>
- Expected role in this project: elliptic-curve point and key encodings
  exchanged by the runtime and stored in registry objects
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

### `spki`

- Upstream project: RustCrypto SubjectPublicKeyInfo support
- Source: <https://docs.rs/spki/latest/spki/>
- Expected role in this project: minimal public-key container support if
  SCP11 / SCP11c needs SPKI-level exchange or storage
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

### `ecdsa`

- Upstream project: RustCrypto ECDSA support
- Source: <https://docs.rs/ecdsa/latest/ecdsa/>
- Expected role in this project: signature verification if the chosen
  SCP11 / SCP11c profile requires authenticated public-key material
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

### `x509-cert`

- Upstream project: RustCrypto X.509 certificate support
- Source: <https://docs.rs/x509-cert/latest/x509_cert/>
- Expected role in this project: optional certificate parsing if the
  selected SCP11 / SCP11c profile requires a more explicit certificate
  chain rather than bare public keys
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

### `cms`

- Upstream project: RustCrypto CMS / Cryptographic Message Syntax
- Source: <https://docs.rs/cms/latest/cms/>
- Expected role in this project: optional support for richer management
  objects if future SCP11-related provisioning requires CMS structures
- Upstream license expression: `MIT OR Apache-2.0`
- Preferred interpretation for this project: MIT

## Integration Note

The project may later vendor third-party sources in order to improve
auditability, reproducibility, or long-term maintenance control.
At present, the simplest integration path is preferred: dependencies are
expected to come from crates.io, while this file records the upstream
components and their licenses.

The current working assumption is that these permissive `MIT OR
Apache-2.0` licenses are compatible with the CeCILL v2.1 licensing
model used by this repository. This file is an engineering trace, not a
formal legal opinion; any definitive long-term dependency decision may
still require project-level legal validation.
