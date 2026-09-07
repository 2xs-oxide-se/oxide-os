# APDU Tool

`apdu-tool` is the command-line client used to communicate with Oxide SE over
T=0 APDUs. It supports TCP connections, Unix sockets, and physical serial ports
configured for 115200 8N1.

The project keeps the simplicity of a “netcat for APDUs” while adding a clear
ATR/APDU lifecycle, high-level ISO 7816 and GlobalPlatform commands, transparent
Secure Channels, and one-command FAE loading and installation. See
[`docs/TODO.md`](docs/TODO.md) for the detailed roadmap.

## Current interface

The implemented commands are:

```text
apdu-tool [OPTIONS] atr
apdu-tool [OPTIONS] raw HEX...
apdu-tool [OPTIONS] raw --file PATH
apdu-tool [OPTIONS] raw --stdin
apdu-tool [OPTIONS] gp get-data TAG [--format hex|binary|tlv]
apdu-tool [OPTIONS] gp get-status CATEGORY [--aid AID]
apdu-tool [OPTIONS] gp store-data TAG (--data HEX|--input FILE|--stdin)
apdu-tool [OPTIONS] gp delete-data TAG
apdu-tool [OPTIONS] gp delete --aid AID
apdu-tool [OPTIONS] gp set-status TYPE AID STATE
apdu-tool [OPTIONS] gp put-key --version V --id I (--key-file USAGE:FILE|--key USAGE:HEX)...
```

From the repository root:

```bash
cargo run -p apdu_tool -- atr
cargo run -p apdu_tool -- \
  raw 00 A4 04 00 08 00 A0 00 00 47 50 4F 53 20
```

A subcommand is mandatory. The old form without a subcommand and its implicit
data generation have been removed. `raw` transmits exactly the bytes provided
and checks that the data length matches `Lc`.

`raw` accepts space-separated bytes, colon-separated bytes, continuous hex, a
text file, or standard input:

```bash
apdu-tool raw 00 A4 04 00 02 00 AA BB
apdu-tool raw 00:A4:04:00:02:00:AA:BB
apdu-tool raw 00A404000200AABB
apdu-tool raw --file command.apdu
printf '00 A4 04 00 02 00 AA BB' | apdu-tool raw --stdin
```

`atr` is the only mode that performs an initial read. `raw` opens the link
once, immediately transmits the APDU, and waits for its response. If the link
still contains an ATR starting with `3B` or `3F`, the tool reports a
desynchronization and recommends running `apdu-tool atr` first.

Timeouts accept the `ms`, `s`, and `m` suffixes:

```text
--connect-timeout <duration>    total ATR connection retry time; default 10s
--atr-timeout <duration>        first ATR byte timeout; default 10s
--response-timeout <duration>   maximum response silence; default 10s
--retry-interval <duration>     ATR connection retry interval; default 100ms
```

`--atr-timeout infinite` waits for the first byte without a deadline. Other
timeouts controlling an active wait must be positive, except
`--connect-timeout=0ms`, which requests a single connection attempt.

Supported link formats are:

```text
127.0.0.1:4444                 TCP, the default
/tmp/rustlet.sock              Unix socket
/dev/tty.usbmodem1101:115200   Unix serial port
COM3:115200                    Windows serial port
```

Configure the link with `--serial` (`-s`). `-v` decodes the ATR or known
management APDUs; `-vv` also colorizes fields in the raw representation.

## ATR and command lifecycle

`atr` waits for the link and then for the first ATR byte. It sends no APDU.
Verbose mode also decodes the ATR:

```bash
cargo run -p apdu_tool -- --serial /dev/ttyUSB0 atr
```

Progress is disabled by default. With `--progress`, a `-`, `\`, `|`, `/`
spinner is updated on `stderr` twice per second while waiting for ATR bytes:

```text
waiting ATR...-
ATR: 3B ...
```

Each state rewrites the same line with `\r`; the line is cleared before the
result or error is printed.

When sending a command, the Secure Element is assumed to be active. The tool
does not wait for an ATR. With `--progress`, the response spinner advances only
when the SE sends a T=0 `NULL` procedure byte (`60`), proving it is still active:

```text
waiting RESPONSE...-
waiting RESPONSE...\
```

Errors distinguish an unavailable endpoint or serial port, an open link with a
silent SE, an incomplete T=0 response or invalid procedure byte, a response
timeout, desynchronization, and a failing status word.

## Target interface

> Beyond `atr` and `raw`, the commands below describe the refactoring target
> and are not all implemented yet.

```text
apdu-tool [GLOBAL OPTIONS] <COMMAND> [OPTIONS]

atr                         wait for and display an ATR
raw                         send an already encoded APDU
select                      build an ISO 7816 SELECT
gp <command>                run a GlobalPlatform operation
```

Command names use hyphens, such as `install-for-load`, rather than underscores.
A future logical APDU format will let the tool calculate `Lc`; the current raw
format deliberately preserves strict wire-level control.

### ISO 7816 commands

The first symbolic command will be `SELECT by DF/application name`:

```bash
apdu-tool select A0:00:00:47:50:4F:53:20
```

Options may select the first or next occurrence and the expected response type
(`FCI`, `FCP`, `FMD`, or no data). Other candidates supported by the Oxide SE
profile include `GET RESPONSE`, `GET CHALLENGE`, `MANAGE CHANNEL`,
`READ BINARY`, `UPDATE BINARY`, `READ RECORD`, and `VERIFY`.

### GlobalPlatform commands

GlobalPlatform commands are grouped under `gp`:

```bash
apdu-tool gp get-data 9F70
apdu-tool gp get-data card-recognition --format tlv
apdu-tool gp get-data card-capabilities --format tlv
apdu-tool gp get-status applications
apdu-tool gp store-data DF11 --data 01:02:03:04
apdu-tool gp delete --aid A0:00:00:47:50:4F:53:20
```

Read and write operations accept data directly or through a file:

```bash
apdu-tool gp get-data DF11 --output object.bin
apdu-tool gp store-data DF11 --data 01:02:03:04
apdu-tool gp store-data DF11 --input object.bin
apdu-tool gp store-data DF11 --stdin
apdu-tool gp delete-data DF11
```

`--data`, `--input`, and `--stdin` are mutually exclusive. With `--output`, raw
bytes are written without diagnostics. Synthetic Oxide SE registry identifiers
remain hidden. The target also includes `get-status`, `set-status`, `delete`,
and `put-key`; pagination is automatic, lifecycle states and privileges accept
symbolic names, and keys are never printed, including under `-vv`.

Registry mutations are atomic short APDUs. `STORE DATA` currently accepts at
most 255 bytes and rejects larger input before opening the link. Oxide SE does
not yet expose a transactional multi-command reassembly protocol, so the tool
does not pretend to segment a mutation that the card would publish piecemeal.

`PUT KEY` accepts AES-128 SCP03 `enc` and `mac` entries, a 32-byte P-256
`scp11-sd-ecka` private scalar (`SK.SD.ECKA`), and a 65-byte uncompressed SEC1
`scp11-ca-kloc` public key (`PK.CA-KLOC.ECDSA`). The command's `--version` and
`--id` select the first key; repeated entries use consecutive identifiers.
Repeat `--key-file USAGE:PATH` to load several keys in one APDU. Key files may
contain 16, 32, or 65 raw bytes, or hexadecimal text, and should use Unix mode
`0600`. Inline
`--key USAGE:HEX` remains available for debugging, but always emits a warning
because the secret is exposed through shell history and process listings.
Command rendering and JSON output redact all key material.

SCP11 resolves provisioned keys within the selected Security Domain. For
bootstrap compatibility, selectors `version=0,id=1` (SD ECKA) and
`version=0,id=0` (CA-KLOC) still fall back to the compiled development keys
when no registry object exists. Provisioning either selector overrides that
fallback. SCP11c derives the matching SD public key from the selected private
scalar.

## Loading and installing an FAE

Individual GlobalPlatform primitives remain available:

```bash
apdu-tool gp install-for-load \
  --package-aid 01:00:A3:7F:E5 \
  --security-domain A0:00:00:00:03:00:00 \
  --hash-file package.sha256 \
  --parameters EF:02:01:00
apdu-tool gp load-block --number 0 --last block.bin
apdu-tool gp install-for-install \
  --package-aid 01:00:A3:7F:E5 \
  --module-aid 01:00:A3:7F:E5:01 \
  --instance-aid 01:00:A3:7F:E5:02
apdu-tool gp install-make-selectable \
  --package-aid 01:00:A3:7F:E5 \
  --module-aid 01:00:A3:7F:E5:01 \
  --instance-aid 01:00:A3:7F:E5:02 \
  --privileges delegated-management \
  --parameters-file install-parameters.bin
```

`install-for-install` emits P1 `04`; `install-make-selectable` emits the
combined `INSTALL [for install and make selectable]` form with P1 `0C`.
Hexadecimal values may instead be read from a file with the corresponding
`--*-file` option. Such files may contain raw bytes or hexadecimal text.
Privileges accept hexadecimal bytes or comma-separated names such as
`security-domain`, `dap-verification`, `delegated-management`, `card-lock`,
`card-terminate`, `card-reset`, `cvm-management`, and `mandated-dap`.

The one-command loading operation stops after registering and transferring the
package:

```bash
apdu-tool gp load 01:00:A3:7F:E5 monfae.fae
```

Complete deployment additionally installs the package's same-AID module and
makes the requested instance selectable:

```bash
apdu-tool gp deploy \
  01:00:A3:7F:E5 monfae.fae 01:00:A3:7F:E5:01 \
  --params C9:02:01:00
```

`--params` is omitted when the Rustlet installation expects no argument. Both
operations validate the FAE 1.0 footer, CRC32, ISA, ABI profile and size before
starting the GP transaction. They discover the current Issuer Security Domain
unless `--security-domain` already names it, calculate the LOAD payload capacity
from T=0 and the active Secure Channel, number at most 256 blocks, and mark the
last block. `deploy` never sends its final INSTALL if any LOAD block fails.

## Secure Channels

Encryption, MAC generation, counters, and response verification belong to the
tool rather than the user.

### SCP03

The recommended multi-command workflow starts by capturing the ATR, which also
creates the persistent session file:

```bash
apdu-tool --serial /dev/ttyACM0:115200 atr
# Reset the device while `atr` is waiting.
apdu-tool scp03 open \
  --scp03-profile s16 \
  --security-level c-mac+c-enc \
  --keyset keys.toml
apdu-tool gp deploy A0000047504F5321 app.fae A0000047504F5322
apdu-tool select A0000047504F5322
apdu-tool raw 80:10:00:00:00:00
apdu-tool close
```

`scp03 open` persists the live derived keys, counters, and MAC chains. Every
following `gp`, `select`, or `raw` invocation resumes that channel and
checkpoints it after each verified response. `raw` is the logical clear APDU:
the tool applies the active security level before transmission and unwraps the
response. A protected command is encrypted only when C-ENC is enabled; C-MAC
alone authenticates it without hiding its data.

The session file is `session.json` in the current directory unless
`APDU_SESSION_FILE` names another path. It contains security-critical live
session material, is atomically written with Unix mode `0600`, and is rejected
if group or other users can access it. Never copy, publish, or retain it after
use. Any transport or response-verification failure removes the resumable
snapshot before stale counters can be reused.

`scp03 inspect` reports only non-secret metadata. `scp03 close` erases the
local SCP03 state but keeps the general ATR/link session; it is a local close,
because SCP03 has no universal remote close command. `close` removes the whole
session file. Do not run concurrent commands against one session or let another
client exchange APDUs with the SE between commands.

The one-shot form remains available when no persistent session is required:

```bash
apdu-tool \
  --secure-channel scp03 \
  --scp03-profile s16 \
  --security-level c-mac+c-enc \
  --keyset keys.toml \
  gp get-data 9F70
```

The tool selects the Security Domain, executes `INITIALIZE UPDATE` and
`EXTERNAL AUTHENTICATE`, derives S-ENC, S-MAC, and S-RMAC, protects commands,
and verifies or decrypts responses. Both SCP03 S8 and S16 are supported. S16 is
the default unless the keyset or `--scp03-profile` selects S8.

An SCP03 keyset is a TOML file containing AES-128 keys:

```toml
version = 0
id = 0
profile = "s16"
enc = "404142434445464748494A4B4C4D4E4F"
mac = "505152535455565758595A5B5C5D5E5F"
```

Unknown fields, malformed keys, non-AES-128 material, mismatched keyset
identifiers, and invalid card cryptograms are rejected. The file should use
mode `0600`; broader Unix permissions produce a warning. Use `--keyset` or
`APDU_KEYSET` as SCP03-specific aliases for `--credentials` and
`APDU_CREDENTIALS`.

An intentionally ad-hoc Pico 1 hardware transcript is available as:

```bash
tools/apdu-tool/tests/hardware_scp03.sh
```

It is a commented sequence of ordinary build, OpenOCD and apdu-tool commands,
intended to remain readable as a manual test recipe. It opens the UART before
releasing reset so the ATR is not lost, then tests S8, S16, the delegated
Rustlet Security Domain, protected registry operations and negative
authentication cases. The script is tied to
the dedicated `/dev/cu.usbmodem21102` test device and erases the Pico's complete
flash and persistent registry.

The shortest end-to-end dynamic-loading tutorial starts with a kernel that
contains only `NullSecurityDomain`, then builds, deploys, selects, and exercises
`getting_started_test` with the five APDU shapes implemented by its source:

```bash
tools/apdu-tool/tests/hardware_null_deploy_getting_started.sh
```

This second script is deliberately a linear list of commented commands so each
line can also be run manually. It erases the dedicated Pico 1 flash.

### SCP11

The same abstraction covers SCP11a, SCP11b, and SCP11c:

```bash
apdu-tool \
  --secure-channel scp11a \
  --security-level c-mac+c-enc+r-mac+r-enc \
  --credentials scp11-host.toml \
  gp get-data lifecycle
```

Credential files may reference private keys, certificates, trust chains, and
profile identifiers. Paths are resolved relative to the TOML file:

```toml
profile = "scp11a" # scp11a, scp11b or scp11c
version = 0
id = 1
host_id = "oxide-se-host"       # use "hex:..." for a binary identifier
sin = "oxide-se-sin"
sdin = "oxide-se-sdin"
card_group_id = "oxide-se-card"
host_private_key_file = "host-private.key"
host_certificate_file = "host-cert.bin"
certificate_chain_files = ["intermediate-cert.bin"]
card_public_key_file = "card-public.key"
```

Private and public key files accept either raw 32/65-byte material or
hexadecimal text. Certificates are read as binary GlobalPlatform certificates.
SCP11b does not use the host private key or OCE certificate, but still requires
the pinned card public key. Inline `host_private_key` and `card_public_key`
fields exist for debugging; the former emits a warning. Every credential and
key file should use mode `0600`; broader Unix permissions also emit a warning.

A Secure Channel session is stateful. Compound operations retain the same
connection, session keys, counters, and MAC chains until completion. Persistent
resumption between ordinary invocations is currently implemented for SCP03;
SCP11 persistence remains pending.

The common Secure Channel abstraction is transport-independent and owns its
protocol engine for the whole operation. An establishment, transport,
protection, MAC/receipt verification, or truncated-response error permanently
invalidates the session and clears its engine state. A new session must then be
established; an invalidated counter or MAC chain cannot be reused. SCP11 uses
the Oxide SE full `3C` key-usage profile and therefore requires
`--security-level c-mac+c-enc+r-mac+r-enc`. SCP11b rejects OCE management
commands locally because card-only authentication cannot authorize them.

## Reusable context and environment

Options explicitly supplied on the command line take precedence over their
environment counterpart; the environment takes precedence over the built-in
default. Empty or invalid environment values are errors.

| CLI option | Environment variable | Status |
| --- | --- | --- |
| `--serial` | `APDU_LINK` | available |
| `--output` | `APDU_OUTPUT` | available |
| `--connect-timeout` | `APDU_CONNECT_TIMEOUT` | available |
| `--atr-timeout` | `APDU_ATR_TIMEOUT` | available |
| `--response-timeout` | `APDU_RESPONSE_TIMEOUT` | available |
| `--retry-interval` | `APDU_RETRY_INTERVAL` | available |
| `--secure-channel` | `APDU_SECURE_CHANNEL` | available |
| `--security-domain` | `APDU_SECURITY_DOMAIN` | available |
| `--security-level` | `APDU_SECURITY_LEVEL` | available |
| `--credentials` | `APDU_CREDENTIALS` | available |
| `--scp03-profile` | `APDU_SCP03_PROFILE` | available |
| `--keyset` | `APDU_KEYSET` | available |
| `--trust-store` | `APDU_TRUST_STORE` | reserved for SCP11 |
| `--manifest` | `APDU_DEPLOYMENT_MANIFEST` | reserved for deployment |
| session path | `APDU_SESSION_FILE` | available (default `session.json`) |

Environment variables only identify credential/keyset files; raw keys, PINs,
private-key passphrases, and other secret bytes are deliberately not accepted
through the environment. Operation targets and payloads (`--package-aid`,
`--module-aid`, `--instance-aid`, `--privileges`, `--params`, key version/ID,
input/output files) also stay explicit or belong in `deployment.toml`. This
avoids an old shell environment silently changing a mutation target.

## Output and scripting

The default is `--output human`. Every field is printed on its own line with a
comment. Data is blue, TL metadata is pink, success is green, and failures are
red:

```text
9F 70 01 # TL : tag 9F 70, length 1
07       # Data
90 00    # Status Word : Success
```

Human output first prints every command field, followed by the response fields.
The `INS` comment identifies known ISO 7816 and GlobalPlatform commands such as
`SELECT`, `GET RESPONSE`, `GET STATUS`, `STORE DATA`, and `INSTALL` variants.

`color` applies the same distinctions to a single uncommented raw line:

```bash
apdu-tool --output color raw 00 04 00 00 00 03
```

Quiet mode overrides the selected format and prints only raw hexadecimal bytes,
without color, comments, verbose output, or progress. A response includes its
status word:

```bash
apdu-tool --quiet raw 00 04 00 00 00 03
# Example stdout: 01 02 03 90 00
```

JSON mode provides a stable automation object containing the complete command:

```json
{"kind":"response","command":{"name":"application or proprietary APDU","cla":"00","ins":"04","p1":"00","p2":"00","lc":0,"le":3,"data":""},"data":"010203","length":3,"status_word":"9000","status":"Success","success":true}
```

Errors use `{"success":false,"error":"description"}`.

`bin` writes only useful response data to `stdout`, with no encoding, status
word, T=0 `NULL` bytes, verbose output, or progress:

```bash
apdu-tool --output bin raw 00 04 00 00 00 03 > response.bin
```

If the status word is not `9000`, it is written to `stderr` and the process
returns a non-zero status. `9000` adds nothing to `stderr`. There is deliberately
no `--allow-sw` option.

Reserved exit codes are:

```text
0   success, including SW=9000
1   unclassified internal error
2   invalid command line or APDU
10  connection failure
11  silent Secure Element
12  desynchronization
13  T=0 protocol error
14  Secure Channel error
15  failing status word
```

## Target operations

The functional target includes `SELECT`, `GET DATA`, `STORE DATA`, `GET STATUS`,
`SET STATUS`, `PUT KEY`, `DELETE`, `INSTALL [for load]`, `LOAD`,
`INSTALL [for install]`, `INSTALL [for install and make selectable]`, SCP03 and
SCP11a/b/c establishment, secured command and response processing, Card
Recognition Data and Card Capability Information discovery, and R-MAC session
management.

Other variants, including `INSTALL [for personalization]`,
`INSTALL [for make selectable]`, and `INSTALL [for extradition]`, should only
be exposed when Oxide SE actually implements their semantics. They are not
currently exposed because the kernel accepts only P1 `02` (`for load`) and P1
`0C` (`for install and make selectable`). The Oxide SE SCP03 profiles seed
R-MAC from `EXTERNAL AUTHENTICATE`; separate GlobalPlatform `BEGIN/END R-MAC
SESSION` commands are outside the profile and are therefore not emitted.
