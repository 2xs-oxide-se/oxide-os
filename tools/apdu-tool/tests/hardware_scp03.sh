#!/usr/bin/env bash
set -euxo pipefail

# Ad-hoc SCP03 hardware transcript for the dedicated Pico 1 currently connected
# through CMSIS-DAP and /dev/cu.usbmodem21102. Running it erases the complete
# Pico flash, including the persistent registry.

cd "$(dirname "$0")/../../.."

# Build the firmware with the kernel-owned SCP03 S8 Security Domain.
cargo run -- build --config configs/config_scp03_test.toml raspi-pico1

# Build apdu-tool once so the commands below do not compile while the ATR is pending.
cargo build -p apdu_tool

# Write the public development keyset used by configs/config_scp03_test.toml.
umask 077
cat >/tmp/apdu-tool-scp03-s8.toml <<'EOF'
version = 1
id = 3
profile = "s8"
enc = "404142434445464748494A4B4C4D4E4F"
mac = "505152535455565758595A5B5C5D5E5F"
EOF

# Prepare a deliberately wrong keyset for the negative authentication test.
cat >/tmp/apdu-tool-scp03-bad-s8.toml <<'EOF'
version = 1
id = 3
profile = "s8"
enc = "004142434445464748494A4B4C4D4E4F"
mac = "005152535455565758595A5B5C5D5E5F"
EOF

# Open the UART before OpenOCD releases reset, otherwise the boot ATR is lost.
target/debug/apdu_tool --serial /dev/cu.usbmodem21102:115200 --atr-timeout infinite atr &

# Erase the dedicated Pico, program the SCP03 firmware, verify it, then boot it.
openocd \
  -f interface/cmsis-dap.cfg \
  -f target/rp2040.cfg \
  -c init \
  -c "reset init" \
  -c "flash erase_address 0x10000000 0x200000" \
  -c "flash write_image {target/kernel/firmware/kernel.elf}" \
  -c "verify_image {target/kernel/firmware/kernel.elf}" \
  -c "reset run" \
  -c shutdown

# Wait until the background apdu-tool has received and printed the ATR.
wait

# Establish SCP03 with C-MAC and read the card-recognition data.
target/debug/apdu_tool \
  --serial /dev/cu.usbmodem21102:115200 \
  --secure-channel scp03 \
  --scp03-profile s8 \
  --security-level c-mac \
  --keyset /tmp/apdu-tool-scp03-s8.toml \
  gp get-data 0066 --format tlv

# Establish SCP03 with C-MAC+C-ENC and write an encrypted registry object.
target/debug/apdu_tool \
  --serial /dev/cu.usbmodem21102:115200 \
  --secure-channel scp03 \
  --scp03-profile s8 \
  --security-level c-mac+c-enc \
  --keyset /tmp/apdu-tool-scp03-s8.toml \
  gp store-data DF11 --data 01020304

# Read the object through a fresh encrypted session; the expected result is
# "01 02 03 04" followed by status word "90 00".
target/debug/apdu_tool \
  --serial /dev/cu.usbmodem21102:115200 \
  --secure-channel scp03 \
  --scp03-profile s8 \
  --security-level c-mac+c-enc \
  --keyset /tmp/apdu-tool-scp03-s8.toml \
  --quiet \
  gp get-data DF11

# Exercise a composed operation: GET STATUS may issue several commands while
# retaining the same connection, session keys, counters and MAC chains.
target/debug/apdu_tool \
  --serial /dev/cu.usbmodem21102:115200 \
  --secure-channel scp03 \
  --scp03-profile s8 \
  --security-level c-mac \
  --keyset /tmp/apdu-tool-scp03-s8.toml \
  gp get-status issuer-security-domain

# A wrong static key must fail locally when the card cryptogram is verified.
! target/debug/apdu_tool \
  --serial /dev/cu.usbmodem21102:115200 \
  --secure-channel scp03 \
  --scp03-profile s8 \
  --security-level c-mac \
  --keyset /tmp/apdu-tool-scp03-bad-s8.toml \
  gp get-data 0066

# S16 framing against this S8 firmware must also be rejected.
! target/debug/apdu_tool \
  --serial /dev/cu.usbmodem21102:115200 \
  --secure-channel scp03 \
  --scp03-profile s16 \
  --security-level c-mac \
  --keyset /tmp/apdu-tool-scp03-s8.toml \
  gp get-data 0066

# Repeat the host-side validation with the kernel SCP03 S16 profile.
cargo run -- build --config configs/config_scp03_s16_test.toml raspi-pico1
cat >/tmp/apdu-tool-scp03-s16.toml <<'EOF'
version = 1
id = 3
profile = "s16"
enc = "404142434445464748494A4B4C4D4E4F"
mac = "505152535455565758595A5B5C5D5E5F"
EOF
target/debug/apdu_tool --serial /dev/cu.usbmodem21102:115200 --atr-timeout infinite atr &
openocd \
  -f interface/cmsis-dap.cfg \
  -f target/rp2040.cfg \
  -c init \
  -c "reset init" \
  -c "flash erase_address 0x10000000 0x200000" \
  -c "flash write_image {target/kernel/firmware/kernel.elf}" \
  -c "verify_image {target/kernel/firmware/kernel.elf}" \
  -c "reset run" \
  -c shutdown
wait

# Verify an encrypted S16 registry round trip.
target/debug/apdu_tool \
  --serial /dev/cu.usbmodem21102:115200 \
  --secure-channel scp03 \
  --scp03-profile s16 \
  --security-level c-mac+c-enc \
  --keyset /tmp/apdu-tool-scp03-s16.toml \
  gp store-data DF12 --data A1B2C3D4
target/debug/apdu_tool \
  --serial /dev/cu.usbmodem21102:115200 \
  --secure-channel scp03 \
  --scp03-profile s16 \
  --security-level c-mac+c-enc \
  --keyset /tmp/apdu-tool-scp03-s16.toml \
  --quiet \
  gp get-data DF12

# Build and boot the delegated Rustlet Security Domain.
cargo run -- build \
  --config configs/config_rustlet_security_domain_delegated_scp03_test.toml \
  raspi-pico1
target/debug/apdu_tool --serial /dev/cu.usbmodem21102:115200 --atr-timeout infinite atr &
openocd \
  -f interface/cmsis-dap.cfg \
  -f target/rp2040.cfg \
  -c init \
  -c "reset init" \
  -c "flash erase_address 0x10000000 0x200000" \
  -c "flash write_image {target/kernel/firmware/kernel.elf}" \
  -c "verify_image {target/kernel/firmware/kernel.elf}" \
  -c "reset run" \
  -c shutdown
wait

# Select the Rustlet Security Domain and exercise its S16 level-33 response:
# C-MAC, C-ENC, R-MAC and R-ENC. Le=29 requests the lifecycle response.
target/debug/apdu_tool \
  --serial /dev/cu.usbmodem21102:115200 \
  --secure-channel scp03 \
  --security-domain A0000047504F5304 \
  --scp03-profile s16 \
  --security-level c-mac+c-enc+r-mac+r-enc \
  --keyset /tmp/apdu-tool-scp03-s16.toml \
  raw 80 CA 9F 70 00 29

# Run the exhaustive target-side S8/S16 rejection campaign: bad cryptograms,
# unknown/rotated keysets, stale chains, missing/bad MAC and command replay.
cargo run -- test gp_scp03 raspi-pico1 \
  --on openocd \
  --serial /dev/cu.usbmodem21102:115200 \
  --allow-destructive \
  --scp03=all \
  --without-rustlets

# Remove the temporary copies of the public development keys.
rm -f \
  /tmp/apdu-tool-scp03-s8.toml \
  /tmp/apdu-tool-scp03-bad-s8.toml \
  /tmp/apdu-tool-scp03-s16.toml

echo "HARDWARE-SCP03-DONE"
