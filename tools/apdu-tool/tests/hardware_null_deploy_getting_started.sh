#!/usr/bin/env bash
set -euxo pipefail

# Ad-hoc, linear Pico 1 transcript. Each apdu-tool line can be copied into a
# terminal manually. This test erases the complete Pico flash and registry.

cd "$(dirname "$0")/../../.."

# Build the smallest delivered Pico 1 image: only the NullSecurityDomain, with
# no predeployed Rustlet and no Secure Channel protocol.
cargo run -- build --config configs/config_noscp_test.toml raspi-pico1

# Build apdu-tool before waiting for the ATR, so compilation cannot make us
# miss bytes emitted immediately after reset.
cargo build -p apdu_tool

# Open the serial link first. The command creates session.json after receiving
# the ATR; subsequent commands recover the link from that session file.
target/debug/apdu_tool \
  --serial /dev/cu.usbmodem21102:115200 \
  --connect-timeout 120s \
  --atr-timeout infinite \
  atr &

# Erase, program, verify, and start the dedicated Pico 1. OpenOCD releasing
# reset causes Oxide SE to emit the ATR awaited by the background command.
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

# Do not send an APDU until apdu-tool has captured and displayed the ATR.
wait

# Build getting_started_test as a Pico 1 (ARMv6-M) FAE payload. The kernel
# image above does not contain this Rustlet: it will be loaded dynamically.
cd rustlets/tests
RUSTLET_TARGET=thumbv6m-none-eabi cargo run -- build-fae getting_started_test
cd ../..

# INSTALL [for load], transfer every LOAD block, then INSTALL [for install and
# make selectable]. The package/module and instance use the tutorial AID.
target/debug/apdu_tool --progress gp deploy \
  A0000047504F5320 \
  rustlets/tests/getting_started_test/build/rustlet_getting_started_test.fae \
  A0000047504F5320

# Select the dynamically installed instance by application AID.
target/debug/apdu_tool select A0000047504F5320

# Accept an APDU with no incoming or outgoing application data.
target/debug/apdu_tool raw 00:00:00:00:00:00

# Receive three bytes and return only a success status word.
target/debug/apdu_tool raw 00:02:00:00:03:00:AA:BB:CC

# Return the fixed three-byte response 10 11 12.
target/debug/apdu_tool raw 00:04:00:00:00:03

# Receive data and return the fixed response AA BB CC.
target/debug/apdu_tool raw 00:06:00:00:03:03:01:02:03

# Echo the four incoming bytes; the expected response is DE AD BE EF 90 00.
target/debug/apdu_tool raw 00:08:00:00:04:04:DE:AD:BE:EF

# End local tracking and remove session.json.
target/debug/apdu_tool close

echo "HARDWARE-NULL-DEPLOY-GETTING-STARTED-DONE"
