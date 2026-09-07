#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

BOARD="mps2-an385"
IMAGE="$REPO_ROOT/target/kernel/firmware/kernel.elf"
HOST="127.0.0.1"
PORT="4444"
WAIT="on"

print_usage() {
    cat <<EOF
Usage: run-qemu-serial.sh [--host HOST] [--port PORT] [--wait on|off] [BOARD] [IMAGE]

Defaults:
  BOARD = mps2-an385
  IMAGE = target/kernel/firmware/kernel.elf
  HOST  = 127.0.0.1
  PORT  = 4444
  WAIT  = on

Examples:
  ./tools/bin/run-qemu-serial.sh
  ./tools/bin/run-qemu-serial.sh olimex-stm32-h405
  ./tools/bin/run-qemu-serial.sh mps2-an385 ./target/kernel/firmware/kernel.elf
  ./tools/bin/run-qemu-serial.sh --port 5555
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --help)
            print_usage
            exit 0
            ;;
        --host)
            HOST="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --wait)
            WAIT="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Unknown option: $1" >&2
            print_usage >&2
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

if [ "$#" -ge 1 ]; then
    BOARD="$1"
    shift
fi

if [ "$#" -ge 1 ]; then
    IMAGE="$1"
    shift
fi

if [ "$#" -ne 0 ]; then
    echo "Too many positional arguments" >&2
    print_usage >&2
    exit 1
fi

case "$BOARD" in
    mps2-an385|olimex-stm32-h405|b-l475e-iot01a|raspi-pico1)
        ;;
    *)
        echo "Unsupported board: $BOARD" >&2
        exit 1
        ;;
esac

case "$WAIT" in
    on|off)
        ;;
    *)
        echo "Invalid --wait value: $WAIT (expected 'on' or 'off')" >&2
        exit 1
        ;;
esac

QEMU_MACHINE="$BOARD"
if [ "$BOARD" = "raspi-pico1" ]; then
    QEMU_MACHINE="raspi-pico"
fi

exec qemu-system-arm \
    -machine "$QEMU_MACHINE" \
    -nographic \
    -monitor none \
    -serial "tcp:${HOST}:${PORT},server=on,wait=${WAIT}" \
    -semihosting-config enable=on,target=native \
    -kernel "$IMAGE"
