#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/run_kernel.sh <kernelname.img> [--target <target_name>] [--host <host>] [--port <port>] [--wait on|off]

Run a bootable Oxide SE kernel image with QEMU and expose the APDU serial
T=0 link over TCP.

Options:
  --target <target_name>  Board/QEMU target. Default: mps2-an385
  --host <host>           Serial TCP host. Default: 127.0.0.1
  --port <port>           Serial TCP port. Default: 1234
  --wait <on|off>         QEMU serial wait mode. Default: on
  -h, --help             Show this help
USAGE
}

abs_path() {
  local path="$1"
  local dir
  local base
  dir="$(cd "$(dirname "$path")" && pwd -P)"
  base="$(basename "$path")"
  printf '%s/%s\n' "$dir" "$base"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 2
fi

kernel_img="$(abs_path "$1")"
shift
target="mps2-an385"
host="127.0.0.1"
port="4444"
wait_mode="on"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      if [[ $# -lt 2 ]]; then
        echo "error: --target requires a value" >&2
        exit 2
      fi
      target="$2"
      shift 2
      ;;
    --host)
      if [[ $# -lt 2 ]]; then
        echo "error: --host requires a value" >&2
        exit 2
      fi
      host="$2"
      shift 2
      ;;
    --port)
      if [[ $# -lt 2 ]]; then
        echo "error: --port requires a value" >&2
        exit 2
      fi
      port="$2"
      shift 2
      ;;
    --wait)
      if [[ $# -lt 2 ]]; then
        echo "error: --wait requires a value" >&2
        exit 2
      fi
      wait_mode="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$kernel_img" ]]; then
  echo "error: kernel image does not exist: $kernel_img" >&2
  exit 2
fi

case "$wait_mode" in
  on|off) ;;
  *)
    echo "error: --wait must be 'on' or 'off'" >&2
    exit 2
    ;;
esac

exec qemu-system-arm \
  -machine "$target" \
  -nographic \
  -monitor none \
  -serial "tcp:${host}:${port},server=on,wait=${wait_mode}" \
  -semihosting-config enable=on,target=native \
  -kernel "$kernel_img"
