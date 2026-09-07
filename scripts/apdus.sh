#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/apdus [--host <host>] [--port <port>] [install <aid> | select <aid> | cla ins p1 p2 ln [data...]]

Send one APDU over the QEMU serial T=0 TCP link using the verbose APDU tool.
Without a command, it connects and prints the ATR.

Defaults:
  host = 127.0.0.1
  port = 4444

Shortcuts:
  install <package-aid> [instance-aid]
                 Send GlobalPlatform INSTALL [for install and make selectable].
                 The package AID is also used as applet AID. If instance-aid
                 is omitted, it defaults to package-aid.
  select <aid>   Send SELECT by AID.

Raw APDU form:
  cla ins p1 p2 ln
      Sends an outgoing/no-data APDU with Le=ln.
  cla ins p1 p2 ln data...
      Sends an incoming APDU with Lc=ln and the provided data bytes.

Examples:
  scripts/apdus.sh
  scripts/apdus.sh select A0:00:00:00:00:11:25:04
  scripts/apdus.sh install A000000000112504
  scripts/apdus.sh install A000000000112504 A000000000112505
  scripts/apdus.sh 00 00 00 00 00
  scripts/apdus.sh 00 04 00 00 03 AA BB CC
USAGE
}

hex_bytes() {
  local value="$1"
  local compact
  compact="$(printf '%s' "$value" | sed 's/0[xX]//g' | tr -d '[:space:]:.-')"
  if [[ -z "$compact" || $(( ${#compact} % 2 )) -ne 0 || ! "$compact" =~ ^[0-9A-Fa-f]+$ ]]; then
    echo "error: invalid hex bytes: $value" >&2
    exit 2
  fi

  local bytes=()
  local i
  for (( i=0; i<${#compact}; i+=2 )); do
    bytes+=("${compact:i:2}")
  done
  printf '%s\n' "${bytes[@]}"
}

aid_bytes() {
  local bytes=()
  local byte
  while IFS= read -r byte; do
    bytes+=("$byte")
  done < <(hex_bytes "$1")
  if (( ${#bytes[@]} < 5 || ${#bytes[@]} > 16 )); then
    echo "error: invalid AID length for '$1' (expected 5..16 bytes)" >&2
    exit 2
  fi
  printf '%s\n' "${bytes[@]}"
}

byte_count_hex() {
  printf '%02X\n' "$1"
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"

tool="${GPOS_APDU_TOOL:-}"
tool_cmd=()
if [[ -n "$tool" ]]; then
  tool_cmd=("$tool")
else
  if command -v gpos_apdu_tool >/dev/null 2>&1; then
    tool_cmd=(gpos_apdu_tool)
  else
    tool_cmd=(cargo run --manifest-path "$repo_root/Cargo.toml" -p apdu_tool --)
  fi
fi

host="127.0.0.1"
port="4444"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --host)
      if [[ $# -lt 2 ]]; then
        echo "error: --host requires a value" >&2
        exit 2
      fi
      host="$2"
      shift 2
      ;;
    --port|-p)
      if [[ $# -lt 2 ]]; then
        echo "error: --port requires a value" >&2
        exit 2
      fi
      port="$2"
      shift 2
      ;;
    *)
      break
      ;;
  esac
done

tool_args=(--verbose --host "$host" --port "$port")

if [[ $# -eq 0 ]]; then
  exec "${tool_cmd[@]}" "${tool_args[@]}"
fi

case "$1" in
  install)
    if [[ $# -lt 2 || $# -gt 3 ]]; then
      echo "error: install expects package AID and optional instance AID" >&2
      usage >&2
      exit 2
    fi
    package_aid=()
    while IFS= read -r byte; do
      package_aid+=("$byte")
    done < <(aid_bytes "$2")

    instance_source="${3:-$2}"
    instance_aid=()
    while IFS= read -r byte; do
      instance_aid+=("$byte")
    done < <(aid_bytes "$instance_source")

    package_aid_len="$(byte_count_hex "${#package_aid[@]}")"
    instance_aid_len="$(byte_count_hex "${#instance_aid[@]}")"
    data=(
      "$package_aid_len" "${package_aid[@]}"
      "$package_aid_len" "${package_aid[@]}"
      "$instance_aid_len" "${instance_aid[@]}"
      01 00
      00
    )
    exec "${tool_cmd[@]}" "${tool_args[@]}" 80 E6 0C 00 "$(byte_count_hex "${#data[@]}")" 00 "${data[@]}"
    ;;
  select)
    if [[ $# -ne 2 ]]; then
      echo "error: select expects exactly one AID" >&2
      usage >&2
      exit 2
    fi
    aid=()
    while IFS= read -r byte; do
      aid+=("$byte")
    done < <(aid_bytes "$2")
    exec "${tool_cmd[@]}" "${tool_args[@]}" 00 A4 04 00 "$(byte_count_hex "${#aid[@]}")" 00 "${aid[@]}"
    ;;
  *)
    if [[ $# -lt 5 ]]; then
      echo "error: raw APDU expects at least cla ins p1 p2 ln" >&2
      usage >&2
      exit 2
    fi
    cla="$1"
    ins="$2"
    p1="$3"
    p2="$4"
    ln="$5"
    shift 5
    if [[ $# -eq 0 ]]; then
      exec "${tool_cmd[@]}" "${tool_args[@]}" "$cla" "$ins" "$p1" "$p2" 00 "$ln"
    fi
    exec "${tool_cmd[@]}" "${tool_args[@]}" "$cla" "$ins" "$p1" "$p2" "$ln" 00 "$@"
    ;;
esac
