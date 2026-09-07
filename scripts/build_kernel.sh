#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/build_kernel.sh [<kernelname.img>] [-o <kernelname.img>] [--target <targetname>] [--embedded_rustlet <rustlet.fae>] [--aid <aid>] [--security_domain <rustlet.fae>]

Build a bootable Oxide SE kernel image, copy it to the output image, and print
the QEMU command that can launch it.

Options:
  -o <kernelname.img>               Output image. Default: kernel_<targetname>.img
  --target <targetname>             Board/QEMU target. Default: mps2-an385
  --embedded_rustlet <rustlet.fae>  Embed a single prebuilt Rustlet FAE
                                    Default: build the kernel-only ping image
  --aid <aid>                       AID for --embedded_rustlet.
                                    Default: A0 00 00 00 00 11 25 04
                                    Accepted forms: A000000000112504, A0:00:..., "A0 00 ..."
  --security_domain <rustlet.fae>   Embed a root security domain FAE
                                    Default: use the kernel NullSecurityDomain
  -h, --help                        Show this help
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

output=""
target="mps2-an385"
embedded_rustlet=""
embedded_aid="A0 00 00 00 00 11 25 04"
security_domain=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      if [[ $# -lt 2 ]]; then
        echo "error: -o requires a value" >&2
        exit 2
      fi
      output="$2"
      shift 2
      ;;
    --target)
      if [[ $# -lt 2 ]]; then
        echo "error: --target requires a value" >&2
        exit 2
      fi
      target="$2"
      shift 2
      ;;
    --embedded_rustlet)
      if [[ $# -lt 2 ]]; then
        echo "error: --embedded_rustlet requires a value" >&2
        exit 2
      fi
      embedded_rustlet="$(abs_path "$2")"
      shift 2
      ;;
    --aid)
      if [[ $# -lt 2 ]]; then
        echo "error: --aid requires a value" >&2
        exit 2
      fi
      embedded_aid="$2"
      shift 2
      ;;
    --security_domain)
      if [[ $# -lt 2 ]]; then
        echo "error: --security_domain requires a value" >&2
        exit 2
      fi
      security_domain="$(abs_path "$2")"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -z "$output" ]]; then
        output="$1"
        shift
      else
        echo "error: unknown argument: $1" >&2
        usage >&2
        exit 2
      fi
      ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
if [[ -z "$output" ]]; then
  output="kernel_${target}.img"
fi
output_abs="$(abs_path "$output")"

if [[ -n "$embedded_rustlet" && ! -f "$embedded_rustlet" ]]; then
  echo "error: embedded Rustlet FAE does not exist: $embedded_rustlet" >&2
  exit 2
fi
if [[ -n "$security_domain" && ! -f "$security_domain" ]]; then
  echo "error: security domain FAE does not exist: $security_domain" >&2
  exit 2
fi

mkdir -p "$(dirname "$output_abs")"
cd "$repo_root"

normalize_aid_for_rust() {
  local value="$1"
  local compact
  compact="$(printf '%s' "$value" | sed 's/0[xX]//g' | tr -d '[:space:]:.-')"
  if [[ -z "$compact" || $(( ${#compact} % 2 )) -ne 0 ]]; then
    echo "error: invalid AID: $value" >&2
    exit 2
  fi
  if (( ${#compact} / 2 < 5 || ${#compact} / 2 > 16 )); then
    echo "error: invalid AID length for '$value' (expected 5..16 bytes)" >&2
    exit 2
  fi
  if [[ ! "$compact" =~ ^[0-9A-Fa-f]+$ ]]; then
    echo "error: invalid AID hex: $value" >&2
    exit 2
  fi

  local out=""
  local i
  for (( i=0; i<${#compact}; i+=2 )); do
    if [[ -n "$out" ]]; then
      out+=", "
    fi
    out+="0x${compact:i:2}"
  done
  printf '%s\n' "$out"
}

write_custom_embedded_registry() {
  local registry_path="$1"
  local aid_bytes="$2"
  cat >"$registry_path" <<EOF
register_embedded_rustlets! {
    {
        name: RUSTLET_MINIMAL_VALID_TEST,
        aid_const: RUSTLET_MINIMAL_VALID_TEST_AID,
        getter: rustlet_minimal_valid_test_fae,
        selected_cfg: oxide_se_embedded_only_rustlet_minimal_valid_test,
        crate_dir: "rustlets/tests/minimal_valid_test",
        bin_name: "rustlet_minimal_valid_test",
        env_var: "OXIDE_SE_SINGLE_EMBEDDED_RUSTLET_FAE_PATH",
        minimal: true,
        aid: [$aid_bytes],
    },
EOF

  if [[ -n "$security_domain" ]]; then
    cat >>"$registry_path" <<'EOF'
    {
        name: COMPLETE_SECURITY_DOMAIN,
        aid_const: COMPLETE_SECURITY_DOMAIN_AID,
        getter: complete_security_domain_fae,
        selected_cfg: oxide_se_embedded_only_complete_security_domain,
        crate_dir: "rustlets/complete_security_domain",
        bin_name: "complete_security_domain",
        env_var: "OXIDE_SE_COMPLETE_SECURITY_DOMAIN_FAE_PATH",
        minimal: false,
        aid: [0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x01],
    },
EOF
  fi

  cat >>"$registry_path" <<'EOF'
}
EOF
}

env_args=()
if [[ -z "$embedded_rustlet" ]]; then
  env_args+=("OXIDE_SE_BUILD_CONFIG=$repo_root/configs/config_kernel_ping.toml")
else
  env_args+=("OXIDE_SE_SINGLE_EMBEDDED_RUSTLET_FAE_PATH=$embedded_rustlet")
fi
if [[ -n "$security_domain" ]]; then
  env_args+=("OXIDE_SE_CUSTOM_SECURITY_DOMAIN_FAE_PATH=$security_domain")
fi

registry_path="$repo_root/kernel/firmware/src/embedded_apps_registry.inc.rs"
registry_backup=""
if [[ -n "$embedded_rustlet" ]]; then
  registry_backup="$(mktemp "${TMPDIR:-/tmp}/oxide-se-registry.XXXXXX")"
  cp "$registry_path" "$registry_backup"
  restore_registry() {
    if [[ -n "$registry_backup" && -f "$registry_backup" ]]; then
      cp "$registry_backup" "$registry_path"
      rm -f "$registry_backup"
    fi
  }
  trap restore_registry EXIT
  write_custom_embedded_registry "$registry_path" "$(normalize_aid_for_rust "$embedded_aid")"
fi

env "${env_args[@]}" cargo run bootable_qemu "$target"

kernel_fae="$repo_root/target/kernel/firmware/kernel.fae"
if [[ ! -f "$kernel_fae" ]]; then
  echo "error: expected kernel image was not produced: $kernel_fae" >&2
  exit 1
fi

cp "$kernel_fae" "$output_abs"

cat <<EOF
Built kernel image: $output_abs

QEMU command:
./scripts/run_kernel.sh "$output_abs" --target "$target"
EOF
