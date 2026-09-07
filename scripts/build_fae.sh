#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/build_fae.sh <path_to_rustlet_dir> -o <rustlet.fae>

Build a Rustlet crate as a FAE image and copy it to the requested output path.

Options:
  -o <rustlet.fae>  Output FAE path
  -h, --help        Show this help
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

package_name() {
  awk '
    /^\[/{ in_package = ($0 == "[package]") }
    in_package && $1 == "name" {
      value = $0
      sub(/^[^=]*=/, "", value)
      gsub(/[ "]/, "", value)
      print value
      exit
    }
  ' "$1"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 2
fi

rustlet_dir="$1"
shift
output=""

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

if [[ -z "$output" ]]; then
  echo "error: missing required -o <rustlet.fae>" >&2
  usage >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
rustlet_dir_abs="$(abs_path "$rustlet_dir")"
output_abs="$(abs_path "$output")"
manifest="$rustlet_dir_abs/Cargo.toml"

if [[ ! -f "$manifest" ]]; then
  echo "error: Rustlet manifest not found: $manifest" >&2
  exit 2
fi

bin_name="$(package_name "$manifest")"
if [[ -z "$bin_name" ]]; then
  echo "error: could not determine package name from $manifest" >&2
  exit 2
fi

mkdir -p "$(dirname "$output_abs")"
cd "$repo_root"

cargo run --manifest-path tooling/build-fae/Cargo.toml --bin build_fae_rust -- \
  --manifest-path "$manifest" \
  --bin "$bin_name" \
  --align_size 2048 \
  --fae

built_fae="$rustlet_dir_abs/build/$bin_name.fae"
if [[ ! -f "$built_fae" ]]; then
  echo "error: expected FAE was not produced: $built_fae" >&2
  exit 1
fi

cp "$built_fae" "$output_abs"
echo "Built Rustlet FAE: $output_abs"
