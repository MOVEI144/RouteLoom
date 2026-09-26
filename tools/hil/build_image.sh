#!/usr/bin/env bash
# Bench entry point: use the same pinned scratch builder as CI and Mesh Lab.
set -euo pipefail
if (( $# < 3 )); then
  echo 'usage: build_image.sh APP CHIP LABEL [CONFIG_LINE ...]' >&2
  exit 2
fi
app=$1 chip=$2 label=$3
shift 3
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || { echo 'invalid label' >&2; exit 2; }
repo=$(cd "$(dirname "$0")/../.." && pwd)
"$repo/tools/meshviz/build_bundle.sh" "$app" "$chip" \
  "$repo/artifacts/hil/images/$label" \
  "$repo/tools/meshviz/packaging/dev-signing-key.pem" "hil-$label" "$@"
