#!/usr/bin/env bash
# Build/export in a disposable copy; never run idf.py against the checkout.
set -euo pipefail
if (( $# < 5 )); then
  echo 'usage: build_bundle.sh APP CHIP OUTPUT_DIR DEV_KEY VERSION [CONFIG_LINE ...]' >&2
  exit 2
fi
app=$1 chip=$2 out=$3 key=$4 version=$5
shift 5
case "$app/$chip" in
  reference_node/esp32c3|reference_node/esp32s3|reference_node/esp32c5|reference_node/esp32c6|bridge_node/esp32c3|bridge_node/esp32s3|bridge_node/esp32c5|bridge_node/esp32c6) ;;
  *) echo 'unsupported app/chip' >&2; exit 2 ;;
esac
[[ ! -e $out ]] || { echo 'output already exists' >&2; exit 2; }
extra=''
for line in "$@"; do
  [[ $line =~ ^CONFIG_ROUTELOOM_[A-Z0-9_]+=(y|n|[0-9]+|0x[0-9a-fA-F]+)$ ||
     $line == 'CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y' ||
     $line == 'CONFIG_ESP_CONSOLE_UART_DEFAULT=n' ]] || {
    echo 'unsupported or unsafe Kconfig override' >&2; exit 2;
  }
  [[ $line != *SECURE_BOOT* && $line != *FLASH_ENCRYPT* && $line != *EFUSE* ]] || {
    echo 'security fuse override forbidden' >&2; exit 2;
  }
  extra+="$line"$'\n'
done
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/routeloom-bundle.XXXXXX)
trap 'rm -rf "$work"' EXIT
# Exclude generated sdkconfig, build output, private credentials and archives.
rsync -a --exclude='.git' --exclude='artifacts/' --exclude='build*/' \
  --exclude='sdkconfig' --exclude='sdkconfig.old' --exclude='host/target' \
  --exclude='__pycache__/' --exclude='*.pyc' --exclude='*.egg-info/' \
  --exclude='.venv/' --exclude='dist/' \
  "$repo/" "$work/src/"
source_digest=$(python3 - "$work/src" <<'PY'
import hashlib
from pathlib import Path
import sys
root = Path(sys.argv[1])
h = hashlib.sha256()
for path in sorted(root.rglob('*')):
    if path.is_symlink():
        raise SystemExit(f'symlink input is not allowed: {path.relative_to(root)}')
    if path.is_file():
        h.update(path.relative_to(root).as_posix().encode() + b'\0')
        h.update(hashlib.sha256(path.read_bytes()).digest())
print(h.hexdigest())
PY
)
sdk_commit=$(git -C "$repo" rev-parse HEAD)
idf_image=$(PYTHONPATH="$work/src/tools/meshviz/src" python3 -c \
  'from routeloom_meshviz.firmware_catalog import IDF_IMAGE; print(IDF_IMAGE)')
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e EXTRA="$extra" \
  -v "$work/src:/src" -w "/src/firmware/$app" "$idf_image" bash -c '
    set -euo pipefail
    . "$IDF_PATH/export.sh" >/dev/null
    test "$(git -C "$IDF_PATH" rev-parse HEAD)" = 76f5dedd9950a3012fee8fb7d5586df21fc67802
    idf.py set-target '"$chip"'
    printf "%s" "$EXTRA" >> sdkconfig
    idf.py build
    idf.py size --format json2 --output-file build/size.json
    python3 /src/tools/firmware_ram_report.py build/size.json \
      --target '"$chip"' --app '"$app"' --cell local --json-out build/ram-report.json
  '
for line in "$@"; do
  applied=$line
  [[ $line != *=n ]] || applied="# ${line%=n} is not set"
  grep -Fqx "$applied" "$work/src/firmware/$app/sdkconfig" || {
    echo "Kconfig override not applied: $line" >&2; exit 1;
  }
done
PYTHONPATH="$work/src/tools/meshviz/src" python3 -m routeloom_meshviz.firmware_catalog package \
  "$work/src/firmware/$app" "$work/src/firmware/$app/build" "$out" "$key" \
  "$chip" "$app" "$version" "$sdk_commit" "$source_digest"
echo "bundle: $out"
