#!/usr/bin/env bash
# Build a bench image in the pinned ESP-IDF container and retain flash inputs.
set -euo pipefail

if (( $# < 3 )); then
  echo "usage: $0 APP TARGET LABEL [CONFIG_LINE ...]" >&2
  exit 2
fi
app=$1 target=$2 label=$3
shift 3
case "$app/$target" in
  reference_node/esp32c3|reference_node/esp32c5|bridge_node/esp32c3|bridge_node/esp32c5) ;;
  *) echo "unsupported app/target: $app/$target" >&2; exit 2 ;;
esac
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "invalid label" >&2; exit 2; }
extra=''
for line in "$@"; do
  case "$line" in
    CONFIG_ROUTELOOM_*=*|CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y|CONFIG_ESP_CONSOLE_UART_DEFAULT=n) ;;
    *) echo "option not allowed for this bench build: $line" >&2; exit 2 ;;
  esac
  extra+="$line"$'\n'
done
repo=$(cd "$(dirname "$0")/../.." && pwd)
out="$repo/artifacts/hil/2026-09-26/images/$label"
mkdir -p "$out"
work=$(mktemp -d /tmp/routeloom-hil-build.XXXXXX)
trap 'rm -rf "$work"' EXIT
rsync -a --exclude '.git' --exclude 'artifacts' --exclude 'build*' \
  --exclude 'host/target' "$repo/" "$work/src/"
printf '%s' "$extra" > "$out/extra-sdkconfig.txt"
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
  -e EXTRA="$extra" -v "$work/src:/src" -w "/src/firmware/$app" \
  espressif/idf:v6.0.3 bash -c '
    set -euo pipefail
    . "$IDF_PATH/export.sh" >/dev/null
    test "$(git -C "$IDF_PATH" rev-parse HEAD)" = \
      76f5dedd9950a3012fee8fb7d5586df21fc67802
    idf.py set-target '"$target"'
    printf "%s" "$EXTRA" >> sdkconfig
    idf.py build
    idf.py size --format json2 --output-file build/size.json
    python3 /src/tools/firmware_ram_report.py build/size.json \
      --target '"$target"' --app '"$app"' --cell hil \
      --json-out build/ram-report.json
  ' > "$out/build.log" 2>&1
cp "$work/src/firmware/$app/sdkconfig" "$out/sdkconfig"
while IFS= read -r requested; do
  [[ -z $requested ]] && continue
  applied=$requested
  if [[ $requested == *=n ]]; then
    applied="# ${requested%=n} is not set"
  fi
  if ! grep -Fqx "$applied" "$out/sdkconfig"; then
    echo "requested Kconfig option was not applied: $requested" >&2
    exit 1
  fi
done <<< "$extra"
if grep -Eq '^CONFIG_(SECURE_BOOT|SECURE_FLASH_ENC_ENABLED|FLASH_ENCRYPTION_ENABLED)=y$' "$out/sdkconfig"; then
  echo "refusing image with secure boot or flash encryption enabled" >&2
  exit 1
fi
mkdir -p "$out/build"
rsync -a --include='*/' --include='*.bin' --include='flasher_args.json' \
  --include='size.json' --include='ram-report.json' --exclude='*' \
  "$work/src/firmware/$app/build/" "$out/build/"
find "$out/build" -type f -print0 | sort -z | xargs -0 sha256sum > "$out/sha256sums.txt"
echo "built $app/$target -> $out"
