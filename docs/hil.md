# Hardware-in-the-loop (HIL) harness

`tools/hil/` automates real-board validation: rig description, firmware
flashing, serial capture, scenario runs, and run reports. Serial controls
require `pyserial`; signed bundle verification requires `cryptography`.

**Hardware status:** the [2026-09-26 bench report](hil/2026-09-26-bench-5node.md)
records the first hardware run and its continuation. The bench contained
three C3s and two C6s; C6 was then an experimental HIL target (v2 makes it
a supported target built by every CI cell in `tools/ci/cells.json`). One C3 stopped enumerating, so the continuation exercised four
boards (two C3s, two C6s). A five-node run and C5 hardware comparison remain
unfinished. A C3 LegacyFixture deep-sleep replay fix passed a wake-and-deliver
cycle in the R3 continuation; DevRam/MemberEdhoc sleep remains open. The
[2026-09-26 fix report](hil/2026-09-26-fix-166-167.md) closes two of the
bench findings: the default C3 images now start with measured heap headroom
(issue #166, floors derived from the measurements) and delivery to a
reference node recovers after its reset (issue #167: ten resets × ten sends
on the C3 pair, every cycle recovered, first delivery 3.0–4.6 s after
release). MemberEdhoc node-to-node delivery passed, while the node's
authority channel still failed to reach the Site Authority. Harness
self-tests alone are not hardware validation.

## Concepts

- A **rig** is a named bench in `tools/hil/rigs.yaml`: boards mapped to
  serial-port globs, chip, firmware app, console type, reset method.
- Boards are identified by **role** (`bridge`, `reference`, …) rather than
  port path, so the same scenarios run on any bench wiring.
- Discovery is non-fatal: a bench whose ports are absent reports OFFLINE and
  scenarios emit SKIP-OFFLINE instead of crashing.

## Commands

```sh
# Resolve ports for a bench (read-only; --probe asks esptool for chip-id,
# which resets the board)
python3 tools/hil/rig.py --rig tools/hil/rigs.yaml --bench bench-a
python3 tools/hil/rig.py --rig tools/hil/rigs.yaml --bench bench-a --probe

# Flash a built firmware image to one board
python3 tools/hil/flash.py --rig tools/hil/rigs.yaml --bench bench-a \
    --board bridge --app-only

# Build a signed development bundle in the pinned ESP-IDF container, then flash it.
tools/hil/build_image.sh reference_node esp32c3 ref-a CONFIG_ROUTELOOM_NODE_ID=0x2
python3 tools/hil/flash.py --rig tools/hil/rigs.yaml --bench bench-a \
    --board ref-a --image-dir artifacts/hil/images/ref-a

# Capture a serial console (DTR asserted by default — required for the
# reference node's USB-Serial-JTAG console)
python3 tools/hil/capture.py --port /dev/cu.usbmodemXXXX --out run.log

# Reset a reference board N times and send M messages after each release:
# per-message outcome, reset-to-first-delivery time, IDEMPOTENCY_FULL count
# and the reference console captured on the same port (issue #167 evidence)
python3 tools/hil/reset_cycles.py --rig tools/hil/rigs.yaml --bench bench-a \
    --board ref-a --ctl host/target/debug/routeloomctl --socket /tmp/rl.sock \
    --destination 2 --cycles 10 --sends 10 --out artifacts/hil/reset-run

# The runner retries the host's two-per-minute admission limit within each
# 10-send cycle. A short cycle gap is sufficient when all ten sends are
# admitted sequentially; admission waiting is separate from delivery latency.
# The health file below comes from a concurrent observe_health.py process.
python3 tools/hil/analyze_reset_cycles.py \
    --result artifacts/hil/reset-run/result.json \
    --health artifacts/hil/reset-run/health-5s.jsonl --route-node 2 \
    --out artifacts/hil/reset-run/analysis.json

# With daemon/serial readers stopped, preflight every named board and pulse
# their reset lines as closely together as USB allows. Inspect reset skew
# and by-id re-enumeration in result.json.
python3 tools/hil/reset_all.py --rig tools/hil/rigs.yaml \
    --bench bench-2026-09-26-mixed5 --boards bridge ref-a ref-c ref-d \
    --out artifacts/hil/all-reset-run

# Each 100-send target gets a fresh, chip/MAC-pinned bridge boot. This stays
# below the gateway's per-boot idempotency history bound.
python3 tools/hil/unicast_campaign.py --rig tools/hil/rigs.yaml \
    --bench bench-2026-09-26-mixed5 --destinations 2 4 5 --count 100 \
    --daemon host/target/debug/routeloom-host \
    --ctl host/target/debug/routeloomctl \
    --acl artifacts/hil/2026-09-26-full/hil-acl.json \
    --socket /tmp/rl.sock --out artifacts/hil/unicast-run

# Compare host terminal results with a receiver's application log, matched
# by message session and sequence. A timeout can precede a late receipt.
python3 tools/hil/correlate_receipts.py \
    --traffic artifacts/hil/unicast-run/cycle-01-node4/traffic.jsonl \
    --console artifacts/hil/ref-c-console.log \
    --out artifacts/hil/node4-receipts.json

# After starting a diagnostic-capable bridge daemon, poll its live routes
# and record first authentication and first route to each requested NodeId.
# A connected learned route has next_hop and route_metric even when hops is
# null in the host view; the probe counts that as routable.
python3 tools/hil/route_convergence.py --ctl host/target/debug/routeloomctl \
    --socket /tmp/rl.sock --nodes 2 3 --seconds 90 \
    --out artifacts/hil/routes.jsonl

# The periodic console lines (stack hwm, owner counters, member/authority
# counters) need CONFIG_ROUTELOOM_TRACE=y; CONFIG_ROUTELOOM_HIL_HEAP_TELEMETRY=y
# also keeps the once-a-minute stack and owner lines.
# For a long run, pace accepted sends below the gateway's admission limit.
# Capture each reference console and poll adapter/nodes/events separately;
# then summarize delivery, routes, boot IDs, and heap trend.
python3 tools/hil/observe_health.py --ctl host/target/debug/routeloomctl \
    --socket /tmp/rl.sock --seconds 3800 --poll-s 30 \
    --out artifacts/hil/longrun/health-30s.jsonl &
python3 tools/hil/accepted_traffic.py --ctl host/target/debug/routeloomctl \
    --socket /tmp/rl.sock --destinations 2 3 4 5 --count 100 \
    --pace-s 37 --timeout-s 4000 --out artifacts/hil/longrun/traffic.jsonl
python3 tools/hil/analyze_longrun.py \
    --traffic artifacts/hil/longrun/traffic.jsonl \
    --health artifacts/hil/longrun/health-30s.jsonl \
    --console 2 artifacts/hil/longrun/node2-console.log \
    --out artifacts/hil/longrun/analysis.json

# With CONFIG_ROUTELOOM_HIL_EDHOC_TIMING=y, summarize on-device primitive
# and full-handshake durations from the captured reference consoles.
python3 tools/hil/analyze_edhoc.py \
    --console 2 artifacts/hil/member-node2-console.log \
    --console 4 artifacts/hil/member-node4-console.log \
    --out artifacts/hil/member-edhoc-times.json

# Build every firmware cell of tools/ci/cells.json (the sdk.yml matrix) in
# the pinned IDF container. The runner shares the local three-container cap;
# its JSON result records build output and each bundle carries a RAM report.
python3 tools/hil/build_ci_matrix.py \
    --out artifacts/hil/ci-matrix.json --jobs 3

# During MemberEdhoc joining or cutover, poll the Site Authority ledger,
# member states, group-key acknowledgements, and any known operation IDs.
python3 tools/hil/observe_site.py --socket /tmp/rl-site.sock \
    --seconds 1200 --poll-s 5 --out artifacts/hil/member-site-health.jsonl

# Keep a reference-node console open across deep-sleep USB disconnect and
# re-enumeration. The by-id path is pinned to the board's USB serial MAC.
python3 tools/hil/capture_reconnect.py \
    --port /dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_94:A9:90:7A:B5:60-if00 \
    --mac 94:a9:90:7a:b5:60 --seconds 300 \
    --out artifacts/hil/member-node2-sleep-console.log
python3 tools/hil/sleep_delivery_probe.py \
    --port /dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_94:A9:90:7A:B5:60-if00 \
    --mac 94:a9:90:7a:b5:60 --ctl host/target/debug/routeloomctl \
    --socket /tmp/rl-site.sock --node 2 --cycles 3 --seconds 900 \
    --out artifacts/hil/member-node2-wake-delivery.jsonl

# Read only the pinned board's rlsec partition. Raw NVS stays in a private
# mode-0700 directory outside the repo; --out contains counter metadata only.
python3 tools/hil/counter_snapshot.py --rig tools/hil/rigs.yaml \
    --bench bench-2026-09-26-mixed5 --board ref-a \
    --private-dir /tmp/routeloom-hil-private --label before-reset \
    --out artifacts/hil/ref-a-counters-before.json

# A deep-sleep image can expose USB for only ~0.2 s. This preloads esptool,
# checks sysfs serial/vendor/product and the USB interface path, then opens
# the matching tty immediately even when its ttyACM number changes.
# The same ROM connection reads chip/MAC and security before any flash write.
/home/sahur/.local/share/uv/tools/esptool/bin/python tools/hil/catch_wake.py \
    --rom-direct --port /dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_94:A9:90:7A:26:AC-if00 \
    --early-tty '/dev/ttyACM*' --usb-sysfs /sys/bus/usb/devices/1-4.2.3 \
    --chip esp32c3 --mac 94:a9:90:7a:26:ac \
    --image-dir artifacts/hil/2026-09-26/images/full-r1-node3-c3-recovery \
    --out artifacts/hil/node3-catch-wake

# Force a C3 1→2→3 chain without changing the normal radio configuration.
# These opt-in images discard only the other end's source MAC on reception;
# Node2 keeps its ordinary image and can BIND to both ends.
tools/hil/build_image.sh bridge_node esp32c3 c3-chain-bridge \
    'CONFIG_ROUTELOOM_CAPABILITY=0x47' \
    'CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="94:a9:90:7a:26:ac"'
tools/hil/build_image.sh reference_node esp32c3 c3-chain-node3 \
    'CONFIG_ROUTELOOM_NODE_ID=0x3' \
    'CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="94:a9:90:6a:ee:c4"'

# Run scenarios (all, or --scenario name repeatedly); --list shows names
python3 tools/hil/scenarios.py --rig tools/hil/rigs.yaml --bench bench-a \
    --out artifacts/hil/run-1
python3 tools/hil/report.py --run-dir artifacts/hil/run-1
```

The HIL flasher requires a full flash for signed bundles. Its app-only path
uses a local build and verifies the device's partition table first.

### Flash layout PT-4M-v2

Every image uses one 4 MB table (`firmware/*/partitions.csv`): NVS first
(`rlcfg` 0x12000, `rlkeys` 0x18000, `rlsec` 0x20000, 128 KiB), `otadata` at
0x10000 and the app in `ota_0` at 0x40000. A full flash writes bootloader,
table, `ota_data_initial.bin` and the app; `--app-only` writes `ota_0` and a
blank `otadata` so the board boots `ota_0`, after verifying the device already
has the same partition table. At boot the firmware checks that
the flash is at least 4 MB and that the table matches PT-4M-v2; otherwise it
logs `partition table is not PT-4M-v2` (or `flash smaller than PT-4M-v2`) and
never starts RF.
The `rlsec` backup, erase, restore and counter tools also compare the device
table with the current build's `partition_table/partition-table.bin` before
accessing offset 0x20000; rebuild the firmware first if that file is absent.

A board still on the old factory layout (app at 0x10000, `rlsec` at
0x190000) cannot be moved by an app write. Migrate it once:

1. Erase the whole flash: `esptool --chip <chip> --port <port> erase-flash`.
   This deletes the board identity, Site state and `rlcfg`/`rlkeys`.
2. Full flash of a PT-4M-v2 image (`tools/hil/flash.py` without
   `--app-only`, or Mesh Lab).
3. Provision the board again (BoardConfig, then Site join) as for a new
   board. Old `rlsec` backups do not restore onto the new offset.

`rig.py --selftest`, `scenarios.py --selftest` run dependency-free
self-checks usable in CI without hardware.

A boot capture that contains `BOOT_HEAP_BELOW_FLOOR` (the ESP-NOW runtime's
on-device heap check, `CONFIG_ROUTELOOM_BOOT_HEAP_FLOOR_BYTES`) or a
Wi-Fi/PHY allocation failure counts as a failed start: `flash.py` reports
the flash as failed and `reset_cycles.py` records the lines as
`boot_failures` and exits non-zero (issue #166).

## Built-in scenarios

| Scenario | Checks |
|---|---|
| `bind_2node` | bridge + reference reset → both reach BOUND + REACHABLE ≤ 60 s |
| `deliver_2node` | bound pair → host `send` ends `delivered`/`END_RECEIVED`, payload visible in the reference log |
| `restart_resume` | delivery, then reference-node reboot mid-session → re-BIND + deliver again |

## Hardware-only checks

Not verifiable on host — confirm on real boards per run:

- No tick wait from TX completion to the next submit (#60-3): measure
  the inter-submit gap and confirm back-to-back frames go out at the
  callback rate instead of riding out the 2 ms poll tick.

## Bench wiring notes

- macOS: match on `/dev/cu.usbmodem*` / `/dev/cu.usbserial-*` (never
  `/dev/tty.*` — it blocks on carrier). Linux: prefer
  `/dev/serial/by-id/*` for stable names. Tighten `port_globs` /
  `serial_hint` so each role resolves to exactly one device — an AMBIGUOUS
  board counts the bench OFFLINE.
- The bridge node's USB port carries the COBS host protocol — **never**
  point a log capture at it; its console is UART0 (see `rigs.yaml`
  comments). Bridge state is observed through the host daemon socket.
- USB-Serial-JTAG consoles emit nothing unless DTR is asserted — capture.py
  asserts it by default (`--no-dtr` opts out).

## Evidence

Each `scenarios.py` run writes `artifacts/hil/<run>/` with per-scenario
logs, daemon transcripts and a machine-readable summary; `report.py`
prints the roll-up. Scenario outcomes are PASS / FAIL / SKIP-OFFLINE —
a SKIP is reported, never silently omitted. Record bench composition
(boards, chips, firmware revs) in the run label (`--label`) so results are
attributable.
