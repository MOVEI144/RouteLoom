# Hardware-in-the-loop (HIL) harness

`tools/hil/` automates real-board validation: rig description, firmware
flashing, serial capture, scenario runs, and run reports. Serial controls
require `pyserial`; signed bundle verification requires `cryptography`.

**Hardware status:** the [2026-09-26 bench report](hil/2026-09-26-bench-5node.md)
records the first hardware run and its continuation. The bench contained
three C3s and two C6s; C6 was then an experimental HIL target (v2 makes it
a supported target built by every CI cell in `tools/ci/cells.json`). One C3 stopped enumerating, so the continuation exercised four
boards (two C3s, two C6s). A five-node run and C5 hardware comparison remain
unfinished. A C3 deep-sleep replay fix for the since-removed dev-PSK fixture
profile passed a wake-and-deliver cycle in the R3 continuation;
DevRam/MemberEdhoc sleep remains open. The
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

The shared E2E catalog has a hardware-free [scenario plan loader](development/e2e.md#hil-plans).
Its `--dry-run <id>` checks board roles and chips without opening serial ports.


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
    'CONFIG_ROUTELOOM_CAPABILITY=0x47' 'CONFIG_ROUTELOOM_USB_NODE_STATUS=y' \
    'CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="94:a9:90:7a:26:ac"'
tools/hil/build_image.sh reference_node esp32c3 c3-chain-node3 \
    'CONFIG_ROUTELOOM_NODE_ID=0x3' \
    'CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="94:a9:90:6a:ee:c4"'

# Run scenarios (all, or --scenario name repeatedly); --list shows names
python3 tools/hil/scenarios.py --rig tools/hil/rigs.yaml --bench bench-a \
    --out artifacts/hil/run-1
python3 tools/hil/report.py --run-dir artifacts/hil/run-1
```

For larger forced topologies, generate source-MAC allow-lists without accessing
hardware:

```sh
python3 tools/hil/topology.py line7 boards.csv --out artifacts/hil/line7
```

The ordered CSV columns are `name,by_id,mac,chip,app,probe_mac`. `by_id` is a
literal `/dev/serial/by-id/…` path; `mac` is the **six-byte Wi-Fi STA MAC** used
by ESP-NOW. `probe_mac` is the esptool `chip-id` identity: mandatory eight-byte
EUI-64 for C6, optional for C3/S3 (defaults to `mac`). Supported chips are
C3/C6/S3; apps are `bridge_node`, `reference_node`, `bench_node`. For example:

```csv
name,by_id,mac,chip,app,probe_mac
gateway,/dev/serial/by-id/board-a,02:00:00:00:00:01,esp32c3,bridge_node,
relay,/dev/serial/by-id/board-b,02:00:00:00:00:02,esp32c6,reference_node,02:00:00:ff:fe:00:00:02
```

Supply seven rows for `line7` (line order), four for `diamond` (G/R1/R2/E),
or 2–9 for `star` (center first; seven rows use all seven boards). Every edge
is enabled in both directions; all other senders are discarded before either
RLD1 or Wire processing, including broadcast. `CONFIG_ROUTELOOM_HIL_RX_ALLOW_MACS`
accepts up to eight comma-separated MACs, parses at compile time, rejects bad
syntax at build time, and compiles away when empty. Existing `DROP_RX_MAC`
still applies afterward; use fresh images without an old drop override.
The output contains per-board `.sdkconfig` overlays, a flasher-compatible
`rig.json`, and `STEPS.md` with build and manual flash commands. Preserve the
site's role/profile overrides and provisioning. Only flash in a separately
authorized hardware round with the existing preflight and port reservation;
generation performs no build or flash. This simulates adjacency, not RF range.

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
2. Full flash of the PT-4M-v2 **setup image** (same chip, role and
   security as the field image, `CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE=y`).
3. Commit the BoardConfig (`benchcfg`/`benchsecret`, then the identity for
   MemberEdhoc) on the setup console and read it back.
4. Write the field image with `--app-only` (or Mesh Lab), then join the
   Site as for a new board. Old `rlsec` backups do not restore onto the new
   offset.

A field image on a board without BoardConfig logs `CONFIG_REQUIRED: board
configuration required` every 10 s and waits awake with RF off, so the
setup image can still be written over USB; it never enters the fail
back-off. `flash.py` refuses to full-flash a signed field bundle (generic
BoardConfig image without the maintenance console) onto a board whose
`rlcfg` partition is blank; `--allow-unconfigured` overrides.

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

## Indoor weak-link campaign

This procedure injects receive loss; it does not measure outdoor range or
attenuate RF. Use the chip/MAC preflight and provisioning rules above. Do
not write eFuses or enable secure boot/flash encryption. Run only in a
separately authorised hardware round; this PR does not flash boards.

Use a gateway, relay and endpoint with the normal security profile and
provisioned identities. Force two hops with the paired
`CONFIG_ROUTELOOM_HIL_DROP_RX_MAC` images above. Keep channel, LR rate,
placement, antennas, admission policy and payload fixed. On all three
boards set TX power to **8 qdBm (2 dBm)**. Measure an unfiltered control
(`RX_MIN_RSSI=0`, `RX_DROP_PERMILLE=0`) and these six conditions:

| RX minimum RSSI (dBm) | Random RX loss (‰) |
| --- | --- |
| -80 | 0 |
| -80 | 100 |
| -80 | 200 |
| -85 | 0 |
| -85 | 100 |
| -85 | 200 |

Build labelled images for each board/condition with `build_image.sh`;
these overrides work for C3 and C6. For example, for the relay:

```sh
tools/hil/build_image.sh reference_node esp32c3 lr-relay-r80-d100 \
    CONFIG_ROUTELOOM_TX_POWER_QDBM=8 \
    CONFIG_ROUTELOOM_HIL_RX_MIN_RSSI=-80 \
    CONFIG_ROUTELOOM_HIL_RX_DROP_PERMILLE=100 \
    CONFIG_ROUTELOOM_HIL_HEAP_TELEMETRY=y
python3 tools/hil/flash.py --rig tools/hil/rigs.yaml --bench bench-a \
    --board ref-a --image-dir artifacts/hil/images/lr-relay-r80-d100
```

Signed bundles require the complete flash layout. On an already provisioned
PT-4M-v2 board, this writes bootloader, partition table, otadata and app without
erasing the NVS partitions. Keep the chip, role and security profile unchanged;
do not erase between conditions.

Capture each reference console and the gateway's separate UART0 console
if wired; never open the bridge USB host-protocol port for log capture.
Retain source SHA, image/sdkconfig hashes, chip/MAC/role, condition and
actual TX power. With the provisioned daemon and approval observer running,
record join attempts and time to Authority-confirmed membership, including
failed attempts. Then collect steady traffic and relay-reset evidence:

```sh
python3 tools/hil/observe_health.py --ctl "$CTL" --socket "$SOCKET" \
    --seconds 900 --poll-s 1 --out "$OUT/health.jsonl" &
python3 tools/hil/submit_traffic.py --ctl "$CTL" --socket "$SOCKET" \
    --network "$NETWORK" --epoch "$EPOCH" --destination "$ENDPOINT" \
    --count 100 --out "$OUT/traffic.jsonl"
# Stop the relay console capture before reset_cycles owns that port.
python3 tools/hil/reset_cycles.py --rig tools/hil/rigs.yaml --bench bench-a \
    --board ref-a --ctl "$CTL" --socket "$SOCKET" --destination "$ENDPOINT" \
    --cycles 3 --sends 10 --out "$OUT/relay-reset"
python3 tools/hil/analyze_reset_cycles.py --result "$OUT/relay-reset/result.json" \
    --health "$OUT/health.jsonl" --route-node "$ENDPOINT" \
    --out "$OUT/relay-reset/analysis.json"
```

Set `CTL`, `SOCKET`, `NETWORK`, `EPOCH`, decimal `ENDPOINT` and a unique
`OUT`; map `ref-a` to the relay in the chosen rig. `reset_cycles.py`
captures the relay console itself; stop its separate capture first.
Keep health and endpoint capture running for the whole reset sequence,
extending the 900 s window if admission waits require it. Record these
per condition:

- **RSSI and injected loss:** once a minute `HIL RX` reports cumulative
  `rssi_dropped` and `random_dropped`; `HIL RSSI` gives sixteen 8 dBm bins
  from [-128, -121] to [-8, -1]. Use the last complete snapshot per boot,
  or differences within one boot; never add successive cumulative snapshots.
  RSSI is clamped to [-128, -1] and includes rejected frames after
  source-MAC exclusion. Missing RX metadata is counted separately and
  bypasses only RSSI rejection. Random
  loss applies to frames remaining after RSSI rejection. Check that the
  RSSI threshold drops frames; otherwise label it inactive for this
  placement. Intentional drops do not increment RX queue-overflow counters.
- **Delivery and p99 latency:** retain all requested/admitted/terminal
  counts and `success_rate`, `admitted`, `delivered`, `rtt_ms_p99` from the
  traffic summary. p99 is admission-to-receipt host latency of successful
  sends; report admission waits and failures/timeouts separately.
- **Route flap:** count route up/down transitions and endpoint `next_hop`
  changes between consecutive valid health snapshots. Query failures are
  unknown; report missing samples and the poll interval. Shorter flaps can
  be missed, so retain discovery/route console lines too.
- **Relay-reset recovery:** retain every `cycle_results[].recovery_s`
  (release to first endpoint delivery), including null/non-recovery and
  boot failures. State whether reset was EN or actual power removal.

Publish numbers and failures in a dated `docs/hil/` record; do not infer a
distance or mark skipped conditions as passed. Restore default images
(both filters zero) afterward. Default cells must pass the `symbols_absent`
gate for `EspNowRuntime::hil_drop_rx` and `hil_log_rx`; compare default
flash/static RAM before and after changes.

## Evidence

Each `scenarios.py` run writes `artifacts/hil/<run>/` with per-scenario
logs, daemon transcripts and a machine-readable summary; `report.py`
prints the roll-up. Scenario outcomes are PASS / FAIL / SKIP-OFFLINE —
a SKIP is reported, never silently omitted. Record bench composition
(boards, chips, firmware revs) in the run label (`--label`) so results are
attributable.
