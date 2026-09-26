# Hardware-in-the-loop (HIL) harness

`tools/hil/` automates real-board validation: rig description, firmware
flashing, serial capture, scenario runs, and run reports. Serial controls
require `pyserial`; read-only reports and many self-checks use the standard
library.

**Hardware status:** the [2026-09-26 bench report](hil/2026-09-26-bench-5node.md)
records the first hardware run and its continuation. The bench contained
three C3s and two C6s; C6 is an experimental HIL target outside the SDK v1
support list. One C3 stopped enumerating, so the continuation exercised four
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

# Build an isolated image in ESP-IDF v6.0.3, then flash its saved inputs.
tools/hil/build_image.sh reference_node esp32c3 ref-a CONFIG_ROUTELOOM_NODE_ID=0x2
python3 tools/hil/flash.py --rig tools/hil/rigs.yaml --bench bench-a \
    --board ref-a --image-dir artifacts/hil/2026-09-26/images/ref-a

# Capture a serial console (DTR asserted by default — required for the
# reference node's USB-Serial-JTAG console)
python3 tools/hil/capture.py --port /dev/cu.usbmodemXXXX --out run.log

# Reset a reference board N times and send M messages after each release:
# per-message outcome, reset-to-first-delivery time, IDEMPOTENCY_FULL count
# and the reference console captured on the same port (issue #167 evidence)
python3 tools/hil/reset_cycles.py --rig tools/hil/rigs.yaml --bench bench-a \
    --board ref-a --ctl host/target/debug/routeloomctl --socket /tmp/rl.sock \
    --destination 2 --cycles 10 --sends 10 --out artifacts/hil/reset-run

# For 10×10 after a reference reset, use --cycle-gap-s 300 so the host's
# two-per-minute admission tokens refill before the next reset.

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
python3 tools/hil/route_convergence.py --ctl host/target/debug/routeloomctl \
    --socket /tmp/rl.sock --nodes 2 3 --seconds 90 \
    --out artifacts/hil/routes.jsonl

# Read only the pinned board's rlsec partition. Raw NVS stays in a private
# mode-0700 directory outside the repo; --out contains counter metadata only.
python3 tools/hil/counter_snapshot.py --rig tools/hil/rigs.yaml \
    --bench bench-2026-09-26-mixed5 --board ref-a \
    --private-dir /tmp/routeloom-hil-private --label before-reset \
    --out artifacts/hil/ref-a-counters-before.json

# A deep-sleep image can expose USB for only ~0.2 s. This preloads esptool
# and checks sysfs serial/vendor/product before opening an early tty. It
# still requires chip-id/MAC and disabled security before any flash write.
/home/sahur/.local/share/uv/tools/esptool/bin/python tools/hil/catch_wake.py \
    --fast-probe --port /dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_94:A9:90:7A:26:AC-if00 \
    --early-tty /dev/ttyACM4 --usb-sysfs /sys/bus/usb/devices/1-4.2.3 \
    --chip esp32c3 --mac 94:a9:90:7a:26:ac \
    --image-dir artifacts/hil/2026-09-26/images/full-r1-node3-c3-recovery \
    --out artifacts/hil/node3-catch-wake

# Run scenarios (all, or --scenario name repeatedly); --list shows names
python3 tools/hil/scenarios.py --rig tools/hil/rigs.yaml --bench bench-a \
    --out artifacts/hil/run-1
python3 tools/hil/report.py --run-dir artifacts/hil/run-1
```

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
