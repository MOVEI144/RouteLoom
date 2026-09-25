# Hardware-in-the-loop (HIL) harness

`tools/hil/` automates real-board validation: rig description, firmware
flashing, serial capture, scenario runs, and run reports. Everything is
stdlib-only Python — no third-party dependencies.

**Hardware status:** the [2026-09-26 bench report](hil/2026-09-26-bench-5node.md)
records the first hardware run and its continuation. The bench contained
three C3s and two C6s; C6 is an experimental HIL target outside the SDK v1
support list. One C3 stopped enumerating, so the continuation exercised four
boards (two C3s, two C6s). A five-node run and C5 hardware comparison remain
unfinished. Harness self-tests alone are not hardware validation.

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

# Run scenarios (all, or --scenario name repeatedly); --list shows names
python3 tools/hil/scenarios.py --rig tools/hil/rigs.yaml --bench bench-a \
    --out artifacts/hil/run-1
python3 tools/hil/report.py --run-dir artifacts/hil/run-1
```

`rig.py --selftest`, `scenarios.py --selftest` run dependency-free
self-checks usable in CI without hardware.

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
