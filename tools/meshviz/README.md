# RouteLoom Mesh Lab

PR 01/02 provide a Qt-free reducer, versioned SQLite capture/replay, fake API1, rig import, port inventory and guarded write plans. PR 03b adds a development-only Ed25519 bundle/catalog and pinned ESP-IDF scratch builder. PR 05 adds the PySide6 GUI described below. No provisioner, generic per-board firmware or product release signing key is available yet. The flash worker verifies the bundle against its packaged public key before ROM access; a `verified_signature` flag alone never permits writing. Captures/replay never issue USB commands.

Build without modifying the checkout (Docker and ESP-IDF v6.0.3 image required):

```sh
./tools/meshviz/build_bundle.sh reference_node esp32c3 /tmp/my-bundle \
  tools/meshviz/packaging/dev-signing-key.pem preview-1
PYTHONPATH=tools/meshviz/src python3 -m routeloom_meshviz.firmware_catalog verify \
  /tmp/my-bundle tools/meshviz/src/routeloom_meshviz/dev-signing-public.pem
```

The CI artifact contains `bundle/` and a signed `catalog.json` for each chip/role. Download and verify offline using the packaged development public key (Python + cryptography + esptool 5.4.0 required for the headless worker; no IDF or Docker required). `manifest.json` signs image offset/size/hash, chip, IDF/source commits, version/profile and partition layout; `SHA256SUMS` covers every exported file. The signing **private key is committed solely for reproducible development fixtures**, is publicly known and grants no production authenticity. Production key custody, release promotion and per-board configuration belong to later work. Do not flash this preview to an already-provisioned device: PR 03a's generic image/setup and boot readback are not yet present; current images retain default Kconfig NodeIds and public development credentials. A ROM write/verify alone does not prove successful boot or site participation.

C6 remains an experimental HIL build target; the Mesh Lab flash worker rejects it until the C6 board checks are completed.

## GUI

Requires Python 3.12 with `PySide6>=6.8,<7`, `pyqtgraph>=0.13,<1` and `cryptography` (plus `pyserial`/`esptool==5.4.0` for real boards). From the repository root:

```sh
PYTHONPATH=tools/meshviz/src python3 -m routeloom_meshviz                       # built-in fake API1 server + demo mesh, fake boards
PYTHONPATH=tools/meshviz/src python3 -m routeloom_meshviz --nodes 100           # larger demo mesh
PYTHONPATH=tools/meshviz/src python3 -m routeloom_meshviz --socket /tmp/routeloom.sock   # live routeloom-host daemon, real serial ports
PYTHONPATH=tools/meshviz/src python3 -m routeloom_meshviz --replay path/to/x.rlcapture
PYTHONPATH=tools/meshviz/src python3 -m routeloom_meshviz --demo-capture /tmp/demo.rlcapture --nodes 20   # synthetic capture, no Qt needed
```

The 接続 menu switches between the fake server, a daemon socket and a capture at runtime. Screens (in place of screenshots):

- **Header** (always visible): LIVE/REPLAY, scope (site/profile are not exposed by API1 yet → 未取得), source/gateway state, recording state and event count, newest/oldest observation age and gap count, trial state.
- **ボード**: enumerated ports (USB descriptor, chip, MAC tail, flash, role, NodeId, state). *ROM 検査* runs a read-only probe (it resets the board) in the esptool worker process. Role/NodeId assignment rejects duplicate NodeIds, the same board on two ports and more than one bridge. After selecting a bundle (verified against the packaged development key) and confirming quiesce, the right pane previews each board's write plan (identity evidence, image offsets/sizes/hashes) or lists every rejection reason (chip/revision/flash mismatch, protection state unknown, C6, role mismatch…). Writes run serially through the existing lease/`run_batch`/flash worker; *次の台から中止* stops before the next board. "Written" means ROM write+verify only — boot/site participation is not checked yet, and per-board NodeId is not written (PR 03a). In fake mode three fake boards run through the real `flash_worker` checks with a fake esptool API (board C has an unknown flash-encryption state and is always refused).
- **トポロジ**: Qt Graphics View with a node list, graph and detail pane. Layers: 物理 link (solid; thick = both directions observed), 宛先への経路 (dashed = logical next hop, the rest of the path is unobserved), gateway tree (dotted, node→gateway selected routes; shown as 未取得 with today's API1, drawn for demo captures), 参加状態 (colour plus ●▲×? marks). Positions are deterministic and never jump; nodes can be dragged. Selecting a node highlights only its path. Unknown hop counts, RSSI etc. show 不明.
- **品質**: per-node RSSI/average/link cost/route metric/hop with time since observation and freshness, trial success-rate range and latency; RSSI time series (select rows, up to 8 series, gaps are not bridged) and the delivery-outcome distribution of trials. heap/reset/MAC retries show 未取得 until the health/telemetry APIs exist.
- **試験**: destination, count, interval, payload length, delivery, TTL. The plan is checked against host admission (2 calls/min, burst 16, including `operations.open_epoch`) before it can start; RATE_LIMITED shifts the schedule by `retry_after_ms`. Counters keep submitted/admitted/SDK-received/unknown/refused apart and the success rate is shown as a range including unknowns. Disabled (未対応) when the daemon does not advertise the send methods, and always in REPLAY.
- **記録と再生**: start/stop recording to a new `.rlcapture` (the current view is seeded as partial snapshots), open a capture, play/pause, 0.1–10× speed, single-event step, seek slider, and export `events.jsonl`, `nodes/links/routes/samples/trial_messages.csv`, `trial_summary.json` up to the current position. REPLAY never probes, writes or sends.

Threads: API1 I/O (QLocalSocket) and the reducer/recorder each own a QThread; board probe/flash batches run on another thread with the esptool work in a subprocess. The GUI repaints at most 20 times per second and only the visible screen. Closing the window stops new sends, closes the capture, disconnects and releases leases. Windows is not supported yet (fake server and daemon use Unix sockets; PR 04).

## Tests

Run the hardware-free tests from the repository root (Qt tests are skipped when PySide6 is missing; CI runs them offscreen):

```sh
PYTHONPATH=tools/meshviz/src:tools python3 -m unittest discover -s tools/meshviz/tests -v
QT_QPA_PLATFORM=offscreen PYTHONPATH=tools/meshviz/src:tools python3 -m unittest discover -s tools/meshviz/tests -v
```
