# STAB-B blocking-review evidence

Acceptance interpretation is in [the HIL report](../../../docs/hil/2026-10-01-stab-fix.md).
Starting SHA: `9ec11566d515043dcbdbfe38c936cbc02578e89b`; final SDK source:
`e597da2ee2160a50bb4cbccb517ab51db0c90391`. ESP-IDF is v6.0.3, pinned by
the image digest and IDF commit in `build-info.json`.

## Records

- `images.json`: app sizes/hashes, matching-config sdkconfig hashes and RAM
  guard outcomes. Earlier intermediate images are identified by source SHA;
  only `stab-fix-r3-*` images represent the final SDK change.
- `build-info.json`: pinned build provenance for the before/after and final
  diagnostic images. Full configurations and binaries are archived locally.
- `flash-r3-{chain,trace,normal}/images.json`: chip/MAC checks, app hashes and
  sealed-NVS preservation. Normal images were restored after the trace.
- `r3-chain-boot/nodes.json`: fresh forced-chain gateway observation,
  endpoint next hop = relay. The existing HIL RX MAC filters exclude the
  direct gateway–endpoint link.
- `relay-reset-r3-forced/acceptance.json`: final ten-cycle acceptance,
  61/100. `relay-reset/` is the invalid direct-path control;
  `relay-reset-final-forced/` is the earlier 69/100 intermediate run;
  `relay-reset-trace/` is a three-cycle timing-instrumented diagnostic.
- `s7-final.json`: five fresh-daemon simultaneous boots. Route time after
  reset release is `boot.all_routes_at_s + boot.offset_after_release_s`.
  Four discoveries succeeded, with 8/10 subsequent smoke deliveries.
  `routes_and_delivery` combines those separate observations and is not the
  S7 discovery verdict. `s7-final-1/` and `s7-owner-poll.excerpt.log` preserve
  receive-silent and measured Owner-poll counters.
- `plan-r3-6-1/`: final offer/release/status, verified member radio events
  and 0/20 sends to each member. `forward_routes` in the original harness
  log used a cached host view; it is explicitly excluded as route proof.
- `return-r3-1-6/`: return offer admitted, READY 0/2, Aborted (phase 8),
  unreleased. The fresh final status is 270.83 s after offer admission.
  The stranded-member scenario could not start.
- `radio-probe{,-reapply}/`: raw radio source, parsed MAC callback results,
  original/full-slot restored image hashes. Protocol/rate/channel controls
  remove mesh and channel-plan code from the data path. These results do
  not identify RF, driver/PHY or board as the unique cause.
- `raw-index.json`: exact original relative paths, byte counts and SHA-256
  for all raw records, including experiment scripts. Large logs are in
  `build/hil-stab-fix-raw`; SDK bundles are in `build/hil-stab-fix-images`.
  These ignored local archives are not distributed by Git. Key files and
  NVS dumps are in private mode-0700 storage outside the repository.
- `validation-log-index.json`: SHA-256 of the final local test and firmware
  build logs copied to ignored `build/hil-stab-fix-validation`.

## Reproduction

Use exclusive bench `bench-2026-09-29-h0` from `tools/hil/rigs.yaml`.
Chip/MAC verification and PT-4M-v2 verification precede every write;
app-only writes retain sealed NVS and compare readback hashes. Do not restore
old security NVS to repeat a test. Provision a fresh sealed MemberEdhoc site
with the existing `routeloomctl` site/identity commands and
`routeloom_meshviz.provisioning` console flow, as recorded in the archived
`scripts/provision.py`; keys are not in this evidence directory. The public
site input is `fresh-site/site-spec.json`.

The normal SDK build commands at the final source are:

```sh
tools/hil/build_image.sh bridge_node esp32c3 stab-fix-r3-br \
  CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y \
  CONFIG_ROUTELOOM_USB_NODE_STATUS=y CONFIG_ROUTELOOM_CAPABILITY=0x2047 \
  CONFIG_ROUTELOOM_MIGRATION=2
tools/hil/build_image.sh reference_node esp32c6 stab-fix-r3-relay \
  CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y CONFIG_ROUTELOOM_CONFIG=y \
  CONFIG_ROUTELOOM_HIL_HEAP_TELEMETRY=y CONFIG_ROUTELOOM_MIGRATION=2
tools/hil/build_image.sh reference_node esp32c6 stab-fix-r3-ep \
  CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y \
  CONFIG_ROUTELOOM_RESOURCE_PROFILE_ENDPOINT=y CONFIG_ROUTELOOM_ROLE_ENDPOINT=y \
  CONFIG_ROUTELOOM_HIL_HEAP_TELEMETRY=y CONFIG_ROUTELOOM_MIGRATION=2
```

For the forced path, the bridge additionally uses
`CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="10:bd:a3:b1:47:54"`, and the endpoint uses
`CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="94:a9:90:7a:26:ac"`; relay is unchanged.
Trace builds additionally enable existing `CONFIG_ROUTELOOM_HIL_TRACE_LINK_EPOCHS`
and `CONFIG_ROUTELOOM_HIL_EDHOC_TIMING` on the bridge and relay. Normal
acceptance does not use those trace switches.

Reset and route observations use `tools/hil/reset_all.py`,
`tools/hil/route_convergence.py`, `tools/hil/reset_cycles.py` and
`routeloomctl` on `/tmp/routeloom-hil-v2-stab.sock`. The archived
`scripts/boot_fresh.py` starts a fresh daemon for each boot to avoid cached
routes. Final reset acceptance used ten relay cycles with ten endpoint
sends per cycle; BOUND times are console UTC offsets, delivery completion
offsets use a monotonic clock. Do not count a direct gateway path as relay
recovery.

Build the two standalone `radio-probe/source` snapshots separately with the
same pinned IDF, targeting esp32c3 and esp32c6. The archived probe runners
verify the chip and partition table, read the full OTA0 slot at `0x40000`
(length `0x1d0000`), replace only that slot, reset the three boards together,
capture phase results, then restore and SHA-256-verify the entire slot in a
`finally` block. They do not write NVS, otadata, bootloader or eFuses.
Source contains only public 128-byte markers; callbacks measure MAC receipt.

At the end of this round the boards retain final normal images, committed
channel 1 / epoch 1 and the fresh site. The return offer is aborted. The task
daemon and captures were stopped, and `fuser` found no serial-port users.
The bench requires channel-1 diagnosis or fresh provisioning before a new
channel-6 acceptance run.
