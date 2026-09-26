# RouteLoom Mesh Lab (headless foundation)

PR 01/02 provide a Qt-free reducer, versioned SQLite capture/replay, fake API1, rig import, port inventory and guarded write plans. PR 03b adds a development-only Ed25519 bundle/catalog and pinned ESP-IDF scratch builder. No GUI, provisioner, generic per-board firmware or product release signing key is available yet. The flash worker verifies the bundle against its packaged public key before ROM access; a `verified_signature` flag alone never permits writing. Captures/replay never issue USB commands.

Build without modifying the checkout (Docker and ESP-IDF v6.0.3 image required):

```sh
./tools/meshviz/build_bundle.sh reference_node esp32c3 /tmp/my-bundle \
  tools/meshviz/packaging/dev-signing-key.pem preview-1
PYTHONPATH=tools/meshviz/src python3 -m routeloom_meshviz.firmware_catalog verify \
  /tmp/my-bundle tools/meshviz/src/routeloom_meshviz/dev-signing-public.pem
```

The CI artifact contains `bundle/` and a signed `catalog.json` for each chip/role. Download and verify offline using the packaged development public key (Python + cryptography + esptool 5.4.0 required for the headless worker; no IDF or Docker required). `manifest.json` signs image offset/size/hash, chip, IDF/source commits, version/profile and partition layout; `SHA256SUMS` covers every exported file. The signing **private key is committed solely for reproducible development fixtures**, is publicly known and grants no production authenticity. Production key custody, release promotion and per-board configuration belong to later work. Do not flash this preview to an already-provisioned device: PR 03a's generic image/setup and boot readback are not yet present; current images retain default Kconfig NodeIds and public development credentials. A ROM write/verify alone does not prove successful boot or site participation.

C6 remains an experimental HIL build target; the Mesh Lab flash worker rejects it until the C6 board checks are completed.

Run the hardware-free tests from the repository root:

```sh
PYTHONPATH=tools/meshviz/src:tools python3 -m unittest discover -s tools/meshviz/tests -v
```
