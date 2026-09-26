# RouteLoom Mesh Lab (headless foundation)

PR 01/02 provide a Qt-free reducer, versioned SQLite capture/replay, fake API1, rig import, port inventory and guarded write plans. No GUI, provisioner, signature trust store or product firmware bundle is available yet. The JSON flash worker and normal `flash()` entry point reject every write until the signed bundle verifier is integrated in PR 03b. Tests can inject a fake esptool adapter to exercise preflight and write sequencing. The `verified_signature` field is only a planning assertion, not cryptographic evidence. Captures/replay never issue USB commands.

Run the hardware-free tests from the repository root:

```sh
PYTHONPATH=tools/meshviz/src:tools python3 -m unittest discover -s tools/meshviz/tests -v
```
