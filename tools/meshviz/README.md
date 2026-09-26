# RouteLoom Mesh Lab (headless foundation)

PR 01/02 provide a Qt-free reducer, versioned SQLite capture/replay, fake API1, rig import, port inventory and guarded write plans. No GUI, provisioner, signature trust store or product firmware bundle is available yet. Do not use the flash worker with an untrusted manifest: the `verified_signature` field is a planning assertion, not a cryptographic signature check. Captures/replay never issue USB commands.

Run the hardware-free tests from the repository root:

```sh
PYTHONPATH=tools/meshviz/src:tools python3 -m unittest discover -s tools/meshviz/tests -v
```
