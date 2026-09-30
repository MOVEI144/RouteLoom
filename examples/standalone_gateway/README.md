# RouteLoom standalone gateway — example

A gateway-role image whose own application uses `routeloom::Device`
directly, with no host in operation. Every message a member sends to the
gateway is answered with `ok`. The configuration is the bridge image's
(gateway role and profile, `gateway_small` on ESP32-C3, UART console,
PT-4M-v2) plus this application.

The node takes its identity and keys from the provisioned BoardConfig, like
`firmware/bridge_node`: commit it with the setup image first
([docs/hil.md](../../docs/hil.md), "BoardConfig"). The USB bridge is still
attached, so a host can be connected for provisioning and joining.

## What works without a host

- Members that already belong to the site keep exchanging messages with the
  gateway and each other.
- With no Site Authority, new joins, group-key rotation, revocation and
  cutover stop. Join the members before deployment, or connect a host for
  that time. Group messages rely on a group key that no longer rotates, so
  send only idempotent state notifications to groups.
- DevRam (the default here) has no Site Authority at all: every board with
  the same network, channel and development PSK is a member. MemberEdhoc
  needs one temporary host for the joins.

## Build

```bash
idf.py set-target esp32c3
idf.py build
```

Outside the repository, use the git dependency described in the
[endpoint example](../endpoint_cpp/README.md#style-b-component-manager-git-dependency).
A successful build proves compile and link only; the standalone exchange is
checked on hardware (E2E row P06).
