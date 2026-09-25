# RouteLoom ESP-NOW node — external-consumption example

Minimal RouteLoom mesh node built **as an external ESP-IDF project**: the
RAM-only development provider (PSK-derived sessions, no NVS
counter/replay writes), the ESP-NOW runtime (fixed channel, Wi-Fi LR250)
and one optional static peer. It is a trimmed copy of
`firmware/reference_node` — discovery, migration, remote config, telemetry
remote answers and the deep-sleep path are deliberately left out.

> EXPERIMENTAL: the default `CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX` is a shared
> development key, and the default security profile is DevRam. Both are
> pinned to `SecurityProfile::Development` — never a production identity.
> Do not deploy the default key. Select
> `ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE` explicitly for the pinned
> host-compatible provider instead.

There are two supported ways to consume the SDK without copying this
repository's sources into your project.

## Style (a): `EXTRA_COMPONENT_DIRS` into a local checkout

Clone RouteLoom next to your project and add its `components/` directory to
the component search path. This example's `CMakeLists.txt` already does this
when it detects it is built inside the repository (`../../components`
exists), so in-repo it just builds:

```bash
idf.py set-target esp32c3
idf.py build
```

In your own project the equivalent is:

```cmake
# CMakeLists.txt, before include($ENV{IDF_PATH}/tools/cmake/project.cmake)
list(APPEND EXTRA_COMPONENT_DIRS "/absolute/path/to/RouteLoom/components")
```

Your `main` component keeps `REQUIRES routeloom routeloom_espnow` (see
`main/CMakeLists.txt`). Because both RouteLoom components carry
`idf_component.yml` manifests, the component manager sees them as local
components and resolves the `routeloom/routeloom` dependency of
`routeloom_espnow` from the same checkout — nothing is downloaded.

## Style (b): component-manager git dependency

When this example is copied out of the repository, the
`EXTRA_COMPONENT_DIRS` block in `CMakeLists.txt` becomes a no-op. Uncomment
the git dependency block in `main/idf_component.yml` instead:

```yaml
dependencies:
  routeloom/routeloom:
    git: https://github.com/MOVEI144/RouteLoom.git
    path: components/routeloom
    version: main          # pin a tag or commit SHA beyond experimentation
  routeloom/routeloom_espnow:
    git: https://github.com/MOVEI144/RouteLoom.git
    path: components/routeloom_espnow
    version: main
```

The component manager clones the repository and installs the two component
subdirectories under `managed_components/`. Both entries are required:
`routeloom_espnow`'s manifest declares `routeloom/routeloom`, and until a
registry release exists the project manifest is what tells the solver where
the core comes from. Pin `version` to a tag or commit SHA — `main` floats.

## Configuration

`menuconfig → RouteLoom ESP-NOW node example` exposes the node identity
(network ID, node ID, channel, TX power), the static peer
(`ROUTELOOM_PEER_NODE_ID`/`ROUTELOOM_PEER_MAC`; `0x0` runs peerless) and the
development master key. Two boards form a mesh by pointing each at the
other's MAC and node ID, or run one board peerless to see it boot.

`ROUTELOOM_ROUTE_GATEWAY_SCOPED` (default `n`) switches the node to the
gateway-scoped routing profile for large sites
([routing-scale design](../../docs/design/sdk-v1/routing-scale.md)):
`ROUTELOOM_ROUTE_GATEWAY_1` (default `0x1`, normally the bridge node's ID)
and optional `ROUTELOOM_ROUTE_GATEWAY_2` name the site gateways, and
`ROUTELOOM_ROUTE_PERIOD_MS` / `ROUTELOOM_ROUTE_LIFETIME_MS` (5000 / 90000)
set the tick and lease. Every node of a site, the bridge included, must
enable it with the same gateways. A lease below `(2 × 6 + 2) × period`, a
zero gateway or a duplicate gateway fails the build. Left off, the node keeps
the flat profile and the SDK's 5 s / 15 s route timers.

## Partition table and NVS

`partitions.csv` (selected in `sdkconfig.defaults`) adds a 64 KiB `rlsec`
NVS partition next to the default `nvs`. Under the legacy profile the
per-peer counter/replay state (`rlcounter`/`rlreplay`) lives there, so it
can never fill the partition that holds the boot session (issue #37); the
default DevRam profile keeps all session state in RAM instead. Old TX
counter records are swept at boot and the number of persisted peers is
capped (`kNodeMaxPersistedPeers`); a new peer beyond the cap is refused with
the `PEER_STATE_CAPACITY` diagnostic, never silently. Changing the partition
table moves NVS: run `idf.py erase-flash` before the first flash of this
layout (already required by Wire v2). The firmware never erases NVS on its
own.

## Honest limits

- Validated targets: `esp32c3`, `esp32s3`, `esp32c5` — matching CI. Other
  ESP-NOW-capable chips are not validated and `routeloom_espnow`'s manifest
  `targets` list excludes them.
- Only ESP-IDF v6.0.3 is CI-validated; manifests require `idf >= 6.0`.
- No version is published to the ESP-IDF component registry. `version:
  0.1.0` in the manifests is the pre-release tag used for git `path`
  dependency solving, not a registry artifact.
- A successful build proves compile/link only — no RF, range, or battery
  claim (see `docs/STATUS.md`).
