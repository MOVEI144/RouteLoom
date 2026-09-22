# Security Policy

## Status

RouteLoom is a **pre-1.0 implementation prototype** in the `CORE_FIXED_250`
profile. It has not undergone a security audit, RF/HIL qualification, or
production-credential review (the `G-SEC` gate is still open — see
`docs/STATUS.md`). Do not deploy it where compromise of a mesh node or
host daemon would cause harm.

## Reporting a Vulnerability

Please report vulnerabilities **privately** via GitHub's private
vulnerability reporting:

- Repository: `MOVEI144/RouteLoom`
- Path: **Security** tab → **Advisories** → **Report a vulnerability**

This keeps reports private until a fix is available. Please do not open
public issues for undisclosed vulnerabilities.

If private vulnerability reporting is unavailable for this repository,
contact the maintainers through the channel listed in the repository
profile/README (contact address to be published before the first stable
release).

We ask that you include: affected version/commit, component
(wire codec, USB session, security provider, host daemon, build
tooling), reproduction steps or a proof of concept, and your assessment
of impact.

## Supported Versions

Only the `main` branch receives fixes. No released version is covered by
a support commitment yet.

| Version / branch | Supported |
|---|---|
| `main`           | Yes — fixes land here first |
| tagged releases  | Pre-1.0; best-effort only, no backports |
| forks / profiles | Not supported |

## Scope

In scope for reports:

- Wire v1 frame decoding/validation (`components/routeloom`,
  `host/routeloom-wire`)
- USB/serial session authentication, framing and credit accounting
  (`usb_*`, `host/routeloom-protocol`)
- Replay/counter and authority-ledger persistence
- The development security provider (`DevelopmentPskSecurityProvider`)
- Host daemon/CLI/TUI input handling
- CI/release pipeline integrity

Out of scope (already documented limitations, not vulnerabilities):

- Attacks that require using the **development PSK** as if it were a
  production credential (see below)
- RF-level attacks on unqualified radio paths, and denial of service by
  jamming
- Issues in ESP-IDF itself (report to Espressif) or in third-party
  crates (report upstream; still tell us if we ship an affected version)

## Development key material — read before deploying

This repository ships **well-known development key material**:

- `CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX` defaults to the ASCII string
  `ROUTELOOM-DEVELOPMENT-KEY-ONLY!!` (hex) in both firmware apps.
- `DevelopmentPskSecurityProvider` (`components/routeloom_espnow`) is
  pinned to `SecurityProfile::Development` and supplies AES-GCM with a
  shared master key.

This key is a **test fixture, not a credential**. It is public by
definition, provides no device identity, and is recoverable by flash
readout. `security_profile()` deliberately defaults to `Development` so
no provider can silently claim production status, and firmware logs mark
the profile EXPERIMENTAL at boot. Replace it with the qualified
EDHOC/RPK identity profile (gate `G-SEC`) before any real deployment.
Finding "the dev key is public" is a documented design property, not a
vulnerability — but flaws that let the dev profile masquerade as a
production profile **are** in scope.

## Response

This is a volunteer-maintained pre-release project; we will acknowledge
reports as time permits and credit reporters in release notes unless you
prefer otherwise. Fixes land on `main`; advisories are published via
GitHub Security Advisories when the fix ships.
