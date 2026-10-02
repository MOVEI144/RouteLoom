# Security Policy

## Status

RouteLoom is at **SDK 2.0.0-dev** (pre-release). Release builds do not
establish a security audit, complete RF/HIL qualification, or
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

Only the `main` branch receives fixes until v2.0.0 is released. From then,
the latest 2.0.x release is supported; the SDK version is recorded in
`protocol/manifest.json`.

| Version / branch | Supported |
|---|---|
| `main` (2.0.0-dev) | Yes — fixes land here first |
| 2.0.x (after release) | Yes |
| 0.1.0 and untagged snapshots before 2.0.0 | No |
| forks / profiles | Not supported |

## Scope

In scope for reports:

- Wire v2 frame decoding/validation (`components/routeloom`,
  `host/routeloom-wire`)
- USB/serial session authentication, framing and credit accounting
  (`usb_*`, `host/routeloom-protocol`)
- Replay/counter and authority-ledger persistence
- The DevRam development security profile and the SDK v1 MemberEdhoc
  stack
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
  `ROUTELOOM-DEVELOPMENT-KEY-ONLY!!` (hex) for the DevRam quick start.
- DevRam (`components/routeloom/src/sdkv1_dev_session.cpp`) is pinned to
  `SecurityProfile::Development` and derives its RAM sessions from a
  shared master key.

This key is a **test fixture, not a credential**. It is public by
definition, provides no device identity, and is recoverable by flash
readout. `security_profile()` deliberately defaults to `Development` so
no provider can silently claim production status, and firmware logs mark
the profile EXPERIMENTAL at boot. Product release selection uses MemberEdhoc
and provisioned identity; its
qualification gate `G-SEC` remains separate from a successful build.
Finding "the dev key is public" is a documented design property, not a
vulnerability — but flaws that let the dev profile masquerade as a
production profile **are** in scope.

Release packaging rejects product images with development identity, master
keys or linked development providers. DevRam archives are labelled for
quick starts. The optional release signing hook rejects meshviz's public
development signer by public-key identity. See [release procedures](docs/releases.md)
for the artifact inventory, unsigned-provenance limits and RC promotion.
Maintainers choose the signing method and configure the private reporting
channel/contact before publishing the first stable release.

## Response

This is a volunteer-maintained project; we will acknowledge
reports as time permits and credit reporters in release notes unless you
prefer otherwise. Fixes land on `main`; advisories are published via
GitHub Security Advisories when the fix ships.
