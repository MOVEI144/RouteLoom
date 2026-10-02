# Security Policy

## Reporting a vulnerability

Report security problems privately through the repository's **Security** tab →
**Report a vulnerability** (GitHub private vulnerability reporting).
Do not open a public issue for an undisclosed vulnerability. Include the affected
version or commit, component, reproduction steps and expected impact. Do not
include production keys or credential dumps.

The reporting setting is managed by repository maintainers; this document does
not verify that it is enabled. Reports and coordinated fixes use GitHub Security
Advisories. No personal contact address is used.

## Supported versions

| Version | Security fixes |
|---|---|
| v2.0.x | Supported |
| Other versions and development snapshots | Not supported |

The current checkout is `2.0.0-dev`; writing the v2.0.x support policy does not
publish a stable release. See [release conditions](docs/STATUS.md).

## Development fixtures and qualification

DevRam's fixed development key, lab CA material and meshviz development signer
are **test-only fixtures**. They are public development values, not production
credentials. Do not use them for product deployments. A changed shared test key
alone does not supply device identity or membership authorization.

MemberEdhoc uses provisioned identities and reports **Candidate**. DevRam reports
**Development**. Neither a successful build nor this policy is a third-party
security audit or a **Production** qualification. HIL and security qualification
remain explicit in [STATUS](docs/STATUS.md). The human third-party review (#100)
is tracked as non-blocking for v2.0.

Product release packaging rejects development identity, keys and providers;
optional signing also rejects the public development signer. See
[release procedures](docs/releases.md) and [user security guide](docs/user/security.md).
