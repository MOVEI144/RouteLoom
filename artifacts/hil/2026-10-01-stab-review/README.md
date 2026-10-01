# Stability review evidence

The acceptance interpretation and source provenance are in
`docs/hil/2026-10-01-stab-review.md`. Raw observations include failures;
process exit codes do not override the specified acceptance gates.

- `boot-1` through `boot-5`, `s7-smoke`: normal-image simultaneous starts.
- `gateway-reset`: ten USB-reauthenticated reset cycles and terminal requests.
- `relay-reset`: forced two-hop next-hop proof, ten reset cycles and strict
  timing in `acceptance.json`.
- `n1`: compiled-out node-status capability and authenticated delivery.
- `j05`: recovery removal, actual isolation timing, reset controls, holdoff,
  generation-2 approval and delivery.
- `channel-plan-final`: released 6→1, failed traffic, normal cooldown,
  unreleased return offer. Earlier BUSY attempts are kept separately.
- `radio-power`, `radio-driver`: unauthenticated public-marker radio controls,
  exact diagnostic source, observations and app/NVS restoration hashes.
- `restored-home`, `restored-home-boot`: authorised fresh-site restoration to
  channel 6, first 19/20 and separate settled 20/20 smoke, final status and
  serial-port cleanup.
- `images`: SDK build/config/image hashes and matched-config RAM reports.

`large-evidence.json` maps bulky progress logs and reset snapshots to ignored
`build-review-raw`. `evidence-outside-repo.sha256` indexes retained build,
red/green and validation logs and image bundles. Current bundles were moved
from untracked `artifacts/hil/images/review-*` to ignored `build-review-images`
after the final hardware action; historical observation paths were preserved.
Recipes expect the original labels when rebuilt with `tools/hil/build_image.sh`.
Keys and NVS contents are private and are not included in these artifacts.

Scripts are records of this pinned bench, not production features. Before
reusing a destructive provisioning recipe, follow the bench rules, reserve all
three devices, verify each chip/MAC and supply a private fresh-site directory.
The raw probe source uses public markers only; its callbacks report MAC
receipt, not authenticated SDK application receipt.
