# Release artifacts and promotion

The release workflow checks the tag against `protocol/manifest.json` before
building. Every build job checks out the same prepared commit SHA. Set the SDK version in that manifest, run `tools/gen_manifest.py`,
and commit all generated versions before tagging a candidate. SDK defaults
and qualification gates remain owned by their implementation PRs.

A manual workflow run with `dry_run=true` performs the same builds and checks
as a tag run and uploads `candidate-assets`; it creates no GitHub release.
A tag run creates a **draft** release. This pipeline does not certify hardware.

Artifacts comprise the complete tracked source archive (including host,
firmware, examples, build tools, vectors and license texts), Linux x86_64 glibc
host daemon/CLI/TUI, and bridge, relay and endpoint reference images for
ESP32-C3/S3/C5/C6. Each firmware role has separate `member` and `devram`
archives. MemberEdhoc is the product selection in this release matrix;
DevRam is explicitly a development quick start. Bridge images need a
provisioned BoardConfig and HostLink secret. Field relay/endpoint images also
need provisioning; development archives do not contain personalized keys.
See the application instructions for provisioning before first boot.

`flasher_args.json` paths are preserved in firmware archives, including the
bootloader, partition table, initial OTA data and app. For an already
provisioned device use an **app-only** update as described in [HIL](hil.md);
writing all flash files again is a factory installation, not an NVS-preserving
update. Follow the chip/MAC preflight and eFuse safety rules there.

Every candidate includes `NOTICE`, `LICENSE`, `THIRD_PARTY_LICENSES.txt`,
a CycloneDX 1.5 SBOM, `cargo-metadata.json`, `SHA256SUMS.txt` and an in-toto/SLSA v1 provenance
statement. The SBOM checks all target-specific locked Rust crates against
reviewed name/version/license credits in NOTICE and the vendored source
inventory. It includes the pinned ESP-IDF framework and bundled SQLite;
it is an SDK dependency inventory, not an exhaustive SBOM of ESP-IDF's
internal toolchain and submodules. Vendored blob integrity is checked before
packaging. Unknown dependencies, stale credits and modified SBOM components
fail assembly. Upstream Cargo/vendor license and notice texts are collected
from the locked sources; missing texts fail inventory generation. Host and
firmware archives also carry these license files. All artifacts are hashed;
firmware provenance includes the
commit, IDF/Rust pins, sdkconfig/flash-argument hashes, hashes of every flashed
image (bootloader, partition table, initial OTA data and app), `PT-4M-v2` and static
RAM free bytes. Checksums establish integrity, not publisher identity.

Product packaging checks the effective security selection, development
identity, development master-key bytes/hex and linked development provider
symbols before staging. Flash offsets, app filenames and the flasher chip must
match the inspected image and matrix. A failure must be fixed in the owning
firmware PR;
do not bypass the check to obtain a candidate. The same static RAM floors
apply as in CI, with the bridge/relay base-cell size ratchets retained.

Signing is optional until maintainers select a method. Configure the runner's
`RELEASE_SIGN_HOOK` repository variable with an executable path. For a
maintainer key, set `RELEASE_SIGNING_KEY_PEM` with its private PEM; leave it
unset for a keyless hook (the job permits OIDC). The executable receives four
arguments: private-key path (or `-` for keyless), SHA256SUMS input, signature
output and public-key output. A keyless hook must export its signer's public
key as PEM; a maintainer key's public output is populated before invocation.
The hook owns its signing method and verification and must exit nonzero on
failure. Signing must preserve every candidate artifact, provenance and checksum
file; the checker rejects changes even if the hook recomputes their hashes.
Signing outputs must be nonempty regular files, with no symbolic links. The
private file is removed on exit; only
`SHA256SUMS.sig` and `signing-public.pem` are published. The checker compares
the derived public-key identity with meshviz's public development key and
rejects that key, including a differently encoded copy. Consumers must verify
the signature using the selected method and an independently trusted public
key. Without signing, provenance is an unsigned build record; no SLSA level
or authenticated publisher is claimed.

Before promoting `v2.0.0-rc.N`, run **P06, P01 and K06/H4 using those exact
host and firmware archives**, checking `sha256sum -c SHA256SUMS.txt` before
flashing and retaining image/sdkconfig hashes in the HIL record. P06 requires
actual boot/provision/join/delivery (20/20) as well as archive hashes; P01
requires preserved NVS hashes on app-only updates. K06 requires the prescribed
five-board 24-hour soak and every H4 threshold, including all 20 reset
recoveries. Unit fixtures, mock success and previous builds are not evidence
for these rows. S3 variants remain pending until connected; C5 RF
qualification remains H5 after hardware is available. See [STATUS](STATUS.md)
and the dated [HIL records](hil.md) for unresolved results; building an image
for a chip does not qualify it.

After H4 passes, create the final tag **at the RC commit**. Dispatch Release
with `tag=v2.0.0` and `promote_from=v2.0.0-rc.N`, first with `dry_run=true`.
Promotion downloads and verifies the complete RC asset set and checks both
tags and provenance name the same commit/base version. With `dry_run=false`
it creates a final draft with those bytes: filenames, hashes, SBOM version
and provenance retain the RC identity. It never rebuilds or re-signs assets.
The final tag deliberately retains the tested RC manifest; a fresh stable-tag
build fails the ordinary exact tag/manifest check. Publish the reviewed draft
through the maintainer's normal release process. Keep the RC and final assets
available so downstream consumers can reproduce the evidence.

`python3 tools/check.py compat` runs current readers against previous record
formats/goldens, the schema-2 SQLite migration/readback/backup, a valid-CRC
HostLink v1 refusal, and the real Owner's downgrade/authentication negatives.
HostLink v1 is intentionally incompatible: it must never become ACTIVE or
silently fall back. Mixed peers from an N-1 **SDK release** are an optional
later-release exercise; there is no previous SDK 2.x release at v2.0.0.
Repository security reporting settings and the reporting contact remain
maintainer-operated prerequisites, as described in [SECURITY](../SECURITY.md).
