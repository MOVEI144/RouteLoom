# routeloom-provision

Host-side provisioning core: byte-exact mirrors of the device record codecs,
the signing seams, and the manufactured NVS sets. The command line is
`routeloomctl provision-*` (local operations — no daemon socket).

| Area | Modules | Design |
|---|---|---|
| Dev/bench provisioning (RLT1 trust image, RLC1 credential, RTM1 manifest, `rltrust`/`rlcred`/`rlboot` blob set) | `image`, `credential`, `manifest`, `verify`, `nvs`, `signer` | `docs/design/sdk-completion/04-provisioning-lifecycle.md` |
| SDK v1 codecs (RLCW1 certificates, RLI1/RLS1/RRS1/RLP1) | `sdkv1::{cert,identity,site,revocation,resume}` | `docs/design/sdk-v1/02`, `04`, `05`; vectors in `protocol/sdkv1-golden/` |
| SDK v1 office tooling (P7-1) | `sdkv1::{devca,pop,office,rlsec}` | `docs/design/sdk-v1/07-host-api-tooling.md` §6 |

**Custody.** Every file-backed signer here (`FileRootSigner`,
`FileDeviceCaSigner`) is a development path: a plaintext P-256 key document
created with mode 0600, never overwritten, refused when group/other
readable. Production keys stay behind the `RootSigner` / `DeviceCaSigner`
traits (offline station or HSM, not implemented here). Nothing in this crate
burns eFuses or enables flash encryption / secure boot.

## SDK v1 office tooling

The office writes only site-independent material: NodeId, the device key,
the DevCert (signed by the organisation's Device CA) and the Site CA
anchors. Network id, site keys and channel come from the zero-touch join.

### Identity spec

A per-product template (`routeloom-identity-spec-v1`); the per-device node
id and certificate serial are command-line arguments.

```json
{
  "format": "routeloom-identity-spec-v1",
  "model": 17,
  "hw_rev": 2,
  "flags": 1,
  "anchors": [
    {"anchor_id": "05ca000000000001", "kind": "site-ca", "status": "active",
     "pubkey_hex": "<128 hex: Site CA X||Y>"}
  ]
}
```

`flags`: bit0 `console_locked`, bit1 `strict_assignment` (A2; needs an
active `assignment-verifier` anchor). 1–3 anchors, at least one active
`site-ca`.

### Device CA key (development)

```sh
routeloomctl provision-devca-keygen --device-ca-id 0dca000000000001 --out devca.key
# {"device_ca_id":"0dca000000000001","pubkey_hex":"…","key_file":"devca.key"}
```

The printed public key is what the Site Authority is configured with to
verify DevCerts.

### Device-generated key (default)

```sh
routeloomctl provision-pop-challenge --node 00a1000000001234
# {"node_id":"00a1000000001234","challenge_hex":"6d30…1bae"}
#   → the device maintenance verb generates its key and returns the proof
#     of possession (183-byte COSE_Sign1, raw or hex) — firmware follow-up
routeloomctl provision-devcert --ca-key devca.key --spec identity-spec.json \
    --node 00a1000000001234 --serial 1 \
    --challenge 6d30…1bae --pop pop.bin --out-dir dev-00a1000000001234
# {"node_id":"00a1000000001234","kid":"…","model":17,"hw_rev":2,"cert_serial":1,"device_ca_id":"0dca000000000001"}
```

The proof must name exactly that node and echo exactly that challenge, and
be signed by the key it carries; otherwise no DevCert is issued. Output:
`devcert.cwt` and `identity-bundle.json` (`routeloom-identity-bundle-v1`:
node id, flags, anchors, DevCert — no secret), which the device verb seals
into `rlsec`/`rlident` after checking the DevCert names its own key. The
stdout line is the inventory record for KGuard.

Proof-of-possession format (`sdkv1::pop`): restricted ES256 COSE_Sign1
(`d2 84 43 a1 01 26 a0 58 6c <payload> 58 40 <R||S>`), payload
`version=1 | key_location (1 nvs-plaintext, 2 efuse-ds-bound, 3
secure-element) | 0x0000 | node_id u64 | challenge 32 B | pubkey 64 B`
(108 B), external AAD `"RouteLoom/device-key-pop/v1" 00`, low-S only.

### Injected key (below tier T1, dev/bench)

```sh
routeloomctl provision-identity --ca-key devca.key --spec identity-spec.json \
    --node 00a1000000001234 --serial 1 --out-dir dev-00a1000000001234
cd dev-00a1000000001234
python -m esp_idf_nvs_partition_gen generate rlsec-nvs.csv rlsec.bin 0x10000   # gateway: 0x20000
esptool.py write_flash 0x190000 rlsec.bin   # the rlsec offset in firmware/*/partitions.csv
```

The key is generated on this host; the tool proves possession to itself
through the same verifier, issues the DevCert, builds RLI1 and reads the
NVS set back as a first boot would. Output (directory 0700; files carrying
the secret 0600, nothing overwritten): `devcert.cwt`, `identity.rli1`,
`rlident_i0.bin`, `rlident_i1.bin` (the same committed record — the twin
pair `IdentityStore` adopts), `rlsec-nvs.csv` (`nvs_partition_gen` input;
run it from the output directory) and `rlsec-set.json` (descriptor with the
hex bytes). Flash, then destroy the directory. Flashing `rlsec.bin` replaces
the whole `rlsec` partition (erase-on-migration accepted in sdk-v1/08 Q13).
