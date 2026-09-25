# Member session handshake golden vectors (P4 §5)

Byte-exact vectors for the member EDHOC wire of G-SEC P4: the link
carrier digest and link/end bindings (§5.2/§5.3), the session EAD values
SessionIntent (−65542), SessionState (−65543), ContextConfirm (−65544)
(§5.3), the 15-element Exporter application contexts with the
capability/contexts digests (§5.4), the RFC 9528 EDHOC_Exporter KDF
from a known PRK_exporter, and the routed end-object envelope with its
lane-separated chunk sub namespace (§7.3).

| side | code | what it does with the vectors |
|---|---|---|
| generator | `tools/gen_sdkv1_handshake_vectors.py` | independent reference encoder from the design text; stdlib only, no C++/Rust oracle; member certificates are inputs from `protocol/sdkv1-golden/valid/cert_membercert{,_peer}.json` |
| C++ | `components/routeloom/src/{sdkv1_session_wire,key_schedule}.cpp`, test `tests/cpp/test_sdkv1_session_wire.cpp` | encode/decode, digest agreement, KDF-info + HKDF-Expand outputs, invalid-shape refusal |
| Rust | `host/routeloom-keysched`, test `host/routeloom-keysched/tests/golden.rs` | the same on the mirror codecs |

Regenerate with `python3 tools/gen_sdkv1_handshake_vectors.py`; CI
regenerates and requires `git diff --exit-code` plus no untracked files
here. The same run rewrites the fuzz seeds
`tests/fuzz/corpus/sdkv1_handshake/` (raw EAD values and Exporter
contexts of every valid vector).

Member fixtures: initiator = device `0x54` (`cert_membercert.json`,
role Endpoint, generation 3), responder = peer `0x56`
(`cert_membercert_peer.json`, role Relay, generation 1); network
`0x000000030A1B2C3D` (site epoch 3). `*_flip_*` vectors change exactly
one input field and must both match byte-for-byte and differ from the
base vector named in `differs_from`.

Layouts pinned here (integers big-endian, all-unknown refused):

- `carrier_digest = SHA-256("RouteLoom/v1/link-carrier" || 00 ||
  rld1_version_u8(1) || full_network_u64 || node_I_u64 || node_R_u64 ||
  requester_nonce16 || responder_nonce16 || cookie16 || capability_I_u32
  || capability_R_u32 || scope_binding32)`; `binding_link =
  SHA-256("RouteLoom/v1/resume-binding" || 00 || 01 || MAC_I6 || MAC_R6
  || carrier_digest32)`; end binding =
  `SHA-256("RouteLoom/v1/end-carrier" || 00 || full_network_u64 ||
  node_I_u64 || node_R_u64 || exchange_id_u32)`.
- SessionIntent (44 B): `ver=1 u8 || purpose u8(1/2) || profile u8=1 ||
  flags u8=0 || caps_I u32 || boot_I u32(nonzero) || binding32`.
- SessionState (24 B): `ver/purpose/profile/flags || site_epoch u32 ||
  rs_epoch u32 || gk_epoch u32 || boot u32(nonzero) || caps u32`.
- ContextConfirm (36 B): `ver/purpose/profile/flags || contexts_digest32`.
- Exporter context: the 15-element definite-length CBOR array
  `["RouteLoom", 1, purpose, full_network, node_I, node_R, kid_I:bstr32,
  kid_R:bstr32, role_I:u32, role_R:u32, [gen_I, gen_R], [2, 0],
  context_epoch:u32, direction:u8, capability_digest:bstr32]`, ≤ 256 B.
- `capability_digest = SHA-256("RouteLoom/v1/session-profile" || 00 ||
  Intent44 || State_R24 || State_I24)`; `contexts_digest =
  SHA-256("RouteLoom/v1/context-confirm" || 00 || len16(C_1) || C_1 ||
  len16(C_2) || C_2 || len16(C_RMS) || C_RMS)`.
- `EDHOC_Exporter(PRK, label, context, L) = HKDF-Expand(PRK,
  uint(label) || bstr(context) || uint(L), L)` (RFC 9528 §4.2.1).
