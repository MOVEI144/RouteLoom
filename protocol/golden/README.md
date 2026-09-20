# Wire v1 shared golden vectors

Byte-exact test vectors for the frozen Wire v1 frame format
(`components/routeloom/include/routeloom/wire.hpp`). Both the C++ harness
(`tests/cpp/test_golden.cpp`) and the Rust harness
(`host/routeloom-wire/tests/golden.rs`) load these files and must agree on
every byte.

## Cipher and key material

The production crypto suite is still pending (G-SEC). These vectors use the
**deterministic test cipher** implemented identically in:

- `tests/cpp/test_security.hpp` (`routeloom_test::TestSecurity`)
- `host/routeloom-wire/src/test_security.rs` (`TestSecurity`)

Scheme (not a real AEAD; test-only):

- `mix(s, v)`: `s ^= v + 0x9e3779b97f4a7c15 + (s<<6) + (s>>2)`, then
  `s *= 0xbf58476d1ce4e5b9` (all wrapping u64 arithmetic).
- `seed(ctx, ctr)`: state `0x726f7574656c6f6f` mixed with scope, network,
  sender, receiver, epoch, then the counter.
- Encryption: `state = seed`; for byte `i`, `state = mix(state, i+1)` and
  `ct[i] = pt[i] ^ (state >> 56)`.
- Tag: `left = seed`, `right = mix(seed, 0x746167)`; mix each AAD byte into
  `left`, each ciphertext byte into `right`; tag = `left` MSB-first (8B) then
  `right` MSB-first (8B).
- Contexts: link `(Link, network, previous_hop, next_hop, link_epoch)`, end
  `(EndToEnd, network, origin, destination, end_epoch)`.
- Each vector operation uses a fresh provider, so the first `next_counter`
  per context returns `link_counter = 0` / `end_counter = 0`.

All header fields are fixed-width big-endian (see wire.hpp for offsets).
`network` is the low 32 bits, node IDs are u64, `session` is the origin's
boot session, and the payload length excludes AEAD tags.

## Layout

- `valid/*.json` — flat objects with every header field, `payload_hex`, and
  `encoded_hex`. Optional `fwd_*` fields describe a relay re-wrap: the link
  layer is opened at `fwd_local_node` and re-sealed toward `fwd_next_hop`
  producing `fwd_encoded_hex` (end-protected plaintext carried unchanged).
- `invalid/*.json` — `expect: "link"` means `open_link` must fail;
  `expect: "end"` means the link layer opens but `open_end` at `end_node`
  must fail (tampered end tag re-wrapped by a relay).

Regenerate with `cargo run -p routeloom-wire --example gen_golden`, then run
both test harnesses to confirm cross-language agreement.
