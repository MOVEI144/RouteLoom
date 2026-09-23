# RFC 9529 EDHOC trace (upstream test vectors)

[chapter3.txt](chapter3.txt) holds the values of
[RFC 9529](https://www.rfc-editor.org/rfc/rfc9529.html) §3 — EDHOC method 3
(static DH both ways), cipher suite 2 (P-256, SHA-256, AES-CCM-16-64-128),
CCS credentials referenced by `kid` — and every invalid message of §4.
They are **upstream IETF vectors**, not RouteLoom goldens: nothing here is
generated from RouteLoom code, and the keys are public test keys that must
never appear in a deployment.

`tools/extract_rfc9529_vectors.py` copies them verbatim from the RFC text
(it checks the text's SHA-256 first, and keeps each value's section and
label as a comment); it needs the RFC downloaded and is not part of the
golden regeneration. The C++ test `tests/cpp/test_edhoc.cpp`
(`routeloom_edhoc_tests`) replays them through the vendored libedhoc and
`routeloom::edhoc` (docs/design/sdk-v1/08 P2-1):

| RFC 9529 | checked |
|---|---|
| §3.1–3.2 | a suite-2 Responder refuses the suite-6 message_1 and answers with the §3.2 error byte for byte; the Initiator reads SUITES_R from it |
| §3.3–3.6 | message_1..message_4 byte for byte, with the RFC's ephemeral private keys fed through the session RNG (G_X, G_Y, G_XY, G_RX, G_IY are computed, not injected) |
| §3.4–3.5 | PRK_3e2m and PRK_4e3m on both sides |
| §3.7 | PRK_out; PRK_exporter recomputed from that PRK_out (libedhoc keeps it only transiently) |
| §3.8 | OSCORE master secret / salt and sender / recipient ids, via both the OSCORE export and the raw exporter (labels 0/1) |
| §3.9 | key update: new PRK_out, PRK_exporter and OSCORE secret / salt |
| §4 | every invalid message_1 is refused — while decoding, or (x ≥ p, x not on P-256) by the backend's point validation before any message_2 exists — except §4.1.2 (C_I sent as the byte string `41 0e`), a non-deterministic encoding libedhoc at the pinned commit accepts as the same C_I; the invalid message_2 and the three invalid PLAINTEXT_2 (re-encrypted with the RFC's keystream construction) are refused |

§2 (method 0, cipher suite 0: X25519 / EdDSA) is not replayed: RouteLoom's
backend implements suite 2 only. Method 0 — RouteLoom's profile — is covered
with suite 2 by the RLCW1 MemberCert round trip in the same test (ECDSA
signatures are not reproducible byte for byte across implementations).

## License of the extracted values

Copyright (c) 2024 IETF Trust and the persons identified as the document
authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
- Neither the name of Internet Society, IETF or IETF Trust, nor the names of
  specific contributors, may be used to endorse or promote products derived
  from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
