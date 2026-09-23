// Fuzz target: SDK v1 record and certificate decoders
// (components/routeloom/src/{rlcw1,sdkv1_records}.cpp) — RLCW1 certificates,
// the RRS1 Sign1 object and storage record, RLI1, RLS1 and RLP1, plus the
// structure-only gates the dual-slot classifier runs on untrusted flash.
// Every decoder sees the same raw input; a successful certificate decode is
// re-encoded and must reproduce the input (canonical encoding is unique).

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_records.hpp"

#include "fuzz_driver.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace routeloom;
  using namespace routeloom::sdkv1;
  if (size > 2048) return 0;
  const ByteView input{data, size};

  CertClaims claims{};
  if (cert_decode(input, claims).ok()) {
    CoseEs256Parts parts{};
    if (!cert_parse(input, parts).ok()) std::abort();
    ByteBuffer<kRlcw1PayloadMax> payload{};
    if (!cert_payload_encode(claims, payload).ok() || payload.size != parts.payload.size ||
        std::memcmp(payload.bytes.data(), parts.payload.data, payload.size) != 0) {
      std::abort();  // decode accepted a non-canonical encoding
    }
    bool verified = false;
    CertClaims again{};
    (void)cert_verify(input, claims.pubkey, again, verified);
  }
  (void)cert_payload_decode(input, claims);

  RevocationSet set{};
  if (revocation_object_decode(input, set).ok()) {
    bool verified = false;
    P256PublicKey key{};
    std::memcpy(key.data(), data, size < key.size() ? size : key.size());
    (void)revocation_object_verify(input, key, set.site_id, set.network, set, verified);
  }
  (void)revocation_payload_decode(input, set);
  ByteView object{};
  (void)revocation_record_decode(input, set, object);
  (void)revocation_record_structure(input);

  IdentityRecord identity{};
  (void)identity_record_decode(input, identity);
  (void)identity_record_structure(input);
  SiteRecord site{};
  (void)site_record_decode(input, site);
  (void)site_record_structure(input);
  ResumeSlot slot{};
  (void)resume_slot_decode(input, slot);
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
