// Fuzz target: SDK v1 zero-touch join EAD codecs
// (components/routeloom/src/sdkv1_ead.cpp, plan P2-3) — the EAD field walk
// for each of the four join messages, the JoinIntent / SiteOffer /
// JoinRequest / SitePackage / JoinResult value decoders, the RemovalNotice
// Sign1 and the device-side Allow check. Every decoder sees the same raw
// input. A successful decode is re-encoded and must reproduce the input
// (each value has exactly one encoding); a JoinResult view must stay inside
// the input. Seeds: tests/fuzz/corpus/sdkv1_ead, written by
// tools/gen_sdkv1_ead_vectors.py from the shared golden vectors.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "routeloom/sdkv1_ead.hpp"

#include "fuzz_driver.hpp"

namespace {

using namespace routeloom;
using namespace routeloom::sdkv1;

template <std::size_t N>
void require_same(const ByteBuffer<N>& encoded, const ByteView input) {
  if (encoded.size != input.size || std::memcmp(encoded.bytes.data(), input.data, input.size) != 0) {
    std::abort();  // decode accepted a non-canonical encoding
  }
}

bool inside(const ByteView part, const ByteView whole) {
  if (part.size == 0) return true;
  return part.data >= whole.data && part.data + part.size <= whole.data + whole.size;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size > 2048) return 0;
  const ByteView input{data, size};

  for (const JoinEad label : {JoinEad::Intent, JoinEad::Offer, JoinEad::Request, JoinEad::Result}) {
    ByteView value{};
    if (join_ead_find(input, label, value).ok()) {
      if (!inside(value, input) || value.size == 0) std::abort();
      JoinResult result{};
      if (label == JoinEad::Result) (void)join_result_decode(value, result);
    }
  }

  // P3-1: EAD_2/EAD_3 with the Credential item (label 65541) first.
  for (const JoinEad label : {JoinEad::Offer, JoinEad::Request}) {
    ByteView credential{};
    ByteView value{};
    if (join_ead_find_with_credential(input, label, credential, value).ok()) {
      if (!inside(credential, input) || !inside(value, input) || credential.size == 0 ||
          value.size == 0) {
        std::abort();
      }
      CertClaims claims{};
      (void)join_credential_check(credential, label == JoinEad::Offer ? CertType::Site
                                                                       : CertType::Device,
                                  ByteView{data, size < 32 ? size : 32}, claims);
    }
  }

  JoinIntent intent{};
  if (join_intent_decode(input, intent).ok()) {
    ByteBuffer<kJoinIntentSize> out{};
    if (!join_intent_encode(intent, out).ok()) std::abort();
    require_same(out, input);
  }
  SiteOffer offer{};
  if (site_offer_decode(input, offer).ok()) {
    ByteBuffer<kSiteOfferSize> out{};
    if (!site_offer_encode(offer, out).ok()) std::abort();
    require_same(out, input);
  }
  JoinRequest request{};
  if (join_request_decode(input, request).ok()) {
    ByteBuffer<kJoinRequestSize> out{};
    if (!join_request_encode(request, out).ok()) std::abort();
    require_same(out, input);
  }
  SitePackage package{};
  if (site_package_decode(input, package).ok()) {
    ByteBuffer<kSitePackageSize> out{};
    if (!site_package_encode(package, out).ok()) std::abort();
    require_same(out, input);
  }

  RemovalNotice notice{};
  if (removal_notice_decode(input, notice).ok()) {
    bool verified = false;
    P256PublicKey key{};
    std::memcpy(key.data(), data, size < key.size() ? size : key.size());
    (void)removal_notice_verify(input, key, notice.site_id, notice.site_id, notice.node_id,
                                notice.generation, notice, verified);
  }

  JoinResult result{};
  if (join_result_decode(input, result).ok()) {
    if (!inside(result.member_cert, input) || !inside(result.assignment_ticket, input) ||
        !inside(result.pending_ticket, input) || !inside(result.removal_notice, input)) {
      std::abort();
    }
    ByteBuffer<kJoinResultMax> out{};
    if (!join_result_encode(result, out).ok()) std::abort();
    require_same(out, input);
    if (result.verdict == JoinVerdict::Allow) {
      // Exercise the 02 §10.2 path with a SiteCert-shaped claim derived
      // from the MemberCert itself (signature check will mostly fail).
      CertClaims member{};
      if (cert_decode(result.member_cert, member).ok()) {
        CertClaims site{};
        site.type = CertType::Site;
        site.subject = member.issuer;
        site.network_low32 = static_cast<std::uint32_t>(member.network);
        site.site_epoch = member.site_epoch;
        site.pubkey = member.pubkey;
        bool verified = false;
        CertClaims out_member{};
        (void)join_allow_verify(result, site, member.subject, member.pubkey, (size & 1U) != 0,
                                out_member, verified);
      }
    }
  }
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
