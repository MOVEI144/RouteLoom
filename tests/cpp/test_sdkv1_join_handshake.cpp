// SDK v1 zero-touch join handshake driver (plan P3-4 PR 1,
// sdkv1_join_handshake.hpp). A real method-0 / suite-2 exchange against a
// scripted Site Authority (a second edhoc::Session with the join EAD
// plumbing), then the decide() verification matrix — the 02 §10.2 Allow
// checks, every authenticated verdict class, the m2 gate (a forged SiteCert
// never draws a DevCert out of the device), the DAMS exporter context
// vectors of protocol/sdkv1-golden/dams/ and the stored-record
// re-verifier.

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include "routeloom/edhoc.hpp"
#include "routeloom/sdkv1_join_handshake.hpp"
#include "routeloom/sdkv1_join_transport.hpp"  // kJoinMessageMax
#include "routeloom/secure_clear.hpp"

#include "test_sdkv1.hpp"

#ifndef ROUTELOOM_SDKV1_GOLDEN_DIR
#define ROUTELOOM_SDKV1_GOLDEN_DIR "protocol/sdkv1-golden"
#endif

namespace {

int failures = 0;
std::string current;
#define CHECK(expr)                                                                  \
  do {                                                                               \
    if (!(expr)) {                                                                   \
      std::fprintf(stderr, "CHECK failed %s:%d [%s]: %s\n", __FILE__, __LINE__,      \
                   current.c_str(), #expr);                                          \
      ++failures;                                                                    \
    }                                                                                \
  } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;
using namespace sdkv1_test;
using Bytes = std::vector<std::uint8_t>;

// --- Deterministic entropy (C_I + ephemeral draws) ------------------------------
class TestEntropy final : public routeloom::EntropySource {
 public:
  explicit TestEntropy(const std::uint64_t seed) : state_(seed | 1) {}
  Status fill(const MutableByteView out) noexcept override {
    if (fail_at != 0 && ++calls == fail_at) {
      return Status::error(StatusCode::InternalError, "injected entropy failure");
    }
    for (std::size_t i = 0; i < out.size; ++i) {
      state_ ^= state_ << 13U;
      state_ ^= state_ >> 7U;
      state_ ^= state_ << 17U;
      out.data[i] = static_cast<std::uint8_t>(state_ >> 32U);
    }
    return Status::success();
  }
  std::size_t calls{0};
  std::size_t fail_at{0};  // 1-based fill call index to fail (0 = never)

 private:
  std::uint64_t state_;
};

// The session's ephemeral draw uses the same RandomFn: this wraps the
// EntropySource-shaped TestEntropy for the authority's own session.
bool entropy_random(void* ctx, std::uint8_t* out, const std::size_t size) noexcept {
  return static_cast<TestEntropy*>(ctx)->fill(MutableByteView{out, size}).ok();
}

// --- Scripted Site Authority -----------------------------------------------------
// Its CredentialProvider stages the device's DevCert (EAD_3 Credential item)
// and resolves it under the Device CA; the EadHandler composes SiteOffer +
// a chosen certificate and a preset JoinResult value, and processes the
// intent/request items with the same token walk the device uses.
class AuthorityCreds final : public edhoc::CredentialProvider {
 public:
  AuthorityCreds(const ByteBuffer<kRlcw1CertMax>& own_cert, const Digest256& own_kid,
                 const std::array<std::uint8_t, 32>& priv)
      : own_cert_(own_cert), own_kid_(own_kid), priv_(priv) {}
  Status local(edhoc::Role, edhoc::LocalCredential& out) noexcept override {
    out.kid = ByteView{own_kid_.data(), own_kid_.size()};
    out.credential = own_cert_.view();
    out.private_key = priv_;
    return Status::success();
  }
  Status peer(edhoc::Role, const ByteView kid, edhoc::PeerCredential& out) noexcept override {
    if (staged.size == 0) return Status::error(StatusCode::NotFound, "no staged devcert");
    CertClaims claims{};
    Status status = join_credential_check(staged.view(), CertType::Device, kid, claims);
    if (!status) {
      ++rejected;
      return status;
    }
    bool verified = false;
    status = cert_verify(staged.view(), device_ca().pub, claims, verified);
    if (!status || !verified) {
      ++rejected;
      return Status::error(StatusCode::AuthenticationFailed, "devcert chain");
    }
    out.credential = staged.view();
    out.public_key = claims.pubkey;
    return Status::success();
  }
  ByteBuffer<kRlcw1CertMax> staged{};
  int rejected{0};

 private:
  const ByteBuffer<kRlcw1CertMax>& own_cert_;
  const Digest256& own_kid_;
  std::array<std::uint8_t, 32> priv_;
};

class AuthorityEad final : public edhoc::EadHandler {
 public:
  explicit AuthorityEad(AuthorityCreds& creds) : creds_(creds) {}
  Status compose(const int message, edhoc::EadItem* items, const std::size_t capacity,
                 std::size_t& count) noexcept override {
    count = 0;
    if (message == 2) {
      if (capacity < 2) return Status::error(StatusCode::NoCapacity, "ead capacity");
      items[count++] = edhoc::EadItem{-static_cast<std::int32_t>(JoinEad::Offer),
                                      offer_value.view()};
      if (credential_cert != nullptr) {
        items[count++] = edhoc::EadItem{-static_cast<std::int32_t>(JoinEad::Credential),
                                        credential_cert->view()};
      }
    } else if (message == 4) {
      if (result_value.size != 0) {
        items[count++] = edhoc::EadItem{-static_cast<std::int32_t>(JoinEad::Result),
                                        result_value.view()};
      }
    }
    return Status::success();
  }
  Status process(const int message, const edhoc::EadItem* items,
                 const std::size_t count) noexcept override {
    if (message == 1) {
      ByteView value{};
      ByteView ignored{};
      Status status = join_ead_items_check(items, count, JoinEad::Intent, false, value, ignored);
      if (!status) return status;
      return join_intent_decode(value, intent);
    }
    if (message == 3) {
      ByteView value{};
      ByteView cert{};
      Status status = join_ead_items_check(items, count, JoinEad::Request, true, value, cert);
      if (!status) return status;
      status = join_request_decode(value, request);
      if (!status) return status;
      creds_.staged.clear();
      std::memcpy(creds_.staged.bytes.data(), cert.data, cert.size);
      creds_.staged.size = cert.size;
      return Status::success();
    }
    return Status::error(StatusCode::ProtocolError, "unexpected ead");
  }
  JoinIntent intent{};
  JoinRequest request{};
  ByteBuffer<kSiteOfferSize> offer_value{};
  ByteBuffer<kJoinResultMax> result_value{};
  const ByteBuffer<kRlcw1CertMax>* credential_cert{nullptr};

 private:
  AuthorityCreds& creds_;
};

struct Authority {
  Authority(const ByteBuffer<kRlcw1CertMax>& site_cert, const Digest256& sak_kid,
            std::uint64_t rng_seed,
            const std::array<std::uint8_t, 32>* sign_priv = nullptr)
      : entropy(rng_seed),
        creds(site_cert, sak_kid, sign_priv != nullptr ? *sign_priv : sak().priv),
        ead(creds) {
    edhoc::SessionConfig config{};
    config.role = edhoc::Role::Responder;
    config.method = edhoc::Method::SignatureSignature;
    static std::array<std::uint8_t, 4> cr{0xA1, 0xA2, 0xA3, 0xA4};
    config.connection_id = ByteView{cr.data(), cr.size()};
    config.credentials = &creds;
    config.ead = &ead;
    config.random = &entropy_random;
    config.random_ctx = &entropy;
    CHECK(session.begin(config).ok());
    SiteOffer offer{};
    offer.site_id = kSiteId;
    offer.network_low32 = kNetworkLow;
    offer.site_epoch = kSiteEpoch;
    CHECK(site_offer_encode(offer, ead.offer_value).ok());
  }
  TestEntropy entropy;
  AuthorityCreds creds;
  AuthorityEad ead;
  edhoc::Session session;
};

struct Transcript {
  Bytes m1, m2, m3, m4;
};

ByteView view(const Bytes& bytes) { return ByteView{bytes.data(), bytes.size()}; }

// Runs m1..m4 between the device handshake and the authority. `tamper`
// bit-flips the last byte of message N (1..4). Returns the stage reached:
// 0 m1 never composed/processed, 1 m2 failed on the device, 2 m3 failed,
// 3 m4 failed, 4 done. `m2_status` (when set) receives the device's m2
// Status so tests can pin the failure classification, not just the stage.
int exchange(JoinHandshake& hs, Authority& auth, Transcript& t, const int tamper = 0,
             Status* m2_status = nullptr) {
  std::array<std::uint8_t, kJoinMessageMax> buffer{};
  std::size_t length = 0;
  const auto flip = [&](Bytes& m, const int which) {
    if (which == tamper && !m.empty()) m[m.size() - 1] ^= 0x01;
  };
  if (!hs.compose_m1(MutableByteView{buffer.data(), buffer.size()}, length)) return 0;
  t.m1.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length));
  flip(t.m1, 1);
  if (!auth.session.process_message_1(view(t.m1)).ok()) return 0;
  if (!auth.session.compose_message_2(MutableByteView{buffer.data(), buffer.size()}, length).ok())
    return 0;
  t.m2.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length));
  flip(t.m2, 2);
  const Status m2 = hs.process_m2(view(t.m2));
  if (m2_status != nullptr) *m2_status = m2;
  if (!m2) return 1;
  if (!hs.compose_m3(MutableByteView{buffer.data(), buffer.size()}, length)) return 2;
  t.m3.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length));
  flip(t.m3, 3);
  if (!auth.session.process_message_3(view(t.m3)).ok()) return 2;
  if (!auth.session.compose_message_4(MutableByteView{buffer.data(), buffer.size()}, length).ok())
    return 3;
  t.m4.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length));
  flip(t.m4, 4);
  if (!hs.process_m4(view(t.m4))) return 3;
  return 4;
}

// --- Fixtures -------------------------------------------------------------------
struct JoinFixture {
  JoinFixture()
      : identity(identity_record()),
        sitecert(issue(sitecert_claims(), site_ca())),
        membercert(issue(membercert_claims(), sak())) {
    CHECK(cert_subject_kid(sitecert_claims(), sak_kid).ok());
    config.node = identity.node_id;
    config.org_hint = join_org_hint(site_ca().pub);
    config.site_hint = join_site_hint(kSiteId);
    config.network_low32 = kNetworkLow;
    config.fw_version = 0x01040000;
    config.capability = kMemberRoleMask;
    config.requested_role = kMemberRoleEndpoint;
    SitePackage& p = package;
    p.site_id = kSiteId;
    p.network = kNetwork;
    p.rs_epoch = 14;
    p.gk_epoch = 203;
    p.gk.fill(0x6B);
    p.role = kMemberRoleEndpoint;
    p.channel = 6;
    p.channel_epoch = 9;
    p.gateway_count = 2;
    p.gateways[0] = 0x00A1000000000001ULL;
    p.gateways[1] = 0x00A1000000000002ULL;
    p.authority_time_s = 1700000000;
    p.time_uncertainty_ms = 150;
    p.membership_revision = 7;
  }
  IdentityRecord identity;
  ByteBuffer<kRlcw1CertMax> sitecert;
  ByteBuffer<kRlcw1CertMax> membercert;
  Digest256 sak_kid{};
  SitePackage package{};
  JoinHandshakeConfig config{};

  // Encodes a JoinResult for the authority's EAD_4. `member` defaults to the
  // fixture cert; pass a different certificate or package to build an
  // authenticated-but-invalid Allow.
  void result(JoinVerdict verdict, ByteBuffer<kJoinResultMax>& out,
              ByteView member = ByteView{}, const SitePackage* pack = nullptr,
              std::uint32_t retry = 0, ByteView removal = ByteView{}) {
    JoinResult r{};
    r.verdict = verdict;
    r.retry_after_s = retry;
    if (verdict == JoinVerdict::Allow) {
      r.member_cert = member.data == nullptr ? membercert.view() : member;
      r.site_package = pack == nullptr ? package : *pack;
    }
    if (verdict == JoinVerdict::PendingAssignment) {
      static const std::array<std::uint8_t, 8> ticket{0x54, 0x49, 0x43, 0x4B,
                                                    0x45, 0x54, 0x30, 0x31};
      r.pending_ticket = ByteView{ticket.data(), ticket.size()};
    }
    if (verdict == JoinVerdict::Removed) r.removal_notice = removal;
    out.clear();
    CHECK(join_result_encode(r, out).ok());
  }
};

// Freshly-issued signed notices for the Removed verdict.
ByteBuffer<kRemovalNoticeObjectSize> removal_notice(const RemovalNotice& notice,
                                                    const routeloom_test::TestKeyPair& signer,
                                                    const NetworkId aad_network) {
  ByteBuffer<kRemovalNoticePayloadSize> payload{};
  ByteBuffer<kRemovalNoticeAadSize> aad{};
  ByteBuffer<kRemovalNoticeObjectSize> object{};
  CHECK(removal_notice_payload_encode(notice, payload).ok());
  CHECK(removal_notice_aad(aad_network, aad).ok());
  Es256Signature signature{};
  sign_payload(signer, payload.view(), aad.view(), signature);
  CHECK(removal_notice_assemble(payload.view(), ByteView{signature.data(), signature.size()},
                                object)
            .ok());
  return object;
}

bool all_zero(const ByteView bytes) {
  std::uint8_t acc = 0;
  for (std::size_t i = 0; i < bytes.size; ++i) acc |= bytes.data[i];
  return acc == 0;
}

// --- Vector loading (same flat-JSON reader as test_sdkv1_ead.cpp) ----------------
using Fields = std::map<std::string, std::string>;

Fields parse_flat_json(const std::string& text) {
  Fields fields;
  std::size_t pos = 0;
  while (pos < text.size()) {
    const std::size_t key_begin = text.find('"', pos);
    if (key_begin == std::string::npos) break;
    const std::size_t key_end = text.find('"', key_begin + 1);
    if (key_end == std::string::npos) break;
    const std::size_t colon = text.find(':', key_end + 1);
    if (colon == std::string::npos) break;
    std::size_t cursor = colon + 1;
    while (cursor < text.size() && std::isspace(static_cast<unsigned char>(text[cursor]))) {
      ++cursor;
    }
    std::string value;
    if (cursor < text.size() && text[cursor] == '"') {
      const std::size_t value_end = text.find('"', cursor + 1);
      if (value_end == std::string::npos) break;
      value = text.substr(cursor + 1, value_end - cursor - 1);
      pos = value_end + 1;
    } else {
      std::size_t value_end = cursor;
      while (value_end < text.size() &&
             std::isdigit(static_cast<unsigned char>(text[value_end]))) {
        ++value_end;
      }
      value = text.substr(cursor, value_end - cursor);
      pos = value_end;
    }
    fields[text.substr(key_begin + 1, key_end - key_begin - 1)] = value;
  }
  return fields;
}

std::uint64_t num(const Fields& fields, const std::string& key) {
  const auto it = fields.find(key);
  if (it == fields.end() || it->second.empty()) {
    std::fprintf(stderr, "[%s] missing numeric field %s\n", current.c_str(), key.c_str());
    ++failures;
    return 0;
  }
  return std::strtoull(it->second.c_str(), nullptr, 10);
}

Bytes hex(const Fields& fields, const std::string& key) {
  Bytes out;
  const auto it = fields.find(key);
  if (it == fields.end() || it->second.size() % 2 != 0) {
    std::fprintf(stderr, "[%s] missing hex field %s\n", current.c_str(), key.c_str());
    ++failures;
    return out;
  }
  for (std::size_t i = 0; i < it->second.size(); i += 2) {
    out.push_back(
        static_cast<std::uint8_t>(std::strtoul(it->second.substr(i, 2).c_str(), nullptr, 16)));
  }
  return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> hex_array(const Fields& fields, const std::string& key) {
  std::array<std::uint8_t, N> out{};
  const auto bytes = hex(fields, key);
  if (bytes.size() == N) {
    std::copy(bytes.begin(), bytes.end(), out.begin());
  } else {
    std::fprintf(stderr, "[%s] field %s is not %zu bytes\n", current.c_str(), key.c_str(), N);
    ++failures;
  }
  return out;
}

// --- Tests -----------------------------------------------------------------------

void test_dams_context_vectors() {
  const std::filesystem::path dir =
      std::filesystem::path(ROUTELOOM_SDKV1_GOLDEN_DIR) / "dams" / "valid";
  std::size_t count = 0;
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (entry.path().extension() != ".json") continue;
    ++count;
    std::ifstream in(entry.path());
    std::stringstream buffer;
    buffer << in.rdbuf();
    const Fields fields = parse_flat_json(buffer.str());
    current = entry.path().filename().string();
    ByteBuffer<kJoinDamsContextMax> context{};
    const Status status =
        dams_exporter_context(num(fields, "network"), num(fields, "node_id"),
                              num(fields, "site_id"), hex_array<32>(fields, "device_kid_hex"),
                              hex_array<32>(fields, "sak_kid_hex"), context);
    const Bytes want = hex(fields, "context_hex");
    CHECK(status.ok());
    CHECK(context.size == want.size() &&
          std::memcmp(context.bytes.data(), want.data(), want.size()) == 0);
  }
  CHECK(count >= 3);
  // The invalid vectors must not produce a context.
  const std::filesystem::path bad_dir =
      std::filesystem::path(ROUTELOOM_SDKV1_GOLDEN_DIR) / "dams" / "invalid";
  for (const auto& entry : std::filesystem::directory_iterator(bad_dir)) {
    if (entry.path().extension() != ".json") continue;
    std::ifstream in(entry.path());
    std::stringstream buffer;
    buffer << in.rdbuf();
    const Fields fields = parse_flat_json(buffer.str());
    current = entry.path().filename().string();
    ByteBuffer<kJoinDamsContextMax> context{};
    CHECK(!dams_exporter_context(num(fields, "network"), num(fields, "node_id"),
                                 num(fields, "site_id"), hex_array<32>(fields, "device_kid_hex"),
                                 hex_array<32>(fields, "sak_kid_hex"), context)
               .ok());
  }
  current.clear();
}

void test_allow() {
  current = "allow";
  JoinFixture fx;
  Authority authority(fx.sitecert, fx.sak_kid, 0x71);
  authority.ead.credential_cert = &fx.sitecert;
  fx.result(JoinVerdict::Allow, authority.ead.result_value);

  JoinHandshake hs;
  TestEntropy entropy(0xA17);
  CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
  Transcript t;
  CHECK(exchange(hs, authority, t) == 4);
  CHECK(hs.m2_authenticated());
  CHECK(hs.offer().site_id == kSiteId && hs.offer().network_low32 == kNetworkLow);
  CHECK(hs.site_claims().subject == kSiteId);
  CHECK(authority.ead.intent.org_hint == join_org_hint(site_ca().pub));
  CHECK(authority.ead.request.model == 17);       // DevCert model flowed into JoinRequest
  CHECK(authority.ead.request.last_site_id == 0); // fresh join
  CHECK(authority.creds.staged.size == fx.identity.devcert.size);

  JoinDecideInput input{};
  input.boot_witness = 99;
  JoinDecided decided{};
  CHECK(hs.decide(input, decided).ok());
  CHECK(decided.outcome == JoinAttemptOutcome::AllowVerified);
  CHECK(decided.record != nullptr);
  CHECK(hs.outcome() == JoinAttemptOutcome::AllowVerified);
  const SiteRecord& record = *decided.record;
  CHECK(record.state == SiteState::Member);
  CHECK(record.site_id == kSiteId && record.network == kNetwork);
  CHECK(record.assignment_generation == 3);
  CHECK(record.rs_epoch_floor == 0);  // not a recovery join
  CHECK(decided.rs_epoch_to_fetch == 14);
  CHECK(record.gk_epoch_current == 203 && record.gk_epoch_next == 0);
  CHECK(!all_zero(ByteView{record.gk_current.data(), record.gk_current.size()}));
  CHECK(!all_zero(ByteView{record.dams.data(), record.dams.size()}));
  CHECK(record.role == kMemberRoleEndpoint);
  CHECK(record.gateway_count == 2 && record.channel == 6 && record.channel_epoch == 9);
  CHECK(record.boot_witness == 99);
  CHECK(record.site_cert.size == fx.sitecert.size);
  CHECK(record.member_cert.size == fx.membercert.size);

  // The DAMS is the authenticated session's exporter output: the authority
  // must derive the same bytes for the same context.
  ByteBuffer<kJoinDamsContextMax> context{};
  CHECK(dams_exporter_context(kNetwork, fx.identity.node_id, kSiteId, fx.identity.kid,
                              hs.sak_kid(), context)
            .ok());
  std::array<std::uint8_t, kJoinDamsSize> peer_dams{};
  CHECK(authority.session
            .exporter(32771, context.view(), MutableByteView{peer_dams.data(), peer_dams.size()})
            .ok());
  CHECK(std::memcmp(peer_dams.data(), record.dams.data(), record.dams.size()) == 0);

  // The prepared record re-verifies like a stored one.
  bool verified = false;
  CHECK(join_membership_verify(record, fx.identity, verified).ok() && verified);

  // Stats: one clean pass.
  const JoinAttemptStats& stats = hs.stats();
  CHECK(stats.m1_composed == 1 && stats.m2_authenticated == 1 && stats.m3_composed == 1 &&
        stats.m4_authenticated == 1);
  CHECK(stats.m2_failures == 0 && stats.ead_rejects == 0 && stats.credential_rejects == 0 &&
        stats.allows_denied == 0);
  hs.end();
  CHECK(all_zero(ByteView{record.dams.data(), record.dams.size()}));  // wiped
}

void test_recovery_join_keeps_floor() {
  current = "recovery join";
  JoinFixture fx;
  fx.config.last_site_id = kSiteId;
  fx.config.last_generation = 3;
  Authority authority(fx.sitecert, fx.sak_kid, 0x73);
  authority.ead.credential_cert = &fx.sitecert;
  fx.result(JoinVerdict::Allow, authority.ead.result_value);
  JoinHandshake hs;
  TestEntropy entropy(0xB22);
  CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
  Transcript t;
  CHECK(exchange(hs, authority, t) == 4);
  JoinDecideInput input{};
  input.boot_witness = 5;
  input.prior_rs_epoch_floor = 14;  // previously accepted floor
  JoinDecided decided{};
  CHECK(hs.decide(input, decided).ok());
  CHECK(decided.outcome == JoinAttemptOutcome::AllowVerified);
  CHECK(decided.record->rs_epoch_floor == 14);  // kept for the held membership
}

void test_verdicts() {
  JoinFixture fx;
  const struct {
    JoinVerdict verdict;
    std::uint32_t retry;
    JoinAttemptOutcome outcome;
  } cases[] = {
      {JoinVerdict::PendingAssignment, 60, JoinAttemptOutcome::PendingAssignment},
      {JoinVerdict::AuthorityBusy, 2, JoinAttemptOutcome::AuthorityBusy},
      {JoinVerdict::DenyNotHere, 0, JoinAttemptOutcome::DenyNotHere},
      {JoinVerdict::DenyBlocked, 0, JoinAttemptOutcome::DenyBlocked},
  };
  for (const auto& c : cases) {
    current = "verdict " + std::to_string(static_cast<int>(c.verdict));
    Authority authority(fx.sitecert, fx.sak_kid, 0x81);
    authority.ead.credential_cert = &fx.sitecert;
    fx.result(c.verdict, authority.ead.result_value, ByteView{}, nullptr, c.retry);
    JoinHandshake hs;
    TestEntropy entropy(0xC0 + c.retry);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    CHECK(exchange(hs, authority, t) == 4);
    JoinDecideInput input{};
    JoinDecided decided{};
    CHECK(hs.decide(input, decided).ok());
    CHECK(decided.outcome == c.outcome);
    CHECK(decided.retry_after_s == c.retry);
    CHECK(decided.record == nullptr);
    hs.end();
  }

  // Removed: verified, denied and no-membership classifications.
  const JoinMembershipEvidence membership{kSiteId, kNetwork, kNode, 3, sak().pub};
  {
    current = "removed verified";
    RemovalNotice notice{};
    notice.reason = RevocationReason::Removed;
    notice.site_id = kSiteId;
    notice.node_id = kNode;
    notice.generation = 3;
    notice.rs_epoch = 15;
    const auto object = removal_notice(notice, sak(), kNetwork);
    Authority authority(fx.sitecert, fx.sak_kid, 0x85);
    authority.ead.credential_cert = &fx.sitecert;
    fx.result(JoinVerdict::Removed, authority.ead.result_value, ByteView{}, nullptr, 0,
              object.view());
    JoinHandshake hs;
    TestEntropy entropy(0xC3);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    CHECK(exchange(hs, authority, t) == 4);
    JoinDecideInput input{};
    input.membership = &membership;
    JoinDecided decided{};
    CHECK(hs.decide(input, decided).ok());
    CHECK(decided.outcome == JoinAttemptOutcome::RemovedVerified);
    CHECK(decided.removal.site_id == kSiteId && decided.removal.generation == 3);
    hs.end();
  }
  {
    // Signed by a key that is not the membership's SAK: denied.
    current = "removed denied signer";
    RemovalNotice notice{};
    notice.reason = RevocationReason::Removed;
    notice.site_id = kSiteId;
    notice.node_id = kNode;
    notice.generation = 3;
    notice.rs_epoch = 15;
    const auto object = removal_notice(notice, other_key(), kNetwork);
    Authority authority(fx.sitecert, fx.sak_kid, 0x87);
    authority.ead.credential_cert = &fx.sitecert;
    fx.result(JoinVerdict::Removed, authority.ead.result_value, ByteView{}, nullptr, 0,
              object.view());
    JoinHandshake hs;
    TestEntropy entropy(0xC4);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    CHECK(exchange(hs, authority, t) == 4);
    JoinDecideInput input{};
    input.membership = &membership;
    JoinDecided decided{};
    CHECK(hs.decide(input, decided).ok());
    CHECK(decided.outcome == JoinAttemptOutcome::RemovedDenied);
    CHECK(hs.stats().notices_denied == 1);
    hs.end();
  }
  {
    // No stored membership: the notice cannot be evaluated at all.
    current = "removed no membership";
    RemovalNotice notice{};
    notice.reason = RevocationReason::Removed;
    notice.site_id = kSiteId;
    notice.node_id = kNode;
    notice.generation = 3;
    notice.rs_epoch = 15;
    const auto object = removal_notice(notice, sak(), kNetwork);
    Authority authority(fx.sitecert, fx.sak_kid, 0x89);
    authority.ead.credential_cert = &fx.sitecert;
    fx.result(JoinVerdict::Removed, authority.ead.result_value, ByteView{}, nullptr, 0,
              object.view());
    JoinHandshake hs;
    TestEntropy entropy(0xC5);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    CHECK(exchange(hs, authority, t) == 4);
    JoinDecideInput input{};
    JoinDecided decided{};
    CHECK(hs.decide(input, decided).ok());
    CHECK(decided.outcome == JoinAttemptOutcome::RemovedNoMembership);
    CHECK(hs.stats().removed_without_membership == 1);
    hs.end();
  }
  current.clear();
}

// Raw SitePackage bytes (the layout of 02 §6.2, no validation) for
// packages the encoder itself refuses.
void raw_package(const SitePackage& p, ByteBuffer<kSitePackageSize>& out) {
  out.clear();
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(kJoinEadVersion);
  if (status) status = writer.write_u8(0);
  if (status) status = writer.write_u16(0);
  if (status) status = writer.write_u64(p.site_id);
  if (status) status = writer.write_u64(p.network);
  if (status) status = writer.write_u32(p.rs_epoch);
  if (status) status = writer.write_u32(p.gk_epoch);
  if (status) status = writer.write_bytes(ByteView{p.gk.data(), p.gk.size()});
  if (status) status = writer.write_u8(p.channel);
  if (status) status = writer.write_u8(p.role);
  if (status) status = writer.write_u8(p.gateway_count);
  if (status) status = writer.write_u8(0);
  if (status) status = writer.write_u32(p.channel_epoch);
  for (const NodeId gateway : p.gateways) {
    if (status) status = writer.write_u64(gateway);
  }
  if (status) status = writer.write_u64(p.authority_time_s);
  if (status) status = writer.write_u32(p.time_uncertainty_ms);
  if (status) status = writer.write_u32(p.membership_revision);
  if (status) status = writer.write_u32(0);
  CHECK(status.ok());
  out.size = writer.size();
}

// JoinResult bytes the encode-level validation would refuse (the authority
// is not bound by our encoder's validate): head + u16 cert + package + u16
// ticket, no checks.
void raw_allow_result(ByteBuffer<kJoinResultMax>& out, const ByteView member,
                      const SitePackage& pack) {
  out.clear();
  ByteBuffer<kSitePackageSize> encoded{};
  raw_package(pack, encoded);
  ByteWriter writer(out.writable());
  Status status = writer.write_u8(kJoinEadVersion);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(JoinVerdict::Allow));
  if (status) status = writer.write_u16(0);
  if (status) status = writer.write_u32(0);
  if (status)
    status = writer.write_u16(
        static_cast<std::uint16_t>(2 + member.size + kSitePackageSize + 2));
  if (status) status = writer.write_u16(0);
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(member.size));
  if (status) status = writer.write_bytes(member);
  if (status) status = writer.write_bytes(encoded.view());
  if (status) status = writer.write_u16(0);
  CHECK(status.ok());
  out.size = writer.size();
}

// One authenticated Allow whose MemberCert or SitePackage fails the 02 §10.2
// matrix: the exchange itself is clean, decide() must refuse the record.
void test_allow_denials() {
  JoinFixture fx;
  const auto run = [&](const ByteBuffer<kRlcw1CertMax>& member,
                       const SitePackage* pack) -> JoinDecided {
    Authority authority(fx.sitecert, fx.sak_kid, 0x91);
    authority.ead.credential_cert = &fx.sitecert;
    fx.result(JoinVerdict::Allow, authority.ead.result_value, member.view(), pack);
    JoinHandshake hs;
    TestEntropy entropy(0xD1);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    CHECK(exchange(hs, authority, t) == 4);
    JoinDecideInput input{};
    JoinDecided decided{};
    CHECK(hs.decide(input, decided).ok());
    return decided;
  };
  const auto run_raw = [&](const ByteView member, const SitePackage& pack) -> JoinDecided {
    Authority authority(fx.sitecert, fx.sak_kid, 0x97);
    authority.ead.credential_cert = &fx.sitecert;
    raw_allow_result(authority.ead.result_value, member, pack);
    JoinHandshake hs;
    TestEntropy entropy(0xD3);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    CHECK(exchange(hs, authority, t) == 4);
    JoinDecideInput input{};
    JoinDecided decided{};
    CHECK(hs.decide(input, decided).ok());
    return decided;
  };

  struct CertCase {
    const char* name;
    CertClaims claims;
  };
  const CertCase cert_cases[] = {
      {"member subject not us", [] { auto c = membercert_claims(); c.subject = kPeer; return c; }()},
      {"member cnf not ours",
       [] { auto c = membercert_claims(); c.pubkey = other_key().pub; return c; }()},
      {"member wrong issuer",
       [] { auto c = membercert_claims(); c.issuer = kPeer; return c; }()},
      {"member wrong network",
       [] { auto c = membercert_claims(); c.network = kNetwork + 1; return c; }()},
      {"member forged sak",
       membercert_claims()},
  };
  for (const auto& c : cert_cases) {
    current = std::string("allow deny: ") + c.name;
    const bool forged = std::string(c.name) == "member forged sak";
    const auto& signer = forged ? device_ca() : sak();
    const auto cert = issue(c.claims, signer);
    CHECK(cert.size != 0);
    const JoinDecided decided = run(cert, nullptr);
    CHECK(decided.outcome == JoinAttemptOutcome::MalformedResult);
    CHECK(decided.record == nullptr);
  }

  // A SiteCert where the MemberCert is expected: encode-level checks cannot
  // stop the authority, decode() classifies it malformed.
  {
    current = "allow deny: member wrong type";
    const JoinDecided decided = run_raw(fx.sitecert.view(), fx.package);
    CHECK(decided.outcome == JoinAttemptOutcome::MalformedResult);
    CHECK(decided.record == nullptr);
  }

  struct PackCase {
    const char* name;
    SitePackage package;
    bool raw;  // encode-level validation refuses it: send the raw bytes
  };
  const PackCase pack_cases[] = {
      {"package wrong site",
       [] { auto p = JoinFixture().package; p.site_id = kPeer; return p; }(), false},
      {"package wrong network",
       [] { auto p = JoinFixture().package; p.network = kNetwork + 1; return p; }(), false},
      {"package role mismatch",
       [] { auto p = JoinFixture().package; p.role = kMemberRoleRelay; return p; }(), false},
      {"package channel 15",
       [] { auto p = JoinFixture().package; p.channel = 15; return p; }(), true},
      {"package no gateways",
       [] { auto p = JoinFixture().package; p.gateway_count = 0; return p; }(), true},
      {"package gk zero",
       [] { auto p = JoinFixture().package; p.gk.fill(0); return p; }(), true},
      {"package gateway dup",
       [] {
         auto p = JoinFixture().package;
         p.gateways[1] = p.gateways[0];
         return p;
       }(),
       true},
      {"package gk epoch zero",
       [] { auto p = JoinFixture().package; p.gk_epoch = 0; return p; }(), true},
  };
  for (const auto& c : pack_cases) {
    current = std::string("allow deny: ") + c.name;
    const JoinDecided decided =
        c.raw ? run_raw(fx.membercert.view(), c.package) : run(fx.membercert, &c.package);
    CHECK(decided.outcome == JoinAttemptOutcome::MalformedResult);
    CHECK(decided.record == nullptr);
  }
  current.clear();

  // "channel unusable" above only differs by the local mask: verify the same
  // allow passes with the default mask and fails with a narrowed one.
  current = "allow channel mask";
  SitePackage narrow = fx.package;
  narrow.channel = 14;
  Authority authority(fx.sitecert, fx.sak_kid, 0x93);
  authority.ead.credential_cert = &fx.sitecert;
  fx.result(JoinVerdict::Allow, authority.ead.result_value, fx.membercert.view(), &narrow);
  JoinHandshake hs;
  TestEntropy entropy(0xD9);
  auto config = fx.config;
  config.usable_channel_mask = 0x003E;  // channels 1..5 only
  CHECK(hs.begin(config, fx.identity, entropy).ok());
  Transcript t;
  CHECK(exchange(hs, authority, t) == 4);
  JoinDecideInput input{};
  JoinDecided decided{};
  CHECK(hs.decide(input, decided).ok());
  CHECK(decided.outcome == JoinAttemptOutcome::MalformedResult);
  CHECK(decided.record == nullptr);
  current.clear();
}

void test_strict_assignment_fails_closed() {
  current = "a2 strict";
  JoinFixture fx;
  fx.identity = identity_record(true);  // strict flag + active verifier anchor
  Authority authority(fx.sitecert, fx.sak_kid, 0x95);
  authority.ead.credential_cert = &fx.sitecert;
  fx.result(JoinVerdict::Allow, authority.ead.result_value);
  JoinHandshake hs;
  TestEntropy entropy(0xE1);
  CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
  Transcript t;
  CHECK(exchange(hs, authority, t) == 4);
  JoinDecideInput input{};
  JoinDecided decided{};
  CHECK(hs.decide(input, decided).ok());
  // A2: an Allow without a ticket is a deny; a ticket is Unsupported —
  // both fail closed through MalformedResult, never a stored record.
  CHECK(decided.outcome == JoinAttemptOutcome::MalformedResult);
  CHECK(decided.record == nullptr);
  current.clear();
}

void test_m2_failures() {
  JoinFixture fx;
  const auto run_m2 = [&](const ByteBuffer<kRlcw1CertMax>* credential) {
    Authority authority(fx.sitecert, fx.sak_kid, 0xA1);
    authority.ead.credential_cert = credential;
    JoinHandshake hs;
    TestEntropy entropy(0xF1);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    Status m2_status = Status::success();
    const int stage = exchange(hs, authority, t, 0, &m2_status);
    return std::tuple{stage, hs.outcome(), m2_status.code, authority.creds.staged.size};
  };

  // Wrong CA: claims identical, signed by the Device CA instead of the Site CA.
  current = "m2 wrong ca";
  const auto wrong_ca = issue(sitecert_claims(), device_ca());
  {
    const auto [stage, outcome, code, staged] = run_m2(&wrong_ca);
    CHECK(stage == 1 && outcome == JoinAttemptOutcome::AuthenticationFailed);
    CHECK(code == StatusCode::AuthenticationFailed);
    CHECK(staged == 0);  // no DevCert ever left the device (02 §12 row 2)
  }
  // Kid mismatch: the cert's cnf does not hash to ID_CRED_R's kid.
  current = "m2 kid mismatch";
  auto claims = sitecert_claims();
  claims.pubkey = other_key().pub;
  const auto wrong_cnf = issue(claims, site_ca());
  {
    const auto [stage, outcome, code, staged] = run_m2(&wrong_cnf);
    CHECK(stage == 1 && outcome == JoinAttemptOutcome::AuthenticationFailed);
    CHECK(code == StatusCode::AuthenticationFailed);
    CHECK(staged == 0);
  }
  // Wrong cert type: a DevCert where the SiteCert is expected.
  current = "m2 wrong type";
  {
    const auto [stage, outcome, code, staged] = run_m2(&fx.identity.devcert);
    CHECK(stage == 1 && outcome == JoinAttemptOutcome::AuthenticationFailed);
    CHECK(code == StatusCode::AuthenticationFailed);
    CHECK(staged == 0);
  }
  // No credential item at all: the profile item is missing, so the session
  // reports a protocol error and no credential is ever presented for
  // verification — transient, but still no m3 and no DevCert out.
  current = "m2 no credential";
  {
    const auto [stage, outcome, code, staged] = run_m2(nullptr);
    CHECK(stage == 1 && outcome == JoinAttemptOutcome::Failed);
    CHECK(code == StatusCode::ProtocolError);
    CHECK(staged == 0);
  }
  // SiteOffer does not match the certified site: the m2 authenticates the
  // responder but the candidate binding fails — still AuthenticationFailed,
  // still no m3.
  current = "m2 offer mismatch";
  {
    Authority authority(fx.sitecert, fx.sak_kid, 0xA3);
    authority.ead.credential_cert = &fx.sitecert;
    SiteOffer offer{};
    offer.site_id = kPeer;  // certifies a different site than the cert
    offer.network_low32 = kNetworkLow;
    offer.site_epoch = kSiteEpoch;
    CHECK(site_offer_encode(offer, authority.ead.offer_value).ok());
    JoinHandshake hs;
    TestEntropy entropy(0xF3);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    CHECK(exchange(hs, authority, t) == 1);
    CHECK(hs.outcome() == JoinAttemptOutcome::AuthenticationFailed);
    CHECK(authority.creds.staged.size == 0);
    CHECK(hs.stats().m2_failures == 1 && hs.stats().m3_composed == 0);
  }
  // Candidate hint mismatch: a perfectly valid site, but not the observed one.
  current = "m2 candidate hint";
  {
    Authority authority(fx.sitecert, fx.sak_kid, 0xA5);
    authority.ead.credential_cert = &fx.sitecert;
    JoinHandshake hs;
    TestEntropy entropy(0xF5);
    auto config = fx.config;
    config.site_hint = join_site_hint(kSiteId) ^ 1;  // colliding observation must not pass
    CHECK(hs.begin(config, fx.identity, entropy).ok());
    Transcript t;
    CHECK(exchange(hs, authority, t) == 1);
    CHECK(hs.outcome() == JoinAttemptOutcome::AuthenticationFailed);
    CHECK(authority.creds.staged.size == 0);
  }
  current.clear();
}

void test_m4_failures() {
  JoinFixture fx;
  // Corrupted m4: transport/crypto failure, classified transient.
  current = "m4 tampered";
  {
    Authority authority(fx.sitecert, fx.sak_kid, 0xB1);
    authority.ead.credential_cert = &fx.sitecert;
    fx.result(JoinVerdict::Allow, authority.ead.result_value);
    JoinHandshake hs;
    TestEntropy entropy(0xF7);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    CHECK(exchange(hs, authority, t, 4) == 3);
    CHECK(hs.outcome() == JoinAttemptOutcome::Failed);
    CHECK(hs.stats().m4_failures == 1);
  }
  // m4 authenticates but carries a malformed JoinResult value.
  current = "m4 malformed result";
  {
    Authority authority(fx.sitecert, fx.sak_kid, 0xB3);
    authority.ead.credential_cert = &fx.sitecert;
    std::memcpy(authority.ead.result_value.bytes.data(), "\x01\x99\x42\x42", 4);
    std::memset(authority.ead.result_value.bytes.data() + 4, 0, 12);
    authority.ead.result_value.size = 16;  // parses as garbage, passes the size bound
    JoinHandshake hs;
    TestEntropy entropy(0xF9);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    CHECK(exchange(hs, authority, t) == 4);
    JoinDecideInput input{};
    JoinDecided decided{};
    CHECK(hs.decide(input, decided).ok());
    CHECK(decided.outcome == JoinAttemptOutcome::MalformedResult);
    CHECK(hs.stats().results_malformed == 1);
  }
  // EAD_4 carries no Result item: libedhoc hands an empty item list to the
  // session (it does not call the handler), so m4 authenticates — and the
  // staged-empty result fails decide()'s decode as MalformedResult.
  current = "m4 no result item";
  {
    Authority authority(fx.sitecert, fx.sak_kid, 0xB5);
    authority.ead.credential_cert = &fx.sitecert;
    // result_value left empty: compose emits no EAD_4 item.
    JoinHandshake hs;
    TestEntropy entropy(0xFB);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    CHECK(exchange(hs, authority, t) == 4);
    JoinDecideInput input{};
    JoinDecided decided{};
    CHECK(hs.decide(input, decided).ok());
    CHECK(decided.outcome == JoinAttemptOutcome::MalformedResult);
    CHECK(decided.record == nullptr);
  }
  current.clear();
}

void test_key_location_and_entropy() {
  JoinFixture fx;
  // None: structurally valid but cannot sign — m1 must never be composed.
  current = "key location none";
  {
    IdentityRecord identity = fx.identity;
    identity.key_location = CredentialKeyLocation::None;
    identity.key_material.fill(0);
    JoinHandshake hs;
    TestEntropy entropy(0x101);
    CHECK(hs.begin(fx.config, identity, entropy).code == StatusCode::InvalidState);
    std::array<std::uint8_t, 64> out{};
    std::size_t len = 0;
    CHECK(hs.compose_m1(MutableByteView{out.data(), out.size()}, len).code ==
          StatusCode::InvalidState);
    CHECK(len == 0);
  }
  // External handle: refused before anything is sent.
  current = "key location handle";
  {
    IdentityRecord identity = fx.identity;
    identity.key_location = CredentialKeyLocation::EfuseDsBound;
    // key_material keeps nonzero handle bytes: they must not be used as a scalar.
    JoinHandshake hs;
    TestEntropy entropy(0x103);
    CHECK(hs.begin(fx.config, identity, entropy).code == StatusCode::Unsupported);
  }
  // Entropy failure: the C_I draw fails the attempt.
  current = "entropy failure";
  {
    JoinHandshake hs;
    TestEntropy entropy(0x105);
    entropy.fail_at = 1;
    CHECK(!hs.begin(fx.config, fx.identity, entropy).ok());
  }
  // Node mismatch is an argument error, never a session.
  current = "node mismatch";
  {
    JoinHandshake hs;
    TestEntropy entropy(0x107);
    auto config = fx.config;
    config.node = kPeer;
    CHECK(hs.begin(config, fx.identity, entropy).code == StatusCode::InvalidArgument);
  }
  // API order: m2/m3/decide before their stages are state errors.
  current = "state guards";
  {
    JoinHandshake hs;
    TestEntropy entropy(0x109);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    std::array<std::uint8_t, 8> out{};
    std::size_t len = 0;
    CHECK(hs.process_m2(ByteView{out.data(), out.size()}).code == StatusCode::InvalidState);
    CHECK(hs.compose_m3(MutableByteView{out.data(), out.size()}, len).code ==
          StatusCode::InvalidState);
    JoinDecideInput input{};
    JoinDecided decided{};
    CHECK(hs.decide(input, decided).code == StatusCode::InvalidState);
  }
  current.clear();
}

void test_m2_classification() {
  JoinFixture fx;
  // One garbage byte: a transport/decode failure, never an authentication
  // failure — the candidate side must retry transiently, not avoid 24 h.
  current = "m2 garbage transient";
  {
    JoinHandshake hs;
    TestEntropy entropy(0xF11);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    std::array<std::uint8_t, kJoinMessageMax> buffer{};
    std::size_t length = 0;
    CHECK(hs.compose_m1(MutableByteView{buffer.data(), buffer.size()}, length).ok());
    const std::uint8_t garbage = 0xFF;
    const Status st = hs.process_m2(ByteView{&garbage, 1});
    CHECK(st.code == StatusCode::ProtocolError);
    CHECK(hs.outcome() == JoinAttemptOutcome::Failed);
    CHECK(hs.stats().m2_failures == 1);
    CHECK(!hs.m2_authenticated());
    CHECK(hs.compose_m3(MutableByteView{buffer.data(), buffer.size()}, length).code ==
          StatusCode::InvalidState);  // no m3 after a failed m2
  }
  // A responder signature that does not verify under the SAK: the message
  // decrypts and the EAD stages fine, but EDHOC authentication fails —
  // still AuthenticationFailed, still no DevCert off the device.
  current = "m2 tampered responder signature";
  {
    Authority authority(fx.sitecert, fx.sak_kid, 0xA7, &other_key().priv);
    authority.ead.credential_cert = &fx.sitecert;
    JoinHandshake hs;
    TestEntropy entropy(0xF13);
    CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
    Transcript t;
    Status m2_status = Status::success();
    CHECK(exchange(hs, authority, t, 0, &m2_status) == 1);
    CHECK(m2_status.code == StatusCode::AuthenticationFailed);
    CHECK(hs.outcome() == JoinAttemptOutcome::AuthenticationFailed);
    CHECK(!hs.m2_authenticated());
    CHECK(authority.creds.staged.size == 0);
  }
  current.clear();
}

void test_wipe_on_end() {
  // After Allow, end() wipes every prepared secret with the clearing
  // primitive: the DAMS and the group key alike.
  current = "wipe on end";
  JoinFixture fx;
  Authority authority(fx.sitecert, fx.sak_kid, 0x71);
  authority.ead.credential_cert = &fx.sitecert;
  fx.result(JoinVerdict::Allow, authority.ead.result_value);
  JoinHandshake hs;
  TestEntropy entropy(0xA19);
  CHECK(hs.begin(fx.config, fx.identity, entropy).ok());
  Transcript t;
  CHECK(exchange(hs, authority, t) == 4);
  JoinDecideInput input{};
  JoinDecided decided{};
  CHECK(hs.decide(input, decided).ok());
  CHECK(decided.outcome == JoinAttemptOutcome::AllowVerified);
  const SiteRecord* record = decided.record;
  CHECK(record != nullptr);
  if (record == nullptr) {
    current.clear();
    return;
  }
  CHECK(!all_zero(ByteView{record->dams.data(), record->dams.size()}));
  CHECK(!all_zero(ByteView{record->gk_current.data(), record->gk_current.size()}));
  hs.end();
  CHECK(all_zero(ByteView{record->dams.data(), record->dams.size()}));
  CHECK(all_zero(ByteView{record->gk_current.data(), record->gk_current.size()}));
  current.clear();
}

void test_ead_items_bounds() {
  // The public token check fails closed on inconsistent (pointer, count)
  // input: the session's 3-token ceiling, null item storage, and null value
  // storage with a nonzero size are all refused outright.
  current = "ead items bounds";
  JoinFixture fx;
  ByteBuffer<kSiteOfferSize> offer_value{};
  SiteOffer offer{};
  offer.site_id = kSiteId;
  offer.network_low32 = kNetworkLow;
  offer.site_epoch = kSiteEpoch;
  CHECK(site_offer_encode(offer, offer_value).ok());
  ByteView value{};
  ByteView credential{};
  {
    edhoc::EadItem items[4] = {
        {-static_cast<std::int32_t>(JoinEad::Offer), offer_value.view()},
        {-static_cast<std::int32_t>(JoinEad::Credential), fx.sitecert.view()},
        {0, ByteView{}},
        {0, ByteView{}},
    };
    // Four items are over the ceiling even though the extras are padding
    // the walker would otherwise skip...
    CHECK(!join_ead_items_check(items, 4, JoinEad::Offer, true, value, credential).ok());
    // ... while value + credential + one padding is accepted.
    CHECK(join_ead_items_check(items, 3, JoinEad::Offer, true, value, credential).ok());
    CHECK(value.size == kSiteOfferSize && credential.size == fx.sitecert.size);
  }
  // Null value storage with a nonzero size is rejected on the value...
  {
    edhoc::EadItem items[2] = {
        {-static_cast<std::int32_t>(JoinEad::Offer), ByteView{nullptr, kSiteOfferSize}},
        {-static_cast<std::int32_t>(JoinEad::Credential), fx.sitecert.view()},
    };
    CHECK(!join_ead_items_check(items, 2, JoinEad::Offer, true, value, credential).ok());
  }
  // ... and on the credential.
  {
    edhoc::EadItem items[2] = {
        {-static_cast<std::int32_t>(JoinEad::Offer), offer_value.view()},
        {-static_cast<std::int32_t>(JoinEad::Credential), ByteView{nullptr, 64}},
    };
    CHECK(!join_ead_items_check(items, 2, JoinEad::Offer, true, value, credential).ok());
  }
  // Null item storage with a nonzero count never reads out of bounds.
  CHECK(!join_ead_items_check(nullptr, 1, JoinEad::Offer, true, value, credential).ok());
  CHECK(!join_ead_items_check(nullptr, 3, JoinEad::Offer, true, value, credential).ok());
  current.clear();
}

void test_membership_verify() {
  current = "membership verify";
  JoinFixture fx;
  const SiteRecord record = site_record();
  bool verified = false;
  CHECK(join_membership_verify(record, fx.identity, verified).ok() && verified);

  // A record of another device does not bind: deny, not malformed.
  SiteRecord foreign = site_record();
  foreign.member_cert = issue(membercert_claims(3, kNetwork, kPeer, other_key().pub), sak());
  CHECK(join_membership_verify(foreign, fx.identity, verified).ok() && !verified);

  // A SiteCert signed by the wrong CA does not verify.
  SiteRecord wrong_ca = site_record();
  wrong_ca.site_cert = issue(sitecert_claims(), device_ca());
  CHECK(join_membership_verify(wrong_ca, fx.identity, verified).ok() && !verified);

  // A MemberCert not signed by the SiteCert's SAK does not verify.
  SiteRecord wrong_member = site_record();
  wrong_member.member_cert = issue(membercert_claims(), device_ca());
  CHECK(join_membership_verify(wrong_member, fx.identity, verified).ok() && !verified);

  // A cleared record is well-formed but is not a membership.
  SiteRecord cleared{};
  CHECK(join_membership_verify(cleared, fx.identity, verified).ok() && !verified);
  current.clear();
}

}  // namespace

int main() {
  test_dams_context_vectors();
  test_allow();
  test_recovery_join_keeps_floor();
  test_verdicts();
  test_allow_denials();
  test_strict_assignment_fails_closed();
  test_m2_failures();
  test_m2_classification();
  test_m4_failures();
  test_key_location_and_entropy();
  test_membership_verify();
  test_wipe_on_end();
  test_ead_items_bounds();
  if (failures != 0) {
    std::fprintf(stderr, "%d join handshake check(s) failed\n", failures);
    return 1;
  }
  std::printf("join handshake tests passed\n");
  return 0;
}
