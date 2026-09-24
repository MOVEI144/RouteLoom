// Test-only two-site join simulator (design P3-4 §10.1). Device D runs the
// REAL Joiner + ZtJoinerLink over a fake channel-switching radio and fake
// slot storage; each site runs a real JoinProxy + JoinRelayGateway and a
// scripted Site Authority (a real edhoc::Session Responder with the join
// EAD plumbing, a durable-approval ledger and policy/mutation hooks).
// Virtual time only; no threads, no sockets. Production MeshNode wiring is
// deliberately absent: the harness moves RLD1 frames and Wire relay frames
// between the engines.

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "routeloom/discovery.hpp"
#include "routeloom/edhoc.hpp"
#include "routeloom/sdkv1_ead.hpp"
#include "routeloom/sdkv1_join_relay.hpp"
#include "routeloom/sdkv1_join_transport.hpp"
#include "routeloom/sdkv1_joiner.hpp"
#include "routeloom/sdkv1_records.hpp"

#include "test_sdkv1.hpp"

namespace join_sim {

using namespace routeloom;
using namespace routeloom::sdkv1;
using namespace sdkv1_test;
using Bytes = std::vector<std::uint8_t>;

inline ByteView view(const Bytes& bytes) { return ByteView{bytes.data(), bytes.size()}; }

// --- Deterministic entropy ------------------------------------------------------
class SimEntropy final : public EntropySource {
 public:
  explicit SimEntropy(const std::uint64_t seed) : state_(seed | 1) {}
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

inline bool sim_random(void* ctx, std::uint8_t* out, const std::size_t size) noexcept {
  return static_cast<SimEntropy*>(ctx)->fill(MutableByteView{out, size}).ok();
}

// --- Storage with an op log -------------------------------------------------------
// FaultyRecordStorage (power cuts, drops, read errors) plus a timestamped
// op log for the V1-J01 durability-ordering check. The pump sets `now_ms`
// before every round; the log stamps each op with it.
struct StorageOp {
  char op{0};  // 'r' read, 'w' write
  std::uint8_t slot{0};
  std::size_t len{0};
  std::uint64_t at{0};
  StatusCode result{StatusCode::Ok};
};

class LoggingStorage final : public RecordSlotStorage {
 public:
  explicit LoggingStorage(const std::size_t slot_bytes) : inner_(slot_bytes) {}
  Status read(const std::uint8_t slot, const MutableByteView target) noexcept override {
    ++read_calls;
    if (read_calls == fail_read_call) {
      log_.push_back(StorageOp{'r', slot, target.size, now_ms, StatusCode::StorageFailure});
      return Status::error(StatusCode::StorageFailure, "injected read failure");
    }
    if (fail_read_once_writes_ge >= 0 &&
        static_cast<long>(writes()) >= fail_read_once_writes_ge) {
      fail_read_once_writes_ge = -1;  // one shot: the commit readback only
      log_.push_back(StorageOp{'r', slot, target.size, now_ms, StatusCode::StorageFailure});
      return Status::error(StatusCode::StorageFailure, "injected readback failure");
    }
    const Status status = inner_.read(slot, target);
    log_.push_back(StorageOp{'r', slot, target.size, now_ms, status.code});
    return status;
  }
  Status write(const std::uint8_t slot, const ByteView data) noexcept override {
    const Status status = inner_.write(slot, data);
    log_.push_back(StorageOp{'w', slot, data.size, now_ms, status.code});
    return status;
  }
  std::size_t writes() const noexcept {
    std::size_t n = 0;
    for (const auto& op : log_)
      if (op.op == 'w') ++n;
    return n;
  }
  std::size_t successful_writes() const noexcept {
    std::size_t n = 0;
    for (const auto& op : log_)
      if (op.op == 'w' && op.result == StatusCode::Ok) ++n;
    return n;
  }

  FaultyRecordStorage inner_;
  std::vector<StorageOp> log_;
  std::uint64_t now_ms{0};
  std::size_t read_calls{0};
  std::size_t fail_read_call{0};  // 1-based call, once
  // Fails the next read once `writes()` reaches the threshold (-1 = off).
  long fail_read_once_writes_ge{-1};
};

// --- Radio / wire plumbing ---------------------------------------------------------
struct RadioFrame {
  MacAddress from{};
  MacAddress to{};
  Bytes bytes;
  std::uint8_t channel{0};
  std::uint64_t deliver_at{0};
};

struct WireFrame {
  NodeId from{kInvalidNodeId};
  NodeId to{kInvalidNodeId};
  FrameType type{FrameType::Data};
  Bytes payload;
  std::uint64_t deliver_at{0};
};

enum class RadioDir : std::uint8_t { Up = 0, Down };  // device->site, site->device

// Programmable faults on the RLD1 hop. Predicates see the raw frame bytes
// (RLD1 decoders stay usable) and may drop or duplicate a frame once.
struct RadioFaults {
  std::function<bool(RadioDir, const Bytes&)> drop_if;
  std::function<bool(RadioDir, const Bytes&)> duplicate_if;
  std::uint64_t up_delay_ms{0};
  std::uint64_t down_delay_ms{0};
  std::uint32_t dropped{0};
  std::uint32_t duplicated{0};
};

class DeviceRadioPort final : public ZtRld1Port {
 public:
  DeviceRadioPort(std::deque<RadioFrame>& air, const MacAddress& self, const std::uint8_t& channel,
                  std::uint64_t& now, RadioFaults& faults)
      : air_(air), self_(self), channel_(channel), now_(now), faults_(faults) {}
  Status send_rld1(const MacAddress& destination, const ByteView frame) noexcept override {
    ++sends;
    if (!(destination == discovery_const::kBroadcastMac)) last_unicast_destination = destination;
    Bytes bytes(frame.data, frame.data + frame.size);
    if (faults_.drop_if && faults_.drop_if(RadioDir::Up, bytes)) {
      ++faults_.dropped;
      return Status::success();
    }
    air_.push_back(RadioFrame{self_, destination, bytes, channel_, now_ + faults_.up_delay_ms});
    if (faults_.duplicate_if && faults_.duplicate_if(RadioDir::Up, bytes)) {
      ++faults_.duplicated;
      air_.push_back(RadioFrame{self_, destination, bytes, channel_, now_ + faults_.up_delay_ms});
    }
    return Status::success();
  }
  std::uint32_t sends{0};
  MacAddress last_unicast_destination{};

 private:
  std::deque<RadioFrame>& air_;
  MacAddress self_;
  const std::uint8_t& channel_;
  std::uint64_t& now_;
  RadioFaults& faults_;
};

class SiteRadioPort final : public ZtRld1Port {
 public:
  SiteRadioPort(std::deque<RadioFrame>& air, const MacAddress& self, std::uint8_t channel,
                std::uint64_t& now, RadioFaults& faults, const bool* muted = nullptr)
      : air_(air), self_(self), channel_(channel), now_(now), faults_(faults), muted_(muted) {}
  Status send_rld1(const MacAddress& destination, const ByteView frame) noexcept override {
    if (muted_ != nullptr && *muted_) return Status::success();  // powered off
    Bytes bytes(frame.data, frame.data + frame.size);
    if (faults_.drop_if && faults_.drop_if(RadioDir::Down, bytes)) {
      ++faults_.dropped;
      return Status::success();
    }
    air_.push_back(RadioFrame{self_, destination, bytes, channel_, now_ + faults_.down_delay_ms});
    if (faults_.duplicate_if && faults_.duplicate_if(RadioDir::Down, bytes)) {
      ++faults_.duplicated;
      air_.push_back(RadioFrame{self_, destination, bytes, channel_, now_ + faults_.down_delay_ms});
    }
    return Status::success();
  }

 private:
  std::deque<RadioFrame>& air_;
  MacAddress self_;
  std::uint8_t channel_;
  std::uint64_t& now_;
  RadioFaults& faults_;
  const bool* muted_{nullptr};
};

class SimWirePort final : public ZtRelayPort {
 public:
  SimWirePort(std::deque<WireFrame>& mesh, const NodeId self, std::uint64_t& now)
      : mesh_(mesh), self_(self), now_(now) {}
  Status send_relay(const NodeId destination, const FrameType type,
                    const ByteView payload) noexcept override {
    mesh_.push_back(WireFrame{self_, destination, type, Bytes(payload.data, payload.data + payload.size),
                              now_});
    return Status::success();
  }

 private:
  std::deque<WireFrame>& mesh_;
  NodeId self_;
  std::uint64_t& now_;
};

// --- Scripted Site Authority ----------------------------------------------------------
// A real edhoc::Session Responder with the join EAD plumbing. Policy knobs
// select the verdict; mutation hooks build cryptographically valid but
// semantically broken Allows (the §10.2 matrix needs those — a garbled
// ciphertext alone proves nothing). Approvals are "durably" ledgered with
// a stamp BEFORE the m4 carrying them is composed, so tests can check the
// V1-J01 order: ledger commit < m4 down < device readback < MemberReady.
struct AuthorityLedger {
  bool approved{false};
  std::uint32_t generation{0};
  Bytes member_cert_bytes;
  Bytes removal_bytes;
  Bytes dams;
  std::uint64_t approved_at{0};
  std::uint64_t m4_down_at{0};
  // Logical order within a tick: approval precedes the m4 carrying it.
  std::uint64_t seq{0};
  std::uint64_t approved_seq{0};
  std::uint64_t m4_seq{0};
  std::vector<std::uint64_t> discovered;  // nodes with a verified m3
  std::uint32_t next_generation{1};
};

struct AuthorityPolicy {
  JoinVerdict verdict{JoinVerdict::Allow};
  std::uint32_t retry_after_s{0};
  std::uint16_t decision_timeout_ms{2000};
  // Mutations for the negative matrix (applied in order before encode).
  std::function<void(JoinResult&)> mutate_result;
  std::function<void(Bytes&)> mutate_result_bytes;
  const ByteBuffer<kRlcw1CertMax>* credential_cert{nullptr};  // default: own site cert
  const std::array<std::uint8_t, 32>* sign_priv{nullptr};     // default: own SAK
  RemovalNotice removal{};
  bool removal_configured{false};
  bool silent{false};  // accept m1/m3 but never answer (timeout tests)
};

class SimAuthorityCreds final : public edhoc::CredentialProvider {
 public:
  SimAuthorityCreds(const ByteBuffer<kRlcw1CertMax>& own_cert, const Digest256& own_kid,
                    const std::array<std::uint8_t, 32>& priv, const P256PublicKey& device_ca_pub)
      : own_cert_(own_cert), own_kid_(own_kid), priv_(priv), device_ca_pub_(device_ca_pub) {}
  Status local(edhoc::Role, edhoc::LocalCredential& out) noexcept override {
    out.kid = ByteView{own_kid_.data(), own_kid_.size()};
    out.credential = own_cert_.view();
    out.private_key = sign_priv_override != nullptr ? *sign_priv_override : priv_;
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
    status = cert_verify(staged.view(), device_ca_pub_, claims, verified);
    if (!status || !verified) {
      ++rejected;
      return Status::error(StatusCode::AuthenticationFailed, "devcert chain");
    }
    device_kid = Digest256{};
    if (kid.size == device_kid.size()) {
      std::memcpy(device_kid.data(), kid.data, kid.size);
    }
    dev_node = claims.subject;
    out.credential = staged.view();
    out.public_key = claims.pubkey;
    return Status::success();
  }
  ByteBuffer<kRlcw1CertMax> staged{};
  Digest256 device_kid{};
  std::uint64_t dev_node{0};
  int rejected{0};
  const std::array<std::uint8_t, 32>* sign_priv_override{nullptr};

 private:
  const ByteBuffer<kRlcw1CertMax>& own_cert_;
  const Digest256& own_kid_;
  std::array<std::uint8_t, 32> priv_;
  P256PublicKey device_ca_pub_;
};

class SimAuthorityEad final : public edhoc::EadHandler {
 public:
  explicit SimAuthorityEad(SimAuthorityCreds& creds) : creds_(creds) {}
  Status compose(const int message, edhoc::EadItem* items, const std::size_t capacity,
                 std::size_t& count) noexcept override {
    count = 0;
    if (message == 2) {
      if (capacity < 2) return Status::error(StatusCode::NoCapacity, "ead capacity");
      items[count++] = edhoc::EadItem{-static_cast<std::int32_t>(JoinEad::Offer), offer_value.view()};
      if (credential_cert != nullptr) {
        items[count++] =
            edhoc::EadItem{-static_cast<std::int32_t>(JoinEad::Credential), credential_cert->view()};
      }
    } else if (message == 4) {
      if (result_value.size != 0) {
        items[count++] =
            edhoc::EadItem{-static_cast<std::int32_t>(JoinEad::Result), result_value.view()};
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
  SimAuthorityCreds& creds_;
};

// One exchange's up input / down answer across the gateway host sink.
struct AuthorityDown {
  bool has{false};
  std::uint8_t step{0};
  bool final{false};
  Bytes body;
};

class SimAuthority {
 public:
  SimAuthority(const ByteBuffer<kRlcw1CertMax>& site_cert, const Digest256& sak_kid,
               const std::array<std::uint8_t, 32>& sak_priv, const P256PublicKey& device_ca_pub,
               std::uint64_t site_id, NetworkId network, const SitePackage& package,
               std::uint64_t rng_seed)
      : entropy_(rng_seed),
        creds_(site_cert, sak_kid, sak_priv, device_ca_pub),
        ead_(creds_),
        site_id_(site_id),
        network_(network),
        package_(package),
        own_cert_(&site_cert),
        sak_kid_(&sak_kid) {
    SiteOffer offer{};
    offer.site_id = site_id;
    offer.network_low32 = static_cast<std::uint32_t>(network);
    offer.site_epoch = static_cast<std::uint32_t>(network >> 32U);
    offer.decision_timeout_ms = policy.decision_timeout_ms;
    if (!site_offer_encode(offer, ead_.offer_value)) std::abort();
    ead_.credential_cert = own_cert_;
  }

  AuthorityPolicy policy;
  AuthorityLedger ledger;

  // Transcript of the latest exchange (for replay injection).
  Bytes last_m1, last_m2, last_m3, last_m4;
  std::uint32_t exchanges{0};
  std::uint32_t m1_seen{0};
  std::uint32_t m1_dropped{0};
  std::uint32_t devcert_rejects() const { return static_cast<std::uint32_t>(creds_.rejected); }

  AuthorityDown on_up(std::uint8_t step, ByteView message, std::uint64_t now) {
    AuthorityDown down;
    std::array<std::uint8_t, kJoinMessageMax> buffer{};
    std::size_t length = 0;
    if (step == 1) {
      session_.end();
      ++m1_seen;
      last_m1.assign(message.data, message.data + message.size);
      edhoc::SessionConfig config{};
      config.role = edhoc::Role::Responder;
      config.method = edhoc::Method::SignatureSignature;
      config.connection_id = ByteView{c_r_.data(), c_r_.size()};
      config.credentials = &creds_;
      config.ead = &ead_;
      config.random = &sim_random;
      config.random_ctx = &entropy_;
      creds_.sign_priv_override = policy.sign_priv;
      ead_.credential_cert =
          policy.credential_cert != nullptr ? policy.credential_cert : own_cert_;
      SiteOffer offer{};
      if (!site_offer_decode(ead_.offer_value.view(), offer)) return down;
      offer.decision_timeout_ms = policy.decision_timeout_ms;
      ead_.offer_value.clear();
      if (!site_offer_encode(offer, ead_.offer_value)) return down;
      if (!session_.begin(config)) return down;
      if (!session_.process_message_1(message)) {
        ++m1_dropped;
        session_.end();
        return down;
      }
      if (policy.silent) return down;
      if (!session_.compose_message_2(MutableByteView{buffer.data(), buffer.size()}, length)) {
        session_.end();
        return down;
      }
      last_m2.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length));
      down.has = true;
      down.step = 2;
      down.final = false;
      down.body = last_m2;
      return down;
    }
    if (step == 3) {
      last_m3.assign(message.data, message.data + message.size);
      if (!session_.process_message_3(message)) {
        // The device never authenticates. Prefer a real EDHOC error, but
        // libedhoc usually cannot emit one after a failed m3 — staying
        // silent (the device times out) is the expected path then.
        if (!policy.silent &&
            session_.compose_error(1, nullptr, 0,
                                   MutableByteView{buffer.data(), buffer.size()}, length)) {
          down.has = true;
          down.step = 5;
          down.final = true;
          down.body.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length));
        }
        session_.end();
        return down;
      }
      ledger.discovered.push_back(creds_.dev_node);
      if (policy.silent) return down;
      JoinResult result{};
      result.verdict = policy.verdict;
      result.retry_after_s = policy.retry_after_s;
      if (policy.verdict == JoinVerdict::Allow) {
        // Durable approval BEFORE the m4 carrying it exists. Re-issuing
        // for a known (node, kid) reuses the MemberCert — only the DAMS
        // follows the fresh session — like the production ledger.
        const std::uint64_t known = creds_.dev_node;
        auto existing = approvals_.find(known);
        if (existing == approvals_.end()) {
          CertClaims member = membercert_claims(ledger.next_generation, network_,
                                                creds_.dev_node, staged_pubkey());
          member.issuer = site_id_;
          const ByteBuffer<kRlcw1CertMax> issued = issue(member, sak_signer());
          Approval approval{};
          approval.generation = ledger.next_generation++;
          approval.cert.assign(issued.bytes.begin(), issued.bytes.begin() + issued.size);
          existing = approvals_.emplace(known, approval).first;
        }
        ledger.approved = true;
        ledger.generation = existing->second.generation;
        ledger.member_cert_bytes = existing->second.cert;
        result.member_cert = view(ledger.member_cert_bytes);
        result.site_package = package_;
        result.site_package.site_id = site_id_;
        result.site_package.network = network_;
        ledger.approved_at = now;
        ledger.approved_seq = ++ledger.seq;
      } else if (policy.verdict == JoinVerdict::Removed && policy.removal_configured) {
        ledger.removal_bytes = removal_object(policy.removal);
        result.removal_notice = view(ledger.removal_bytes);
      } else if (policy.verdict == JoinVerdict::PendingAssignment) {
        static const std::array<std::uint8_t, 8> ticket{0x54, 0x49, 0x43, 0x4B,
                                                        0x45, 0x54, 0x30, 0x31};
        result.pending_ticket = ByteView{ticket.data(), ticket.size()};
      }
      if (policy.mutate_result) policy.mutate_result(result);
      ead_.result_value.clear();
      if (!join_result_encode(result, ead_.result_value)) {
        session_.end();
        return down;
      }
      if (policy.mutate_result_bytes) {
        Bytes encoded(ead_.result_value.bytes.begin(),
                      ead_.result_value.bytes.begin() + ead_.result_value.size);
        policy.mutate_result_bytes(encoded);
        ead_.result_value.clear();
        if (encoded.size() > ead_.result_value.bytes.size()) {
          session_.end();
          return down;
        }
        std::memcpy(ead_.result_value.bytes.data(), encoded.data(), encoded.size());
        ead_.result_value.size = encoded.size();
      }
      if (!session_.compose_message_4(MutableByteView{buffer.data(), buffer.size()}, length)) {
        session_.end();
        return down;
      }
      if (policy.verdict == JoinVerdict::Allow) {
        // The DAMS lands in the ledger after m4 exists but before the down
        // carrying m4 is emitted (approved_at < m4_down_at still holds).
        // libedhoc only exports once message 4 is composed — exporting
        // earlier breaks its responder state and m4 never composes.
        ByteBuffer<kJoinDamsContextMax> context{};
        std::array<std::uint8_t, kJoinDamsSize> dams{};
        if (!dams_exporter_context(network_, creds_.dev_node, site_id_, creds_.device_kid,
                                   *sak_kid_, context) ||
            !session_.exporter(32771, context.view(), MutableByteView{dams.data(), dams.size()})) {
          session_.end();
          return down;
        }
        ledger.dams.assign(dams.begin(), dams.end());
      }
      last_m4.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length));
      if (policy.verdict == JoinVerdict::Allow) {
        ledger.m4_down_at = now;
        ledger.m4_seq = ++ledger.seq;
      }
      ++exchanges;
      session_.end();
      down.has = true;
      down.step = 4;
      down.final = true;
      down.body = last_m4;
      return down;
    }
    return down;  // step 5 up: the device never sends one; ignore
  }

  void set_sak_signer(const routeloom_test::TestKeyPair* signer) { sak_override_ = signer; }

 private:
  P256PublicKey staged_pubkey() const {
    CertClaims claims{};
    P256PublicKey empty{};
    if (!cert_decode(creds_.staged.view(), claims)) return empty;
    return claims.pubkey;
  }
  const routeloom_test::TestKeyPair& sak_signer() const {
    static const auto fallback = routeloom_test::test_keypair(0x53);
    return sak_override_ != nullptr ? *sak_override_ : fallback;
  }
  Bytes removal_object(const RemovalNotice& notice) {
    ByteBuffer<kRemovalNoticePayloadSize> payload{};
    ByteBuffer<kRemovalNoticeAadSize> aad{};
    ByteBuffer<kRemovalNoticeObjectSize> object{};
    if (!removal_notice_payload_encode(notice, payload)) std::abort();
    if (!removal_notice_aad(network_, aad)) std::abort();
    Es256Signature signature{};
    sign_payload(sak_signer(), payload.view(), aad.view(), signature);
    if (!removal_notice_assemble(payload.view(), ByteView{signature.data(), signature.size()},
                                 object)) {
      std::abort();
    }
    return Bytes(object.bytes.begin(), object.bytes.begin() + object.size);
  }

  struct Approval {
    std::uint32_t generation{0};
    Bytes cert;
  };
  SimEntropy entropy_;
  SimAuthorityCreds creds_;
  SimAuthorityEad ead_;
  std::map<std::uint64_t, Approval> approvals_;
  edhoc::Session session_;
  std::array<std::uint8_t, 4> c_r_{{0xA1, 0xA2, 0xA3, 0xA4}};
  std::uint64_t site_id_;
  NetworkId network_;
  SitePackage package_;
  const ByteBuffer<kRlcw1CertMax>* own_cert_{nullptr};
  const Digest256* sak_kid_{nullptr};
  const routeloom_test::TestKeyPair* sak_override_{nullptr};
};

// --- One site: gateway + 1-2 proxies + authority -----------------------------------
struct SimProxyParams {
  MacAddress mac{};
  NodeId node{kInvalidNodeId};
  std::uint8_t channel{1};
  std::int16_t rssi{-50};
  std::uint8_t hops{1};
  bool reachable{true};
};

struct SimSiteParams {
  std::uint64_t site_id{0};
  NetworkId network{0};
  const routeloom_test::TestKeyPair* sak{nullptr};
  const routeloom_test::TestKeyPair* site_ca{nullptr};
  std::uint64_t site_ca_id{0};
  std::uint32_t serial{7};
  NodeId gateway{kInvalidNodeId};
  SitePackage package{};
  std::vector<SimProxyParams> proxies;
  AuthorityPolicy policy;
};

struct SimUp {
  NodeId proxy{kInvalidNodeId};
  std::uint8_t hops{0};
  Bytes object;
};

class SimHostSink final : public JoinRelayHostSink {
 public:
  explicit SimHostSink(std::deque<SimUp>& inbox) : inbox_(inbox) {}
  Status relay_up(const NodeId proxy, const std::uint8_t hops,
                  const ByteView object) noexcept override {
    inbox_.push_back(SimUp{proxy, hops, Bytes(object.data, object.data + object.size)});
    return Status::success();
  }
  Status relay_abort(const NodeId, const RelayToken, const RelayAbortReason) noexcept override {
    ++aborts;
    return Status::success();
  }
  std::uint32_t aborts{0};

 private:
  std::deque<SimUp>& inbox_;
};

class SimSite {
 public:
  SimSite(const SimSiteParams& params, std::deque<RadioFrame>& air, std::deque<WireFrame>& mesh,
          std::uint64_t& now, RadioFaults& faults, std::uint64_t rng_seed)
      : authority_(site_cert_, sak_kid_, params.sak->priv, sdkv1_test::device_ca().pub,
                   params.site_id, params.network, params.package, rng_seed),
        params_(params),
        gateway_wire_(mesh, params.gateway, now),
        gateway_(gateway_config(params), gateway_wire_),
        sink_(inbox_),
        cookie_(cookie_key_),
        proxy_entropy_(rng_seed ^ 0x9E3779B9ULL) {
    CertClaims claims{};
    claims.type = CertType::Site;
    claims.issuer = params.site_ca_id;
    claims.subject = params.site_id;
    claims.pubkey = params.sak->pub;
    claims.network_low32 = static_cast<std::uint32_t>(params.network);
    claims.site_epoch = static_cast<std::uint32_t>(params.network >> 32U);
    claims.usage = 1;
    claims.serial = params.serial;
    site_cert_ = issue(claims, *params.site_ca);
    if (!cert_subject_kid(claims, sak_kid_)) std::abort();
    authority_.policy = params.policy;
    authority_.set_sak_signer(params.sak);
    gateway_.set_host_sink(&sink_);
    gateway_.set_membership(MembershipState::Member);
    for (const auto& proxy : params.proxies) {
      proxies_.emplace_back(
          new ProxyEnds(proxy, params, air, mesh, now, faults, cookie_, proxy_entropy_));
    }
  }

  void set_policy(const AuthorityPolicy& policy) { authority_.policy = policy; }
  void set_proxy_muted(std::size_t index, bool muted) {
    if (index < proxies_.size()) proxies_[index]->muted = muted;
  }
  void on_radio(const RadioFrame& frame, std::uint64_t now) {
    for (auto& proxy : proxies_) {
      if (proxy->muted) continue;
      if (frame.channel != proxy->params.channel) continue;
      proxy->engine.on_rld1_rx(frame.from, frame.to, proxy->params.rssi, view(frame.bytes), now);
    }
  }
  void on_wire(const WireFrame& frame, std::uint64_t now) {
    if (frame.to == params_.gateway) {
      gateway_.on_relay_rx(frame.from, /*hops=*/1, frame.type, view(frame.payload), now);
      return;
    }
    for (auto& proxy : proxies_) {
      if (frame.to == proxy->params.node) {
        proxy->engine.on_relay_rx(frame.from, frame.type, view(frame.payload), now);
      }
    }
  }
  // Runs queued ups through the authority; hands downs back to the gateway
  // (phase 4 only — the test adapter rule of design §10.2).
  void drive_authority(std::uint64_t now) {
    while (!inbox_.empty()) {
      SimUp up = inbox_.front();
      inbox_.pop_front();
      RelayObject object{};
      if (!relay_object_decode(view(up.object), object)) {
        ++up_decode_failures;
        continue;
      }
      if (object.header.phase != JoinAuthPhase::EdhocMessage) {
        ++up_phase_rejects;
        continue;
      }
      const AuthorityDown down = authority_.on_up(object.header.step, object.message, now);
      if (!down.has) continue;
      RelayObject out{};
      out.header.dir = RelayDirection::Down;
      out.header.relay_id = object.header.relay_id;
      out.header.gateway_epoch = object.header.gateway_epoch;
      out.header.proxy_epoch = object.header.proxy_epoch;
      out.header.proxy = up.proxy;
      out.header.joiner_mac = object.header.joiner_mac;
      out.header.phase = JoinAuthPhase::EdhocMessage;
      out.header.step = down.step;
      out.header.state = down.final ? RelayState::Final : RelayState::Continue;
      out.message = view(down.body);
      std::array<std::uint8_t, kRelayObjectMax> encoded{};
      std::size_t written = 0;
      if (!relay_object_encode(out, MutableByteView{encoded.data(), encoded.size()}, written)) {
        continue;
      }
      (void)gateway_.host_down(up.proxy, ByteView{encoded.data(), written}, now);
    }
  }
  void poll(std::uint64_t now) {
    for (auto& proxy : proxies_) proxy->engine.poll(now);
    gateway_.poll(now);
  }

  // The authority borrows these; they must precede it in declaration order.
  ByteBuffer<kRlcw1CertMax> site_cert_{};
  Digest256 sak_kid_{};
  SimAuthority authority_;
  std::uint32_t up_decode_failures{0};
  std::uint32_t up_phase_rejects{0};

 private:
  struct ProxyEnds {
    ProxyEnds(const SimProxyParams& proxy, const SimSiteParams& site, std::deque<RadioFrame>& air,
              std::deque<WireFrame>& mesh, std::uint64_t& now, RadioFaults& faults,
              JoinCookieSealer& cookie, EntropySource& entropy)
        : params(proxy),
          radio(air, proxy.mac, proxy.channel, now, faults, &muted),
          wire(mesh, proxy.node, now),
          engine(proxy_config(proxy, site), radio, wire, cookie, entropy) {
      engine.set_policy(true);
      engine.set_authority(proxy.reachable, proxy.hops, 0);
      engine.set_membership(MembershipState::Member, 0);
    }
    SimProxyParams params;
    bool muted{false};
    SiteRadioPort radio;
    SimWirePort wire;
    JoinProxy engine;
  };

  static JoinRelayGatewayConfig gateway_config(const SimSiteParams& params) {
    JoinRelayGatewayConfig config{};
    config.node = params.gateway;
    config.gateway_epoch = 7;
    return config;
  }
  static JoinProxyConfig proxy_config(const SimProxyParams& proxy, const SimSiteParams& site) {
    JoinProxyConfig config{};
    config.node = proxy.node;
    config.mac = proxy.mac;
    config.network_low32 = static_cast<std::uint32_t>(site.network);
    config.org_hint = join_org_hint(site.site_ca->pub);
    config.site_hint = join_site_hint(site.site_id);
    config.gateway = site.gateway;
    config.proxy_epoch = 3;
    return config;
  }

  SimSiteParams params_;
  SimWirePort gateway_wire_;
  JoinRelayGateway gateway_;
  std::deque<SimUp> inbox_;
  SimHostSink sink_;
  std::array<std::uint8_t, 32> cookie_key_{{0xC0, 0x01, 0x5E, 0xED}};
  HmacJoinCookie cookie_;
  SimEntropy proxy_entropy_;
  std::vector<std::unique_ptr<ProxyEnds>> proxies_;
};

// --- Device ends -------------------------------------------------------------------------------
// The unit under test with its scripted Owner (channel switch, action log).
struct JoinObserverLog final : public JoinObserver {
  void on_event(const JoinEvent& event) noexcept override { events.push_back(event); }
  std::vector<JoinEvent> events;
};

class DeviceEnds {
 public:
  DeviceEnds(const JoinerConfig& config, const IdentityRecord& identity, std::uint64_t rng_seed,
             RadioFaults& faults, bool provision = true)
      : entropy(rng_seed),
        radio(air, config.mac, channel, now_ms, faults),
        identity_store(identity_storage),
        site_store(site_storage),
        joiner(config, identity_store, site_store, entropy, radio, observer) {
    if (!identity_store.initialize()) std::abort();
    if (provision && !identity_store.commit(identity)) std::abort();
    if (!site_store.initialize()) std::abort();
  }

  std::uint64_t now_ms{0};
  std::uint8_t channel{0};  // Owner-tuned channel, 0 = untuned
  std::deque<RadioFrame> air{};  // device -> sites; drained by the network pump
  SimEntropy entropy;
  DeviceRadioPort radio;
  LoggingStorage identity_storage{kIdentitySlotBytes};
  LoggingStorage site_storage{kSiteSlotBytes};
  IdentityStore identity_store;
  SiteStore site_store;
  JoinObserverLog observer;
  Joiner joiner;
};

// --- The network -------------------------------------------------------------------------------
// Owns the device and up to two sites, moves frames, drives time. Tuning is
// synchronous: ChangeChannel actions apply immediately and complete in the
// same round (sync radio, separate call after take_action, per the Joiner
// contract).
class JoinSimNetwork {
 public:
  JoinSimNetwork(const JoinerConfig& config, const IdentityRecord& identity,
                 std::uint64_t rng_seed = 0x5EED1234ULL)
      : device_(new DeviceEnds(config, identity, rng_seed, faults_)),
        seed_(rng_seed),
        device_mac_(config.mac) {}

  DeviceEnds& device() { return *device_; }
  RadioFaults& faults() { return faults_; }
  SimSite& site(std::size_t index) { return *sites_.at(index); }
  std::size_t site_count() const { return sites_.size(); }
  std::uint64_t now() const { return now_; }

  void add_site(const SimSiteParams& params) {
    sites_.emplace_back(new SimSite(params, air_, mesh_, now_, faults_,
                                    seed_ ^ (0x1000U * (sites_.size() + 1))));
    for (const auto& proxy : params.proxies) {
      network_overrides_.push_back(
          {proxy.mac, static_cast<std::uint32_t>(params.network & 0xFFFFFFFFULL)});
      rssi_map_.push_back({proxy.mac, proxy.rssi});
    }
  }

  // One pump round at the current time: deliver due frames, run the
  // authorities, poll every engine, consume ChangeChannel actions.
  // Returns false when a terminal device action is pending (the test owns
  // it) or a Status error escaped (recorded in `error_`).
  bool round() {
    DeviceEnds& dev = *device_;
    dev.now_ms = now_;
    dev.identity_storage.now_ms = now_;
    dev.site_storage.now_ms = now_;
    deliver_radio();
    if (error_ != StatusCode::Ok) return false;
    deliver_wire();
    for (auto& site : sites_) site->drive_authority(now_);
    for (auto& site : sites_) site->poll(now_);
    if (!dev.joiner.poll(now_).ok()) {
      error_ = dev.joiner.snapshot().last_error;
      last_error_detail_ = "device poll failed";
      return false;
    }
    return consume_actions();
  }

  // Pumps until `done()` or `timeout_ms` elapses (5 ms ticks). Terminal
  // actions stop the pump with the action left pending for the test.
  bool pump_until(const std::function<bool()>& done, std::uint64_t timeout_ms) {
    const std::uint64_t end = now_ + timeout_ms;
    while (now_ <= end) {
      if (!round()) return done();
      if (done()) return true;
      now_ += 5;
    }
    return done();
  }

  // Jumps virtual time forward (avoid-expiry tests): everything due is
  // delivered and every engine settles, without stepping each tick.
  void skip_to(std::uint64_t target) {
    while (now_ < target) {
      now_ = target;
      for (int i = 0; i < 4; ++i) {
        if (!round()) return;
      }
      // round() left no work undelivered: air/mesh drained by deliver_*.
      if (!air_.empty() || !mesh_.empty()) continue;
      break;
    }
  }

  // Rebuilds the device ends on the same flash image (power-cut tests):
  // fresh Joiner/Link/Session/stores, same slot bytes, entropy continuing.
  void restart_device(const JoinerConfig& config, std::uint64_t entropy_seed) {
    LoggingStorage identity_image{kIdentitySlotBytes};
    LoggingStorage site_image{kSiteSlotBytes};
    identity_image.inner_.slot(0) = device_->identity_storage.inner_.slot(0);
    identity_image.inner_.slot(1) = device_->identity_storage.inner_.slot(1);
    site_image.inner_.slot(0) = device_->site_storage.inner_.slot(0);
    site_image.inner_.slot(1) = device_->site_storage.inner_.slot(1);
    const std::uint8_t channel = device_->channel;
    device_.reset(new DeviceEnds(config, placeholder_identity(), entropy_seed, faults_, false));
    device_->identity_storage.inner_.slot(0) = identity_image.inner_.slot(0);
    device_->identity_storage.inner_.slot(1) = identity_image.inner_.slot(1);
    device_->site_storage.inner_.slot(0) = site_image.inner_.slot(0);
    device_->site_storage.inner_.slot(1) = site_image.inner_.slot(1);
    device_->identity_storage.log_.clear();
    device_->site_storage.log_.clear();
    device_->channel = channel;
    device_->now_ms = now_;
  }

  // A soft Owner clock-domain restart keeps the Joiner instance but gives
  // the radio side fresh peer instances and an empty event queue.
  void reset_clock_and_sites() {
    sites_.clear();
    air_.clear();
    mesh_.clear();
    device_->air.clear();
    air_history_.clear();
    network_overrides_.clear();
    rssi_map_.clear();
    now_ = 0;
    device_->now_ms = 0;
    device_->channel = 0;
  }

  StatusCode error() const { return error_; }
  const std::string& last_error_detail() const { return last_error_detail_; }
  std::uint32_t tunes() const { return tunes_; }
  const std::vector<Bytes>& air_history() const { return air_history_; }

  // Wraps raw down-message bytes in a live RLD1 frame from `proxy` on the
  // device's current channel and feeds it to the Joiner (replay tests).
  // Uses the proxy's real header values; the caller picks the bytes.
  bool inject_down(const SimProxyParams& proxy, const Bytes& message, std::uint8_t step) {
    JoinAuthObject object{};
    object.phase = JoinAuthPhase::EdhocMessage;
    object.step = step;
    object.message = view(message);
    std::array<std::uint8_t, kJoinObjectMax> encoded{};
    std::size_t written = 0;
    if (!join_object_encode(object, MutableByteView{encoded.data(), encoded.size()}, written)) {
      return false;
    }
    // Single-frame carriage only here; larger replay units ride
    // inject_down_chunked below.
    if (written > autonomy::kRld1MaxBody) return false;
    return inject_down_raw(proxy, Bytes(encoded.begin(), encoded.begin() + written),
                           FrameType::BootstrapAuth);
  }

  // Chunked carriage of a down message: splits the object the way the
  // proxy would and queues every chunk on the live channel/nonce.
  bool inject_down_chunked(const SimProxyParams& proxy, const Bytes& message, std::uint8_t step) {
    JoinAuthObject object{};
    object.phase = JoinAuthPhase::EdhocMessage;
    object.step = step;
    object.message = view(message);
    JoinObjectBytes encoded{};
    std::size_t written = 0;
    if (!join_object_encode(object, MutableByteView{encoded.bytes.data(), encoded.bytes.size()},
                            written)) {
      return false;
    }
    JoinObjectSlot slot;
    if (!slot.load(JoinCarrier::Rld1, JoinAuthPhase::EdhocMessage, step,
                   join_rld1_object_id(last_device_nonce()),
                   0, 0,
                   ByteView{encoded.bytes.data(), written}, now_)) {
      return false;
    }
    for (std::size_t i = 0; i < slot.chunk_total(); ++i) {
      JoinChunk chunk{};
      if (!slot.chunk_at(i, chunk)) return false;
      std::array<std::uint8_t, autonomy::kRld1MaxBody> body{};
      std::size_t body_len = 0;
      if (!join_chunk_encode(JoinCarrier::Rld1, chunk, MutableByteView{body.data(), body.size()},
                             body_len)) {
        return false;
      }
      if (!inject_down_raw(proxy, Bytes(body.begin(), body.begin() + body_len),
                           FrameType::BootstrapChunk)) {
        return false;
      }
    }
    return true;
  }

  // Feeds an arbitrary RLD1 body with the proxy's header values; the
  // overrides build foreign frames (wrong source/nonce/network).
  bool inject_down_raw(const SimProxyParams& proxy, const Bytes& body, FrameType kind,
                       const MacAddress* source_override = nullptr,
                       const JoinNonce* nonce_override = nullptr,
                       std::uint32_t network_override = 0, bool use_network_override = false) {
    DeviceEnds& dev = *device_;
    autonomy::Rld1Envelope env{};
    env.kind = kind;
    env.network_hint = use_network_override ? network_override : network_of(proxy);
    env.claimed_node = proxy.node;
    env.capability_bits = 0;
    env.transaction_nonce = nonce_override != nullptr ? *nonce_override : last_device_nonce();
    env.body_size = body.size();
    if (body.size() > env.body.size()) return false;
    std::memcpy(env.body.data(), body.data(), body.size());
    autonomy::Rld1Encoded frame{};
    if (!autonomy::rld1_encode(env, frame)) return false;
    JoinRxMeta meta{};
    meta.source = source_override != nullptr ? *source_override : proxy.mac;
    meta.destination = device_mac_;
    meta.channel = dev.channel;
    meta.rssi = proxy.rssi;
    return dev.joiner
        .on_rld1_rx(meta, ByteView{frame.bytes.data(), frame.size}, now_)
        .ok();
  }

  void set_device_mac(const MacAddress& mac) { device_mac_ = mac; }
  void set_network_of(const SimProxyParams& proxy, std::uint32_t network_low32) {
    for (auto& entry : network_overrides_) {
      if (entry.first == proxy.mac) {
        entry.second = network_low32;
        return;
      }
    }
    network_overrides_.push_back({proxy.mac, network_low32});
  }

 private:
  static IdentityRecord placeholder_identity() {
    IdentityRecord record{};
    record.node_id = 0x00A1000000001234ULL;
    return record;
  }

  std::uint32_t network_of(const SimProxyParams& proxy) const {
    for (const auto& override : network_overrides_) {
      if (override.first == proxy.mac) return override.second;
    }
    return 0x0A1B2C3DU;
  }

  JoinNonce last_device_nonce() {
    // The live transaction nonce is the Link's; recover it from the last
    // DISCOVER the device broadcast (test-only introspection).
    for (auto it = air_history_.rbegin(); it != air_history_.rend(); ++it) {
      autonomy::Rld1Envelope env{};
      if (!autonomy::rld1_decode(view(*it), env)) continue;
      if (env.kind == FrameType::Discover) {
        JoinNonce nonce{};
        std::copy(env.transaction_nonce.begin(), env.transaction_nonce.end(), nonce.begin());
        return nonce;
      }
    }
    return JoinNonce{};
  }

  void deliver_radio() {
    DeviceEnds& dev = *device_;
    // Device -> sites.
    while (!dev.air.empty()) {
      RadioFrame frame = dev.air.front();
      dev.air.pop_front();
      air_history_.push_back(frame.bytes);
      if (frame.deliver_at > now_) {
        dev.air.push_front(frame);
        break;
      }
      for (auto& site : sites_) site->on_radio(frame, now_);
    }
    // Sites -> device (the device hears its tuned channel only).
    while (!air_.empty()) {
      RadioFrame frame = air_.front();
      if (frame.deliver_at > now_) break;
      air_.pop_front();
      if (frame.channel != dev.channel) continue;
      JoinRxMeta meta{};
      meta.source = frame.from;
      meta.destination = frame.to;
      meta.channel = frame.channel;
      meta.rssi = rssi_of(frame.from);
      // The pump never injects faults here; a hard error is a test bug.
      const Status status = dev.joiner.on_rld1_rx(meta, view(frame.bytes), now_);
      if (!status.ok() && status.code != StatusCode::Busy) {
        error_ = status.code;
        last_error_detail_ = "device on_rld1_rx failed";
        return;
      }
    }
  }

  void deliver_wire() {
    while (!mesh_.empty()) {
      WireFrame frame = mesh_.front();
      if (frame.deliver_at > now_) break;
      mesh_.pop_front();
      for (auto& site : sites_) site->on_wire(frame, now_);
    }
  }

  bool consume_actions() {
    DeviceEnds& dev = *device_;
    for (;;) {
      if (hold_terminal_) {
        // The test owns terminal actions: leave them pending, take tunes.
        const JoinSnapshot snap = dev.joiner.snapshot();
        if (!snap.action_pending) return true;
        if (snap.pending_action != JoinActionKind::ChangeChannel) return false;
      }
      JoinAction action{};
      const Status taken = dev.joiner.take_action(action);
      if (taken.code == StatusCode::NotFound) return true;
      if (!taken.ok()) {
        error_ = taken.code;
        last_error_detail_ = "take_action failed";
        return false;
      }
      if (action.kind == JoinActionKind::ChangeChannel) {
        ++tunes_;
        dev.channel = action.channel;
        Status result = Status::success();
        if (fail_tunes_ > 0) {
          --fail_tunes_;
          result = Status::error(StatusCode::RadioFailure, "injected tune failure");
        }
        const Status reported =
            dev.joiner.on_channel_ready(action.channel_token, result, now_);
        if (!reported.ok()) {
          error_ = reported.code;
          last_error_detail_ = "on_channel_ready failed";
          return false;
        }
        continue;
      }
      // Terminal action: taken into `terminal_` for the test to own.
      terminal_ = action;
      has_terminal_ = true;
      return false;
    }
  }

  std::int16_t rssi_of(const MacAddress& from) const {
    for (const auto& entry : rssi_map_) {
      if (entry.first == from) return entry.second;
    }
    return -50;
  }

  RadioFaults faults_;  // network-owned: stable across device restarts
  std::unique_ptr<DeviceEnds> device_;
  std::vector<std::unique_ptr<SimSite>> sites_;
  std::deque<RadioFrame> air_;   // sites -> device
  std::deque<WireFrame> mesh_;   // proxy <-> gateway (all sites share the test mesh)
  std::vector<Bytes> air_history_;
  std::uint64_t now_{0};
  std::uint64_t seed_{0};
  MacAddress device_mac_{};
  std::vector<std::pair<MacAddress, std::uint32_t>> network_overrides_;
  std::vector<std::pair<MacAddress, std::int16_t>> rssi_map_;
  JoinAction terminal_{};
  bool has_terminal_{false};
  bool hold_terminal_{false};
  std::uint32_t tunes_{0};
  std::uint32_t fail_tunes_{0};
  StatusCode error_{StatusCode::Ok};
  std::string last_error_detail_;

 public:
  // Test knobs owned by the pump.
  void set_fail_tunes(std::uint32_t n) { fail_tunes_ = n; }
  void set_hold_terminal(bool hold) { hold_terminal_ = hold; }
  bool has_terminal_action() const { return has_terminal_; }
  const JoinAction& terminal_action() const { return terminal_; }
  void clear_terminal() {
    terminal_ = JoinAction{};
    has_terminal_ = false;
  }
};

}  // namespace join_sim
