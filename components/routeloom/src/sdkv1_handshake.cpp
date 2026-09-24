#include "routeloom/sdkv1_handshake.hpp"

#include <cstring>

#include "routeloom/discovery_scope.hpp"  // sha256, hmac_sha256
#include "routeloom/rlcw1.hpp"  // cert_decode, cert_subject_kid (kid rule)
#include "routeloom/sdkv1_ead.hpp"  // join_credential_check (cert + kid match)
#include "routeloom/sdkv1_join_transport.hpp"  // join_step_valid (shared object codec)
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {

constexpr char kCookieLabel[] = "RouteLoom/v1/member-cookie";
constexpr char kProofLabel[] = "RouteLoom/v1/handshake-proof";

constexpr std::int32_t kEadCredential = -65541;  // one MemberCert by value (<= 256 B)

bool id_usable(const NodeId id) noexcept {
  return id != kInvalidNodeId && id != kBroadcastNodeId && id != 0;
}

bool mac_nonzero(const MacAddress& mac) noexcept {
  for (const auto byte : mac) {
    if (byte != 0) return true;
  }
  return false;
}

bool scope_pairwise(const SecurityScope scope) noexcept {
  return scope == SecurityScope::Link || scope == SecurityScope::EndToEnd;
}

keys::Purpose to_keys_purpose(const SecurityScope scope) noexcept {
  return scope == SecurityScope::EndToEnd ? keys::Purpose::End : keys::Purpose::Link;
}

ResumePurpose to_resume_purpose(const SecurityScope scope) noexcept {
  return scope == SecurityScope::EndToEnd ? ResumePurpose::End : ResumePurpose::Link;
}

// P4 §5.1 capability policy (production profile, PR2). Received bits are
// selection hints: the requester refuses upfront when mutual support is
// unconfirmed, and the authenticated State must then repeat the frozen
// P4-reserved bits. DevRam (bit 26) never mixes with profile 1.
bool caps_production(const std::uint32_t ours, const std::uint32_t theirs) noexcept {
  return ((ours | theirs) & kRld1CapDevRamSessionV1) == 0;
}

bool caps_p4_agree(const std::uint32_t frozen, const std::uint32_t live) noexcept {
  return (frozen & kRld1CapP4Mask) == (live & kRld1CapP4Mask);
}

// The EDHOC floor: both sides offer member EDHOC, neither is DevRam.
bool caps_edhoc_pair(const std::uint32_t ours, const std::uint32_t theirs) noexcept {
  return caps_production(ours, theirs) && ((ours & kRld1CapMemberEdhocV1) != 0) &&
         ((theirs & kRld1CapMemberEdhocV1) != 0);
}

// Resume additionally needs the resume bit on both sides.
bool caps_resume_pair(const std::uint32_t ours, const std::uint32_t theirs) noexcept {
  return caps_production(ours, theirs) && ((ours & kRld1CapMemberResumeV1) != 0) &&
         ((theirs & kRld1CapMemberResumeV1) != 0);
}

bool carrier_equal(const keys::LinkCarrier& a, const keys::LinkCarrier& b) noexcept {
  // Field-by-field: padding bytes are indeterminate, memcmp is not.
  return a.network == b.network && a.node_i == b.node_i && a.node_r == b.node_r &&
         a.requester_nonce == b.requester_nonce && a.responder_nonce == b.responder_nonce &&
         a.cookie == b.cookie && a.capability_i == b.capability_i &&
         a.capability_r == b.capability_r && a.scope_binding == b.scope_binding;
}

void put_u32_be(std::uint8_t* at, const std::uint32_t value) noexcept {
  at[0] = static_cast<std::uint8_t>(value >> 24U);
  at[1] = static_cast<std::uint8_t>(value >> 16U);
  at[2] = static_cast<std::uint8_t>(value >> 8U);
  at[3] = static_cast<std::uint8_t>(value);
}

// Epoch compatibility for a disclosed peer state (P4 §5.3): the site must
// match exactly, the GK within one step either way, the RS unconstrained
// (we enforce revocation with OUR view, never demand the peer's latest).
bool epochs_compatible(const HandshakeLocal& local, const std::uint32_t site_epoch,
                       const std::uint32_t peer_gk) noexcept {
  if (site_epoch != local.site_epoch) return false;
  const std::uint64_t peer = peer_gk;
  const std::uint64_t ours = local.gk_epoch;
  if (peer > ours + 1U) return false;
  if (ours >= peer + 2U) return false;
  return true;
}

Status resume_slot_identity(const ResumeSlot2& slot, ScopeDigest& out) noexcept {
  ResumeSlot2 stable = slot;
  stable.flags = 0;
  stable.last_used_boot = 0;
  stable.reserved_uses = 0;
  std::array<std::uint8_t, kResume2SlotBytes> encoded{};
  const Status status = resume2_slot_encode(stable, encoded);
  if (status) sha256(ByteView{encoded.data(), encoded.size()}, out);
  secure_clear(stable.rms);
  secure_clear(encoded);
  return status;
}

}  // namespace

// --- MemberCookie ---------------------------------------------------------------

Status MemberCookie::configure(const RandomFn random, void* random_ctx) noexcept {
  if (random == nullptr) return Status::error(StatusCode::InvalidArgument, "cookie random null");
  std::array<std::uint8_t, 32> key{};
  if (!random(random_ctx, key.data(), key.size())) {
    return Status::error(StatusCode::InvalidState, "cookie entropy not ready");
  }
  key_ = key;
  secure_clear(key);
  configured_ = true;
  return Status::success();
}

void MemberCookie::mac(const MacAddress& requester,
                       const std::array<std::uint8_t, 16>& txn_nonce, const NetworkId network,
                       const std::uint32_t bucket,
                       std::array<std::uint8_t, kCookieBytes>& out) const noexcept {
  std::array<std::uint8_t, 64> input{};
  std::size_t at = 0;
  const auto put = [&](const void* data, const std::size_t size) {
    if (at + size > input.size()) return;
    std::memcpy(input.data() + at, data, size);
    at += size;
  };
  put(kCookieLabel, sizeof(kCookieLabel));  // with the single NUL
  put(requester.data(), requester.size());
  put(txn_nonce.data(), txn_nonce.size());
  std::uint8_t be[8];
  for (std::size_t i = 0; i < 8; ++i) be[i] = static_cast<std::uint8_t>(network >> (56U - 8U * i));
  put(be, 8);
  std::uint8_t bucket_be[4];
  put_u32_be(bucket_be, bucket);
  put(bucket_be, 4);
  ScopeDigest digest{};
  hmac_sha256(ByteView{key_.data(), key_.size()}, ByteView{input.data(), at}, digest);
  secure_clear(input);
  std::memcpy(out.data(), digest.data(), out.size());
  secure_clear(digest);
}

Status MemberCookie::seal(const MacAddress& requester,
                          const std::array<std::uint8_t, 16>& txn_nonce, const NetworkId network,
                          const MonotonicMs now,
                          std::array<std::uint8_t, kCookieBytes>& out) const noexcept {
  out.fill(0);
  if (!configured_) return Status::error(StatusCode::InvalidState, "cookie not configured");
  mac(requester, txn_nonce, network, static_cast<std::uint32_t>(now / kBucketMs), out);
  return Status::success();
}

Status MemberCookie::verify(const MacAddress& requester,
                            const std::array<std::uint8_t, 16>& txn_nonce, const NetworkId network,
                            const ByteView cookie, const MonotonicMs now) const noexcept {
  if (!configured_) return Status::error(StatusCode::InvalidState, "cookie not configured");
  if (cookie.data == nullptr || cookie.size != kCookieBytes) {
    return Status::error(StatusCode::AuthenticationFailed, "cookie shape");
  }
  const std::uint32_t bucket = static_cast<std::uint32_t>(now / kBucketMs);
  for (std::uint32_t back = 0; back < 2; ++back) {
    if (back > bucket) break;  // no underflow at boot
    std::array<std::uint8_t, kCookieBytes> expect{};
    mac(requester, txn_nonce, network, bucket - back, expect);
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < kCookieBytes; ++i) {
      diff |= static_cast<std::uint8_t>(expect[i] ^ cookie.data[i]);
    }
    secure_clear(expect);
    if (diff == 0) return Status::success();
  }
  return Status::error(StatusCode::AuthenticationFailed, "cookie mismatch");
}

// --- HandshakeEngine ------------------------------------------------------------

HandshakeEngine::HandshakeEngine(ResumeCache2& cache, HandshakeSessionSink& sink,
                                 MemberCookie& cookie, HandshakeMembershipView& membership,
                                 SessionCredentialVerifier& verifier, const RandomFn random,
                                 void* random_ctx) noexcept
    : cache_(cache),
      sink_(sink),
      cookie_(cookie),
      membership_(membership),
      verifier_(verifier),
      random_(random),
      random_ctx_(random_ctx),
      credentials_(*this) {}

Status HandshakeEngine::configure(const MonotonicMs now) noexcept {
  if (entered_) return Status::error(StatusCode::Busy, "handshake re-entered");
  const EnterGuard guard(entered_);
  if (random_ == nullptr) return Status::error(StatusCode::InvalidArgument, "handshake random");
  if (!cookie_.configured()) {
    return Status::error(StatusCode::InvalidState, "handshake cookie not configured");
  }
  cancel_all_internal();
  rlres1_configured_ = false;
  staged_ = StagedEstablished{};
  has_pending_ = false;
  pending_ = HandshakeResult{};
  last_tick_ = now;
  ecc_primed_ = false;
  const Status local = refresh_local();
  if (!local) return local;
  configured_ = true;
  return Status::success();
}

Status HandshakeEngine::refresh_local() noexcept {
  HandshakeLocal fresh{};
  if (!membership_.local(fresh)) {
    cancel_all_internal();
    rlres1_configured_ = false;
    return Status::error(StatusCode::InvalidState, "handshake local evidence missing");
  }
  if (!id_usable(fresh.self) || fresh.network == 0 || fresh.site_id == 0 || fresh.role == 0 ||
      fresh.generation == 0) {
    cancel_all_internal();
    rlres1_configured_ = false;
    return Status::error(StatusCode::InvalidState, "handshake local view invalid");
  }
  if (local_set_ && fresh.site_id == local_.site_id &&
      (fresh.site_epoch < local_.site_epoch || fresh.rs_epoch < local_.rs_epoch ||
       fresh.gk_epoch < local_.gk_epoch || fresh.generation < local_.generation ||
       fresh.boot < local_.boot ||
       (fresh.site_epoch == local_.site_epoch && fresh.network != local_.network))) {
    cancel_all_internal();
    rlres1_configured_ = false;
    return Status::error(StatusCode::Conflict, "handshake local evidence regressed");
  }
  const bool changed =
      local_set_ && (fresh.network != local_.network || fresh.site_id != local_.site_id ||
                     fresh.self != local_.self || fresh.site_epoch != local_.site_epoch ||
                     fresh.rs_epoch != local_.rs_epoch || fresh.gk_epoch != local_.gk_epoch ||
                     fresh.generation != local_.generation || fresh.role != local_.role ||
                     fresh.caps != local_.caps || fresh.boot != local_.boot ||
                     fresh.local_cert_id != local_.local_cert_id);
  if (changed) {
    // An in-flight proof and every queued result belong to the old local
    // evidence. The caller retries after the new view has been adopted.
    cancel_all_internal();
    rlres1_configured_ = false;
  }
  local_ = fresh;
  local_set_ = true;
  if (!rlres1_configured_) {
    // A new site/network/self ends every exchange: the old bindings are
    // meaningless and the old keys must not install.
    cancel_all_internal();
    rlres1::Local view{};
    view.self = local_.self;
    view.network = local_.network;
    view.site_id = local_.site_id;
    view.epochs.site_epoch = local_.site_epoch;
    view.epochs.rs_epoch = local_.rs_epoch;
    view.epochs.gk_epoch = local_.gk_epoch;
    rlres1::Limits limits{};
    limits.base_timeout_ms = 2000;  // 3 x 500 ms R1 retransmits fit inside
    const Status configured = rlres1_.configure(view, limits);
    if (!configured) return configured;
    rlres1_configured_ = true;
  } else {
    rlres1::Epochs epochs{};
    epochs.site_epoch = local_.site_epoch;
    epochs.rs_epoch = local_.rs_epoch;
    epochs.gk_epoch = local_.gk_epoch;
    const Status updated = rlres1_.update_epochs(epochs);
    if (!updated) {
      // A regressed GK/RS view fails closed, loudly (never applied).
      cancel_all_internal();
      return updated;
    }
  }
  return changed ? Status::error(StatusCode::Conflict, "handshake local evidence changed")
                 : Status::success();
}

bool HandshakeEngine::quiescent() const noexcept {
  if (entered_) return false;
  if (has_pending_ || staged_.pending || edhoc_flight_.active) return false;
  for (const auto& record : records_) {
    if (record.used) return false;
  }
  return true;
}

// --- EAD compose/process (libedhoc downcalls; stage only, never decide) ---

Status HandshakeEngine::compose(const int message, edhoc::EadItem* items,
                                const std::size_t capacity, std::size_t& count) noexcept {
  count = 0;
  if (!edhoc_flight_.active || message != edhoc_flight_.phase || items == nullptr) {
    return Status::error(StatusCode::InvalidState, "session ead phase");
  }
  if (!edhoc_flight_.local_cred_set) {
    return Status::error(StatusCode::InvalidState, "session ead no credential");
  }
  const LocalCredential& cred = edhoc_flight_.local_cred;
  const ByteView cert{cred.cred.data(), cred.cred_size};
  auto set_item = [&](const std::size_t index, const std::int32_t label, const ByteView value) {
    items[index].label = label;
    items[index].value = value;
  };
  switch (message) {
    case 1: {
      if (capacity < 1) return Status::error(StatusCode::NoCapacity, "session ead room");
      set_item(0, kEadSessionIntent,
               ByteView{edhoc_flight_.intent_bytes.data(), edhoc_flight_.intent_bytes.size()});
      count = 1;
      return Status::success();
    }
    case 2: {
      if (capacity < 2) return Status::error(StatusCode::NoCapacity, "session ead room");
      set_item(0, kEadSessionState,
               ByteView{edhoc_flight_.state_r_bytes.data(), edhoc_flight_.state_r_bytes.size()});
      set_item(1, kEadCredential, cert);
      count = 2;
      return Status::success();
    }
    case 3: {
      if (capacity < 3) return Status::error(StatusCode::NoCapacity, "session ead room");
      set_item(0, kEadSessionState,
               ByteView{edhoc_flight_.state_i_bytes.data(), edhoc_flight_.state_i_bytes.size()});
      set_item(1, kEadCredential, cert);
      set_item(2, kEadContextConfirm,
               ByteView{edhoc_flight_.confirm_i_bytes.data(),
                        edhoc_flight_.confirm_i_bytes.size()});
      count = 3;
      return Status::success();
    }
    case 4: {
      if (capacity < 1) return Status::error(StatusCode::NoCapacity, "session ead room");
      set_item(0, kEadContextConfirm,
               ByteView{edhoc_flight_.confirm_r_bytes.data(),
                        edhoc_flight_.confirm_r_bytes.size()});
      count = 1;
      return Status::success();
    }
    default:
      return Status::error(StatusCode::InvalidState, "session ead message");
  }
}

Status HandshakeEngine::process(const int message, const edhoc::EadItem* items,
                                const std::size_t count) noexcept {
  // Syntax and staging only: libedhoc has NOT authenticated the peer yet
  // when this runs (m2 step 9 before step 10), so every staged value is
  // untrusted until the process_message_N call returns Ok.
  if (!edhoc_flight_.active || items == nullptr) {
    return Status::error(StatusCode::InvalidState, "session ead phase");
  }
  EdhocFlight& flight = edhoc_flight_;
  const bool initiator = flight.role == HandshakeRole::Initiator;
  auto stage_cert = [&](const ByteView value, std::array<std::uint8_t, 256>& slot,
                        std::size_t& size) {
    if (value.data == nullptr || value.size == 0 || value.size > slot.size()) {
      return Status::error(StatusCode::ProtocolError, "session ead credential");
    }
    slot.fill(0);
    std::memcpy(slot.data(), value.data, value.size);
    size = value.size;
    return Status::success();
  };
  if (message == 1 && !initiator) {
    if (count != 1 || items[0].label != kEadSessionIntent) {
      return Status::error(StatusCode::ProtocolError, "session ead m1 shape");
    }
    SessionIntent intent{};
    const Status decoded = session_intent_decode(items[0].value, intent);
    if (!decoded) return decoded;
    std::memcpy(flight.intent_bytes.data(), items[0].value.data, flight.intent_bytes.size());
    flight.intent_set = true;
    return Status::success();
  }
  if (message == 2 && initiator) {
    if (count != 2 || items[0].label != kEadSessionState ||
        items[1].label != kEadCredential) {
      return Status::error(StatusCode::ProtocolError, "session ead m2 shape");
    }
    SessionState state{};
    Status decoded = session_state_decode(items[0].value, state);
    if (!decoded) return decoded;
    decoded = stage_cert(items[1].value, flight.cred_r, flight.cred_r_size);
    if (!decoded) return decoded;
    std::memcpy(flight.state_r_bytes.data(), items[0].value.data, flight.state_r_bytes.size());
    flight.state_r_set = true;
    return Status::success();
  }
  if (message == 3 && !initiator) {
    if (count != 3 || items[0].label != kEadSessionState || items[1].label != kEadCredential ||
        items[2].label != kEadContextConfirm) {
      return Status::error(StatusCode::ProtocolError, "session ead m3 shape");
    }
    SessionState state{};
    Status decoded = session_state_decode(items[0].value, state);
    if (!decoded) return decoded;
    decoded = stage_cert(items[1].value, flight.cred_i, flight.cred_i_size);
    if (!decoded) return decoded;
    ContextConfirm confirm{};
    decoded = context_confirm_decode(items[2].value, confirm);
    if (!decoded) return decoded;
    std::memcpy(flight.state_i_bytes.data(), items[0].value.data, flight.state_i_bytes.size());
    std::memcpy(flight.confirm_i_bytes.data(), items[2].value.data,
                flight.confirm_i_bytes.size());
    flight.state_i_set = true;
    flight.confirm_i_set = true;
    return Status::success();
  }
  if (message == 4 && initiator) {
    if (count != 1 || items[0].label != kEadContextConfirm) {
      return Status::error(StatusCode::ProtocolError, "session ead m4 shape");
    }
    ContextConfirm confirm{};
    const Status decoded = context_confirm_decode(items[0].value, confirm);
    if (!decoded) return decoded;
    std::memcpy(flight.confirm_r_bytes.data(), items[0].value.data,
                flight.confirm_r_bytes.size());
    flight.confirm_r_set = true;
    return Status::success();
  }
  return Status::error(StatusCode::ProtocolError, "session ead out of place");
}

Status HandshakeEngine::MemberCredentials::local(const edhoc::Role role,
                                                edhoc::LocalCredential& out) noexcept {
  HandshakeEngine& self = engine_;
  if (!self.edhoc_flight_.active || !self.edhoc_flight_.local_cred_set) {
    return Status::error(StatusCode::InvalidState, "session credential missing");
  }
  const bool initiator = self.edhoc_flight_.role == HandshakeRole::Initiator;
  if ((role == edhoc::Role::Initiator) != initiator) {
    return Status::error(StatusCode::InvalidState, "session credential role");
  }
  const EdhocFlight& flight = self.edhoc_flight_;
  const LocalCredential& cred = flight.local_cred;
  out.kid = ByteView{flight.kid_local.data(), flight.kid_local.size()};
  out.credential = ByteView{cred.cred.data(), cred.cred_size};
  out.private_key = cred.privkey;
  return Status::success();
}

Status HandshakeEngine::MemberCredentials::peer(const edhoc::Role role, const ByteView kid,
                                               edhoc::PeerCredential& out) noexcept {
  HandshakeEngine& self = engine_;
  out = edhoc::PeerCredential{};
  if (!self.edhoc_flight_.active) {
    return Status::error(StatusCode::InvalidState, "session credential missing");
  }
  EdhocFlight& flight = self.edhoc_flight_;
  const bool initiator = flight.role == HandshakeRole::Initiator;
  // The peer's CRED arrived by value in this message's EAD (staged by
  // process() just before libedhoc authenticates). Decode it and match
  // the ID_CRED kid against the cnf key hash (P4 §5.1); the port then
  // verifies the chain, and every reported field is cross-checked
  // against the decode. Nothing cached, nothing trusted from an
  // earlier message, and a hook saying "ok" alone authenticates
  // nothing.
  const std::array<std::uint8_t, 256>& staged = initiator ? flight.cred_r : flight.cred_i;
  const std::size_t staged_size = initiator ? flight.cred_r_size : flight.cred_i_size;
  const ByteView staged_view{staged.data(), staged_size};
  CertClaims decoded{};
  const Status matched =
      join_credential_check(staged_view, CertType::Member, kid, decoded);
  if (!matched) return matched;
  CarrierRecord* record = self.find_record_by_token(flight.owner_token);
  if (record == nullptr) {
    return Status::error(StatusCode::InvalidState, "session peer orphan");
  }
  PeerCertClaims claims{};
  if (!self.verifier_.verify_peer(staged_view, record->peer, claims)) {
    return Status::error(StatusCode::AuthenticationFailed, "session peer chain");
  }
  if (claims.node != decoded.subject || claims.role != decoded.role ||
      claims.generation != decoded.assignment_generation ||
      claims.site_epoch != decoded.site_epoch) {
    return Status::error(StatusCode::AuthenticationFailed, "session peer claims disagree");
  }
  // The §5.3 m2 row: sub names the expected peer, the credential is
  // issued for our adopted network/site, the role is a known member
  // mask (cert_decode already enforces nonzero + mask).
  if (decoded.subject != record->peer || decoded.network != self.local_.network ||
      decoded.site_epoch != self.local_.site_epoch) {
    return Status::error(StatusCode::AuthenticationFailed, "session peer binding");
  }
  ScopeDigest cert_digest{};
  sha256(staged_view, cert_digest);
  VerifiedPeerClaims trusted{};
  trusted.node = decoded.subject;
  trusted.role = decoded.role;
  trusted.generation = decoded.assignment_generation;
  trusted.site_epoch = decoded.site_epoch;
  std::memcpy(trusted.cert_id.data(), cert_digest.data(), trusted.cert_id.size());
  trusted.pubkey = decoded.pubkey;
  flight.peer_claims = trusted;
  std::memcpy(flight.kid_peer.data(), kid.data, flight.kid_peer.size());
  flight.peer_verified = true;
  (void)role;
  out.credential = staged_view;
  out.public_key = decoded.pubkey;
  return Status::success();
}

// --- rlres1::Environment (the engine is the resume directory) ---

bool HandshakeEngine::random(const MutableByteView out) noexcept {
  if (random_ == nullptr || out.data == nullptr) return false;
  return random_(random_ctx_, out.data, out.size);
}

bool HandshakeEngine::find_slot(const rlres1::Purpose purpose, const rlres1::ResumeId& rid,
                                rlres1::Slot& out) noexcept {
  out = rlres1::Slot{};
  ResumeContext context{};
  context.network = local_.network;
  context.gk_epoch = local_.gk_epoch;
  // Revocation is consulted by the rlres1 gates (revoked(), below) at the
  // exact decision points — not here — so a view change between lookup
  // and gate cannot resurrect a rejected slot.
  context.revocations = nullptr;
  ResumeSlot2 found{};
  std::size_t index = 0;
  const ResumePurpose resume_purpose =
      purpose == keys::Purpose::End ? ResumePurpose::End : ResumePurpose::Link;
  if (!cache_.find_by_id(resume_purpose, rid, kInvalidNodeId, context, found, index).ok()) {
    return false;
  }
  // The slot must belong to OUR current credential: a stale cache from a
  // superseded local key never resumes (P4 §5.5).
  if (found.local_cert_id != local_.local_cert_id) return false;
  ResumeBinding binding{};
  binding.slot_index = index;
  if (!resume_slot_identity(found, binding.identity)) return false;
  binding.valid = true;
  resume_lookup_ = binding;
  out.purpose = purpose;
  out.peer = found.peer;
  out.network = found.network;
  out.created_gk_epoch = found.created_gk_epoch;
  out.peer_generation = found.peer_generation;
  out.secret = found.rms;
  return true;
}

bool HandshakeEngine::revoked(const NodeId peer, const std::uint32_t generation) noexcept {
  return membership_.revoked(peer, generation);
}

bool HandshakeEngine::allocate_context_id(const rlres1::Purpose purpose, const NodeId peer,
                                          std::uint32_t& cid) noexcept {
  (void)purpose;
  (void)peer;
  // Bank-unique, and kept out of the in-flight EDHOC CIDs (those enter the
  // context-id namespace at install).
  for (std::size_t attempt = 0; attempt < 8; ++attempt) {
    std::uint32_t id = 0;
    if (!sink_.allocate_context_id(id).ok()) return false;
    if (!edhoc_cid_in_flight(id)) {
      cid = id;
      return true;
    }
  }
  return false;
}

bool HandshakeEngine::reserve_resume_use(const rlres1::Purpose purpose,
                                         const rlres1::ResumeId& rid) noexcept {
  ResumeContext context{};
  context.network = local_.network;
  context.gk_epoch = local_.gk_epoch;
  context.revocations = nullptr;
  ResumeSlot2 found{};
  std::size_t index = 0;
  const ResumePurpose resume_purpose =
      purpose == keys::Purpose::End ? ResumePurpose::End : ResumePurpose::Link;
  if (!cache_.find_by_id(resume_purpose, rid, kInvalidNodeId, context, found, index).ok()) {
    return false;
  }
  if (found.local_cert_id != local_.local_cert_id) return false;
  return cache_.reserve_uses(index, context, local_.boot, false).ok();
}

// --- Records and results ---

void HandshakeEngine::end_edhoc_flight() noexcept {
  edhoc_.end();
  secure_clear(edhoc_flight_.local_cred.privkey);
  secure_clear(edhoc_flight_.local_cred.cred);
  secure_clear(edhoc_flight_.cred_i);
  secure_clear(edhoc_flight_.cred_r);
  secure_clear(edhoc_flight_.peer_claims.pubkey);
  const std::uint32_t owner = edhoc_flight_.owner_token;
  edhoc_flight_ = EdhocFlight{};
  if (big_tx_owner_ == owner) {  // our bytes only; a parked stash survives
    big_tx_.fill(0);
    big_tx_size_ = 0;
    big_tx_owner_ = 0;
  }
}

void HandshakeEngine::park_m1(CarrierRecord& record, const ByteView message) noexcept {
  if (message.data == nullptr || message.size == 0 || message.size > big_tx_.size()) {
    drop_record(record);  // unreachable: on_message caps at 960
    return;
  }
  if (message.data != big_tx_.data()) {
    std::memcpy(big_tx_.data(), message.data, message.size);
    big_tx_size_ = message.size;
  }
  big_tx_owner_ = record.token;
  record.state = RecordState::EdhocM1Parked;
}

HandshakeEngine::CarrierRecord* HandshakeEngine::find_record(const SecurityScope scope,
                                                             const NodeId peer,
                                                             const HandshakeRole role) noexcept {
  for (auto& record : records_) {
    if (record.used && record.scope == scope && record.peer == peer && record.role == role) {
      return &record;
    }
  }
  return nullptr;
}

HandshakeEngine::CarrierRecord* HandshakeEngine::find_record_by_token(
    const std::uint32_t token) noexcept {
  if (token == 0) return nullptr;
  for (auto& record : records_) {
    if (record.used && record.token == token) return &record;
  }
  return nullptr;
}

HandshakeEngine::CarrierRecord* HandshakeEngine::alloc_record() noexcept {
  for (auto& record : records_) {
    if (!record.used) {
      record = CarrierRecord{};
      record.used = true;
      return &record;
    }
  }
  return nullptr;
}

void HandshakeEngine::drop_record(CarrierRecord& record) noexcept {
  if (edhoc_flight_.active && edhoc_flight_.owner_token == record.token) end_edhoc_flight();
  if (record.state == RecordState::ResumeWaitR2) {
    rlres1_.abort(rlres1::Role::Initiator, record.peer, to_keys_purpose(record.scope));
  } else if (record.state == RecordState::ResumeWaitR3) {
    rlres1_.abort(rlres1::Role::Responder, record.peer, to_keys_purpose(record.scope));
  }
  record = CarrierRecord{};
}

void HandshakeEngine::cancel_all_internal() noexcept {
  for (auto& record : records_) {
    if (record.used) drop_record(record);
  }
  end_edhoc_flight();
  rlres1_.clear_all();
  resume_lookup_ = ResumeBinding{};
  pending_ = HandshakeResult{};
  has_pending_ = false;
  staged_ = StagedEstablished{};
  pending_commit_tx_ = 0;
  pending_commit_rx_ = 0;
  pending_commit_proof_ = AuthenticatedPeerProof{};
}

Status HandshakeEngine::emit_send(CarrierRecord& record, const std::uint8_t phase,
                                 const std::uint8_t step, const ByteView bytes,
                                 const bool cookie_attach) noexcept {
  if (has_pending_) return Status::error(StatusCode::Busy, "handshake result pending");
  if (bytes.data == nullptr || bytes.size == 0 || bytes.size > pending_.message.size()) {
    return Status::error(StatusCode::ProtocolError, "handshake send shape");
  }
  pending_ = HandshakeResult{};
  pending_.event = HandshakeEvent::Send;
  pending_.token = record.token;
  pending_.scope = record.scope;
  pending_.peer = record.peer;
  pending_.role = record.role;
  pending_.phase = phase;
  pending_.step = step;
  std::memcpy(pending_.message.data(), bytes.data, bytes.size);
  pending_.message_size = bytes.size;
  pending_.cookie_attach = cookie_attach;
  has_pending_ = true;
  return Status::success();
}

Status HandshakeEngine::emit_failed(CarrierRecord& record, const StatusCode failure) noexcept {
  if (!record.used) return Status::success();
  const std::uint32_t token = record.token;
  const SecurityScope scope = record.scope;
  const NodeId peer = record.peer;
  const HandshakeRole role = record.role;
  drop_record(record);
  if (has_pending_) return Status::error(StatusCode::Busy, "handshake result pending");
  pending_ = HandshakeResult{};
  pending_.event = HandshakeEvent::Failed;
  pending_.token = token;
  pending_.scope = scope;
  pending_.peer = peer;
  pending_.role = role;
  pending_.failure = failure;
  has_pending_ = true;
  return Status::success();
}

void HandshakeEngine::stage_established(const StagedEstablished& established) noexcept {
  staged_ = established;
  staged_.pending = true;
}

bool HandshakeEngine::ecc_budget_ok(const MonotonicMs now) noexcept {
  if (!ecc_primed_) return true;
  const MonotonicMs elapsed = now >= last_ecc_ ? now - last_ecc_ : 0;
  return elapsed >= kEccMinGapMs;
}

void HandshakeEngine::ecc_spent(const MonotonicMs now) noexcept {
  last_ecc_ = now;
  ecc_primed_ = true;
}

Status HandshakeEngine::draw_exchange_id(std::uint32_t& out) noexcept {
  out = 0;
  std::uint8_t raw[4] = {0, 0, 0, 0};
  if (random_ == nullptr || !random_(random_ctx_, raw, sizeof(raw))) {
    return Status::error(StatusCode::InvalidState, "handshake entropy not ready");
  }
  const std::uint32_t id = (static_cast<std::uint32_t>(raw[0]) << 24U) |
                           (static_cast<std::uint32_t>(raw[1]) << 16U) |
                           (static_cast<std::uint32_t>(raw[2]) << 8U) | raw[3];
  if (id == 0) return Status::error(StatusCode::Busy, "handshake exchange retry");
  out = id;
  return Status::success();
}

bool HandshakeEngine::edhoc_cid_in_flight(const std::uint32_t id) const noexcept {
  if (id == 0 || !edhoc_flight_.active) return id == 0;
  return id == edhoc_flight_.cid_own || id == edhoc_flight_.cid_peer;
}

Status HandshakeEngine::build_binding(const SecurityScope scope, const keys::LinkCarrier& carrier,
                                     const MacAddress& mac_i, const MacAddress& mac_r,
                                     const NodeId node_i, const NodeId node_r,
                                     const std::uint32_t exchange_id,
                                     std::array<std::uint8_t, 32>& out) noexcept {
  out.fill(0);
  if (scope == SecurityScope::Link) {
    ScopeDigest carrier_digest{};
    keys::link_carrier_digest(carrier, carrier_digest);
    ScopeDigest binding{};
    keys::resume_binding_link(mac_i, mac_r, carrier_digest, binding);
    out = binding;
    return Status::success();
  }
  if (scope == SecurityScope::EndToEnd) {
    // Both ends adopt the same full network or the Intent gate fails
    // closed; the link carrier has no meaning here.
    ScopeDigest binding{};
    keys::end_carrier_binding(local_.network, node_i, node_r, exchange_id, binding);
    out = binding;
    return Status::success();
  }
  return Status::error(StatusCode::Unsupported, "handshake scope");
}

Status HandshakeEngine::responder_cookie_ok(const HandshakeRx& rx) noexcept {
  if (rx.scope == SecurityScope::EndToEnd) return Status::success();  // no discovery cookie (PR3)
  if (!member_cookie_required(rx.phase, rx.step)) return Status::success();
  // The cookie the OFFER issued for (requester MAC, txn): verified before
  // any session state exists. The attached bytes must equal the frozen
  // exchange's cookie AND verify under the boot key.
  if (rx.cookie.size != MemberCookie::kCookieBytes) {
    return Status::error(StatusCode::AuthenticationFailed, "handshake cookie missing");
  }
  if (std::memcmp(rx.cookie.data, rx.carrier.cookie.data(), rx.cookie.size) != 0) {
    return Status::error(StatusCode::AuthenticationFailed, "handshake cookie mismatch");
  }
  return cookie_.verify(rx.src_mac, rx.carrier.requester_nonce, rx.carrier.network, rx.cookie,
                        last_tick_);
}

// --- Requests ---

Status HandshakeEngine::request(const HandshakeRequest& req, const MonotonicMs now) noexcept {
  if (entered_) return Status::error(StatusCode::Busy, "handshake re-entered");
  const EnterGuard guard(entered_);
  if (!configured_) return Status::error(StatusCode::InvalidState, "handshake not configured");
  if (has_pending_) return Status::error(StatusCode::Busy, "handshake result pending");
  if (now < last_tick_) return Status::error(StatusCode::InvalidArgument, "handshake time moved");
  last_tick_ = now;
  const Status local = refresh_local();
  if (!local) return local;
  if (!scope_pairwise(req.scope) || !id_usable(req.peer) || req.peer == local_.self) {
    return Status::error(StatusCode::InvalidArgument, "handshake request shape");
  }
  if (req.reason != HandshakeReason::Initial && req.reason != HandshakeReason::Rekey &&
      req.reason != HandshakeReason::ResumeRetry) {
    return Status::error(StatusCode::InvalidArgument, "handshake reason");
  }
  for (const auto& candidate : records_) {
    if (candidate.used && candidate.scope == req.scope && candidate.peer == req.peer) {
      return Status::error(StatusCode::Busy, "handshake already in flight");
    }
  }
  if (next_token_ == 0xFFFFFFFFU) {
    return Status::error(StatusCode::CounterExhausted, "handshake token exhausted");
  }
  CarrierRecord seed{};
  seed.used = true;
  seed.scope = req.scope;
  seed.peer = req.peer;
  seed.role = HandshakeRole::Initiator;
  seed.reason = req.reason;
  seed.token = next_token_++;
  seed.elevation_token = req.elevation_token;
  seed.deadline = now + kLinkTimeoutMs;
  bool resume_offered = false;
  if (req.scope == SecurityScope::Link) {
    if (!mac_nonzero(req.mac_i) || !mac_nonzero(req.mac_r) || req.mac_i == req.mac_r) {
      return Status::error(StatusCode::InvalidArgument, "handshake link macs");
    }
    if (req.carrier.network != local_.network || req.carrier.node_i != local_.self ||
        req.carrier.node_r != req.peer) {
      return Status::error(StatusCode::InvalidArgument, "handshake link carrier");
    }
    // Selection on the frozen hints (P4 §5.1): the EDHOC floor must be
    // mutual or the link is Unsupported; resume-first additionally
    // needs the resume bit on both sides.
    if (!caps_edhoc_pair(req.carrier.capability_i, req.carrier.capability_r)) {
      return Status::error(StatusCode::Unsupported, "handshake peer edhoc unsupported");
    }
    seed.mac_i = req.mac_i;
    seed.mac_r = req.mac_r;
    seed.carrier = req.carrier;
    resume_offered = caps_resume_pair(req.carrier.capability_i, req.carrier.capability_r);
  } else {
    const Status drawn = draw_exchange_id(seed.exchange_id);
    if (!drawn) return drawn;
    resume_offered = true;  // end has no DISCOVER hint; the RMS proof decides
  }
  // Resume-first (except an explicit retry, which goes straight to EDHOC):
  // look up and reserve BEFORE the record commits, so a refused request
  // leaves no trace.
  if (req.reason != HandshakeReason::ResumeRetry && resume_offered) {
    ResumeContext context{};
    context.network = local_.network;
    context.gk_epoch = local_.gk_epoch;
    context.revocations = nullptr;
    ResumeSlot2 slot{};
    std::size_t index = 0;
    const Status found =
        cache_.find_by_peer(to_resume_purpose(req.scope), req.peer, context, slot, index);
    if (found.ok() && slot.local_cert_id == local_.local_cert_id &&
        !membership_.revoked(slot.peer, slot.peer_generation) &&
        rlres1_.initiator_in_flight() < 4) {
      // The use is spent here, before R1 exists; a later failure is never
      // refunded (P4 §6.2).
      if (cache_.reserve_uses(index, context, local_.boot, false).ok()) {
        CarrierRecord* record = alloc_record();
        if (record == nullptr) {
          return Status::error(StatusCode::Busy, "handshake table full");
        }
        *record = seed;
        return begin_resume(*record, slot, index, now);
      }
    }
  }
  CarrierRecord* record = alloc_record();
  if (record == nullptr) return Status::error(StatusCode::Busy, "handshake table full");
  *record = seed;
  record->state = RecordState::EdhocQueued;
  record->retransmit_at = now;  // poll starts the flight when free
  if (!edhoc_flight_.active && ecc_budget_ok(now)) {
    return begin_edhoc(*record, now);
  }
  return Status::success();
}

Status HandshakeEngine::begin_resume(CarrierRecord& record, const ResumeSlot2& slot,
                                     const std::size_t slot_index,
                                     const MonotonicMs now) noexcept {
  record.resume.slot_index = slot_index;
  const Status identity = resume_slot_identity(slot, record.resume.identity);
  if (!identity) {
    drop_record(record);
    return identity;
  }
  record.resume.valid = true;
  rlres1::BeginRequest begin{};
  begin.slot.purpose = to_keys_purpose(record.scope);
  begin.slot.peer = slot.peer;
  begin.slot.network = slot.network;
  begin.slot.created_gk_epoch = slot.created_gk_epoch;
  begin.slot.peer_generation = slot.peer_generation;
  begin.slot.secret = slot.rms;
  if (record.scope == SecurityScope::Link) {
    begin.carrier.kind = rlres1::Carrier::Kind::Link;
    begin.carrier.mac_i = record.mac_i;
    begin.carrier.mac_r = record.mac_r;
    keys::link_carrier_digest(record.carrier, begin.carrier.carrier_digest);
  } else {
    begin.carrier.kind = rlres1::Carrier::Kind::Routed;
    begin.carrier.hops = 0;  // PR2: direct end sessions only (PR3 routes)
  }
  rlres1::Output out{};
  rlres1_.begin(begin, now, *this, out);
  if (out.action != rlres1::Action::Send) {
    // The cache said usable but the engine disagrees (RRS moved, GK moved):
    // fall back to a full EDHOC rather than fail the request.
    if (out.reject == rlres1::Reject::SlotExpired || out.reject == rlres1::Reject::PeerRevoked) {
      record.state = RecordState::EdhocQueued;
      record.retransmit_at = now;
      if (!edhoc_flight_.active && ecc_budget_ok(now)) return begin_edhoc(record, now);
      return Status::success();
    }
    const StatusCode failure = out.reject == rlres1::Reject::TableFull ||
                                       out.reject == rlres1::Reject::EntropyUnavailable
                                   ? StatusCode::Busy
                                   : StatusCode::InternalError;
    drop_record(record);
    secure_clear(out.message);
    return Status::error(failure, "handshake resume begin refused");
  }
  if (out.message_size > record.last_tx.size()) {
    drop_record(record);
    secure_clear(out.message);
    return Status::error(StatusCode::InternalError, "handshake r1 oversized");
  }
  std::memcpy(record.last_tx.data(), out.message.data(), out.message_size);
  record.last_tx_size = out.message_size;
  record.last_phase = 5;
  record.last_step = 1;
  record.state = RecordState::ResumeWaitR2;
  record.retransmit_at = now + kResumeRetransmitMs;
  record.retransmits = 0;
  const Status sent = emit_send(record, 5, 1, ByteView{out.message.data(), out.message_size},
                                record.scope == SecurityScope::Link);
  secure_clear(out.message);
  return sent;
}

Status HandshakeEngine::begin_edhoc(CarrierRecord& record, const MonotonicMs now) noexcept {
  if (edhoc_flight_.active) {
    record.state = RecordState::EdhocQueued;
    record.retransmit_at = now;
    return Status::success();
  }
  if (!ecc_budget_ok(now)) {
    record.state = RecordState::EdhocQueued;
    record.retransmit_at = last_ecc_ + kEccMinGapMs;
    return Status::success();
  }
  // Own C_x: nonzero, bank-unique, collision-free against the peer id we
  // are about to learn (checked again at parse time).
  std::uint32_t cid = 0;
  for (std::size_t attempt = 0; attempt < 8; ++attempt) {
    std::uint32_t id = 0;
    if (!sink_.allocate_context_id(id).ok()) {
      return Status::error(StatusCode::Busy, "handshake context id unavailable");
    }
    if (!edhoc_cid_in_flight(id)) {
      cid = id;
      break;
    }
  }
  if (cid == 0) return Status::error(StatusCode::Busy, "handshake context id unavailable");
  EdhocFlight flight{};
  flight.active = true;
  flight.owner_token = record.token;
  flight.role = record.role;
  flight.cid_own = cid;
  flight.phase = record.role == HandshakeRole::Initiator ? 1 : 2;
  if (!verifier_.local_credential(flight.local_cred)) {
    return Status::error(StatusCode::InvalidState, "handshake local credential missing");
  }
  if (flight.local_cred.cred_size == 0 || flight.local_cred.cred_size > 256) {
    secure_clear(flight.local_cred.privkey);
    return Status::error(StatusCode::InvalidState, "handshake local credential shape");
  }
  // Bind the port's credential to this exchange: it must BE our member
  // certificate (type + sub), the kid is derived from it (P4 §5.1), and
  // the membership view's cert id must name the same bytes — a port and
  // a view disagreeing about who we are ends the exchange, not the
  // binding.
  CertClaims local_claims{};
  const ByteView local_cert{flight.local_cred.cred.data(), flight.local_cred.cred_size};
  Status local_ok = cert_decode(local_cert, local_claims);
  if (local_ok.ok() && (local_claims.type != CertType::Member ||
                         local_claims.subject != local_.self ||
                         local_claims.network != local_.network)) {
    local_ok = Status::error(StatusCode::InvalidState, "handshake local credential binding");
  }
  Digest256 local_kid{};
  if (local_ok.ok()) local_ok = cert_subject_kid(local_claims, local_kid);
  ScopeDigest local_digest{};
  if (local_ok.ok()) {
    sha256(local_cert, local_digest);
    if (std::memcmp(local_digest.data(), local_.local_cert_id.data(),
                     local_.local_cert_id.size()) != 0) {
      local_ok = Status::error(StatusCode::InvalidState, "handshake local cert id disagree");
    }
  }
  if (!local_ok.ok()) {
    secure_clear(flight.local_cred.privkey);
    secure_clear(flight.local_cred.cred);
    return local_ok;
  }
  flight.kid_local = local_kid;
  edhoc_flight_ = flight;
  secure_clear(flight.local_cred.privkey);
  edhoc_flight_.local_cred_set = true;
  put_u32_be(edhoc_cid_bytes_.data(), cid);
  edhoc::SessionConfig config{};
  config.role = record.role == HandshakeRole::Initiator ? edhoc::Role::Initiator
                                                        : edhoc::Role::Responder;
  config.method = edhoc::Method::SignatureSignature;  // P4 §5.1: method 0
  config.suites = {{edhoc::kCipherSuite2}};
  config.suite_count = 1;
  config.connection_id = ByteView{edhoc_cid_bytes_.data(), edhoc_cid_bytes_.size()};
  config.credentials = &credentials_;
  config.aead = nullptr;  // suite builtin
  config.random = random_;
  config.random_ctx = random_ctx_;
  config.ead = this;
  const Status begun = edhoc_.begin(config);
  if (!begun) {
    end_edhoc_flight();
    return begun;
  }
  ecc_spent(now);
  if (record.role == HandshakeRole::Initiator) {
    // Intent commits to the carrier BEFORE any key exists (P4 §5.3).
    std::array<std::uint8_t, 32> binding{};
    const Status bound = build_binding(record.scope, record.carrier, record.mac_i, record.mac_r,
                                       local_.self, record.peer, record.exchange_id, binding);
    if (!bound) {
      end_edhoc_flight();
      return bound;
    }
    SessionIntent intent{};
    intent.purpose = record.scope == SecurityScope::EndToEnd ? kSessionPurposeEnd
                                                             : kSessionPurposeLink;
    intent.profile = kSessionProfileMember;
    // Caps repeat the FROZEN carrier word (P4 §5.3 agreement), never the
    // live view: the responder's State check compares against the same
    // frozen bytes.
    intent.caps_i = record.scope == SecurityScope::Link ? record.carrier.capability_i : 0;
    intent.boot_i = local_.boot;
    intent.binding = binding;
    std::array<std::uint8_t, kSessionIntentBytes> encoded{};
    const Status packed = session_intent_encode(intent, encoded);
    if (!packed) {
      end_edhoc_flight();
      return packed;
    }
    edhoc_flight_.intent_bytes = encoded;
    edhoc_flight_.intent_set = true;
    std::array<std::uint8_t, kMaxMessageBytes> m1{};
    std::size_t m1_size = 0;
    const Status composed = edhoc_.compose_message_1(MutableByteView{m1.data(), m1.size()},
                                                    m1_size);
    if (!composed || m1_size == 0 || m1_size > record.last_tx.size()) {
      end_edhoc_flight();
      secure_clear(m1);
      return Status::error(StatusCode::ProtocolError, "handshake m1 oversized");
    }
    std::memcpy(record.last_tx.data(), m1.data(), m1_size);
    record.last_tx_size = m1_size;
    record.last_phase = 4;
    record.last_step = 1;
    record.state = RecordState::EdhocWaitM2;
    record.retransmit_at = now + kEdhocRetransmitMs;
    record.retransmits = 0;
    const Status sent =
        emit_send(record, 4, 1, ByteView{m1.data(), m1_size}, record.scope == SecurityScope::Link);
    secure_clear(m1);
    return sent;
  }
  return Status::success();
}

// --- Inbound ---

Status HandshakeEngine::on_message(const HandshakeRx& rx, const ByteView message,
                                   const MonotonicMs now) noexcept {
  if (entered_) return Status::error(StatusCode::Busy, "handshake re-entered");
  const EnterGuard guard(entered_);
  if (!configured_) return Status::error(StatusCode::InvalidState, "handshake not configured");
  if (has_pending_) return Status::error(StatusCode::Busy, "handshake result pending");
  if (now < last_tick_) return Status::error(StatusCode::InvalidArgument, "handshake time moved");
  last_tick_ = now;
  const Status local = refresh_local();
  if (!local) return local;
  if (!scope_pairwise(rx.scope) || message.data == nullptr || message.size == 0 ||
      message.size > kMaxMessageBytes) {
    return Status::success();  // stranger bytes: drop, never fail a record
  }
  // The exchange id travels in the routed envelope (P4 §7.3); link
  // frames have no such field and must read 0.
  if ((rx.scope == SecurityScope::Link) == (rx.exchange_id != 0)) {
    return Status::success();
  }
  const bool edhoc = rx.phase == 4;
  const bool resume = rx.phase == 5;
  if (!edhoc && !resume) return Status::success();
  const JoinAuthPhase phase =
      edhoc ? JoinAuthPhase::EdhocMessage : JoinAuthPhase::Resume;
  if (!join_step_valid(phase, rx.step)) return Status::success();
  if (rx.step == 5) return Status::success();  // EDHOC errors never fail us (timeout owns that)
  CarrierRecord* record = nullptr;
  if (rx.claimed_peer != kInvalidNodeId) {
    // Later steps repeat the carrier; a re-bound carrier is a drop.
    // Step-1 matches only the same protocol's responder states: a
    // step-1 for a completed or foreign-protocol exchange is a NEW
    // exchange, never a duplicate.
    for (auto& candidate : records_) {
      if (!candidate.used || candidate.scope != rx.scope) continue;
      const bool expects_initiator =
          (edhoc && (rx.step == 2 || rx.step == 4)) || (resume && rx.step == 2);
      if ((candidate.role == HandshakeRole::Initiator) != expects_initiator) continue;
      if (candidate.peer != rx.claimed_peer) continue;
      if (rx.step == 1) {
        const RecordState state = candidate.state;
        if (edhoc) {
          if (state != RecordState::EdhocWaitM3 && state != RecordState::EdhocM4Sent &&
              state != RecordState::EdhocM1Parked) {
            continue;
          }
        } else if (state != RecordState::ResumeWaitR3) {
          continue;
        }
      }
      if (rx.scope == SecurityScope::Link && rx.step != 1 &&
          !carrier_equal(candidate.carrier, rx.carrier)) {
        continue;
      }
      if (rx.scope == SecurityScope::EndToEnd && candidate.exchange_id != rx.exchange_id) {
        continue;
      }
      record = &candidate;
      break;
    }
  } else if (rx.step != 1) {
    // Unknown claimant: only a unique in-flight match answers (end
    // frames still filter on the envelope's exchange id).
    for (auto& candidate : records_) {
      if (!candidate.used || candidate.scope != rx.scope) continue;
      const bool expects_initiator =
          (edhoc && (rx.step == 2 || rx.step == 4)) || (resume && rx.step == 2);
      if ((candidate.role == HandshakeRole::Initiator) != expects_initiator) continue;
      if (rx.scope == SecurityScope::EndToEnd && candidate.exchange_id != rx.exchange_id) continue;
      if (record != nullptr) return Status::success();  // ambiguous: drop
      record = &candidate;
    }
  }
  if (edhoc) return on_edhoc_message(record, rx, message, now);
  return on_resume_message(record, rx, message, now);
}

Status HandshakeEngine::verify_cookie_and_allocate(const HandshakeRx& rx, const ByteView message,
                                                  CarrierRecord*& record,
                                                  const MonotonicMs now) noexcept {
  (void)message;
  record = nullptr;
  const Status cookie = responder_cookie_ok(rx);
  if (!cookie) return cookie;
  // No ECC-budget gate here: an over-budget m1 parks for poll()
  // (responder_begin_m1) instead of dropping, so the initiator's
  // retransmits refresh the stash rather than race the budget.
  if (next_token_ == 0xFFFFFFFFU) {
    return Status::error(StatusCode::CounterExhausted, "handshake token exhausted");
  }
  CarrierRecord* fresh = alloc_record();
  if (fresh == nullptr) return Status::error(StatusCode::Busy, "handshake table full");
  fresh->used = true;
  fresh->scope = rx.scope;
  fresh->peer = rx.claimed_peer;  // unverified hint until the Credential lands
  fresh->role = HandshakeRole::Responder;
  fresh->reason = HandshakeReason::Initial;
  fresh->token = next_token_++;
  fresh->elevation_token = rx.elevation_token;
  fresh->deadline = now + kLinkTimeoutMs;
  if (rx.scope == SecurityScope::Link) {
    fresh->mac_i = rx.src_mac;
    fresh->mac_r = rx.dst_mac;
    fresh->carrier = rx.carrier;
  } else {
    fresh->exchange_id = rx.exchange_id;  // nonzero: checked in on_message
  }
  record = fresh;
  return Status::success();
}

bool HandshakeEngine::step1_may_proceed(const SecurityScope scope, const NodeId peer) noexcept {
  if (peer == kInvalidNodeId) return true;  // unknown: duplicates die by hash/nonce
  for (auto& candidate : records_) {
    if (!candidate.used || candidate.scope != scope || candidate.peer != peer) continue;
    if (candidate.state == RecordState::EdhocM4Sent ||
        candidate.state == RecordState::ResumeR3Confirm) {
      // Completed: the peer's new step-1 ends our quiet resend duty.
      // (Same-protocol retransmits never reach here — the duplicate
      // path matches them first — so this is unambiguously new.)
      drop_record(candidate);
      return true;
    }
    if (candidate.role == HandshakeRole::Responder) return false;  // ours owns this peer
    // Simultaneous open, any protocol: the smaller NodeId stays
    // initiator (P4 §5.5). Larger yields silently and answers as
    // responder — no livelock, no failure.
    if (local_.self < peer) return false;  // we proceed; drop theirs
    drop_record(candidate);
    return true;
  }
  return true;
}

Status HandshakeEngine::read_peer_cid(std::uint32_t& out) noexcept {
  out = 0;
  std::array<std::uint8_t, 4> raw{};
  std::size_t length = 0;
  const Status read =
      edhoc_.peer_connection_id(MutableByteView{raw.data(), raw.size()}, length);
  if (!read) return read;
  // The member profile fixes both CIDs to nonzero 4-byte strings (P4
  // §5.1); integer/short CIDs are otherwise valid EDHOC but refused
  // here, and a peer echoing our own C_x is a reflection.
  if (length != raw.size()) {
    return Status::error(StatusCode::ProtocolError, "session peer cid width");
  }
  const std::uint32_t id = (static_cast<std::uint32_t>(raw[0]) << 24U) |
                           (static_cast<std::uint32_t>(raw[1]) << 16U) |
                           (static_cast<std::uint32_t>(raw[2]) << 8U) | raw[3];
  if (id == 0 || id == edhoc_flight_.cid_own) {
    return Status::error(StatusCode::ProtocolError, "session peer cid value");
  }
  out = id;
  return Status::success();
}

Status HandshakeEngine::responder_begin_m1(CarrierRecord& record,
                                                   const ByteView message,
                                                   const MonotonicMs now) noexcept {
  if (edhoc_flight_.active || !ecc_budget_ok(now)) {
    park_m1(record, message);
    return Status::success();
  }
  const Status begun = begin_edhoc(record, now);
  if (!begun) {
    if (begun.code == StatusCode::Busy) {
      park_m1(record, message);  // context-id pool transiently dry
      return Status::success();
    }
    drop_record(record);  // credential failure: not parkable
    return Status::success();
  }
  if (record.state == RecordState::EdhocQueued) {
    park_m1(record, message);  // begin queued us (backstop): park instead
    return Status::success();
  }
  const Status processed = edhoc_.process_message_1(message);
    std::uint32_t cid_i = 0;
    const Status cid_ok = processed.ok() ? read_peer_cid(cid_i) : processed;
    if (!processed || !cid_ok.ok() || !edhoc_flight_.intent_set) {
      drop_record(record);
      return Status::success();
    }
    edhoc_flight_.cid_peer = cid_i;
    // Cheap gates on the UNAUTHENTICATED Intent (agreement, not trust):
    // the exchange must name this carrier, or it is not ours. Caps are
    // NOT gated here: the received bits are selection hints, and the
    // authenticated State confirms agreement at m3 (P4 §5.1/§5.3).
    SessionIntent intent{};
    std::array<std::uint8_t, 32> binding{};
    const Status bound = build_binding(record.scope, record.carrier, record.mac_i, record.mac_r,
                                       record.peer, local_.self, record.exchange_id, binding);
    if (!bound) {
      drop_record(record);
      return Status::success();
    }
    Status intent_ok = session_intent_decode(
        ByteView{edhoc_flight_.intent_bytes.data(), edhoc_flight_.intent_bytes.size()}, intent);
    if (intent_ok.ok()) {
      const std::uint8_t want_purpose = record.scope == SecurityScope::EndToEnd
                                            ? kSessionPurposeEnd
                                            : kSessionPurposeLink;
      if (intent.purpose != want_purpose || intent.binding != binding) {
        intent_ok = Status::error(StatusCode::ProtocolError, "intent binding");
      }
    }
    if (!intent_ok.ok()) {
      drop_record(record);
      return Status::success();
    }
    // State_R: our disclosed epochs/caps (compose() sends these). Caps
    // repeat the frozen OFFER word, like the initiator's Intent repeats
    // the frozen DISCOVER word.
    SessionState state_r{};
    state_r.purpose = record.scope == SecurityScope::EndToEnd ? kSessionPurposeEnd
                                                              : kSessionPurposeLink;
    state_r.profile = kSessionProfileMember;
    state_r.site_epoch = local_.site_epoch;
    state_r.rs_epoch = local_.rs_epoch;
    state_r.gk_epoch = local_.gk_epoch;
    state_r.boot = local_.boot;
    state_r.caps =
        record.scope == SecurityScope::Link ? record.carrier.capability_r : 0;
    std::array<std::uint8_t, kSessionStateBytes> state_r_bytes{};
    if (!session_state_encode(state_r, state_r_bytes).ok()) {
      drop_record(record);
      return Status::success();
    }
    edhoc_flight_.state_r_bytes = state_r_bytes;
    edhoc_flight_.state_r_set = true;
    std::array<std::uint8_t, kMaxMessageBytes> m2{};
    std::size_t m2_size = 0;
    const Status composed =
        edhoc_.compose_message_2(MutableByteView{m2.data(), m2.size()}, m2_size);
    if (!composed || m2_size == 0 || m2_size > big_tx_.size()) {
      drop_record(record);
      secure_clear(m2);
      return Status::success();
    }
    std::memcpy(big_tx_.data(), m2.data(), m2_size);
    big_tx_size_ = m2_size;
    big_tx_owner_ = record.token;
    sha256(message, edhoc_flight_.m1_hash);
    edhoc_flight_.m1_seen = true;
    record.state = RecordState::EdhocWaitM3;
    const Status sent =
        emit_send(record, 4, 2, ByteView{m2.data(), m2_size}, false);
    secure_clear(m2);
    return sent;
  }

Status HandshakeEngine::on_edhoc_message(CarrierRecord* record, const HandshakeRx& rx,
                                         const ByteView message, const MonotonicMs now) noexcept {
  if (rx.step == 1) {
    // Responder-new, or a duplicate m1 (resend cached m2/m4 without
    // touching libedhoc). Unknown claimants match only an equally
    // unknown in-flight record.
    if (record == nullptr && rx.claimed_peer == kInvalidNodeId) {
      for (auto& candidate : records_) {
        if (candidate.used && candidate.scope == rx.scope &&
            candidate.role == HandshakeRole::Responder && candidate.peer == kInvalidNodeId &&
            (candidate.state == RecordState::EdhocWaitM3 ||
             candidate.state == RecordState::EdhocM4Sent ||
             candidate.state == RecordState::EdhocM1Parked)) {
          record = &candidate;
          break;
        }
      }
    }
    if (record != nullptr && record->state == RecordState::EdhocM1Parked) {
      // Still waiting for the flight/budget: refresh a clobbered stash
      // from the retransmit, else the first parking stands. First bytes
      // win — a differing m1 while parked is dropped, not displaced.
      if (big_tx_owner_ != record->token && message.size <= big_tx_.size()) {
        std::memcpy(big_tx_.data(), message.data, message.size);
        big_tx_size_ = message.size;
        big_tx_owner_ = record->token;
      }
      return Status::success();
    }
    if (record != nullptr) {
      ScopeDigest hash{};
      sha256(message, hash);
      const bool duplicate =
          edhoc_flight_.m1_seen && edhoc_flight_.owner_token == record->token &&
          std::memcmp(hash.data(), edhoc_flight_.m1_hash.data(), hash.size()) == 0;
      if (!duplicate || big_tx_size_ == 0 || big_tx_owner_ != record->token) {
        return Status::success();  // busy or clobbered: drop
      }
      const std::uint8_t step =
          record->state == RecordState::EdhocM4Sent ? 4 : 2;
      return emit_send(*record, 4, step, ByteView{big_tx_.data(), big_tx_size_}, false);
    }
    if (!step1_may_proceed(rx.scope, rx.claimed_peer)) return Status::success();
    CarrierRecord* fresh = nullptr;
    const Status allocated = verify_cookie_and_allocate(rx, message, fresh, now);
    if (!allocated) return Status::success();  // cookie/budget/table: drop
    return responder_begin_m1(*fresh, message, now);
  }
  if (record == nullptr) return Status::success();  // no exchange expects this
  if (rx.step == 2) {
    if (record->role != HandshakeRole::Initiator ||
        record->state != RecordState::EdhocWaitM2 ||
        !edhoc_flight_.active || edhoc_flight_.owner_token != record->token) {
      return Status::success();
    }
    const Status processed = edhoc_.process_message_2(message);
    std::uint32_t cid_r = 0;
    const Status cid_ok = processed.ok() ? read_peer_cid(cid_r) : processed;
    if (!processed || !cid_ok.ok()) {
      return emit_failed(*record, StatusCode::AuthenticationFailed);
    }
    edhoc_flight_.cid_peer = cid_r;
    if (!edhoc_flight_.state_r_set || !edhoc_flight_.peer_verified) {
      return emit_failed(*record, StatusCode::AuthenticationFailed);
    }
    const Status checked = check_peer_state(*record, false);
    if (!checked) return emit_failed(*record, StatusCode::AuthenticationFailed);
    // State_I + Confirm_I (compose() sends these). Caps repeat the
    // frozen DISCOVER word, like the m1 Intent did.
    SessionState state_i{};
    state_i.purpose =
        record->scope == SecurityScope::EndToEnd ? kSessionPurposeEnd : kSessionPurposeLink;
    state_i.profile = kSessionProfileMember;
    state_i.site_epoch = local_.site_epoch;
    state_i.rs_epoch = local_.rs_epoch;
    state_i.gk_epoch = local_.gk_epoch;
    state_i.boot = local_.boot;
    state_i.caps = record->scope == SecurityScope::Link ? record->carrier.capability_i : 0;
    std::array<std::uint8_t, kSessionStateBytes> state_i_bytes{};
    if (!session_state_encode(state_i, state_i_bytes).ok()) {
      return emit_failed(*record, StatusCode::InternalError);
    }
    edhoc_flight_.state_i_bytes = state_i_bytes;
    edhoc_flight_.state_i_set = true;
    const Status confirmed = build_confirm(*record, true);
    if (!confirmed) return emit_failed(*record, StatusCode::AuthenticationFailed);
    edhoc_flight_.phase = 3;
    std::array<std::uint8_t, kMaxMessageBytes> m3{};
    std::size_t m3_size = 0;
    const Status composed =
        edhoc_.compose_message_3(MutableByteView{m3.data(), m3.size()}, m3_size);
    if (!composed || m3_size == 0 || m3_size > big_tx_.size()) {
      return emit_failed(*record, StatusCode::ProtocolError);
    }
    std::memcpy(big_tx_.data(), m3.data(), m3_size);
    big_tx_size_ = m3_size;
    big_tx_owner_ = record->token;
    record->state = RecordState::EdhocWaitM4;
    record->retransmit_at = now + kEdhocRetransmitMs;
    record->retransmits = 0;
    const Status sent = emit_send(*record, 4, 3, ByteView{m3.data(), m3_size}, false);
    secure_clear(m3);
    return sent;
  }
  if (rx.step == 3) {
    if (record->role != HandshakeRole::Responder || !edhoc_flight_.active ||
        edhoc_flight_.owner_token != record->token) {
      return Status::success();
    }
    if (record->state == RecordState::EdhocM4Sent) {
      // Duplicate m3: resend the cached m4, never reinstall.
      ScopeDigest hash{};
      sha256(message, hash);
      const bool duplicate =
          edhoc_flight_.m3_seen &&
          std::memcmp(hash.data(), edhoc_flight_.m3_hash.data(), hash.size()) == 0;
      if (!duplicate || big_tx_size_ == 0) return Status::success();
      return emit_send(*record, 4, 4, ByteView{big_tx_.data(), big_tx_size_}, false);
    }
    if (record->state != RecordState::EdhocWaitM3) return Status::success();
    const Status processed = edhoc_.process_message_3(message);
    if (!processed || !edhoc_flight_.state_i_set || !edhoc_flight_.confirm_i_set ||
        !edhoc_flight_.peer_verified) {
      return emit_failed(*record, StatusCode::AuthenticationFailed);
    }
    Status checked = check_peer_state(*record, true);
    if (checked.ok()) checked = check_confirm(*record, true);
    if (!checked) return emit_failed(*record, StatusCode::AuthenticationFailed);
    const Status confirmed = build_confirm(*record, false);
    if (!confirmed) return emit_failed(*record, StatusCode::AuthenticationFailed);
    edhoc_flight_.phase = 4;
    std::array<std::uint8_t, kMaxMessageBytes> m4{};
    std::size_t m4_size = 0;
    const Status composed =
        edhoc_.compose_message_4(MutableByteView{m4.data(), m4.size()}, m4_size);
    if (!composed || m4_size == 0 || m4_size > big_tx_.size()) {
      return emit_failed(*record, StatusCode::ProtocolError);
    }
    // Commit BEFORE the m4 goes out: a refused install sends nothing.
    const Status committed = edhoc_commit(*record);
    if (!committed) return emit_failed(*record, map_commit_failure(committed));
    StagedEstablished responder_done{};
    responder_done.token = record->token;
    responder_done.scope = record->scope;
    responder_done.peer = record->peer;
    responder_done.role = record->role;
    responder_done.tx_context_id = pending_commit_tx_;
    responder_done.rx_context_id = pending_commit_rx_;
    responder_done.has_proof = pending_commit_proof_.valid();
    responder_done.proof = pending_commit_proof_;
    stage_established(responder_done);
    std::memcpy(big_tx_.data(), m4.data(), m4_size);
    big_tx_size_ = m4_size;
    big_tx_owner_ = record->token;
    sha256(message, edhoc_flight_.m3_hash);
    edhoc_flight_.m3_seen = true;
    record->state = RecordState::EdhocM4Sent;
    const Status sent = emit_send(*record, 4, 4, ByteView{m4.data(), m4_size}, false);
    secure_clear(m4);
    return sent;
  }
  if (rx.step == 4) {
    if (record->role != HandshakeRole::Initiator || record->state != RecordState::EdhocWaitM4 ||
        !edhoc_flight_.active || edhoc_flight_.owner_token != record->token) {
      return Status::success();
    }
    const Status processed = edhoc_.process_message_4(message);
    if (!processed || !edhoc_flight_.confirm_r_set) {
      return emit_failed(*record, StatusCode::AuthenticationFailed);
    }
    const Status checked = check_confirm(*record, false);
    if (!checked) return emit_failed(*record, StatusCode::AuthenticationFailed);
    const Status committed = edhoc_commit(*record);
    if (!committed) return emit_failed(*record, map_commit_failure(committed));
    // Staged: take_result delivers the Established after the caller drains.
    StagedEstablished established{};
    established.token = record->token;
    established.scope = record->scope;
    established.peer = record->peer;
    established.role = record->role;
    established.tx_context_id = pending_commit_tx_;
    established.rx_context_id = pending_commit_rx_;
    established.has_proof = pending_commit_proof_.valid();
    established.proof = pending_commit_proof_;
    drop_record(*record);
    stage_established(established);
    return Status::success();
  }
  return Status::success();
}

Status HandshakeEngine::on_resume_message(CarrierRecord* record, const HandshakeRx& rx,
                                          const ByteView message, const MonotonicMs now) noexcept {
  if (rx.step == 1) {
    if (record == nullptr && rx.claimed_peer == kInvalidNodeId) {
      for (auto& candidate : records_) {
        if (candidate.used && candidate.scope == rx.scope &&
            candidate.role == HandshakeRole::Responder && candidate.peer == kInvalidNodeId &&
            candidate.state == RecordState::ResumeWaitR3) {
          record = &candidate;
          break;
        }
      }
    }
    if (record != nullptr) {
      // Duplicate R1: resend the cached R2 without spending another use.
      // Link/end R1 has no ticket: exactly the 60-byte base form.
      std::uint8_t nonce[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      if (message.size != rlres1::kR1BaseSize || !record->r1_nonce_set ||
          record->last_tx_size == 0 || record->state != RecordState::ResumeWaitR3) {
        return Status::success();
      }
      std::memcpy(nonce, message.data + 12, sizeof(nonce));
      if (std::memcmp(nonce, record->r1_nonce.data(), sizeof(nonce)) != 0) {
        return Status::success();  // a new exchange while one runs: drop
      }
      return emit_send(*record, 5, 2,
                       ByteView{record->last_tx.data(), record->last_tx_size}, false);
    }
    if (!step1_may_proceed(rx.scope, rx.claimed_peer)) return Status::success();
    CarrierRecord* fresh = nullptr;
    const Status allocated = verify_cookie_and_allocate(rx, message, fresh, now);
    if (!allocated) return Status::success();  // cookie/table: drop
    rlres1::Carrier carrier{};
    if (rx.scope == SecurityScope::Link) {
      carrier.kind = rlres1::Carrier::Kind::Link;
      carrier.mac_i = rx.src_mac;
      carrier.mac_r = rx.dst_mac;
      keys::link_carrier_digest(rx.carrier, carrier.carrier_digest);
    } else {
      carrier.kind = rlres1::Carrier::Kind::Routed;
      carrier.hops = 0;
    }
    rlres1::Output out{};
    resume_lookup_ = ResumeBinding{};
    rlres1_.on_r1(message, carrier, rx.claimed_peer, now, *this, out);
    if (out.action == rlres1::Action::Send && out.message_size == rlres1::kR2Size) {
      if (!resume_lookup_.valid || out.message_size > fresh->last_tx.size() ||
          message.size != rlres1::kR1BaseSize) {
        drop_record(*fresh);
        secure_clear(out.message);
        return Status::success();
      }
      fresh->resume = resume_lookup_;
      std::memcpy(fresh->last_tx.data(), out.message.data(), out.message_size);
      fresh->last_tx_size = out.message_size;
      fresh->last_phase = 5;
      fresh->last_step = 2;
      std::memcpy(fresh->r1_nonce.data(), message.data + 12, fresh->r1_nonce.size());
      fresh->r1_nonce_set = true;
      fresh->state = RecordState::ResumeWaitR3;
      if (out.superseded_initiator) {
        // Simultaneous open resolved against us-as-initiator: our own
        // attempt yielded; its record dies silently (the responder path
        // proceeds and reports).
        CarrierRecord* ours = find_record(rx.scope, fresh->peer, HandshakeRole::Initiator);
        if (ours != nullptr && ours != fresh) drop_record(*ours);
      }
      const Status sent = emit_send(*fresh, 5, 2, ByteView{out.message.data(), out.message_size},
                                    false);
      secure_clear(out.message);
      return sent;
    }
    if (out.action == rlres1::Action::Send) {
      // An unauthenticated hint (Expired/UnknownId/Revoked): forward it,
      // keep no record — the initiator falls back to a full EDHOC.
      const Status sent = emit_send(*fresh, 5, 2, ByteView{out.message.data(), out.message_size},
                                    false);
      secure_clear(out.message);
      drop_record(*fresh);
      return sent;
    }
    drop_record(*fresh);
    secure_clear(out.message);
    return Status::success();
  }
  if (record == nullptr) return Status::success();
  if (rx.step == 2) {
    if (record->role != HandshakeRole::Initiator ||
        record->state != RecordState::ResumeWaitR2) {
      return Status::success();
    }
    rlres1::Output out{};
    rlres1_.on_r2(record->peer, to_keys_purpose(record->scope), message, now, out);
    if (out.action == rlres1::Action::SendAndInstall) {
      // Install BEFORE the R3 goes out: a refused install sends nothing.
      const Status committed = resume_commit(*record, out.established);
      if (!committed) {
        secure_clear(out.message);
        return emit_failed(*record, map_commit_failure(committed));
      }
      if (out.message_size == 0 || out.message_size > record->last_tx.size()) {
        secure_clear(out.message);
        return emit_failed(*record, StatusCode::ProtocolError);
      }
      std::memcpy(record->last_tx.data(), out.message.data(), out.message_size);
      record->last_tx_size = out.message_size;
      record->last_phase = 5;
      record->last_step = 3;
      record->state = RecordState::ResumeR3Confirm;
      record->retransmit_at = now + kResumeRetransmitMs;
      record->retransmits = 0;
      StagedEstablished established{};
      established.token = record->token;
      established.scope = record->scope;
      established.peer = record->peer;
      established.role = record->role;
      established.tx_context_id = pending_commit_tx_;
      established.rx_context_id = pending_commit_rx_;
      established.has_proof = pending_commit_proof_.valid();
      established.proof = pending_commit_proof_;
      stage_established(established);
      const Status sent =
          emit_send(*record, 5, 3, ByteView{out.message.data(), out.message_size}, false);
      secure_clear(out.message);
      return sent;
    }
    if (out.action == rlres1::Action::Fallback) {
      secure_clear(out.message);
      // A hint (or a late R2): the RMS did not resume — run the full
      // EDHOC on the same record. The RLP slot stays valid (06 §4.3).
      rlres1_.abort(rlres1::Role::Initiator, record->peer, to_keys_purpose(record->scope));
      record->state = RecordState::EdhocQueued;
      record->retransmit_at = now;
      if (!edhoc_flight_.active && ecc_budget_ok(now)) return begin_edhoc(*record, now);
      return Status::success();
    }
    secure_clear(out.message);
    if (out.reject == rlres1::Reject::NoSession || out.reject == rlres1::Reject::Timeout) {
      return emit_failed(*record, StatusCode::Expired);
    }
    return emit_failed(*record, StatusCode::AuthenticationFailed);
  }
  if (rx.step == 3) {
    // Responder: R3 installs or the exchange dies silently (the initiator
    // already reported; a Failed here would carry an unknown token).
    if (record->role != HandshakeRole::Responder ||
        record->state != RecordState::ResumeWaitR3) {
      return Status::success();
    }
    rlres1::Output out{};
    rlres1_.on_r3(record->peer, to_keys_purpose(record->scope), message, now, out);
    if (out.action != rlres1::Action::Install) {
      secure_clear(out.message);
      drop_record(*record);
      return Status::success();
    }
    const Status committed = resume_commit(*record, out.established);
    secure_clear(out.message);
    if (!committed) {
      drop_record(*record);
      return Status::success();
    }
    StagedEstablished established{};
    established.token = record->token;
    established.scope = record->scope;
    established.peer = record->peer;
    established.role = record->role;
    established.tx_context_id = pending_commit_tx_;
    established.rx_context_id = pending_commit_rx_;
    established.has_proof = pending_commit_proof_.valid();
    established.proof = pending_commit_proof_;
    drop_record(*record);
    stage_established(established);
    return Status::success();
  }
  return Status::success();
}

// --- Peer checks, confirms, commits ---

Status HandshakeEngine::check_peer_state(CarrierRecord& record,
                                         const bool peer_is_initiator) noexcept {
  EdhocFlight& flight = edhoc_flight_;
  if (!flight.peer_verified) {
    return Status::error(StatusCode::AuthenticationFailed, "session peer unverified");
  }
  const std::array<std::uint8_t, kSessionStateBytes>& staged =
      peer_is_initiator ? flight.state_i_bytes : flight.state_r_bytes;
  SessionState state{};
  const Status decoded =
      session_state_decode(ByteView{staged.data(), staged.size()}, state);
  if (!decoded) return decoded;
  // State and Credential arrived (and were staged) in the SAME
  // authenticated message — that pairing, not a back-reference, binds
  // them. The checks below are the §5.3 m2/m3 rows.
  const std::uint8_t want_purpose =
      record.scope == SecurityScope::EndToEnd ? kSessionPurposeEnd : kSessionPurposeLink;
  if (state.purpose != want_purpose) {
    return Status::error(StatusCode::AuthenticationFailed, "session purpose");
  }
  if (flight.peer_claims.node != record.peer) {
    return Status::error(StatusCode::AuthenticationFailed, "session peer node");
  }
  // The disclosed site must be the adopted one AND the credential's —
  // a state for another site is refused even with a valid signature.
  if (state.site_epoch != local_.site_epoch ||
      state.site_epoch != flight.peer_claims.site_epoch) {
    return Status::error(StatusCode::AuthenticationFailed, "session peer site");
  }
  if (!epochs_compatible(local_, state.site_epoch, state.gk_epoch)) {
    return Status::error(StatusCode::AuthenticationFailed, "session peer epochs");
  }
  if (record.scope == SecurityScope::Link) {
    // Capability agreement with the frozen RLD1 exchange (P4 §5.3):
    // the P4-reserved bits repeat the carrier word, the EDHOC floor
    // holds, and no DevRam bit sneaks in on either side.
    const std::uint32_t carrier_caps =
        peer_is_initiator ? record.carrier.capability_i : record.carrier.capability_r;
    if (!caps_p4_agree(carrier_caps, state.caps) || !caps_production(carrier_caps, state.caps) ||
        (state.caps & kRld1CapMemberEdhocV1) == 0) {
      return Status::error(StatusCode::AuthenticationFailed, "session caps carrier");
    }
    if (peer_is_initiator) {
      // The initiator's m3 State repeats its m1 Intent word for word
      // (P4 §5.3): boot and caps are immutable within the exchange.
      SessionIntent intent{};
      const Status intent_ok = session_intent_decode(
          ByteView{flight.intent_bytes.data(), flight.intent_bytes.size()}, intent);
      if (!intent_ok.ok() || state.boot != intent.boot_i || state.caps != intent.caps_i) {
        return Status::error(StatusCode::AuthenticationFailed, "session intent echo");
      }
    }
  }
  flight.peer_gk_epoch = state.gk_epoch;
  return Status::success();
}

Status HandshakeEngine::build_contexts(
    CarrierRecord& record, ScopeDigest& capability,
    std::array<std::uint8_t, kExporterContextMax>& dir1, std::size_t& dir1_size,
    std::array<std::uint8_t, kExporterContextMax>& dir2, std::size_t& dir2_size,
    std::array<std::uint8_t, kExporterContextMax>& rms, std::size_t& rms_size) noexcept {
  const EdhocFlight& flight = edhoc_flight_;
  capability.fill(0);
  dir1_size = dir2_size = rms_size = 0;
  if (!flight.intent_set || !flight.state_r_set || !flight.state_i_set || !flight.peer_verified) {
    return Status::error(StatusCode::InvalidState, "session contexts incomplete");
  }
  if (flight.cid_own == 0 || flight.cid_peer == 0) {
    return Status::error(StatusCode::InvalidState, "session contexts cids");
  }
  Status status = keys::session_capability_digest(
      ByteView{flight.intent_bytes.data(), flight.intent_bytes.size()},
      ByteView{flight.state_r_bytes.data(), flight.state_r_bytes.size()},
      ByteView{flight.state_i_bytes.data(), flight.state_i_bytes.size()}, capability);
  if (!status) return status;
  const bool we_are_initiator = record.role == HandshakeRole::Initiator;
  const NodeId node_i = we_are_initiator ? local_.self : record.peer;
  const NodeId node_r = we_are_initiator ? record.peer : local_.self;
  // kid_I/R are the EDHOC kids (P4 §5.1: cnf hashes): ours derived
  // at begin, theirs verified against the presented ID_CRED kid.
  const ScopeDigest kid_i = we_are_initiator ? flight.kid_local : flight.kid_peer;
  const ScopeDigest kid_r = we_are_initiator ? flight.kid_peer : flight.kid_local;
  ExporterContextParams params{};
  params.purpose = record.scope == SecurityScope::EndToEnd ? 2 : 1;
  params.network = local_.network;
  params.node_i = node_i;
  params.node_r = node_r;
  params.kid_i = kid_i;
  params.kid_r = kid_r;
  params.role_i = we_are_initiator ? local_.role : flight.peer_claims.role;
  params.role_r = we_are_initiator ? flight.peer_claims.role : local_.role;
  params.generation_i = we_are_initiator ? local_.generation : flight.peer_claims.generation;
  params.generation_r = we_are_initiator ? flight.peer_claims.generation : local_.generation;
  params.capability_digest = capability;
  // Direction 1 (I->R) binds the receiver's C_R; direction 2 the C_I.
  const std::uint32_t cid_i = we_are_initiator ? flight.cid_own : flight.cid_peer;
  const std::uint32_t cid_r = we_are_initiator ? flight.cid_peer : flight.cid_own;
  params.context_epoch = cid_r;
  params.direction = 1;
  status = exporter_context_encode(params, dir1, dir1_size);
  if (!status) return status;
  params.context_epoch = cid_i;
  params.direction = 2;
  status = exporter_context_encode(params, dir2, dir2_size);
  if (!status) return status;
  params.context_epoch = 0;
  params.direction = 0;
  status = exporter_context_encode(params, rms, rms_size);
  return status;
}

Status HandshakeEngine::build_confirm(CarrierRecord& record, const bool ours_is_initiator) noexcept {
  ScopeDigest capability{};
  std::array<std::uint8_t, kExporterContextMax> dir1{}, dir2{}, rms{};
  std::size_t dir1_size = 0, dir2_size = 0, rms_size = 0;
  Status status = build_contexts(record, capability, dir1, dir1_size, dir2, dir2_size, rms,
                                 rms_size);
  if (!status) return status;
  ScopeDigest digest{};
  status = keys::session_contexts_digest(ByteView{dir1.data(), dir1_size}, ByteView{dir2.data(), dir2_size},
                                   ByteView{rms.data(), rms_size}, digest);
  if (!status) return status;
  ContextConfirm confirm{};
  confirm.purpose =
      record.scope == SecurityScope::EndToEnd ? kSessionPurposeEnd : kSessionPurposeLink;
  confirm.profile = kSessionProfileMember;
  confirm.contexts_digest = digest;
  std::array<std::uint8_t, kContextConfirmBytes> encoded{};
  status = context_confirm_encode(confirm, encoded);
  if (!status) return status;
  if (ours_is_initiator) {
    edhoc_flight_.confirm_i_bytes = encoded;
    edhoc_flight_.confirm_i_set = true;
  } else {
    edhoc_flight_.confirm_r_bytes = encoded;
    edhoc_flight_.confirm_r_set = true;
  }
  return Status::success();
}

Status HandshakeEngine::check_confirm(CarrierRecord& record,
                                      const bool theirs_is_initiator) noexcept {
  ScopeDigest capability{};
  std::array<std::uint8_t, kExporterContextMax> dir1{}, dir2{}, rms{};
  std::size_t dir1_size = 0, dir2_size = 0, rms_size = 0;
  Status status = build_contexts(record, capability, dir1, dir1_size, dir2, dir2_size, rms,
                                 rms_size);
  if (!status) return status;
  ScopeDigest digest{};
  status = keys::session_contexts_digest(ByteView{dir1.data(), dir1_size}, ByteView{dir2.data(), dir2_size},
                                   ByteView{rms.data(), rms_size}, digest);
  if (!status) return status;
  const std::array<std::uint8_t, kContextConfirmBytes>& staged =
      theirs_is_initiator ? edhoc_flight_.confirm_i_bytes : edhoc_flight_.confirm_r_bytes;
  ContextConfirm confirm{};
  status = context_confirm_decode(ByteView{staged.data(), staged.size()}, confirm);
  if (!status) return status;
  const std::uint8_t want_purpose =
      record.scope == SecurityScope::EndToEnd ? kSessionPurposeEnd : kSessionPurposeLink;
  if (confirm.purpose != want_purpose) {
    return Status::error(StatusCode::AuthenticationFailed, "session confirm purpose");
  }
  // The digest already binds nodes, kids, roles and generations: an
  // exact match is the whole check (P4 §5.4).
  if (confirm.contexts_digest != digest) {
    return Status::error(StatusCode::AuthenticationFailed, "session contexts differ");
  }
  return Status::success();
}

StatusCode HandshakeEngine::map_commit_failure(const Status& status) noexcept {
  if (status.code == StatusCode::Busy) return StatusCode::Busy;
  if (status.code == StatusCode::NoCapacity) return StatusCode::NoCapacity;
  if (status.code == StatusCode::Conflict) return StatusCode::Conflict;
  return StatusCode::AuthenticationFailed;
}

Status HandshakeEngine::pre_install_checks(const NodeId peer, const std::uint32_t peer_generation,
                                           const std::uint32_t peer_role,
                                           const NetworkId network) noexcept {
  const Status local = refresh_local();
  if (!local) return local;
  if (network != local_.network || peer_role == 0 || peer_generation == 0) {
    return Status::error(StatusCode::AuthenticationFailed, "session commit identity");
  }
  // The CURRENT revocation view decides — a peer revoked after the first
  // message still never installs (P4 §5.5). The same call covers us.
  if (membership_.revoked(peer, peer_generation)) {
    return Status::error(StatusCode::AuthenticationFailed, "session peer revoked");
  }
  if (membership_.revoked(local_.self, local_.generation)) {
    return Status::error(StatusCode::AuthenticationFailed, "session self revoked");
  }
  return Status::success();
}

Status HandshakeEngine::save_resume_slot(const SecurityScope scope, const NodeId peer,
                                         const std::uint32_t peer_generation,
                                         const std::uint32_t peer_role,
                                         const std::array<std::uint8_t, 8>& peer_cert_id,
                                         const std::uint32_t created_gk_epoch,
                                         const std::array<std::uint8_t, 32>& rms) noexcept {
  ResumeSlot2 slot{};
  slot.valid = true;
  slot.purpose = to_resume_purpose(scope);
  slot.peer = peer;
  slot.network = local_.network;
  slot.peer_cert_id = peer_cert_id;
  slot.local_cert_id = local_.local_cert_id;
  slot.peer_generation = peer_generation;
  slot.peer_role = peer_role;
  slot.created_gk_epoch = created_gk_epoch;
  slot.last_used_boot = local_.boot;
  slot.reserved_uses = 0;  // a fresh RMS restarts the count
  slot.rms = rms;
  ResumeContext context{};
  context.network = local_.network;
  context.gk_epoch = local_.gk_epoch;
  context.revocations = nullptr;
  return cache_.put(slot, context);
}

Status HandshakeEngine::mint_proof(CarrierRecord& record, AuthenticatedPeerProof& proof) noexcept {
  proof = AuthenticatedPeerProof{};
  if (record.scope != SecurityScope::Link) return Status::success();  // end: no discovery proof
  const MacAddress& peer_mac = record.role == HandshakeRole::Initiator ? record.mac_r : record.mac_i;
  std::array<std::uint8_t, 96> input{};
  std::size_t at = 0;
  const auto put = [&](const void* data, const std::size_t size) {
    if (at + size > input.size()) return;
    std::memcpy(input.data() + at, data, size);
    at += size;
  };
  put(kProofLabel, sizeof(kProofLabel));
  std::uint8_t token_be[4];
  put_u32_be(token_be, record.token);
  put(token_be, 4);
  put_u32_be(token_be, record.elevation_token);
  put(token_be, 4);
  const std::uint8_t scope_byte = static_cast<std::uint8_t>(record.scope);
  put(&scope_byte, 1);
  std::uint8_t be[8];
  for (std::size_t i = 0; i < 8; ++i) be[i] = static_cast<std::uint8_t>(record.peer >> (56U - 8U * i));
  put(be, 8);
  put(peer_mac.data(), peer_mac.size());
  for (std::size_t i = 0; i < 8; ++i) {
    be[i] = static_cast<std::uint8_t>(local_.network >> (56U - 8U * i));
  }
  put(be, 8);
  ScopeDigest carrier_digest{};
  keys::link_carrier_digest(record.carrier, carrier_digest);
  put(carrier_digest.data(), carrier_digest.size());
  ScopeDigest digest{};
  sha256(ByteView{input.data(), at}, digest);
  AuthTag evidence{};
  std::memcpy(evidence.data(), digest.data(), evidence.size());
  proof = AuthenticatedPeerProof(record.peer, peer_mac, local_.network, evidence,
                                record.elevation_token, carrier_digest);
  return Status::success();
}

Status HandshakeEngine::edhoc_commit(CarrierRecord& record) noexcept {
  pending_commit_tx_ = 0;
  pending_commit_rx_ = 0;
  pending_commit_proof_ = AuthenticatedPeerProof{};
  const EdhocFlight& flight = edhoc_flight_;
  if (!flight.active || flight.owner_token != record.token || !flight.peer_verified) {
    return Status::error(StatusCode::InvalidState, "session commit no flight");
  }
  ScopeDigest capability{};
  std::array<std::uint8_t, kExporterContextMax> dir1{}, dir2{}, rms_ctx{};
  std::size_t dir1_size = 0, dir2_size = 0, rms_size = 0;
  Status status = build_contexts(record, capability, dir1, dir1_size, dir2, dir2_size, rms_ctx,
                                 rms_size);
  if (!status) return status;
  const Status checked =
      pre_install_checks(record.peer, flight.peer_claims.generation, flight.peer_claims.role,
                         local_.network);
  if (!checked) return checked;
  const bool we_are_initiator = record.role == HandshakeRole::Initiator;
  std::array<std::uint8_t, 16> key1{}, key2{};
  std::array<std::uint8_t, 12> iv1{}, iv2{};
  std::array<std::uint8_t, 32> rms{};
  status = edhoc_.exporter(kExporterLabelKey, ByteView{dir1.data(), dir1_size},
                           MutableByteView{key1.data(), key1.size()});
  if (status)
    status = edhoc_.exporter(kExporterLabelIv, ByteView{dir1.data(), dir1_size},
                             MutableByteView{iv1.data(), iv1.size()});
  if (status)
    status = edhoc_.exporter(kExporterLabelKey, ByteView{dir2.data(), dir2_size},
                             MutableByteView{key2.data(), key2.size()});
  if (status)
    status = edhoc_.exporter(kExporterLabelIv, ByteView{dir2.data(), dir2_size},
                             MutableByteView{iv2.data(), iv2.size()});
  if (status)
    status = edhoc_.exporter(kExporterLabelRms, ByteView{rms_ctx.data(), rms_size},
                             MutableByteView{rms.data(), rms.size()});
  if (!status) {
    secure_clear(key1);
    secure_clear(key2);
    secure_clear(iv1);
    secure_clear(iv2);
    secure_clear(rms);
    return status;
  }
  // Direction 1 is I->R: the initiator transmits with it, the responder
  // receives with it. Context ids are the EDHOC CIDs (transcript-bound,
  // receiver-chosen): our RX id is our own C_x.
  ContextKeys keys{};
  keys.scope = record.scope;
  keys.network = local_.network;
  keys.peer = record.peer;
  keys.tx_context_id = flight.cid_peer;
  keys.rx_context_id = flight.cid_own;
  keys.tx_key = we_are_initiator ? key1 : key2;
  keys.rx_key = we_are_initiator ? key2 : key1;
  keys.tx_iv = we_are_initiator ? iv1 : iv2;
  keys.rx_iv = we_are_initiator ? iv2 : iv1;
  keys.peer_cert_id = flight.peer_claims.cert_id;
  keys.peer_generation = flight.peer_claims.generation;
  // The new RMS/context birthday is the SMALLER of both ends' GK
  // epochs (P4 §5.3): the peer's State carried its epoch, verified
  // above. A context both ends cannot agree to keep dies here.
  const std::uint32_t created_gk = flight.peer_gk_epoch < local_.gk_epoch
                                       ? flight.peer_gk_epoch
                                       : local_.gk_epoch;
  InstallAttestation att{};
  att.peer_role = flight.peer_claims.role;
  att.created_gk_epoch = created_gk;
  status = sink_.install_verified(keys, att);
  secure_clear(key1);
  secure_clear(key2);
  secure_clear(iv1);
  secure_clear(iv2);
  if (!status) {
    secure_clear(rms);
    return status;
  }
  // The RLP save is best-effort: the session is installed and usable, and
  // a cache failure only costs the next full EDHOC (never a silent key).
  static_cast<void>(save_resume_slot(record.scope, record.peer, flight.peer_claims.generation,
                                     flight.peer_claims.role, flight.peer_claims.cert_id,
                                     created_gk, rms));
  secure_clear(rms);
  AuthenticatedPeerProof proof{};
  status = mint_proof(record, proof);
  if (!status) return status;
  pending_commit_tx_ = keys.tx_context_id;
  pending_commit_rx_ = keys.rx_context_id;
  pending_commit_proof_ = proof;
  return Status::success();
}

Status HandshakeEngine::resume_commit(CarrierRecord& record,
                                      const rlres1::Established& established) noexcept {
  pending_commit_tx_ = 0;
  pending_commit_rx_ = 0;
  pending_commit_proof_ = AuthenticatedPeerProof{};
  ResumeSlot2 slot{};
  bool intact = false;
  if (!record.resume.valid ||
      !cache_.read_at(record.resume.slot_index, slot, intact).ok() || !intact || !slot.valid ||
      slot.purpose != to_resume_purpose(record.scope) || slot.peer != record.peer ||
      slot.peer != established.peer) {
    return Status::error(StatusCode::AuthenticationFailed, "session resume slot gone");
  }
  ScopeDigest identity{};
  if (!resume_slot_identity(slot, identity) || identity != record.resume.identity) {
    return Status::error(StatusCode::AuthenticationFailed, "session resume slot changed");
  }
  if (slot.local_cert_id != local_.local_cert_id) {
    return Status::error(StatusCode::AuthenticationFailed, "session resume credential");
  }
  // GK lifetime, re-checked at install (P4 §5.5): the slot that was valid
  // at R1 may have aged out while the messages flew.
  const std::uint64_t created = slot.created_gk_epoch;
  const std::uint64_t current = local_.gk_epoch;
  if (current < created || current >= created + 2U) {
    return Status::error(StatusCode::AuthenticationFailed, "session resume lifetime");
  }
  const Status checked =
      pre_install_checks(slot.peer, slot.peer_generation, slot.peer_role, slot.network);
  if (!checked) return checked;
  ContextKeys keys{};
  keys.scope = record.scope;
  keys.network = local_.network;
  keys.peer = established.peer;
  keys.tx_context_id = established.tx_context_id;
  keys.rx_context_id = established.rx_context_id;
  keys.tx_key = established.tx.key;
  keys.rx_key = established.rx.key;
  keys.tx_iv = established.tx.iv;
  keys.rx_iv = established.rx.iv;
  keys.peer_cert_id = slot.peer_cert_id;
  keys.peer_generation = slot.peer_generation;
  InstallAttestation att{};
  att.peer_role = slot.peer_role;
  att.created_gk_epoch = slot.created_gk_epoch;
  const Status installed = sink_.install_verified(keys, att);
  if (!installed) return installed;
  AuthenticatedPeerProof proof{};
  const Status minted = mint_proof(record, proof);
  if (!minted) return minted;
  pending_commit_tx_ = keys.tx_context_id;
  pending_commit_rx_ = keys.rx_context_id;
  pending_commit_proof_ = proof;
  return Status::success();
}

// --- Time, results, cancellation ---

Status HandshakeEngine::poll(const MonotonicMs now) noexcept {
  if (entered_) return Status::error(StatusCode::Busy, "handshake re-entered");
  const EnterGuard guard(entered_);
  if (!configured_) return Status::error(StatusCode::InvalidState, "handshake not configured");
  if (has_pending_) return Status::error(StatusCode::Busy, "handshake result pending");
  if (now < last_tick_) return Status::error(StatusCode::InvalidArgument, "handshake time moved");
  last_tick_ = now;
  const Status local = refresh_local();
  if (!local) {
    cancel_all_internal();
    return local;
  }
  // One emission per poll, in fixed priority: rlres1 expiry, record
  // deadline, retransmit, queued EDHOC start. The rest waits for the next
  // poll (the Owner polls every tick).
  rlres1::ExpiredSession expired{};
  if (rlres1_.next_expired(now, expired)) {
    CarrierRecord* record = nullptr;
    for (auto& candidate : records_) {
      if (!candidate.used) continue;
      const bool initiator = expired.role == rlres1::Role::Initiator;
      if ((candidate.role == HandshakeRole::Initiator) != initiator) continue;
      if (candidate.peer != expired.peer || to_keys_purpose(candidate.scope) != expired.purpose) {
        continue;
      }
      record = &candidate;
      break;
    }
    if (record == nullptr) return Status::success();  // already gone
    if (record->role == HandshakeRole::Initiator &&
        record->state == RecordState::ResumeWaitR2) {
      // Unanswered R1: the RMS did not resume — run the full EDHOC.
      record->state = RecordState::EdhocQueued;
      record->retransmit_at = now;
      if (!edhoc_flight_.active && ecc_budget_ok(now)) return begin_edhoc(*record, now);
      return Status::success();
    }
    drop_record(*record);  // responder-side expiry is silent
    return Status::success();
  }
  for (auto& record : records_) {
    if (!record.used || now < record.deadline) continue;
    if (record.state == RecordState::EdhocM4Sent ||
        record.state == RecordState::ResumeR3Confirm) {
      drop_record(record);  // post-Established quiet done
      return Status::success();
    }
    if (record.state == RecordState::EdhocM1Parked) {
      drop_record(record);  // never started: silent like responder R1 expiry
      return Status::success();
    }
    return emit_failed(record, StatusCode::Expired);
  }
  for (auto& record : records_) {
    if (!record.used || now < record.retransmit_at) continue;
    const bool small_tx = record.last_tx_size != 0;
    const bool big_tx = record.state == RecordState::EdhocWaitM4 && edhoc_flight_.active &&
                        edhoc_flight_.owner_token == record.token && big_tx_size_ != 0 &&
                        big_tx_owner_ == record.token;
    if (!small_tx && !big_tx) continue;
    if (record.retransmits >= kMaxRetransmits) {
      if (record.state == RecordState::ResumeWaitR2) {
        // R1 exhausted: stop hammering, let the rlres1 deadline drive
        // the EDHOC fallback.
        record.retransmit_at = record.deadline;
        continue;
      }
      if (record.state == RecordState::ResumeR3Confirm) {
        drop_record(record);
        return Status::success();
      }
      return emit_failed(record, StatusCode::Expired);
    }
    ++record.retransmits;
    record.retransmit_at =
        now + (record.last_phase == 5 ? kResumeRetransmitMs : kEdhocRetransmitMs);
    const ByteView bytes = small_tx ? ByteView{record.last_tx.data(), record.last_tx_size}
                                    : ByteView{big_tx_.data(), big_tx_size_};
    const std::uint8_t phase = small_tx ? record.last_phase : 4;
    const std::uint8_t step = small_tx ? record.last_step : 3;
    const bool cookie = step == 1 && record.scope == SecurityScope::Link;
    return emit_send(record, phase, step, bytes, cookie);
  }
  for (auto& record : records_) {
    if (!record.used ||
        (record.state != RecordState::EdhocQueued &&
         record.state != RecordState::EdhocM1Parked) ||
        now < record.retransmit_at || now >= record.deadline) {
      continue;
    }
    if (edhoc_flight_.active || !ecc_budget_ok(now)) return Status::success();  // wait
    if (record.state == RecordState::EdhocQueued) {
      const Status begun = begin_edhoc(record, now);
      if (!begun) return emit_failed(record, map_commit_failure(begun));
      return Status::success();
    }
    // Parked m1: only the stash owner may start it — a clobbered
    // stash drops silently and the initiator's retransmit re-parks.
    if (big_tx_owner_ != record.token || big_tx_size_ == 0) {
      drop_record(record);
      return Status::success();
    }
    // process_message_1 consumes the stash before compose_message_2
    // overwrites it, so no copy is needed.
    return responder_begin_m1(record, ByteView{big_tx_.data(), big_tx_size_}, now);
  }
  return Status::success();
}

Status HandshakeEngine::take_result(HandshakeResult& out) noexcept {
  if (entered_) return Status::error(StatusCode::Busy, "handshake re-entered");
  const EnterGuard guard(entered_);
  out = HandshakeResult{};
  if (!configured_) return Status::error(StatusCode::InvalidState, "handshake not configured");
  const Status local = refresh_local();
  if (!local) return local;
  if (has_pending_) {
    out = pending_;
    pending_ = HandshakeResult{};
    has_pending_ = false;
    if (staged_.pending) {
      // The Established staged behind a Send promotes now.
      pending_ = HandshakeResult{};
      pending_.event = HandshakeEvent::Established;
      pending_.token = staged_.token;
      pending_.scope = staged_.scope;
      pending_.peer = staged_.peer;
      pending_.role = staged_.role;
      pending_.has_proof = staged_.has_proof;
      pending_.proof = staged_.proof;
      pending_.tx_context_id = staged_.tx_context_id;
      pending_.rx_context_id = staged_.rx_context_id;
      has_pending_ = true;
      staged_ = StagedEstablished{};
    }
    return Status::success();
  }
  if (staged_.pending) {
    out.event = HandshakeEvent::Established;
    out.token = staged_.token;
    out.scope = staged_.scope;
    out.peer = staged_.peer;
    out.role = staged_.role;
    out.has_proof = staged_.has_proof;
    out.proof = staged_.proof;
    out.tx_context_id = staged_.tx_context_id;
    out.rx_context_id = staged_.rx_context_id;
    staged_ = StagedEstablished{};
    return Status::success();
  }
  return Status::error(StatusCode::NotFound, "handshake no result");
}

Status HandshakeEngine::cancel(const NodeId peer, const HandshakeCancelReason reason) noexcept {
  (void)reason;
  if (entered_) return Status::error(StatusCode::Busy, "handshake re-entered");
  const EnterGuard guard(entered_);
  for (auto& record : records_) {
    if (record.used && record.peer == peer) drop_record(record);
  }
  rlres1_.abort_peer(peer);
  if (has_pending_ && pending_.peer == peer) {
    pending_ = HandshakeResult{};
    has_pending_ = false;
    if (staged_.pending) {
      // The exchange died with its Send: promote the survivor, if any.
      HandshakeResult survivor{};
      survivor.event = HandshakeEvent::Established;
      survivor.token = staged_.token;
      survivor.scope = staged_.scope;
      survivor.peer = staged_.peer;
      survivor.role = staged_.role;
      survivor.has_proof = staged_.has_proof;
      survivor.proof = staged_.proof;
      survivor.tx_context_id = staged_.tx_context_id;
      survivor.rx_context_id = staged_.rx_context_id;
      pending_ = survivor;
      has_pending_ = true;
      staged_ = StagedEstablished{};
    }
  }
  if (staged_.pending && staged_.peer == peer) staged_ = StagedEstablished{};
  return Status::success();
}

Status HandshakeEngine::cancel_all() noexcept {
  if (entered_) return Status::error(StatusCode::Busy, "handshake re-entered");
  const EnterGuard guard(entered_);
  cancel_all_internal();
  pending_ = HandshakeResult{};
  has_pending_ = false;
  staged_ = StagedEstablished{};
  pending_commit_tx_ = 0;
  pending_commit_rx_ = 0;
  pending_commit_proof_ = AuthenticatedPeerProof{};
  return Status::success();
}

// --- StoreCredentialVerifier -------------------------------------------------------------------
// Fail-closed on every issue: the engine treats false as "unverifiable"
// and refuses the exchange (never a silent downgrade to an unverified
// peer). The cnf-kid match stays the engine's own check (P4 §5.1) — the
// verifier never sees the kid.

bool StoreCredentialVerifier::local_credential(LocalCredential& out) noexcept {
  out = LocalCredential{};
  if (!identity_.has_identity() || !site_.has_site()) return false;
  const IdentityRecord& identity = identity_.identity();
  const SiteRecord& site = site_.site();
  // Handles name a key the device cannot export; PR4 has no DS/SE signer,
  // so only NVS-plaintext material can drive EDHOC here.
  if (identity.key_location != CredentialKeyLocation::NvsPlaintext) return false;
  if (!p256_scalar_valid(
          ByteView{identity.key_material.data(), identity.key_material.size()})) {
    return false;
  }
  if (site.member_cert.size == 0 || site.member_cert.size > out.cred.size()) return false;
  std::memcpy(out.cred.data(), site.member_cert.bytes.data(), site.member_cert.size);
  out.cred_size = site.member_cert.size;
  out.privkey = identity.key_material;
  return true;
}

bool StoreCredentialVerifier::verify_peer(const ByteView cert, const NodeId expected_node,
                                          PeerCertClaims& out) noexcept {
  out = PeerCertClaims{};
  if (cert.data == nullptr || cert.size == 0 || !id_usable(expected_node)) return false;
  if (!site_.has_site()) return false;
  const SiteRecord& site = site_.site();
  CertClaims claims{};
  if (!cert_decode(cert, claims).ok()) return false;
  // Binding first (cheap, no crypto): a well-formed MemberCert of another
  // node, site or network is reported unverified, never an error.
  if (claims.type != CertType::Member || claims.subject != expected_node ||
      claims.issuer != site.site_id || claims.network != site.network ||
      claims.site_epoch != static_cast<std::uint32_t>(site.network >> 32)) {
    return false;
  }
  // SAK signature over the peer cert: the SAK is the adopted SiteCert's
  // cnf key, so only the site's assignment key mints acceptable peers.
  CertClaims site_claims{};
  if (!cert_decode(site.site_cert.view(), site_claims).ok()) return false;
  if (site_claims.type != CertType::Site) return false;
  CertClaims unused{};
  bool verified = false;
  if (!cert_verify(cert, site_claims.pubkey, unused, verified, verifier_).ok() || !verified) {
    return false;
  }
  out.node = claims.subject;
  out.generation = claims.assignment_generation;
  out.role = claims.role;
  out.site_epoch = claims.site_epoch;
  return true;
}

}  // namespace routeloom::sdkv1
