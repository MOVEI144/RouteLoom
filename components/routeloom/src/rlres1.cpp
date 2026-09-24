#include "routeloom/rlres1.hpp"

#include <cstring>

#include "routeloom/secure_clear.hpp"

namespace routeloom::rlres1 {
namespace {

using keys::Direction;

constexpr std::size_t kR1MacOffset = 44;     // fields before the optional ticket
constexpr std::size_t kR2BodySize = 36;      // R2 bytes covered by mac_R
constexpr std::uint32_t kGkLifetime = 2;     // RMS valid while gk < created + 2

std::uint32_t get_u32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

void put_u32(std::uint8_t* p, const std::uint32_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v >> 24);
  p[1] = static_cast<std::uint8_t>(v >> 16);
  p[2] = static_cast<std::uint8_t>(v >> 8);
  p[3] = static_cast<std::uint8_t>(v);
}

void get_epochs(const std::uint8_t* p, Epochs& out) noexcept {
  out.site_epoch = get_u32(p);
  out.rs_epoch = get_u32(p + 4);
  out.gk_epoch = get_u32(p + 8);
}

void put_epochs(std::uint8_t* p, const Epochs& e) noexcept {
  put_u32(p, e.site_epoch);
  put_u32(p + 4, e.rs_epoch);
  put_u32(p + 8, e.gk_epoch);
}

bool pairwise(const Purpose purpose) noexcept {
  return purpose == Purpose::Link || purpose == Purpose::End;
}

bool mac_equal(const Mac& a, const Mac& b) noexcept {
  return constant_time_equal(ByteView{a.data(), a.size()}, ByteView{b.data(), b.size()});
}

// ScopeDigest and Secret are the same 32-byte array type.
ByteView view(const ScopeDigest& d) noexcept { return ByteView{d.data(), d.size()}; }

void compute_binding(const Carrier& carrier, const Purpose purpose, const NodeId node_i,
                     const NodeId node_r, ScopeDigest& out) noexcept {
  if (purpose == Purpose::Link) {
    keys::resume_binding_link(carrier.mac_i, carrier.mac_r, carrier.carrier_digest, out);
  } else {
    keys::resume_binding_routed(purpose, node_i, node_r, out);
  }
}

// Transcript -> (expected mac_I3, I->R key, R->I key). Everything but the
// outputs is zeroized before return.
Status derive_session(const Secret& secret, const ResumeNonce& nonce_i,
                      const ResumeNonce& nonce_r, const ByteView r1, const ByteView r2,
                      const keys::ResumeKeyContext& context, Mac& mac_i3, TrafficKey& i_to_r,
                      TrafficKey& r_to_i) noexcept {
  ScopeDigest th{};
  {
    Sha256 hash;
    hash.update(r1);
    hash.update(r2);
    hash.finish(th);
  }
  ScopeDigest prk{};
  keys::resume_prk(nonce_i, nonce_r, secret, prk);
  Secret k_conf{};
  Status status = keys::resume_confirm_key(prk, th, k_conf);
  if (status) {
    status = keys::resume_mac(view(k_conf), keys::kLabelResumeR3, view(th), ByteView{},
                              ByteView{}, mac_i3);
  }
  if (status) {
    status = keys::resume_traffic_key(prk, context, Direction::InitiatorToResponder, th, i_to_r);
  }
  if (status) {
    status = keys::resume_traffic_key(prk, context, Direction::ResponderToInitiator, th, r_to_i);
  }
  secure_clear(k_conf);
  secure_clear(prk);
  if (!status) {
    keys::clear(i_to_r);
    keys::clear(r_to_i);
    secure_clear(mac_i3);
  }
  return status;
}

}  // namespace

// --- Codecs ------------------------------------------------------------------

bool purpose_is_resumable(const Purpose purpose) noexcept {
  return purpose == Purpose::Link || purpose == Purpose::End || purpose == Purpose::Authority ||
         purpose == Purpose::PendingJoin;
}

std::size_t r1_size(const R1& message) noexcept {
  return message.purpose == Purpose::PendingJoin ? kR1BaseSize + 1 + message.ticket_size
                                                 : kR1BaseSize;
}

DecodeError decode_r1(const ByteView input, R1& out) noexcept {
  out = R1{};
  if (input.data == nullptr || input.size < kR1BaseSize) return DecodeError::Truncated;
  if (input.size > kR1MaxSize) return DecodeError::Oversized;
  const std::uint8_t* p = input.data;
  const auto purpose = static_cast<Purpose>(p[0]);
  if (!purpose_is_resumable(purpose)) return DecodeError::BadPurpose;
  if (p[1] != 0) return DecodeError::UnsupportedFlags;
  if (p[2] != 0 || p[3] != 0) return DecodeError::ReservedNonZero;
  std::size_t ticket = 0;
  if (purpose == Purpose::PendingJoin) {
    if (input.size < kR1BaseSize + 1) return DecodeError::LengthMismatch;
    ticket = p[kR1MacOffset];
    if (ticket == 0 || ticket > kTicketMax) return DecodeError::TicketLength;
    if (input.size != kR1BaseSize + 1 + ticket) return DecodeError::LengthMismatch;
  } else if (input.size != kR1BaseSize) {
    return DecodeError::LengthMismatch;
  }
  const std::uint32_t cid = get_u32(p + 28);
  if (cid == 0) return DecodeError::ZeroContextId;
  out.purpose = purpose;
  std::memcpy(out.rid.data(), p + 4, out.rid.size());
  std::memcpy(out.nonce_i.data(), p + 12, out.nonce_i.size());
  out.cid_i = cid;
  get_epochs(p + 32, out.epochs);
  out.ticket_size = static_cast<std::uint8_t>(ticket);
  if (ticket != 0) std::memcpy(out.ticket.data(), p + kR1MacOffset + 1, ticket);
  std::memcpy(out.mac.data(), p + input.size - out.mac.size(), out.mac.size());
  return DecodeError::None;
}

DecodeError decode_r2(const ByteView input, R2& out) noexcept {
  out = R2{};
  if (input.data == nullptr || input.size < kR2HintSize) return DecodeError::Truncated;
  if (input.size > kR2Size) return DecodeError::Oversized;
  const std::uint8_t* p = input.data;
  if (p[0] > static_cast<std::uint8_t>(R2Status::RevokedHint)) return DecodeError::BadStatus;
  if (p[1] != 0) return DecodeError::UnsupportedFlags;
  if (p[2] != 0 || p[3] != 0) return DecodeError::ReservedNonZero;
  out.status = static_cast<R2Status>(p[0]);
  if (out.status != R2Status::Ok) {
    if (input.size != kR2HintSize) return DecodeError::LengthMismatch;
    std::memcpy(out.hint_rid.data(), p + 4, out.hint_rid.size());
    return DecodeError::None;
  }
  if (input.size != kR2Size) return DecodeError::LengthMismatch;
  const std::uint32_t cid = get_u32(p + 20);
  if (cid == 0) return DecodeError::ZeroContextId;
  std::memcpy(out.nonce_r.data(), p + 4, out.nonce_r.size());
  out.cid_r = cid;
  get_epochs(p + 24, out.epochs);
  std::memcpy(out.mac.data(), p + kR2BodySize, out.mac.size());
  return DecodeError::None;
}

DecodeError decode_r3(const ByteView input, Mac& out) noexcept {
  out.fill(0);
  if (input.data == nullptr || input.size < kR3Size) return DecodeError::Truncated;
  if (input.size > kR3Size) return DecodeError::Oversized;
  std::memcpy(out.data(), input.data, out.size());
  return DecodeError::None;
}

Status encode_r1(const R1& message, const MutableByteView out, std::size_t& written) noexcept {
  written = 0;
  if (!purpose_is_resumable(message.purpose) || message.cid_i == 0) {
    return Status::error(StatusCode::InvalidArgument, "rlres1 r1 fields");
  }
  const bool pending = message.purpose == Purpose::PendingJoin;
  if (pending ? (message.ticket_size == 0 || message.ticket_size > kTicketMax)
              : message.ticket_size != 0) {
    return Status::error(StatusCode::InvalidArgument, "rlres1 r1 ticket");
  }
  const std::size_t size = r1_size(message);
  if (out.data == nullptr || out.size < size) {
    return Status::error(StatusCode::NoCapacity, "rlres1 r1 buffer");
  }
  std::uint8_t* p = out.data;
  p[0] = static_cast<std::uint8_t>(message.purpose);
  p[1] = 0;
  p[2] = 0;
  p[3] = 0;
  std::memcpy(p + 4, message.rid.data(), message.rid.size());
  std::memcpy(p + 12, message.nonce_i.data(), message.nonce_i.size());
  put_u32(p + 28, message.cid_i);
  put_epochs(p + 32, message.epochs);
  if (pending) {
    p[kR1MacOffset] = message.ticket_size;
    std::memcpy(p + kR1MacOffset + 1, message.ticket.data(), message.ticket_size);
  }
  std::memcpy(p + size - message.mac.size(), message.mac.data(), message.mac.size());
  written = size;
  return Status::success();
}

Status encode_r2(const R2& message, const MutableByteView out, std::size_t& written) noexcept {
  written = 0;
  if (static_cast<std::uint8_t>(message.status) > static_cast<std::uint8_t>(R2Status::RevokedHint) ||
      (message.status == R2Status::Ok && message.cid_r == 0)) {
    return Status::error(StatusCode::InvalidArgument, "rlres1 r2 fields");
  }
  const std::size_t size = message.status == R2Status::Ok ? kR2Size : kR2HintSize;
  if (out.data == nullptr || out.size < size) {
    return Status::error(StatusCode::NoCapacity, "rlres1 r2 buffer");
  }
  std::uint8_t* p = out.data;
  p[0] = static_cast<std::uint8_t>(message.status);
  p[1] = 0;
  p[2] = 0;
  p[3] = 0;
  if (message.status != R2Status::Ok) {
    std::memcpy(p + 4, message.hint_rid.data(), message.hint_rid.size());
  } else {
    std::memcpy(p + 4, message.nonce_r.data(), message.nonce_r.size());
    put_u32(p + 20, message.cid_r);
    put_epochs(p + 24, message.epochs);
    std::memcpy(p + kR2BodySize, message.mac.data(), message.mac.size());
  }
  written = size;
  return Status::success();
}

const char* reject_name(const Reject reject) noexcept {
  switch (reject) {
    case Reject::None: return "none";
    case Reject::Malformed: return "malformed";
    case Reject::NoSession: return "no_session";
    case Reject::Reflection: return "reflection";
    case Reject::SimultaneousOpen: return "simultaneous_open";
    case Reject::DuplicateSession: return "duplicate_session";
    case Reject::ReplayedNonce: return "replayed_nonce";
    case Reject::Timeout: return "timeout";
    case Reject::UnknownResumptionId: return "unknown_resumption_id";
    case Reject::SlotExpired: return "slot_expired";
    case Reject::PeerRevoked: return "peer_revoked";
    case Reject::WrongNetwork: return "wrong_network";
    case Reject::PeerMismatch: return "peer_mismatch";
    case Reject::SiteEpochMismatch: return "site_epoch_mismatch";
    case Reject::StaleGkEpoch: return "stale_gk_epoch";
    case Reject::FutureGkEpoch: return "future_gk_epoch";
    case Reject::BadMac: return "bad_mac";
    case Reject::UnauthenticatedHint: return "unauthenticated_hint";
    case Reject::HintMismatch: return "hint_mismatch";
    case Reject::PurposeNotServed: return "purpose_not_served";
    case Reject::TableFull: return "table_full";
    case Reject::RateLimited: return "rate_limited";
    case Reject::EntropyUnavailable: return "entropy_unavailable";
    case Reject::ContextIdUnavailable: return "context_id_unavailable";
    case Reject::ResumeBudgetExhausted: return "resume_budget_exhausted";
    case Reject::InvalidRequest: return "invalid_request";
  }
  return "unknown";
}

void Output::clear() noexcept {
  keys::clear(established.tx);
  keys::clear(established.rx);
  secure_clear(message.data(), message.size());
  secure_clear(established.ticket.data(), established.ticket.size());
  action = Action::None;
  reject = Reject::None;
  decode = DecodeError::None;
  superseded_initiator = false;
  message_size = 0;
  established = Established{};
}

// --- Engine ------------------------------------------------------------------

Status Engine::configure(const Local& local, const Limits& limits) noexcept {
  clear_all();
  configured_ = false;
  if (local.self == kInvalidNodeId || local.self == kBroadcastNodeId || local.network == 0 ||
      local.epochs.site_epoch != static_cast<std::uint32_t>(local.network >> 32)) {
    return Status::error(StatusCode::InvalidArgument, "rlres1 local view");
  }
  if (limits.max_initiator == 0 || limits.max_initiator > kMaxInitiatorSessions ||
      limits.max_responder == 0 || limits.max_responder > kMaxResponderSessions ||
      limits.responder_rate_per_s == 0 || limits.responder_burst == 0 ||
      limits.base_timeout_ms == 0 || limits.max_hops == 0 ||
      (limits.responder_purposes & ~((1u << 1) | (1u << 2) | (1u << 4) | (1u << 5))) != 0) {
    return Status::error(StatusCode::InvalidArgument, "rlres1 limits");
  }
  local_ = local;
  limits_ = limits;
  tokens_primed_ = false;
  configured_ = true;
  return Status::success();
}

Status Engine::update_epochs(const Epochs& epochs) noexcept {
  if (!configured_ || epochs.site_epoch != local_.epochs.site_epoch) {
    return Status::error(StatusCode::InvalidState, "rlres1 site epoch change needs configure");
  }
  // Epochs advance monotonically within a site: a regressed GK/RS is a
  // caller bug or a confused deputy, never applied (P4 §6.2).
  if (epochs.gk_epoch < local_.epochs.gk_epoch || epochs.rs_epoch < local_.epochs.rs_epoch) {
    return Status::error(StatusCode::InvalidState, "rlres1 epochs regressed");
  }
  local_.epochs = epochs;
  return Status::success();
}

void Engine::reject(Output& out, const Reject reason, const DecodeError decode) noexcept {
  out.reject = reason;
  out.decode = decode;
  // Saturating: flood counters must not wrap back to a healthy-looking 0.
  std::uint32_t& count = reject_counts_[static_cast<std::size_t>(reason)];
  if (count < 0xFFFFFFFFU) ++count;
}

void Engine::send_hint(Output& out, const R2Status status, const ResumeId& rid,
                       const Reject reason) noexcept {
  reject(out, reason);
  R2 hint{};
  hint.status = status;
  hint.hint_rid = rid;
  std::size_t written = 0;
  if (encode_r2(hint, MutableByteView{out.message.data(), out.message.size()}, written)) {
    out.action = Action::Send;
    out.message_size = written;
  }
}

MonotonicMs Engine::deadline_for(const MonotonicMs now, const std::uint8_t hops) const noexcept {
  // Saturating: near the clock ceiling a wrapped deadline would expire a
  // live session instantly (or never). The per-hop product cannot overflow
  // (u32 milliseconds times a u8 hop count fits u64).
  const MonotonicMs span = static_cast<MonotonicMs>(limits_.per_hop_timeout_ms) * hops +
                           limits_.base_timeout_ms;
  return (now > UINT64_MAX - span) ? UINT64_MAX : (now + span);
}

NodeId Engine::responder_identity(const Purpose purpose) const noexcept {
  return pairwise(purpose) ? local_.self : local_.site_id;
}

Reject Engine::check_gk(const Purpose purpose, const std::uint32_t peer_gk,
                        const std::uint32_t created) const noexcept {
  if (!pairwise(purpose)) return Reject::None;  // authority/pending: the reason to call
  const std::uint64_t local = local_.epochs.gk_epoch;
  if (peer_gk < created || static_cast<std::uint64_t>(peer_gk) + 1 < local) {
    return Reject::StaleGkEpoch;
  }
  if (static_cast<std::uint64_t>(peer_gk) > local + 1) return Reject::FutureGkEpoch;
  return Reject::None;
}

bool Engine::take_token(const MonotonicMs now) noexcept {
  const std::uint64_t cap = static_cast<std::uint64_t>(limits_.responder_burst) * 1000u;
  if (!tokens_primed_) {
    tokens_milli_ = static_cast<std::uint32_t>(cap);
    tokens_at_ = now;
    tokens_primed_ = true;
  }
  if (now > tokens_at_) {
    // Clamp the elapsed span before scaling: past the clock ceiling the raw
    // product would wrap and starve the bucket instead of refilling it.
    const std::uint64_t elapsed = now - tokens_at_;
    const std::uint64_t gained = (elapsed > cap)
                                     ? cap
                                     : elapsed * static_cast<std::uint64_t>(
                                                     limits_.responder_rate_per_s);
    const std::uint64_t total = tokens_milli_ + (gained > cap ? cap : gained);
    tokens_milli_ = static_cast<std::uint32_t>(total > cap ? cap : total);
    tokens_at_ = now;
  }
  if (tokens_milli_ < 1000u) return false;
  tokens_milli_ -= 1000u;
  return true;
}

bool Engine::replay_seen(const ResumeNonce& nonce) const noexcept {
  for (const auto& entry : replay_) {
    if (entry.used &&
        constant_time_equal(ByteView{entry.nonce.data(), entry.nonce.size()},
                            ByteView{nonce.data(), nonce.size()})) {
      return true;
    }
  }
  return false;
}

void Engine::replay_remember(const ResumeNonce& nonce) noexcept {
  replay_[replay_next_].used = true;
  replay_[replay_next_].nonce = nonce;
  replay_next_ = (replay_next_ + 1) % replay_.size();
}

Engine::InitiatorSession* Engine::find_initiator(const NodeId peer, const Purpose purpose) noexcept {
  for (auto& s : initiators_) {
    if (s.state != SlotState::Free && s.peer == peer && s.purpose == purpose) return &s;
  }
  return nullptr;
}

Engine::ResponderSession* Engine::find_responder(const NodeId peer, const Purpose purpose) noexcept {
  for (auto& s : responders_) {
    if (s.state != SlotState::Free && s.established.peer == peer &&
        s.established.purpose == purpose) {
      return &s;
    }
  }
  return nullptr;
}

void Engine::wipe(InitiatorSession& s) noexcept {
  secure_clear(s.secret);
  secure_clear(s.auth_key);
  secure_clear(s.r1);
  s = InitiatorSession{};
}

void Engine::wipe(ResponderSession& s) noexcept {
  secure_clear(s.expected_r3);
  keys::clear(s.established.tx);
  keys::clear(s.established.rx);
  s = ResponderSession{};
}

void Engine::clear_all() noexcept {
  for (auto& s : initiators_) wipe(s);
  for (auto& s : responders_) wipe(s);
  for (auto& e : replay_) e = ReplayEntry{};
  replay_next_ = 0;
}

std::size_t Engine::initiator_in_flight() const noexcept {
  std::size_t n = 0;
  for (const auto& s : initiators_) n += s.state != SlotState::Free ? 1 : 0;
  return n;
}

std::size_t Engine::responder_in_flight() const noexcept {
  std::size_t n = 0;
  for (const auto& s : responders_) n += s.state != SlotState::Free ? 1 : 0;
  return n;
}

void Engine::begin(const BeginRequest& request, const MonotonicMs now, Environment& env,
                   Output& out) noexcept {
  out.clear();
  const Slot& slot = request.slot;
  const Purpose purpose = slot.purpose;
  const bool pending = purpose == Purpose::PendingJoin;
  const bool link_carrier = request.carrier.kind == Carrier::Kind::Link;
  // The self-handshake refusal is pairwise-only: for authority/pending-join
  // the peer is the site id, which lives in a separate namespace and may
  // numerically equal this node's id (the site check below still applies).
  if (!configured_ || !purpose_is_resumable(purpose) || slot.peer == kInvalidNodeId ||
      slot.peer == kBroadcastNodeId || (pairwise(purpose) && slot.peer == local_.self) ||
      (pending ? (request.ticket.data == nullptr || request.ticket.size == 0 ||
                  request.ticket.size > kTicketMax)
               : request.ticket.size != 0) ||
      link_carrier != (purpose == Purpose::Link) || request.carrier.hops > limits_.max_hops) {
    reject(out, Reject::InvalidRequest);
    return;
  }
  if (!pairwise(purpose) && slot.peer != local_.site_id) {
    reject(out, Reject::PeerMismatch);
    return;
  }
  if (slot.network != local_.network) {
    reject(out, Reject::WrongNetwork);
    return;
  }
  if (pairwise(purpose)) {
    if (static_cast<std::uint64_t>(slot.created_gk_epoch) + kGkLifetime <=
        local_.epochs.gk_epoch) {
      reject(out, Reject::SlotExpired);
      return;
    }
    if (env.revoked(slot.peer, slot.peer_generation)) {
      reject(out, Reject::PeerRevoked);
      return;
    }
  }
  if (find_initiator(slot.peer, purpose) != nullptr) {
    reject(out, Reject::DuplicateSession);
    return;
  }
  InitiatorSession* session = nullptr;
  std::size_t used = 0;
  for (auto& s : initiators_) {
    if (s.state != SlotState::Free) {
      ++used;
    } else if (session == nullptr) {
      session = &s;
    }
  }
  if (session == nullptr || used >= limits_.max_initiator) {
    reject(out, Reject::TableFull);
    return;
  }

  R1 r1{};
  r1.purpose = purpose;
  keys::resume_id(slot.secret, purpose, r1.rid);
  if (!env.random(MutableByteView{r1.nonce_i.data(), r1.nonce_i.size()})) {
    reject(out, Reject::EntropyUnavailable);
    return;
  }
  if (!env.allocate_context_id(purpose, slot.peer, r1.cid_i) || r1.cid_i == 0) {
    reject(out, Reject::ContextIdUnavailable);
    return;
  }
  r1.epochs = local_.epochs;
  if (pending) {
    r1.ticket_size = static_cast<std::uint8_t>(request.ticket.size);
    std::memcpy(r1.ticket.data(), request.ticket.data, request.ticket.size);
  }

  InitiatorSession& s = *session;
  s.purpose = purpose;
  s.peer = slot.peer;
  s.node_r = pairwise(purpose) ? slot.peer : local_.site_id;
  s.created_gk_epoch = slot.created_gk_epoch;
  s.secret = slot.secret;
  compute_binding(request.carrier, purpose, local_.self, s.node_r, s.binding);
  if (!keys::resume_auth_key(slot.secret, purpose, local_.network, local_.self, s.node_r,
                             s.auth_key)) {
    wipe(s);
    reject(out, Reject::InvalidRequest);
    return;
  }
  std::size_t written = 0;
  if (!encode_r1(r1, MutableByteView{s.r1.data(), s.r1.size()}, written) ||
      !keys::resume_mac(view(s.auth_key), keys::kLabelResumeR1, view(s.binding),
                        ByteView{s.r1.data(), written - keys::kResumeMacSize}, ByteView{},
                        r1.mac)) {
    wipe(s);
    reject(out, Reject::InvalidRequest);
    return;
  }
  std::memcpy(s.r1.data() + written - keys::kResumeMacSize, r1.mac.data(), r1.mac.size());
  s.r1_size = static_cast<std::uint8_t>(written);
  s.deadline = deadline_for(now, request.carrier.hops);
  s.state = SlotState::WaitR2;

  std::memcpy(out.message.data(), s.r1.data(), written);
  out.message_size = written;
  out.action = Action::Send;
}

void Engine::on_r1(const ByteView message, const Carrier& carrier, const NodeId claimed_peer,
                   const MonotonicMs now, Environment& env, Output& out) noexcept {
  out.clear();
  if (!configured_) {
    reject(out, Reject::InvalidRequest);
    return;
  }
  R1 r1{};
  const DecodeError decoded = decode_r1(message, r1);
  if (decoded != DecodeError::None) {
    reject(out, Reject::Malformed, decoded);
    return;
  }
  const Purpose purpose = r1.purpose;
  if ((limits_.responder_purposes & (1u << static_cast<unsigned>(purpose))) == 0 ||
      (carrier.kind == Carrier::Kind::Link) != (purpose == Purpose::Link) ||
      carrier.hops > limits_.max_hops) {
    reject(out, Reject::PurposeNotServed);
    return;
  }
  // Reflection: our own outstanding R1 (by its fresh nonce_I) sent back to us.
  for (const auto& s : initiators_) {
    if (s.state == SlotState::WaitR2 &&
        constant_time_equal(ByteView{s.r1.data() + 12, keys::kResumeNonceSize},
                            ByteView{r1.nonce_i.data(), r1.nonce_i.size()})) {
      reject(out, Reject::Reflection);
      return;
    }
  }
  Slot slot{};
  if (!env.find_slot(purpose, r1.rid, slot) || slot.purpose != purpose) {
    secure_clear(slot.secret);
    send_hint(out, R2Status::UnknownId, r1.rid, Reject::UnknownResumptionId);
    return;
  }
  // From here the slot secret is on the stack: every exit clears it.
  struct SecretGuard {
    Secret& s;
    ~SecretGuard() { secure_clear(s); }
  } guard{slot.secret};

  if (slot.peer == kInvalidNodeId || (pairwise(purpose) && slot.peer == local_.self) ||
      (claimed_peer != kInvalidNodeId && claimed_peer != slot.peer)) {
    reject(out, Reject::PeerMismatch);
    return;
  }
  if (slot.network != local_.network) {
    reject(out, Reject::WrongNetwork);
    return;
  }
  const NodeId node_i = slot.peer;
  const NodeId node_r = responder_identity(purpose);
  Secret auth_key{};
  struct AuthGuard {
    Secret& s;
    ~AuthGuard() { secure_clear(s); }
  } auth_guard{auth_key};
  ScopeDigest binding{};
  compute_binding(carrier, purpose, node_i, node_r, binding);
  Mac expected{};
  if (!keys::resume_auth_key(slot.secret, purpose, local_.network, node_i, node_r, auth_key) ||
      !keys::resume_mac(view(auth_key), keys::kLabelResumeR1, view(binding),
                        ByteView{message.data, message.size - keys::kResumeMacSize}, ByteView{},
                        expected) ||
      !mac_equal(expected, r1.mac)) {
    reject(out, Reject::BadMac);
    return;
  }
  if (replay_seen(r1.nonce_i)) {
    reject(out, Reject::ReplayedNonce);
    return;
  }
  replay_remember(r1.nonce_i);

  if (pairwise(purpose)) {
    if (static_cast<std::uint64_t>(slot.created_gk_epoch) + kGkLifetime <=
        local_.epochs.gk_epoch) {
      send_hint(out, R2Status::Expired, r1.rid, Reject::SlotExpired);
      return;
    }
    if (env.revoked(slot.peer, slot.peer_generation)) {
      send_hint(out, R2Status::RevokedHint, r1.rid, Reject::PeerRevoked);
      return;
    }
  }
  if (r1.epochs.site_epoch != local_.epochs.site_epoch) {
    reject(out, Reject::SiteEpochMismatch);
    return;
  }
  const Reject gk = check_gk(purpose, r1.epochs.gk_epoch, slot.created_gk_epoch);
  if (gk != Reject::None) {
    reject(out, gk);
    return;
  }
  if (find_responder(slot.peer, purpose) != nullptr) {
    reject(out, Reject::DuplicateSession);
    return;
  }
  // Simultaneous open: the handshake initiated by the lower NodeId proceeds.
  // Our own attempt is only dropped once this responder session is committed.
  InitiatorSession* yielding = pairwise(purpose) ? find_initiator(slot.peer, purpose) : nullptr;
  if (yielding != nullptr && local_.self < slot.peer) {
    reject(out, Reject::SimultaneousOpen);
    return;
  }
  ResponderSession* session = nullptr;
  std::size_t used = 0;
  for (auto& s : responders_) {
    if (s.state != SlotState::Free) {
      ++used;
    } else if (session == nullptr) {
      session = &s;
    }
  }
  if (session == nullptr || used >= limits_.max_responder) {
    reject(out, Reject::TableFull);
    return;
  }
  if (!take_token(now)) {
    reject(out, Reject::RateLimited);
    return;
  }
  // The slot is verified: spend one of its 64 uses before R2 exists. A
  // spent or unprovable budget answers Expired (full EDHOC), never
  // UnknownId — the MAC already proved the RMS is ours.
  if (!env.reserve_resume_use(purpose, r1.rid)) {
    send_hint(out, R2Status::Expired, r1.rid, Reject::ResumeBudgetExhausted);
    return;
  }

  R2 r2{};
  r2.status = R2Status::Ok;
  if (!env.random(MutableByteView{r2.nonce_r.data(), r2.nonce_r.size()})) {
    reject(out, Reject::EntropyUnavailable);
    return;
  }
  if (!env.allocate_context_id(purpose, slot.peer, r2.cid_r) || r2.cid_r == 0) {
    reject(out, Reject::ContextIdUnavailable);
    return;
  }
  r2.epochs = local_.epochs;
  std::size_t r2_size = 0;
  if (!encode_r2(r2, MutableByteView{out.message.data(), out.message.size()}, r2_size) ||
      !keys::resume_mac(view(auth_key), keys::kLabelResumeR2, view(binding), message,
                        ByteView{out.message.data(), kR2BodySize}, r2.mac)) {
    out.message_size = 0;
    reject(out, Reject::InvalidRequest);
    return;
  }
  std::memcpy(out.message.data() + kR2BodySize, r2.mac.data(), r2.mac.size());

  ResponderSession& s = *session;
  Established& e = s.established;
  e.purpose = purpose;
  e.role = Role::Responder;
  e.peer = slot.peer;
  e.network = local_.network;
  e.rx_context_id = r2.cid_r;
  e.tx_context_id = r1.cid_i;
  e.peer_epochs = r1.epochs;
  e.peer_rs_behind = r1.epochs.rs_epoch < local_.epochs.rs_epoch;
  e.local_rs_behind = r1.epochs.rs_epoch > local_.epochs.rs_epoch;
  e.ticket_size = r1.ticket_size;
  e.ticket = r1.ticket;
  keys::ResumeKeyContext context{purpose, local_.network, node_i, node_r, r1.cid_i, r2.cid_r};
  if (!derive_session(slot.secret, r1.nonce_i, r2.nonce_r, message,
                      ByteView{out.message.data(), kR2Size}, context, s.expected_r3, e.rx,
                      e.tx)) {
    wipe(s);
    secure_clear(out.message.data(), out.message.size());
    reject(out, Reject::InvalidRequest);
    return;
  }
  s.deadline = deadline_for(now, carrier.hops);
  s.state = SlotState::WaitR3;
  if (yielding != nullptr) {
    wipe(*yielding);
    out.superseded_initiator = true;
  }
  out.message_size = kR2Size;
  out.action = Action::Send;
}

void Engine::on_r2(const NodeId peer, const Purpose purpose, const ByteView message,
                   const MonotonicMs now, Output& out) noexcept {
  out.clear();
  InitiatorSession* found = find_initiator(peer, purpose);
  if (found == nullptr || found->state != SlotState::WaitR2) {
    reject(out, Reject::NoSession);
    return;
  }
  InitiatorSession& s = *found;
  // Every outcome below ends this session: one R2 per R1 (06 §2.2).
  struct Ender {
    InitiatorSession& s;
    ~Ender() { Engine::wipe(s); }
  } ender{s};
  out.action = Action::Fallback;
  if (now > s.deadline) {
    reject(out, Reject::Timeout);
    return;
  }
  R2 r2{};
  const DecodeError decoded = decode_r2(message, r2);
  if (decoded != DecodeError::None) {
    reject(out, Reject::Malformed, decoded);
    return;
  }
  if (r2.status != R2Status::Ok) {
    const bool ours = constant_time_equal(ByteView{r2.hint_rid.data(), r2.hint_rid.size()},
                                          ByteView{s.r1.data() + 4, keys::kResumeIdSize});
    reject(out, ours ? Reject::UnauthenticatedHint : Reject::HintMismatch);
    return;
  }
  Mac expected{};
  if (!keys::resume_mac(view(s.auth_key), keys::kLabelResumeR2, view(s.binding),
                        ByteView{s.r1.data(), s.r1_size}, ByteView{message.data, kR2BodySize},
                        expected) ||
      !mac_equal(expected, r2.mac)) {
    reject(out, Reject::BadMac);
    return;
  }
  if (r2.epochs.site_epoch != local_.epochs.site_epoch) {
    reject(out, Reject::SiteEpochMismatch);
    return;
  }
  const Reject gk = check_gk(purpose, r2.epochs.gk_epoch, s.created_gk_epoch);
  if (gk != Reject::None) {
    reject(out, gk);
    return;
  }
  ResumeNonce nonce_i{};
  std::memcpy(nonce_i.data(), s.r1.data() + 12, nonce_i.size());
  const std::uint32_t cid_i = get_u32(s.r1.data() + 28);
  Established& e = out.established;
  keys::ResumeKeyContext context{purpose, local_.network, local_.self, s.node_r, cid_i, r2.cid_r};
  Mac mac_i3{};
  if (!derive_session(s.secret, nonce_i, r2.nonce_r, ByteView{s.r1.data(), s.r1_size}, message,
                      context, mac_i3, e.tx, e.rx)) {
    out.established = Established{};
    reject(out, Reject::InvalidRequest);
    return;
  }
  e.purpose = purpose;
  e.role = Role::Initiator;
  e.peer = s.peer;
  e.network = local_.network;
  e.rx_context_id = cid_i;
  e.tx_context_id = r2.cid_r;
  e.peer_epochs = r2.epochs;
  e.peer_rs_behind = r2.epochs.rs_epoch < local_.epochs.rs_epoch;
  e.local_rs_behind = r2.epochs.rs_epoch > local_.epochs.rs_epoch;
  std::memcpy(out.message.data(), mac_i3.data(), mac_i3.size());
  secure_clear(mac_i3);
  out.message_size = kR3Size;
  out.action = Action::SendAndInstall;
}

void Engine::on_r3(const NodeId peer, const Purpose purpose, const ByteView message,
                   const MonotonicMs now, Output& out) noexcept {
  out.clear();
  ResponderSession* found = find_responder(peer, purpose);
  if (found == nullptr || found->state != SlotState::WaitR3) {
    reject(out, Reject::NoSession);
    return;
  }
  ResponderSession& s = *found;
  struct Ender {
    ResponderSession& s;
    ~Ender() { Engine::wipe(s); }
  } ender{s};
  if (now > s.deadline) {
    reject(out, Reject::Timeout);
    return;
  }
  Mac mac{};
  const DecodeError decoded = decode_r3(message, mac);
  if (decoded != DecodeError::None) {
    reject(out, Reject::Malformed, decoded);
    return;
  }
  if (!mac_equal(mac, s.expected_r3)) {
    reject(out, Reject::BadMac);
    return;
  }
  out.established = s.established;
  out.action = Action::Install;
}

bool Engine::next_expired(const MonotonicMs now, ExpiredSession& out) noexcept {
  for (auto& s : initiators_) {
    if (s.state != SlotState::Free && now > s.deadline) {
      out = ExpiredSession{Role::Initiator, s.purpose, s.peer};
      wipe(s);
      ++reject_counts_[static_cast<std::size_t>(Reject::Timeout)];
      return true;
    }
  }
  for (auto& s : responders_) {
    if (s.state != SlotState::Free && now > s.deadline) {
      out = ExpiredSession{Role::Responder, s.established.purpose, s.established.peer};
      wipe(s);
      ++reject_counts_[static_cast<std::size_t>(Reject::Timeout)];
      return true;
    }
  }
  return false;
}

void Engine::abort(const Role role, const NodeId peer, const Purpose purpose) noexcept {
  if (role == Role::Initiator) {
    if (InitiatorSession* s = find_initiator(peer, purpose)) wipe(*s);
  } else if (ResponderSession* s = find_responder(peer, purpose)) {
    wipe(*s);
  }
}

void Engine::abort_peer(const NodeId peer) noexcept {
  for (auto& s : initiators_) {
    if (s.state != SlotState::Free && s.peer == peer) wipe(s);
  }
  for (auto& s : responders_) {
    if (s.state != SlotState::Free && s.established.peer == peer) wipe(s);
  }
}

}  // namespace routeloom::rlres1
