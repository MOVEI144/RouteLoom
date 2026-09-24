#include "routeloom/sdkv1_join_relay.hpp"

#include <algorithm>
#include <cstring>

#include "routeloom/discovery.hpp"        // EntropySource
#include "routeloom/discovery_scope.hpp"  // hmac_sha256, constant_time_equal
#include "routeloom/secure_clear.hpp"

// Zero-touch join transport engines (docs/design/sdk-v1/02 §4, §5, §7). See
// sdkv1_join_relay.hpp for the roles; the byte layouts are in
// sdkv1_join_transport.hpp.

namespace routeloom::sdkv1 {
namespace {

constexpr std::uint64_t kAllOnes = ~std::uint64_t{0};
constexpr MacAddress kBroadcastMac{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

bool id_valid(const std::uint64_t id) noexcept { return id != 0 && id != kAllOnes; }

Status invalid(const char* what) noexcept {
  return Status::error(StatusCode::InvalidArgument, what);
}

std::uint8_t first_step(const JoinAuthPhase phase, const std::uint8_t step) noexcept {
  return join_step_valid(phase, step) ? step : std::uint8_t{1};
}

bool offset_of(const JoinObjectSlot& slot, const ByteView view, std::size_t& offset) noexcept {
  const ByteView whole = slot.assembled();
  if (whole.data == nullptr || view.data < whole.data ||
      view.data + view.size > whole.data + whole.size) {
    return false;
  }
  offset = static_cast<std::size_t>(view.data - whole.data);
  return true;
}

}  // namespace

// ===================================================================================
// HmacJoinCookie
// ===================================================================================

HmacJoinCookie::~HmacJoinCookie() { secure_clear(key_); }

Status HmacJoinCookie::seal(const JoinCookieMaterial& material, JoinCookieBytes& out) noexcept {
  std::array<std::uint8_t, sizeof(kJoinCookieDomain) + 6 + 16 + 8 + 4 + 8> input{};
  std::size_t pos = 0;
  std::memcpy(input.data(), kJoinCookieDomain, sizeof(kJoinCookieDomain));
  pos += sizeof(kJoinCookieDomain);
  std::memcpy(input.data() + pos, material.requester_mac.data(), 6);
  pos += 6;
  std::memcpy(input.data() + pos, material.nonce.data(), 16);
  pos += 16;
  for (int i = 0; i < 8; ++i) {
    input[pos++] = static_cast<std::uint8_t>(material.proxy >> (56U - 8U * i));
  }
  for (int i = 0; i < 4; ++i) {
    input[pos++] = static_cast<std::uint8_t>(material.network_low32 >> (24U - 8U * i));
  }
  for (int i = 0; i < 8; ++i) {
    input[pos++] = static_cast<std::uint8_t>(material.bucket >> (56U - 8U * i));
  }
  ScopeDigest digest{};
  hmac_sha256(ByteView{key_.data(), key_.size()}, ByteView{input.data(), pos}, digest);
  std::memcpy(out.data(), digest.data(), out.size());
  secure_clear(digest);
  return Status::success();
}

// ===================================================================================
// ZtJoinerLink
// ===================================================================================

ZtJoinerLink::ZtJoinerLink(const ZtJoinerConfig& config, ZtRld1Port& port, EntropySource& entropy,
                           ZtJoinerObserver& observer) noexcept
    : config_(config), port_(port), entropy_(entropy), observer_(observer) {}

Status ZtJoinerLink::emit(const MacAddress& destination, const FrameType kind,
                          const ByteView body) noexcept {
  if (body.size > autonomy::kRld1MaxBody) return invalid("zt body size");
  autonomy::Rld1Envelope env{};
  env.kind = kind;
  env.network_hint = 0;
  env.claimed_node = config_.node;
  env.transaction_nonce = nonce_;
  env.capability_bits = 0;
  if (body.size != 0) std::memcpy(env.body.data(), body.data, body.size);
  env.body_size = body.size;
  Status status = zt_admit_rld1(membership_, AdmissionDirection::Tx, env);
  if (!status) return status;
  autonomy::Rld1Encoded frame{};
  status = autonomy::rld1_encode(env, frame);
  if (!status) return status;
  status = port_.send_rld1(destination, frame.view());
  if (!status) ++stats_.send_failures;
  return status;
}

Status ZtJoinerLink::discover(const ZtDiscoverBody& body, const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (!id_valid(config_.node)) return invalid("zt joiner node");
  ByteBuffer<kZtDiscoverBodySize> encoded{};
  Status status = zt_discover_body_encode(body, encoded);
  if (!status) return status;
  close();
  status = entropy_.fill(MutableByteView{nonce_.data(), nonce_.size()});
  if (!status) return status;
  discovering_ = true;
  status = emit(kBroadcastMac, FrameType::Discover, encoded.view());
  if (status) ++stats_.discovers_tx;
  return status;
}

Status ZtJoinerLink::connect(const ZtOfferView& offer) noexcept {
  if (!discovering_ || offer.nonce != nonce_ || !id_valid(offer.proxy) ||
      offer.network_low32 == 0) {
    return Status::error(StatusCode::InvalidState, "zt connect without a matching offer");
  }
  discovering_ = false;
  connected_ = true;
  proxy_mac_ = offer.proxy_mac;
  proxy_ = offer.proxy;
  network_low32_ = offer.network_low32;
  cookie_ = offer.body.cookie;
  last_down_sub_ = 0;
  slot_.reset();
  return Status::success();
}

void ZtJoinerLink::close() noexcept {
  discovering_ = false;
  connected_ = false;
  proxy_mac_ = MacAddress{};
  proxy_ = kInvalidNodeId;
  network_low32_ = 0;
  secure_clear(cookie_);
  last_down_sub_ = 0;
  slot_.reset();
}

Status ZtJoinerLink::send(const JoinAuthPhase phase, const std::uint8_t step,
                          const ByteView message, const MonotonicMs now_ms) noexcept {
  if (!connected_) return Status::error(StatusCode::InvalidState, "zt send without a proxy");
  if (phase == JoinAuthPhase::RelayStatus || !join_step_valid(phase, step) ||
      join_step_flow(phase, step) == JoinFlow::Down) {
    return invalid("zt joiner step");
  }
  JoinAuthObject object{};
  object.phase = phase;
  object.step = step;
  object.cookie_present = step == 1;
  object.cookie = cookie_;
  object.message = message;
  Status status = join_object_validate(object);
  if (!status) return status;
  // Newest message wins: an unconfirmed older up object or a half-received
  // down object is abandoned (the peer retransmits what still matters).
  slot_.release_assembled();
  std::size_t written = 0;
  status = join_object_encode(object, slot_.writable_buffer(), written);
  if (!status) return status;
  if (written <= autonomy::kRld1MaxBody) {
    status = emit(proxy_mac_, FrameType::BootstrapAuth,
                  ByteView{slot_.writable_buffer().data, written});
    slot_.release_assembled();
  } else {
    status = slot_.load_in_place(JoinCarrier::Rld1, phase, step, join_rld1_object_id(nonce_),
                                 written, now_ms);
    if (status) send_due_chunks(now_ms);
  }
  if (status) ++stats_.objects_tx;
  return status;
}

void ZtJoinerLink::send_due_chunks(const MonotonicMs now_ms) noexcept {
  const std::uint16_t mask = slot_.pending_mask();
  for (std::size_t i = 0; i < slot_.chunk_total(); ++i) {
    if ((mask & (1U << i)) == 0) continue;
    JoinChunk chunk{};
    if (!slot_.chunk_at(i, chunk)) continue;
    std::array<std::uint8_t, autonomy::kRld1MaxBody> body{};
    std::size_t written = 0;
    if (!join_chunk_encode(JoinCarrier::Rld1, chunk, MutableByteView{body.data(), body.size()},
                           written)) {
      continue;
    }
    (void)emit(proxy_mac_, FrameType::BootstrapChunk, ByteView{body.data(), written});
  }
  slot_.note_sent(now_ms);
}

void ZtJoinerLink::send_reply(const JoinReply& reply) noexcept {
  std::array<std::uint8_t, kJoinReplySize> body{};
  std::size_t written = 0;
  if (join_reply_encode(reply, MutableByteView{body.data(), body.size()}, written)) {
    (void)emit(proxy_mac_, FrameType::BootstrapReply, ByteView{body.data(), written});
  }
}

bool ZtJoinerLink::from_proxy(const MacAddress& source,
                              const autonomy::Rld1Envelope& env) const noexcept {
  return connected_ && source == proxy_mac_ && env.transaction_nonce == nonce_ &&
         env.claimed_node == proxy_ && env.network_hint == network_low32_ &&
         env.capability_bits == 0;
}

void ZtJoinerLink::on_rld1_rx(const MacAddress& source, const MacAddress& destination,
                              const ByteView frame, const MonotonicMs now_ms) noexcept {
  autonomy::Rld1Envelope env{};
  if (!autonomy::rld1_decode(frame, env) || !zt_rld1_frame(env)) return;  // not this lane
  if (!zt_admit_rld1(membership_, AdmissionDirection::Rx, env)) {
    ++stats_.frames_rejected;
    return;
  }
  const ByteView body{env.body.data(), env.body_size};
  switch (env.kind) {
    case FrameType::Offer: {
      ZtOfferView offer{};
      autonomy::Rld1Envelope checked{};
      if (!discovering_ || destination != config_.mac ||
          !zt_offer_frame_decode(frame, checked, offer.body) ||
          checked.transaction_nonce != nonce_) {
        ++stats_.offers_ignored;
        return;
      }
      if (offer.body.org_hint != config_.org_hint) {  // 02 §11 rule 1
        ++stats_.offers_ignored;
        return;
      }
      offer.proxy_mac = source;
      offer.proxy = checked.claimed_node;
      offer.network_low32 = checked.network_hint;
      offer.nonce = nonce_;
      ++stats_.offers_rx;
      observer_.on_offer(offer);
      return;
    }
    case FrameType::BootstrapAuth: {
      JoinAuthObject object{};
      if (!from_proxy(source, env) || !join_object_decode(body, object) ||
          object.cookie_present) {
        ++stats_.frames_rejected;
        return;
      }
      if (object.phase == JoinAuthPhase::RelayStatus) {
        observer_.on_relay_status(object.relay_status, object.retry_after_ms);
        return;
      }
      // A down message answers our last up object only when it advances
      // the exchange: a retransmitted duplicate of an earlier stage is
      // dropped without touching the slot or the observer (single-frame
      // objects have no receipt to re-send).
      const std::uint8_t sub = join_sub(object.phase, object.step);
      if (sub <= last_down_sub_) return;
      if (slot_.mode() == JoinObjectSlot::Mode::Sending) slot_.release_assembled();
      ++stats_.messages_rx;
      last_down_sub_ = sub;
      observer_.on_message(object.phase, object.step, object.message);
      return;
    }
    case FrameType::BootstrapChunk: {
      JoinChunk chunk{};
      if (!from_proxy(source, env) || !join_chunk_decode(JoinCarrier::Rld1, body, chunk) ||
          chunk.id != join_rld1_object_id(nonce_)) {
        ++stats_.frames_rejected;
        return;
      }
      JoinObjectSlot::Accepted accepted = slot_.accept(JoinCarrier::Rld1, chunk, now_ms);
      if (accepted.outcome == JoinObjectSlot::Outcome::Busy &&
          slot_.mode() == JoinObjectSlot::Mode::Sending &&
          join_sub(chunk.phase, chunk.step) > last_down_sub_) {
        // Only a NEW down object displaces our Sending object (it reached
        // the proxy): a duplicate of the delivered one re-earns its
        // Complete reply above, a stale one stays refused.
        slot_.release_assembled();
        accepted = slot_.accept(JoinCarrier::Rld1, chunk, now_ms);
      }
      if (accepted.send_reply) send_reply(accepted.reply);
      if (accepted.outcome == JoinObjectSlot::Outcome::Conflict) ++stats_.assembly_conflicts;
      if (accepted.outcome == JoinObjectSlot::Outcome::Busy ||
          accepted.outcome == JoinObjectSlot::Outcome::Rejected) {
        ++stats_.frames_rejected;
      }
      if (accepted.outcome != JoinObjectSlot::Outcome::Complete) return;
      JoinAuthObject object{};
      if (!join_object_decode(slot_.assembled(), object) || object.phase != chunk.phase ||
          object.step != chunk.step || object.cookie_present) {
        ++stats_.frames_rejected;
        slot_.release_assembled();
        return;
      }
      const std::uint8_t sub = join_sub(object.phase, object.step);
      if (sub <= last_down_sub_) {
        // A stale object re-assembled (older than the stage delivered
        // last): drop it like a single-frame duplicate.
        slot_.release_assembled();
        return;
      }
      ++stats_.messages_rx;
      last_down_sub_ = sub;
      // The callback may re-enter the link (send/close/discover): release
      // the slot only while it still holds the delivered object.
      const std::uint32_t delivered = slot_.generation();
      observer_.on_message(object.phase, object.step, object.message);
      slot_.release_assembled_if(delivered);
      return;
    }
    case FrameType::BootstrapReply: {
      JoinReply reply{};
      if (!from_proxy(source, env) || !join_reply_decode(body, reply)) {
        ++stats_.frames_rejected;
        return;
      }
      if (slot_.on_reply(reply, now_ms) == JoinObjectSlot::ReplyOutcome::Restart) {
        send_due_chunks(now_ms);
      }
      return;
    }
    default:
      ++stats_.frames_rejected;
      return;
  }
}

void ZtJoinerLink::poll(const MonotonicMs now_ms) noexcept {
  if (slot_.expire(now_ms, config_.assembly_timeout_ms)) ++stats_.assembly_expired;
  if (slot_.mode() != JoinObjectSlot::Mode::Sending ||
      now_ms - slot_.last_send_ms() < config_.retransmit_ms) {
    return;
  }
  if (slot_.sends() >= config_.max_sends) {
    slot_.release_assembled();
    observer_.on_link_failure("DELIVERY_FAILED");
    return;
  }
  ++stats_.retransmissions;
  send_due_chunks(now_ms);
}

// ===================================================================================
// JoinProxy
// ===================================================================================

JoinProxy::JoinProxy(const JoinProxyConfig& config, ZtRld1Port& rld1, ZtRelayPort& relay,
                     JoinCookieSealer& cookie, EntropySource& entropy) noexcept
    : config_(config), rld1_(rld1), relay_port_(relay), cookie_(cookie), entropy_(entropy) {}

void JoinProxy::set_authority(const bool reachable, const std::uint8_t hops,
                              const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  reachable_ = reachable;
  hops_ = hops;
  // Without a path to the authority the relay cannot finish: tell the device
  // (a hint it waits on) and stop. The gateway cannot be told either.
  if (!reachable && relay_.active) abort_relay(RelayStatusCode::AuthorityUnreachable, false);
}

void JoinProxy::set_membership(const MembershipState state, const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  const bool was_member = membership_ == MembershipState::Member;
  if (state != MembershipState::Member && was_member) {
    // 02 §7.3: own membership revoked / GK unknown -> stop relaying and
    // offering. The RelayStatus still leaves while the lane is open.
    abort_relay(RelayStatusCode::Aborted, false);
    offers_.clear();
  }
  membership_ = state;
}

Status JoinProxy::emit_rld1(const MacAddress& mac, const JoinNonce& nonce, const FrameType kind,
                            const ByteView body) noexcept {
  if (body.size > autonomy::kRld1MaxBody) return invalid("zt body size");
  autonomy::Rld1Envelope env{};
  env.kind = kind;
  env.network_hint = config_.network_low32;
  env.claimed_node = config_.node;
  env.transaction_nonce = nonce;
  env.capability_bits = 0;
  if (body.size != 0) std::memcpy(env.body.data(), body.data, body.size);
  env.body_size = body.size;
  Status status = zt_admit_rld1(membership_, AdmissionDirection::Tx, env);
  if (!status) return status;
  autonomy::Rld1Encoded frame{};
  status = autonomy::rld1_encode(env, frame);
  if (status) status = rld1_.send_rld1(mac, frame.view());
  if (!status) ++stats_.send_failures;
  return status;
}

void JoinProxy::on_rld1_rx(const MacAddress& source, const MacAddress& destination,
                           const std::int8_t rssi_dbm, const ByteView frame,
                           const MonotonicMs now_ms) noexcept {
  autonomy::Rld1Envelope env{};
  if (!autonomy::rld1_decode(frame, env) || !zt_rld1_frame(env)) return;  // not this lane
  if (!zt_admit_rld1(membership_, AdmissionDirection::Rx, env)) {
    ++stats_.frames_rejected;
    return;
  }
  switch (env.kind) {
    case FrameType::Discover:
      handle_discover(source, destination, frame, now_ms);
      return;
    case FrameType::BootstrapAuth:
      handle_auth(source, env, rssi_dbm, now_ms);
      return;
    case FrameType::BootstrapChunk:
      handle_chunk(source, env, rssi_dbm, now_ms);
      return;
    case FrameType::BootstrapReply:
      handle_reply(source, env, now_ms);
      return;
    default:
      ++stats_.frames_rejected;
      return;
  }
}

void JoinProxy::handle_discover(const MacAddress& source, const MacAddress& destination,
                                const ByteView frame, const MonotonicMs now_ms) noexcept {
  autonomy::Rld1Envelope env{};
  ZtDiscoverBody body{};
  if (destination != kBroadcastMac || !zt_discover_frame_decode(frame, env, body)) {
    ++stats_.frames_rejected;
    return;
  }
  ++stats_.discovers_rx;
  // 02 §7.3 IDLE row: zero_touch_open, authority reachable, same
  // organization, the site not avoided, and no relay in progress.
  if (!open_ || !reachable_ || relay_.active || body.org_hint != config_.org_hint ||
      zt_discover_avoids(body, config_.site_hint)) {
    ++stats_.offers_suppressed;
    return;
  }
  const bool pending = offers_.find([&](const PendingOffer& offer) {
    return offer.mac == source && offer.nonce == env.transaction_nonce;
  }) != nullptr;
  if (pending) return;
  PendingOffer* offer = offers_.allocate();
  if (offer == nullptr) {
    ++stats_.offers_suppressed;
    return;
  }
  offer->mac = source;
  offer->nonce = env.transaction_nonce;
  std::uint32_t random = 0;
  std::array<std::uint8_t, 4> bytes{};
  if (entropy_.fill(MutableByteView{bytes.data(), bytes.size()})) {
    random = (static_cast<std::uint32_t>(bytes[0]) << 24U) |
             (static_cast<std::uint32_t>(bytes[1]) << 16U) |
             (static_cast<std::uint32_t>(bytes[2]) << 8U) | bytes[3];
  }
  const std::uint32_t slots = config_.offer_slots == 0 ? 1 : config_.offer_slots;
  offer->due_ms = now_ms + static_cast<MonotonicMs>(random % slots) * config_.offer_slot_ms;
}

void JoinProxy::send_offer(const PendingOffer& pending, const MonotonicMs now_ms) noexcept {
  if (!open_ || !reachable_ || relay_.active || membership_ != MembershipState::Member) {
    ++stats_.offers_suppressed;
    return;
  }
  ZtOfferBody body{};
  body.density = static_cast<std::uint8_t>(std::min<std::size_t>(offers_.size(), 255));
  body.flags = kZtOfferAuthorityReachable;
  if (now_ms < next_m1_ms_) body.flags |= kZtOfferProxyBusy;
  JoinCookieMaterial material{};
  material.requester_mac = pending.mac;
  material.nonce = pending.nonce;
  material.proxy = config_.node;
  material.network_low32 = config_.network_low32;
  material.bucket = config_.cookie_bucket_ms == 0 ? 0 : now_ms / config_.cookie_bucket_ms;
  if (!cookie_.seal(material, body.cookie) ||
      !entropy_.fill(MutableByteView{body.responder_nonce.data(), body.responder_nonce.size()})) {
    ++stats_.send_failures;
    return;
  }
  body.org_hint = config_.org_hint;
  body.site_hint = config_.site_hint;
  body.authority_hops = hops_;
  body.load = 0;
  ByteBuffer<kZtOfferBodySize> encoded{};
  if (!zt_offer_body_encode(body, encoded)) return;
  if (emit_rld1(pending.mac, pending.nonce, FrameType::Offer, encoded.view())) ++stats_.offers_tx;
}

bool JoinProxy::cookie_valid(const MacAddress& mac, const JoinNonce& nonce,
                             const JoinCookieBytes& cookie, const MonotonicMs now_ms) noexcept {
  JoinCookieMaterial material{};
  material.requester_mac = mac;
  material.nonce = nonce;
  material.proxy = config_.node;
  material.network_low32 = config_.network_low32;
  const std::uint64_t bucket =
      config_.cookie_bucket_ms == 0 ? 0 : now_ms / config_.cookie_bucket_ms;
  // Current and previous bucket only (02 §5).
  for (std::uint64_t back = 0; back < 2 && back <= bucket; ++back) {
    material.bucket = bucket - back;
    JoinCookieBytes expected{};
    if (!cookie_.seal(material, expected)) return false;
    if (constant_time_equal(ByteView{expected.data(), expected.size()},
                            ByteView{cookie.data(), cookie.size()})) {
      return true;
    }
  }
  return false;
}

bool JoinProxy::relay_peer(const MacAddress& source,
                           const autonomy::Rld1Envelope& env) const noexcept {
  return relay_.active && source == relay_.joiner_mac && env.transaction_nonce == relay_.nonce &&
         env.claimed_node == relay_.joiner && env.network_hint == 0 && env.capability_bits == 0;
}

bool JoinProxy::admit_first(const MacAddress& source, const autonomy::Rld1Envelope& env,
                            const JoinCookieBytes& cookie, const std::int8_t rssi,
                            const MonotonicMs now_ms) noexcept {
  if (env.network_hint != 0 || !id_valid(env.claimed_node) || env.capability_bits != 0 ||
      !cookie_valid(source, env.transaction_nonce, cookie, now_ms)) {
    ++stats_.cookie_rejects;
    return false;
  }
  if (relay_.active) {
    if (relay_peer(source, env)) return true;  // step-1 retransmission of this relay
    ++stats_.busy_replies;
    send_relay_status(source, env.transaction_nonce, RelayStatusCode::Busy,
                      config_.busy_retry_after_ms);
    return false;
  }
  if (!reachable_) {
    ++stats_.unreachable_replies;
    send_relay_status(source, env.transaction_nonce, RelayStatusCode::AuthorityUnreachable,
                      config_.busy_retry_after_ms);
    return false;
  }
  if (now_ms < next_m1_ms_) {  // 02 §13: one new m1 per m1_interval
    ++stats_.rate_limited;
    const MonotonicMs wait = next_m1_ms_ - now_ms;
    send_relay_status(source, env.transaction_nonce, RelayStatusCode::Busy,
                      static_cast<std::uint32_t>(std::min<MonotonicMs>(wait, kJoinRetryAfterMaxMs)));
    return false;
  }
  if (next_relay_id_ == 0) {
    std::array<std::uint8_t, 4> bytes{};
    if (entropy_.fill(MutableByteView{bytes.data(), bytes.size()})) {
      next_relay_id_ = (static_cast<std::uint32_t>(bytes[0]) << 24U) |
                       (static_cast<std::uint32_t>(bytes[1]) << 16U) |
                       (static_cast<std::uint32_t>(bytes[2]) << 8U) | bytes[3];
    }
    if (next_relay_id_ == 0) next_relay_id_ = 1;
  }
  slot_.reset();
  relay_ = Relay{};
  relay_.active = true;
  relay_.relay_id = next_relay_id_++;
  if (next_relay_id_ == 0) next_relay_id_ = 1;
  relay_.joiner_mac = source;
  relay_.nonce = env.transaction_nonce;
  relay_.joiner = env.claimed_node;
  relay_.rssi = rssi;
  relay_.started_ms = now_ms;
  // A chunked first object must finish within the device-silence window.
  relay_.device_deadline_ms = now_ms + config_.device_silence_ms;
  next_m1_ms_ = now_ms + config_.m1_interval_ms;
  offers_.clear();
  ++stats_.relays_started;
  return true;
}

void JoinProxy::handle_auth(const MacAddress& source, const autonomy::Rld1Envelope& env,
                            const std::int8_t rssi, const MonotonicMs now_ms) noexcept {
  JoinAuthObject object{};
  if (!join_object_decode(ByteView{env.body.data(), env.body_size}, object) ||
      object.phase == JoinAuthPhase::RelayStatus) {
    ++stats_.frames_rejected;
    return;
  }
  if (object.step == 1) {
    // Both first steps must echo the OFFER cookie on the zero-touch lane.
    if (!object.cookie_present) {
      ++stats_.cookie_rejects;
      return;
    }
    if (!admit_first(source, env, object.cookie, rssi, now_ms)) return;
  } else if (!relay_peer(source, env) || object.phase != relay_.phase) {
    ++stats_.frames_rejected;
    return;
  }
  relay_.rssi = rssi;
  // Newest message wins: the device moved on, so whatever the slot held (a
  // down object being delivered, a stale assembly) is done.
  slot_.release_assembled();
  const MutableByteView buffer = slot_.writable_buffer();
  std::memcpy(buffer.data + kRelayHeaderSize, object.message.data, object.message.size);
  forward_up(object.phase, object.step, kRelayHeaderSize, object.message.size, now_ms);
  if (object.phase == JoinAuthPhase::EdhocMessage && object.step == kJoinEdhocErrorStep) {
    ++stats_.relays_aborted;  // the device ended the exchange with an EDHOC error
    end_relay();
  }
}

void JoinProxy::handle_chunk(const MacAddress& source, const autonomy::Rld1Envelope& env,
                             const std::int8_t rssi, const MonotonicMs now_ms) noexcept {
  JoinChunk chunk{};
  if (!join_chunk_decode(JoinCarrier::Rld1, ByteView{env.body.data(), env.body_size}, chunk) ||
      chunk.id != join_rld1_object_id(env.transaction_nonce)) {
    ++stats_.frames_rejected;
    return;
  }
  if (!relay_peer(source, env)) {
    // Only the offset-0 chunk of a first step may open a relay: its head
    // carries the object prefix and the cookie in the clear, so the cookie
    // is checked before any assembly memory is granted (06 admission §3.2).
    const std::uint8_t* d = chunk.data.data;
    if (chunk.step != 1 || chunk.offset != 0 ||
        chunk.data.size < kJoinObjectHeadSize + kJoinCookieSize ||
        d[0] != autonomy::kPayloadVersion || d[1] != static_cast<std::uint8_t>(chunk.phase) ||
        d[2] != chunk.step || d[3] != 0 || d[4] != 1 || d[5] != 0) {
      ++stats_.frames_rejected;
      return;
    }
    JoinCookieBytes cookie{};
    std::memcpy(cookie.data(), d + kJoinObjectHeadSize, cookie.size());
    if (!admit_first(source, env, cookie, rssi, now_ms)) return;
    relay_.phase = chunk.phase;
  } else if (chunk.phase != relay_.phase) {
    ++stats_.frames_rejected;
    return;
  }
  relay_.rssi = rssi;
  if (slot_.mode() == JoinObjectSlot::Mode::Sending && !relay_.slot_up) {
    slot_.release_assembled();  // the device answered: our down object arrived
  }
  const JoinObjectSlot::Accepted accepted = slot_.accept(JoinCarrier::Rld1, chunk, now_ms);
  if (accepted.send_reply) send_rld1_reply(accepted.reply);
  if (accepted.outcome == JoinObjectSlot::Outcome::Busy ||
      accepted.outcome == JoinObjectSlot::Outcome::Rejected) {
    ++stats_.frames_rejected;
  }
  if (accepted.outcome != JoinObjectSlot::Outcome::Complete) return;
  JoinAuthObject object{};
  std::size_t offset = 0;
  if (!join_object_decode(slot_.assembled(), object) || object.phase != chunk.phase ||
      object.step != chunk.step || !offset_of(slot_, object.message, offset)) {
    ++stats_.frames_rejected;
    slot_.release_assembled();
    return;
  }
  forward_up(object.phase, object.step, offset, object.message.size, now_ms);
  if (object.phase == JoinAuthPhase::EdhocMessage && object.step == kJoinEdhocErrorStep) {
    ++stats_.relays_aborted;
    end_relay();
  }
}

void JoinProxy::handle_reply(const MacAddress& source, const autonomy::Rld1Envelope& env,
                             const MonotonicMs now_ms) noexcept {
  JoinReply reply{};
  if (!relay_peer(source, env) ||
      !join_reply_decode(ByteView{env.body.data(), env.body_size}, reply) || relay_.slot_up) {
    ++stats_.frames_rejected;
    return;
  }
  switch (slot_.on_reply(reply, now_ms)) {
    case JoinObjectSlot::ReplyOutcome::Done:
      if (relay_.final_pending) {  // 02 §7.3: the final down object arrived
        ++stats_.relays_completed;
        end_relay();
      }
      return;
    case JoinObjectSlot::ReplyOutcome::Restart:
      send_due_chunks(now_ms);
      return;
    default:
      return;
  }
}

void JoinProxy::forward_up(const JoinAuthPhase phase, const std::uint8_t step,
                           const std::size_t offset, const std::size_t size,
                           const MonotonicMs now_ms) noexcept {
  const MutableByteView buffer = slot_.writable_buffer();
  if (offset != kRelayHeaderSize) {
    std::memmove(buffer.data + kRelayHeaderSize, buffer.data + offset, size);
  }
  RelayObject object{};
  object.header.dir = RelayDirection::Up;
  object.header.relay_id = relay_.relay_id;
  object.header.proxy = config_.node;
  object.header.joiner_mac = relay_.joiner_mac;
  object.header.phase = phase;
  object.header.step = step;
  object.header.state = RelayState::Continue;
  object.header.joiner_rssi_dbm = relay_.rssi > 0 ? std::int8_t{0} : relay_.rssi;
  object.message = ByteView{buffer.data + kRelayHeaderSize, size};
  std::size_t written = 0;
  if (!relay_object_encode(object, buffer, written)) {
    ++stats_.frames_rejected;
    slot_.release_assembled();
    return;
  }
  relay_.phase = phase;
  relay_.last_step = step;
  relay_.device_deadline_ms = 0;  // now the authority's turn
  relay_.final_pending = false;
  ++stats_.up_objects;
  if (written <= kMaxApplicationPayload) {
    if (!relay_port_.send_relay(config_.gateway, FrameType::BootstrapAuth,
                                ByteView{buffer.data, written})) {
      ++stats_.send_failures;
    }
    slot_.release_assembled();
    relay_.slot_up = false;
    return;
  }
  if (!slot_.load_in_place(JoinCarrier::WireRelay, phase, step, relay_.relay_id, written,
                           now_ms)) {
    slot_.release_assembled();
    return;
  }
  relay_.slot_up = true;
  send_due_chunks(now_ms);
}

void JoinProxy::on_relay_rx(const NodeId from, const FrameType type, const ByteView payload,
                            const MonotonicMs now_ms) noexcept {
  if (!zt_admit_relay(membership_, false, AdmissionDirection::Rx, type, from, config_.gateway) ||
      !relay_.active) {
    ++stats_.frames_rejected;
    return;
  }
  const auto ours = [&](const RelayHeader& h) {
    return h.dir == RelayDirection::Down && h.relay_id == relay_.relay_id &&
           h.proxy == config_.node && h.joiner_mac == relay_.joiner_mac &&
           h.phase == relay_.phase;
  };
  switch (type) {
    case FrameType::BootstrapAuth:
    case FrameType::MembershipResult: {
      RelayObject object{};
      if (!relay_single_frame_decode(type, payload, object) || !ours(object.header)) {
        ++stats_.frames_rejected;
        return;
      }
      // The authority answered: our up object reached it.
      if (relay_.slot_up) {
        slot_.release_assembled();
        relay_.slot_up = false;
      }
      deliver_down(object, now_ms);
      return;
    }
    case FrameType::BootstrapChunk: {
      JoinChunk chunk{};
      if (!join_chunk_decode(JoinCarrier::WireRelay, payload, chunk) ||
          chunk.id != relay_.relay_id || chunk.phase != relay_.phase ||
          join_step_flow(chunk.phase, chunk.step) == JoinFlow::Up) {
        ++stats_.frames_rejected;
        return;
      }
      if (relay_.slot_up && slot_.mode() == JoinObjectSlot::Mode::Sending) {
        slot_.release_assembled();
        relay_.slot_up = false;
      }
      const JoinObjectSlot::Accepted accepted =
          slot_.accept(JoinCarrier::WireRelay, chunk, now_ms);
      if (accepted.send_reply) send_wire_receipt(accepted.reply);
      if (accepted.outcome == JoinObjectSlot::Outcome::Busy ||
          accepted.outcome == JoinObjectSlot::Outcome::Rejected) {
        ++stats_.frames_rejected;
      }
      if (accepted.outcome != JoinObjectSlot::Outcome::Complete) return;
      RelayObject object{};
      if (!relay_object_decode(slot_.assembled(), object) || !ours(object.header) ||
          object.header.step != chunk.step) {
        ++stats_.frames_rejected;
        slot_.release_assembled();
        return;
      }
      deliver_down(object, now_ms);
      return;
    }
    case FrameType::BootstrapReply: {
      JoinReply reply{};
      if (!join_reply_decode(payload, reply) || reply.id != relay_.relay_id || !relay_.slot_up) {
        ++stats_.frames_rejected;
        return;
      }
      switch (slot_.on_reply(reply, now_ms)) {
        case JoinObjectSlot::ReplyOutcome::Done:
          relay_.slot_up = false;
          return;
        case JoinObjectSlot::ReplyOutcome::Restart:
          send_due_chunks(now_ms);
          return;
        default:
          return;
      }
    }
    default:
      ++stats_.frames_rejected;
      return;
  }
}

void JoinProxy::deliver_down(const RelayObject& object, const MonotonicMs now_ms) noexcept {
  ++stats_.down_objects;
  const RelayHeader& h = object.header;
  if (h.state == RelayState::Abort) {
    // The authority/gateway refused or ended it: a hint for the device.
    send_relay_status(relay_.joiner_mac, relay_.nonce, object.abort.status,
                      object.abort.retry_after_ms);
    ++stats_.relays_aborted;
    end_relay();
    return;
  }
  const MutableByteView buffer = slot_.writable_buffer();
  const bool in_slot = object.message.data >= buffer.data &&
                       object.message.data < buffer.data + buffer.size;
  if (!in_slot) slot_.release_assembled();  // single-frame down: the slot is free
  JoinAuthObject down{};
  down.phase = h.phase;
  down.step = h.step;
  down.cookie_present = false;
  down.message = object.message;
  std::size_t written = 0;
  if (!join_object_encode(down, buffer, written)) {
    ++stats_.frames_rejected;
    slot_.release_assembled();
    return;
  }
  relay_.last_step = h.step;
  relay_.final_pending = h.state == RelayState::Final;
  relay_.slot_up = false;
  if (written <= autonomy::kRld1MaxBody) {
    (void)emit_rld1(relay_.joiner_mac, relay_.nonce, FrameType::BootstrapAuth,
                    ByteView{buffer.data, written});
    slot_.release_assembled();
    if (relay_.final_pending) {
      ++stats_.relays_completed;
      end_relay();
      return;
    }
  } else {
    if (!slot_.load_in_place(JoinCarrier::Rld1, h.phase, h.step,
                             join_rld1_object_id(relay_.nonce), written, now_ms)) {
      slot_.release_assembled();
      return;
    }
    send_due_chunks(now_ms);
  }
  // Continue: the device must answer within the silence window.
  if (!relay_.final_pending) relay_.device_deadline_ms = now_ms + config_.device_silence_ms;
}

void JoinProxy::send_relay_status(const MacAddress& mac, const JoinNonce& nonce,
                                  const RelayStatusCode status,
                                  const std::uint32_t retry_after_ms) noexcept {
  JoinAuthObject object{};
  object.phase = JoinAuthPhase::RelayStatus;
  object.step = 1;
  object.relay_status = status;
  object.retry_after_ms = std::min(retry_after_ms, kJoinRetryAfterMaxMs);
  std::array<std::uint8_t, kRelayStatusObjectSize> body{};
  std::size_t written = 0;
  if (join_object_encode(object, MutableByteView{body.data(), body.size()}, written)) {
    (void)emit_rld1(mac, nonce, FrameType::BootstrapAuth, ByteView{body.data(), written});
  }
}

void JoinProxy::send_rld1_reply(const JoinReply& reply) noexcept {
  std::array<std::uint8_t, kJoinReplySize> body{};
  std::size_t written = 0;
  if (join_reply_encode(reply, MutableByteView{body.data(), body.size()}, written)) {
    (void)emit_rld1(relay_.joiner_mac, relay_.nonce, FrameType::BootstrapReply,
                    ByteView{body.data(), written});
  }
}

void JoinProxy::send_wire_receipt(const JoinReply& reply) noexcept {
  std::array<std::uint8_t, kJoinReplySize> body{};
  std::size_t written = 0;
  if (join_reply_encode(reply, MutableByteView{body.data(), body.size()}, written) &&
      !relay_port_.send_relay(config_.gateway, FrameType::BootstrapReply,
                              ByteView{body.data(), written})) {
    ++stats_.send_failures;
  }
}

void JoinProxy::send_due_chunks(const MonotonicMs now_ms) noexcept {
  if (slot_.mode() != JoinObjectSlot::Mode::Sending) return;
  const JoinCarrier carrier = relay_.slot_up ? JoinCarrier::WireRelay : JoinCarrier::Rld1;
  const std::uint16_t mask = slot_.pending_mask();
  for (std::size_t i = 0; i < slot_.chunk_total(); ++i) {
    if ((mask & (1U << i)) == 0) continue;
    JoinChunk chunk{};
    if (!slot_.chunk_at(i, chunk)) continue;
    std::array<std::uint8_t, kMaxApplicationPayload> body{};
    std::size_t written = 0;
    if (!join_chunk_encode(carrier, chunk, MutableByteView{body.data(), body.size()}, written)) {
      continue;
    }
    if (relay_.slot_up) {
      if (!relay_port_.send_relay(config_.gateway, FrameType::BootstrapChunk,
                                  ByteView{body.data(), written})) {
        ++stats_.send_failures;
      }
    } else {
      (void)emit_rld1(relay_.joiner_mac, relay_.nonce, FrameType::BootstrapChunk,
                      ByteView{body.data(), written});
    }
  }
  slot_.note_sent(now_ms);
}

void JoinProxy::abort_relay(const RelayStatusCode device_status,
                            const bool notify_gateway) noexcept {
  if (!relay_.active) return;
  if (notify_gateway && membership_ == MembershipState::Member && id_valid(config_.gateway)) {
    RelayObject object{};
    object.header.dir = RelayDirection::Up;
    object.header.relay_id = relay_.relay_id;
    object.header.proxy = config_.node;
    object.header.joiner_mac = relay_.joiner_mac;
    object.header.phase = relay_.phase;
    object.header.step = first_step(relay_.phase, relay_.last_step);
    object.header.state = RelayState::Abort;
    object.header.joiner_rssi_dbm = relay_.rssi > 0 ? std::int8_t{0} : relay_.rssi;
    object.abort.status = RelayStatusCode::Aborted;
    std::array<std::uint8_t, kRelayHeaderSize + kRelayAbortBodySize> body{};
    std::size_t written = 0;
    if (relay_object_encode(object, MutableByteView{body.data(), body.size()}, written) &&
        !relay_port_.send_relay(config_.gateway, relay_single_frame_type(object.header),
                                ByteView{body.data(), written})) {
      ++stats_.send_failures;
    }
  }
  send_relay_status(relay_.joiner_mac, relay_.nonce, device_status, 0);
  ++stats_.relays_aborted;
  end_relay();
}

void JoinProxy::end_relay() noexcept {
  relay_ = Relay{};
  slot_.reset();
}

void JoinProxy::poll(const MonotonicMs now_ms) noexcept {
  for (std::size_t guard = 0; guard < kPendingOffers; ++guard) {
    PendingOffer* due = offers_.find([&](const PendingOffer& offer) {
      return offer.due_ms <= now_ms;
    });
    if (due == nullptr) break;
    const PendingOffer offer = *due;
    offers_.release(due);
    send_offer(offer, now_ms);
  }
  if (!relay_.active) return;
  if (now_ms - relay_.started_ms >= config_.relay_timeout_ms ||
      (relay_.device_deadline_ms != 0 && now_ms >= relay_.device_deadline_ms)) {
    abort_relay(RelayStatusCode::Aborted, true);  // 02 §7.3: 20 s cap / 5 s device silence
    return;
  }
  (void)slot_.expire(now_ms, config_.assembly_timeout_ms);
  if (slot_.mode() != JoinObjectSlot::Mode::Sending ||
      now_ms - slot_.last_send_ms() < config_.retransmit_ms) {
    return;
  }
  if (slot_.sends() >= config_.max_sends) {
    abort_relay(RelayStatusCode::Aborted, true);
    return;
  }
  ++stats_.retransmissions;
  send_due_chunks(now_ms);
}

// ===================================================================================
// JoinRelayGateway
// ===================================================================================

JoinRelayGateway::JoinRelayGateway(const JoinRelayGatewayConfig& config,
                                   ZtRelayPort& wire) noexcept
    : config_(config), wire_(wire) {}

void JoinRelayGateway::set_membership(const MembershipState state) noexcept {
  membership_ = state;
  if (state != MembershipState::Member) {
    for (Slot& slot : slots_) free_slot(slot);
    for (Recent& recent : recent_) recent = Recent{};
  }
}

std::size_t JoinRelayGateway::slots_in_use() const noexcept {
  std::size_t used = 0;
  for (const Slot& slot : slots_) used += slot.active ? 1U : 0U;
  return used;
}

JoinRelayGateway::Slot* JoinRelayGateway::find(const NodeId proxy,
                                               const std::uint32_t relay_id) noexcept {
  for (Slot& slot : slots_) {
    if (slot.active && slot.proxy == proxy && slot.relay_id == relay_id) return &slot;
  }
  return nullptr;
}

JoinRelayGateway::Slot* JoinRelayGateway::allocate(const NodeId proxy,
                                                   const std::uint32_t relay_id) noexcept {
  Slot* chosen = nullptr;
  for (Slot& slot : slots_) {
    if (!slot.active) {
      chosen = &slot;
      break;
    }
  }
  if (chosen == nullptr) {
    // A slot that only remembers a completed object may be reclaimed.
    for (Slot& slot : slots_) {
      if (slot.object.mode() == JoinObjectSlot::Mode::Idle) {
        chosen = &slot;
        break;
      }
    }
  }
  if (chosen == nullptr) return nullptr;
  chosen->object.reset();
  chosen->active = true;
  chosen->down = false;
  chosen->proxy = proxy;
  chosen->relay_id = relay_id;
  chosen->hops = 0;
  return chosen;
}

void JoinRelayGateway::free_slot(Slot& slot) noexcept {
  slot.object.reset();
  slot.active = false;
  slot.down = false;
  slot.proxy = kInvalidNodeId;
  slot.relay_id = 0;
  slot.hops = 0;
}

JoinRelayGateway::Recent* JoinRelayGateway::find_recent(
    const NodeId proxy, const std::uint32_t relay_id) noexcept {
  for (Recent& recent : recent_) {
    if (recent.valid && recent.proxy == proxy && recent.relay_id == relay_id) return &recent;
  }
  return nullptr;
}

const JoinRelayGateway::Recent* JoinRelayGateway::find_recent(
    const NodeId proxy, const std::uint32_t relay_id) const noexcept {
  for (const Recent& recent : recent_) {
    if (recent.valid && recent.proxy == proxy && recent.relay_id == relay_id) return &recent;
  }
  return nullptr;
}

void JoinRelayGateway::abort_slot(Slot& slot, const RelayAbortReason reason) noexcept {
  const NodeId proxy = slot.proxy;
  const std::uint32_t relay_id = slot.relay_id;
  // The callback may re-enter the gateway (a host_down re-opens this or
  // another relay, possibly in this very slot; a host_abort clears it):
  // drop the recent entry only while it is still the reported one, and
  // the slot only while it still holds the reported occupant.
  const Recent* written = find_recent(proxy, relay_id);
  const std::uint32_t epoch = written != nullptr ? written->epoch : 0;
  const std::uint32_t occupant = slot.object.generation();
  if (sink_ != nullptr) (void)sink_->relay_abort(proxy, relay_id, reason);
  const Recent* current = find_recent(proxy, relay_id);
  if (current == written && (current == nullptr || current->epoch == epoch)) {
    forget(proxy, relay_id);
  }
  if (slot.object.generation() == occupant) free_slot(slot);
}

void JoinRelayGateway::remember(const NodeId proxy, const RelayHeader& header,
                                const MonotonicMs now_ms) noexcept {
  Recent* target = find_recent(proxy, header.relay_id);
  if (target == nullptr) {
    for (Recent& recent : recent_) {
      if (!recent.valid) {
        target = &recent;
        break;
      }
    }
  }
  if (target == nullptr) {
    target = &recent_[0];
    for (Recent& recent : recent_) {
      if (recent.seen_ms < target->seen_ms) target = &recent;
    }
  }
  target->valid = true;
  target->proxy = proxy;
  target->relay_id = header.relay_id;
  target->joiner_mac = header.joiner_mac;
  target->phase = header.phase;
  target->step = header.step;
  if (header.dir == RelayDirection::Up) target->up_sub = join_sub(header.phase, header.step);
  ++target->epoch;
  target->seen_ms = now_ms;
}

void JoinRelayGateway::forget(const NodeId proxy, const std::uint32_t relay_id) noexcept {
  if (Recent* entry = find_recent(proxy, relay_id)) {
    // The epoch survives the clear: an entry re-created at this slot
    // can never collide with the writer the callbacks were told about.
    const std::uint32_t epoch = entry->epoch;
    *entry = Recent{};
    entry->epoch = epoch;
  }
}

std::uint8_t JoinRelayGateway::last_up_sub(const NodeId proxy,
                                           const std::uint32_t relay_id) const noexcept {
  const Recent* entry = find_recent(proxy, relay_id);
  return entry != nullptr ? entry->up_sub : 0;
}

void JoinRelayGateway::send_reply(const NodeId to, const JoinReply& reply) noexcept {
  std::array<std::uint8_t, kJoinReplySize> body{};
  std::size_t written = 0;
  if (join_reply_encode(reply, MutableByteView{body.data(), body.size()}, written)) {
    (void)wire_.send_relay(to, FrameType::BootstrapReply, ByteView{body.data(), written});
  }
}

void JoinRelayGateway::send_down_abort(const NodeId proxy, const RelayHeader& up,
                                       const RelayStatusCode status,
                                       const std::uint32_t retry_after_ms) noexcept {
  RelayObject object{};
  object.header = up;
  object.header.dir = RelayDirection::Down;
  object.header.proxy = proxy;
  object.header.state = RelayState::Abort;
  object.header.joiner_rssi_dbm = 0;
  object.abort.status = status;
  object.abort.retry_after_ms = std::min(retry_after_ms, kJoinRetryAfterMaxMs);
  std::array<std::uint8_t, kRelayHeaderSize + kRelayAbortBodySize> body{};
  std::size_t written = 0;
  if (relay_object_encode(object, MutableByteView{body.data(), body.size()}, written)) {
    (void)wire_.send_relay(proxy, relay_single_frame_type(object.header),
                           ByteView{body.data(), written});
  }
}

void JoinRelayGateway::deliver_up(const NodeId proxy, const std::uint8_t hops,
                                  const RelayObject& object, const ByteView bytes,
                                  const MonotonicMs now_ms) noexcept {
  const RelayHeader& h = object.header;
  if (h.state == RelayState::Abort) {
    ++stats_.proxy_aborts;
    // Forget before the call: the relay is already over, so a reentrant
    // host_abort is NotFound and a reentrant host_down starts fresh.
    forget(proxy, h.relay_id);
    if (sink_ != nullptr) (void)sink_->relay_abort(proxy, h.relay_id, RelayAbortReason::ProxyAborted);
    return;
  }
  remember(proxy, h, now_ms);
  ++stats_.up_objects;
  const Recent* written = find_recent(proxy, h.relay_id);
  const std::uint32_t epoch = written != nullptr ? written->epoch : 0;
  if (sink_ == nullptr || !sink_->relay_up(proxy, hops, bytes)) {
    // 07 §7: no host -> the proxy tells the device authority_unreachable.
    ++stats_.host_unavailable;
    // A callback that re-entered for this relay (a fresh host_down, a
    // host_abort) already installed or cleared the bookkeeping — the
    // abort and the forget would only tear down what it started.
    const Recent* current = find_recent(proxy, h.relay_id);
    if (current == written && (current == nullptr || current->epoch == epoch)) {
      send_down_abort(proxy, h, RelayStatusCode::AuthorityUnreachable,
                      config_.unreachable_retry_ms);
      forget(proxy, h.relay_id);
    }
  }
}

void JoinRelayGateway::on_relay_rx(const NodeId from, const std::uint8_t hops,
                                   const FrameType type, const ByteView payload,
                                   const MonotonicMs now_ms) noexcept {
  if (from == config_.node ||
      !zt_admit_relay(membership_, true, AdmissionDirection::Rx, type, from, config_.node)) {
    ++stats_.frames_rejected;
    return;
  }
  switch (type) {
    case FrameType::BootstrapAuth: {
      RelayObject object{};
      if (!relay_single_frame_decode(type, payload, object) ||
          object.header.dir != RelayDirection::Up || object.header.proxy != from) {
        ++stats_.frames_rejected;
        return;
      }
      // A duplicate of an up stage already handed to the host is dropped
      // without touching the slot: only a NEW up stage ends a down
      // object we are still sending (single frames have no receipt).
      if (object.header.state == RelayState::Continue &&
          join_sub(object.header.phase, object.header.step) <=
              last_up_sub(from, object.header.relay_id)) {
        ++stats_.frames_rejected;
        return;
      }
      // The proxy moved on: a down object we were still sending arrived, and
      // a stale partial up assembly of this relay is obsolete.
      if (Slot* slot = find(from, object.header.relay_id)) free_slot(*slot);
      deliver_up(from, hops, object, payload, now_ms);
      return;
    }
    case FrameType::BootstrapChunk: {
      JoinChunk chunk{};
      if (!join_chunk_decode(JoinCarrier::WireRelay, payload, chunk) ||
          join_step_flow(chunk.phase, chunk.step) == JoinFlow::Down) {
        ++stats_.frames_rejected;
        return;
      }
      Slot* slot = find(from, chunk.id);
      if (slot != nullptr && slot->down &&
          slot->object.mode() == JoinObjectSlot::Mode::Sending) {
        // Only a NEW up stage displaces our down object (it reached the
        // device): a retransmitted duplicate of the delivered one
        // re-earns its Complete reply through the completed-key memory
        // kept in this slot, a stale one stays refused.
        const JoinObjectSlot::Accepted probe =
            slot->object.accept(JoinCarrier::WireRelay, chunk, now_ms);
        if (probe.outcome == JoinObjectSlot::Outcome::Repeat) {
          send_reply(from, probe.reply);
          return;
        }
        if (probe.outcome != JoinObjectSlot::Outcome::Busy ||
            join_sub(chunk.phase, chunk.step) <= last_up_sub(from, chunk.id)) {
          ++stats_.frames_rejected;
          return;
        }
      }
      if (slot != nullptr && slot->down) {
        free_slot(*slot);  // implicit receipt of our down object
        slot = nullptr;
      }
      if (slot == nullptr) slot = allocate(from, chunk.id);
      if (slot == nullptr) {
        ++stats_.slot_busy;
        return;
      }
      slot->hops = hops;
      const JoinObjectSlot::Accepted accepted =
          slot->object.accept(JoinCarrier::WireRelay, chunk, now_ms);
      if (accepted.send_reply) send_reply(from, accepted.reply);
      if (accepted.outcome == JoinObjectSlot::Outcome::Busy ||
          accepted.outcome == JoinObjectSlot::Outcome::Rejected) {
        ++stats_.frames_rejected;
      }
      if (accepted.outcome != JoinObjectSlot::Outcome::Complete) return;
      RelayObject object{};
      const ByteView bytes = slot->object.assembled();
      if (!relay_object_decode(bytes, object) || object.header.dir != RelayDirection::Up ||
          object.header.proxy != from || object.header.relay_id != chunk.id ||
          object.header.phase != chunk.phase || object.header.step != chunk.step) {
        ++stats_.frames_rejected;
        slot->object.release_assembled();
        return;
      }
      if (object.header.state == RelayState::Continue &&
          join_sub(object.header.phase, object.header.step) <=
              last_up_sub(from, chunk.id)) {
        // A stale object re-assembled (not newer than the stage
        // delivered last): its Complete reply already went out above —
        // drop it like a single-frame duplicate.
        slot->object.release_assembled();
        return;
      }
      // The sink callback inside deliver_up may re-enter the gateway (a
      // host_down for this relay installs a Sending object, possibly in
      // this very slot): release only the object that was delivered.
      const std::uint32_t delivered = slot->object.generation();
      deliver_up(from, hops, object, bytes, now_ms);
      // Keep only the completed key (Repeat of a lost receipt); the slot is
      // reclaimable from now on.
      slot->object.release_assembled_if(delivered);
      return;
    }
    case FrameType::BootstrapReply: {
      JoinReply reply{};
      Slot* slot = nullptr;
      if (!join_reply_decode(payload, reply) || (slot = find(from, reply.id)) == nullptr ||
          !slot->down) {
        ++stats_.frames_rejected;
        return;
      }
      switch (slot->object.on_reply(reply, now_ms)) {
        case JoinObjectSlot::ReplyOutcome::Done:
          free_slot(*slot);
          return;
        case JoinObjectSlot::ReplyOutcome::Restart:
          (void)send_due_chunks(*slot, now_ms);
          return;
        default:
          return;
      }
    }
    default:
      ++stats_.frames_rejected;
      return;
  }
}

Status JoinRelayGateway::send_due_chunks(Slot& slot, const MonotonicMs now_ms) noexcept {
  Status first_failure = Status::success();
  const std::uint16_t mask = slot.object.pending_mask();
  for (std::size_t i = 0; i < slot.object.chunk_total(); ++i) {
    if ((mask & (1U << i)) == 0) continue;
    JoinChunk chunk{};
    if (!slot.object.chunk_at(i, chunk)) continue;
    std::array<std::uint8_t, kMaxApplicationPayload> body{};
    std::size_t written = 0;
    Status status = join_chunk_encode(JoinCarrier::WireRelay, chunk,
                                      MutableByteView{body.data(), body.size()}, written);
    if (status) {
      status = wire_.send_relay(slot.proxy, FrameType::BootstrapChunk,
                                ByteView{body.data(), written});
    }
    if (!status && first_failure) first_failure = status;
  }
  slot.object.note_sent(now_ms);
  return first_failure;
}

Status JoinRelayGateway::host_down(const NodeId to_proxy, const ByteView object,
                                   const MonotonicMs now_ms) noexcept {
  if (membership_ != MembershipState::Member) {
    return Status::error(StatusCode::InvalidState, "gateway is not a member");
  }
  RelayObject decoded{};
  Status status = relay_object_decode(object, decoded);
  if (!status) return status;
  const RelayHeader& h = decoded.header;
  if (h.dir != RelayDirection::Down || h.proxy != to_proxy || to_proxy == config_.node) {
    return invalid("relay down header");
  }
  status = zt_admit_relay(membership_, true, AdmissionDirection::Tx,
                          object.size <= kMaxApplicationPayload ? relay_single_frame_type(h)
                                                                : FrameType::BootstrapChunk,
                          to_proxy, config_.node);
  if (!status) return status;
  if (object.size <= kMaxApplicationPayload) {
    status = wire_.send_relay(to_proxy, relay_single_frame_type(h), object);
    if (!status) return status;
    if (Slot* slot = find(to_proxy, h.relay_id)) free_slot(*slot);
  } else {
    Slot* slot = find(to_proxy, h.relay_id);
    if (slot != nullptr) {
      // The host answered: any partial up object is moot — but the
      // completed-key memory stays, so retransmitted up chunks re-earn
      // their Complete reply instead of displacing this send.
      slot->object.release_assembled();
      slot->down = true;
      slot->hops = 0;
    } else {
      slot = allocate(to_proxy, h.relay_id);
      if (slot == nullptr) {
        ++stats_.slot_busy;
        return Status::error(StatusCode::NoCapacity, "no relay slot");
      }
      slot->down = true;
    }
    status = slot->object.load(JoinCarrier::WireRelay, h.phase, h.step, h.relay_id, object,
                               now_ms);
    if (status) status = send_due_chunks(*slot, now_ms);
    if (!status) {
      free_slot(*slot);
      return status;
    }
  }
  ++stats_.down_objects;
  if (h.state == RelayState::Continue) {
    remember(to_proxy, h, now_ms);
  } else {
    forget(to_proxy, h.relay_id);
  }
  return Status::success();
}

Status JoinRelayGateway::host_abort(const NodeId proxy, const std::uint32_t relay_id,
                                    const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (membership_ != MembershipState::Member) {
    return Status::error(StatusCode::InvalidState, "gateway is not a member");
  }
  const Recent* known = find_recent(proxy, relay_id);
  if (known == nullptr) return Status::error(StatusCode::NotFound, "relay not known");
  RelayHeader header{};
  header.dir = RelayDirection::Down;
  header.relay_id = relay_id;
  header.proxy = proxy;
  header.joiner_mac = known->joiner_mac;
  header.phase = known->phase;
  header.step = first_step(known->phase, known->step);
  RelayObject object{};
  object.header = header;
  object.header.state = RelayState::Abort;
  object.abort.status = RelayStatusCode::Aborted;
  std::array<std::uint8_t, kRelayHeaderSize + kRelayAbortBodySize> body{};
  std::size_t written = 0;
  Status status = relay_object_encode(object, MutableByteView{body.data(), body.size()}, written);
  if (status) {
    status = wire_.send_relay(proxy, relay_single_frame_type(object.header),
                              ByteView{body.data(), written});
  }
  if (!status) return status;
  ++stats_.host_aborts;
  forget(proxy, relay_id);
  if (Slot* slot = find(proxy, relay_id)) free_slot(*slot);
  return Status::success();
}

void JoinRelayGateway::poll(const MonotonicMs now_ms) noexcept {
  for (Slot& slot : slots_) {
    if (!slot.active) continue;
    if (slot.object.expire(now_ms, config_.assembly_timeout_ms)) {
      ++stats_.expired;
      abort_slot(slot, RelayAbortReason::GatewayExpired);
      continue;
    }
    if (!slot.down || slot.object.mode() != JoinObjectSlot::Mode::Sending ||
        now_ms - slot.object.last_send_ms() < config_.retransmit_ms) {
      continue;
    }
    if (slot.object.sends() >= config_.max_sends) {
      ++stats_.delivery_failed;
      abort_slot(slot, RelayAbortReason::DeliveryFailed);
      continue;
    }
    ++stats_.retransmissions;
    (void)send_due_chunks(slot, now_ms);
  }
}

}  // namespace routeloom::sdkv1
