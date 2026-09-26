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

// Up-stage slot in ActiveRelay::accepted_up_mask: steps (1, 3, 5) -> (0, 1, 2).
std::uint8_t up_stage_slot(const std::uint8_t step) noexcept {
  if (step == 1) return 0;
  if (step == 3) return 1;
  return 2;  // step 5 (EDHOC error); callers only pass up steps
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

Status HmacJoinCookie::install_key(const std::array<std::uint8_t, 32>& key) noexcept {
  if (keyed_) return Status::error(StatusCode::InvalidState, "cookie sealer already keyed");
  bool nonzero = false;
  for (const std::uint8_t byte : key) nonzero = nonzero || (byte != 0);
  if (!nonzero) return Status::error(StatusCode::InvalidArgument, "cookie key is zero");
  key_ = key;
  keyed_ = true;
  return Status::success();
}

Status HmacJoinCookie::seal(const JoinCookieMaterial& material, JoinCookieBytes& out) noexcept {
  if (!keyed_) return Status::error(StatusCode::InvalidState, "cookie sealer unkeyed");
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

Status ZtJoinerLink::set_membership(const MembershipState state) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in link callback");
  membership_ = state;
  return Status::success();
}

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
  if (in_call_) return Status::error(StatusCode::Busy, "in link callback");
  in_call_ = true;
  const Status result = discover_impl(body, now_ms);
  in_call_ = false;
  return result;
}

Status ZtJoinerLink::discover_impl(const ZtDiscoverBody& body,
                                    const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (!id_valid(config_.node)) return invalid("zt joiner node");
  ByteBuffer<kZtDiscoverBodySize> encoded{};
  Status status = zt_discover_body_encode(body, encoded);
  if (!status) return status;
  close_impl();
  // The nonce's first four bytes are the chunk object id: a zero id
  // collides with "no object", so redraw (at most four draws) instead of
  // patching the bytes.
  status = Status::error(StatusCode::InternalError, "zt discover entropy");
  for (int draw = 0; draw < 4; ++draw) {
    status = entropy_.fill(MutableByteView{nonce_.data(), nonce_.size()});
    if (!status) return status;
    if (join_rld1_object_id(nonce_) != 0) break;
    status = Status::error(StatusCode::InternalError, "zt discover nonce");
  }
  if (!status || join_rld1_object_id(nonce_) == 0) return status;
  discover_org_hint_ = body.org_hint;
  discovering_ = true;
  status = emit(kBroadcastMac, FrameType::Discover, encoded.view());
  if (status) ++stats_.discovers_tx;
  return status;
}

Status ZtJoinerLink::connect(const ZtOfferView& offer) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in link callback");
  in_call_ = true;
  const Status result = connect_impl(offer);
  in_call_ = false;
  return result;
}

Status ZtJoinerLink::connect_impl(const ZtOfferView& offer) noexcept {
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

Status ZtJoinerLink::close() noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in link callback");
  close_impl();
  return Status::success();
}

void ZtJoinerLink::close_impl() noexcept {
  discovering_ = false;
  discover_org_hint_ = 0;
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
  if (in_call_) return Status::error(StatusCode::Busy, "in link callback");
  in_call_ = true;
  const Status result = send_impl(phase, step, message, now_ms);
  in_call_ = false;
  return result;
}

Status ZtJoinerLink::send_impl(const JoinAuthPhase phase, const std::uint8_t step,
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
    status = slot_.load_in_place(JoinCarrier::Rld1, phase, step, join_rld1_object_id(nonce_), 0, 0,
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
  if (join_reply_encode(JoinCarrier::Rld1, reply, MutableByteView{body.data(), body.size()},
                        written)) {
    (void)emit(proxy_mac_, FrameType::BootstrapReply, ByteView{body.data(), written});
  }
}

bool ZtJoinerLink::from_proxy(const MacAddress& source,
                              const autonomy::Rld1Envelope& env) const noexcept {
  return connected_ && source == proxy_mac_ && env.transaction_nonce == nonce_ &&
         env.claimed_node == proxy_ && env.network_hint == network_low32_ &&
         env.capability_bits == 0;
}

Status ZtJoinerLink::on_rld1_rx(const MacAddress& source, const MacAddress& destination,
                                const ByteView frame, const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in link callback");
  in_call_ = true;
  on_rld1_rx_impl(source, destination, frame, now_ms);
  in_call_ = false;
  return Status::success();
}

void ZtJoinerLink::on_rld1_rx_impl(const MacAddress& source, const MacAddress& destination,
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
      if (offer.body.org_hint != discover_org_hint_) {  // 02 §11 rule 1
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
      if (chunk.total > kJoinObjectHeadSize + kJoinMessageMax) {
        ++stats_.frames_rejected;
        return;
      }
      JoinObjectSlot::Accepted accepted = slot_.accept(JoinCarrier::Rld1, chunk, now_ms);
      if (accepted.outcome == JoinObjectSlot::Outcome::Busy &&
          slot_.mode() == JoinObjectSlot::Mode::Sending &&
          join_sub(chunk.phase, chunk.step) > last_down_sub_ && chunk.offset == 0 &&
          chunk.data.size >= kJoinObjectHeadSize + 1 &&
          chunk.data.data[0] == autonomy::kPayloadVersion &&
          chunk.data.data[1] == static_cast<std::uint8_t>(chunk.phase) &&
          chunk.data.data[2] == chunk.step && chunk.data.data[3] == 0 &&
          chunk.data.data[4] == 0 && chunk.data.data[5] == 0) {
        // Only a NEW down object displaces our Sending object (it reached
        // the proxy): a duplicate of the delivered one re-earns its
        // Complete reply above, a stale one stays refused.
        slot_.release_assembled();
        accepted = slot_.accept(JoinCarrier::Rld1, chunk, now_ms);
      }
      if (accepted.send_reply && accepted.outcome != JoinObjectSlot::Outcome::Complete)
        send_reply(accepted.reply);
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
        slot_.reset();
        return;
      }
      send_reply(accepted.reply);
      const std::uint8_t sub = join_sub(object.phase, object.step);
      if (sub <= last_down_sub_) {
        // A stale object re-assembled (older than the stage delivered
        // last): drop it like a single-frame duplicate.
        slot_.release_assembled();
        return;
      }
      ++stats_.messages_rx;
      last_down_sub_ = sub;
      observer_.on_message(object.phase, object.step, object.message);
      slot_.release_assembled();
      return;
    }
    case FrameType::BootstrapReply: {
      JoinReply reply{};
      if (!from_proxy(source, env) || !join_reply_decode(JoinCarrier::Rld1, body, reply)) {
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

Status ZtJoinerLink::poll(const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in link callback");
  in_call_ = true;
  poll_impl(now_ms);
  in_call_ = false;
  return Status::success();
}

void ZtJoinerLink::poll_impl(const MonotonicMs now_ms) noexcept {
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
    : config_(config),
      rld1_(rld1),
      relay_port_(relay),
      cookie_(cookie),
      entropy_(entropy),
      config_valid_(id_valid(config.node) && id_valid(config.gateway) &&
                    (config.node != config.gateway || config.colocated_gateway) &&
                    config.network_low32 != 0 && config.proxy_epoch != 0 &&
                    config.cookie_bucket_ms != 0 &&
                    config.offer_slots != 0 && config.offer_slot_ms != 0 &&
                    config.m1_interval_ms != 0 && config.relay_timeout_ms != 0 &&
                    config.device_silence_ms != 0 && config.assembly_timeout_ms != 0 &&
                    config.retransmit_ms != 0 && config.max_sends != 0) {}

Status JoinProxy::set_policy(const bool zero_touch_open) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in port callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "proxy epoch");
  open_ = zero_touch_open;
  return Status::success();
}

Status JoinProxy::set_authority(const bool reachable, const std::uint8_t hops,
                                const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in port callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "proxy epoch");
  if (now_ms < last_now_ms_) return Status::error(StatusCode::TimeUncertain, "clock regressed");
  last_now_ms_ = now_ms;
  in_call_ = true;
  reachable_ = reachable;
  hops_ = hops;
  // Without a path to the authority the relay cannot finish: tell the device
  // (a hint it waits on) and stop. The gateway cannot be told either.
  if (!reachable && relay_.active) abort_relay(RelayStatusCode::AuthorityUnreachable, false);
  in_call_ = false;
  return Status::success();
}

Status JoinProxy::set_membership(const MembershipState state, const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in port callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "proxy epoch");
  if (now_ms < last_now_ms_) return Status::error(StatusCode::TimeUncertain, "clock regressed");
  last_now_ms_ = now_ms;
  in_call_ = true;
  const bool was_member = membership_ == MembershipState::Member;
  if (state != MembershipState::Member && was_member) {
    // 02 §7.3: own membership revoked / GK unknown -> stop relaying and
    // offering. The RelayStatus still leaves while the lane is open.
    abort_relay(RelayStatusCode::Aborted, false);
    offers_.clear();
  }
  membership_ = state;
  in_call_ = false;
  return Status::success();
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

Status JoinProxy::on_rld1_rx(const MacAddress& source, const MacAddress& destination,
                                 const std::int8_t rssi_dbm, const ByteView frame,
                                 const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in port callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "proxy epoch");
  if (now_ms < last_now_ms_) return Status::error(StatusCode::TimeUncertain, "clock regressed");
  last_now_ms_ = now_ms;
  in_call_ = true;
  autonomy::Rld1Envelope env{};
  if (!autonomy::rld1_decode(frame, env) || !zt_rld1_frame(env)) {
    in_call_ = false;
    return Status::success();  // not this lane
  }
  if (!zt_admit_rld1(membership_, AdmissionDirection::Rx, env)) {
    ++stats_.frames_rejected;
    in_call_ = false;
    return Status::success();
  }
  switch (env.kind) {
    case FrameType::Discover:
      handle_discover(source, destination, frame, now_ms);
      break;
    case FrameType::BootstrapAuth:
      handle_auth(source, env, rssi_dbm, now_ms);
      break;
    case FrameType::BootstrapChunk:
      handle_chunk(source, env, rssi_dbm, now_ms);
      break;
    case FrameType::BootstrapReply:
      handle_reply(source, env, now_ms);
      break;
    default:
      ++stats_.frames_rejected;
      break;
  }
  in_call_ = false;
  return Status::success();
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
  // An OFFER may lead to a relay, which needs the gateway's epoch: a
  // DISCOVER creates the need when the cache is missing (#116 §3.3).
  need_gateway_epoch(now_ms);
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
  const MonotonicMs delay = static_cast<MonotonicMs>(random % slots) * config_.offer_slot_ms;
  if (delay > ~MonotonicMs{0} - now_ms) {
    offers_.release(offer);
    ++stats_.offers_suppressed;
    return;
  }
  offer->due_ms = now_ms + delay;
}

void JoinProxy::send_offer(const PendingOffer& pending, const MonotonicMs now_ms) noexcept {
  if (!open_ || !reachable_ || relay_.active || membership_ != MembershipState::Member) {
    ++stats_.offers_suppressed;
    return;
  }
  ZtOfferBody body{};
  body.density = static_cast<std::uint8_t>(std::min<std::size_t>(offers_.size(), 255));
  // Authority-reachable only with a live gateway epoch whose reply said
  // ready; without it the device should prefer another proxy and retry
  // discovery later (#116 §3.3).
  body.flags = 0;
  if (reachable_ && epoch_cache_valid(now_ms) && gateway_ready_) {
    body.flags |= kZtOfferAuthorityReachable;
  }
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
  // The relay rides the gateway incarnation in the cache: without it the
  // device retries (and the query this DISCOVER started may fill it); a
  // ready=0 gateway has no host, so the device looks elsewhere (#116 §3.3).
  if (!epoch_cache_valid(now_ms)) {
    ++stats_.busy_replies;
    need_gateway_epoch(now_ms);
    send_relay_status(source, env.transaction_nonce, RelayStatusCode::Busy,
                      config_.busy_retry_after_ms);
    return false;
  }
  if (!gateway_ready_) {
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
  // Relay ids are strictly increasing within proxy_epoch from 1, never
  // reused after a failure, never wrapped: after UINT32_MAX the proxy seat
  // is exhausted until the Owner reserves a new epoch (#116 §3.1).
  if (relay_ids_exhausted_) {
    ++stats_.busy_replies;
    send_relay_status(source, env.transaction_nonce, RelayStatusCode::Busy,
                      config_.busy_retry_after_ms);
    return false;
  }
  if (now_ms > ~MonotonicMs{0} - config_.relay_timeout_ms ||
      now_ms > ~MonotonicMs{0} - config_.device_silence_ms ||
      now_ms > ~MonotonicMs{0} - config_.m1_interval_ms) {
    ++stats_.busy_replies;
    send_relay_status(source, env.transaction_nonce, RelayStatusCode::Busy,
                      config_.busy_retry_after_ms);
    return false;
  }
  const std::uint32_t relay_id = next_relay_id_;
  if (relay_id == ~std::uint32_t{0}) {
    relay_ids_exhausted_ = true;
  } else {
    next_relay_id_ = relay_id + 1;
  }
  slot_.reset();
  relay_ = Relay{};
  relay_.active = true;
  relay_.relay_id = relay_id;
  relay_.gateway_epoch = gateway_epoch_;
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
    if (relay_.last_step != 0 || slot_.mode() == JoinObjectSlot::Mode::Assembling) {
      if (object.phase != relay_.phase) ++stats_.frames_rejected;
      return;
    }
  } else if (!relay_peer(source, env) || object.phase != relay_.phase) {
    ++stats_.frames_rejected;
    return;
  }
  if (object.step == 3 && relay_.last_step != 2) {
    ++stats_.frames_rejected;
    return;
  }
  if (object.step == kJoinEdhocErrorStep &&
      (relay_.last_step == 0 || relay_.final_pending)) {
    ++stats_.frames_rejected;
    return;
  }
  relay_.rssi = rssi;
  // Only a new valid stage proves that the previous down object arrived.
  slot_.release_assembled();
  const MutableByteView buffer = slot_.writable_buffer();
  std::memcpy(buffer.data + kRelayHeaderSize, object.message.data, object.message.size);
  if (object.step == 1 || object.step == 3) {
    const std::size_t stage = object.step == 1 ? 0 : 1;
    relay_.accepted_up_mask = static_cast<std::uint8_t>(relay_.accepted_up_mask | (1U << stage));
    relay_.accepted_up_totals[stage] = static_cast<std::uint16_t>(env.body_size);
  }
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
  const bool tracked_stage = chunk.step == 1 || chunk.step == 3;
  const std::size_t stage = chunk.step == 1 ? 0 : 1;
  if (tracked_stage && (relay_.accepted_up_mask & (1U << stage)) != 0) {
    if (relay_.accepted_up_totals[stage] == chunk.total) {
      JoinReply complete{};
      complete.phase = chunk.phase;
      complete.step = chunk.step;
      complete.id = chunk.id;
      complete.received = chunk.total;
      complete.status = JoinReplyStatus::Complete;
      send_rld1_reply(complete);
    } else {
      ++stats_.frames_rejected;
    }
    return;
  }
  if ((chunk.step == 1 && relay_.last_step != 0) ||
      (chunk.step == 3 && relay_.last_step != 2) ||
      (chunk.step == kJoinEdhocErrorStep &&
       (relay_.last_step == 0 || relay_.final_pending)) ||
      chunk.total > kJoinObjectHeadSize +
                        (chunk.step == 1 ? kJoinCookieSize : 0) + kJoinMessageMax) {
    ++stats_.frames_rejected;
    return;
  }
  if (slot_.mode() != JoinObjectSlot::Mode::Assembling && chunk.offset != 0) return;
  if (chunk.step != 1 && chunk.offset == 0) {
    const std::uint8_t* d = chunk.data.data;
    if (chunk.data.size < kJoinObjectHeadSize + 1 || d[0] != autonomy::kPayloadVersion ||
        d[1] != static_cast<std::uint8_t>(chunk.phase) || d[2] != chunk.step ||
        d[3] != 0 || d[4] != 0 || d[5] != 0) {
      ++stats_.frames_rejected;
      return;
    }
  }
  relay_.rssi = rssi;
  if (slot_.mode() == JoinObjectSlot::Mode::Sending && !relay_.slot_up &&
      chunk.step != 1 && chunk.offset == 0) {
    slot_.release_assembled();  // the device answered: our down object arrived
  }
  const JoinObjectSlot::Accepted accepted = slot_.accept(JoinCarrier::Rld1, chunk, now_ms);
  if (accepted.send_reply && accepted.outcome != JoinObjectSlot::Outcome::Complete)
    send_rld1_reply(accepted.reply);
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
    slot_.reset();
    return;
  }
  if (tracked_stage) {
    relay_.accepted_up_mask = static_cast<std::uint8_t>(relay_.accepted_up_mask | (1U << stage));
    relay_.accepted_up_totals[stage] = chunk.total;
  }
  send_rld1_reply(accepted.reply);
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
      !join_reply_decode(JoinCarrier::Rld1, ByteView{env.body.data(), env.body_size}, reply) ||
      relay_.slot_up) {
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
  object.header.gateway_epoch = relay_.gateway_epoch;
  object.header.proxy_epoch = config_.proxy_epoch;
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
      abort_relay(RelayStatusCode::AuthorityUnreachable, false);
      return;
    }
    slot_.release_assembled();
    relay_.slot_up = false;
    return;
  }
  if (!slot_.load_in_place(JoinCarrier::WireRelay, phase, step, relay_.relay_id,
                           relay_.gateway_epoch, config_.proxy_epoch, written, now_ms)) {
    slot_.release_assembled();
    return;
  }
  relay_.slot_up = true;
  send_due_chunks(now_ms);
}

Status JoinProxy::on_relay_rx(const NodeId from, const FrameType type, const ByteView payload,
                                    const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in port callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "proxy epoch");
  if (now_ms < last_now_ms_) return Status::error(StatusCode::TimeUncertain, "clock regressed");
  last_now_ms_ = now_ms;
  in_call_ = true;
  on_relay_rx_impl(from, type, payload, now_ms);
  in_call_ = false;
  return Status::success();
}

bool JoinProxy::down_expected(const RelayHeader& header) const noexcept {
  if (header.state == RelayState::Abort) return relay_.last_step != 0;
  if (header.step == 2) return relay_.last_step == 1;
  if (header.phase == JoinAuthPhase::EdhocMessage && header.step == 4)
    return relay_.last_step == 3;
  if (header.phase == JoinAuthPhase::EdhocMessage && header.step == kJoinEdhocErrorStep)
    return relay_.last_step != 0 && !relay_.final_pending;
  return false;
}

void JoinProxy::on_relay_rx_impl(const NodeId from, const FrameType type, const ByteView payload,
                                 const MonotonicMs now_ms) noexcept {
  if (!zt_admit_relay(membership_, false, AdmissionDirection::Rx, type, from, config_.gateway)) {
    ++stats_.frames_rejected;
    return;
  }
  // The full token of the live relay: an input from another epoch or for
  // another id never touches it (#116 §3.1).
  const auto ours = [&](const RelayHeader& h) {
    return relay_.active && h.dir == RelayDirection::Down && h.relay_id == relay_.relay_id &&
           h.gateway_epoch == relay_.gateway_epoch && h.proxy_epoch == config_.proxy_epoch &&
           h.proxy == config_.node && h.joiner_mac == relay_.joiner_mac &&
           h.phase == relay_.phase;
  };
  const auto chunk_ours = [&](const JoinChunk& chunk) {
    return relay_.active && chunk.id == relay_.relay_id &&
           chunk.gateway_epoch == relay_.gateway_epoch &&
           chunk.proxy_epoch == config_.proxy_epoch && chunk.phase == relay_.phase;
  };
  switch (type) {
    case FrameType::BootstrapAuth: {
      // An epoch reply needs no live relay; anything else here does.
      if (classify_wire_relay(payload) == WireRelayKind::EpochReply) {
        EpochReply reply{};
        if (!epoch_reply_decode(payload, reply)) {
          ++stats_.frames_rejected;
          return;
        }
        handle_epoch_reply(reply, now_ms);
        return;
      }
      if (!relay_.active) {
        ++stats_.frames_rejected;
        return;
      }
      RelayObject object{};
      if (!relay_single_frame_decode(type, payload, object) || !ours(object.header) ||
          !down_expected(object.header)) {
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
    case FrameType::MembershipResult: {
      if (!relay_.active) {
        ++stats_.frames_rejected;
        return;
      }
      RelayObject object{};
      if (!relay_single_frame_decode(type, payload, object) || !ours(object.header) ||
          !down_expected(object.header)) {
        ++stats_.frames_rejected;
        return;
      }
      if (relay_.slot_up) {
        slot_.release_assembled();
        relay_.slot_up = false;
      }
      deliver_down(object, now_ms);
      return;
    }
    case FrameType::BootstrapChunk: {
      JoinChunk chunk{};
      // Lane guard (P4 §7.3): end-session chunks never enter the
      // join-relay assembly, even on a colliding (id, phase, step).
      if (!join_chunk_decode(JoinCarrier::WireRelay, payload, chunk) ||
          chunk.lane != ObjectLane::JoinRelay || !chunk_ours(chunk) ||
          join_step_flow(chunk.phase, chunk.step) == JoinFlow::Up ||
          chunk.total > kRelayObjectMax) {
        ++stats_.frames_rejected;
        return;
      }
      if (relay_.accepted_down_step == chunk.step) {
        if (relay_.accepted_down_total == chunk.total) {
          JoinReply complete{};
          complete.phase = chunk.phase;
          complete.step = chunk.step;
          complete.id = chunk.id;
          complete.gateway_epoch = chunk.gateway_epoch;
          complete.proxy_epoch = chunk.proxy_epoch;
          complete.received = chunk.total;
          complete.status = JoinReplyStatus::Complete;
          send_wire_receipt(complete);
        } else {
          ++stats_.frames_rejected;
        }
        return;
      }
      if (chunk.offset == 0) {
        RelayObject prefix{};
        if (chunk.data.size < kRelayHeaderSize + 1 ||
            !relay_object_decode(ByteView{chunk.data.data, kRelayHeaderSize + 1}, prefix) ||
            !ours(prefix.header) || prefix.header.step != chunk.step ||
            !down_expected(prefix.header)) {
          ++stats_.frames_rejected;
          return;
        }
      } else if (slot_.mode() != JoinObjectSlot::Mode::Assembling) {
        return;
      }
      if (relay_.slot_up && slot_.mode() == JoinObjectSlot::Mode::Sending) {
        slot_.release_assembled();
        relay_.slot_up = false;
      }
      const JoinObjectSlot::Accepted accepted =
          slot_.accept(JoinCarrier::WireRelay, chunk, now_ms);
      if (accepted.send_reply && accepted.outcome != JoinObjectSlot::Outcome::Complete)
        send_wire_receipt(accepted.reply);
      if (accepted.outcome == JoinObjectSlot::Outcome::Busy ||
          accepted.outcome == JoinObjectSlot::Outcome::Rejected) {
        ++stats_.frames_rejected;
      }
      if (accepted.outcome != JoinObjectSlot::Outcome::Complete) return;
      RelayObject object{};
      if (!relay_object_decode(slot_.assembled(), object) || !ours(object.header) ||
          object.header.step != chunk.step || !down_expected(object.header)) {
        ++stats_.frames_rejected;
        slot_.reset();
        return;
      }
      relay_.accepted_down_step = chunk.step;
      relay_.accepted_down_total = chunk.total;
      send_wire_receipt(accepted.reply);
      deliver_down(object, now_ms);
      return;
    }
    case FrameType::BootstrapReply: {
      JoinReply reply{};
      // Lane guard (P4 §7.3): an end-lane reply never advances a
      // join-relay send.
      if (!join_reply_decode(JoinCarrier::WireRelay, payload, reply) || !relay_.active ||
          reply.lane != ObjectLane::JoinRelay || reply.id != relay_.relay_id ||
          reply.gateway_epoch != relay_.gateway_epoch ||
          reply.proxy_epoch != config_.proxy_epoch || !relay_.slot_up) {
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
  if (h.state == RelayState::Continue &&
      now_ms > ~MonotonicMs{0} - config_.device_silence_ms) {
    abort_relay(RelayStatusCode::Aborted, true);
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
    const Status sent = emit_rld1(relay_.joiner_mac, relay_.nonce, FrameType::BootstrapAuth,
                                  ByteView{buffer.data, written});
    slot_.release_assembled();
    if (!sent) {
      abort_relay(RelayStatusCode::Aborted, true);
      return;
    }
    if (relay_.final_pending) {
      ++stats_.relays_completed;
      end_relay();
      return;
    }
  } else {
    if (!slot_.load_in_place(JoinCarrier::Rld1, h.phase, h.step,
                             join_rld1_object_id(relay_.nonce), 0, 0, written, now_ms)) {
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
  if (join_reply_encode(JoinCarrier::Rld1, reply, MutableByteView{body.data(), body.size()},
                        written)) {
    (void)emit_rld1(relay_.joiner_mac, relay_.nonce, FrameType::BootstrapReply,
                    ByteView{body.data(), written});
  }
}

void JoinProxy::send_wire_receipt(const JoinReply& reply) noexcept {
  std::array<std::uint8_t, kWireRelayReplySize> body{};
  std::size_t written = 0;
  if (join_reply_encode(JoinCarrier::WireRelay, reply, MutableByteView{body.data(), body.size()},
                        written) &&
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
    object.header.gateway_epoch = relay_.gateway_epoch;
    object.header.proxy_epoch = config_.proxy_epoch;
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

bool JoinProxy::epoch_cache_valid(const MonotonicMs now_ms) const noexcept {
  return gateway_epoch_ != 0 && now_ms - gateway_cached_ms_ < kGatewayEpochCacheMs;
}

void JoinProxy::need_gateway_epoch(const MonotonicMs now_ms) noexcept {
  if (epoch_cache_valid(now_ms) || query_.active) return;
  if (!id_valid(config_.gateway) || membership_ != MembershipState::Member) return;
  EpochQueryState query{};
  if (!entropy_.fill(MutableByteView{query.nonce.data(), query.nonce.size()})) return;
  bool all_zero = true;
  for (const std::uint8_t b : query.nonce) all_zero = all_zero && b == 0;
  if (all_zero) return;  // never send a predictable query nonce
  if (kEpochQueryLifetimeMs > ~MonotonicMs{0} - now_ms) return;
  query.active = true;
  query.next_ms = now_ms;
  query.deadline_ms = now_ms + kEpochQueryLifetimeMs;
  query_ = query;
  send_epoch_query(now_ms);
}

void JoinProxy::send_epoch_query(const MonotonicMs now_ms) noexcept {
  if (!query_.active || query_.sends >= kEpochQueryMaxSends) return;
  EpochQuery query{};
  query.nonce = query_.nonce;
  std::array<std::uint8_t, kEpochQuerySize> body{};
  std::size_t written = 0;
  if (!epoch_query_encode(query, MutableByteView{body.data(), body.size()}, written)) return;
  ++query_.sends;
  query_.next_ms = now_ms > ~MonotonicMs{0} - kEpochQueryIntervalMs
                       ? query_.deadline_ms
                       : now_ms + kEpochQueryIntervalMs;
  if (relay_port_.send_relay(config_.gateway, FrameType::BootstrapAuth,
                             ByteView{body.data(), written})) {
    ++stats_.epoch_queries_tx;
  } else {
    ++stats_.send_failures;
  }
}

void JoinProxy::handle_epoch_reply(const EpochReply& reply, const MonotonicMs now_ms) noexcept {
  // Only the outstanding query's fresh nonce is adopted; anything else is
  // a replay or a misdirected frame and is ignored (#116 §3.3).
  if (!query_.active || now_ms >= query_.deadline_ms || reply.nonce != query_.nonce) {
    if (query_.active && now_ms >= query_.deadline_ms) query_ = EpochQueryState{};
    ++stats_.frames_rejected;
    return;
  }
  // Epochs only move forward for a gateway; a smaller reply is stale.
  if (reply.gateway_epoch < gateway_max_epoch_) {
    ++stats_.frames_rejected;
    return;
  }
  const bool newer = reply.gateway_epoch > gateway_max_epoch_;
  gateway_max_epoch_ = reply.gateway_epoch;
  gateway_epoch_ = reply.gateway_epoch;
  gateway_ready_ = reply.authority_ready;
  gateway_cached_ms_ = now_ms;
  query_ = EpochQueryState{};
  ++stats_.epoch_replies_rx;
  // A new gateway incarnation cannot serve the old exchange: close it so
  // the device re-discovers instead of retransmitting into the void.
  if (newer && relay_.active) abort_relay(RelayStatusCode::Aborted, false);
}

Status JoinProxy::poll(const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in port callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "proxy epoch");
  if (now_ms < last_now_ms_) return Status::error(StatusCode::TimeUncertain, "clock regressed");
  last_now_ms_ = now_ms;
  in_call_ = true;
  if (query_.active) {
    if (now_ms >= query_.deadline_ms) {
      query_ = EpochQueryState{};  // the next DISCOVER restarts it
    } else if (now_ms >= query_.next_ms) {
      send_epoch_query(now_ms);
    }
  }
  for (std::size_t guard = 0; guard < kPendingOffers; ++guard) {
    PendingOffer* due = offers_.find([&](const PendingOffer& offer) {
      return offer.due_ms <= now_ms;
    });
    if (due == nullptr) break;
    const PendingOffer offer = *due;
    offers_.release(due);
    send_offer(offer, now_ms);
  }
  if (!relay_.active) {
    in_call_ = false;
    return Status::success();
  }
  if (now_ms - relay_.started_ms >= config_.relay_timeout_ms ||
      (relay_.device_deadline_ms != 0 && now_ms >= relay_.device_deadline_ms)) {
    abort_relay(RelayStatusCode::Aborted, true);  // 02 §7.3: 20 s cap / 5 s device silence
    in_call_ = false;
    return Status::success();
  }
  (void)slot_.expire(now_ms, config_.assembly_timeout_ms);
  if (slot_.mode() != JoinObjectSlot::Mode::Sending ||
      now_ms - slot_.last_send_ms() < config_.retransmit_ms) {
    in_call_ = false;
    return Status::success();
  }
  if (slot_.sends() >= config_.max_sends) {
    abort_relay(RelayStatusCode::Aborted, true);
    in_call_ = false;
    return Status::success();
  }
  ++stats_.retransmissions;
  send_due_chunks(now_ms);
  in_call_ = false;
  return Status::success();
}

// ===================================================================================
// JoinRelayGateway
// ===================================================================================

JoinRelayGateway::JoinRelayGateway(const JoinRelayGatewayConfig& config,
                                   ZtRelayPort& wire) noexcept
    : config_(config), wire_(wire),
      config_valid_(id_valid(config.node) && config.gateway_epoch != 0 &&
                    config.assembly_timeout_ms != 0 && config.retransmit_ms != 0 &&
                    config.max_sends != 0) {}

Status JoinRelayGateway::set_host_sink(JoinRelayHostSink* sink) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in sink callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "gateway epoch");
  in_call_ = true;
  if (sink == nullptr) {
    // Detaching ends every live exchange: the proxies hear
    // authority_unreachable (best effort) while the lane still exists. The
    // floors and the epoch stay: old keys remain old (#116 §4.5).
    for (std::uint8_t i = 0; i < kActiveRelays; ++i) {
      ActiveRelay& relay = relays_[i];
      if (!relay.active) continue;
      const ProxyFloor& floor = floors_[relay.floor];
      RelayHeader up{};
      up.dir = RelayDirection::Up;
      up.relay_id = relay.token.relay_id;
      up.proxy = floor.proxy;
      up.joiner_mac = relay.joiner_mac;
      up.phase = relay.phase;
      up.step = 1;
      up.state = RelayState::Continue;
      up.gateway_epoch = relay.token.gateway_epoch;
      up.proxy_epoch = relay.token.proxy_epoch;
      send_down_abort(floor.proxy, up, RelayStatusCode::AuthorityUnreachable,
                      config_.unreachable_retry_ms);
      finish_silent(relay);
    }
  }
  sink_ = sink;
  in_call_ = false;
  return Status::success();
}

Status JoinRelayGateway::set_membership(const MembershipState state) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in sink callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "gateway epoch");
  in_call_ = true;
  membership_ = state;
  if (state != MembershipState::Member) {
    // Leaving Member ends the live exchanges silently; the floors (the
    // per-proxy frontiers) are kept, never reset (#116 §3.2).
    for (std::uint8_t i = 0; i < kActiveRelays; ++i) {
      if (relays_[i].active) finish_silent(relays_[i]);
    }
  }
  in_call_ = false;
  return Status::success();
}

std::size_t JoinRelayGateway::slots_in_use() const noexcept {
  std::size_t used = 0;
  for (const Slot& slot : slots_) used += slot.active ? 1U : 0U;
  return used;
}

JoinRelayGateway::KeyOrder JoinRelayGateway::order_key(const NodeId proxy, const RelayToken& token,
                                                       ProxyFloor*& floor) noexcept {
  floor = nullptr;
  for (ProxyFloor& row : floors_) {
    if (row.valid && row.proxy == proxy) {
      floor = &row;
      break;
    }
  }
  if (floor == nullptr) return KeyOrder::UnknownProxy;
  RelayToken max{};
  max.gateway_epoch = token.gateway_epoch;
  max.proxy_epoch = floor->max_proxy_epoch;
  max.relay_id = floor->max_relay_id;
  if (relay_key_less(token, max)) return KeyOrder::Older;
  if (token.proxy_epoch == max.proxy_epoch && token.relay_id == max.relay_id) {
    return KeyOrder::Same;
  }
  return KeyOrder::Newer;
}

JoinRelayGateway::ActiveRelay* JoinRelayGateway::live_exchange(ProxyFloor& floor) noexcept {
  if (floor.active >= kActiveRelays) return nullptr;
  ActiveRelay& relay = relays_[floor.active];
  if (!relay.active || relay.floor >= kProxyFloors || &floors_[relay.floor] != &floor) {
    return nullptr;
  }
  return &relay;
}

Status JoinRelayGateway::open_exchange(const NodeId proxy, const std::uint8_t hops,
                                       const RelayHeader& header, const MonotonicMs now_ms,
                                       ActiveRelay*& relay) noexcept {
  relay = nullptr;
  // Batch admission: every resource is confirmed before any other exchange
  // is touched, so a refused newcomer breaks nothing (#116 §4.2).
  ProxyFloor* floor = nullptr;
  const KeyOrder order = order_key(proxy, relay_token_of(header), floor);
  ProxyFloor* target = floor;
  if (order == KeyOrder::UnknownProxy) {
    for (ProxyFloor& row : floors_) {
      if (!row.valid) {
        target = &row;
        break;
      }
    }
    if (target == nullptr) return Status::error(StatusCode::NoCapacity, "proxy floors full");
  } else if (order != KeyOrder::Newer) {
    return Status::error(StatusCode::Conflict, "key is not new");
  }
  ActiveRelay* free_row = nullptr;
  for (ActiveRelay& row : relays_) {
    if (!row.active) {
      free_row = &row;
      break;
    }
  }
  ActiveRelay* old = floor != nullptr ? live_exchange(*floor) : nullptr;
  if (free_row == nullptr) free_row = old;
  if (free_row == nullptr) return Status::error(StatusCode::NoCapacity, "exchanges full");
  if (kRelayExchangeTimeoutMs > ~MonotonicMs{0} - now_ms) {
    return Status::error(StatusCode::TimeUncertain, "deadline overflow");
  }
  // A larger key supersedes the proxy's previous exchange first; its Host
  // session (if it ever received an up object) hears Superseded, never a
  // forged ProxyAborted (#116 §4.4).
  if (floor != nullptr) {
    if (old != nullptr)
      finish_exchange(*old, RelayAbortReason::Superseded, old->host_up_delivered);
  } else {
    target->valid = true;
    target->proxy = proxy;
  }
  target->max_proxy_epoch = header.proxy_epoch;
  target->max_relay_id = header.relay_id;
  const auto floor_index = static_cast<std::uint8_t>(target - floors_.data());
  const auto relay_index = static_cast<std::uint8_t>(free_row - relays_.data());
  *free_row = ActiveRelay{};  // every field is (re)initialized here
  free_row->active = true;
  free_row->floor = floor_index;
  free_row->token = relay_token_of(header);
  free_row->joiner_mac = header.joiner_mac;
  free_row->phase = header.phase;
  free_row->hops = hops;
  free_row->started_ms = now_ms;
  free_row->deadline_ms = now_ms + kRelayExchangeTimeoutMs;
  target->active = relay_index;
  relay = free_row;
  return Status::success();
}

JoinRelayGateway::Slot* JoinRelayGateway::slot_for(ActiveRelay& relay) noexcept {
  if (relay.slot >= kSlots) return nullptr;
  Slot& slot = slots_[relay.slot];
  if (!slot.active || slot.relay >= kActiveRelays || &relays_[slot.relay] != &relay) return nullptr;
  return &slot;
}

JoinRelayGateway::Slot* JoinRelayGateway::allocate_slot(ActiveRelay& relay,
                                                        const std::uint8_t relay_index,
                                                        const bool down) noexcept {
  for (std::uint8_t i = 0; i < kSlots; ++i) {
    if (slots_[i].active) continue;
    Slot& slot = slots_[i];
    slot.object.reset();
    slot.active = true;
    slot.down = down;
    slot.relay = relay_index;
    relay.slot = i;
    return &slot;
  }
  return nullptr;
}

void JoinRelayGateway::free_slot(Slot& slot) noexcept {
  if (slot.relay < kActiveRelays && relays_[slot.relay].slot < kSlots &&
      &slots_[relays_[slot.relay].slot] == &slot) {
    relays_[slot.relay].slot = kNoSlot;
  }
  slot.object.reset();
  slot.active = false;
  slot.down = false;
  slot.relay = kNoActive;
}

void JoinRelayGateway::finish_exchange(ActiveRelay& relay, const RelayAbortReason reason,
                                        const bool notify_sink) noexcept {
  if (!relay.active) return;  // a second finish of the same key is a no-op
  // Snapshot the notification before unlinking anything.
  const ProxyFloor& floor = floors_[relay.floor];
  const NodeId proxy = floor.proxy;
  const RelayToken token = relay.token;
  // (1) The floor stays terminated at this key: smaller keys remain old and
  // the same key never reopens.
  floors_[relay.floor].active = kNoActive;
  // (2) Wipe the buffer and unlink the live row.
  if (Slot* slot = slot_for(relay)) free_slot(*slot);
  relay = ActiveRelay{};
  // (3) At most one notification goes out, counted once.
  switch (reason) {
    case RelayAbortReason::ProxyAborted:
      ++stats_.proxy_aborts;
      break;
    case RelayAbortReason::GatewayExpired:
      ++stats_.expired;
      break;
    case RelayAbortReason::DeliveryFailed:
      ++stats_.delivery_failed;
      break;
    case RelayAbortReason::HostAborted:
      ++stats_.host_aborts;
      break;
    case RelayAbortReason::Superseded:
      break;  // reported through the sink reason, not counted separately
  }
  if (notify_sink && sink_ != nullptr) {
    (void)sink_->relay_abort(proxy, token, reason);
  }
}

void JoinRelayGateway::finish_index(const std::uint8_t relay_index, const RelayAbortReason reason,
                                    const bool notify_sink) noexcept {
  if (relay_index >= kActiveRelays) return;
  finish_exchange(relays_[relay_index], reason, notify_sink);
}

void JoinRelayGateway::finish_silent(ActiveRelay& relay) noexcept {
  if (!relay.active) return;
  floors_[relay.floor].active = kNoActive;
  if (Slot* slot = slot_for(relay)) free_slot(*slot);
  relay = ActiveRelay{};
}

void JoinRelayGateway::implicit_down_receipt(ActiveRelay& relay) noexcept {
  // A valid new up stage proves the down object in flight arrived: free it
  // and remember it as done, so a retried down reads as Expired.
  if (Slot* slot = slot_for(relay)) {
    if (slot->down) free_slot(*slot);
  }
  if (relay.down_sending) {
    if (relay.down_step == 2) relay.m2_done = true;
    relay.down_sending = false;
    relay.down_done = true;
  }
}

void JoinRelayGateway::deliver_up(ActiveRelay& relay, const std::uint8_t relay_index,
                                  const std::uint8_t hops, const RelayObject& object,
                                  const ByteView bytes) noexcept {
  const RelayHeader& h = object.header;
  const std::uint8_t stage = up_stage_slot(h.step);
  const bool is_error = h.step == kJoinEdhocErrorStep;
  ++stats_.up_objects;
  // An up EDHOC error terminates the exchange, but its body still goes to
  // the host exactly once: commit the termination first while the source
  // buffer stays readable for the callback, wipe it right after (#116 §4.4).
  if (is_error) {
    const NodeId proxy = floors_[relay.floor].proxy;
    floors_[relay.floor].active = kNoActive;
    relay = ActiveRelay{};
    bool accepted = false;
    if (sink_ != nullptr) accepted = sink_->relay_up(proxy, hops, bytes).ok();
    for (Slot& slot : slots_) {
      if (slot.active && slot.relay == relay_index) free_slot(slot);
    }
    if (!accepted) {
      ++stats_.host_unavailable;
      send_down_abort(proxy, h, RelayStatusCode::AuthorityUnreachable,
                      config_.unreachable_retry_ms);
    }
    return;
  }
  bool accepted = false;
  if (sink_ != nullptr) accepted = sink_->relay_up(floors_[relay.floor].proxy, hops, bytes).ok();
  if (!accepted) {
    // 07 §7: no host (or a refusing one) -> the proxy tells the device
    // authority_unreachable. The up is never handed over again for this key.
    ++stats_.host_unavailable;
    send_down_abort(floors_[relay.floor].proxy, h, RelayStatusCode::AuthorityUnreachable,
                    config_.unreachable_retry_ms);
    finish_silent(relay);
    return;
  }
  relay.accepted_up_mask = static_cast<std::uint8_t>(relay.accepted_up_mask | (1U << stage));
  relay.accepted_totals[stage] = static_cast<std::uint16_t>(bytes.size);
  relay.host_up_delivered = true;
  if (Slot* slot = slot_for(relay)) {
    if (!slot->down) free_slot(*slot);  // the assembly buffer is reusable now
  }
  // A Resume R3 is the authority's last inbound message: the exchange ends
  // silently once the host owns it.
  if (h.phase == JoinAuthPhase::Resume && h.step == 3) finish_silent(relay);
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

void JoinRelayGateway::send_up_complete(const NodeId proxy, const RelayToken& token,
                                        const JoinAuthPhase phase, const std::uint8_t step,
                                        const std::uint16_t total) noexcept {
  // Re-acknowledges an accepted up stage without rebuilding the buffer or
  // re-delivering to the host: the receipt of that logical object (#116).
  JoinReply reply{};
  reply.phase = phase;
  reply.step = step;
  reply.id = token.relay_id;
  reply.received = total;
  reply.status = JoinReplyStatus::Complete;
  reply.gateway_epoch = token.gateway_epoch;
  reply.proxy_epoch = token.proxy_epoch;
  std::array<std::uint8_t, kWireRelayReplySize> body{};
  std::size_t written = 0;
  if (join_reply_encode(JoinCarrier::WireRelay, reply, MutableByteView{body.data(), body.size()},
                        written)) {
    (void)wire_.send_relay(proxy, FrameType::BootstrapReply, ByteView{body.data(), written});
  }
}

void JoinRelayGateway::answer_epoch_query(const NodeId proxy, const EpochQuery& query,
                                          const MonotonicMs now_ms) noexcept {
  ++stats_.epoch_queries_rx;
  // Stateless token bucket: bursts of 4, 10 answers per second. Queries
  // consume no table row and no assembly slot (#116 §3.3).
  const MonotonicMs elapsed = now_ms - answer_refill_ms_;
  const std::uint32_t intervals = static_cast<std::uint32_t>(
      std::min<MonotonicMs>(elapsed / 100, kEpochAnswerBurst));
  answer_budget_ = std::min<std::uint32_t>(kEpochAnswerBurst * 10,
                                            answer_budget_ + intervals * 10);
  answer_refill_ms_ = elapsed / 100 >= kEpochAnswerBurst
                          ? now_ms - elapsed % 100
                          : answer_refill_ms_ + static_cast<MonotonicMs>(intervals) * 100;
  if (answer_budget_ < 10) return;
  answer_budget_ -= 10;
  EpochReply reply{};
  reply.gateway_epoch = config_.gateway_epoch;
  reply.nonce = query.nonce;
  reply.authority_ready = sink_ != nullptr;
  std::array<std::uint8_t, kEpochReplySize> body{};
  std::size_t written = 0;
  if (!epoch_reply_encode(reply, MutableByteView{body.data(), body.size()}, written)) return;
  if (wire_.send_relay(proxy, FrameType::BootstrapAuth, ByteView{body.data(), written})) {
    ++stats_.epoch_replies_tx;
  }
}

void JoinRelayGateway::expire_due(const MonotonicMs now_ms) noexcept {
  for (ActiveRelay& relay : relays_) {
    if (relay.active && now_ms >= relay.deadline_ms)
      finish_exchange(relay, RelayAbortReason::GatewayExpired, relay.host_up_delivered);
  }
}

bool JoinRelayGateway::first_chunk_header(const ByteView chunk_data,
                                          RelayHeader& header) const noexcept {
  // The offset-0 chunk of a new stage carries the whole 32 B object head in
  // the clear, checked before any buffer is granted or freed (#116 §4.2).
  // An Abort object (37 B) never chunks, so an Abort head here is invalid.
  if (chunk_data.data == nullptr || chunk_data.size < kRelayHeaderSize + 1) return false;
  if (chunk_data.data[21] == static_cast<std::uint8_t>(RelayState::Abort)) return false;
  RelayObject object{};
  if (!relay_object_decode(ByteView{chunk_data.data, kRelayHeaderSize + 1}, object)) return false;
  if (object.header.state != RelayState::Continue) return false;
  header = object.header;
  return true;
}

Status JoinRelayGateway::on_relay_rx(const NodeId from, const std::uint8_t hops,
                                         const FrameType type, const ByteView payload,
                                         const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in sink callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "gateway epoch");
  if (now_ms < last_now_ms_) return Status::error(StatusCode::TimeUncertain, "clock regressed");
  last_now_ms_ = now_ms;
  in_call_ = true;
  on_relay_rx_impl(from, hops, type, payload, now_ms);
  in_call_ = false;
  return Status::success();
}

void JoinRelayGateway::on_relay_rx_impl(const NodeId from, const std::uint8_t hops,
                                        const FrameType type, const ByteView payload,
                                        const MonotonicMs now_ms) noexcept {
  if ((from == config_.node && !config_.colocated_proxy) ||
      !zt_admit_relay(membership_, true, AdmissionDirection::Rx, type, from, config_.node)) {
    ++stats_.frames_rejected;
    return;
  }
  expire_due(now_ms);
  switch (type) {
    case FrameType::BootstrapAuth: {
      // An epoch query is answered statelessly; a reply here is misdirected.
      const WireRelayKind kind = classify_wire_relay(payload);
      if (kind == WireRelayKind::EpochQuery) {
        EpochQuery query{};
        if (!epoch_query_decode(payload, query)) {
          ++stats_.frames_rejected;
          return;
        }
        answer_epoch_query(from, query, now_ms);
        return;
      }
      if (kind != WireRelayKind::RelayObject) {
        ++stats_.frames_rejected;
        return;
      }
      RelayObject object{};
      if (!relay_single_frame_decode(type, payload, object) ||
          object.header.dir != RelayDirection::Up || object.header.proxy != from) {
        ++stats_.frames_rejected;
        return;
      }
      handle_up_single(from, hops, object, payload, now_ms);
      return;
    }
    case FrameType::BootstrapChunk: {
      JoinChunk chunk{};
      // Lane guard (P4 §7.3): end-session chunks never enter the
      // join-relay assembly, even on a colliding (id, phase, step).
      if (!join_chunk_decode(JoinCarrier::WireRelay, payload, chunk) ||
          chunk.lane != ObjectLane::JoinRelay ||
          join_step_flow(chunk.phase, chunk.step) == JoinFlow::Down) {
        ++stats_.frames_rejected;
        return;
      }
      handle_up_chunk(from, hops, chunk, now_ms);
      return;
    }
    case FrameType::BootstrapReply: {
      JoinReply reply{};
      // Lane guard (P4 §7.3): an end-lane reply never touches the
      // join-relay gateway slots.
      if (!join_reply_decode(JoinCarrier::WireRelay, payload, reply) ||
          reply.lane != ObjectLane::JoinRelay) {
        ++stats_.frames_rejected;
        return;
      }
      handle_down_reply(from, reply, now_ms);
      return;
    }
    default:
      ++stats_.frames_rejected;
      return;
  }
}

void JoinRelayGateway::handle_up_single(const NodeId from, const std::uint8_t hops,
                                        const RelayObject& object, const ByteView bytes,
                                        const MonotonicMs now_ms) noexcept {
  const RelayHeader& h = object.header;
  // The gateway epoch comes first: an old incarnation's input never touches
  // a slot, whatever else it claims (#116 §4.2).
  if (h.gateway_epoch != config_.gateway_epoch) return;
  const RelayToken token = relay_token_of(h);
  if (h.state == RelayState::Abort) {
    handle_proxy_aborted(from, token, h);
    return;
  }
  ProxyFloor* floor = nullptr;
  const KeyOrder order = order_key(from, token, floor);
  if (order == KeyOrder::Older) return;  // a stale duplicate: no slot, no Host call
  if (order == KeyOrder::Same) {
    ActiveRelay* relay = live_exchange(*floor);
    if (relay == nullptr) return;  // terminated: never reopened
    handle_up_same(*relay, hops, h, bytes, static_cast<std::uint16_t>(bytes.size));
    return;
  }
  // A new key opens only on a step-1 single; anything else is dropped
  // without holding any state.
  if (h.step != 1) return;
  ActiveRelay* relay = nullptr;
  if (!open_exchange(from, hops, h, now_ms, relay)) {
    ++stats_.slot_busy;
    return;
  }
  const auto index = static_cast<std::uint8_t>(relay - relays_.data());
  deliver_up(*relay, index, hops, object, bytes);
}

void JoinRelayGateway::handle_up_same(ActiveRelay& relay, const std::uint8_t hops,
                                      const RelayHeader& h, const ByteView bytes,
                                      const std::uint16_t total) noexcept {
  // Same live key: the bound phase/MAC/stage decide duplicate, progress or
  // contradiction — before any slot is touched (#116 §4.2).
  if (h.phase != relay.phase || h.joiner_mac != relay.joiner_mac) {
    ++stats_.frames_rejected;
    return;
  }
  const std::uint8_t stage = up_stage_slot(h.step);
  const std::uint8_t bit = static_cast<std::uint8_t>(1U << stage);
  if ((relay.accepted_up_mask & bit) != 0) {
    // Accepted before: an exact duplicate is suppressed (a single frame has
    // no receipt to re-send); a differing total contradicts it.
    if (relay.accepted_totals[stage] != total) ++stats_.frames_rejected;
    return;
  }
  // A new stage: step 1 contradicts an in-progress step-1 assembly (the
  // proxy encodes each stage once), step 3 needs step 1 first, and an
  // EDHOC error is valid while the exchange is alive.
  if (h.step == 1) {
    if ((relay.accepted_up_mask & 1U) != 0 || slot_for(relay) != nullptr) {
      ++stats_.frames_rejected;
      return;
    }
    RelayObject object{};
    object.header = h;
    object.message = ByteView{bytes.data + kRelayHeaderSize, bytes.size - kRelayHeaderSize};
    const auto index = static_cast<std::uint8_t>(&relay - relays_.data());
    deliver_up(relay, index, hops, object, bytes);
    return;
  }
  if (h.step == 3 && ((relay.accepted_up_mask & 1U) == 0 ||
                      (!relay.m2_done && !(relay.down_sending && relay.down_step == 2)))) {
    ++stats_.frames_rejected;
    return;
  }
  // Valid progress implicitly received the down object in flight — and only
  // valid progress ever frees it (a duplicate frees nothing) (#116 Q116-01).
  implicit_down_receipt(relay);
  RelayObject object{};
  object.header = h;
  object.message = ByteView{bytes.data + kRelayHeaderSize, bytes.size - kRelayHeaderSize};
  const auto index = static_cast<std::uint8_t>(&relay - relays_.data());
  deliver_up(relay, index, hops, object, bytes);
}

void JoinRelayGateway::handle_up_chunk(const NodeId from, const std::uint8_t hops,
                                       const JoinChunk& chunk, const MonotonicMs now_ms) noexcept {
  if (chunk.gateway_epoch != config_.gateway_epoch) return;
  if (chunk.total > kRelayObjectMax) {
    ++stats_.frames_rejected;
    return;
  }
  RelayToken token{};
  token.gateway_epoch = chunk.gateway_epoch;
  token.proxy_epoch = chunk.proxy_epoch;
  token.relay_id = chunk.id;
  ProxyFloor* floor = nullptr;
  const KeyOrder order = order_key(from, token, floor);
  if (order == KeyOrder::Older) return;
  if (order == KeyOrder::Same) {
    ActiveRelay* relay = live_exchange(*floor);
    if (relay == nullptr) return;
    handle_chunk_same(from, *relay, chunk, now_ms);
    return;
  }
  // A new key opens only on the offset-0 chunk of step 1, whose cleartext
  // head is fully checked first; a mid-object tail is dropped held-nothing.
  if (chunk.step != 1 || chunk.offset != 0) return;
  RelayHeader inner{};
  if (!first_chunk_header(chunk.data, inner) || inner.dir != RelayDirection::Up ||
      inner.proxy != from || !relay_token_equal(relay_token_of(inner), token) ||
      inner.phase != chunk.phase || inner.step != chunk.step) {
    ++stats_.frames_rejected;
    return;
  }
  const bool reclaimable = floor != nullptr && order == KeyOrder::Newer &&
                           live_exchange(*floor) != nullptr &&
                           slot_for(*live_exchange(*floor)) != nullptr;
  if (slots_in_use() >= kSlots && !reclaimable) {
    ++stats_.slot_busy;
    return;
  }
  ActiveRelay* relay = nullptr;
  if (!open_exchange(from, hops, inner, now_ms, relay)) {
    ++stats_.slot_busy;
    return;
  }
  const auto index = static_cast<std::uint8_t>(relay - relays_.data());
  Slot* slot = allocate_slot(*relay, index, false);
  if (slot == nullptr) {  // pre-checked above; defensive only
    ++stats_.slot_busy;
    finish_silent(*relay);
    return;
  }
  feed_assembly(from, *relay, *slot, chunk, now_ms);
}

void JoinRelayGateway::handle_chunk_same(const NodeId from, ActiveRelay& relay,
                                         const JoinChunk& chunk,
                                         const MonotonicMs now_ms) noexcept {
  if (chunk.phase != relay.phase || chunk.total > kRelayObjectMax) {
    ++stats_.frames_rejected;
    return;
  }
  const std::uint8_t stage = up_stage_slot(chunk.step);
  const std::uint8_t bit = static_cast<std::uint8_t>(1U << stage);
  if ((relay.accepted_up_mask & bit) != 0) {
    // Accepted before: an exact duplicate re-earns its Complete receipt
    // from the stage record alone — no buffer rebuild, no Host call. A
    // differing total or MAC contradicts it.
    if (relay.accepted_totals[stage] != chunk.total) {
      ++stats_.frames_rejected;
      return;
    }
    send_up_complete(from, relay.token, chunk.phase, chunk.step, chunk.total);
    return;
  }
  // A new stage arrives only in order; anything else contradicts the live
  // exchange and frees nothing.
  if (chunk.step == 3 && ((relay.accepted_up_mask & 1U) == 0 ||
                          (!relay.m2_done && !(relay.down_sending && relay.down_step == 2)))) {
    ++stats_.frames_rejected;
    return;
  }
  Slot* slot = slot_for(relay);
  const bool assembling_same =
      slot != nullptr && !slot->down && slot->object.mode() == JoinObjectSlot::Mode::Assembling &&
      slot->object.phase() == chunk.phase && slot->object.step() == chunk.step &&
      slot->object.id() == chunk.id;
  if (assembling_same) {
    feed_assembly(from, relay, *slot, chunk, now_ms);
    return;
  }
  // No assembly holds this stage yet: only its offset-0 chunk may start
  // one, after its cleartext head is checked and — for a stage past the
  // first — the down object in flight is implicitly received.
  if (chunk.offset != 0) return;
  RelayHeader inner{};
  if (!first_chunk_header(chunk.data, inner) || inner.dir != RelayDirection::Up ||
      inner.proxy != from || !relay_token_equal(relay_token_of(inner), relay.token) ||
      inner.phase != chunk.phase || inner.step != chunk.step ||
      inner.joiner_mac != relay.joiner_mac) {
    ++stats_.frames_rejected;
    return;
  }
  if (chunk.step != 1) implicit_down_receipt(relay);
  slot = slot_for(relay);
  if (slot != nullptr && (slot->down || slot->object.mode() != JoinObjectSlot::Mode::Idle)) {
    ++stats_.frames_rejected;  // another object still owns the relay's slot
    return;
  }
  if (slot == nullptr) {
    const auto index = static_cast<std::uint8_t>(&relay - relays_.data());
    slot = allocate_slot(relay, index, false);
    if (slot == nullptr) {
      ++stats_.slot_busy;
      return;
    }
  }
  feed_assembly(from, relay, *slot, chunk, now_ms);
}

void JoinRelayGateway::feed_assembly(const NodeId from, ActiveRelay& relay, Slot& slot,
                                     const JoinChunk& chunk, const MonotonicMs now_ms) noexcept {
  const JoinObjectSlot::Accepted accepted = slot.object.accept(JoinCarrier::WireRelay, chunk,
                                                               now_ms);
  if (accepted.send_reply && accepted.outcome != JoinObjectSlot::Outcome::Complete) {
    std::array<std::uint8_t, kWireRelayReplySize> body{};
    std::size_t written = 0;
    if (join_reply_encode(JoinCarrier::WireRelay, accepted.reply,
                          MutableByteView{body.data(), body.size()}, written)) {
      (void)wire_.send_relay(from, FrameType::BootstrapReply, ByteView{body.data(), written});
    }
  }
  if (accepted.outcome == JoinObjectSlot::Outcome::Conflict) {
    ++stats_.frames_rejected;  // differing bytes for the held stage
    return;
  }
  if (accepted.outcome == JoinObjectSlot::Outcome::Busy ||
      accepted.outcome == JoinObjectSlot::Outcome::Rejected) {
    ++stats_.frames_rejected;
    return;
  }
  if (accepted.outcome != JoinObjectSlot::Outcome::Complete) return;
  // A complete assembly is re-checked against the outer key before anyone
  // is told: the inner head must name this same exchange (#116 §4.2).
  RelayObject object{};
  const ByteView bytes = slot.object.assembled();
  ActiveRelay* live = &relay;
  if (!relay_object_decode(bytes, object) || object.header.dir != RelayDirection::Up ||
      object.header.proxy != from || !relay_token_equal(relay_token_of(object.header),
                                                        relay.token) ||
      object.header.phase != chunk.phase || object.header.step != chunk.step ||
      object.header.phase != relay.phase || object.header.joiner_mac != relay.joiner_mac ||
      bytes.size != chunk.total) {
    ++stats_.frames_rejected;
    free_slot(slot);
    return;
  }
  const std::uint8_t stage = up_stage_slot(object.header.step);
  const std::uint8_t bit = static_cast<std::uint8_t>(1U << stage);
  if ((relay.accepted_up_mask & bit) != 0) {
    // Accepted while assembling (a single-frame twin won the race): this
    // copy is a duplicate, acknowledged but never re-delivered.
    free_slot(slot);
    if (relay.accepted_totals[stage] == chunk.total) {
      send_up_complete(from, relay.token, chunk.phase, chunk.step, chunk.total);
    } else {
      ++stats_.frames_rejected;
    }
    return;
  }
  const auto index = static_cast<std::uint8_t>(live - relays_.data());
  if (accepted.send_reply) {
    std::array<std::uint8_t, kWireRelayReplySize> body{};
    std::size_t written = 0;
    if (join_reply_encode(JoinCarrier::WireRelay, accepted.reply,
                          MutableByteView{body.data(), body.size()}, written)) {
      (void)wire_.send_relay(from, FrameType::BootstrapReply, ByteView{body.data(), written});
    }
  }
  deliver_up(*live, index, relay.hops, object, bytes);
}

void JoinRelayGateway::handle_proxy_aborted(const NodeId from, const RelayToken& token,
                                            const RelayHeader& h) noexcept {
  ProxyFloor* floor = nullptr;
  const KeyOrder order = order_key(from, token, floor);
  if (order == KeyOrder::Older) return;
  if (order == KeyOrder::Same) {
    // Only the first termination of a live exchange notifies; a repeated
    // abort finds the floor terminated and stays silent (#116 Q116-03).
    ActiveRelay* relay = live_exchange(*floor);
    if (relay == nullptr) return;
    if (h.phase != relay->phase || h.joiner_mac != relay->joiner_mac) {
      ++stats_.frames_rejected;
      return;
    }
    finish_exchange(*relay, RelayAbortReason::ProxyAborted, relay->host_up_delivered);
    return;
  }
  // A newer key (or a first key) that aborts before its m1 still claims the
  // frontier as terminated, so a late m1 never opens it — without ever
  // creating a Host session for an unknown key (#116 §4.4).
  if (order == KeyOrder::UnknownProxy) {
    for (ProxyFloor& row : floors_) {
      if (!row.valid) {
        row.valid = true;
        row.proxy = from;
        row.max_proxy_epoch = token.proxy_epoch;
        row.max_relay_id = token.relay_id;
        return;
      }
    }
    return;  // floors full: the late m1 is refused for capacity instead
  }
  if (ActiveRelay* old = live_exchange(*floor)) {
    finish_exchange(*old, RelayAbortReason::Superseded, old->host_up_delivered);
  }
  floor->max_proxy_epoch = token.proxy_epoch;
  floor->max_relay_id = token.relay_id;
}

void JoinRelayGateway::handle_down_reply(const NodeId from, const JoinReply& reply,
                                         const MonotonicMs now_ms) noexcept {
  // A receipt applies to the Sending down object of its same token, phase
  // and step only; an old epoch never touches the current slot (#116 §5.1).
  if (reply.gateway_epoch != config_.gateway_epoch) return;
  RelayToken token{};
  token.gateway_epoch = reply.gateway_epoch;
  token.proxy_epoch = reply.proxy_epoch;
  token.relay_id = reply.id;
  ProxyFloor* floor = nullptr;
  if (order_key(from, token, floor) != KeyOrder::Same) return;
  ActiveRelay* relay = live_exchange(*floor);
  if (relay == nullptr || !relay_token_equal(relay->token, token) || !relay->down_sending) return;
  Slot* slot = slot_for(*relay);
  if (slot == nullptr || !slot->down) return;
  switch (slot->object.on_reply(reply, now_ms)) {
    case JoinObjectSlot::ReplyOutcome::Done:
      if (relay->down_final) {
        finish_silent(*relay);  // the Final down arrived; nothing to report
      } else {
        if (relay->down_step == 2) relay->m2_done = true;
        relay->down_sending = false;
        relay->down_done = true;
        free_slot(*slot);
      }
      return;
    case JoinObjectSlot::ReplyOutcome::Restart:
      (void)send_due_chunks(*slot, from, now_ms);
      return;
    default:
      return;
  }
}

Status JoinRelayGateway::send_due_chunks(Slot& slot, const NodeId proxy,
                                            const MonotonicMs now_ms) noexcept {
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
      status = wire_.send_relay(proxy, FrameType::BootstrapChunk,
                                ByteView{body.data(), written});
    }
    if (!status && first_failure) first_failure = status;
  }
  slot.object.note_sent(now_ms);
  return first_failure;
}

Status JoinRelayGateway::host_down(const NodeId to_proxy, const ByteView object,
                                   const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in sink callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "gateway epoch");
  if (now_ms < last_now_ms_) return Status::error(StatusCode::TimeUncertain, "clock regressed");
  if (membership_ != MembershipState::Member) {
    return Status::error(StatusCode::InvalidState, "gateway is not a member");
  }
  RelayObject decoded{};
  Status status = relay_object_decode(object, decoded);
  if (!status) return status;
  const RelayHeader& h = decoded.header;
  if (h.dir != RelayDirection::Down || h.proxy != to_proxy ||
      (to_proxy == config_.node && !config_.colocated_proxy)) {
    return invalid("relay down header");
  }
  if (h.state == RelayState::Abort) {
    // The old bypass (a down Abort through host_down, even for unknown
    // relays) is gone: cancel with host_abort instead (#116 §4.5).
    return Status::error(StatusCode::ProtocolError, "use host_abort to cancel");
  }
  if (h.gateway_epoch != config_.gateway_epoch) {
    return Status::error(StatusCode::Expired, "stale gateway epoch");
  }
  status = zt_admit_relay(membership_, true, AdmissionDirection::Tx,
                          object.size <= kMaxApplicationPayload ? relay_single_frame_type(h)
                                                                : FrameType::BootstrapChunk,
                          to_proxy, config_.node);
  if (!status) return status;
  // Only a live exchange takes a down object, and only the down stage it
  // expects; capacity is checked before anything is freed (#116 §4.5).
  ProxyFloor* floor = nullptr;
  const KeyOrder order = order_key(to_proxy, relay_token_of(h), floor);
  if (order == KeyOrder::UnknownProxy || order == KeyOrder::Newer) {
    return Status::error(StatusCode::NotFound, "relay not known");
  }
  if (order == KeyOrder::Older) return Status::error(StatusCode::Expired, "relay superseded");
  ActiveRelay* relay = live_exchange(*floor);
  if (relay == nullptr || !relay_token_equal(relay->token, relay_token_of(h))) {
    return Status::error(StatusCode::Expired, "relay terminated");
  }
  if (now_ms >= relay->deadline_ms) {
    in_call_ = true;
    finish_exchange(*relay, RelayAbortReason::GatewayExpired, relay->host_up_delivered);
    in_call_ = false;
    return Status::error(StatusCode::Expired, "relay deadline");
  }
  if (h.phase != relay->phase || h.joiner_mac != relay->joiner_mac) {
    return Status::error(StatusCode::Conflict, "relay identity mismatch");
  }
  const bool is_final = h.state == RelayState::Final;
  // The down stage must follow the accepted ups: step 2 wants step 1, an
  // EDHOC step 4 wants step 3, a step-5 error wants step 1.
  const bool up1 = (relay->accepted_up_mask & 1U) != 0;
  const bool up3 = (relay->accepted_up_mask & (1U << 1)) != 0;
  const bool resume = h.phase == JoinAuthPhase::Resume;
  bool stage_ok = false;
  if (h.step == 2 && !is_final) {
    stage_ok = up1;
  } else if (h.step == 2 && is_final && resume) {
    stage_ok = up1;
  } else if (h.step == 4 && is_final && !resume) {
    stage_ok = up3;
  } else if (h.step == kJoinEdhocErrorStep && is_final && !resume) {
    stage_ok = up1;
  }
  if (!stage_ok) return Status::error(StatusCode::Conflict, "unexpected down stage");
  if (h.step == 2 && relay->m2_done) {
    return Status::error(StatusCode::Expired, "down step 2 already completed");
  }
  if (is_final && relay->down_done && relay->down_final && relay->down_step == h.step) {
    return Status::error(StatusCode::Expired, "down already completed");
  }
  if (relay->down_sending) {
    // A retried down is idempotent only byte-for-byte; anything else while
    // sending contradicts the live exchange.
    Slot* held = slot_for(*relay);
    const ByteView sending = held != nullptr ? held->object.sending() : ByteView{};
    if (relay->down_step != h.step || relay->down_final != is_final || sending.size != object.size ||
        (object.size != 0 && std::memcmp(sending.data, object.data, object.size) != 0)) {
      return Status::error(StatusCode::Conflict, "down already sending");
    }
    last_now_ms_ = now_ms;
    return Status::success();  // same bytes: accepted, timers untouched
  }
  if (relay->down_done) {
    // The previous down finished but this one is for an older step (its
    // successor was already sent): it must not transmit again.
    if ((h.step == 2 && relay->down_step != 2) || (is_final && relay->down_step == h.step)) {
      return Status::error(StatusCode::Expired, "down already completed");
    }
    if (h.step != 2 && !is_final) return Status::error(StatusCode::Conflict, "down out of order");
  }
  last_now_ms_ = now_ms;
  in_call_ = true;
  status = Status::success();
  if (object.size <= kMaxApplicationPayload) {
    // A single frame either leaves at once or nothing changes.
    status = wire_.send_relay(to_proxy, relay_single_frame_type(h), object);
    if (status) {
      if (h.step == 2) relay->m2_done = true;
      relay->down_step = h.step;
      relay->down_done = true;
      relay->down_final = is_final;
      ++stats_.down_objects;
      if (is_final) finish_silent(*relay);
    }
  } else {
    const auto index = static_cast<std::uint8_t>(relay - relays_.data());
    Slot* slot = allocate_slot(*relay, index, true);
    if (slot == nullptr) {
      ++stats_.slot_busy;
      status = Status::error(StatusCode::NoCapacity, "no relay slot");
    } else {
      status = slot->object.load(JoinCarrier::WireRelay, h.phase, h.step, h.relay_id,
                                 h.gateway_epoch, h.proxy_epoch, object, now_ms);
      if (status) {
        // Local acceptance: a partially refused first burst stays queued
        // for the normal retransmit; the slot is never freed to fake a
        // rejection after bytes went out (#116 §4.5).
        (void)send_due_chunks(*slot, to_proxy, now_ms);
        relay->down_step = h.step;
        relay->down_sending = true;
        relay->down_final = is_final;
        ++stats_.down_objects;
      } else {
        free_slot(*slot);
      }
    }
  }
  in_call_ = false;
  return status;
}

Status JoinRelayGateway::host_abort(const NodeId proxy, const RelayToken token,
                                    const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in sink callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "gateway epoch");
  if (now_ms < last_now_ms_) return Status::error(StatusCode::TimeUncertain, "clock regressed");
  if (membership_ != MembershipState::Member) {
    return Status::error(StatusCode::InvalidState, "gateway is not a member");
  }
  if (!relay_token_valid(token) || token.gateway_epoch != config_.gateway_epoch) {
    return Status::error(StatusCode::NotFound, "relay not known");
  }
  ProxyFloor* floor = nullptr;
  if (order_key(proxy, token, floor) != KeyOrder::Same) {
    return Status::error(StatusCode::NotFound, "relay not known");
  }
  ActiveRelay* relay = live_exchange(*floor);
  if (relay == nullptr || !relay_token_equal(relay->token, token)) {
    return Status::error(StatusCode::NotFound, "relay not known");
  }
  if (now_ms >= relay->deadline_ms) {
    in_call_ = true;
    finish_exchange(*relay, RelayAbortReason::GatewayExpired, relay->host_up_delivered);
    in_call_ = false;
    return Status::error(StatusCode::Expired, "relay deadline");
  }
  last_now_ms_ = now_ms;
  in_call_ = true;
  // Cancel with the bound identity; the step only needs to be valid for
  // the phase (the proxy ends the relay on any Abort).
  std::uint8_t step = 1;
  if ((relay->accepted_up_mask & (1U << 1)) != 0) {
    step = 3;
  } else if ((relay->accepted_up_mask & (1U << 2)) != 0) {
    step = kJoinEdhocErrorStep;
  }
  RelayHeader header{};
  header.dir = RelayDirection::Down;
  header.relay_id = token.relay_id;
  header.proxy = proxy;
  header.joiner_mac = relay->joiner_mac;
  header.phase = relay->phase;
  header.step = first_step(relay->phase, step);
  header.gateway_epoch = token.gateway_epoch;
  header.proxy_epoch = token.proxy_epoch;
  RelayObject abort{};
  abort.header = header;
  abort.header.state = RelayState::Abort;
  abort.abort.status = RelayStatusCode::Aborted;
  std::array<std::uint8_t, kRelayHeaderSize + kRelayAbortBodySize> body{};
  std::size_t written = 0;
  Status status = relay_object_encode(abort, MutableByteView{body.data(), body.size()}, written);
  if (status) {
    status = wire_.send_relay(proxy, relay_single_frame_type(abort.header),
                              ByteView{body.data(), written});
  }
  finish_exchange(*relay, RelayAbortReason::HostAborted, false);
  in_call_ = false;
  return status;
}

Status JoinRelayGateway::poll(const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "in sink callback");
  if (!config_valid_) return Status::error(StatusCode::InvalidArgument, "gateway epoch");
  if (now_ms < last_now_ms_) return Status::error(StatusCode::TimeUncertain, "clock regressed");
  last_now_ms_ = now_ms;
  in_call_ = true;
  for (std::uint8_t i = 0; i < kActiveRelays; ++i) {
    ActiveRelay& relay = relays_[i];
    if (!relay.active) continue;
    // The 20 s exchange bound is fixed at admission; duplicates never move
    // it. Only a Host-owned session is told about the expiry.
    if (now_ms >= relay.deadline_ms) {
      finish_exchange(relay, RelayAbortReason::GatewayExpired, relay.host_up_delivered);
      continue;
    }
    Slot* slot = slot_for(relay);
    if (slot != nullptr && !slot->down &&
        slot->object.expire(now_ms, config_.assembly_timeout_ms)) {
      finish_exchange(relay, RelayAbortReason::GatewayExpired, relay.host_up_delivered);
      continue;
    }
    if (slot == nullptr || !slot->down ||
        slot->object.mode() != JoinObjectSlot::Mode::Sending ||
        now_ms - slot->object.last_send_ms() < config_.retransmit_ms) {
      continue;
    }
    if (slot->object.sends() >= config_.max_sends) {
      // The host sent this down object, so it always hears the failure.
      finish_exchange(relay, RelayAbortReason::DeliveryFailed, true);
      continue;
    }
    ++stats_.retransmissions;
    const NodeId proxy = floors_[relay.floor].proxy;
    (void)send_due_chunks(*slot, proxy, now_ms);
  }
  in_call_ = false;
  return Status::success();
}

}  // namespace routeloom::sdkv1
