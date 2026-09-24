#include "routeloom/sdkv1_join_transport.hpp"

#include <algorithm>
#include <cstring>

// SDK v1 zero-touch join transport codecs (docs/design/sdk-v1/02 §5, §7).
// See sdkv1_join_transport.hpp for the layouts and the rules each decoder
// enforces; the shared vectors in protocol/sdkv1-golden/join-transport/ pin
// the bytes.

namespace routeloom::sdkv1 {
namespace {

constexpr std::uint64_t kAllOnes = ~std::uint64_t{0};

bool id_valid(const std::uint64_t id) noexcept { return id != 0 && id != kAllOnes; }

Status malformed(const char* what) noexcept {
  return Status::error(StatusCode::ProtocolError, what);
}

Status invalid(const char* what) noexcept {
  return Status::error(StatusCode::InvalidArgument, what);
}

Status denied(const char* what) noexcept {
  return Status::error(StatusCode::AuthorizationFailed, what);
}

void put_u16(std::uint8_t* p, const std::uint16_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v >> 8U);
  p[1] = static_cast<std::uint8_t>(v);
}

void put_u32(std::uint8_t* p, const std::uint32_t v) noexcept {
  for (int i = 0; i < 4; ++i) p[i] = static_cast<std::uint8_t>(v >> (24U - 8U * i));
}

void put_u64(std::uint8_t* p, const std::uint64_t v) noexcept {
  for (int i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>(v >> (56U - 8U * i));
}

std::uint16_t get_u16(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8U) | p[1]);
}

std::uint32_t get_u32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24U) | (static_cast<std::uint32_t>(p[1]) << 16U) |
         (static_cast<std::uint32_t>(p[2]) << 8U) | p[3];
}

std::uint64_t get_u64(const std::uint8_t* p) noexcept {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8U) | p[i];
  return v;
}

bool message_size_ok(const ByteView message) noexcept {
  return message.data != nullptr && message.size >= 1 && message.size <= kJoinMessageMax;
}

bool relay_status_known(const std::uint8_t value) noexcept {
  return value >= static_cast<std::uint8_t>(RelayStatusCode::Queued) &&
         value <= static_cast<std::uint8_t>(RelayStatusCode::Aborted);
}

bool unicast_mac(const MacAddress& mac) noexcept {
  bool zero = true;
  for (const std::uint8_t b : mac) zero = zero && b == 0;
  return !zero && (mac[0] & 0x01U) == 0;
}

std::size_t chunk_len(const JoinCarrier carrier, const std::size_t total,
                      const std::size_t index) noexcept {
  const std::size_t grid = join_chunk_data_max(carrier);
  const std::size_t offset = index * grid;
  return offset >= total ? 0 : std::min(grid, total - offset);
}

// Shared chunk checks for encode and decode.
Status chunk_check(const JoinCarrier carrier, const JoinChunk& chunk) noexcept {
  if (chunk.phase == JoinAuthPhase::RelayStatus || !join_step_valid(chunk.phase, chunk.step)) {
    return malformed("join chunk sub");
  }
  if (chunk.id == 0) return malformed("join chunk id");
  const std::size_t grid = join_chunk_data_max(carrier);
  if (chunk.total <= join_single_frame_max(carrier) || chunk.total > kJoinObjectMax) {
    return malformed("join chunk total");
  }
  if (chunk.offset % grid != 0 || chunk.offset >= chunk.total) {
    return malformed("join chunk offset");
  }
  if (chunk.data.size != std::min<std::size_t>(grid, chunk.total - chunk.offset) ||
      chunk.data.data == nullptr) {
    return malformed("join chunk length");
  }
  return Status::success();
}

}  // namespace

// ===================================================================================
// RLD1 body v3
// ===================================================================================

Status zt_discover_body_validate(const ZtDiscoverBody& body) noexcept {
  if ((body.profile_bits & kJoinProfileRljoin1) == 0 ||
      (body.profile_bits & ~kJoinProfileMask) != 0) {
    return invalid("zt discover profile bits");
  }
  const std::uint32_t a0 = body.avoid_site_hints[0];
  const std::uint32_t a1 = body.avoid_site_hints[1];
  if (a0 == 0 && a1 != 0) return invalid("zt discover avoid packing");
  if (a0 != 0 && a0 == a1) return invalid("zt discover avoid duplicate");
  if (body.preferred_site_hint != 0 &&
      (body.preferred_site_hint == a0 || body.preferred_site_hint == a1)) {
    return invalid("zt discover preferred site avoided");
  }
  return Status::success();
}

Status zt_discover_body_encode(const ZtDiscoverBody& body,
                               ByteBuffer<kZtDiscoverBodySize>& out) noexcept {
  out.clear();
  const Status status = zt_discover_body_validate(body);
  if (!status) return status;
  std::uint8_t* p = out.bytes.data();
  p[0] = kZtBodyVersion;
  p[1] = kZtClass;
  put_u16(p + 2, body.preferred_site_hint != 0 ? kZtDiscoverPreferredValid : 0);
  put_u32(p + 4, body.profile_bits);
  put_u32(p + 8, body.org_hint);
  put_u32(p + 12, body.preferred_site_hint);
  put_u32(p + 16, body.avoid_site_hints[0]);
  put_u32(p + 20, body.avoid_site_hints[1]);
  out.size = kZtDiscoverBodySize;
  return Status::success();
}

Status zt_discover_body_decode(const ByteView encoded, ZtDiscoverBody& out) noexcept {
  if (encoded.data == nullptr || encoded.size != kZtDiscoverBodySize ||
      encoded.data[0] != kZtBodyVersion || encoded.data[1] != kZtClass) {
    return malformed("zt discover body");
  }
  const std::uint8_t* p = encoded.data;
  const std::uint16_t flags = get_u16(p + 2);
  ZtDiscoverBody body{};
  body.profile_bits = get_u32(p + 4);
  body.org_hint = get_u32(p + 8);
  body.preferred_site_hint = get_u32(p + 12);
  body.avoid_site_hints[0] = get_u32(p + 16);
  body.avoid_site_hints[1] = get_u32(p + 20);
  if ((flags & ~kZtDiscoverPreferredValid) != 0 ||
      ((flags & kZtDiscoverPreferredValid) != 0) != (body.preferred_site_hint != 0)) {
    return malformed("zt discover flags");
  }
  if (!zt_discover_body_validate(body)) return malformed("zt discover fields");
  out = body;
  return Status::success();
}

bool zt_discover_avoids(const ZtDiscoverBody& body, const std::uint32_t site_hint) noexcept {
  return site_hint != 0 &&
         (body.avoid_site_hints[0] == site_hint || body.avoid_site_hints[1] == site_hint);
}

Status zt_offer_body_validate(const ZtOfferBody& body) noexcept {
  if ((body.flags & ~kZtOfferFlagMask) != 0) return invalid("zt offer flags");
  return Status::success();
}

Status zt_offer_body_encode(const ZtOfferBody& body, ByteBuffer<kZtOfferBodySize>& out) noexcept {
  out.clear();
  const Status status = zt_offer_body_validate(body);
  if (!status) return status;
  std::uint8_t* p = out.bytes.data();
  p[0] = kZtBodyVersion;
  p[1] = kZtClass;
  p[2] = body.density;
  p[3] = body.flags;
  std::memcpy(p + 4, body.cookie.data(), kJoinCookieSize);
  std::memcpy(p + 20, body.responder_nonce.data(), body.responder_nonce.size());
  put_u32(p + 36, body.org_hint);
  put_u32(p + 40, body.site_hint);
  p[44] = body.authority_hops;
  p[45] = body.load;
  put_u16(p + 46, 0);
  out.size = kZtOfferBodySize;
  return Status::success();
}

Status zt_offer_body_decode(const ByteView encoded, ZtOfferBody& out) noexcept {
  if (encoded.data == nullptr || encoded.size != kZtOfferBodySize ||
      encoded.data[0] != kZtBodyVersion || encoded.data[1] != kZtClass) {
    return malformed("zt offer body");
  }
  const std::uint8_t* p = encoded.data;
  ZtOfferBody body{};
  body.density = p[2];
  body.flags = p[3];
  std::memcpy(body.cookie.data(), p + 4, kJoinCookieSize);
  std::memcpy(body.responder_nonce.data(), p + 20, body.responder_nonce.size());
  body.org_hint = get_u32(p + 36);
  body.site_hint = get_u32(p + 40);
  body.authority_hops = p[44];
  body.load = p[45];
  if (get_u16(p + 46) != 0 || !zt_offer_body_validate(body)) return malformed("zt offer fields");
  out = body;
  return Status::success();
}

Status zt_discover_frame_encode(const NodeId self, const JoinNonce& nonce,
                                const ZtDiscoverBody& body, autonomy::Rld1Encoded& out) noexcept {
  out.clear();
  if (!id_valid(self)) return invalid("zt discover claimed node");
  ByteBuffer<kZtDiscoverBodySize> encoded{};
  Status status = zt_discover_body_encode(body, encoded);
  if (!status) return status;
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::Discover;
  env.network_hint = 0;
  env.claimed_node = self;
  env.transaction_nonce = nonce;
  env.capability_bits = 0;
  std::memcpy(env.body.data(), encoded.bytes.data(), encoded.size);
  env.body_size = encoded.size;
  return autonomy::rld1_encode(env, out);
}

Status zt_discover_frame_decode(const ByteView frame, autonomy::Rld1Envelope& env,
                                ZtDiscoverBody& out) noexcept {
  autonomy::Rld1Envelope decoded{};
  if (!autonomy::rld1_decode(frame, decoded) || decoded.kind != FrameType::Discover) {
    return malformed("zt discover frame");
  }
  if (decoded.network_hint != 0 || !id_valid(decoded.claimed_node) ||
      decoded.capability_bits != 0) {
    return malformed("zt discover header");
  }
  ZtDiscoverBody body{};
  const Status status =
      zt_discover_body_decode(ByteView{decoded.body.data(), decoded.body_size}, body);
  if (!status) return status;
  env = decoded;
  out = body;
  return Status::success();
}

Status zt_offer_frame_encode(const NodeId proxy, const std::uint32_t network_low32,
                             const JoinNonce& nonce, const ZtOfferBody& body,
                             autonomy::Rld1Encoded& out) noexcept {
  out.clear();
  if (!id_valid(proxy) || network_low32 == 0) return invalid("zt offer header");
  ByteBuffer<kZtOfferBodySize> encoded{};
  Status status = zt_offer_body_encode(body, encoded);
  if (!status) return status;
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::Offer;
  env.network_hint = network_low32;
  env.claimed_node = proxy;
  env.transaction_nonce = nonce;
  env.capability_bits = 0;
  std::memcpy(env.body.data(), encoded.bytes.data(), encoded.size);
  env.body_size = encoded.size;
  return autonomy::rld1_encode(env, out);
}

Status zt_offer_frame_decode(const ByteView frame, autonomy::Rld1Envelope& env,
                             ZtOfferBody& out) noexcept {
  autonomy::Rld1Envelope decoded{};
  if (!autonomy::rld1_decode(frame, decoded) || decoded.kind != FrameType::Offer) {
    return malformed("zt offer frame");
  }
  if (decoded.network_hint == 0 || !id_valid(decoded.claimed_node) ||
      decoded.capability_bits != 0) {
    return malformed("zt offer header");
  }
  ZtOfferBody body{};
  const Status status =
      zt_offer_body_decode(ByteView{decoded.body.data(), decoded.body_size}, body);
  if (!status) return status;
  env = decoded;
  out = body;
  return Status::success();
}

// ===================================================================================
// BootstrapAuth phases 4-6
// ===================================================================================

bool join_step_valid(const JoinAuthPhase phase, const std::uint8_t step) noexcept {
  switch (phase) {
    case JoinAuthPhase::EdhocMessage:
      return step >= 1 && step <= kJoinEdhocErrorStep;
    case JoinAuthPhase::Resume:
      return step >= 1 && step <= 3;
    case JoinAuthPhase::RelayStatus:
      return step == 1;
  }
  return false;
}

JoinFlow join_step_flow(const JoinAuthPhase phase, const std::uint8_t step) noexcept {
  switch (phase) {
    case JoinAuthPhase::EdhocMessage:
      if (step == kJoinEdhocErrorStep) return JoinFlow::Either;
      return (step % 2U) == 1U ? JoinFlow::Up : JoinFlow::Down;
    case JoinAuthPhase::Resume:
      return step == 2 ? JoinFlow::Down : JoinFlow::Up;
    case JoinAuthPhase::RelayStatus:
      return JoinFlow::Down;
  }
  return JoinFlow::Either;
}

Status join_object_validate(const JoinAuthObject& object) noexcept {
  if (!join_step_valid(object.phase, object.step)) return invalid("join object step");
  if (object.phase == JoinAuthPhase::RelayStatus) {
    if (!relay_status_known(static_cast<std::uint8_t>(object.relay_status)) ||
        object.retry_after_ms > kJoinRetryAfterMaxMs) {
      return invalid("join relay status");
    }
    return Status::success();
  }
  const bool first = object.step == 1;
  if (object.phase == JoinAuthPhase::EdhocMessage) {
    if (object.cookie_present != first) return invalid("join cookie echo");
  } else if (object.cookie_present && !first) {
    return invalid("join cookie echo");
  }
  if (!message_size_ok(object.message)) return invalid("join message size");
  return Status::success();
}

std::size_t join_object_encoded_size(const JoinAuthObject& object) noexcept {
  if (object.phase == JoinAuthPhase::RelayStatus) return kRelayStatusObjectSize;
  return kJoinObjectHeadSize + (object.cookie_present ? kJoinCookieSize : 0) +
         object.message.size;
}

Status join_object_encode(const JoinAuthObject& object, const MutableByteView out,
                          std::size_t& written) noexcept {
  written = 0;
  const Status status = join_object_validate(object);
  if (!status) return status;
  const std::size_t size = join_object_encoded_size(object);
  if (out.data == nullptr || out.size < size) {
    return Status::error(StatusCode::NoCapacity, "join object output");
  }
  std::uint8_t* p = out.data;
  p[0] = autonomy::kPayloadVersion;
  p[1] = static_cast<std::uint8_t>(object.phase);
  p[2] = object.step;
  p[3] = 0;
  if (object.phase == JoinAuthPhase::RelayStatus) {
    p[4] = static_cast<std::uint8_t>(object.relay_status);
    put_u32(p + 5, object.retry_after_ms);
  } else {
    p[4] = object.cookie_present ? 1 : 0;
    p[5] = 0;
    std::size_t pos = kJoinObjectHeadSize;
    if (object.cookie_present) {
      std::memcpy(p + pos, object.cookie.data(), kJoinCookieSize);
      pos += kJoinCookieSize;
    }
    // In-place encodes (the message already sits at its final offset) are
    // allowed; memmove also covers a shifted overlap.
    if (object.message.data != p + pos) {
      std::memmove(p + pos, object.message.data, object.message.size);
    }
  }
  written = size;
  return Status::success();
}

Status join_object_decode(const ByteView encoded, JoinAuthObject& out) noexcept {
  if (encoded.data == nullptr || encoded.size < kJoinAuthPrefixSize ||
      encoded.size > kJoinObjectMax || encoded.data[0] != autonomy::kPayloadVersion ||
      encoded.data[3] != 0) {
    return malformed("join object prefix");
  }
  const std::uint8_t phase = encoded.data[1];
  if (phase < static_cast<std::uint8_t>(JoinAuthPhase::EdhocMessage) ||
      phase > static_cast<std::uint8_t>(JoinAuthPhase::RelayStatus)) {
    return malformed("join object phase");
  }
  JoinAuthObject object{};
  object.phase = static_cast<JoinAuthPhase>(phase);
  object.step = encoded.data[2];
  if (!join_step_valid(object.phase, object.step)) return malformed("join object step");
  if (object.phase == JoinAuthPhase::RelayStatus) {
    if (encoded.size != kRelayStatusObjectSize) return malformed("join relay status size");
    object.relay_status = static_cast<RelayStatusCode>(encoded.data[4]);
    object.retry_after_ms = get_u32(encoded.data + 5);
  } else {
    if (encoded.size < kJoinObjectHeadSize || encoded.data[4] > 1 || encoded.data[5] != 0) {
      return malformed("join object head");
    }
    object.cookie_present = encoded.data[4] == 1;
    std::size_t pos = kJoinObjectHeadSize;
    if (object.cookie_present) {
      if (encoded.size < pos + kJoinCookieSize) return malformed("join object cookie");
      std::memcpy(object.cookie.data(), encoded.data + pos, kJoinCookieSize);
      pos += kJoinCookieSize;
    }
    object.message = ByteView{encoded.data + pos, encoded.size - pos};
  }
  const Status status = join_object_validate(object);
  if (!status) return malformed(status.detail);
  out = object;
  return Status::success();
}

// ===================================================================================
// Chunks and replies
// ===================================================================================

bool join_sub_decode(const std::uint8_t sub, JoinAuthPhase& phase, std::uint8_t& step) noexcept {
  const std::uint8_t high = static_cast<std::uint8_t>(sub >> 4U);
  const std::uint8_t low = static_cast<std::uint8_t>(sub & 0x0FU);
  if (high != static_cast<std::uint8_t>(JoinAuthPhase::EdhocMessage) &&
      high != static_cast<std::uint8_t>(JoinAuthPhase::Resume)) {
    return false;
  }
  const JoinAuthPhase candidate = static_cast<JoinAuthPhase>(high);
  if (!join_step_valid(candidate, low)) return false;
  phase = candidate;
  step = low;
  return true;
}

std::uint32_t join_rld1_object_id(const JoinNonce& nonce) noexcept {
  return get_u32(nonce.data());
}

Status join_chunk_encode(const JoinCarrier carrier, const JoinChunk& chunk,
                         const MutableByteView out, std::size_t& written) noexcept {
  written = 0;
  const Status status = chunk_check(carrier, chunk);
  if (!status) return invalid(status.detail);
  const std::size_t size = kJoinChunkHeaderSize + chunk.data.size;
  if (out.data == nullptr || out.size < size) {
    return Status::error(StatusCode::NoCapacity, "join chunk output");
  }
  std::uint8_t* p = out.data;
  p[0] = kJoinChunkVersion;
  p[1] = join_sub(chunk.phase, chunk.step);
  put_u32(p + 2, chunk.id);
  put_u16(p + 6, chunk.offset);
  put_u16(p + 8, chunk.total);
  std::memcpy(p + kJoinChunkHeaderSize, chunk.data.data, chunk.data.size);
  written = size;
  return Status::success();
}

Status join_chunk_decode(const JoinCarrier carrier, const ByteView encoded,
                         JoinChunk& out) noexcept {
  if (encoded.data == nullptr || encoded.size <= kJoinChunkHeaderSize ||
      encoded.size > kJoinChunkHeaderSize + join_chunk_data_max(carrier) ||
      encoded.data[0] != kJoinChunkVersion) {
    return malformed("join chunk head");
  }
  JoinChunk chunk{};
  if (!join_sub_decode(encoded.data[1], chunk.phase, chunk.step)) {
    return malformed("join chunk sub");
  }
  chunk.id = get_u32(encoded.data + 2);
  chunk.offset = get_u16(encoded.data + 6);
  chunk.total = get_u16(encoded.data + 8);
  chunk.data = ByteView{encoded.data + kJoinChunkHeaderSize, encoded.size - kJoinChunkHeaderSize};
  const Status status = chunk_check(carrier, chunk);
  if (!status) return status;
  out = chunk;
  return Status::success();
}

Status join_reply_encode(const JoinReply& reply, const MutableByteView out,
                         std::size_t& written) noexcept {
  written = 0;
  if (reply.phase == JoinAuthPhase::RelayStatus || !join_step_valid(reply.phase, reply.step) ||
      reply.id == 0 || reply.received > kJoinObjectMax ||
      static_cast<std::uint8_t>(reply.status) > static_cast<std::uint8_t>(JoinReplyStatus::Aborted) ||
      (reply.status == JoinReplyStatus::Aborted && reply.received != 0) ||
      (reply.status == JoinReplyStatus::Complete && reply.received == 0)) {
    return invalid("join reply fields");
  }
  if (out.data == nullptr || out.size < kJoinReplySize) {
    return Status::error(StatusCode::NoCapacity, "join reply output");
  }
  std::uint8_t* p = out.data;
  p[0] = kJoinChunkVersion;
  p[1] = join_sub(reply.phase, reply.step);
  put_u32(p + 2, reply.id);
  put_u16(p + 6, reply.received);
  p[8] = static_cast<std::uint8_t>(reply.status);
  p[9] = 0;
  written = kJoinReplySize;
  return Status::success();
}

Status join_reply_decode(const ByteView encoded, JoinReply& out) noexcept {
  if (encoded.data == nullptr || encoded.size != kJoinReplySize ||
      encoded.data[0] != kJoinChunkVersion || encoded.data[9] != 0) {
    return malformed("join reply head");
  }
  JoinReply reply{};
  if (!join_sub_decode(encoded.data[1], reply.phase, reply.step)) {
    return malformed("join reply sub");
  }
  reply.id = get_u32(encoded.data + 2);
  reply.received = get_u16(encoded.data + 6);
  const std::uint8_t status = encoded.data[8];
  if (reply.id == 0 || reply.received > kJoinObjectMax ||
      status > static_cast<std::uint8_t>(JoinReplyStatus::Aborted)) {
    return malformed("join reply fields");
  }
  reply.status = static_cast<JoinReplyStatus>(status);
  if ((reply.status == JoinReplyStatus::Aborted && reply.received != 0) ||
      (reply.status == JoinReplyStatus::Complete && reply.received == 0)) {
    return malformed("join reply received");
  }
  out = reply;
  return Status::success();
}

// --- JoinObjectSlot ------------------------------------------------------------------

void JoinObjectSlot::reset() noexcept {
  // The buffer held transcript bytes of an unauthenticated peer: wipe it so
  // nothing leaks into the next exchange.
  data_.fill(0);
  mode_ = Mode::Idle;
  ++generation_;
  step_ = 0;
  id_ = 0;
  total_ = 0;
  have_ = 0;
  started_ms_ = 0;
  last_send_ms_ = 0;
  sends_ = 0;
  completed_valid_ = false;
  completed_carrier_ = JoinCarrier::Rld1;
  completed_sub_ = 0;
  completed_id_ = 0;
  completed_total_ = 0;
}

void JoinObjectSlot::drop_keep_completed() noexcept {
  const bool keep = completed_valid_;
  const JoinCarrier keep_carrier = completed_carrier_;
  const std::uint8_t keep_sub = completed_sub_;
  const std::uint32_t keep_id = completed_id_;
  const std::uint16_t keep_total = completed_total_;
  reset();
  completed_valid_ = keep;
  completed_carrier_ = keep_carrier;
  completed_sub_ = keep_sub;
  completed_id_ = keep_id;
  completed_total_ = keep_total;
}

std::uint16_t JoinObjectSlot::full_mask() const noexcept {
  const std::size_t count = join_chunk_count(carrier_, total_);
  return count >= kJoinChunkBitmapBits ? std::uint16_t{0xFFFF}
                                       : static_cast<std::uint16_t>((1U << count) - 1U);
}

std::uint16_t JoinObjectSlot::contiguous() const noexcept {
  const std::size_t count = join_chunk_count(carrier_, total_);
  std::size_t bytes = 0;
  for (std::size_t i = 0; i < count; ++i) {
    if ((have_ & (1U << i)) == 0) break;
    bytes += chunk_len(carrier_, total_, i);
  }
  return static_cast<std::uint16_t>(bytes);
}

JoinObjectSlot::Accepted JoinObjectSlot::accept(const JoinCarrier carrier, const JoinChunk& chunk,
                                                const MonotonicMs now_ms) noexcept {
  Accepted result{};
  result.reply.phase = chunk.phase;
  result.reply.step = chunk.step;
  result.reply.id = chunk.id;
  if (!chunk_check(carrier, chunk)) return result;  // Rejected
  const std::uint8_t sub = join_sub(chunk.phase, chunk.step);
  // A late duplicate of the object completed last (its Complete reply was
  // lost): answer Complete again, whatever the slot holds now.
  if (mode_ != Mode::Assembling && completed_valid_ && completed_carrier_ == carrier &&
      completed_sub_ == sub && completed_id_ == chunk.id && completed_total_ == chunk.total) {
    result.outcome = Outcome::Repeat;
    result.reply.received = chunk.total;
    result.reply.status = JoinReplyStatus::Complete;
    result.send_reply = true;
    return result;
  }
  if (mode_ == Mode::Sending || mode_ == Mode::Assembled) {
    result.outcome = Outcome::Busy;
    return result;
  }
  const bool same_key = mode_ == Mode::Assembling && carrier == carrier_ &&
                        sub == join_sub(phase_, step_) && chunk.id == id_;
  if (mode_ == Mode::Idle) {
    data_.fill(0);
    mode_ = Mode::Assembling;
    ++generation_;
    carrier_ = carrier;
    phase_ = chunk.phase;
    step_ = chunk.step;
    id_ = chunk.id;
    total_ = chunk.total;
    have_ = 0;
    started_ms_ = now_ms;
  } else if (!same_key) {
    result.outcome = Outcome::Busy;  // one assembly at a time (02 §10.1)
    return result;
  } else if (chunk.total != total_) {
    drop_keep_completed();
    result.outcome = Outcome::Conflict;
    result.reply.status = JoinReplyStatus::Aborted;
    result.send_reply = true;
    return result;
  }
  const std::size_t index = chunk.offset / join_chunk_data_max(carrier_);
  const std::uint16_t bit = static_cast<std::uint16_t>(1U << index);
  if ((have_ & bit) != 0) {
    if (std::memcmp(data_.data() + chunk.offset, chunk.data.data, chunk.data.size) != 0) {
      drop_keep_completed();
      result.outcome = Outcome::Conflict;
      result.reply.status = JoinReplyStatus::Aborted;
      result.send_reply = true;
      return result;
    }
  } else {
    std::memcpy(data_.data() + chunk.offset, chunk.data.data, chunk.data.size);
    have_ = static_cast<std::uint16_t>(have_ | bit);
  }
  result.send_reply = true;
  if (have_ == full_mask()) {
    mode_ = Mode::Assembled;
    ++generation_;
    completed_valid_ = true;
    completed_carrier_ = carrier_;
    completed_sub_ = sub;
    completed_id_ = id_;
    completed_total_ = total_;
    result.outcome = Outcome::Complete;
    result.reply.received = total_;
    result.reply.status = JoinReplyStatus::Complete;
  } else {
    result.outcome = Outcome::Progress;
    result.reply.received = contiguous();
    result.reply.status = JoinReplyStatus::Progress;
  }
  return result;
}

ByteView JoinObjectSlot::assembled() const noexcept {
  if (mode_ != Mode::Assembled) return ByteView{};
  return ByteView{data_.data(), total_};
}

void JoinObjectSlot::release_assembled() noexcept { drop_keep_completed(); }

void JoinObjectSlot::release_assembled_if(const std::uint32_t expected) noexcept {
  if (mode_ == Mode::Assembled && generation_ == expected) release_assembled();
}

Status JoinObjectSlot::load(const JoinCarrier carrier, const JoinAuthPhase phase,
                            const std::uint8_t step, const std::uint32_t id,
                            const ByteView object, const MonotonicMs now_ms) noexcept {
  if (object.data == nullptr || object.size > kJoinObjectMax) {
    return invalid("join slot object");
  }
  if (object.data != data_.data()) {
    // Validate before touching the buffer so a refused load keeps the slot.
    if (object.size <= join_single_frame_max(carrier) || phase == JoinAuthPhase::RelayStatus ||
        !join_step_valid(phase, step) || id == 0) {
      return invalid("join slot load");
    }
    std::memmove(data_.data(), object.data, object.size);
  }
  return load_in_place(carrier, phase, step, id, object.size, now_ms);
}

Status JoinObjectSlot::load_in_place(const JoinCarrier carrier, const JoinAuthPhase phase,
                                     const std::uint8_t step, const std::uint32_t id,
                                     const std::size_t size, const MonotonicMs now_ms) noexcept {
  if (size <= join_single_frame_max(carrier) || size > kJoinObjectMax ||
      phase == JoinAuthPhase::RelayStatus || !join_step_valid(phase, step) || id == 0) {
    return invalid("join slot load");
  }
  std::fill(data_.begin() + static_cast<std::ptrdiff_t>(size), data_.end(), std::uint8_t{0});
  mode_ = Mode::Sending;
  ++generation_;
  carrier_ = carrier;
  phase_ = phase;
  step_ = step;
  id_ = id;
  total_ = static_cast<std::uint16_t>(size);
  have_ = 0;
  started_ms_ = now_ms;
  last_send_ms_ = now_ms;
  sends_ = 0;
  return Status::success();
}

std::size_t JoinObjectSlot::chunk_total() const noexcept {
  return total_ == 0 ? 0 : join_chunk_count(carrier_, total_);
}

Status JoinObjectSlot::chunk_at(const std::size_t index, JoinChunk& out) const noexcept {
  if (mode_ != Mode::Sending || index >= chunk_total()) return invalid("join slot chunk");
  const std::size_t offset = index * join_chunk_data_max(carrier_);
  out.phase = phase_;
  out.step = step_;
  out.id = id_;
  out.offset = static_cast<std::uint16_t>(offset);
  out.total = total_;
  out.data = ByteView{data_.data() + offset, chunk_len(carrier_, total_, index)};
  return Status::success();
}

std::uint16_t JoinObjectSlot::pending_mask() const noexcept {
  if (mode_ != Mode::Sending) return 0;
  return static_cast<std::uint16_t>(full_mask() & ~have_);
}

JoinObjectSlot::ReplyOutcome JoinObjectSlot::on_reply(const JoinReply& reply,
                                                      const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (mode_ != Mode::Sending || reply.phase != phase_ || reply.step != step_ ||
      reply.id != id_) {
    return ReplyOutcome::Ignored;
  }
  switch (reply.status) {
    case JoinReplyStatus::Complete:
      if (reply.received != total_) return ReplyOutcome::Ignored;
      data_.fill(0);
      mode_ = Mode::Idle;
      ++generation_;
      have_ = 0;
      return ReplyOutcome::Done;
    case JoinReplyStatus::Aborted:
      have_ = 0;
      return ReplyOutcome::Restart;
    case JoinReplyStatus::Progress: {
      if (reply.received > total_) return ReplyOutcome::Ignored;
      // Every chunk that ends inside the confirmed contiguous prefix.
      const std::size_t count = join_chunk_count(carrier_, total_);
      std::size_t end = 0;
      for (std::size_t i = 0; i < count; ++i) {
        end += chunk_len(carrier_, total_, i);
        if (end > reply.received) break;
        have_ = static_cast<std::uint16_t>(have_ | (1U << i));
      }
      return ReplyOutcome::Progress;
    }
  }
  return ReplyOutcome::Ignored;
}

void JoinObjectSlot::note_sent(const MonotonicMs now_ms) noexcept {
  last_send_ms_ = now_ms;
  if (sends_ != 0xFF) ++sends_;
}

bool JoinObjectSlot::expire(const MonotonicMs now_ms, const std::uint32_t timeout_ms) noexcept {
  if (mode_ != Mode::Assembling || now_ms - started_ms_ < timeout_ms) return false;
  drop_keep_completed();
  return true;
}

// ===================================================================================
// Relay object
// ===================================================================================

Status relay_object_validate(const RelayObject& object) noexcept {
  const RelayHeader& h = object.header;
  if (h.dir != RelayDirection::Up && h.dir != RelayDirection::Down) {
    return invalid("relay direction");
  }
  if (h.relay_id == 0 || !id_valid(h.proxy) || !unicast_mac(h.joiner_mac)) {
    return invalid("relay identity");
  }
  if (h.phase == JoinAuthPhase::RelayStatus || !join_step_valid(h.phase, h.step)) {
    return invalid("relay step");
  }
  const bool up = h.dir == RelayDirection::Up;
  if (up ? h.joiner_rssi_dbm > 0 : h.joiner_rssi_dbm != 0) return invalid("relay rssi");
  const bool edhoc = h.phase == JoinAuthPhase::EdhocMessage;
  switch (h.state) {
    case RelayState::Continue:
      if (up) {
        if (join_step_flow(h.phase, h.step) == JoinFlow::Down) return invalid("relay up step");
      } else if (h.step != 2) {
        return invalid("relay down step");
      }
      break;
    case RelayState::Final:
      if (up) return invalid("relay final up");
      if (edhoc ? (h.step != 4 && h.step != kJoinEdhocErrorStep) : h.step != 2) {
        return invalid("relay final step");
      }
      break;
    case RelayState::Abort: {
      const std::uint8_t code = static_cast<std::uint8_t>(object.abort.status);
      if (!relay_status_known(code) || object.abort.retry_after_ms > kJoinRetryAfterMaxMs ||
          (up ? object.abort.status != RelayStatusCode::Aborted
              : object.abort.status == RelayStatusCode::Queued) ||
          object.message.size != 0) {
        return invalid("relay abort body");
      }
      return Status::success();
    }
    default:
      return invalid("relay state");
  }
  if (!message_size_ok(object.message)) return invalid("relay message size");
  return Status::success();
}

std::size_t relay_object_encoded_size(const RelayObject& object) noexcept {
  return kRelayHeaderSize + (object.header.state == RelayState::Abort ? kRelayAbortBodySize
                                                                      : object.message.size);
}

Status relay_object_encode(const RelayObject& object, const MutableByteView out,
                           std::size_t& written) noexcept {
  written = 0;
  const Status status = relay_object_validate(object);
  if (!status) return status;
  const std::size_t size = relay_object_encoded_size(object);
  if (out.data == nullptr || out.size < size) {
    return Status::error(StatusCode::NoCapacity, "relay object output");
  }
  const RelayHeader& h = object.header;
  std::uint8_t* p = out.data;
  p[0] = kRelayVersion;
  p[1] = static_cast<std::uint8_t>(h.dir);
  put_u32(p + 2, h.relay_id);
  put_u64(p + 6, h.proxy);
  std::memcpy(p + 14, h.joiner_mac.data(), h.joiner_mac.size());
  p[20] = h.step;
  p[21] = static_cast<std::uint8_t>(h.state);
  p[22] = static_cast<std::uint8_t>(h.joiner_rssi_dbm);
  p[23] = static_cast<std::uint8_t>(h.phase);
  if (h.state == RelayState::Abort) {
    p[24] = static_cast<std::uint8_t>(object.abort.status);
    put_u32(p + 25, object.abort.retry_after_ms);
  } else if (object.message.data != p + kRelayHeaderSize) {
    std::memmove(p + kRelayHeaderSize, object.message.data, object.message.size);
  }
  written = size;
  return Status::success();
}

Status relay_object_decode(const ByteView encoded, RelayObject& out) noexcept {
  if (encoded.data == nullptr || encoded.size <= kRelayHeaderSize ||
      encoded.size > kRelayObjectMax || encoded.data[0] != kRelayVersion) {
    return malformed("relay header");
  }
  const std::uint8_t* p = encoded.data;
  RelayObject object{};
  RelayHeader& h = object.header;
  h.dir = static_cast<RelayDirection>(p[1]);
  h.relay_id = get_u32(p + 2);
  h.proxy = get_u64(p + 6);
  std::memcpy(h.joiner_mac.data(), p + 14, h.joiner_mac.size());
  h.step = p[20];
  const std::uint8_t state = p[21];
  if (state > static_cast<std::uint8_t>(RelayState::Abort)) return malformed("relay state");
  h.state = static_cast<RelayState>(state);
  h.joiner_rssi_dbm = static_cast<std::int8_t>(p[22]);
  const std::uint8_t phase = p[23];
  if (phase != static_cast<std::uint8_t>(JoinAuthPhase::EdhocMessage) &&
      phase != static_cast<std::uint8_t>(JoinAuthPhase::Resume)) {
    return malformed("relay phase");
  }
  h.phase = static_cast<JoinAuthPhase>(phase);
  const ByteView body{p + kRelayHeaderSize, encoded.size - kRelayHeaderSize};
  if (h.state == RelayState::Abort) {
    if (body.size != kRelayAbortBodySize) return malformed("relay abort size");
    object.abort.status = static_cast<RelayStatusCode>(body.data[0]);
    object.abort.retry_after_ms = get_u32(body.data + 1);
  } else {
    object.message = body;
  }
  const Status status = relay_object_validate(object);
  if (!status) return malformed(status.detail);
  out = object;
  return Status::success();
}

FrameType relay_single_frame_type(const RelayHeader& header) noexcept {
  if (header.dir == RelayDirection::Down && header.state != RelayState::Continue) {
    return FrameType::MembershipResult;
  }
  return FrameType::BootstrapAuth;
}

Status relay_single_frame_decode(const FrameType type, const ByteView payload,
                                 RelayObject& out) noexcept {
  if (payload.size > kMaxApplicationPayload) return malformed("relay single frame size");
  RelayObject object{};
  const Status status = relay_object_decode(payload, object);
  if (!status) return status;
  if (relay_single_frame_type(object.header) != type) return malformed("relay frame type");
  out = object;
  return Status::success();
}

// ===================================================================================
// Lane classification and admission
// ===================================================================================

bool zt_rld1_frame(const autonomy::Rld1Envelope& env) noexcept {
  JoinAuthPhase phase{};
  std::uint8_t step = 0;
  switch (env.kind) {
    case FrameType::Discover:
    case FrameType::Offer:
      return env.body_size >= 1 && env.body[0] == kZtBodyVersion;
    case FrameType::BootstrapAuth:
      return env.body_size >= 2 &&
             env.body[1] >= static_cast<std::uint8_t>(JoinAuthPhase::EdhocMessage) &&
             env.body[1] <= static_cast<std::uint8_t>(JoinAuthPhase::RelayStatus);
    case FrameType::BootstrapChunk:
    case FrameType::BootstrapReply:
      return env.body_size >= 2 && env.body[0] == kJoinChunkVersion &&
             join_sub_decode(env.body[1], phase, step);
    default:
      return false;
  }
}

Status zt_admit_rld1(const MembershipState local, const AdmissionDirection direction,
                     const autonomy::Rld1Envelope& env) noexcept {
  if (!zt_rld1_frame(env)) return malformed("not a zero-touch frame");
  const bool joiner =
      local == MembershipState::Discovering || local == MembershipState::Authenticating;
  const bool proxy = local == MembershipState::Member;
  if (!joiner && !proxy) return denied("zero-touch lane closed in this membership state");
  // Who originates this frame: the device (up) or the proxy (down).
  JoinFlow origin = JoinFlow::Either;
  bool discovery = false;
  switch (env.kind) {
    case FrameType::Discover:
      origin = JoinFlow::Up;
      discovery = true;
      break;
    case FrameType::Offer:
      origin = JoinFlow::Down;
      discovery = true;
      break;
    case FrameType::BootstrapAuth: {
      if (env.body_size < 3) return malformed("zero-touch auth prefix");
      const JoinAuthPhase phase = static_cast<JoinAuthPhase>(env.body[1]);
      if (!join_step_valid(phase, env.body[2])) return malformed("zero-touch auth step");
      origin = join_step_flow(phase, env.body[2]);
      break;
    }
    case FrameType::BootstrapChunk:
    case FrameType::BootstrapReply: {
      JoinAuthPhase phase{};
      std::uint8_t step = 0;
      (void)join_sub_decode(env.body[1], phase, step);  // zt_rld1_frame checked it
      origin = join_step_flow(phase, step);
      // A reply acknowledges an object that flows the other way.
      if (env.kind == FrameType::BootstrapReply && origin != JoinFlow::Either) {
        origin = origin == JoinFlow::Up ? JoinFlow::Down : JoinFlow::Up;
      }
      break;
    }
    default:
      return malformed("not a zero-touch frame");
  }
  if (joiner && !discovery && local != MembershipState::Authenticating) {
    return denied("zero-touch exchange before authentication");
  }
  const bool tx = direction == AdmissionDirection::Tx;
  // The joiner sends up-frames and receives down-frames; the proxy the reverse.
  const JoinFlow mine = joiner ? JoinFlow::Up : JoinFlow::Down;
  const bool local_origin = origin == JoinFlow::Either || origin == mine;
  const bool remote_origin = origin == JoinFlow::Either || origin != mine;
  if (tx ? !local_origin : !remote_origin) {
    return denied("zero-touch frame not permitted for this role and direction");
  }
  return Status::success();
}

Status zt_admit_relay(const MembershipState local, const bool local_is_gateway,
                      const AdmissionDirection direction, const FrameType type, const NodeId peer,
                      const NodeId gateway) noexcept {
  if (type != FrameType::BootstrapAuth && type != FrameType::MembershipResult &&
      type != FrameType::BootstrapChunk && type != FrameType::BootstrapReply) {
    return malformed("not a relay frame type");
  }
  if (local != MembershipState::Member) return denied("relay requires a member");
  if (!id_valid(peer)) return denied("relay peer");
  const bool tx = direction == AdmissionDirection::Tx;
  if (local_is_gateway) {
    // The gateway never receives a final/abort type from a proxy.
    if (!tx && type == FrameType::MembershipResult) return denied("relay final toward gateway");
    return Status::success();
  }
  if (!id_valid(gateway) || peer != gateway) return denied("relay peer is not the gateway");
  if (tx && type == FrameType::MembershipResult) return denied("relay final from a proxy");
  return Status::success();
}

}  // namespace routeloom::sdkv1
