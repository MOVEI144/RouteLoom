// Authority-channel mesh transport — see sdkv1_authority_transport.hpp.

#include "routeloom/sdkv1_authority_transport.hpp"

#include <cstring>

#include "routeloom/discovery_scope.hpp"  // sha256
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {

constexpr std::size_t kChunkDataMax = kMaxApplicationPayload - 38;  // 90
constexpr std::size_t kUsbFragmentDataMax = 960;

void sat_inc(std::uint32_t& counter) noexcept {
  if (counter < 0xFFFFFFFFu) ++counter;
}

bool hash_equal(const autonomy::ObjectHash& a, const autonomy::ObjectHash& b) noexcept {
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool chunk_on_grid(const std::uint16_t total, const std::uint16_t offset,
                   const std::uint16_t size, const std::uint16_t received) noexcept {
  if (size == 0 || offset >= total || offset % kChunkDataMax != 0 || offset > received) {
    return false;
  }
  const std::uint32_t remaining = static_cast<std::uint32_t>(total) - offset;
  return size == (remaining < kChunkDataMax ? remaining : kChunkDataMax);
}

bool acked_sent_chunk(const std::uint16_t total, const std::uint16_t progress,
                      const std::uint16_t acknowledged,
                      const std::uint8_t sends) noexcept {
  if (sends == 0 || acknowledged <= progress || acknowledged > total ||
      (acknowledged != total && acknowledged % kChunkDataMax != 0)) {
    return false;
  }
  return static_cast<std::size_t>(acknowledged - progress) <= kChunkDataMax;
}

}  // namespace

Status authority_carrier_encode(const AuthorityCarrierKind kind,
                                const std::uint32_t exchange_id, const ByteView body,
                                const MutableByteView out,
                                std::size_t& written) noexcept {
  written = 0;
  const auto kind_byte = static_cast<std::uint8_t>(kind);
  const bool token_ok = kind == AuthorityCarrierKind::R1 ||
                                kind == AuthorityCarrierKind::R2 ||
                                kind == AuthorityCarrierKind::R3
                            ? exchange_id != 0
                            : exchange_id == 0;
  if (!authority_carrier_kind_valid(kind_byte) || !token_ok ||
      !authority_carrier_length_valid(kind, body.size) ||
      body.size > kAuthorityCarrierBodyMax ||
      out.size < kAuthorityCarrierHeadSize + body.size ||
      (body.size != 0 && (body.data == nullptr || out.data == nullptr))) {
    return Status::error(StatusCode::InvalidArgument, "authority carrier encode");
  }
  out.data[0] = 1;
  out.data[1] = kAuthorityControlSubtype;
  out.data[2] = kind_byte;
  out.data[3] = 0;
  out.data[4] = static_cast<std::uint8_t>(exchange_id >> 24);
  out.data[5] = static_cast<std::uint8_t>(exchange_id >> 16);
  out.data[6] = static_cast<std::uint8_t>(exchange_id >> 8);
  out.data[7] = static_cast<std::uint8_t>(exchange_id);
  if (body.size != 0) std::memcpy(out.data + kAuthorityCarrierHeadSize, body.data, body.size);
  written = kAuthorityCarrierHeadSize + body.size;
  return Status::success();
}

Status authority_carrier_decode(const ByteView input, AuthorityCarrierKind& kind,
                                std::uint32_t& exchange_id, ByteView& body) noexcept {
  kind = AuthorityCarrierKind::Envelope;
  exchange_id = 0;
  body = {};
  if (input.size < kAuthorityCarrierHeadSize || input.size > kMaxApplicationPayload ||
      input.data == nullptr || input.data[0] != 1 ||
      input.data[1] != kAuthorityControlSubtype ||
      !authority_carrier_kind_valid(input.data[2]) || input.data[3] != 0) {
    return Status::error(StatusCode::ProtocolError, "authority carrier head");
  }
  kind = static_cast<AuthorityCarrierKind>(input.data[2]);
  exchange_id = (static_cast<std::uint32_t>(input.data[4]) << 24) |
                (static_cast<std::uint32_t>(input.data[5]) << 16) |
                (static_cast<std::uint32_t>(input.data[6]) << 8) |
                static_cast<std::uint32_t>(input.data[7]);
  const bool token_ok = kind == AuthorityCarrierKind::R1 ||
                                kind == AuthorityCarrierKind::R2 ||
                                kind == AuthorityCarrierKind::R3
                            ? exchange_id != 0
                            : exchange_id == 0;
  body = ByteView{input.data + kAuthorityCarrierHeadSize,
                  input.size - kAuthorityCarrierHeadSize};
  if (!token_ok || !authority_carrier_length_valid(kind, body.size)) {
    body = {};
    return Status::error(StatusCode::ProtocolError, "authority carrier body");
  }
  return Status::success();
}

// --- Endpoint -----------------------------------------------------------------

AuthorityEndpoint::~AuthorityEndpoint() {
  drop_rx();
  drop_tx();
}

void AuthorityEndpoint::drop_rx() noexcept {
  carrier_ready_ = false;
  carrier_size_ = 0;
  object_ready_ = false;
  rx_.active = false;
  secure_clear(carrier_buf_.data(), carrier_buf_.size());
  secure_clear(rx_.buffer.data(), rx_.buffer.size());
  for (auto& byte : rx_.bitmap) byte = 0;
}

void AuthorityEndpoint::drop_tx() noexcept {
  tx_.active = false;
  tx_.hash.fill(0);
  secure_clear(tx_.buffer.data(), tx_.buffer.size());
}

bool AuthorityEndpoint::try_send(const NodeId gateway, const AuthorityCarrierKind kind,
                                 const ByteView carrier,
                                 std::uint64_t& token) noexcept {
  token = 0;
  if (in_call_ || tx_.active || tx_result_ready_) return false;
  if (gateway == kInvalidNodeId || gateway == self_ ||
      !authority_carrier_kind_valid(static_cast<std::uint8_t>(kind)) ||
      !authority_carrier_length_valid(kind, carrier.size) ||
      carrier.size > kAuthorityObjectMax ||
      (carrier.size != 0 && carrier.data == nullptr)) {
    return false;
  }
  // Only envelopes exceed the carrier frame; handshake messages always fit.
  if (carrier.size > kAuthorityCarrierBodyMax && kind != AuthorityCarrierKind::Envelope) {
    return false;
  }
  // Stage only: the pump sends on poll with the Owner's clock (try_send
  // carries none, and a job deadline needs real time).
  std::memcpy(tx_.buffer.data(), carrier.data, carrier.size);
  tx_.kind = kind;
  if (carrier.size > kAuthorityCarrierBodyMax) {
    Digest256 digest{};
    sha256(ByteView{tx_.buffer.data(), carrier.size}, digest);
    for (std::size_t i = 0; i < tx_.hash.size(); ++i) tx_.hash[i] = digest[i];
    secure_clear(digest);
  }
  token = next_token_;
  if (++next_token_ == 0) next_token_ = 1;
  tx_.active = true;
  tx_.gateway = gateway;
  tx_.token = token;
  tx_.total_len = static_cast<std::uint16_t>(carrier.size);
  tx_.acked = 0;
  tx_.sends = 0;
  tx_.started_ms = 0;  // stamped on the first poll
  tx_.last_send_ms = 0;
  if (carrier.size <= kAuthorityCarrierBodyMax) {
    sat_inc(counters_.tx_carriers);
  } else {
    sat_inc(counters_.tx_objects);
  }
  return true;
}

bool AuthorityEndpoint::claim_control(const std::uint8_t subtype) noexcept {
  return subtype == kAuthorityControlSubtype;
}

bool AuthorityEndpoint::claim_kind(const autonomy::ControlObjectKind kind) noexcept {
  return kind == autonomy::ControlObjectKind::AuthorityEnvelope;
}

bool AuthorityEndpoint::claim_transfer(const NodeId origin,
                                       const autonomy::ObjectHash& hash) noexcept {
  if ((rx_.active || object_ready_) && origin == rx_.origin &&
      hash_equal(hash, rx_.hash)) return true;
  return tx_.active && tx_.total_len > kAuthorityCarrierBodyMax &&
         origin == tx_.gateway && hash_equal(hash, tx_.hash);
}

void AuthorityEndpoint::on_control(const NodeId origin, const ByteView payload,
                                   const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (in_call_) return;
  AuthorityCarrierKind kind{AuthorityCarrierKind::Envelope};
  std::uint32_t exchange = 0;
  ByteView body{};
  if (origin == kInvalidNodeId || origin == self_ || carrier_ready_ ||
      !authority_carrier_decode(payload, kind, exchange, body)) {
    sat_inc(counters_.rx_denied);
    return;
  }
  // The exchange token pairs wire retries only; the channel correlates by
  // content (RLRES1 nonces, envelope counters), so it is not forwarded.
  (void)exchange;
  std::memcpy(carrier_buf_.data(), body.data, body.size);
  carrier_kind_ = kind;
  carrier_size_ = body.size;
  carrier_ready_ = true;
  sat_inc(counters_.rx_carriers);
}

void AuthorityEndpoint::on_manifest(
    const NodeId origin, const autonomy::ControlObjectPayload& manifest,
    const MonotonicMs now_ms) noexcept {
  if (in_call_) return;
  if (rx_.active && origin == rx_.origin && hash_equal(manifest.object_hash, rx_.hash) &&
      manifest.total_len == rx_.total_len) {
    // Sender retry of the live manifest: re-ack progress, no extension.
    send_ack(origin, manifest.object_hash, rx_.received,
             autonomy::ObjectAckStatus::Incomplete, now_ms);
    return;
  }
  if (origin == kInvalidNodeId || origin == self_ || rx_.active || object_ready_ ||
      manifest.total_len < keys::kAuthorityEnvelopeMin ||
      manifest.total_len > kAuthorityObjectMax) {
    send_ack(origin, manifest.object_hash, 0, autonomy::ObjectAckStatus::Failed, now_ms);
    sat_inc(counters_.rx_denied);
    return;
  }
  rx_.active = true;
  rx_.origin = origin;
  rx_.hash = manifest.object_hash;
  rx_.total_len = manifest.total_len;
  rx_.received = 0;
  rx_.started_ms = now_ms;
  for (auto& byte : rx_.bitmap) byte = 0;
  send_ack(origin, manifest.object_hash, 0, autonomy::ObjectAckStatus::Incomplete, now_ms);
}

void AuthorityEndpoint::on_chunk(const NodeId origin,
                                 const autonomy::ObjectChunkPayload& chunk,
                                 const MonotonicMs now_ms) noexcept {
  if (in_call_) return;
  if (!rx_.active || object_ready_ || origin != rx_.origin ||
      !hash_equal(chunk.object_hash, rx_.hash)) {
    sat_inc(counters_.rx_denied);
    return;
  }
  if (now_ms - rx_.started_ms > kAuthorityReassemblyTimeoutMs) {
    const std::uint16_t progress = rx_.received;
    const autonomy::ObjectHash hash = rx_.hash;
    drop_rx();
    send_ack(origin, hash, progress, autonomy::ObjectAckStatus::Failed, now_ms);
    sat_inc(counters_.rx_denied);
    return;
  }
  if (!chunk_on_grid(rx_.total_len, chunk.offset, chunk.data_size, rx_.received)) {
    // Out-of-window bytes poison the assembly, like the config path.
    const std::uint16_t progress = rx_.received;
    const autonomy::ObjectHash hash = rx_.hash;
    drop_rx();
    send_ack(origin, hash, progress, autonomy::ObjectAckStatus::Failed, now_ms);
    sat_inc(counters_.rx_denied);
    return;
  }
  for (std::uint16_t i = 0; i < chunk.data_size; ++i) {
    const std::uint16_t at = static_cast<std::uint16_t>(chunk.offset + i);
    const std::uint8_t mask = static_cast<std::uint8_t>(1U << (at & 7U));
    if ((rx_.bitmap[at >> 3U] & mask) != 0) {
      if (rx_.buffer[at] != chunk.data[i]) {
        const std::uint16_t progress = rx_.received;
        const autonomy::ObjectHash hash = rx_.hash;
        drop_rx();
        send_ack(origin, hash, progress, autonomy::ObjectAckStatus::Failed, now_ms);
        sat_inc(counters_.rx_denied);
        return;
      }
      continue;
    }
    rx_.bitmap[at >> 3U] = static_cast<std::uint8_t>(rx_.bitmap[at >> 3U] | mask);
    rx_.buffer[at] = chunk.data[i];
    ++rx_.received;
  }
  if (rx_.received >= rx_.total_len) {
    Digest256 digest{};
    sha256(ByteView{rx_.buffer.data(), rx_.total_len}, digest);
    bool match = true;
    for (std::size_t i = 0; i < rx_.hash.size(); ++i) {
      if (digest[i] != rx_.hash[i]) match = false;
    }
    secure_clear(digest);
    if (!match) {
      const autonomy::ObjectHash hash = rx_.hash;
      drop_rx();
      send_ack(origin, hash, rx_.total_len, autonomy::ObjectAckStatus::Failed, now_ms);
      sat_inc(counters_.rx_denied);
      return;
    }
    rx_.active = false;
    object_ready_ = true;
    send_ack(origin, rx_.hash, rx_.total_len, autonomy::ObjectAckStatus::Ok, now_ms);
    sat_inc(counters_.rx_objects);
    return;
  }
  send_ack(origin, chunk.object_hash, rx_.received,
           autonomy::ObjectAckStatus::Incomplete, now_ms);
}

void AuthorityEndpoint::on_ack(const NodeId origin, const autonomy::ObjectAckPayload& ack,
                               const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (in_call_ || !tx_.active || tx_.total_len <= kAuthorityCarrierBodyMax ||
      origin != tx_.gateway ||
      !hash_equal(ack.object_hash, tx_.hash)) {
    return;
  }
  const bool progress =
      acked_sent_chunk(tx_.total_len, tx_.acked, ack.received_len, tx_.sends);
  if (ack.status == autonomy::ObjectAckStatus::Ok && progress &&
      ack.received_len == tx_.total_len) {
    complete_tx(true);
    return;
  }
  if (ack.status == autonomy::ObjectAckStatus::Failed) {
    complete_tx(false);
    return;
  }
  if (ack.status == autonomy::ObjectAckStatus::Incomplete && progress &&
      ack.received_len < tx_.total_len) {
    tx_.acked = ack.received_len;
    tx_.sends = 0;  // the next outstanding chunk gets a fresh retry budget
  }
}

bool AuthorityEndpoint::take_rx(AuthorityRxCarrier& out) noexcept {
  if (in_call_) return false;
  if (carrier_ready_) {
    out.kind = carrier_kind_;
    out.bytes = ByteView{carrier_buf_.data(), carrier_size_};
    carrier_ready_ = false;
    return true;
  }
  if (object_ready_) {
    // Kind-7 objects are envelope bytes verbatim (never handshake wire).
    out.kind = AuthorityCarrierKind::Envelope;
    out.bytes = ByteView{rx_.buffer.data(), rx_.total_len};
    object_ready_ = false;
    return true;
  }
  return false;
}

bool AuthorityEndpoint::take_tx_result(AuthorityTxResult& out) noexcept {
  if (in_call_ || !tx_result_ready_) return false;
  out = tx_result_;
  tx_result_ready_ = false;
  return true;
}

void AuthorityEndpoint::send_ack(const NodeId dest, const autonomy::ObjectHash& hash,
                                 const std::uint16_t received,
                                 const autonomy::ObjectAckStatus status,
                                 const MonotonicMs now_ms) noexcept {
  if (dest == kInvalidNodeId || dest == self_) return;
  autonomy::ObjectAckPayload ack{};
  ack.object_hash = hash;
  ack.received_len = received;
  ack.status = status;
  autonomy::EncodedPayload encoded{};
  if (!autonomy::object_ack_encode(ack, encoded)) return;
  in_call_ = true;
  (void)mesh_.config_send(dest, FrameType::ObjectAck, encoded.view(), now_ms);
  in_call_ = false;
}

void AuthorityEndpoint::complete_tx(const bool delivered) noexcept {
  tx_result_ = AuthorityTxResult{tx_.token, delivered};
  tx_result_ready_ = true;
  drop_tx();
}

bool AuthorityEndpoint::pump_tx(const MonotonicMs now_ms) noexcept {
  if (!tx_.active) return true;
  if (tx_.started_ms == 0) {
    tx_.started_ms = now_ms;
    tx_.last_send_ms = 0;
  }
  if (now_ms - tx_.started_ms > kAuthorityTransferTimeoutMs) {
    complete_tx(false);
    sat_inc(counters_.tx_timeouts);
    return true;
  }
  if (tx_.total_len <= kAuthorityCarrierBodyMax) {
    // Small carriers are fire-and-forget at this layer: the mesh
    // hop-accepts them and the channel's own ACK/retry recovers loss.
    std::uint32_t exchange = 0;
    if (tx_.kind == AuthorityCarrierKind::R1 || tx_.kind == AuthorityCarrierKind::R2 ||
        tx_.kind == AuthorityCarrierKind::R3) {
      exchange = next_exchange_;
      if (++next_exchange_ == 0) next_exchange_ = 1;
    }
    std::array<std::uint8_t, kMaxApplicationPayload> frame{};
    std::size_t written = 0;
    if (!authority_carrier_encode(tx_.kind, exchange,
                                  ByteView{tx_.buffer.data(), tx_.total_len},
                                  MutableByteView{frame.data(), frame.size()},
                                  written)) {
      complete_tx(false);
      return true;
    }
    in_call_ = true;
    const Status sent = mesh_.config_send(tx_.gateway, FrameType::Control,
                                          ByteView{frame.data(), written}, now_ms);
    in_call_ = false;
    if (!sent) return true;  // mesh shed it: retry on the next poll
    complete_tx(true);
    return true;
  }
  if (tx_.acked >= tx_.total_len) return true;  // waiting for the Ok
  if (tx_.sends >= kAuthorityChunkSendsMax) {
    complete_tx(false);  // the receiver never caught up: the channel retries
    sat_inc(counters_.tx_timeouts);
    return true;
  }
  if (tx_.sends != 0 && now_ms - tx_.last_send_ms < kAuthorityChunkResendMs) return true;
  if (tx_.acked == 0) {
    // The receiver cannot assemble chunks without the manifest: precede
    // the first chunk with it until progress arrives.
    autonomy::ControlObjectPayload manifest{};
    manifest.kind = autonomy::ControlObjectKind::AuthorityEnvelope;
    manifest.total_len = tx_.total_len;
    manifest.object_hash = tx_.hash;
    autonomy::EncodedPayload encoded{};
    if (!autonomy::control_object_encode(manifest, encoded)) {
      complete_tx(false);
      return true;
    }
    in_call_ = true;
    const Status sent = mesh_.config_send(tx_.gateway, FrameType::ControlObject,
                                          encoded.view(), now_ms);
    in_call_ = false;
    if (!sent) return true;
  }
  autonomy::ObjectChunkPayload chunk{};
  chunk.object_hash = tx_.hash;
  chunk.offset = tx_.acked;
  const std::uint32_t rest = static_cast<std::uint32_t>(tx_.total_len) - tx_.acked;
  chunk.data_size = static_cast<std::uint16_t>(rest > kChunkDataMax ? kChunkDataMax : rest);
  std::memcpy(chunk.data.data(), tx_.buffer.data() + tx_.acked, chunk.data_size);
  autonomy::EncodedPayload encoded{};
  if (!autonomy::object_chunk_encode(chunk, encoded)) {
    complete_tx(false);
    return true;
  }
  in_call_ = true;
  const Status sent =
      mesh_.config_send(tx_.gateway, FrameType::ObjectChunk, encoded.view(), now_ms);
  in_call_ = false;
  if (!sent) return true;  // mesh shed the frame: retry on the next poll
  tx_.last_send_ms = now_ms;
  ++tx_.sends;
  return true;
}

void AuthorityEndpoint::poll(const MonotonicMs now_ms) noexcept {
  if (in_call_) return;
  if (rx_.active && !object_ready_ &&
      now_ms - rx_.started_ms > kAuthorityReassemblyTimeoutMs) {
    const NodeId origin = rx_.origin;
    const autonomy::ObjectHash hash = rx_.hash;
    const std::uint16_t progress = rx_.received;
    drop_rx();
    send_ack(origin, hash, progress, autonomy::ObjectAckStatus::Failed, now_ms);
    sat_inc(counters_.rx_denied);
  }
  (void)pump_tx(now_ms);
}

bool AuthorityEndpoint::quiescent() const noexcept {
  return !rx_.active && !carrier_ready_ && !object_ready_ && !tx_.active &&
         !tx_result_ready_ && !in_call_;
}

// --- Gateway ------------------------------------------------------------------

AuthorityGateway::~AuthorityGateway() { drop_all(); }

bool AuthorityGateway::claim_control(const std::uint8_t subtype) noexcept {
  return subtype == kAuthorityControlSubtype;
}

bool AuthorityGateway::claim_kind(const autonomy::ControlObjectKind kind) noexcept {
  return kind == autonomy::ControlObjectKind::AuthorityEnvelope;
}

bool AuthorityGateway::claim_transfer(const NodeId origin,
                                      const autonomy::ObjectHash& hash) noexcept {
  for (const auto& slot : slots_) {
    if (!slot.active) continue;
    // Only transfers with a pinned mesh hash: an Up slot still
    // reassembling, or a Down slot whose manifest went out. Completed
    // small-carrier slots never own a hash.
    if (slot.direction == Direction::Up && slot.received >= slot.total_len) continue;
    if (slot.direction == Direction::Down && !slot.mesh_manifest_sent) continue;
    if (origin == (slot.direction == Direction::Up ? slot.origin : slot.device) &&
        hash_equal(hash, slot.hash)) return true;
  }
  return false;
}

AuthorityGateway::Slot* AuthorityGateway::find_slot(
    const NodeId device, const Direction direction, const std::uint32_t transfer_id,
    const AuthorityCarrierKind kind) noexcept {
  for (auto& slot : slots_) {
    if (slot.active && slot.device == device && slot.direction == direction &&
        slot.transfer_id == transfer_id && slot.kind == kind) {
      return &slot;
    }
  }
  return nullptr;
}

AuthorityGateway::Slot* AuthorityGateway::claim_slot() noexcept {
  for (auto& slot : slots_) {
    if (!slot.active) return &slot;
  }
  return nullptr;
}

void AuthorityGateway::drop_slot(Slot& slot) noexcept {
  secure_clear(slot.buffer.data(), slot.buffer.size());
  slot = Slot{};
}

void AuthorityGateway::drop_all() noexcept {
  for (auto& slot : slots_) drop_slot(slot);
}

void AuthorityGateway::send_ack(const NodeId dest, const autonomy::ObjectHash& hash,
                                const std::uint16_t received,
                                const autonomy::ObjectAckStatus status,
                                const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (dest == kInvalidNodeId || dest == self_) return;
  autonomy::ObjectAckPayload ack{};
  ack.object_hash = hash;
  ack.received_len = received;
  ack.status = status;
  autonomy::EncodedPayload encoded{};
  if (!autonomy::object_ack_encode(ack, encoded)) return;
  in_call_ = true;
  (void)mesh_.config_send(dest, FrameType::ObjectAck, encoded.view(), now_ms);
  in_call_ = false;
}

void AuthorityGateway::on_control(const NodeId origin, const ByteView payload,
                                  const MonotonicMs now_ms) noexcept {
  if (in_call_) return;
  AuthorityCarrierKind kind{AuthorityCarrierKind::Envelope};
  std::uint32_t exchange = 0;
  ByteView body{};
  if (origin == kInvalidNodeId || origin == self_ ||
      !authority_carrier_decode(payload, kind, exchange, body)) {
    sat_inc(counters_.denied);
    return;
  }
  (void)exchange;
  Slot* slot = claim_slot();
  if (slot == nullptr) {
    sat_inc(counters_.denied);  // both slots live: the endpoints retry
    return;
  }
  std::uint32_t transfer = next_transfer_;
  if (++next_transfer_ == 0) next_transfer_ = 1;
  slot->active = true;
  slot->direction = Direction::Up;
  slot->device = origin;
  slot->transfer_id = transfer;
  slot->kind = kind;
  slot->total_len = static_cast<std::uint16_t>(body.size);
  slot->received = static_cast<std::uint16_t>(body.size);
  slot->origin = origin;
  slot->started_ms = now_ms;
  slot->last_send_ms = now_ms;
  std::memcpy(slot->buffer.data(), body.data, body.size);
}

void AuthorityGateway::on_manifest(
    const NodeId origin, const autonomy::ControlObjectPayload& manifest,
    const MonotonicMs now_ms) noexcept {
  if (in_call_) return;
  for (auto& live : slots_) {
    if (live.active && live.direction == Direction::Up && live.origin == origin &&
        live.received < live.total_len && hash_equal(manifest.object_hash, live.hash) &&
        manifest.total_len == live.total_len) {
      // Sender retry of the live manifest: re-ack progress, no extension.
      send_ack(origin, manifest.object_hash, live.received,
               autonomy::ObjectAckStatus::Incomplete, now_ms);
      return;
    }
  }
  Slot* slot = claim_slot();
  if (origin == kInvalidNodeId || origin == self_ || slot == nullptr ||
      manifest.total_len < keys::kAuthorityEnvelopeMin ||
      manifest.total_len > kAuthorityObjectMax) {
    send_ack(origin, manifest.object_hash, 0, autonomy::ObjectAckStatus::Failed, now_ms);
    sat_inc(counters_.denied);
    return;
  }
  std::uint32_t transfer = next_transfer_;
  if (++next_transfer_ == 0) next_transfer_ = 1;
  slot->active = true;
  slot->direction = Direction::Up;
  slot->device = origin;
  slot->transfer_id = transfer;
  slot->kind = AuthorityCarrierKind::Envelope;  // kind-7 objects are envelopes
  slot->total_len = manifest.total_len;
  slot->received = 0;
  slot->origin = origin;
  slot->hash = manifest.object_hash;
  slot->started_ms = now_ms;
  slot->last_send_ms = now_ms;
  send_ack(origin, manifest.object_hash, 0, autonomy::ObjectAckStatus::Incomplete, now_ms);
}

void AuthorityGateway::on_chunk(const NodeId origin,
                                const autonomy::ObjectChunkPayload& chunk,
                                const MonotonicMs now_ms) noexcept {
  if (in_call_) return;
  Slot* slot = nullptr;
  for (auto& candidate : slots_) {
    if (candidate.active && candidate.direction == Direction::Up &&
        candidate.received < candidate.total_len && candidate.origin == origin &&
        hash_equal(chunk.object_hash, candidate.hash)) {
      slot = &candidate;
      break;
    }
  }
  if (slot == nullptr) {
    sat_inc(counters_.denied);
    return;
  }
  if (now_ms - slot->started_ms > kAuthorityReassemblyTimeoutMs) {
    send_ack(origin, chunk.object_hash, slot->received,
             autonomy::ObjectAckStatus::Failed, now_ms);
    drop_slot(*slot);
    sat_inc(counters_.denied);
    return;
  }
  if (!chunk_on_grid(slot->total_len, chunk.offset, chunk.data_size, slot->received)) {
    send_ack(origin, chunk.object_hash, slot->received,
             autonomy::ObjectAckStatus::Failed, now_ms);
    drop_slot(*slot);
    sat_inc(counters_.denied);
    return;
  }
  for (std::uint16_t i = 0; i < chunk.data_size; ++i) {
    const std::uint16_t at = static_cast<std::uint16_t>(chunk.offset + i);
    const std::uint8_t mask = static_cast<std::uint8_t>(1U << (at & 7U));
    if ((slot->bitmap[at >> 3U] & mask) != 0) {
      if (slot->buffer[at] != chunk.data[i]) {
        send_ack(origin, chunk.object_hash, slot->received,
                 autonomy::ObjectAckStatus::Failed, now_ms);
        drop_slot(*slot);
        sat_inc(counters_.denied);
        return;
      }
      continue;
    }
    slot->bitmap[at >> 3U] = static_cast<std::uint8_t>(slot->bitmap[at >> 3U] | mask);
    slot->buffer[at] = chunk.data[i];
    ++slot->received;
  }
  if (slot->received >= slot->total_len) {
    Digest256 digest{};
    sha256(ByteView{slot->buffer.data(), slot->total_len}, digest);
    bool match = true;
    for (std::size_t i = 0; i < slot->hash.size(); ++i) {
      if (digest[i] != slot->hash[i]) match = false;
    }
    secure_clear(digest);
    if (!match) {
      send_ack(origin, chunk.object_hash, slot->total_len,
               autonomy::ObjectAckStatus::Failed, now_ms);
      drop_slot(*slot);
      sat_inc(counters_.denied);
      return;
    }
    send_ack(origin, slot->hash, slot->total_len, autonomy::ObjectAckStatus::Ok, now_ms);
    return;
  }
  send_ack(origin, chunk.object_hash, slot->received,
           autonomy::ObjectAckStatus::Incomplete, now_ms);
}

void AuthorityGateway::on_ack(const NodeId origin, const autonomy::ObjectAckPayload& ack,
                              const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (in_call_) return;
  for (auto& slot : slots_) {
    if (!slot.active || slot.direction != Direction::Down || !slot.mesh_manifest_sent ||
        slot.device != origin || !hash_equal(ack.object_hash, slot.hash)) {
      continue;
    }
    const bool progress = acked_sent_chunk(slot.total_len, slot.emitted,
                                           ack.received_len, slot.sends);
    if ((ack.status == autonomy::ObjectAckStatus::Ok && progress &&
         ack.received_len == slot.total_len) ||
        ack.status == autonomy::ObjectAckStatus::Failed) {
      // The mesh leg is done either way; the endpoints resync over the
      // channel (the 0x67 was only a transport receipt).
      drop_slot(slot);
      return;
    }
    if (ack.status == autonomy::ObjectAckStatus::Incomplete && progress &&
        ack.received_len < slot.total_len) {
      slot.emitted = ack.received_len;
      slot.sends = 0;
    }
    return;
  }
}

Status AuthorityGateway::authority_down(const NodeId device,
                                        const usb::AuthorityFragment& fragment,
                                        bool& complete,
                                        const MonotonicMs now_ms) noexcept {
  complete = false;
  if (in_call_) return Status::error(StatusCode::Busy, "authority gateway re-entry");
  if (device == kInvalidNodeId || fragment.device != device ||
      fragment.transfer_id == 0 || fragment.data.size > kUsbFragmentDataMax ||
      (fragment.data.size != 0 && fragment.data.data == nullptr)) {
    return Status::error(StatusCode::InvalidArgument, "authority down binding");
  }
  Slot* slot = find_slot(device, Direction::Down, fragment.transfer_id, fragment.kind);
  if (slot == nullptr) {
    slot = claim_slot();
    if (slot == nullptr) {
      sat_inc(counters_.denied);
      return Status::error(StatusCode::Busy, "authority gateway full");
    }
    if (fragment.total < keys::kAuthorityEnvelopeMin &&
        fragment.kind == AuthorityCarrierKind::Envelope) {
      return Status::error(StatusCode::InvalidArgument, "authority down length");
    }
    if (!authority_carrier_length_valid(fragment.kind, fragment.total) &&
        fragment.kind != AuthorityCarrierKind::Envelope) {
      return Status::error(StatusCode::InvalidArgument, "authority down length");
    }
    slot->active = true;
    slot->direction = Direction::Down;
    slot->device = device;
    slot->transfer_id = fragment.transfer_id;
    slot->kind = fragment.kind;
    slot->total_len = fragment.total;
    slot->started_ms = now_ms;
    slot->last_send_ms = now_ms;
  } else if (slot->total_len != fragment.total) {
    return Status::error(StatusCode::Conflict, "authority down retargeted");
  }
  if (static_cast<std::uint32_t>(fragment.offset) + fragment.data.size > slot->total_len) {
    drop_slot(*slot);
    return Status::error(StatusCode::InvalidArgument, "authority down overrun");
  }
  for (std::size_t i = 0; i < fragment.data.size; ++i) {
    const std::uint16_t at = static_cast<std::uint16_t>(fragment.offset + i);
    const std::uint8_t mask = static_cast<std::uint8_t>(1U << (at & 7U));
    if ((slot->bitmap[at >> 3U] & mask) != 0) {
      if (slot->buffer[at] != fragment.data.data[i]) {
        drop_slot(*slot);
        return Status::error(StatusCode::Conflict, "authority down rewritten");
      }
      continue;
    }
    slot->bitmap[at >> 3U] = static_cast<std::uint8_t>(slot->bitmap[at >> 3U] | mask);
    slot->buffer[at] = fragment.data.data[i];
    ++slot->received;
  }
  if (slot->received < slot->total_len) return Status::success();
  // Reassembled: envelopes larger than a carrier frame hash for the
  // kind-7 pump now, so the mesh leg never forwards unchecked bytes.
  if (slot->total_len > kAuthorityCarrierBodyMax) {
    Digest256 digest{};
    sha256(ByteView{slot->buffer.data(), slot->total_len}, digest);
    for (std::size_t i = 0; i < slot->hash.size(); ++i) slot->hash[i] = digest[i];
    secure_clear(digest);
  }
  complete = true;
  sat_inc(counters_.down_objects);
  return Status::success();
}

bool AuthorityGateway::pump_down_mesh(Slot& slot, const MonotonicMs now_ms) noexcept {
  if (slot.received < slot.total_len) return true;
  if (now_ms - slot.started_ms > kAuthorityTransferTimeoutMs) {
    drop_slot(slot);
    sat_inc(counters_.timeouts);
    return true;
  }
  if (slot.device == self_) {
    // Our own channel bypasses the mesh: deliver the reassembled object
    // to the local client instead of looping it onto the radio.
    in_call_ = true;
    local_.on_local_down(slot.kind, ByteView{slot.buffer.data(), slot.total_len});
    in_call_ = false;
    drop_slot(slot);
    return true;
  }
  if (slot.total_len <= kAuthorityCarrierBodyMax) {
    std::uint32_t exchange = 0;
    if (slot.kind == AuthorityCarrierKind::R1 || slot.kind == AuthorityCarrierKind::R2 ||
        slot.kind == AuthorityCarrierKind::R3) {
      exchange = slot.transfer_id;  // nonzero USB token pairs the wire retry
    }
    std::array<std::uint8_t, kMaxApplicationPayload> frame{};
    std::size_t written = 0;
    if (!authority_carrier_encode(slot.kind, exchange,
                                  ByteView{slot.buffer.data(), slot.total_len},
                                  MutableByteView{frame.data(), frame.size()},
                                  written)) {
      drop_slot(slot);
      sat_inc(counters_.denied);
      return true;
    }
    in_call_ = true;
    const Status sent =
        mesh_.config_send(slot.device, FrameType::Control, ByteView{frame.data(), written}, now_ms);
    in_call_ = false;
    if (!sent) return true;  // mesh shed it: retry on the next poll
    drop_slot(slot);
    return true;
  }
  if (slot.kind != AuthorityCarrierKind::Envelope) {
    drop_slot(slot);  // only envelopes exceed the carrier frame
    sat_inc(counters_.denied);
    return true;
  }
  if (slot.emitted >= slot.total_len) return true;  // waiting for the Ok
  if (slot.sends >= kAuthorityChunkSendsMax) {
    drop_slot(slot);
    sat_inc(counters_.timeouts);
    return true;
  }
  if (slot.sends != 0 && now_ms - slot.last_send_ms < kAuthorityChunkResendMs) return true;
  if (slot.emitted == 0) {
    // The receiver cannot assemble chunks without the manifest: precede
    // the first chunk with it until progress arrives.
    autonomy::ControlObjectPayload manifest{};
    manifest.kind = autonomy::ControlObjectKind::AuthorityEnvelope;
    manifest.total_len = slot.total_len;
    manifest.object_hash = slot.hash;
    autonomy::EncodedPayload encoded{};
    if (!autonomy::control_object_encode(manifest, encoded)) {
      drop_slot(slot);
      sat_inc(counters_.denied);
      return true;
    }
    in_call_ = true;
    const Status sent = mesh_.config_send(slot.device, FrameType::ControlObject,
                                          encoded.view(), now_ms);
    in_call_ = false;
    if (!sent) return true;
    slot.mesh_manifest_sent = true;
  }
  autonomy::ObjectChunkPayload chunk{};
  chunk.object_hash = slot.hash;
  chunk.offset = slot.emitted;
  const std::uint32_t rest = static_cast<std::uint32_t>(slot.total_len) - slot.emitted;
  chunk.data_size = static_cast<std::uint16_t>(rest > kChunkDataMax ? kChunkDataMax : rest);
  std::memcpy(chunk.data.data(), slot.buffer.data() + slot.emitted, chunk.data_size);
  autonomy::EncodedPayload encoded{};
  if (!autonomy::object_chunk_encode(chunk, encoded)) {
    drop_slot(slot);
    sat_inc(counters_.denied);
    return true;
  }
  in_call_ = true;
  const Status sent = mesh_.config_send(slot.device, FrameType::ObjectChunk,
                                        encoded.view(), now_ms);
  in_call_ = false;
  if (!sent) return true;
  slot.last_send_ms = now_ms;
  ++slot.sends;
  return true;
}

bool AuthorityGateway::pump_up_usb(Slot& slot) noexcept {
  if (slot.received < slot.total_len) return true;
  const std::uint32_t rest = static_cast<std::uint32_t>(slot.total_len) - slot.emitted;
  if (rest == 0) {
    drop_slot(slot);
    return true;
  }
  usb::AuthorityFragment fragment{};
  fragment.device = slot.device;
  fragment.transfer_id = slot.transfer_id;
  fragment.kind = slot.kind;
  fragment.hops = 1;  // relayed over the mesh (the exact count is unknowable)
  fragment.total = slot.total_len;
  fragment.offset = slot.emitted;
  const std::uint16_t length =
      static_cast<std::uint16_t>(rest > kUsbFragmentDataMax ? kUsbFragmentDataMax : rest);
  fragment.data = ByteView{slot.buffer.data() + slot.emitted, length};
  in_call_ = true;
  const bool accepted = host_.send_up(fragment);
  in_call_ = false;
  if (!accepted) return false;  // USB queue full: the cursor retries on poll
  slot.emitted = static_cast<std::uint16_t>(slot.emitted + length);
  sat_inc(counters_.up_fragments);
  if (slot.emitted >= slot.total_len) drop_slot(slot);
  return true;
}

void AuthorityGateway::expire_slots(const MonotonicMs now_ms) noexcept {
  for (auto& slot : slots_) {
    if (!slot.active) continue;
    const MonotonicMs budget = slot.direction == Direction::Up &&
                                       slot.received < slot.total_len
                                   ? kAuthorityReassemblyTimeoutMs
                                   : kAuthorityTransferTimeoutMs;
    if (now_ms - slot.started_ms <= budget) continue;
    if (slot.direction == Direction::Up && slot.received < slot.total_len &&
        slot.total_len > kAuthorityCarrierBodyMax) {
      send_ack(slot.origin, slot.hash, slot.received, autonomy::ObjectAckStatus::Failed,
               now_ms);
    }
    drop_slot(slot);
    sat_inc(counters_.timeouts);
  }
}

void AuthorityGateway::poll(const MonotonicMs now_ms) noexcept {
  if (in_call_) return;
  expire_slots(now_ms);
  for (auto& slot : slots_) {
    if (!slot.active) continue;
    if (slot.direction == Direction::Up) {
      // At most 3 fragments per object: drain the cursor every poll so a
      // completed assembly never wedges a slot behind USB backpressure.
      for (int i = 0; i < 3 && slot.active; ++i) {
        if (!pump_up_usb(slot)) break;
      }
    } else {
      (void)pump_down_mesh(slot, now_ms);
    }
  }
}

bool AuthorityGateway::quiescent() const noexcept {
  if (in_call_) return false;
  for (const auto& slot : slots_) {
    if (slot.active) return false;
  }
  return true;
}

void AuthorityMeshSink::on_config_frame(const NodeId peer, const wire::PlainFrame& frame,
                                        const MonotonicMs now_ms) noexcept {
  (void)peer;  // replies route to the end-authenticated origin, like ConfigTarget
  const ByteView payload{frame.payload.data(), frame.payload_size};
  switch (frame.header.type) {
    case FrameType::Control:
      if (frame.payload_size >= 2 && demux_.claim_control(frame.payload[1])) {
        demux_.on_control(frame.header.origin, payload, now_ms);
      }
      break;
    case FrameType::ControlObject: {
      autonomy::ControlObjectPayload manifest{};
      if (autonomy::control_object_decode(payload, manifest) &&
          demux_.claim_kind(manifest.kind)) {
        demux_.on_manifest(frame.header.origin, manifest, now_ms);
      }
      break;
    }
    case FrameType::ObjectChunk: {
      autonomy::ObjectChunkPayload chunk{};
      if (autonomy::object_chunk_decode(payload, chunk) &&
          demux_.claim_transfer(frame.header.origin, chunk.object_hash)) {
        demux_.on_chunk(frame.header.origin, chunk, now_ms);
      }
      break;
    }
    case FrameType::ObjectAck: {
      autonomy::ObjectAckPayload ack{};
      if (autonomy::object_ack_decode(payload, ack) &&
          demux_.claim_transfer(frame.header.origin, ack.object_hash)) {
        demux_.on_ack(frame.header.origin, ack, now_ms);
      }
      break;
    }
    default:
      break;
  }
}

}  // namespace routeloom::sdkv1
