// Authority channel, device side (routeloom/sdkv1_authority.hpp, G-SEC P5 PR1).

#include "routeloom/sdkv1_authority.hpp"
#include "routeloom/sdkv1_group_keys.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {

// Refusal details double as the golden-vector `reason` tokens, so both
// languages report the same word for the same malformed input.
constexpr char kTruncated[] = "truncated";
constexpr char kSurplus[] = "surplus";
constexpr char kBadVersion[] = "bad_version";
constexpr char kBadOp[] = "bad_op";
constexpr char kReservedNonZero[] = "reserved_nonzero";
constexpr char kZeroGeneration[] = "zero_generation";
constexpr char kZeroRequestId[] = "zero_request_id";
constexpr char kBadCause[] = "bad_cause";
constexpr char kBadOverlap[] = "bad_overlap";
constexpr char kBadResult[] = "bad_result";
constexpr char kBadStoredState[] = "bad_stored_state";
constexpr char kBadReason[] = "bad_reason";

constexpr std::uint16_t kOverlapRemovalS = 10;
constexpr std::uint16_t kOverlapNormalS = 60;

constexpr MonotonicMs kHandshakeTimeoutMs = 5000;
constexpr MonotonicMs kPullBucketMs = 60000;
constexpr MonotonicMs kJoinConfirmTimeoutMs = 15000;
constexpr MonotonicMs kIdleRetireMs = 600000;  // 10 minutes without traffic
constexpr std::uint32_t kBackoffMaxS = 60;
constexpr std::uint64_t kProactiveRekeyCounter = std::uint64_t{1} << 32;

Status refusal(const char* reason) noexcept {
  return Status::error(StatusCode::InvalidArgument, reason);
}

bool cause_valid(std::uint8_t raw) noexcept {
  return raw >= 1 && raw <= 3;
}

bool overlap_valid(UpdateCause cause, std::uint16_t overlap) noexcept {
  // Only 60 s (periodic/manual) and 10 s (removal) exist; the pairing is
  // part of the wire rule so a removal cannot smuggle a long overlap.
  if (cause == UpdateCause::Removal) return overlap == kOverlapRemovalS;
  return overlap == kOverlapNormalS;
}

bool result_valid(std::uint8_t raw) noexcept { return raw <= 4; }
bool stored_state_valid(std::uint8_t raw) noexcept { return raw <= 2; }
bool reason_valid(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 3; }

Status decode_head_checked(ByteReader& reader, std::uint8_t want_op,
                           AuthorityBodyHead& head) noexcept {
  std::uint8_t version = 0;
  std::uint16_t flags = 0;
  if (!reader.read_u8(version) || !reader.read_u8(head.op) || !reader.read_u16(flags) ||
      !reader.read_u32(head.generation) || !reader.read_u64(head.request_id)) {
    return refusal(kTruncated);
  }
  if (version != kAuthorityBodyVersion) return refusal(kBadVersion);
  if (head.op != want_op) return refusal(kBadOp);
  if (flags != 0) return refusal(kReservedNonZero);
  if (head.generation == 0) return refusal(kZeroGeneration);
  if (head.request_id == 0) return refusal(kZeroRequestId);
  return Status::success();
}

Status encode_head_checked(ByteWriter& writer, const AuthorityBodyHead& head,
                           std::uint8_t want_op) noexcept {
  if (head.op != want_op) return refusal(kBadOp);
  if (head.generation == 0) return refusal(kZeroGeneration);
  if (head.request_id == 0) return refusal(kZeroRequestId);
  if (!writer.write_u8(kAuthorityBodyVersion) || !writer.write_u8(head.op) ||
      !writer.write_u16(0) || !writer.write_u32(head.generation) ||
      !writer.write_u64(head.request_id)) {
    return refusal(kTruncated);
  }
  return Status::success();
}

MonotonicMs sat_add(MonotonicMs a, MonotonicMs b) noexcept {
  return (a > UINT64_MAX - b) ? UINT64_MAX : (a + b);
}

}  // namespace

Status authority_head_encode(const AuthorityBodyHead& head, const MutableByteView out,
                             std::size_t& written) noexcept {
  written = 0;
  if (head.op != 1 && head.op != 2) return refusal(kBadOp);
  if (out.data == nullptr || out.size < kAuthorityBodyHeadSize) return refusal(kTruncated);
  ByteWriter writer(out);
  const Status status = encode_head_checked(writer, head, head.op);
  if (!status) return status;
  written = writer.size();
  return Status::success();
}

Status authority_head_decode(const ByteView input, AuthorityBodyHead& out) noexcept {
  out = AuthorityBodyHead{};
  if (input.data == nullptr || input.size < kAuthorityBodyHeadSize) return refusal(kTruncated);
  if (input.size > kAuthorityBodyHeadSize) return refusal(kSurplus);
  ByteReader reader(input);
  std::uint8_t version = 0;
  std::uint16_t flags = 0;
  if (!reader.read_u8(version) || !reader.read_u8(out.op) || !reader.read_u16(flags) ||
      !reader.read_u32(out.generation) || !reader.read_u64(out.request_id)) {
    return refusal(kTruncated);
  }
  if (version != kAuthorityBodyVersion) return refusal(kBadVersion);
  if (out.op != 1 && out.op != 2) return refusal(kBadOp);
  if (flags != 0) return refusal(kReservedNonZero);
  if (out.generation == 0) return refusal(kZeroGeneration);
  if (out.request_id == 0) return refusal(kZeroRequestId);
  return Status::success();
}

Status encode_join_confirm_up(const JoinConfirmUp& msg, const MutableByteView out,
                              std::size_t& written) noexcept {
  written = 0;
  if (out.data == nullptr || out.size < kJoinConfirmUpSize) return refusal(kTruncated);
  ByteWriter writer(out);
  Status status = encode_head_checked(writer, msg.head, 1);
  if (!status) return status;
  if (!writer.write_bytes(ByteView{msg.cert_hash.data(), msg.cert_hash.size()}) ||
      !writer.write_u32(msg.boot) || !writer.write_u32(msg.current) ||
      !writer.write_u32(msg.next)) {
    return refusal(kTruncated);
  }
  written = writer.size();
  return Status::success();
}

Status decode_join_confirm_up(const ByteView input, JoinConfirmUp& out) noexcept {
  out = JoinConfirmUp{};
  if (input.data == nullptr || input.size < kJoinConfirmUpSize) return refusal(kTruncated);
  if (input.size > kJoinConfirmUpSize) return refusal(kSurplus);
  ByteReader reader(input);
  Status status = decode_head_checked(reader, 1, out.head);
  if (!status) return status;
  std::array<std::uint8_t, 32> cert{};
  if (!reader.read_bytes(MutableByteView{cert.data(), cert.size()}) ||
      !reader.read_u32(out.boot) || !reader.read_u32(out.current) ||
      !reader.read_u32(out.next)) {
    return refusal(kTruncated);
  }
  out.cert_hash = cert;
  return Status::success();
}

Status encode_join_confirm_down(const JoinConfirmDown& msg, const MutableByteView out,
                                std::size_t& written) noexcept {
  written = 0;
  if (out.data == nullptr || out.size < kJoinConfirmDownSize) return refusal(kTruncated);
  ByteWriter writer(out);
  Status status = encode_head_checked(writer, msg.head, 2);
  if (!status) return status;
  if (!writer.write_u32(msg.confirmed_generation) || !writer.write_u32(msg.authority_active)) {
    return refusal(kTruncated);
  }
  written = writer.size();
  return Status::success();
}

Status decode_join_confirm_down(const ByteView input, JoinConfirmDown& out) noexcept {
  out = JoinConfirmDown{};
  if (input.data == nullptr || input.size < kJoinConfirmDownSize) return refusal(kTruncated);
  if (input.size > kJoinConfirmDownSize) return refusal(kSurplus);
  ByteReader reader(input);
  const Status status = decode_head_checked(reader, 2, out.head);
  if (!status) return status;
  if (!reader.read_u32(out.confirmed_generation) || !reader.read_u32(out.authority_active)) {
    return refusal(kTruncated);
  }
  return Status::success();
}

Status encode_group_key_update(const GroupKeyUpdate& msg, const MutableByteView out,
                               std::size_t& written) noexcept {
  written = 0;
  if (out.data == nullptr || out.size < kGroupKeyUpdateSize) return refusal(kTruncated);
  if (!cause_valid(static_cast<std::uint8_t>(msg.cause))) return refusal(kBadCause);
  if (!overlap_valid(msg.cause, msg.overlap_s)) return refusal(kBadOverlap);
  ByteWriter writer(out);
  Status status = encode_head_checked(writer, msg.head, 1);
  if (!status) return status;
  if (!writer.write_u32(msg.g) || !writer.write_u8(static_cast<std::uint8_t>(msg.cause)) ||
      !writer.write_u8(0) || !writer.write_u16(msg.overlap_s) ||
      !writer.write_bytes(ByteView{msg.gk.data(), msg.gk.size()})) {
    return refusal(kTruncated);
  }
  written = writer.size();
  return Status::success();
}

Status decode_group_key_update(const ByteView input, GroupKeyUpdate& out) noexcept {
  out = GroupKeyUpdate{};
  if (input.data == nullptr || input.size < kGroupKeyUpdateSize) return refusal(kTruncated);
  if (input.size > kGroupKeyUpdateSize) return refusal(kSurplus);
  ByteReader reader(input);
  Status status = decode_head_checked(reader, 1, out.head);
  if (!status) return status;
  std::uint8_t cause = 0;
  std::uint8_t reserved = 0;
  keys::Secret gk{};
  if (!reader.read_u32(out.g) || !reader.read_u8(cause) || !reader.read_u8(reserved) ||
      !reader.read_u16(out.overlap_s) ||
      !reader.read_bytes(MutableByteView{gk.data(), gk.size()})) {
    secure_clear(gk);
    return refusal(kTruncated);
  }
  if (reserved != 0) {
    secure_clear(gk);
    return refusal(kReservedNonZero);
  }
  if (!cause_valid(cause)) {
    secure_clear(gk);
    return refusal(kBadCause);
  }
  out.cause = static_cast<UpdateCause>(cause);
  if (!overlap_valid(out.cause, out.overlap_s)) {
    secure_clear(gk);
    return refusal(kBadOverlap);
  }
  out.gk = gk;  // the caller consumes or wipes the key before returning
  secure_clear(gk);
  return Status::success();
}

Status encode_group_key_ack(const GroupKeyAck& msg, const MutableByteView out,
                            std::size_t& written) noexcept {
  written = 0;
  if (out.data == nullptr || out.size < kGroupKeyAckSize) return refusal(kTruncated);
  if (!result_valid(static_cast<std::uint8_t>(msg.result))) return refusal(kBadResult);
  if (!stored_state_valid(static_cast<std::uint8_t>(msg.stored_state))) {
    return refusal(kBadStoredState);
  }
  if (msg.result == UpdateResult::Durable && msg.stored_state == StoredState::None) {
    return refusal(kBadStoredState);
  }
  ByteWriter writer(out);
  Status status = encode_head_checked(writer, msg.head, 2);
  if (!status) return status;
  if (!writer.write_u32(msg.g) ||
      !writer.write_bytes(ByteView{msg.gk_id.data(), msg.gk_id.size()}) ||
      !writer.write_u8(static_cast<std::uint8_t>(msg.result)) ||
      !writer.write_u8(static_cast<std::uint8_t>(msg.stored_state)) || !writer.write_u16(0)) {
    return refusal(kTruncated);
  }
  written = writer.size();
  return Status::success();
}

Status decode_group_key_ack(const ByteView input, GroupKeyAck& out) noexcept {
  out = GroupKeyAck{};
  if (input.data == nullptr || input.size < kGroupKeyAckSize) return refusal(kTruncated);
  if (input.size > kGroupKeyAckSize) return refusal(kSurplus);
  ByteReader reader(input);
  Status status = decode_head_checked(reader, 2, out.head);
  if (!status) return status;
  std::uint8_t result = 0;
  std::uint8_t stored = 0;
  std::uint16_t reserved = 0;
  std::array<std::uint8_t, 32> gk_id{};
  if (!reader.read_u32(out.g) ||
      !reader.read_bytes(MutableByteView{gk_id.data(), gk_id.size()}) ||
      !reader.read_u8(result) || !reader.read_u8(stored) || !reader.read_u16(reserved)) {
    return refusal(kTruncated);
  }
  if (reserved != 0) return refusal(kReservedNonZero);
  if (!result_valid(result)) return refusal(kBadResult);
  if (!stored_state_valid(stored)) return refusal(kBadStoredState);
  if (result == static_cast<std::uint8_t>(UpdateResult::Durable) &&
      stored == static_cast<std::uint8_t>(StoredState::None)) {
    return refusal(kBadStoredState);
  }
  out.gk_id = gk_id;
  out.result = static_cast<UpdateResult>(result);
  out.stored_state = static_cast<StoredState>(stored);
  return Status::success();
}

Status encode_group_key_activate(const GroupKeyActivate& msg, const MutableByteView out,
                                 std::size_t& written) noexcept {
  written = 0;
  if (out.data == nullptr || out.size < kGroupKeyActivateSize) return refusal(kTruncated);
  if (!cause_valid(static_cast<std::uint8_t>(msg.cause))) return refusal(kBadCause);
  if (!overlap_valid(msg.cause, msg.overlap_s)) return refusal(kBadOverlap);
  ByteWriter writer(out);
  Status status = encode_head_checked(writer, msg.head, 1);
  if (!status) return status;
  if (!writer.write_u32(msg.g) ||
      !writer.write_bytes(ByteView{msg.gk_id.data(), msg.gk_id.size()}) ||
      !writer.write_u8(static_cast<std::uint8_t>(msg.cause)) || !writer.write_u8(0) ||
      !writer.write_u16(msg.overlap_s)) {
    return refusal(kTruncated);
  }
  written = writer.size();
  return Status::success();
}

Status decode_group_key_activate(const ByteView input, GroupKeyActivate& out) noexcept {
  out = GroupKeyActivate{};
  if (input.data == nullptr || input.size < kGroupKeyActivateSize) return refusal(kTruncated);
  if (input.size > kGroupKeyActivateSize) return refusal(kSurplus);
  ByteReader reader(input);
  Status status = decode_head_checked(reader, 1, out.head);
  if (!status) return status;
  std::uint8_t cause = 0;
  std::uint8_t reserved = 0;
  std::array<std::uint8_t, 32> gk_id{};
  if (!reader.read_u32(out.g) ||
      !reader.read_bytes(MutableByteView{gk_id.data(), gk_id.size()}) ||
      !reader.read_u8(cause) || !reader.read_u8(reserved) || !reader.read_u16(out.overlap_s)) {
    return refusal(kTruncated);
  }
  if (reserved != 0) return refusal(kReservedNonZero);
  if (!cause_valid(cause)) return refusal(kBadCause);
  out.cause = static_cast<UpdateCause>(cause);
  if (!overlap_valid(out.cause, out.overlap_s)) return refusal(kBadOverlap);
  out.gk_id = gk_id;
  return Status::success();
}

Status encode_group_key_pull(const GroupKeyPull& msg, const MutableByteView out,
                             std::size_t& written) noexcept {
  written = 0;
  if (out.data == nullptr || out.size < kGroupKeyPullSize) return refusal(kTruncated);
  if (!reason_valid(static_cast<std::uint8_t>(msg.reason))) return refusal(kBadReason);
  ByteWriter writer(out);
  Status status = encode_head_checked(writer, msg.head, 1);
  if (!status) return status;
  if (!writer.write_u32(msg.current) || !writer.write_u32(msg.next) ||
      !writer.write_u8(static_cast<std::uint8_t>(msg.reason)) || !writer.write_u8(0) ||
      !writer.write_u8(0) || !writer.write_u8(0)) {
    return refusal(kTruncated);
  }
  written = writer.size();
  return Status::success();
}

Status decode_group_key_pull(const ByteView input, GroupKeyPull& out) noexcept {
  out = GroupKeyPull{};
  if (input.data == nullptr || input.size < kGroupKeyPullSize) return refusal(kTruncated);
  if (input.size > kGroupKeyPullSize) return refusal(kSurplus);
  ByteReader reader(input);
  Status status = decode_head_checked(reader, 1, out.head);
  if (!status) return status;
  std::uint8_t reason = 0;
  std::uint8_t r0 = 0;
  std::uint8_t r1 = 0;
  std::uint8_t r2 = 0;
  if (!reader.read_u32(out.current) || !reader.read_u32(out.next) || !reader.read_u8(reason) ||
      !reader.read_u8(r0) || !reader.read_u8(r1) || !reader.read_u8(r2)) {
    return refusal(kTruncated);
  }
  if (r0 != 0 || r1 != 0 || r2 != 0) return refusal(kReservedNonZero);
  if (!reason_valid(reason)) return refusal(kBadReason);
  out.reason = static_cast<PullReason>(reason);
  return Status::success();
}

void authority_gk_id(const NetworkId network, const std::uint32_t epoch,
                     const keys::Secret& gk, GkId& out) noexcept {
  // "RouteLoom/v1/gk-id" || 0x00 || network:u64 || epoch:u32 || GK:32.
  std::array<std::uint8_t, sizeof(keys::kLabelGkId) + 8 + 4 + keys::kSecretSize> input{};
  static_assert(sizeof(keys::kLabelGkId) == 19, "label plus NUL");
  std::memcpy(input.data(), keys::kLabelGkId, sizeof(keys::kLabelGkId));
  std::size_t at = sizeof(keys::kLabelGkId);
  for (int i = 7; i >= 0; --i) input[at++] = static_cast<std::uint8_t>(network >> (8 * i));
  for (int i = 3; i >= 0; --i) input[at++] = static_cast<std::uint8_t>(epoch >> (8 * i));
  std::memcpy(input.data() + at, gk.data(), gk.size());
  ScopeDigest digest{};
  sha256(ByteView{input.data(), input.size()}, digest);
  out = digest;
  secure_clear(input);
  secure_clear(digest);
}

Status authority_seal(const routeloom::AeadGcm& aead, const keys::TrafficKey& tx,
                      const keys::AuthorityEnvelopeType type, const std::uint32_t ctx_id,
                      const std::uint64_t counter, const ByteView plaintext,
                      const MutableByteView out, std::size_t& written) noexcept {
  written = 0;
  if (ctx_id == 0) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_CTX_ZERO");
  }
  if (counter > keys::kMaxAeadCounter) {
    return Status::error(StatusCode::CounterExhausted, "AUTHORITY_COUNTER_WRAP");
  }
  if (plaintext.data == nullptr && plaintext.size != 0) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_PLAINTEXT_NULL");
  }
  if (plaintext.size > keys::kAuthorityEnvelopeMax - keys::kAuthorityEnvelopeMin) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_PLAINTEXT_OVERSIZED");
  }
  if (out.data == nullptr ||
      out.size < keys::kAuthorityEnvelopeHeaderSize + plaintext.size + kAeadTagSize) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_OUTPUT_SMALL");
  }
  keys::AuthorityEnvelopeHeader header{};
  header.type = type;
  header.ctx_id = ctx_id;
  header.counter = counter;
  std::array<std::uint8_t, keys::kAuthorityEnvelopeHeaderSize> aad{};
  if (!keys::authority_envelope_header_encode(header, aad)) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_HEADER_INVALID");
  }
  keys::AeadNonce nonce{};
  if (!keys::aead_nonce(tx.iv, counter, nonce)) {
    secure_clear(nonce);
    return Status::error(StatusCode::CounterExhausted, "AUTHORITY_COUNTER_WRAP");
  }
  std::memcpy(out.data, aad.data(), aad.size());
  const bool sealed =
      aead.seal(aead.ctx, tx.key.data(), nonce.data(), ByteView{aad.data(), aad.size()},
                plaintext, out.data + aad.size());
  secure_clear(nonce);
  secure_clear(aad);
  if (!sealed) {
    secure_clear(out.data, aad.size() + plaintext.size + kAeadTagSize);
    return Status::error(StatusCode::InternalError, "AUTHORITY_SEAL_FAILED");
  }
  written = aad.size() + plaintext.size + kAeadTagSize;
  return Status::success();
}

Status authority_open(const routeloom::AeadGcm& aead, const keys::TrafficKey& rx, const ByteView envelope,
                      const std::uint32_t want_ctx, const MutableByteView plaintext,
                      std::size_t& written, keys::AuthorityEnvelopeHeader& header) noexcept {
  written = 0;
  header = keys::AuthorityEnvelopeHeader{};
  const keys::DecodeError decoded = keys::authority_envelope_decode(envelope, header);
  if (decoded != keys::DecodeError::None) {
    return Status::error(StatusCode::InvalidArgument, keys::decode_error_name(decoded));
  }
  if (header.ctx_id != want_ctx || want_ctx == 0) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_CTX_MISMATCH");
  }
  const std::size_t cipher_size = envelope.size - keys::kAuthorityEnvelopeHeaderSize;
  const std::size_t plain_size = cipher_size - kAeadTagSize;
  if (plaintext.data == nullptr || plaintext.size < plain_size) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_OUTPUT_SMALL");
  }
  keys::AeadNonce nonce{};
  if (!keys::aead_nonce(rx.iv, header.counter, nonce)) {
    secure_clear(nonce);
    return Status::error(StatusCode::AuthenticationFailed, "AUTHORITY_COUNTER_INVALID");
  }
  // May alias `envelope` with a forward offset (plaintext at the buffer
  // front, ciphertext 12 bytes ahead): reads always run ahead of writes, so
  // any streaming decrypt handles it. The backend zeroes `plaintext` itself
  // on failure (part of the AeadGcm contract).
  const bool opened =
      aead.open(aead.ctx, rx.key.data(), nonce.data(),
                ByteView{envelope.data, keys::kAuthorityEnvelopeHeaderSize},
                ByteView{envelope.data + keys::kAuthorityEnvelopeHeaderSize, cipher_size},
                plaintext.data);
  secure_clear(nonce);
  if (!opened) {
    std::memset(plaintext.data, 0, plain_size);
    return Status::error(StatusCode::AuthenticationFailed, "AUTHORITY_BAD_TAG");
  }
  written = plain_size;
  return Status::success();
}

void AuthorityReplayWindow::reset() noexcept {
  max_ = 0;
  bitmap_ = 0;
  empty_ = true;
}

bool AuthorityReplayWindow::accept(const std::uint64_t counter) noexcept {
  if (empty_) {
    empty_ = false;
    max_ = counter;
    bitmap_ = 1;
    return true;
  }
  if (counter > max_) {
    const std::uint64_t shift = counter - max_;
    if (shift >= 64) {
      bitmap_ = 1;
    } else {
      bitmap_ = (bitmap_ << shift) | 1;
    }
    max_ = counter;
    return true;
  }
  const std::uint64_t back = max_ - counter;
  if (back >= 64) return false;
  const std::uint64_t bit = std::uint64_t{1} << back;
  if ((bitmap_ & bit) != 0) return false;
  bitmap_ |= bit;
  return true;
}

AuthorityClient::AuthorityClient(const routeloom::AeadGcm& aead, AuthorityPort& port,
                                 AuthorityObserver& observer,
                                 rlres1::Environment& rlres1_env,
                                 GroupKeyState* group) noexcept
    : aead_(aead), port_(port), observer_(observer), env_(rlres1_env), group_(group) {}

Status AuthorityClient::advance(const AuthorityInput& in, const MonotonicMs now) noexcept {
  if (in_call_) {
    // Re-entry from a port/observer/entropy/AEAD callback: refuse with
    // everything untouched. The outer call finishes first.
    return Status::error(StatusCode::Busy, "AUTHORITY_REENTRY");
  }
  in_call_ = true;
  Status status;
  switch (in.kind) {
    case AuthorityInputKind::Start:
      status = on_start(in.start, now);
      break;
    case AuthorityInputKind::RxCarrier:
      status = on_rx(in.rx, now);
      break;
    case AuthorityInputKind::TxResult:
      status = on_tx_result(in.tx);
      break;
    case AuthorityInputKind::Tick:
      status = on_tick(now);
      break;
    case AuthorityInputKind::RequestPull:
      status = on_pull(in.pull, now);
      break;
    case AuthorityInputKind::Suspend:
      status = on_suspend();
      break;
    case AuthorityInputKind::SendTyped:
      status = on_typed(in.typed, now);
      break;
    default:
      status = Status::error(StatusCode::InvalidArgument, "AUTHORITY_INPUT_UNKNOWN");
      break;
  }
  in_call_ = false;
  return status;
}

AuthoritySnapshot AuthorityClient::snapshot() const noexcept {
  AuthoritySnapshot snap{};
  snap.state = state_;
  snap.started = started_;
  snap.rx_ctx = rx_ctx_;
  snap.tx_ctx = tx_ctx_;
  snap.tx_counter = tx_counter_;
  snap.rx_max = rx_window_.empty() ? 0 : rx_window_.max_seen();
  snap.next_request_id = next_request_id_;
  snap.tx_sent = tx_sent_;
  snap.tx_failed = tx_failed_;
  snap.rx_accepted = rx_accepted_;
  snap.rx_rejected = rx_rejected_;
  snap.backoff_s = backoff_s_;
  snap.pull_pending = pull_pending_;
  snap.join_confirmed = join_confirmed_;
  snap.busy = tx_size_ != 0 || ack_pending_ ||
              state_ == AuthoritySnapshot::State::Connecting ||
              state_ == AuthoritySnapshot::State::Backoff;
  return snap;
}

bool AuthorityClient::quiescent() const noexcept {
  if (in_call_) return false;
  if (state_ != AuthoritySnapshot::State::Dormant) return false;
  if (tx_size_ != 0 || pull_pending_ || ack_pending_) return false;
  return true;
}

MonotonicMs AuthorityClient::next_deadline() const noexcept {
  if (state_ == AuthoritySnapshot::State::Dormant) return UINT64_MAX;
  if (tx_size_ != 0) return 0;  // staged bytes wait for the port; retry now
  if (state_ == AuthoritySnapshot::State::Backoff) return backoff_until_;
  if (state_ == AuthoritySnapshot::State::Connecting) return hs_deadline_;
  if (ack_pending_ || !join_confirm_sent_) return 0;
  MonotonicMs deadline = UINT64_MAX;
  if (!join_confirmed_) deadline = sat_add(ready_since_, kJoinConfirmTimeoutMs);
  if (pull_pending_) {
    const MonotonicMs due =
        !pull_sent_ ? ready_since_ : sat_add(last_pull_ms_, kPullBucketMs);
    if (due < deadline) deadline = due;
  }
  const MonotonicMs idle_at = sat_add(last_activity_, kIdleRetireMs);
  if (idle_at < deadline) deadline = idle_at;
  return deadline;
}

Status AuthorityClient::on_start(const AuthorityStart& start, const MonotonicMs now) noexcept {
  if (started_ && state_ != AuthoritySnapshot::State::Dormant) {
    return Status::error(StatusCode::InvalidState, "AUTHORITY_ALREADY_STARTED");
  }
  if (start.network == 0 || start.self == kInvalidNodeId || start.self == kBroadcastNodeId ||
      start.gateway == kInvalidNodeId || start.gateway == kBroadcastNodeId ||
      start.site_id == 0 || start.generation == 0) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_START_INVALID");
  }
  if (start.epochs.site_epoch != static_cast<std::uint32_t>(start.network >> 32)) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_START_EPOCH");
  }
  bool dams_zero = true;
  for (const auto b : start.dams) dams_zero = dams_zero && (b == 0);
  if (dams_zero) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_START_NO_DAMS");
  }
  if (group_ != nullptr) {
    if (!group_->ready()) return Status::error(StatusCode::RecoveryRequired, "AUTHORITY_GROUP_BLOCKED");
    const SiteRecord& site = group_->store_.site();
    ScopeDigest cert_hash{};
    sha256(ByteView{site.member_cert.bytes.data(), site.member_cert.size}, cert_hash);
    bool gateway_bound = false;
    for (std::uint8_t i = 0; i < site.gateway_count; ++i) {
      gateway_bound = gateway_bound || site.gateways[i] == start.gateway;
    }
    const bool bound = site.state == SiteState::Member && site.network == start.network &&
        site.site_id == start.site_id && site.assignment_generation == start.generation &&
        site.dams == start.dams && gateway_bound && group_->boot() == start.boot &&
        start.boot >= site.boot_witness &&
        start.gk_current == site.gk_epoch_current && start.gk_next == site.gk_epoch_next &&
        cert_hash == start.member_cert_hash;
    secure_clear(cert_hash);
    if (!bound) return Status::error(StatusCode::Conflict, "AUTHORITY_SITE_BINDING");
  }
  if (started_) {
    engine_.clear_all();
    engine_ready_ = false;
    secure_clear(local_.dams);
  }
  local_ = start;
  started_ = true;
  return begin_handshake(now);
}

Status AuthorityClient::on_rx(const AuthorityRxCarrier& rx, const MonotonicMs now) noexcept {
  if (!started_) {
    return Status::error(StatusCode::InvalidState, "AUTHORITY_NOT_STARTED");
  }
  if (rx.bytes.data == nullptr && rx.bytes.size != 0) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_RX_NULL");
  }
  // Every carrier, including R2 and Wake, is bound to the current durable
  // assignment before it can progress or reopen a channel.
  if (!site_bound()) {
    to_dormant();
    AuthorityEvent event{};
    event.kind = AuthorityEvent::Kind::ChannelLost;
    event.reason = "SITE_CHANGED";
    observer_.on_event(event);
    return Status::error(StatusCode::Conflict, "AUTHORITY_SITE_CHANGED");
  }
  if (state_ == AuthoritySnapshot::State::Dormant) {
    // Armed by an earlier Start, channel retired: only a Wake may re-open it.
    if (rx.kind == AuthorityCarrierKind::Wake) {
      if (rx.bytes.size != 8) {
        ++rx_rejected_;
        return Status::success();
      }
      if (wake_seen_ && now < sat_add(last_wake_ms_, kPullBucketMs)) {
        return Status::success();  // coalesced; the last handshake is still fresh
      }
      wake_seen_ = true;
      last_wake_ms_ = now;
      return begin_handshake(now);
    }
    ++rx_rejected_;
    return Status::success();
  }
  if (state_ == AuthoritySnapshot::State::Backoff) {
    ++rx_rejected_;  // nothing is expected mid-backoff, not even a Wake
    return Status::success();
  }
  if (state_ == AuthoritySnapshot::State::Connecting) {
    if (rx.kind == AuthorityCarrierKind::R2) {
      rlres1::Output out{};
      engine_.on_r2(local_.site_id, keys::Purpose::Authority, rx.bytes, now, out);
      // The engine ended its initiator session either way (one R2 per R1).
      if (out.action != rlres1::Action::SendAndInstall || out.message_size == 0 ||
          out.message_size > tx_buffer_.size()) {
        out.clear();
        enter_backoff(now, "BAD_R2");
        return Status::success();
      }
      if (out.established.rx_context_id == 0 || out.established.tx_context_id == 0) {
        out.clear();
        enter_backoff(now, "BAD_R2");
        return Status::success();
      }
      // Copy the keys and the R3 bytes first, then wipe the engine output:
      // the context becomes usable only after R3 leaves for the port.
      tx_key_ = out.established.tx;
      rx_key_ = out.established.rx;
      rx_ctx_ = out.established.rx_context_id;
      tx_ctx_ = out.established.tx_context_id;
      tx_size_ = out.message_size;
      tx_kind_ = TxKind::R3;
      std::memcpy(tx_buffer_.data(), out.message.data(), tx_size_);
      out.clear();
      last_activity_ = now;
      if (flush_tx()) {
        state_ = AuthoritySnapshot::State::Ready;
        ready_since_ = now;
        join_confirmed_ = false;
        join_confirm_sent_ = false;
        backoff_s_ = 0;
        AuthorityEvent event{};
        event.kind = AuthorityEvent::Kind::ChannelReady;
        observer_.on_event(event);
        // The first business message also proves R3 arrived; a missing ACK
        // retires the channel (Tick) instead of reusing a half-open context.
        (void)send_join_confirm(now);
      }
      return Status::success();
    }
    ++rx_rejected_;
    return Status::success();
  }
  // Ready.
  if (rx.kind != AuthorityCarrierKind::Envelope) {
    ++rx_rejected_;  // stray handshake bytes and Wakes change nothing
    return Status::success();
  }
  on_envelope_ready(rx, now);
  return Status::success();
}

Status AuthorityClient::on_tx_result(const AuthorityTxResult& tx) noexcept {
  if (!tx_token_live_ || tx.token != tx_token_) return Status::success();  // stale
  tx_token_live_ = false;
  if (!tx.delivered) ++tx_failed_;
  return Status::success();
}

Status AuthorityClient::on_tick(const MonotonicMs now) noexcept {
  if (!started_) {
    return Status::error(StatusCode::InvalidState, "AUTHORITY_NOT_STARTED");
  }
  if (!site_bound()) {
    to_dormant();
    return Status::error(StatusCode::Conflict, "AUTHORITY_SITE_CHANGED");
  }
  switch (state_) {
    case AuthoritySnapshot::State::Dormant:
      break;
    case AuthoritySnapshot::State::Connecting: {
      rlres1::ExpiredSession expired{};
      if (engine_.next_expired(now, expired) || now >= hs_deadline_) {
        // Either the engine session or a port-stalled R3 (whose session the
        // engine already ended) ran out of time: back off and re-handshake.
        enter_backoff(now, "HANDSHAKE_TIMEOUT");
        break;
      }
      // R1 or R3 may still sit staged when the port was full.
      if (flush_tx() && tx_kind_ == TxKind::None && tx_size_ == 0 && rx_ctx_ != 0) {
        // R3 just left: the context stalled in Connecting becomes Ready.
        state_ = AuthoritySnapshot::State::Ready;
        ready_since_ = now;
        join_confirmed_ = false;
        join_confirm_sent_ = false;
        backoff_s_ = 0;
        AuthorityEvent event{};
        event.kind = AuthorityEvent::Kind::ChannelReady;
        observer_.on_event(event);
        (void)send_join_confirm(now);
      }
      break;
    }
    case AuthoritySnapshot::State::Backoff:
      if (now >= backoff_until_) {
        if (!begin_handshake(now)) {
          enter_backoff(now, "BACKOFF");  // entropy/cid failure: step it up
        }
      }
      break;
    case AuthoritySnapshot::State::Ready: {
      if (tx_size_ == 0) {
        if (ack_pending_) (void)stage_pending_ack(now);
        if (!join_confirm_sent_) (void)send_join_confirm(now);
        if (pull_pending_ && tx_size_ == 0 && !ack_pending_) {
          const bool due =
              !pull_sent_ || (now >= sat_add(last_pull_ms_, kPullBucketMs));
          if (due && send_pull(pending_reason_, now)) pull_pending_ = false;
        }
      } else {
        (void)flush_tx();
      }
      if (!join_confirmed_ && now >= sat_add(ready_since_, kJoinConfirmTimeoutMs)) {
        // No business ACK: the host may have missed R3. Retire the context
        // and re-establish fresh instead of reusing a half-open channel.
        retire_channel("JOIN_CONFIRM_TIMEOUT", now);
        break;
      }
      if (now >= sat_add(last_activity_, kIdleRetireMs)) {
        // Ten idle minutes: keep the DAMS, drop the traffic keys. A Wake or
        // a Pull re-opens the channel on demand.
        wipe_channel_keys();
        backoff_s_ = 0;
        state_ = AuthoritySnapshot::State::Dormant;  // armed: DAMS retained
        AuthorityEvent event{};
        event.kind = AuthorityEvent::Kind::ChannelLost;
        event.reason = "IDLE";
        observer_.on_event(event);
      }
      break;
    }
  }
  return Status::success();
}

Status AuthorityClient::on_pull(const AuthorityPullRequest& pull, const MonotonicMs now) noexcept {
  if (!started_) {
    return Status::error(StatusCode::InvalidState, "AUTHORITY_NOT_STARTED");
  }
  if (!site_bound()) {
    to_dormant();
    return Status::error(StatusCode::Conflict, "AUTHORITY_SITE_CHANGED");
  }
  if (state_ == AuthoritySnapshot::State::Dormant) {
    // Armed: re-open the channel first, then pull on the new Ready.
    pull_pending_ = true;
    pending_reason_ = pull.reason;
    return begin_handshake(now);
  }
  if (state_ != AuthoritySnapshot::State::Ready) {
    pull_pending_ = true;  // Connecting/Backoff: send once Ready
    pending_reason_ = pull.reason;
    return Status::success();
  }
  const bool due = !pull_sent_ || (now >= sat_add(last_pull_ms_, kPullBucketMs));
  if (!due) {
    pull_pending_ = true;  // one Pull per 60 s device-wide; coalesced
    pending_reason_ = pull.reason;
    return Status::success();
  }
  const Status status = send_pull(pull.reason, now);
  if (status.code == StatusCode::Busy) {
    pull_pending_ = true;
    pending_reason_ = pull.reason;
    return Status::success();  // Tick retries; the request is not lost
  }
  return status;
}

Status AuthorityClient::on_suspend() noexcept {
  to_dormant();
  return Status::success();
}

Status AuthorityClient::begin_handshake(const MonotonicMs now) noexcept {
  if (!engine_ready_) {
    rlres1::Local local{};
    local.self = local_.self;
    local.network = local_.network;
    local.site_id = local_.site_id;
    local.epochs = local_.epochs;
    rlres1::Limits limits{};
    limits.max_initiator = 1;
    limits.max_responder = 1;
    limits.responder_purposes = 0;  // initiator only; never answers R1
    limits.base_timeout_ms = static_cast<std::uint32_t>(kHandshakeTimeoutMs);
    if (!engine_.configure(local, limits)) {
      return Status::error(StatusCode::InvalidState, "AUTHORITY_ENGINE_CONFIG");
    }
    engine_ready_ = true;
  }
  rlres1::BeginRequest request{};
  request.slot.purpose = keys::Purpose::Authority;
  request.slot.peer = local_.site_id;
  request.slot.network = local_.network;
  request.slot.created_gk_epoch = local_.epochs.gk_epoch;
  request.slot.peer_generation = local_.generation;
  request.slot.secret = local_.dams;
  request.carrier.kind = rlres1::Carrier::Kind::Routed;
  rlres1::Output out{};
  engine_.begin(request, now, env_, out);
  secure_clear(request.slot.secret);
  if (out.action != rlres1::Action::Send || out.message_size == 0 ||
      out.message_size > tx_buffer_.size()) {
    out.clear();
    return Status::error(StatusCode::Busy, "AUTHORITY_BEGIN_DEFERRED");
  }
  // A fresh R1 supersedes anything staged: the old handshake is dead (its
  // engine session expired or never began).
  tx_size_ = out.message_size;
  tx_kind_ = TxKind::R1;
  std::memcpy(tx_buffer_.data(), out.message.data(), tx_size_);
  out.clear();
  hs_deadline_ = sat_add(now, kHandshakeTimeoutMs);
  last_activity_ = now;
  state_ = AuthoritySnapshot::State::Connecting;
  (void)flush_tx();
  return Status::success();
}

void AuthorityClient::wipe_channel_keys() noexcept {
  engine_.clear_all();
  keys::clear(tx_key_);
  keys::clear(rx_key_);
  rx_ctx_ = 0;
  tx_ctx_ = 0;
  rx_window_.reset();
  tx_counter_ = 0;
  next_request_id_ = 1;
  secure_clear(tx_buffer_);
  secure_clear(rx_control_);
  tx_size_ = 0;
  tx_kind_ = TxKind::None;
  tx_token_live_ = false;
  ack_pending_ = false;
  secure_clear(ack_gk_id_);
  ack_g_ = 0;
  ack_result_ = UpdateResult::Unsupported;
  ack_state_ = StoredState::None;
  join_confirm_sent_ = false;
  join_confirmed_ = false;
}

void AuthorityClient::enter_backoff(const MonotonicMs now, const char* reason) noexcept {
  wipe_channel_keys();
  backoff_s_ = (backoff_s_ == 0) ? 1 : ((backoff_s_ >= kBackoffMaxS) ? kBackoffMaxS : (backoff_s_ * 2));
  std::uint8_t jitter = 0;
  MonotonicMs jitter_ms = 0;
  if (env_.random(MutableByteView{&jitter, 1})) {
    jitter_ms = static_cast<MonotonicMs>(jitter % 251);  // 0..250 ms
  }
  backoff_until_ = sat_add(now, static_cast<MonotonicMs>(backoff_s_) * 1000 + jitter_ms);
  state_ = AuthoritySnapshot::State::Backoff;
  AuthorityEvent event{};
  event.kind = AuthorityEvent::Kind::ChannelLost;
  event.reason = reason;
  observer_.on_event(event);
}

void AuthorityClient::retire_channel(const char* reason, const MonotonicMs now) noexcept {
  // Staged business bytes die with the keys that sealed them; the authority
  // re-sends its Update and the JoinConfirm/Pull go out on the new channel.
  // A pending Pull survives (still wanted); a pending ACK does not (the new
  // channel answers the re-sent Update instead).
  enter_backoff(now, reason);
}

void AuthorityClient::to_dormant() noexcept {
  wipe();
  started_ = false;
  state_ = AuthoritySnapshot::State::Dormant;
}

bool AuthorityClient::flush_tx() noexcept {
  if (tx_size_ == 0 || tx_kind_ == TxKind::None) return true;
  AuthorityCarrierKind kind = AuthorityCarrierKind::Envelope;
  if (tx_kind_ == TxKind::R1) {
    kind = AuthorityCarrierKind::R1;
  } else if (tx_kind_ == TxKind::R3) {
    kind = AuthorityCarrierKind::R3;
  }
  std::uint64_t token = 0;
  if (!port_.try_send(local_.gateway, kind, ByteView{tx_buffer_.data(), tx_size_}, token)) {
    return false;  // port full; Tick retries with the same bytes
  }
  tx_token_ = token;
  tx_token_live_ = true;
  ++tx_sent_;
  tx_size_ = 0;
  tx_kind_ = TxKind::None;
  return true;
}

Status AuthorityClient::do_seal(const keys::AuthorityEnvelopeType type, const ByteView plaintext,
                                const MonotonicMs now) noexcept {
  if (state_ != AuthoritySnapshot::State::Ready) {
    return Status::error(StatusCode::InvalidState, "AUTHORITY_NOT_READY");
  }
  if (tx_size_ != 0) {
    return Status::error(StatusCode::Busy, "AUTHORITY_TX_BUSY");
  }
  if (tx_counter_ >= kProactiveRekeyCounter) {
    // 2^32 envelopes on one context: retire before the 2^48 hard stop and
    // re-establish. The caller re-queues what is still wanted.
    retire_channel("COUNTER_REKEY", now);
    return Status::error(StatusCode::CounterExhausted, "AUTHORITY_COUNTER_REKEY");
  }
  std::size_t written = 0;
  const std::uint64_t counter = tx_counter_++;
  const Status status = authority_seal(aead_, tx_key_, type, tx_ctx_, counter, plaintext,
                                       MutableByteView{tx_buffer_.data(), tx_buffer_.size()},
                                       written);
  if (!status) {
    retire_channel("AEAD_SEAL_FAILED", now);
    return status;
  }
  tx_size_ = written;
  tx_kind_ = TxKind::Envelope;
  last_activity_ = now;
  (void)flush_tx();
  return Status::success();
}

Status AuthorityClient::on_typed(const AuthorityTypedRequest& typed,
                                 const MonotonicMs now) noexcept {
  if (typed.type < 5 || typed.type > 7 || typed.body.data == nullptr ||
      typed.body.size == 0 || typed.body.size > 1024) {
    return Status::error(StatusCode::InvalidArgument, "AUTHORITY_TYPED_BODY");
  }
  if (state_ != AuthoritySnapshot::State::Ready || !site_bound()) {
    return Status::error(StatusCode::InvalidState, "AUTHORITY_NOT_BOUND");
  }
  if (tx_size_ != 0) return Status::error(StatusCode::Busy, "AUTHORITY_TX_BUSY");
  if (next_request_id_ == UINT64_MAX) {
    return Status::error(StatusCode::CounterExhausted, "AUTHORITY_REQUEST_EXHAUSTED");
  }
  std::array<std::uint8_t, kAuthorityBodyHeadSize + 1024> plaintext{};
  AuthorityBodyHead head{};
  head.op = 2;
  head.generation = local_.generation;
  head.request_id = next_request_id_;
  std::size_t written = 0;
  const Status encoded = authority_head_encode(
      head, MutableByteView{plaintext.data(), plaintext.size()}, written);
  if (!encoded) return encoded;
  std::memcpy(plaintext.data() + written, typed.body.data, typed.body.size);
  const Status sent = do_seal(static_cast<keys::AuthorityEnvelopeType>(typed.type),
                              ByteView{plaintext.data(), written + typed.body.size}, now);
  secure_clear(plaintext);
  if (sent) ++next_request_id_;
  return sent;
}

bool AuthorityClient::site_bound() const noexcept {
  if (group_ == nullptr) return true;  // PR1 fake-carrier mode
  // A failed GK twin write blocks group traffic, but the already established
  // DAMS may still report StorageFailure if the assignment remains known.
  if (!group_->store_.has_site() || group_->store_.quarantined()) return false;
  const SiteRecord& site = group_->store_.site();
  ScopeDigest cert_hash{};
  sha256(ByteView{site.member_cert.bytes.data(), site.member_cert.size}, cert_hash);
  bool gateway_bound = false;
  for (std::uint8_t i = 0; i < site.gateway_count; ++i) {
    gateway_bound = gateway_bound || site.gateways[i] == local_.gateway;
  }
  const bool bound = site.state == SiteState::Member && site.network == local_.network &&
         site.site_id == local_.site_id && site.assignment_generation == local_.generation &&
         site.dams == local_.dams && gateway_bound && cert_hash == local_.member_cert_hash &&
         group_->boot() == local_.boot && local_.boot >= site.boot_witness;
  secure_clear(cert_hash);
  return bound;
}

StoredState AuthorityClient::stored_state(const std::uint32_t g) const noexcept {
  if (group_ == nullptr || !group_->ready()) return StoredState::None;
  const SiteRecord& site = group_->store_.site();
  if (site.gk_epoch_current == g) return StoredState::Active;
  if (site.gk_epoch_next == g) return StoredState::Staged;
  return StoredState::None;
}

UpdateResult AuthorityClient::apply_update(const GroupKeyUpdate& msg,
                                           const MonotonicMs now) noexcept {
  if (group_ == nullptr) return UpdateResult::Unsupported;
  GroupKeyState::Input input{};
  input.op = GroupKeyState::Op::Stage;
  input.epoch = msg.g;
  input.key = msg.gk;
  input.generation = msg.head.generation;
  input.overlap_s = msg.overlap_s;
  const Status result = group_->advance(input, now);
  secure_clear(input.key);
  if (result) {
    local_.gk_current = group_->current();
    local_.gk_next = group_->store_.site().gk_epoch_next;
    return UpdateResult::Durable;
  }
  if (result.code == StatusCode::Conflict) return UpdateResult::Conflict;
  if (result.code == StatusCode::Busy) return UpdateResult::Busy;
  return UpdateResult::StorageFailure;
}

UpdateResult AuthorityClient::apply_activate(const GroupKeyActivate& msg,
                                             const MonotonicMs now) noexcept {
  if (group_ == nullptr) return UpdateResult::Unsupported;
  if (!group_->ready()) return UpdateResult::StorageFailure;
  const SiteRecord& site = group_->store_.site();
  const keys::Secret* key = nullptr;
  if (msg.g == site.gk_epoch_next) key = &site.gk_next;
  else if (msg.g == site.gk_epoch_current && site.gk_epoch_next == 0) key = &site.gk_current;
  if (key == nullptr) return UpdateResult::Conflict;
  GkId actual{};
  authority_gk_id(site.network, msg.g, *key, actual);
  std::uint8_t mismatch = 0;
  for (std::size_t i = 0; i < actual.size(); ++i) mismatch |= actual[i] ^ msg.gk_id[i];
  secure_clear(actual);
  if (mismatch != 0) return UpdateResult::Conflict;
  GroupKeyState::Input input{};
  input.op = GroupKeyState::Op::Activate;
  input.epoch = msg.g;
  input.generation = msg.head.generation;
  input.boot = group_->boot();
  input.overlap_s = msg.overlap_s;
  const Status result = group_->advance(input, now);
  if (result) {
    local_.gk_current = group_->current();
    local_.gk_next = group_->store_.site().gk_epoch_next;
    return UpdateResult::Durable;
  }
  if (result.code == StatusCode::Conflict) return UpdateResult::Conflict;
  if (result.code == StatusCode::Busy) return UpdateResult::Busy;
  return UpdateResult::StorageFailure;
}

Status AuthorityClient::stage_pending_ack(const MonotonicMs now) noexcept {
  if (!ack_pending_) return Status::success();
  if (tx_size_ != 0) return Status::error(StatusCode::Busy, "AUTHORITY_TX_BUSY");
  if (next_request_id_ == UINT64_MAX) {
    retire_channel("REQUEST_ID_EXHAUSTED", now);
    return Status::error(StatusCode::CounterExhausted, "AUTHORITY_REQUEST_ID_WRAP");
  }
  GroupKeyAck ack{};
  ack.head.op = 2;
  ack.head.generation = local_.generation;
  ack.head.request_id = next_request_id_++;
  ack.g = ack_g_;
  ack.gk_id = ack_gk_id_;
  // Only a verified store readback yields Durable; the port's queued result
  // is transport evidence, not an application ACK.
  ack.result = ack_result_;
  ack.stored_state = ack_state_;
  std::array<std::uint8_t, kGroupKeyAckSize> encoded{};
  std::size_t encoded_size = 0;
  if (!encode_group_key_ack(ack, MutableByteView{encoded.data(), encoded.size()},
                            encoded_size)) {
    return Status::error(StatusCode::InternalError, "AUTHORITY_ACK_ENCODE");
  }
  const Status status = do_seal(ack_type_, ByteView{encoded.data(), encoded_size}, now);
  secure_clear(encoded);
  if (!status) return status;
  ack_pending_ = false;
  secure_clear(ack_gk_id_);
  ack_g_ = 0;
  ack_result_ = UpdateResult::Unsupported;
  ack_state_ = StoredState::None;
  return Status::success();
}

Status AuthorityClient::send_join_confirm(const MonotonicMs now) noexcept {
  if (join_confirm_sent_) return Status::success();
  if (tx_size_ != 0) return Status::error(StatusCode::Busy, "AUTHORITY_TX_BUSY");
  if (next_request_id_ == UINT64_MAX) {
    retire_channel("REQUEST_ID_EXHAUSTED", now);
    return Status::error(StatusCode::CounterExhausted, "AUTHORITY_REQUEST_ID_WRAP");
  }
  JoinConfirmUp msg{};
  msg.head.op = 1;
  msg.head.generation = local_.generation;
  msg.head.request_id = next_request_id_++;
  msg.cert_hash = local_.member_cert_hash;
  msg.boot = local_.boot;
  msg.current = local_.gk_current;
  msg.next = local_.gk_next;
  std::array<std::uint8_t, kJoinConfirmUpSize> encoded{};
  std::size_t encoded_size = 0;
  if (!encode_join_confirm_up(msg, MutableByteView{encoded.data(), encoded.size()},
                              encoded_size)) {
    return Status::error(StatusCode::InternalError, "AUTHORITY_CONFIRM_ENCODE");
  }
  const Status status = do_seal(keys::AuthorityEnvelopeType::JoinConfirm,
                                ByteView{encoded.data(), encoded_size}, now);
  if (!status) return status;
  join_confirm_sent_ = true;
  return Status::success();
}

Status AuthorityClient::send_pull(const PullReason reason, const MonotonicMs now) noexcept {
  if (tx_size_ != 0) return Status::error(StatusCode::Busy, "AUTHORITY_TX_BUSY");
  if (next_request_id_ == UINT64_MAX) {
    retire_channel("REQUEST_ID_EXHAUSTED", now);
    return Status::error(StatusCode::CounterExhausted, "AUTHORITY_REQUEST_ID_WRAP");
  }
  GroupKeyPull msg{};
  msg.head.op = 1;
  msg.head.generation = local_.generation;
  msg.head.request_id = next_request_id_++;
  msg.current = group_ != nullptr ? group_->current() : local_.gk_current;
  msg.next = group_ != nullptr ? group_->store_.site().gk_epoch_next : local_.gk_next;
  msg.reason = reason;
  std::array<std::uint8_t, kGroupKeyPullSize> encoded{};
  std::size_t encoded_size = 0;
  if (!encode_group_key_pull(msg, MutableByteView{encoded.data(), encoded.size()},
                             encoded_size)) {
    return Status::error(StatusCode::InternalError, "AUTHORITY_PULL_ENCODE");
  }
  const Status status =
      do_seal(keys::AuthorityEnvelopeType::GroupKeyPull, ByteView{encoded.data(), encoded_size},
              now);
  if (!status) return status;
  last_pull_ms_ = now;
  pull_sent_ = true;
  return Status::success();
}

void AuthorityClient::on_envelope_ready(const AuthorityRxCarrier& rx,
                                         const MonotonicMs now) noexcept {
  const ByteView bytes = rx.bytes;
  const bool direct = tx_size_ != 0 && bytes.size > rx_control_.size() &&
                      rx.writable.data == bytes.data && rx.writable.size >= bytes.size;
  std::uint8_t* const workspace = tx_size_ == 0 ? tx_buffer_.data()
                                  : direct ? rx.writable.data : rx_control_.data();
  const std::size_t capacity = tx_size_ == 0 ? tx_buffer_.size()
                               : direct ? rx.writable.size : rx_control_.size();
  if (bytes.data == nullptr || bytes.size > keys::kAuthorityEnvelopeMax ||
      bytes.size > capacity) {
    ++rx_rejected_;
    return;
  }
  if (!direct) std::memmove(workspace, bytes.data, bytes.size);
  const std::size_t wipe_size = direct ? bytes.size : capacity;
  const ByteView envelope{workspace, bytes.size};
  keys::AuthorityEnvelopeHeader header{};
  std::size_t plain_size = 0;
  // In place: plaintext lands at the buffer front while its ciphertext sits
  // 12 bytes ahead, so reads always run ahead of writes (see the AeadGcm
  // contract). No second 2 KiB buffer, no big stack array.
  const Status opened = authority_open(aead_, rx_key_, envelope, rx_ctx_,
                                       MutableByteView{workspace, capacity},
                                       plain_size, header);
  if (!opened) {
    secure_clear(workspace, wipe_size);
    ++rx_rejected_;
    return;
  }
  if (ack_pending_ && (header.type == keys::AuthorityEnvelopeType::GroupKeyUpdate ||
                       header.type == keys::AuthorityEnvelopeType::GroupKeyActivate)) {
    secure_clear(workspace, wipe_size);
    ++rx_rejected_;
    return;
  }
  // The AEAD tag verified: commit the replay window before any meaning check.
  if (!rx_window_.accept(header.counter)) {
    secure_clear(workspace, wipe_size);
    ++rx_rejected_;
    return;
  }
  last_activity_ = now;
  const ByteView body{workspace, plain_size};
  const auto fail = [&](void) {
    secure_clear(workspace, wipe_size);
    ++rx_rejected_;
  };
  const auto done = [&](void) {
    secure_clear(workspace, wipe_size);
    ++rx_accepted_;
  };
  switch (header.type) {
    case keys::AuthorityEnvelopeType::JoinConfirm: {
      JoinConfirmDown msg{};
      if (!decode_join_confirm_down(body, msg)) {
        fail();
        return;
      }
      if (msg.head.generation != local_.generation ||
          msg.confirmed_generation != local_.generation) {
        fail();
        return;
      }
      join_confirmed_ = true;
      AuthorityEvent event{};
      event.kind = AuthorityEvent::Kind::JoinConfirmAck;
      event.envelope_type = 1;
      event.confirmed_generation = msg.confirmed_generation;
      event.authority_active = msg.authority_active;
      done();
      observer_.on_event(event);
      return;
    }
    case keys::AuthorityEnvelopeType::GroupKeyUpdate: {
      GroupKeyUpdate msg{};
      if (!decode_group_key_update(body, msg)) {
        fail();
        return;
      }
      if (msg.head.generation != local_.generation) {
        secure_clear(msg.gk);
        fail();
        return;
      }
      GkId gk_id{};
      authority_gk_id(local_.network, msg.g, msg.gk, gk_id);
      ack_result_ = apply_update(msg, now);
      ack_state_ = ack_result_ == UpdateResult::Durable ? stored_state(msg.g) : StoredState::None;
      secure_clear(msg.gk);
      ack_type_ = keys::AuthorityEnvelopeType::GroupKeyUpdate;
      ack_g_ = msg.g;
      ack_gk_id_ = gk_id;
      ack_pending_ = true;
      secure_clear(gk_id);
      AuthorityEvent event{};
      event.kind = AuthorityEvent::Kind::UpdateReceived;
      event.envelope_type = 2;
      event.g = msg.g;
      event.cause = msg.cause;
      event.overlap_s = msg.overlap_s;
      done();
      observer_.on_event(event);
      (void)stage_pending_ack(now);
      return;
    }
    case keys::AuthorityEnvelopeType::GroupKeyActivate: {
      GroupKeyActivate msg{};
      if (!decode_group_key_activate(body, msg)) {
        fail();
        return;
      }
      if (msg.head.generation != local_.generation) {
        fail();
        return;
      }
      ack_result_ = apply_activate(msg, now);
      ack_state_ = ack_result_ == UpdateResult::Durable ? stored_state(msg.g) : StoredState::None;
      ack_type_ = keys::AuthorityEnvelopeType::GroupKeyActivate;
      ack_g_ = msg.g;
      ack_gk_id_ = msg.gk_id;  // name the key we could not apply
      ack_pending_ = true;
      AuthorityEvent event{};
      event.kind = AuthorityEvent::Kind::ActivateReceived;
      event.envelope_type = 3;
      event.g = msg.g;
      event.cause = msg.cause;
      event.overlap_s = msg.overlap_s;
      done();
      observer_.on_event(event);
      (void)stage_pending_ack(now);
      return;
    }
    case keys::AuthorityEnvelopeType::GroupKeyPull:
      // Wrong direction: only the authority receives Pulls.
      fail();
      return;
    default: {
      // Types 5..8: AEAD-verified plaintext for the P6 sink. The head must
      // still be well-formed; the tail stays opaque to PR1. The observer
      // borrows `body` during the call, so notify first and wipe after.
      AuthorityBodyHead head{};
      if (plain_size < kAuthorityBodyHeadSize ||
          !authority_head_decode(ByteView{workspace, kAuthorityBodyHeadSize}, head) ||
          head.op != 1 || head.generation != local_.generation) {
        fail();
        return;
      }
      AuthorityEvent event{};
      event.kind = AuthorityEvent::Kind::Passthrough;
      event.envelope_type = static_cast<std::uint8_t>(header.type);
      event.reason = "P6_SINK";
      event.passthrough = body;
      ++rx_accepted_;
      observer_.on_event(event);
      secure_clear(workspace, wipe_size);
      return;
    }
  }
}

void AuthorityClient::wipe() noexcept {
  engine_.clear_all();
  engine_ready_ = false;
  secure_clear(local_.dams);
  local_ = AuthorityStart{};
  keys::clear(tx_key_);
  keys::clear(rx_key_);
  rx_ctx_ = 0;
  tx_ctx_ = 0;
  rx_window_.reset();
  tx_counter_ = 0;
  next_request_id_ = 1;
  secure_clear(tx_buffer_);
  secure_clear(rx_control_);
  tx_size_ = 0;
  tx_kind_ = TxKind::None;
  tx_token_ = 0;
  tx_token_live_ = false;
  backoff_until_ = 0;
  hs_deadline_ = 0;
  backoff_s_ = 0;
  pull_pending_ = false;
  ack_pending_ = false;
  ack_g_ = 0;
  ack_result_ = UpdateResult::Unsupported;
  ack_state_ = StoredState::None;
  secure_clear(ack_gk_id_);
  last_activity_ = 0;
  last_wake_ms_ = 0;
  wake_seen_ = false;
  ready_since_ = 0;
  join_confirmed_ = false;
  join_confirm_sent_ = false;
  tx_sent_ = 0;
  tx_failed_ = 0;
  rx_accepted_ = 0;
  rx_rejected_ = 0;
}

}  // namespace routeloom::sdkv1
