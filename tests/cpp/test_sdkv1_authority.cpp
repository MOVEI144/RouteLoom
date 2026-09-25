// Authority channel, device side (routeloom/sdkv1_authority.hpp, G-SEC P5
// PR1, acceptance V1-K11 crypto/endpoint part + K03/K04): body codecs, the
// GK-id derivation and the sealed envelopes against
// protocol/sdkv1-golden/authority/, then a live client driven against a
// small in-test fake authority (a real rlres1::Engine responder + the
// builtin AES-GCM) over loopback carriers — handshake, JoinConfirm, Pull,
// Update/Activate round-trips, re-entry, backoff and timers. The clock is
// injected (`now` on every call).

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
#include <new>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "routeloom/aead_gcm.hpp"
#include "routeloom/key_schedule.hpp"
#include "routeloom/rlres1.hpp"
#include "routeloom/sdkv1_authority.hpp"

static_assert(sizeof(routeloom::sdkv1::AuthorityClient) <= 4840,
              "authority client shares its send and receive workspace");
#include "routeloom/sdkv1_group_keys.hpp"
#include "test_sdkv1.hpp"

#ifndef ROUTELOOM_SDKV1_GOLDEN_DIR
#error "ROUTELOOM_SDKV1_GOLDEN_DIR must point at protocol/sdkv1-golden"
#endif

namespace {

int failures = 0;
#define CHECK(expr)                                                        \
  do {                                                                     \
    if (!(expr)) {                                                         \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__,   \
                   #expr);                                                 \
      ++failures;                                                          \
    }                                                                      \
  } while (false)

namespace keys = routeloom::keys;
namespace rlres1 = routeloom::rlres1;
namespace sdkv1 = routeloom::sdkv1;
using routeloom::ByteView;
using routeloom::MutableByteView;
using routeloom::MonotonicMs;
using routeloom::NodeId;
using routeloom::Status;
using Bytes = std::vector<std::uint8_t>;
using Fields = std::map<std::string, std::string>;

constexpr std::uint64_t kNetwork = (std::uint64_t{7} << 32) | 0x0A0B0C0Du;
constexpr NodeId kSelf = 0x101;
constexpr NodeId kGateway = 0x102;
constexpr std::uint64_t kSite = 0x5100000000000042ull;
constexpr std::uint32_t kGeneration = 9;

// Minimal extractor for the flat "key": value golden objects (strings or
// unsigned integers), same subset as test_key_schedule.cpp.
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
    while (cursor < text.size() && std::isspace(static_cast<unsigned char>(text[cursor]))) ++cursor;
    std::string value;
    if (cursor < text.size() && text[cursor] == '"') {
      const std::size_t value_end = text.find('"', cursor + 1);
      if (value_end == std::string::npos) break;
      value = text.substr(cursor + 1, value_end - cursor - 1);
      pos = value_end + 1;
    } else {
      std::size_t value_end = cursor;
      while (value_end < text.size() && std::isdigit(static_cast<unsigned char>(text[value_end]))) {
        ++value_end;
      }
      value = text.substr(cursor, value_end - cursor);
      pos = value_end;
    }
    fields[text.substr(key_begin + 1, key_end - key_begin - 1)] = value;
  }
  return fields;
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream file(path);
  std::stringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

std::uint64_t u64(const Fields& f, const char* key) {
  const auto it = f.find(key);
  if (it == f.end() || it->second.empty()) {
    std::fprintf(stderr, "missing integer field %s\n", key);
    ++failures;
    return 0;
  }
  return std::strtoull(it->second.c_str(), nullptr, 10);
}

Bytes hex(const Fields& f, const char* key) {
  const auto it = f.find(key);
  Bytes out;
  if (it == f.end() || it->second.size() % 2 != 0) {
    std::fprintf(stderr, "missing/odd hex field %s\n", key);
    ++failures;
    return out;
  }
  for (std::size_t i = 0; i < it->second.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>(std::stoul(it->second.substr(i, 2), nullptr, 16)));
  }
  return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> arr(const Fields& f, const char* key) {
  std::array<std::uint8_t, N> out{};
  const Bytes b = hex(f, key);
  CHECK(b.size() == N);
  for (std::size_t i = 0; i < N && i < b.size(); ++i) out[i] = b[i];
  return out;
}

std::vector<std::filesystem::path> list(const char* sub) {
  std::vector<std::filesystem::path> out;
  const auto dir = std::filesystem::path(ROUTELOOM_SDKV1_GOLDEN_DIR) / "authority" / sub;
  for (const auto& e : std::filesystem::directory_iterator(dir)) {
    if (e.path().extension() == ".json") out.push_back(e.path());
  }
  std::sort(out.begin(), out.end());
  return out;
}

keys::Secret secret(std::uint8_t seed) {
  keys::Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(seed + i);
  return s;
}

// --- Golden bodies -----------------------------------------------------------

void test_golden_bodies() {
  for (const auto& path : list("valid")) {
    const Fields f = parse_flat_json(read_text(path));
    if (f.find("codec") == f.end() || f.at("codec") != "authority_body") continue;
    CHECK(f.at("format") == "routeloom-sdkv1-authority-golden-v1");
    const Bytes pt = hex(f, "plaintext_hex");
    const std::string name = f.at("name");
    const int type = static_cast<int>(u64(f, "type"));
    const int op = static_cast<int>(u64(f, "op"));
    std::array<std::uint8_t, 64> encoded{};
    std::size_t written = 0;
    if (type == 1 && op == 1) {
      sdkv1::JoinConfirmUp msg{};
      CHECK(sdkv1::decode_join_confirm_up(ByteView{pt.data(), pt.size()}, msg));
      CHECK(msg.head.generation == u64(f, "generation"));
      CHECK(msg.head.request_id == u64(f, "request_id"));
      CHECK(msg.boot == u64(f, "boot"));
      CHECK(msg.current == u64(f, "current"));
      CHECK(msg.next == u64(f, "next"));
      CHECK(sdkv1::encode_join_confirm_up(
          msg, MutableByteView{encoded.data(), encoded.size()}, written));
      CHECK(written == pt.size() &&
            std::memcmp(encoded.data(), pt.data(), pt.size()) == 0);
    } else if (type == 1 && op == 2) {
      sdkv1::JoinConfirmDown msg{};
      CHECK(sdkv1::decode_join_confirm_down(ByteView{pt.data(), pt.size()}, msg));
      CHECK(msg.confirmed_generation == u64(f, "confirmed_generation"));
      CHECK(msg.authority_active == u64(f, "authority_active"));
      CHECK(sdkv1::encode_join_confirm_down(
          msg, MutableByteView{encoded.data(), encoded.size()}, written));
      CHECK(written == pt.size() &&
            std::memcmp(encoded.data(), pt.data(), pt.size()) == 0);
    } else if (type == 2 && op == 1) {
      sdkv1::GroupKeyUpdate msg{};
      CHECK(sdkv1::decode_group_key_update(ByteView{pt.data(), pt.size()}, msg));
      CHECK(msg.g == u64(f, "g"));
      CHECK(static_cast<int>(msg.cause) == static_cast<int>(u64(f, "cause")));
      CHECK(msg.overlap_s == u64(f, "overlap_s"));
      CHECK(sdkv1::encode_group_key_update(
          msg, MutableByteView{encoded.data(), encoded.size()}, written));
      CHECK(written == pt.size() &&
            std::memcmp(encoded.data(), pt.data(), pt.size()) == 0);
    } else if ((type == 2 || type == 3) && op == 2) {
      sdkv1::GroupKeyAck msg{};
      CHECK(sdkv1::decode_group_key_ack(ByteView{pt.data(), pt.size()}, msg));
      CHECK(msg.g == u64(f, "g"));
      CHECK(static_cast<int>(msg.result) == static_cast<int>(u64(f, "result")));
      CHECK(static_cast<int>(msg.stored_state) == static_cast<int>(u64(f, "stored_state")));
      CHECK(sdkv1::encode_group_key_ack(
          msg, MutableByteView{encoded.data(), encoded.size()}, written));
      CHECK(written == pt.size() &&
            std::memcmp(encoded.data(), pt.data(), pt.size()) == 0);
    } else if (type == 3 && op == 1) {
      sdkv1::GroupKeyActivate msg{};
      CHECK(sdkv1::decode_group_key_activate(ByteView{pt.data(), pt.size()}, msg));
      CHECK(msg.g == u64(f, "g"));
      CHECK(static_cast<int>(msg.cause) == static_cast<int>(u64(f, "cause")));
      CHECK(msg.overlap_s == u64(f, "overlap_s"));
      CHECK(sdkv1::encode_group_key_activate(
          msg, MutableByteView{encoded.data(), encoded.size()}, written));
      CHECK(written == pt.size() &&
            std::memcmp(encoded.data(), pt.data(), pt.size()) == 0);
    } else if (type == 4 && op == 1) {
      sdkv1::GroupKeyPull msg{};
      CHECK(sdkv1::decode_group_key_pull(ByteView{pt.data(), pt.size()}, msg));
      CHECK(msg.current == u64(f, "current"));
      CHECK(msg.next == u64(f, "next"));
      CHECK(static_cast<int>(msg.reason) == static_cast<int>(u64(f, "reason")));
      CHECK(sdkv1::encode_group_key_pull(
          msg, MutableByteView{encoded.data(), encoded.size()}, written));
      CHECK(written == pt.size() &&
            std::memcmp(encoded.data(), pt.data(), pt.size()) == 0);
    } else {
      CHECK(false);  // unknown valid body in the goldens
    }
    (void)name;
  }
  // Every invalid body must be refused with the golden reason word.
  int invalid_seen = 0;
  for (const auto& path : list("invalid")) {
    const Fields f = parse_flat_json(read_text(path));
    if (f.find("codec") == f.end() || f.at("codec") != "authority_body") continue;
    const Bytes raw = hex(f, "encoded_hex");
    const std::string want = f.at("reason");
    const std::string name = f.at("name");
    Status status;
    if (name.find("pull") != std::string::npos) {
      sdkv1::GroupKeyPull msg{};
      status = sdkv1::decode_group_key_pull(ByteView{raw.data(), raw.size()}, msg);
    } else if (name.find("ack") != std::string::npos) {
      sdkv1::GroupKeyAck msg{};
      status = sdkv1::decode_group_key_ack(ByteView{raw.data(), raw.size()}, msg);
    } else {
      sdkv1::GroupKeyUpdate msg{};
      status = sdkv1::decode_group_key_update(ByteView{raw.data(), raw.size()}, msg);
    }
    CHECK(!status);
    CHECK(status.detail != nullptr && want == status.detail);
    ++invalid_seen;
  }
  CHECK(invalid_seen == 15);
}

void test_golden_gk_id() {
  for (const auto& path : list("valid")) {
    const Fields f = parse_flat_json(read_text(path));
    if (f.find("codec") == f.end() || f.at("codec") != "gk_id") continue;
    sdkv1::GkId id{};
    sdkv1::authority_gk_id(u64(f, "network"), static_cast<std::uint32_t>(u64(f, "epoch")),
                           arr<32>(f, "gk_hex"), id);
    const Bytes want = hex(f, "gk_id_hex");
    CHECK(want.size() == id.size() &&
          std::memcmp(want.data(), id.data(), id.size()) == 0);
  }
}

// --- Golden envelopes (real AES-GCM both directions) -------------------------

void test_golden_envelopes() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  int valid_seen = 0;
  for (const auto& path : list("valid")) {
    const Fields f = parse_flat_json(read_text(path));
    if (f.find("codec") == f.end() || f.at("codec") != "authority_envelope") continue;
    keys::TrafficKey key{};
    key.key = arr<16>(f, "key_hex");
    key.iv = arr<12>(f, "iv_hex");
    const Bytes envelope = hex(f, "envelope_hex");
    const Bytes plaintext = hex(f, "plaintext_hex");
    // Open direction.
    std::array<std::uint8_t, keys::kAuthorityEnvelopeMax> out{};
    std::size_t written = 0;
    keys::AuthorityEnvelopeHeader header{};
    const Status opened = sdkv1::authority_open(
        *aead, key, ByteView{envelope.data(), envelope.size()},
        static_cast<std::uint32_t>(u64(f, "ctx_id")),
        MutableByteView{out.data(), out.size()}, written, header);
    CHECK(opened);
    CHECK(written == plaintext.size() &&
          std::memcmp(out.data(), plaintext.data(), plaintext.size()) == 0);
    CHECK(header.counter == u64(f, "counter"));
    CHECK(static_cast<int>(header.type) == static_cast<int>(u64(f, "type")));
    // Seal direction: GCM is deterministic, so the same inputs must produce
    // the same bytes.
    std::array<std::uint8_t, keys::kAuthorityEnvelopeMax> sealed{};
    std::size_t sealed_size = 0;
    const Status sealed_status = sdkv1::authority_seal(
        *aead, key, header.type, header.ctx_id, header.counter,
        ByteView{plaintext.data(), plaintext.size()},
        MutableByteView{sealed.data(), sealed.size()}, sealed_size);
    CHECK(sealed_status);
    CHECK(sealed_size == envelope.size() &&
          std::memcmp(sealed.data(), envelope.data(), envelope.size()) == 0);
    ++valid_seen;
  }
  CHECK(valid_seen == 11);
  // Tampered envelopes must fail authentication without emitting plaintext.
  int invalid_seen = 0;
  for (const auto& path : list("invalid")) {
    const Fields f = parse_flat_json(read_text(path));
    if (f.find("codec") == f.end() || f.at("codec") != "authority_envelope") continue;
    keys::TrafficKey key{};
    key.key = arr<16>(f, "key_hex");
    key.iv = arr<12>(f, "iv_hex");
    const Bytes envelope = hex(f, "envelope_hex");
    std::array<std::uint8_t, keys::kAuthorityEnvelopeMax> out{};
    std::memset(out.data(), 0xA5, out.size());
    std::size_t written = 0;
    keys::AuthorityEnvelopeHeader header{};
    const Status opened = sdkv1::authority_open(
        *aead, key, ByteView{envelope.data(), envelope.size()}, 0x66666666,
        MutableByteView{out.data(), out.size()}, written, header);
    CHECK(!opened);
    CHECK(opened.code == routeloom::StatusCode::AuthenticationFailed);
    CHECK(written == 0);
    // The backend zeroes exactly the output span on failure; bytes past the
    // plaintext length are never touched.
    const std::size_t plain_size = envelope.size() - keys::kAuthorityEnvelopeMin;
    for (std::size_t i = 0; i < out.size(); ++i) {
      CHECK(out[i] == (i < plain_size ? 0 : 0xA5));
    }
    ++invalid_seen;
  }
  CHECK(invalid_seen == 2);
  // Counter 2^48 is unrepresentable: seal must refuse, never wrap.
  keys::TrafficKey key{};
  std::array<std::uint8_t, 64> sealed{};
  std::size_t sealed_size = 0;
  const std::uint8_t one = 1;
  const Status wrapped = sdkv1::authority_seal(
      *aead, key, keys::AuthorityEnvelopeType::GroupKeyPull, 1,
      std::uint64_t{1} << 48, ByteView{&one, 1},
      MutableByteView{sealed.data(), sealed.size()}, sealed_size);
  CHECK(!wrapped && wrapped.code == routeloom::StatusCode::CounterExhausted);
}

// --- Builtin AES-GCM: NIST KAT, tamper zeroing, in-place ---------------------

void test_builtin_gcm() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  // NIST SP 800-38D F.5.1 (AES-128-GCM, 12-byte IV, no AAD): key/nonce/plain
  // zero, 16-byte plaintext.
  const std::array<std::uint8_t, 16> key{};
  const std::array<std::uint8_t, 12> nonce{};
  const std::array<std::uint8_t, 16> pt{};
  const std::array<std::uint8_t, 16> want_ct{0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                             0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
  const std::array<std::uint8_t, 16> want_tag{0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                              0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
  std::array<std::uint8_t, 32> sealed{};
  CHECK(aead->seal(aead->ctx, key.data(), nonce.data(), ByteView{}, ByteView{pt.data(), pt.size()},
                   sealed.data()));
  CHECK(std::memcmp(sealed.data(), want_ct.data(), 16) == 0);
  CHECK(std::memcmp(sealed.data() + 16, want_tag.data(), 16) == 0);
  std::array<std::uint8_t, 16> opened{};
  CHECK(aead->open(aead->ctx, key.data(), nonce.data(), ByteView{},
                   ByteView{sealed.data(), sealed.size()}, opened.data()));
  CHECK(opened == pt);
  // A flipped tag bit fails and zeroes the whole output span.
  std::array<std::uint8_t, 32> bad = sealed;
  bad[31] ^= 0x01;
  std::memset(opened.data(), 0x5A, opened.size());
  CHECK(!aead->open(aead->ctx, key.data(), nonce.data(), ByteView{},
                    ByteView{bad.data(), bad.size()}, opened.data()));
  for (const auto b : opened) CHECK(b == 0);
  // Forward-offset in-place decrypt (the channel's RX reuse): plaintext at
  // the buffer front, its ciphertext 12 bytes ahead.
  std::array<std::uint8_t, 64> buf{};
  std::memcpy(buf.data() + 12, sealed.data(), sealed.size());
  CHECK(aead->open(aead->ctx, key.data(), nonce.data(), ByteView{},
                   ByteView{buf.data() + 12, sealed.size()}, buf.data()));
  CHECK(std::memcmp(buf.data(), pt.data(), pt.size()) == 0);
}

// --- Replay window -----------------------------------------------------------

void test_replay_window() {
  sdkv1::AuthorityReplayWindow window{};
  CHECK(window.accept(7));   // first counter accepted unconditionally
  CHECK(!window.accept(7));  // duplicate
  CHECK(window.accept(9));   // gap tolerated
  CHECK(window.accept(8));   // gap filled
  CHECK(!window.accept(8));
  CHECK(window.accept(0));   // inside the window, first sight: accepted
  CHECK(!window.accept(0));  // now a duplicate
  for (std::uint64_t c = 10; c < 10 + 64; ++c) CHECK(window.accept(c));
  CHECK(!window.accept(10));  // max is 73; counter 10 was seen: duplicate
  CHECK(window.accept(1000));
  CHECK(window.accept(1000 - 63));   // window floor edge, first sight
  CHECK(!window.accept(1000 - 63));  // now a duplicate
  CHECK(!window.accept(1000 - 64));  // below the floor: rejected
  CHECK(!window.accept(10));         // long out of the window: rejected
  window.reset();
  CHECK(window.accept(3));  // reset channels start over legitimately
}

// --- Fake port / observer / entropy ------------------------------------------

struct SentCarrier {
  NodeId gateway{kGateway};
  sdkv1::AuthorityCarrierKind kind{sdkv1::AuthorityCarrierKind::Envelope};
  Bytes bytes;
  std::uint64_t token{0};
};

struct FakePort final : sdkv1::AuthorityPort {
  std::vector<SentCarrier> sent;
  std::uint64_t next_token{1};
  bool full{false};
  bool block_envelopes{false};
  sdkv1::AuthorityClient* reenter{nullptr};  // when set, advance() from try_send

  bool try_send(NodeId gateway, sdkv1::AuthorityCarrierKind kind, ByteView carrier,
                std::uint64_t& token) noexcept override {
    if (full || (block_envelopes && kind == sdkv1::AuthorityCarrierKind::Envelope)) return false;
    token = next_token++;
    SentCarrier out{};
    out.gateway = gateway;
    out.kind = kind;
    out.bytes.assign(carrier.data, carrier.data + carrier.size);
    out.token = token;
    sent.push_back(std::move(out));
    if (reenter != nullptr) {
      sdkv1::AuthorityInput in{};
      in.kind = sdkv1::AuthorityInputKind::Tick;
      const Status nested = reenter->advance(in, 0);
      reenter_result = nested.code;
    }
    return true;
  }

  routeloom::StatusCode reenter_result{routeloom::StatusCode::Ok};
};

struct FakeObserver final : sdkv1::AuthorityObserver {
  struct Seen {
    sdkv1::AuthorityEvent::Kind kind{sdkv1::AuthorityEvent::Kind::ChannelLost};
    std::string reason;
    std::uint8_t type{0};
    std::uint32_t g{0};
    Bytes passthrough;
  };
  std::vector<Seen> seen;
  sdkv1::AuthorityClient* reenter{nullptr};
  routeloom::StatusCode reenter_result{routeloom::StatusCode::Ok};

  void on_event(const sdkv1::AuthorityEvent& event) noexcept override {
    Seen s{};
    s.kind = event.kind;
    s.reason = (event.reason != nullptr) ? event.reason : "";
    s.type = event.envelope_type;
    s.g = event.g;
    if (event.passthrough.data != nullptr && event.passthrough.size != 0) {
      s.passthrough.assign(event.passthrough.data,
                           event.passthrough.data + event.passthrough.size);
    }
    seen.push_back(std::move(s));
    if (reenter != nullptr) {
      sdkv1::AuthorityInput in{};
      in.kind = sdkv1::AuthorityInputKind::Tick;
      reenter_result = reenter->advance(in, 0).code;
    }
  }
};

struct FakeEnv final : rlres1::Environment {
  std::uint64_t rng{0x12345678};
  std::uint32_t next_cid{0xA000};
  bool entropy_ok{true};
  sdkv1::AuthorityClient* reenter{nullptr};
  routeloom::StatusCode reenter_result{routeloom::StatusCode::Ok};

  bool random(MutableByteView out) noexcept override {
    if (reenter != nullptr) {
      sdkv1::AuthorityInput in{};
      in.kind = sdkv1::AuthorityInputKind::Tick;
      reenter_result = reenter->advance(in, 0).code;
    }
    if (!entropy_ok) return false;
    for (std::size_t i = 0; i < out.size; ++i) {
      rng = rng * 6364136223846793005ull + 1442695040888963407ull;
      out.data[i] = static_cast<std::uint8_t>(rng >> 33);
    }
    return true;
  }

  bool find_slot(rlres1::Purpose, const keys::ResumeId&, rlres1::Slot&) noexcept override {
    return false;  // initiator only
  }
  bool reserve_resume_use(rlres1::Purpose, const keys::ResumeId&) noexcept override {
    return false;
  }

  bool revoked(NodeId, std::uint32_t) noexcept override { return false; }

  bool allocate_context_id(rlres1::Purpose, NodeId, std::uint32_t& cid) noexcept override {
    cid = next_cid++;
    if (next_cid == 0) next_cid = 1;
    return true;
  }
};

sdkv1::AuthorityStart make_start() {
  sdkv1::AuthorityStart start{};
  start.network = kNetwork;
  start.self = kSelf;
  start.site_id = kSite;
  start.gateway = kGateway;
  start.dams = secret(0xD0);
  start.generation = kGeneration;
  start.epochs.site_epoch = 7;
  start.epochs.rs_epoch = 4;
  start.epochs.gk_epoch = 12;
  for (std::size_t i = 0; i < start.member_cert_hash.size(); ++i) {
    start.member_cert_hash[i] = static_cast<std::uint8_t>(0xC0 + i);
  }
  start.boot = 5;
  start.gk_current = 10;
  start.gk_next = 0;
  return start;
}

// --- Fake authority: a real RLRES1 responder + real AES-GCM ------------------
//
// Fault-injection double for the host side (§10.4 first step). It answers R1
// with R2, installs on R3, then runs a scripted business dialogue: a
// JoinConfirm gets its ACK, a Pull gets an Update, an ACK is recorded. All
// crypto is real; only the policy is canned.

struct FakeAuthorityEnv final : rlres1::Environment {
  std::uint64_t rng{0xF00D};
  std::uint32_t next_cid{0xB000};
  keys::Secret dams{};
  NodeId device{kSelf};
  std::uint64_t network{kNetwork};
  std::uint64_t site{kSite};
  std::uint32_t generation{kGeneration};
  std::uint32_t gk_epoch{12};

  bool random(MutableByteView out) noexcept override {
    for (std::size_t i = 0; i < out.size; ++i) {
      rng = rng * 6364136223846793005ull + 1442695040888963407ull;
      out.data[i] = static_cast<std::uint8_t>(rng >> 33);
    }
    return true;
  }

  bool find_slot(rlres1::Purpose purpose, const keys::ResumeId& rid,
                 rlres1::Slot& out) noexcept override {
    if (purpose != keys::Purpose::Authority) return false;
    keys::ResumeId want{};
    keys::resume_id(dams, keys::Purpose::Authority, want);
    if (want != rid) return false;
    out.purpose = keys::Purpose::Authority;
    out.peer = device;
    out.network = network;
    out.created_gk_epoch = gk_epoch;
    out.peer_generation = generation;
    out.secret = dams;
    return true;
  }
  bool reserve_resume_use(rlres1::Purpose, const keys::ResumeId&) noexcept override {
    return true;
  }

  bool revoked(NodeId, std::uint32_t) noexcept override { return false; }

  bool allocate_context_id(rlres1::Purpose, NodeId, std::uint32_t& cid) noexcept override {
    cid = next_cid++;
    if (next_cid == 0) next_cid = 1;
    return true;
  }
};

struct FakeAuthority {
  rlres1::Engine engine;
  FakeAuthorityEnv env;
  keys::TrafficKey tx{};  // responder -> initiator: seals to the device
  keys::TrafficKey rx{};  // initiator -> responder: opens from the device
  std::uint32_t rx_ctx{0};
  std::uint32_t tx_ctx{0};
  std::uint64_t next_request{1};
  bool ready{false};
  int updates_sent{0};
  int acks_seen{0};
  sdkv1::UpdateResult last_ack_result{sdkv1::UpdateResult::Durable};
  std::uint32_t last_ack_g{0};

  const routeloom::AeadGcm* aead{routeloom::builtin_aead_gcm()};

  explicit FakeAuthority(const keys::Secret& dams, const sdkv1::AuthorityStart start = make_start()) {
    env.dams = dams;
    env.device = start.self;
    env.network = start.network;
    env.site = start.site_id;
    env.generation = start.generation;
    env.gk_epoch = start.epochs.gk_epoch;
    rlres1::Local local{};
    local.self = start.site_id;  // the authority's node namespace is the site id
    local.network = start.network;
    local.site_id = start.site_id;
    local.epochs = start.epochs;
    rlres1::Limits limits{};
    limits.responder_purposes = (1u << 4);
    CHECK(engine.configure(local, limits));
  }

  // Feeds one device carrier; returns carriers to send back.
  std::vector<SentCarrier> on_carrier(sdkv1::AuthorityCarrierKind kind, ByteView bytes,
                                      MonotonicMs now) {
    std::vector<SentCarrier> replies;
    if (kind == sdkv1::AuthorityCarrierKind::R1) {
      rlres1::Carrier carrier{};
      rlres1::Output out{};
      engine.on_r1(bytes, carrier, env.device, now, env, out);
      if (out.action == rlres1::Action::Send && out.message_size != 0) {
        SentCarrier r2{};
        r2.kind = sdkv1::AuthorityCarrierKind::R2;
        r2.bytes.assign(out.message.data(), out.message.data() + out.message_size);
        replies.push_back(std::move(r2));
      }
      return replies;
    }
    if (kind == sdkv1::AuthorityCarrierKind::R3) {
      rlres1::Output out{};
      engine.on_r3(env.device, keys::Purpose::Authority, bytes, now, out);
      if (out.action == rlres1::Action::Install) {
        tx = out.established.tx;
        rx = out.established.rx;
        rx_ctx = out.established.rx_context_id;
        tx_ctx = out.established.tx_context_id;
        ready = true;
      }
      return replies;
    }
    if (kind != sdkv1::AuthorityCarrierKind::Envelope || !ready) return replies;
    std::array<std::uint8_t, keys::kAuthorityEnvelopeMax> plain{};
    std::size_t plain_size = 0;
    keys::AuthorityEnvelopeHeader header{};
    // NOTE: the fake's `rx_ctx` is what the DEVICE stamps (it chose it).
    if (!sdkv1::authority_open(*aead, rx, bytes, rx_ctx,
                               MutableByteView{plain.data(), plain.size()}, plain_size,
                               header)) {
      return replies;
    }
    const ByteView body{plain.data(), plain_size};
    if (header.type == keys::AuthorityEnvelopeType::JoinConfirm) {
      sdkv1::JoinConfirmUp up{};
      if (!sdkv1::decode_join_confirm_up(body, up)) return replies;
      sdkv1::JoinConfirmDown down{};
      down.head.op = 2;
      down.head.generation = env.generation;
      down.head.request_id = next_request++;
      down.confirmed_generation = up.head.generation;
      down.authority_active = 10;
      replies.push_back(seal(keys::AuthorityEnvelopeType::JoinConfirm, down));
    } else if (header.type == keys::AuthorityEnvelopeType::GroupKeyPull) {
      sdkv1::GroupKeyPull pull{};
      if (!sdkv1::decode_group_key_pull(body, pull)) return replies;
      sdkv1::GroupKeyUpdate update{};
      update.head.op = 1;
      update.head.generation = env.generation;
      update.head.request_id = next_request++;
      update.g = 11;
      update.cause = sdkv1::UpdateCause::Periodic;
      update.overlap_s = 60;
      update.gk = secret(0xA0);
      replies.push_back(seal(keys::AuthorityEnvelopeType::GroupKeyUpdate, update));
      ++updates_sent;
    } else if (header.type == keys::AuthorityEnvelopeType::GroupKeyUpdate ||
               header.type == keys::AuthorityEnvelopeType::GroupKeyActivate) {
      sdkv1::GroupKeyAck ack{};
      if (!sdkv1::decode_group_key_ack(body, ack)) return replies;
      ++acks_seen;
      last_ack_result = ack.result;
      last_ack_g = ack.g;
    }
    return replies;
  }

  SentCarrier seal(keys::AuthorityEnvelopeType type, const sdkv1::JoinConfirmDown& msg) {
    std::array<std::uint8_t, sdkv1::kJoinConfirmDownSize> pt{};
    std::size_t pt_size = 0;
    CHECK(sdkv1::encode_join_confirm_down(msg, MutableByteView{pt.data(), pt.size()}, pt_size));
    return seal_bytes(type, ByteView{pt.data(), pt_size});
  }

  SentCarrier seal(keys::AuthorityEnvelopeType type, const sdkv1::GroupKeyUpdate& msg) {
    std::array<std::uint8_t, sdkv1::kGroupKeyUpdateSize> pt{};
    std::size_t pt_size = 0;
    CHECK(sdkv1::encode_group_key_update(msg, MutableByteView{pt.data(), pt.size()}, pt_size));
    return seal_bytes(type, ByteView{pt.data(), pt_size});
  }

  SentCarrier seal_bytes(keys::AuthorityEnvelopeType type, ByteView plaintext) {
    std::array<std::uint8_t, keys::kAuthorityEnvelopeMax> envelope{};
    std::size_t written = 0;
    CHECK(sdkv1::authority_seal(*aead, tx, type, tx_ctx, tx_counter_++, plaintext,
                                MutableByteView{envelope.data(), envelope.size()},
                                written));
    SentCarrier out{};
    out.kind = sdkv1::AuthorityCarrierKind::Envelope;
    out.bytes.assign(envelope.data(), envelope.data() + written);
    return out;
  }

  std::uint64_t tx_counter_{0};
};

// Pumps carriers between a client and its fake authority until both sides
// are quiet (bounded iterations; returns false on timeout).
bool pump(sdkv1::AuthorityClient& client, FakePort& port, FakeAuthority& fake, MonotonicMs now) {
  for (int round = 0; round < 16; ++round) {
    bool moved = false;
    std::vector<SentCarrier> pending = std::move(port.sent);
    port.sent.clear();
    for (const auto& sent : pending) {
      moved = true;
      for (auto& reply :
           fake.on_carrier(sent.kind, ByteView{sent.bytes.data(), sent.bytes.size()}, now)) {
        sdkv1::AuthorityInput in{};
        in.kind = sdkv1::AuthorityInputKind::RxCarrier;
        in.rx.kind = reply.kind;
        in.rx.bytes = ByteView{reply.bytes.data(), reply.bytes.size()};
        if (!client.advance(in, now)) return false;
        moved = true;
      }
    }
    sdkv1::AuthorityInput tick{};
    tick.kind = sdkv1::AuthorityInputKind::Tick;
    if (!client.advance(tick, now)) return false;
    if (!moved && port.sent.empty()) return true;
  }
  return port.sent.empty();
}

sdkv1::AuthorityStart bound_start(const sdkv1::SiteRecord& site) {
  sdkv1::AuthorityStart start{};
  start.network = site.network;
  start.self = 0x101;
  start.gateway = site.gateways[0];
  start.site_id = site.site_id;
  start.dams = site.dams;
  start.generation = site.assignment_generation;
  start.epochs.site_epoch = static_cast<std::uint32_t>(site.network >> 32);
  start.epochs.rs_epoch = site.rs_epoch_floor;
  start.epochs.gk_epoch = site.gk_epoch_current;
  start.boot = site.boot_witness;
  start.gk_current = site.gk_epoch_current;
  start.gk_next = site.gk_epoch_next;
  routeloom::sha256({site.member_cert.bytes.data(), site.member_cert.size},
                    start.member_cert_hash);
  return start;
}

void test_durable_group_ack_round_trip() {
  sdkv1_test::FaultyRecordStorage storage(sdkv1::kSiteSlotBytes);
  sdkv1::SiteStore store(storage);
  CHECK(store.initialize());
  auto site = sdkv1_test::site_record(3, 10);
  CHECK(store.commit(site));
  sdkv1::GroupKeyState group(store);
  sdkv1::GroupKeyState::Input begin{};
  begin.op = sdkv1::GroupKeyState::Op::Start;
  begin.boot = site.boot_witness;
  CHECK(group.advance(begin, 1000));

  sdkv1::AuthorityStart start = bound_start(site);
  FakePort port;
  FakeObserver observer;
  FakeEnv env;
  sdkv1::AuthorityClient client(*routeloom::builtin_aead_gcm(), port, observer, env, &group);
  FakeAuthority fake(site.dams, start);
  sdkv1::AuthorityInput input{};
  input.kind = sdkv1::AuthorityInputKind::Start;
  input.start = start;
  input.start.member_cert_hash[0] ^= 1;
  CHECK(client.advance(input, 1000).code == routeloom::StatusCode::Conflict);
  CHECK(port.sent.empty());
  input.start = start;
  CHECK(client.advance(input, 1000));
  CHECK(pump(client, port, fake, 1000));
  input = {};
  input.kind = sdkv1::AuthorityInputKind::RequestPull;
  CHECK(client.advance(input, 1000));
  CHECK(pump(client, port, fake, 1000));
  CHECK(fake.last_ack_result == sdkv1::UpdateResult::Durable);
  CHECK(store.site().gk_epoch_next == 11);
  CHECK(store.site().gk_next == secret(0xA0));
  const auto writes = storage.write_calls;
  sdkv1::GroupKeyUpdate update{};
  update.head = {1, site.assignment_generation, 40};
  update.g = 11;
  update.gk = secret(0xA0);
  update.overlap_s = 60;
  auto sent = fake.seal(keys::AuthorityEnvelopeType::GroupKeyUpdate, update);
  input = {};
  input.kind = sdkv1::AuthorityInputKind::RxCarrier;
  input.rx = {sent.kind, ByteView{sent.bytes.data(), sent.bytes.size()}};
  CHECK(client.advance(input, 1001));
  CHECK(pump(client, port, fake, 1001));
  CHECK(storage.write_calls == writes);
  CHECK(fake.last_ack_result == sdkv1::UpdateResult::Durable);

  sdkv1::GroupKeyActivate activation{};
  activation.head = {1, site.assignment_generation, 41};
  activation.g = 11;
  activation.overlap_s = 60;
  sdkv1::authority_gk_id(site.network, 11, update.gk, activation.gk_id);
  std::array<std::uint8_t, sdkv1::kGroupKeyActivateSize> bytes{};
  std::size_t length = 0;
  CHECK(sdkv1::encode_group_key_activate(activation, {bytes.data(), bytes.size()}, length));
  auto wrong = activation;
  wrong.head.request_id = 42;
  wrong.gk_id[0] ^= 1;
  CHECK(sdkv1::encode_group_key_activate(wrong, {bytes.data(), bytes.size()}, length));
  sent = fake.seal_bytes(keys::AuthorityEnvelopeType::GroupKeyActivate, {bytes.data(), length});
  input.rx = {sent.kind, {sent.bytes.data(), sent.bytes.size()}};
  CHECK(client.advance(input, 1002));
  CHECK(pump(client, port, fake, 1002));
  CHECK(fake.last_ack_result == sdkv1::UpdateResult::Conflict);
  CHECK(storage.write_calls == writes);
  CHECK(store.site().gk_epoch_current == 10);
  CHECK(sdkv1::encode_group_key_activate(activation, {bytes.data(), bytes.size()}, length));
  sent = fake.seal_bytes(keys::AuthorityEnvelopeType::GroupKeyActivate, {bytes.data(), length});
  input.rx = {sent.kind, {sent.bytes.data(), sent.bytes.size()}};
  CHECK(client.advance(input, 1002));
  CHECK(pump(client, port, fake, 1002));
  CHECK(fake.last_ack_result == sdkv1::UpdateResult::Durable);
  CHECK(store.site().gk_epoch_current == 11);
  CHECK(store.site().gk_epoch_next == 0);
  sdkv1::SiteStore reboot(storage);
  CHECK(reboot.initialize());
  CHECK(!reboot.group_scrub_needed());
  CHECK(reboot.site().gk_epoch_current == 11);

  // A failed twin promotion can have written its first slot: no durable ACK,
  // no fallback to the old transmitting key, and cold boot must scrub.
  update.head.request_id = 43;
  update.g = 12;
  update.gk = secret(0xB0);
  sent = fake.seal(keys::AuthorityEnvelopeType::GroupKeyUpdate, update);
  input.rx = {sent.kind, {sent.bytes.data(), sent.bytes.size()}};
  CHECK(client.advance(input, 1003));
  CHECK(pump(client, port, fake, 1003));
  CHECK(fake.last_ack_result == sdkv1::UpdateResult::Durable);
  activation.head.request_id = 44;
  activation.g = 12;
  sdkv1::authority_gk_id(site.network, 12, update.gk, activation.gk_id);
  CHECK(sdkv1::encode_group_key_activate(activation, {bytes.data(), bytes.size()}, length));
  sent = fake.seal_bytes(keys::AuthorityEnvelopeType::GroupKeyActivate, {bytes.data(), length});
  storage.cut_call = storage.write_calls + 2;  // first slot sealed, sibling not yet scrubbed
  storage.cut_bytes = 0;
  input.rx = {sent.kind, {sent.bytes.data(), sent.bytes.size()}};
  CHECK(client.advance(input, 1004));
  storage.disarm();
  CHECK(pump(client, port, fake, 1004));
  CHECK(fake.last_ack_result == sdkv1::UpdateResult::StorageFailure);
  CHECK(!group.ready());
  update.head.request_id = 45;
  update.g = 13;
  update.gk = secret(0xC0);
  sent = fake.seal(keys::AuthorityEnvelopeType::GroupKeyUpdate, update);
  input.rx = {sent.kind, {sent.bytes.data(), sent.bytes.size()}};
  CHECK(client.advance(input, 1005));
  CHECK(pump(client, port, fake, 1005));
  CHECK(fake.last_ack_result == sdkv1::UpdateResult::StorageFailure);
  sdkv1::SiteStore after_cut(storage);
  CHECK(after_cut.initialize());
  sdkv1::GroupKeyState recovery(after_cut);
  CHECK(recovery.advance(begin, 1005));
  CHECK(recovery.current() == 12);
  CHECK(!after_cut.group_scrub_needed());
}

void test_bound_channel_fences_changed_site() {
  const auto* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  for (const bool during_handshake : {true, false}) {
    sdkv1_test::FaultyRecordStorage storage(sdkv1::kSiteSlotBytes);
    sdkv1::SiteStore store(storage);
    CHECK(store.initialize());
    const auto site = sdkv1_test::site_record(3, 10);
    CHECK(store.commit(site));
    sdkv1::GroupKeyState group(store);
    sdkv1::GroupKeyState::Input begin{};
    begin.op = sdkv1::GroupKeyState::Op::Start;
    begin.boot = site.boot_witness;
    CHECK(group.advance(begin, 1000));
    const auto start = bound_start(site);
    FakePort port;
    FakeObserver observer;
    FakeEnv env;
    sdkv1::AuthorityClient client(*aead, port, observer, env, &group);
    FakeAuthority fake(site.dams, start);
    sdkv1::AuthorityInput input{};
    input.kind = sdkv1::AuthorityInputKind::Start;
    input.start = start;
    CHECK(client.advance(input, 1000));
    if (during_handshake) {
      CHECK(port.sent.size() == 1);
      if (port.sent.size() != 1) continue;
      const auto r2 = fake.on_carrier(port.sent[0].kind,
                                      {port.sent[0].bytes.data(), port.sent[0].bytes.size()},
                                      1000);
      CHECK(r2.size() == 1);
      if (r2.size() != 1) continue;
      port.sent.clear();
      CHECK(store.clear());
      input = {};
      input.kind = sdkv1::AuthorityInputKind::RxCarrier;
      input.rx = {sdkv1::AuthorityCarrierKind::R2,
                  {r2[0].bytes.data(), r2[0].bytes.size()}};
      CHECK(client.advance(input, 1001).code == routeloom::StatusCode::Conflict);
      CHECK(port.sent.empty());
    } else {
      CHECK(pump(client, port, fake, 1000));
      sdkv1::SiteRecord newer = store.site();
      ++newer.boot_witness;
      CHECK(store.commit(newer));
      CHECK(!group.tx_ready());
      input = {};
      input.kind = sdkv1::AuthorityInputKind::RequestPull;
      CHECK(client.advance(input, 1001).code == routeloom::StatusCode::Conflict);
      CHECK(port.sent.empty());
    }
  }
}

void test_round_trip() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  FakePort port;
  FakeObserver observer;
  FakeEnv env;
  sdkv1::AuthorityClient client(*aead, port, observer, env);
  FakeAuthority fake(secret(0xD0));
  MonotonicMs now = 1000;

  sdkv1::AuthorityInput start{};
  start.kind = sdkv1::AuthorityInputKind::Start;
  start.start = make_start();
  CHECK(client.advance(start, now));
  CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Connecting);
  CHECK(port.sent.size() == 1);
  CHECK(port.sent[0].kind == sdkv1::AuthorityCarrierKind::R1);
  CHECK(client.next_deadline() == now + 5000);

  CHECK(pump(client, port, fake, now));
  CHECK(fake.ready);
  CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Ready);
  CHECK(client.snapshot().tx_ctx != 0 && client.snapshot().rx_ctx != 0);
  // R3 went out, the JoinConfirm followed, its ACK came back.
  CHECK(client.snapshot().join_confirmed);
  bool saw_ready = false;
  bool saw_ack = false;
  for (const auto& e : observer.seen) {
    if (e.kind == sdkv1::AuthorityEvent::Kind::ChannelReady) saw_ready = true;
    if (e.kind == sdkv1::AuthorityEvent::Kind::JoinConfirmAck) saw_ack = true;
  }
  CHECK(saw_ready && saw_ack);
  CHECK(port.sent.empty());

  // A Pull round-trips into an Update; PR1 answers unsupported honestly.
  sdkv1::AuthorityInput pull{};
  pull.kind = sdkv1::AuthorityInputKind::RequestPull;
  pull.pull.reason = sdkv1::PullReason::BootReconnectSync;
  CHECK(client.advance(pull, now));
  CHECK(pump(client, port, fake, now));
  CHECK(fake.updates_sent == 1);
  CHECK(fake.acks_seen == 1);
  CHECK(fake.last_ack_result == sdkv1::UpdateResult::Unsupported);
  CHECK(fake.last_ack_g == 11);
  bool saw_update = false;
  for (const auto& e : observer.seen) {
    if (e.kind == sdkv1::AuthorityEvent::Kind::UpdateReceived && e.g == 11) saw_update = true;
  }
  CHECK(saw_update);
  // Request ids advanced monotonically: JoinConfirm(1) + Pull(2) + ACK(3).
  CHECK(client.snapshot().next_request_id == 4);
}

void test_reentry() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  // Nested advance() from the port during R1 send: Busy, outer unaffected.
  {
    FakePort port;
    FakeObserver observer;
    FakeEnv env;
    sdkv1::AuthorityClient client(*aead, port, observer, env);
    port.reenter = &client;
    sdkv1::AuthorityInput start{};
    start.kind = sdkv1::AuthorityInputKind::Start;
    start.start = make_start();
    CHECK(client.advance(start, 1000));
    CHECK(port.reenter_result == routeloom::StatusCode::Busy);
    CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Connecting);
    CHECK(port.sent.size() == 1);  // no recursive duplicate send
  }
  // Nested advance() from entropy during Start: Busy, R1 still staged.
  {
    FakePort port;
    FakeObserver observer;
    FakeEnv env;
    sdkv1::AuthorityClient client(*aead, port, observer, env);
    env.reenter = &client;
    sdkv1::AuthorityInput start{};
    start.kind = sdkv1::AuthorityInputKind::Start;
    start.start = make_start();
    CHECK(client.advance(start, 1000));
    CHECK(env.reenter_result == routeloom::StatusCode::Busy);
    CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Connecting);
  }
  // Nested advance() from the observer during UpdateReceived: Busy, and the
  // outer call's effect is identical to the undisturbed run.
  auto run_update = [&](bool disturb) {
    FakePort port;
    FakeObserver observer;
    FakeEnv env;
    sdkv1::AuthorityClient client(*aead, port, observer, env);
    FakeAuthority fake(secret(0xD0));
    sdkv1::AuthorityInput start{};
    start.kind = sdkv1::AuthorityInputKind::Start;
    start.start = make_start();
    CHECK(client.advance(start, 1000));
    CHECK(pump(client, port, fake, 1000));
    if (disturb) observer.reenter = &client;
    sdkv1::AuthorityInput pull{};
    pull.kind = sdkv1::AuthorityInputKind::RequestPull;
    CHECK(client.advance(pull, 1000));
    CHECK(pump(client, port, fake, 1000));
    return std::make_pair(client.snapshot(), observer.reenter_result);
  };
  const auto calm = run_update(false);
  const auto disturbed = run_update(true);
  CHECK(disturbed.second == routeloom::StatusCode::Busy);
  const sdkv1::AuthoritySnapshot& a = calm.first;
  const sdkv1::AuthoritySnapshot& b = disturbed.first;
  CHECK(a.state == b.state && a.tx_counter == b.tx_counter &&
        a.next_request_id == b.next_request_id && a.tx_sent == b.tx_sent &&
        a.rx_accepted == b.rx_accepted && a.rx_rejected == b.rx_rejected);
}

void test_timeouts_and_backoff() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  // No R2: the handshake times out into Backoff, then re-handshakes.
  {
    FakePort port;
    FakeObserver observer;
    FakeEnv env;
    sdkv1::AuthorityClient client(*aead, port, observer, env);
    sdkv1::AuthorityInput start{};
    start.kind = sdkv1::AuthorityInputKind::Start;
    start.start = make_start();
    CHECK(client.advance(start, 1000));
    sdkv1::AuthorityInput tick{};
    tick.kind = sdkv1::AuthorityInputKind::Tick;
    CHECK(client.advance(tick, 1000 + 5000));
    CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Backoff);
    CHECK(client.snapshot().backoff_s == 1);
    CHECK(!client.quiescent());
    CHECK(client.next_deadline() > 6000 && client.next_deadline() <= 6000 + 1000 + 250);
    port.sent.clear();
    CHECK(client.advance(tick, client.next_deadline()));
    CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Connecting);
    CHECK(port.sent.size() == 1);  // fresh R1
  }
  // A bad R2 backs off immediately.
  {
    FakePort port;
    FakeObserver observer;
    FakeEnv env;
    sdkv1::AuthorityClient client(*aead, port, observer, env);
    sdkv1::AuthorityInput start{};
    start.kind = sdkv1::AuthorityInputKind::Start;
    start.start = make_start();
    CHECK(client.advance(start, 1000));
    sdkv1::AuthorityInput rx{};
    rx.kind = sdkv1::AuthorityInputKind::RxCarrier;
    rx.rx.kind = sdkv1::AuthorityCarrierKind::R2;
    const std::array<std::uint8_t, 52> garbage{};
    rx.rx.bytes = ByteView{garbage.data(), garbage.size()};
    CHECK(client.advance(rx, 1000));
    CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Backoff);
  }
  // R3 sent but JoinConfirm never ACKed: the half-open channel retires.
  {
    FakePort port;
    FakeObserver observer;
    FakeEnv env;
    sdkv1::AuthorityClient client(*aead, port, observer, env);
    FakeAuthority fake(secret(0xD0));
    sdkv1::AuthorityInput start{};
    start.kind = sdkv1::AuthorityInputKind::Start;
    start.start = make_start();
    CHECK(client.advance(start, 1000));
    // Pump only the handshake: deliver R2, swallow the JoinConfirm reply.
    std::vector<SentCarrier> pending = std::move(port.sent);
    port.sent.clear();
    for (const auto& sent : pending) {
      for (auto& reply :
           fake.on_carrier(sent.kind, ByteView{sent.bytes.data(), sent.bytes.size()}, 1000)) {
        if (reply.kind == sdkv1::AuthorityCarrierKind::R2) {
          sdkv1::AuthorityInput in{};
          in.kind = sdkv1::AuthorityInputKind::RxCarrier;
          in.rx.kind = reply.kind;
          in.rx.bytes = ByteView{reply.bytes.data(), reply.bytes.size()};
          CHECK(client.advance(in, 1000));
        }
      }
    }
    CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Ready);
    port.sent.clear();  // the JoinConfirm leaves; no ACK ever returns
    sdkv1::AuthorityInput tick{};
    tick.kind = sdkv1::AuthorityInputKind::Tick;
    CHECK(client.advance(tick, 1000 + 15000));
    CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Backoff);
  }
  // Ten idle minutes retire an idle channel; a Wake re-opens it.
  {
    FakePort port;
    FakeObserver observer;
    FakeEnv env;
    sdkv1::AuthorityClient client(*aead, port, observer, env);
    FakeAuthority fake(secret(0xD0));
    sdkv1::AuthorityInput start{};
    start.kind = sdkv1::AuthorityInputKind::Start;
    start.start = make_start();
    CHECK(client.advance(start, 1000));
    CHECK(pump(client, port, fake, 1000));
    CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Ready);
    sdkv1::AuthorityInput tick{};
    tick.kind = sdkv1::AuthorityInputKind::Tick;
    CHECK(client.advance(tick, 1000 + 600000));
    CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Dormant);
    CHECK(client.snapshot().started);  // armed: the DAMS survived
    CHECK(client.quiescent());
    CHECK(client.next_deadline() == UINT64_MAX);
    bool saw_idle = false;
    for (const auto& e : observer.seen) {
      if (e.kind == sdkv1::AuthorityEvent::Kind::ChannelLost && e.reason == "IDLE") {
        saw_idle = true;
      }
    }
    CHECK(saw_idle);
    sdkv1::AuthorityInput wake{};
    wake.kind = sdkv1::AuthorityInputKind::RxCarrier;
    wake.rx.kind = sdkv1::AuthorityCarrierKind::Wake;
    const std::array<std::uint8_t, 8> hint{};
    wake.rx.bytes = ByteView{hint.data(), hint.size()};
    CHECK(client.advance(wake, 1000 + 600000));
    CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Connecting);
    CHECK(pump(client, port, fake, 1000 + 600000));
    CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Ready);
    CHECK(client.snapshot().next_request_id == 2);  // new channel starts at one
  }
  // Pulls coalesce to one per 60 s device-wide.
  {
    FakePort port;
    FakeObserver observer;
    FakeEnv env;
    sdkv1::AuthorityClient client(*aead, port, observer, env);
    FakeAuthority fake(secret(0xD0));
    sdkv1::AuthorityInput start{};
    start.kind = sdkv1::AuthorityInputKind::Start;
    start.start = make_start();
    CHECK(client.advance(start, 1000));
    CHECK(pump(client, port, fake, 1000));
    sdkv1::AuthorityInput pull{};
    pull.kind = sdkv1::AuthorityInputKind::RequestPull;
    CHECK(client.advance(pull, 2000));
    CHECK(client.advance(pull, 2001));  // coalesced, not sent
    int pulls = 0;
    for (const auto& sent : port.sent) {
      if (sent.kind == sdkv1::AuthorityCarrierKind::Envelope) ++pulls;
    }
    CHECK(pulls == 1);
    CHECK(client.snapshot().pull_pending);
    CHECK(pump(client, port, fake, 2001));
    CHECK(client.snapshot().pull_pending);  // still waiting for the bucket
    sdkv1::AuthorityInput tick{};
    tick.kind = sdkv1::AuthorityInputKind::Tick;
    CHECK(client.advance(tick, 2000 + 60000));
    CHECK(!client.snapshot().pull_pending);
  }
}

void test_rx_attacks() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  FakePort port;
  FakeObserver observer;
  FakeEnv env;
  sdkv1::AuthorityClient client(*aead, port, observer, env);
  FakeAuthority fake(secret(0xD0));
  sdkv1::AuthorityInput start{};
  start.kind = sdkv1::AuthorityInputKind::Start;
  start.start = make_start();
  CHECK(client.advance(start, 1000));
  CHECK(pump(client, port, fake, 1000));
  const std::uint64_t accepted = client.snapshot().rx_accepted;

  auto feed = [&](const Bytes& envelope) {
    sdkv1::AuthorityInput in{};
    in.kind = sdkv1::AuthorityInputKind::RxCarrier;
    in.rx.kind = sdkv1::AuthorityCarrierKind::Envelope;
    in.rx.bytes = ByteView{envelope.data(), envelope.size()};
    CHECK(client.advance(in, 1000));
  };
  auto sealed_pull = [&]() {
    sdkv1::GroupKeyPull pull{};
    pull.head.op = 1;
    pull.head.generation = kGeneration;
    pull.head.request_id = 0xABC;
    pull.current = 10;
    pull.reason = sdkv1::PullReason::BootReconnectSync;
    std::array<std::uint8_t, sdkv1::kGroupKeyPullSize> pt{};
    std::size_t pt_size = 0;
    CHECK(sdkv1::encode_group_key_pull(pull, MutableByteView{pt.data(), pt.size()}, pt_size));
    return fake.seal_bytes(keys::AuthorityEnvelopeType::GroupKeyPull,
                           ByteView{pt.data(), pt_size});
  };
  // A wrong-direction Pull addressed to the device: rejected, no state moved.
  feed(sealed_pull().bytes);
  CHECK(client.snapshot().rx_accepted == accepted);
  CHECK(port.sent.empty());
  // An Update with an undefined cause: rejected before any ACK.
  {
    sdkv1::GroupKeyUpdate update{};
    update.head.op = 1;
    update.head.generation = kGeneration;
    update.head.request_id = 0xDEF;
    update.g = 11;
    update.cause = sdkv1::UpdateCause::Periodic;
    update.overlap_s = 60;
    update.gk = secret(0xA0);
    std::array<std::uint8_t, sdkv1::kGroupKeyUpdateSize> pt{};
    std::size_t pt_size = 0;
    CHECK(sdkv1::encode_group_key_update(update, MutableByteView{pt.data(), pt.size()},
                                         pt_size));
    pt[20] = 9;  // cause 9 under a valid tag
    feed(fake.seal_bytes(keys::AuthorityEnvelopeType::GroupKeyUpdate,
                         ByteView{pt.data(), pt_size})
             .bytes);
    CHECK(client.snapshot().rx_accepted == accepted);
    CHECK(port.sent.empty());
  }
  // A flipped ciphertext bit fails authentication and leaves the replay
  // window unmoved: the intact envelope still opens afterwards.
  SentCarrier good_update{};
  {
    sdkv1::AuthorityInput pull{};
    pull.kind = sdkv1::AuthorityInputKind::RequestPull;
    CHECK(client.advance(pull, 1000));
    for (const auto& sent : port.sent) {
      for (auto& reply :
           fake.on_carrier(sent.kind, ByteView{sent.bytes.data(), sent.bytes.size()}, 1000)) {
        if (reply.kind == sdkv1::AuthorityCarrierKind::Envelope) good_update = reply;
      }
    }
    port.sent.clear();
    CHECK(!good_update.bytes.empty());
  }
  Bytes tampered = good_update.bytes;
  tampered[20] ^= 0x01;
  feed(tampered);
  CHECK(client.snapshot().rx_accepted == accepted);
  feed(good_update.bytes);
  CHECK(client.snapshot().rx_accepted == accepted + 1);
  CHECK(port.sent.size() == 1);  // the unsupported ACK went out
  port.sent.clear();
  // The same bytes again: a replay, rejected without a second ACK.
  feed(good_update.bytes);
  CHECK(client.snapshot().rx_accepted == accepted + 1);
  CHECK(port.sent.empty());
  // Right tag, wrong context id: rejected (proves the ctx binding matters).
  {
    std::array<std::uint8_t, keys::kAuthorityEnvelopeMax> plain{};
    std::size_t plain_size = 0;
    keys::AuthorityEnvelopeHeader header{};
    CHECK(sdkv1::authority_open(*aead, fake.tx,
                                ByteView{good_update.bytes.data(), good_update.bytes.size()},
                                fake.tx_ctx, MutableByteView{plain.data(), plain.size()},
                                plain_size, header));
    std::array<std::uint8_t, keys::kAuthorityEnvelopeMax> wrong_ctx{};
    std::size_t wrong_size = 0;
    CHECK(sdkv1::authority_seal(*aead, fake.tx, header.type, 0xDEADu, 4242,
                                ByteView{plain.data(), plain_size},
                                MutableByteView{wrong_ctx.data(), wrong_ctx.size()},
                                wrong_size));
    feed(Bytes(wrong_ctx.data(), wrong_ctx.data() + wrong_size));
    CHECK(client.snapshot().rx_accepted == accepted + 1);
  }
  // Truncated and oversized carriers: rejected without touching the window.
  feed(Bytes(good_update.bytes.begin(), good_update.bytes.begin() + 20));
  CHECK(client.snapshot().rx_accepted == accepted + 1);
  feed(Bytes(keys::kAuthorityEnvelopeMax + 1, 0x00));
  CHECK(client.snapshot().rx_accepted == accepted + 1);
  // An Activate round-trips into a type-3 unsupported ACK.
  {
    sdkv1::GroupKeyActivate activate{};
    activate.head.op = 1;
    activate.head.generation = kGeneration;
    activate.head.request_id = 0xA1;
    activate.g = 11;
    sdkv1::authority_gk_id(kNetwork, 11, secret(0xA0), activate.gk_id);
    activate.cause = sdkv1::UpdateCause::Periodic;
    activate.overlap_s = 60;
    std::array<std::uint8_t, sdkv1::kGroupKeyActivateSize> pt{};
    std::size_t pt_size = 0;
    CHECK(sdkv1::encode_group_key_activate(activate, MutableByteView{pt.data(), pt.size()},
                                           pt_size));
    feed(fake.seal_bytes(keys::AuthorityEnvelopeType::GroupKeyActivate,
                         ByteView{pt.data(), pt_size})
             .bytes);
    CHECK(port.sent.size() == 1);
    std::array<std::uint8_t, keys::kAuthorityEnvelopeMax> ack_plain{};
    std::size_t ack_size = 0;
    keys::AuthorityEnvelopeHeader ack_header{};
    CHECK(sdkv1::authority_open(*aead, fake.rx,
                                ByteView{port.sent[0].bytes.data(), port.sent[0].bytes.size()},
                                fake.rx_ctx, MutableByteView{ack_plain.data(), ack_plain.size()},
                                ack_size, ack_header));
    CHECK(ack_header.type == keys::AuthorityEnvelopeType::GroupKeyActivate);
    sdkv1::GroupKeyAck ack{};
    CHECK(sdkv1::decode_group_key_ack(ByteView{ack_plain.data(), ack_size}, ack));
    CHECK(ack.result == sdkv1::UpdateResult::Unsupported);
    CHECK(ack.g == 11);
    port.sent.clear();
  }
  // Types 5..8 pass verified plaintext to the P6 sink; a bad head does not.
  {
    std::array<std::uint8_t, 20> pt{};
    sdkv1::AuthorityBodyHead head{};
    head.op = 1;
    head.generation = kGeneration;
    head.request_id = 0x55;
    std::size_t head_size = 0;
    CHECK(sdkv1::authority_head_encode(head, MutableByteView{pt.data(), pt.size()}, head_size));
    CHECK(head_size == sdkv1::kAuthorityBodyHeadSize);
    pt[16] = 0xDE;
    pt[17] = 0xAD;
    pt[18] = 0xBE;
    pt[19] = 0xEF;
    const std::size_t before = observer.seen.size();
    feed(fake.seal_bytes(keys::AuthorityEnvelopeType::RemovalNotice,
                         ByteView{pt.data(), pt.size()})
             .bytes);
    CHECK(observer.seen.size() == before + 1);
    const auto& event = observer.seen.back();
    CHECK(event.kind == sdkv1::AuthorityEvent::Kind::Passthrough);
    CHECK(event.type == 6);
    CHECK(event.passthrough.size() == pt.size() &&
          std::memcmp(event.passthrough.data(), pt.data(), pt.size()) == 0);
    pt[0] = 2;  // bad body version under a valid tag
    feed(fake.seal_bytes(keys::AuthorityEnvelopeType::RemovalNotice,
                         ByteView{pt.data(), pt.size()})
             .bytes);
    CHECK(observer.seen.size() == before + 1);
  }
}

void test_port_full_and_tx_result() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  FakePort port;
  FakeObserver observer;
  FakeEnv env;
  sdkv1::AuthorityClient client(*aead, port, observer, env);
  port.full = true;
  sdkv1::AuthorityInput start{};
  start.kind = sdkv1::AuthorityInputKind::Start;
  start.start = make_start();
  CHECK(client.advance(start, 1000));
  CHECK(port.sent.empty());  // R1 staged, not lost
  CHECK(client.snapshot().tx_sent == 0);
  port.full = false;
  sdkv1::AuthorityInput tick{};
  tick.kind = sdkv1::AuthorityInputKind::Tick;
  CHECK(client.advance(tick, 1000));
  CHECK(port.sent.size() == 1);
  CHECK(client.snapshot().tx_sent == 1);
  // A stale token is ignored; a failed delivery is counted, not fatal.
  sdkv1::AuthorityInput result{};
  result.kind = sdkv1::AuthorityInputKind::TxResult;
  result.tx.token = port.sent[0].token + 100;
  result.tx.delivered = false;
  CHECK(client.advance(result, 1000));
  CHECK(client.snapshot().tx_failed == 0);
  result.tx.token = port.sent[0].token;
  CHECK(client.advance(result, 1000));
  CHECK(client.snapshot().tx_failed == 1);
  CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Connecting);
}

void test_staged_confirm_and_one_pending_ack() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  FakePort port;
  FakeObserver observer;
  FakeEnv env;
  sdkv1::AuthorityClient client(*aead, port, observer, env);
  FakeAuthority fake(secret(0xD0));
  sdkv1::AuthorityInput start{};
  start.kind = sdkv1::AuthorityInputKind::Start;
  start.start = make_start();
  CHECK(client.advance(start, 1000));
  CHECK(port.sent.size() == 1);
  if (port.sent.empty()) return;
  const auto r2 = fake.on_carrier(port.sent[0].kind,
                                  ByteView{port.sent[0].bytes.data(), port.sent[0].bytes.size()},
                                  1000);
  CHECK(r2.size() == 1);
  if (r2.empty()) return;
  port.sent.clear();
  port.block_envelopes = true;
  sdkv1::AuthorityInput rx{};
  rx.kind = sdkv1::AuthorityInputKind::RxCarrier;
  rx.rx.kind = sdkv1::AuthorityCarrierKind::R2;
  rx.rx.bytes = ByteView{r2[0].bytes.data(), r2[0].bytes.size()};
  CHECK(client.advance(rx, 1000));
  CHECK(port.sent.size() == 1);  // R3 left, JoinConfirm is still staged.
  if (port.sent.empty()) return;
  (void)fake.on_carrier(port.sent[0].kind,
                        ByteView{port.sent[0].bytes.data(), port.sent[0].bytes.size()}, 1000);
  CHECK(fake.ready);
  port.sent.clear();

  Bytes large_plain(keys::kAuthorityEnvelopeMax - keys::kAuthorityEnvelopeMin, 0xA5);
  sdkv1::AuthorityBodyHead large_head{};
  large_head.op = 1;
  large_head.generation = kGeneration;
  large_head.request_id = 0x55;
  std::size_t large_head_size = 0;
  CHECK(sdkv1::authority_head_encode(
      large_head, MutableByteView{large_plain.data(), large_plain.size()}, large_head_size));
  auto large = fake.seal_bytes(keys::AuthorityEnvelopeType::RemovalNotice,
                               ByteView{large_plain.data(), large_plain.size()});
  CHECK(large.bytes.size() == keys::kAuthorityEnvelopeMax);
  rx.rx.kind = sdkv1::AuthorityCarrierKind::Envelope;
  rx.rx.bytes = ByteView{large.bytes.data(), large.bytes.size()};
  rx.rx.writable = MutableByteView{large.bytes.data(), large.bytes.size()};
  CHECK(client.advance(rx, 1001));
  CHECK(!observer.seen.empty() &&
        observer.seen.back().kind == sdkv1::AuthorityEvent::Kind::Passthrough);
  CHECK(port.sent.empty());  // stalled JoinConfirm remains byte-for-byte intact
  CHECK(std::all_of(large.bytes.begin(), large.bytes.end(),
                    [](std::uint8_t byte) { return byte == 0; }));
  rx.rx.writable = {};

  auto make_update = [&](std::uint32_t g) {
    sdkv1::GroupKeyUpdate update{};
    update.head.op = 1;
    update.head.generation = kGeneration;
    update.head.request_id = fake.next_request++;
    update.g = g;
    update.cause = sdkv1::UpdateCause::Periodic;
    update.overlap_s = 60;
    update.gk = secret(static_cast<std::uint8_t>(g));
    return fake.seal(keys::AuthorityEnvelopeType::GroupKeyUpdate, update);
  };
  const SentCarrier first = make_update(11);
  rx.rx.kind = sdkv1::AuthorityCarrierKind::Envelope;
  rx.rx.bytes = ByteView{first.bytes.data(), first.bytes.size()};
  CHECK(client.advance(rx, 1001));
  CHECK(client.snapshot().tx_counter == 1);  // only staged JoinConfirm was sealed
  const SentCarrier second = make_update(12);
  rx.rx.bytes = ByteView{second.bytes.data(), second.bytes.size()};
  CHECK(client.advance(rx, 1002));
  CHECK(client.snapshot().tx_counter == 1);  // second update waits for capacity

  port.block_envelopes = false;
  sdkv1::AuthorityInput tick{};
  tick.kind = sdkv1::AuthorityInputKind::Tick;
  CHECK(client.advance(tick, 1003));
  CHECK(client.advance(tick, 1004));
  CHECK(port.sent.size() == 2);
  for (const auto& sent : port.sent) {
    (void)fake.on_carrier(sent.kind, ByteView{sent.bytes.data(), sent.bytes.size()}, 1004);
  }
  CHECK(fake.acks_seen == 1);
  CHECK(fake.last_ack_g == 11);
  port.sent.clear();
  rx.rx.bytes = ByteView{second.bytes.data(), second.bytes.size()};
  CHECK(client.advance(rx, 1005));
  for (const auto& sent : port.sent) {
    (void)fake.on_carrier(sent.kind, ByteView{sent.bytes.data(), sent.bytes.size()}, 1005);
  }
  CHECK(fake.acks_seen == 2);
  CHECK(fake.last_ack_g == 12);
}

void test_pull_bucket_at_zero() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  FakePort port;
  FakeObserver observer;
  FakeEnv env;
  sdkv1::AuthorityClient client(*aead, port, observer, env);
  FakeAuthority fake(secret(0xD0));
  sdkv1::AuthorityInput start{};
  start.kind = sdkv1::AuthorityInputKind::Start;
  start.start = make_start();
  CHECK(client.advance(start, 0));
  CHECK(pump(client, port, fake, 0));
  sdkv1::AuthorityInput pull{};
  pull.kind = sdkv1::AuthorityInputKind::RequestPull;
  CHECK(client.advance(pull, 0));
  CHECK(client.advance(pull, 1));
  CHECK(port.sent.size() == 1);
  CHECK(client.snapshot().pull_pending);
}

void test_unknown_body_op_is_refused() {
  sdkv1::AuthorityBodyHead head{};
  head.op = 3;
  head.generation = kGeneration;
  head.request_id = 1;
  std::array<std::uint8_t, sdkv1::kAuthorityBodyHeadSize> bytes{};
  std::size_t written = 0;
  CHECK(!sdkv1::authority_head_encode(head, MutableByteView{bytes.data(), bytes.size()},
                                      written));
  head.op = 1;
  CHECK(sdkv1::authority_head_encode(head, MutableByteView{bytes.data(), bytes.size()},
                                     written));
  bytes[1] = 3;
  CHECK(!sdkv1::authority_head_decode(ByteView{bytes.data(), bytes.size()}, head));
}

void test_durable_ack_requires_stored_key() {
  sdkv1::GroupKeyAck ack{};
  ack.head.op = 2;
  ack.head.generation = kGeneration;
  ack.head.request_id = 1;
  ack.g = 12;
  ack.gk_id.fill(0xA5);
  ack.result = sdkv1::UpdateResult::Durable;
  ack.stored_state = sdkv1::StoredState::None;
  std::array<std::uint8_t, sdkv1::kGroupKeyAckSize> bytes{};
  std::size_t written = 0;
  CHECK(!sdkv1::encode_group_key_ack(ack, MutableByteView{bytes.data(), bytes.size()},
                                     written));
  ack.stored_state = sdkv1::StoredState::Staged;
  CHECK(sdkv1::encode_group_key_ack(ack, MutableByteView{bytes.data(), bytes.size()},
                                    written));
  bytes[53] = 0;
  CHECK(!sdkv1::decode_group_key_ack(ByteView{bytes.data(), bytes.size()}, ack));
}

void test_receiver_generation_fence() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  FakePort port;
  FakeObserver observer;
  FakeEnv env;
  sdkv1::AuthorityClient client(*aead, port, observer, env);
  FakeAuthority fake(secret(0xD0));
  sdkv1::AuthorityInput start{};
  start.kind = sdkv1::AuthorityInputKind::Start;
  start.start = make_start();
  CHECK(client.advance(start, 1000));
  CHECK(port.sent.size() == 1);
  if (port.sent.empty()) return;
  const auto r2 = fake.on_carrier(port.sent[0].kind,
                                  ByteView{port.sent[0].bytes.data(), port.sent[0].bytes.size()},
                                  1000);
  CHECK(r2.size() == 1);
  if (r2.empty()) return;
  port.sent.clear();
  sdkv1::AuthorityInput rx{};
  rx.kind = sdkv1::AuthorityInputKind::RxCarrier;
  rx.rx.kind = sdkv1::AuthorityCarrierKind::R2;
  rx.rx.bytes = ByteView{r2[0].bytes.data(), r2[0].bytes.size()};
  CHECK(client.advance(rx, 1000));
  CHECK(port.sent.size() == 2);
  if (port.sent.size() < 2) return;
  (void)fake.on_carrier(port.sent[0].kind,
                        ByteView{port.sent[0].bytes.data(), port.sent[0].bytes.size()}, 1000);
  CHECK(fake.ready);
  port.sent.clear();
  sdkv1::JoinConfirmDown down{};
  down.head.op = 2;
  down.head.generation = kGeneration;
  down.head.request_id = 1;
  down.confirmed_generation = kGeneration + 1;
  const auto wrong_confirm = fake.seal(keys::AuthorityEnvelopeType::JoinConfirm, down);
  rx.rx.kind = sdkv1::AuthorityCarrierKind::Envelope;
  rx.rx.bytes = ByteView{wrong_confirm.bytes.data(), wrong_confirm.bytes.size()};
  CHECK(client.advance(rx, 1001));
  CHECK(!client.snapshot().join_confirmed);

  sdkv1::GroupKeyUpdate update{};
  update.head.op = 1;
  update.head.generation = kGeneration + 1;
  update.head.request_id = 2;
  update.g = 11;
  update.cause = sdkv1::UpdateCause::Periodic;
  update.overlap_s = 60;
  update.gk = secret(0xA0);
  const auto wrong_update = fake.seal(keys::AuthorityEnvelopeType::GroupKeyUpdate, update);
  rx.rx.bytes = ByteView{wrong_update.bytes.data(), wrong_update.bytes.size()};
  CHECK(client.advance(rx, 1002));
  bool saw_update = false;
  for (const auto& event : observer.seen) {
    if (event.kind == sdkv1::AuthorityEvent::Kind::UpdateReceived) saw_update = true;
  }
  CHECK(!saw_update);
}

struct FailingSeal {
  const routeloom::AeadGcm* inner{routeloom::builtin_aead_gcm()};
  sdkv1::AuthorityClient* client{nullptr};
  std::uint64_t seen_counter{0};
  bool fail_once{true};

  static bool seal(void* context, const std::uint8_t* key, const std::uint8_t* nonce,
                   ByteView aad, ByteView plaintext, std::uint8_t* out) noexcept {
    auto& self = *static_cast<FailingSeal*>(context);
    if (self.fail_once) {
      self.fail_once = false;
      if (self.client != nullptr) self.seen_counter = self.client->snapshot().tx_counter;
      return false;
    }
    return self.inner->seal(self.inner->ctx, key, nonce, aad, plaintext, out);
  }
  static bool open(void* context, const std::uint8_t* key, const std::uint8_t* nonce,
                   ByteView aad, ByteView ciphertext, std::uint8_t* out) noexcept {
    auto& self = *static_cast<FailingSeal*>(context);
    return self.inner->open(self.inner->ctx, key, nonce, aad, ciphertext, out);
  }
};

void test_failed_seal_burns_counter() {
  FailingSeal failing{};
  CHECK(failing.inner != nullptr);
  if (failing.inner == nullptr) return;
  const routeloom::AeadGcm aead{&FailingSeal::seal, &FailingSeal::open, &failing};
  FakePort port;
  FakeObserver observer;
  FakeEnv env;
  sdkv1::AuthorityClient client(aead, port, observer, env);
  failing.client = &client;
  FakeAuthority fake(secret(0xD0));
  sdkv1::AuthorityInput start{};
  start.kind = sdkv1::AuthorityInputKind::Start;
  start.start = make_start();
  CHECK(client.advance(start, 1000));
  CHECK(port.sent.size() == 1);
  if (port.sent.empty()) return;
  const auto r2 = fake.on_carrier(port.sent[0].kind,
                                  ByteView{port.sent[0].bytes.data(), port.sent[0].bytes.size()},
                                  1000);
  CHECK(r2.size() == 1);
  if (r2.empty()) return;
  port.sent.clear();
  sdkv1::AuthorityInput rx{};
  rx.kind = sdkv1::AuthorityInputKind::RxCarrier;
  rx.rx.kind = sdkv1::AuthorityCarrierKind::R2;
  rx.rx.bytes = ByteView{r2[0].bytes.data(), r2[0].bytes.size()};
  CHECK(client.advance(rx, 1000));
  CHECK(failing.seen_counter == 1);
  CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Backoff);
  CHECK(client.snapshot().rx_ctx == 0);
}

void test_malformed_wake_does_not_start_handshake() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  FakePort port;
  FakeObserver observer;
  FakeEnv env;
  sdkv1::AuthorityClient client(*aead, port, observer, env);
  FakeAuthority fake(secret(0xD0));
  sdkv1::AuthorityInput start{};
  start.kind = sdkv1::AuthorityInputKind::Start;
  start.start = make_start();
  CHECK(client.advance(start, 1000));
  CHECK(pump(client, port, fake, 1000));
  sdkv1::AuthorityInput tick{};
  tick.kind = sdkv1::AuthorityInputKind::Tick;
  CHECK(client.advance(tick, 601000));
  CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Dormant);
  sdkv1::AuthorityInput wake{};
  wake.kind = sdkv1::AuthorityInputKind::RxCarrier;
  wake.rx.kind = sdkv1::AuthorityCarrierKind::Wake;
  const std::array<std::uint8_t, 7> short_hint{};
  wake.rx.bytes = ByteView{short_hint.data(), short_hint.size()};
  CHECK(client.advance(wake, 601001));
  CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Dormant);
  CHECK(port.sent.empty());
  start.start = make_start();
  start.start.network += (std::uint64_t{1} << 32);
  start.start.epochs.site_epoch = 8;
  start.start.site_id += 1;
  start.start.dams = secret(0xC1);
  CHECK(client.advance(start, 601002));
  CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Connecting);
  CHECK(port.sent.size() == 1);
}

void test_suspend_and_validation() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  FakePort port;
  FakeObserver observer;
  FakeEnv env;
  sdkv1::AuthorityClient client(*aead, port, observer, env);
  // Start validation refuses bad inputs without starting.
  sdkv1::AuthorityInput start{};
  start.kind = sdkv1::AuthorityInputKind::Start;
  start.start = make_start();
  start.start.dams = keys::Secret{};
  CHECK(!client.advance(start, 1000));
  CHECK(!client.snapshot().started);
  start.start = make_start();
  start.start.epochs.site_epoch = 8;  // network says 7
  CHECK(!client.advance(start, 1000));
  CHECK(!client.snapshot().started);
  CHECK(client.quiescent());
  CHECK(client.next_deadline() == UINT64_MAX);
  // Rx/Tick/Pull before Start are caller errors, not silent drops.
  sdkv1::AuthorityInput rx{};
  rx.kind = sdkv1::AuthorityInputKind::RxCarrier;
  CHECK(!client.advance(rx, 1000));
  sdkv1::AuthorityInput pull{};
  pull.kind = sdkv1::AuthorityInputKind::RequestPull;
  CHECK(!client.advance(pull, 1000));
  // A double Start is refused; Suspend wipes back to a clean Dormant.
  start.start = make_start();
  CHECK(client.advance(start, 1000));
  CHECK(!client.advance(start, 1000));
  sdkv1::AuthorityInput suspend{};
  suspend.kind = sdkv1::AuthorityInputKind::Suspend;
  CHECK(client.advance(suspend, 1000));
  CHECK(client.quiescent());
  const sdkv1::AuthoritySnapshot snap = client.snapshot();
  CHECK(!snap.started && snap.tx_sent == 0 && snap.rx_ctx == 0);
  CHECK(client.advance(suspend, 1000));  // idempotent
  // And the client starts over cleanly afterwards.
  CHECK(client.advance(start, 2000));
  CHECK(client.snapshot().state == sdkv1::AuthoritySnapshot::State::Connecting);
}

// --- No-heap probe -----------------------------------------------------------
//
// The portable core must not allocate: the doubles below use fixed storage
// only, so any operator new during the round-trip is the client's fault.

namespace heap_probe {
bool armed{false};
std::size_t new_calls{0};
}  // namespace heap_probe

struct HeapCheckPort final : sdkv1::AuthorityPort {
  std::array<std::uint8_t, keys::kAuthorityEnvelopeMax> last{};
  std::size_t last_size{0};
  std::uint64_t next_token{1};

  bool try_send(NodeId, sdkv1::AuthorityCarrierKind, ByteView carrier,
                std::uint64_t& token) noexcept override {
    if (carrier.size > last.size()) return false;
    std::memcpy(last.data(), carrier.data, carrier.size);
    last_size = carrier.size;
    token = next_token++;
    return true;
  }
};

struct HeapCheckObserver final : sdkv1::AuthorityObserver {
  int events{0};
  void on_event(const sdkv1::AuthorityEvent&) noexcept override { ++events; }
};

void test_no_heap() {
  const routeloom::AeadGcm* aead = routeloom::builtin_aead_gcm();
  CHECK(aead != nullptr);
  if (aead == nullptr) return;
  HeapCheckPort port;
  HeapCheckObserver observer;
  FakeEnv env;
  sdkv1::AuthorityClient client(*aead, port, observer, env);
  sdkv1::AuthorityInput start{};
  start.kind = sdkv1::AuthorityInputKind::Start;
  start.start = make_start();
  heap_probe::armed = true;
  const std::size_t before = heap_probe::new_calls;
  CHECK(client.advance(start, 1000));
  sdkv1::AuthorityInput tick{};
  tick.kind = sdkv1::AuthorityInputKind::Tick;
  CHECK(client.advance(tick, 2000));
  CHECK(client.advance(tick, 7000));  // into Backoff (jitter draws entropy)
  CHECK(client.advance(tick, 9000));  // and back to Connecting
  sdkv1::AuthorityInput suspend{};
  suspend.kind = sdkv1::AuthorityInputKind::Suspend;
  CHECK(client.advance(suspend, 9000));
  heap_probe::armed = false;
  CHECK(heap_probe::new_calls == before);
  std::printf("sizeof(AuthorityClient) = %zu\n", sizeof(sdkv1::AuthorityClient));
}

}  // namespace

void* operator new(std::size_t size) {
  if (heap_probe::armed) ++heap_probe::new_calls;
  void* p = std::malloc(size);
  if (p == nullptr) throw std::bad_alloc();
  return p;
}

void operator delete(void* p) noexcept { std::free(p); }

void* operator new[](std::size_t size) {
  if (heap_probe::armed) ++heap_probe::new_calls;
  void* p = std::malloc(size);
  if (p == nullptr) throw std::bad_alloc();
  return p;
}

void operator delete[](void* p) noexcept { std::free(p); }

// Sized deallocation (C++14): some standard libraries call these.
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

static_assert(sizeof(sdkv1::AuthorityClient) <= 8192,
              "P5 authority/transport budget: the client must stay small");

int main() {
  test_golden_bodies();
  test_golden_gk_id();
  test_golden_envelopes();
  test_builtin_gcm();
  test_replay_window();
  test_round_trip();
  test_durable_group_ack_round_trip();
  test_bound_channel_fences_changed_site();
  test_reentry();
  test_timeouts_and_backoff();
  test_rx_attacks();
  test_port_full_and_tx_result();
  test_staged_confirm_and_one_pending_ack();
  test_pull_bucket_at_zero();
  test_unknown_body_op_is_refused();
  test_durable_ack_requires_stored_key();
  test_receiver_generation_fence();
  test_failed_seal_burns_counter();
  test_malformed_wake_does_not_start_handshake();
  test_suspend_and_validation();
  test_no_heap();
  if (failures == 0) {
    std::printf("sdkv1_authority: all tests passed\n");
    return 0;
  }
  std::printf("sdkv1_authority: %d FAILURES\n", failures);
  return 1;
}
