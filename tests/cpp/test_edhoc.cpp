// EDHOC through the vendored libedhoc and RouteLoom's bounded backend
// (docs/design/sdk-v1/08-implementation-plan.md P2-1).
//
//  1. RFC 9529 §3 (method 3, cipher suite 2 — the RFC's only suite-2 trace):
//     the suite-6 negotiation error, message_1..message_4, PRK_3e2m,
//     PRK_4e3m, PRK_out, PRK_exporter, the OSCORE exporter outputs and the
//     key update, byte for byte, with the RFC's ephemeral keys fed through
//     the session RNG (the P-256 points are computed, not injected).
//  2. RFC 9529 §4 invalid messages: every one is refused.
//  3. RouteLoom's profile — method 0 (ES256 both ways), suite 2, kid =
//     SHA-256(COSE_Key) of real RLCW1 MemberCerts used as CRED_x — round
//     trip, exporter agreement, and the failure cases (unknown kid, forged
//     certificate, wrong key, tampered messages, exhausted arena).
//  4. The zero-touch join profile (sdk-v1/02 §3, §6; P3-1): DevCert/SiteCert
//     by kid with the certificates in the Credential EAD item (label 65541),
//     JoinIntent / SiteOffer / JoinRequest / JoinResult EAD, the real m1..m4
//     lengths against the transport budgets, and the refusals.
//  5. Arena / KeyStore unit behaviour, and the sizes and stack high-water
//     this backend needs (printed; see docs/design/sdk-v1/ram-budget.md).
//
// Vectors: protocol/edhoc-rfc9529/chapter3.txt (tools/extract_rfc9529_vectors.py).
//
// Known upstream report under UBSan (recoverable, the test still passes):
// libedhoc's message_3/message_4 Enc_structure encodes the empty
// external_aad as (NULL, 0), and zcbor copies it with memmove(dst, NULL, 0)
// (zcbor_encode.c str_encode) — undefined by the letter of the C standard,
// a no-op on every libc. It comes from the vendored code at the pinned
// commits, not from RouteLoom inputs, and is left visible rather than
// suppressed.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#if defined(__linux__)
#include <pthread.h>
#endif

#include "libedhoc_api.hpp"
#include "routeloom/edhoc.hpp"
#include "routeloom/kdf.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_ead.hpp"
#include "routeloom/sdkv1_join_transport.hpp"
#include "test_sdkv1.hpp"
#include "uECC.h"

extern "C" int routeloom_edhoc_probe_slot(const edhoc_context* ctx, int slot,
                                          std::uint8_t* handle);
extern "C" int routeloom_edhoc_probe_slot_id(const char* name);
extern "C" std::size_t routeloom_edhoc_context_sizeof(void);
// libedhoc's custom memory hooks (edhoc_backend_memory.h), defined by the
// RouteLoom backend.
extern "C" void* edhoc_mem_alloc(std::size_t size);
extern "C" void edhoc_mem_free(void* ptr);

namespace {

int failures = 0;
#define CHECK(expr)                                                        \
  do {                                                                     \
    if (!(expr)) {                                                         \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, \
                   #expr);                                                 \
      ++failures;                                                          \
    }                                                                      \
  } while (false)

using routeloom::ByteView;
using routeloom::MutableByteView;
using routeloom::Status;
using routeloom::StatusCode;
namespace edhoc = routeloom::edhoc;
using Bytes = std::vector<std::uint8_t>;

ByteView view(const Bytes& b) { return ByteView{b.data(), b.size()}; }

std::string to_hex(const std::uint8_t* data, const std::size_t size) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  for (std::size_t i = 0; i < size; ++i) {
    out.push_back(digits[data[i] >> 4]);
    out.push_back(digits[data[i] & 0x0F]);
  }
  return out;
}

bool same(const Bytes& expected, const std::uint8_t* data, const std::size_t size,
          const char* what) {
  if (expected.size() == size && std::equal(expected.begin(), expected.end(), data)) {
    return true;
  }
  std::fprintf(stderr, "%s mismatch\n  want %s\n  got  %s\n", what,
               to_hex(expected.data(), expected.size()).c_str(), to_hex(data, size).c_str());
  return false;
}

// --- RFC 9529 vectors ---------------------------------------------------------

std::map<std::string, Bytes> load_vectors() {
  std::map<std::string, Bytes> out;
  std::ifstream file(std::string(ROUTELOOM_EDHOC_RFC9529_DIR) + "/chapter3.txt");
  std::string line;
  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '#') continue;
    const std::size_t eq = line.find(" = ");
    if (eq == std::string::npos) continue;
    const std::string name = line.substr(0, eq);
    const std::string value = line.substr(eq + 3);
    Bytes bytes;
    for (std::size_t i = 0; i + 1 < value.size(); i += 2) {
      bytes.push_back(static_cast<std::uint8_t>(std::stoul(value.substr(i, 2), nullptr, 16)));
    }
    out[name] = bytes;
  }
  return out;
}

const std::map<std::string, Bytes>& tv() {
  static const std::map<std::string, Bytes> vectors = load_vectors();
  return vectors;
}

const Bytes& V(const char* name) {
  static const Bytes empty;
  const auto it = tv().find(name);
  if (it == tv().end()) {
    std::fprintf(stderr, "missing vector %s\n", name);
    ++failures;
    return empty;
  }
  return it->second;
}

// --- RNG that replays fixed outputs (the RFC's ephemeral private keys) -------

struct ScriptedRng {
  std::vector<Bytes> outputs;
  std::size_t next{0};
};

bool scripted_random(void* ctx, std::uint8_t* out, const std::size_t size) noexcept {
  auto* rng = static_cast<ScriptedRng*>(ctx);
  if (rng->next >= rng->outputs.size() || rng->outputs[rng->next].size() != size) {
    return false;
  }
  std::memcpy(out, rng->outputs[rng->next].data(), size);
  ++rng->next;
  return true;
}

// Deterministic test-only stream (xorshift); fine for ephemeral keys in a
// host test, never a CSPRNG.
bool counter_random(void* ctx, std::uint8_t* out, const std::size_t size) noexcept {
  auto* state = static_cast<std::uint64_t*>(ctx);
  for (std::size_t i = 0; i < size; ++i) {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    out[i] = static_cast<std::uint8_t>(*state >> 24);
  }
  return true;
}

// --- Probes -------------------------------------------------------------------

Bytes slot(edhoc::Session& session, const char* name) {
  std::uint8_t handle[edhoc::KeyStore::kHandleSize] = {};
  if (routeloom_edhoc_probe_slot(session.native(), routeloom_edhoc_probe_slot_id(name),
                                 handle) == 0) {
    return {};
  }
  const ByteView key = session.keys().peek(handle);
  return Bytes(key.data, key.data + key.size);
}

void check_slot(edhoc::Session& session, const char* name, const Bytes& expected,
                const char* who) {
  const Bytes got = slot(session, name);
  const std::string what = std::string(who) + " " + name;
  CHECK(same(expected, got.data(), got.size(), what.c_str()));
}

std::size_t g_arena_high_water = 0;
std::size_t g_arena_max_blocks = 0;
std::size_t g_key_high_water = 0;

void note(const edhoc::Session& session) {
  // Every libedhoc call returns all of its scratch.
  CHECK(session.arena().live_blocks() == 0);
  CHECK(session.arena().failures() == 0);
  g_arena_high_water = std::max(g_arena_high_water, session.arena().high_water());
  g_arena_max_blocks = std::max(g_arena_max_blocks, session.arena().max_live_blocks());
  g_key_high_water = std::max(g_key_high_water, session.keys().high_water());
}

edhoc_error_code error_code(edhoc::Session& session) {
  edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;
  (void)edhoc_error_get_code(session.native(), &code);
  return code;
}

// --- RFC 9529 §3 credentials (CCS, kid) ----------------------------------------

class RfcCredentials final : public edhoc::CredentialProvider {
 public:
  Status local(const edhoc::Role role, edhoc::LocalCredential& out) noexcept override {
    const bool initiator = role == edhoc::Role::Initiator;
    const Bytes& id_cred = V(initiator ? "ID_CRED_I" : "ID_CRED_R");
    const Bytes& cred = V(initiator ? "CRED_I" : "CRED_R");
    const Bytes& sk = V(initiator ? "SK_I" : "SK_R");
    // ID_CRED_x = {4: h'xx'} = a1 04 41 xx
    if (id_cred.size() != 4 || sk.size() != 32) {
      return Status::error(StatusCode::InvalidArgument, "rfc credential");
    }
    out.kid = ByteView{id_cred.data() + 3, 1};
    out.credential = view(cred);
    std::copy(sk.begin(), sk.end(), out.private_key.begin());
    return Status::success();
  }
  Status peer(const edhoc::Role role, const ByteView kid,
              edhoc::PeerCredential& out) noexcept override {
    const bool initiator = role == edhoc::Role::Initiator;
    const Bytes& id_cred = V(initiator ? "ID_CRED_R" : "ID_CRED_I");
    if (kid.size != 1 || id_cred.size() != 4 || kid.data[0] != id_cred[3]) {
      ++unknown_kid;
      return Status::error(StatusCode::NotFound, "unknown kid");
    }
    const Bytes& x = V(initiator ? "PK_R_x" : "PK_I_x");
    const Bytes& y = V(initiator ? "PK_R_y" : "PK_I_y");
    out.credential = view(V(initiator ? "CRED_R" : "CRED_I"));
    std::copy(x.begin(), x.end(), out.public_key.begin());
    std::copy(y.begin(), y.end(), out.public_key.begin() + 32);
    return Status::success();
  }
  int unknown_kid{0};
};

edhoc::SessionConfig rfc_config(const edhoc::Role role, edhoc::CredentialProvider& creds,
                                ScriptedRng& rng) {
  edhoc::SessionConfig config{};
  config.role = role;
  config.method = edhoc::Method::StaticStatic;
  if (role == edhoc::Role::Initiator) {
    config.suites = {6, edhoc::kCipherSuite2};  // SUITES_I = [6, 2]
    config.suite_count = 2;
    config.connection_id = view(V("C_I"));
  } else {
    config.suites = {edhoc::kCipherSuite2, 0};
    config.suite_count = 1;
    config.connection_id = view(V("C_R"));
  }
  config.credentials = &creds;
  config.random = &scripted_random;
  config.random_ctx = &rng;
  return config;
}

// The P-256 arithmetic under the trace, straight through micro-ecc: G_X/G_Y
// from X/Y, and G_XY, G_RX, G_IY. (The session reaches the same values
// through its callbacks; this pins the curve helpers independently.)
void test_rfc9529_points() {
  const auto x_only = [](const Bytes& scalar) {
    std::array<std::uint8_t, 64> pub{};
    CHECK(uECC_compute_public_key(scalar.data(), pub.data(), uECC_secp256r1()) != 0);
    return Bytes(pub.begin(), pub.begin() + 32);
  };
  const auto dh = [](const Bytes& scalar, const Bytes& x) {
    std::array<std::uint8_t, 33> compressed{};
    compressed[0] = 0x02;
    std::copy(x.begin(), x.end(), compressed.begin() + 1);
    std::array<std::uint8_t, 64> point{};
    uECC_decompress(compressed.data(), point.data(), uECC_secp256r1());
    CHECK(uECC_valid_public_key(point.data(), uECC_secp256r1()) != 0);
    std::array<std::uint8_t, 32> secret{};
    CHECK(uECC_shared_secret(point.data(), scalar.data(), secret.data(), uECC_secp256r1()) != 0);
    return Bytes(secret.begin(), secret.end());
  };
  const Bytes gx = x_only(V("X"));
  const Bytes gy = x_only(V("Y"));
  CHECK(same(V("G_X"), gx.data(), gx.size(), "G_X"));
  CHECK(same(V("G_Y"), gy.data(), gy.size(), "G_Y"));
  const Bytes pkr = x_only(V("SK_R"));
  const Bytes pki = x_only(V("SK_I"));
  CHECK(same(V("PK_R_x"), pkr.data(), pkr.size(), "PK_R"));
  CHECK(same(V("PK_I_x"), pki.data(), pki.size(), "PK_I"));
  const Bytes gxy = dh(V("X"), V("G_Y"));
  const Bytes grx = dh(V("SK_R"), V("G_X"));
  const Bytes giy = dh(V("SK_I"), V("G_Y"));
  CHECK(same(V("G_XY"), gxy.data(), gxy.size(), "G_XY"));
  CHECK(same(V("G_RX"), grx.data(), grx.size(), "G_RX"));
  CHECK(same(V("G_IY"), giy.data(), giy.size(), "G_IY"));
}

void test_rfc9529_trace() {
  RfcCredentials creds;
  std::array<std::uint8_t, 256> buffer{};
  std::size_t length = 0;

  // §3.1–3.2: the first message_1 selects suite 6; a suite-2-only Responder
  // refuses it and answers with ERR_CODE 2, SUITES_R = 2.
  {
    ScriptedRng rng;
    edhoc::Session responder;
    CHECK(responder.begin(rfc_config(edhoc::Role::Responder, creds, rng)).ok());
    CHECK(!responder.process_message_1(view(V("message_1_first"))).ok());
    CHECK(error_code(responder) == EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE);
    note(responder);
    const std::int32_t suites_r[] = {edhoc::kCipherSuite2};
    CHECK(responder
              .compose_error(EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, suites_r, 1,
                             MutableByteView{buffer.data(), buffer.size()}, length)
              .ok());
    CHECK(same(V("error"), buffer.data(), length, "error"));
  }

  ScriptedRng init_rng;
  init_rng.outputs.push_back(V("X"));
  ScriptedRng resp_rng;
  resp_rng.outputs.push_back(V("Y"));
  edhoc::Session initiator;
  edhoc::Session responder;
  CHECK(initiator.begin(rfc_config(edhoc::Role::Initiator, creds, init_rng)).ok());
  CHECK(responder.begin(rfc_config(edhoc::Role::Responder, creds, resp_rng)).ok());

  // The first Initiator session reads SUITES_R from the error; an error
  // ends that exchange (RFC 9528 §6), so message_1 is sent by a new one.
  {
    ScriptedRng unused;
    edhoc::Session first;
    CHECK(first.begin(rfc_config(edhoc::Role::Initiator, creds, unused)).ok());
    std::int32_t code = 0;
    std::array<std::int32_t, 2> suites{};
    std::size_t count = 0;
    CHECK(first.process_error(view(V("error")), code, suites.data(), suites.size(), count).ok());
    CHECK(code == EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE);
    CHECK(count == 1 && suites[0] == edhoc::kCipherSuite2);
    note(first);
    std::size_t unused_length = 0;
    CHECK(first.compose_message_1(MutableByteView{buffer.data(), buffer.size()}, unused_length)
              .code == StatusCode::InvalidState);
  }

  // §3.3 message_1 (second time): SUITES_I = [6, 2], G_X from X.
  CHECK(initiator.compose_message_1(MutableByteView{buffer.data(), buffer.size()}, length).ok());
  CHECK(same(V("message_1"), buffer.data(), length, "message_1"));
  note(initiator);
  CHECK(responder.process_message_1(view(V("message_1"))).ok());
  note(responder);

  // §3.4 message_2
  CHECK(responder.compose_message_2(MutableByteView{buffer.data(), buffer.size()}, length).ok());
  CHECK(same(V("message_2"), buffer.data(), length, "message_2"));
  check_slot(responder, "PRK_3e2m", V("PRK_3e2m"), "responder");
  note(responder);
  CHECK(initiator.process_message_2(view(V("message_2"))).ok());
  check_slot(initiator, "PRK_3e2m", V("PRK_3e2m"), "initiator");
  note(initiator);

  // §3.5 message_3
  CHECK(initiator.compose_message_3(MutableByteView{buffer.data(), buffer.size()}, length).ok());
  CHECK(same(V("message_3"), buffer.data(), length, "message_3"));
  check_slot(initiator, "PRK_4e3m", V("PRK_4e3m"), "initiator");
  note(initiator);
  CHECK(responder.process_message_3(view(V("message_3"))).ok());
  check_slot(responder, "PRK_4e3m", V("PRK_4e3m"), "responder");
  note(responder);

  // §3.6 message_4, §3.7 PRK_out
  CHECK(responder.compose_message_4(MutableByteView{buffer.data(), buffer.size()}, length).ok());
  CHECK(same(V("message_4"), buffer.data(), length, "message_4"));
  note(responder);
  CHECK(initiator.process_message_4(view(V("message_4"))).ok());
  note(initiator);
  // libedhoc derives PRK_out lazily, at the first export.
  CHECK(slot(initiator, "PRK_out").empty());

  // §3.7 PRK_out / PRK_exporter and §3.8 OSCORE parameters. PRK_exporter
  // is transient in libedhoc (derived per export, destroyed right after),
  // so it is checked two ways: recomputed from the PRK_out the session
  // holds with the RFC's info (10, h'', 32) = 0a 40 18 20, and through the
  // library's own exporter (labels 0 and 1 are the OSCORE secret and salt).
  const auto oscore = [&](edhoc::Session& session, const bool is_initiator,
                          const char* secret_name, const char* salt_name,
                          const char* prk_out_name, const char* prk_exporter_name) {
    std::array<std::uint8_t, 16> secret{};
    std::array<std::uint8_t, 8> salt{};
    std::array<std::uint8_t, 4> sender{};
    std::array<std::uint8_t, 4> recipient{};
    std::size_t sender_len = 0;
    std::size_t recipient_len = 0;
    CHECK(session
              .oscore_context(MutableByteView{secret.data(), secret.size()},
                              MutableByteView{salt.data(), salt.size()},
                              MutableByteView{sender.data(), sender.size()}, sender_len,
                              MutableByteView{recipient.data(), recipient.size()},
                              recipient_len)
              .ok());
    note(session);
    CHECK(same(V(secret_name), secret.data(), secret.size(), secret_name));
    CHECK(same(V(salt_name), salt.data(), salt.size(), salt_name));
    // The client (Initiator) sends with C_R and receives with C_I.
    CHECK(same(V(is_initiator ? "OSCORE_client_sender_id" : "OSCORE_server_sender_id"),
               sender.data(), sender_len, "OSCORE sender id"));
    CHECK(same(V(is_initiator ? "OSCORE_server_sender_id" : "OSCORE_client_sender_id"),
               recipient.data(), recipient_len, "OSCORE recipient id"));
    const Bytes prk_out = slot(session, "PRK_out");
    CHECK(same(V(prk_out_name), prk_out.data(), prk_out.size(), prk_out_name));
    const Bytes prk_exporter_info = {0x0a, 0x40, 0x18, 0x20};
    std::array<std::uint8_t, 32> prk_exporter{};
    CHECK(routeloom::hkdf_sha256_expand(view(prk_out), view(prk_exporter_info),
                                        MutableByteView{prk_exporter.data(), prk_exporter.size()})
              .ok());
    CHECK(same(V(prk_exporter_name), prk_exporter.data(), prk_exporter.size(),
               prk_exporter_name));
    std::array<std::uint8_t, 16> exported_secret{};
    std::array<std::uint8_t, 8> exported_salt{};
    CHECK(session
              .exporter(0, ByteView{},
                        MutableByteView{exported_secret.data(), exported_secret.size()})
              .ok());
    CHECK(session
              .exporter(1, ByteView{}, MutableByteView{exported_salt.data(), exported_salt.size()})
              .ok());
    CHECK(exported_secret == secret && exported_salt == salt);
    note(session);
  };
  oscore(initiator, true, "OSCORE_master_secret", "OSCORE_master_salt", "PRK_out",
         "PRK_exporter");
  oscore(responder, false, "OSCORE_master_secret", "OSCORE_master_salt", "PRK_out",
         "PRK_exporter");

  // §3.9 key update, then the OSCORE parameters again.
  CHECK(initiator.key_update(view(V("key_update_context"))).ok());
  CHECK(responder.key_update(view(V("key_update_context"))).ok());
  note(initiator);
  note(responder);
  oscore(initiator, true, "key_update_OSCORE_master_secret", "key_update_OSCORE_master_salt",
         "key_update_PRK_out", "key_update_PRK_exporter");
  oscore(responder, false, "key_update_OSCORE_master_secret", "key_update_OSCORE_master_salt",
         "key_update_PRK_out", "key_update_PRK_exporter");

  CHECK(init_rng.next == 1 && resp_rng.next == 1);  // one ephemeral key each
  CHECK(creds.unknown_kid == 0);
  initiator.end();
  responder.end();
  CHECK(initiator.keys().live() == 0 && responder.keys().live() == 0);
}

// §4 invalid messages. message_1 variants go to a fresh suite-2 Responder
// and are refused either while decoding message_1 (CBOR shape, suite,
// key length) or, for a G_X that is not a P-256 point, by the backend's
// point validation when message_2 is built — no message_2 ever leaves.
// One exception is pinned deliberately: §4.1.2 (C_I = 0x0e sent as the
// byte string 41 0e instead of the int 0e) is a non-deterministic encoding
// that RFC 9529 §4 lists under "must or may reject"; libedhoc at the pinned
// commit decodes it as the same C_I and continues. The received bytes are
// what H(message_1) covers, so both ends still bind the same transcript;
// the acceptance is recorded here so an upstream change is noticed.
// message_2 / PLAINTEXT_2 variants go to an Initiator that sent the §3.3
// message_1 (PLAINTEXT_2 is encrypted with the RFC's keystream
// construction, KEYSTREAM_2 = EDHOC_KDF(PRK_2e, 0, TH_2, len)).
void test_rfc9529_invalid() {
  enum class Refusal { Decode, PointCheck, AcceptedNonCanonical };
  const std::map<std::string, Refusal> expected = {
      {"invalid_4_1_1_message_1", Refusal::Decode},      // CBOR array, not a sequence
      {"invalid_4_1_2_message_1", Refusal::AcceptedNonCanonical},
      {"invalid_4_1_3_message_1", Refusal::Decode},      // SUITES_I as [2]
      {"invalid_4_1_4_message_1", Refusal::Decode},      // G_X as a text string
      {"invalid_4_2_1_message_1", Refusal::Decode},      // suite 24: not supported
      {"invalid_4_2_2_message_1", Refusal::PointCheck},  // x >= p
      {"invalid_4_2_3_message_1", Refusal::PointCheck},  // x not on P-256
      {"invalid_4_2_4_message_1", Refusal::Decode},      // suite 0: not supported
      {"invalid_4_2_6_message_1", Refusal::Decode},      // 31-byte G_X
      {"invalid_4_3_1_message_1", Refusal::Decode},      // METHOD as 19 00 03
      {"invalid_4_3_2_message_1", Refusal::Decode},      // indefinite-length SUITES_I
  };
  RfcCredentials creds;
  std::array<std::uint8_t, 256> buffer{};
  std::size_t length = 0;
  std::size_t seen = 0;
  for (const auto& [name, message] : tv()) {
    if (name.rfind("invalid_", 0) != 0 || name.find("_message_1") == std::string::npos) {
      continue;
    }
    ++seen;
    const auto want = expected.find(name);
    CHECK(want != expected.end());
    if (want == expected.end()) continue;
    ScriptedRng rng;
    rng.outputs.push_back(V("Y"));
    edhoc::Session responder;
    CHECK(responder.begin(rfc_config(edhoc::Role::Responder, creds, rng)).ok());
    const bool decoded = responder.process_message_1(view(message)).ok();
    note(responder);
    const bool composed =
        decoded &&
        responder.compose_message_2(MutableByteView{buffer.data(), buffer.size()}, length).ok();
    note(responder);
    switch (want->second) {
      case Refusal::Decode:
        if (decoded) std::fprintf(stderr, "%s decoded\n", name.c_str());
        CHECK(!decoded);
        break;
      case Refusal::PointCheck:
        CHECK(decoded && !composed);
        CHECK(responder.last_error() == EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE);
        break;
      case Refusal::AcceptedNonCanonical:
        CHECK(decoded && composed);
        break;
    }
  }
  CHECK(seen == expected.size());

  // Forged message_2 bodies.
  Bytes keystream_info_prefix = {0x00, 0x58, 0x20};
  keystream_info_prefix.insert(keystream_info_prefix.end(), V("TH_2").begin(), V("TH_2").end());
  const auto seal_plaintext_2 = [&](const Bytes& plaintext) {
    Bytes info = keystream_info_prefix;
    info.push_back(static_cast<std::uint8_t>(plaintext.size()));  // < 24: one-byte uint
    Bytes keystream(plaintext.size());
    CHECK(routeloom::hkdf_sha256_expand(view(V("PRK_2e")), view(info),
                                        MutableByteView{keystream.data(), keystream.size()})
              .ok());
    Bytes body = V("G_Y");
    for (std::size_t i = 0; i < plaintext.size(); ++i) {
      body.push_back(static_cast<std::uint8_t>(plaintext[i] ^ keystream[i]));
    }
    Bytes message = {0x58, static_cast<std::uint8_t>(body.size())};
    message.insert(message.end(), body.begin(), body.end());
    return message;
  };
  // The construction itself reproduces the valid §3.4 message_2.
  const Bytes rebuilt = seal_plaintext_2(V("PLAINTEXT_2"));
  CHECK(same(V("message_2"), rebuilt.data(), rebuilt.size(), "rebuilt message_2"));

  const std::vector<std::pair<const char*, Bytes>> forged = {
      {"4.1.5 message_2", V("invalid_4_1_5_message_2")},
      {"4.1.6 PLAINTEXT_2", seal_plaintext_2(V("invalid_4_1_6_PLAINTEXT_2"))},
      {"4.1.7 PLAINTEXT_2", seal_plaintext_2(V("invalid_4_1_7_PLAINTEXT_2"))},
      {"4.2.5 PLAINTEXT_2", seal_plaintext_2(V("invalid_4_2_5_PLAINTEXT_2"))},
  };
  for (const auto& [what, message] : forged) {
    ScriptedRng rng;
    rng.outputs.push_back(V("X"));
    edhoc::Session initiator;
    CHECK(initiator.begin(rfc_config(edhoc::Role::Initiator, creds, rng)).ok());
    CHECK(initiator.compose_message_1(MutableByteView{buffer.data(), buffer.size()}, length)
              .ok());
    const bool accepted = initiator.process_message_2(view(message)).ok();
    if (accepted) {
      std::fprintf(stderr, "RFC 9529 §%s accepted\n", what);
    }
    CHECK(!accepted);
    note(initiator);
  }
}

// --- RouteLoom profile: method 0, suite 2, RLCW1 MemberCerts ----------------

using namespace sdkv1_test;

struct Party {
  routeloom::ByteBuffer<routeloom::sdkv1::kRlcw1CertMax> cert{};
  routeloom::Digest256 kid{};
  std::array<std::uint8_t, 32> priv{};
};

Party make_party(const routeloom::NodeId node, const routeloom_test::TestKeyPair& key,
                 const routeloom_test::TestKeyPair& issuer) {
  Party p;
  const auto claims = membercert_claims(3, kNetwork, node, key.pub);
  p.cert = issue(claims, issuer);
  CHECK(p.cert.size != 0);
  CHECK(routeloom::sdkv1::cert_subject_kid(claims, p.kid).ok());
  p.priv = key.priv;
  return p;
}

// Trust: a peer kid resolves to a MemberCert that verifies under the SAK,
// whose cnf key hashes back to that kid.
class MemberCertCredentials final : public edhoc::CredentialProvider {
 public:
  MemberCertCredentials(const Party& self, std::vector<const Party*> directory)
      : self_(self), directory_(std::move(directory)) {}

  Status local(edhoc::Role, edhoc::LocalCredential& out) noexcept override {
    out.kid = ByteView{self_.kid.data(), self_.kid.size()};
    out.credential = self_.cert.view();
    out.private_key = self_.priv;
    return Status::success();
  }
  Status peer(edhoc::Role, const ByteView kid, edhoc::PeerCredential& out) noexcept override {
    for (const Party* party : directory_) {
      if (kid.size != party->kid.size() ||
          std::memcmp(kid.data, party->kid.data(), kid.size) != 0) {
        continue;
      }
      routeloom::sdkv1::CertClaims claims{};
      bool verified = false;
      if (!routeloom::sdkv1::cert_verify(party->cert.view(), sak().pub, claims, verified).ok() ||
          !verified || claims.type != routeloom::sdkv1::CertType::Member) {
        ++rejected;
        return Status::error(StatusCode::AuthenticationFailed, "membercert");
      }
      routeloom::Digest256 computed{};
      if (!routeloom::sdkv1::cert_subject_kid(claims, computed).ok() || computed != party->kid) {
        ++rejected;
        return Status::error(StatusCode::AuthenticationFailed, "kid binding");
      }
      out.credential = party->cert.view();
      out.public_key = claims.pubkey;
      return Status::success();
    }
    ++rejected;
    return Status::error(StatusCode::NotFound, "unknown kid");
  }
  int rejected{0};

 private:
  const Party& self_;
  std::vector<const Party*> directory_;
};

edhoc::SessionConfig profile_config(const edhoc::Role role, edhoc::CredentialProvider& creds,
                                    std::uint64_t& rng_state, const std::uint8_t cid) {
  static std::uint8_t cids[256];
  cids[cid] = cid;
  edhoc::SessionConfig config{};
  config.role = role;
  config.method = edhoc::Method::SignatureSignature;
  config.connection_id = ByteView{&cids[cid], 1};
  config.credentials = &creds;
  config.random = &counter_random;
  config.random_ctx = &rng_state;
  return config;
}

struct Transcript {
  Bytes m1, m2, m3, m4;
};

// Runs the handshake; `tamper` may alter a message in flight (1..4).
// Returns the number of messages delivered and accepted.
int run(edhoc::Session& initiator, edhoc::Session& responder, Transcript& t,
        int tamper_message = 0) {
  std::array<std::uint8_t, 512> buffer{};
  std::size_t length = 0;
  const auto flip = [&](Bytes& m, const int which) {
    if (which == tamper_message && !m.empty()) m[m.size() - 1] ^= 0x01;
  };
  if (!initiator.compose_message_1(MutableByteView{buffer.data(), buffer.size()}, length).ok())
    return 0;
  t.m1.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length));
  flip(t.m1, 1);
  if (!responder.process_message_1(view(t.m1)).ok()) return 0;
  if (!responder.compose_message_2(MutableByteView{buffer.data(), buffer.size()}, length).ok())
    return 1;
  t.m2.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length));
  flip(t.m2, 2);
  if (!initiator.process_message_2(view(t.m2)).ok()) return 1;
  if (!initiator.compose_message_3(MutableByteView{buffer.data(), buffer.size()}, length).ok())
    return 2;
  t.m3.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length));
  flip(t.m3, 3);
  if (!responder.process_message_3(view(t.m3)).ok()) return 2;
  if (!responder.compose_message_4(MutableByteView{buffer.data(), buffer.size()}, length).ok())
    return 3;
  t.m4.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(length));
  flip(t.m4, 4);
  if (!initiator.process_message_4(view(t.m4)).ok()) return 3;
  return 4;
}

void test_profile_round_trip() {
  const Party device = make_party(kNode, device_key(), sak());
  const Party peer = make_party(kPeer, other_key(), sak());
  MemberCertCredentials device_creds(device, {&peer});
  MemberCertCredentials peer_creds(peer, {&device});
  std::uint64_t rng_i = 0x1234567890ABCDEFULL;
  std::uint64_t rng_r = 0x0FEDCBA987654321ULL;

  edhoc::Session initiator;
  edhoc::Session responder;
  CHECK(initiator.begin(profile_config(edhoc::Role::Initiator, device_creds, rng_i, 0x21)).ok());
  CHECK(responder.begin(profile_config(edhoc::Role::Responder, peer_creds, rng_r, 0x22)).ok());
  Transcript t;
  CHECK(run(initiator, responder, t) == 4);
  note(initiator);
  note(responder);
  std::printf("method 0 / suite 2 with RLCW1 MemberCerts (%zu B, kid 32 B): "
              "message_1 %zu B, message_2 %zu B, message_3 %zu B, message_4 %zu B\n",
              device.cert.size, t.m1.size(), t.m2.size(), t.m3.size(), t.m4.size());
  // message_2/3 carry the 64-byte ES256 signature and the 32-byte kid.
  CHECK(t.m2.size() > 32 + 64 + 32);
  CHECK(t.m3.size() > 64 + 32);
  CHECK(device_creds.rejected == 0 && peer_creds.rejected == 0);

  // RouteLoom's private-use Exporter labels (05 §5): key 32768 (16 B) and
  // base_iv 32769 (12 B) agree across the two ends and differ from each other.
  const Bytes context = {'R', 'o', 'u', 't', 'e', 'L', 'o', 'o', 'm'};
  std::array<std::uint8_t, 16> key_i{}, key_r{};
  std::array<std::uint8_t, 12> iv_i{}, iv_r{};
  CHECK(initiator.exporter(32768, view(context), MutableByteView{key_i.data(), key_i.size()}).ok());
  CHECK(responder.exporter(32768, view(context), MutableByteView{key_r.data(), key_r.size()}).ok());
  CHECK(initiator.exporter(32769, view(context), MutableByteView{iv_i.data(), iv_i.size()}).ok());
  CHECK(responder.exporter(32769, view(context), MutableByteView{iv_r.data(), iv_r.size()}).ok());
  CHECK(key_i == key_r);
  CHECK(iv_i == iv_r);
  CHECK(std::memcmp(key_i.data(), iv_i.data(), iv_i.size()) != 0);
  note(initiator);
  note(responder);
  // A label outside the private-use range is not a RouteLoom label; libedhoc
  // still derives it, but PRK_out-bound secrets must match both sides only.
  const Bytes other_context = {'x'};
  std::array<std::uint8_t, 16> key_other{};
  CHECK(initiator
            .exporter(32768, view(other_context), MutableByteView{key_other.data(), key_other.size()})
            .ok());
  CHECK(key_other != key_i);

  // Fresh ephemeral keys: a second handshake between the same two
  // credentials yields a different PRK_out.
  const Bytes first_prk_out = slot(initiator, "PRK_out");
  edhoc::Session initiator2;
  edhoc::Session responder2;
  CHECK(initiator2.begin(profile_config(edhoc::Role::Initiator, device_creds, rng_i, 0x21)).ok());
  CHECK(responder2.begin(profile_config(edhoc::Role::Responder, peer_creds, rng_r, 0x22)).ok());
  Transcript t2;
  CHECK(run(initiator2, responder2, t2) == 4);
  CHECK(!first_prk_out.empty() && slot(initiator2, "PRK_out") != first_prk_out);
  CHECK(slot(initiator2, "PRK_out") == slot(responder2, "PRK_out"));

  // Tampering with any message stops the handshake at that message.
  for (int which = 1; which <= 4; ++which) {
    edhoc::Session i3;
    edhoc::Session r3;
    CHECK(i3.begin(profile_config(edhoc::Role::Initiator, device_creds, rng_i, 0x21)).ok());
    CHECK(r3.begin(profile_config(edhoc::Role::Responder, peer_creds, rng_r, 0x22)).ok());
    Transcript t3;
    const int delivered = run(i3, r3, t3, which);
    // message_1's last byte is C_I, which is not authenticated until
    // message_2 binds TH_2 — so tampering it breaks message_2 processing.
    CHECK(delivered == (which == 1 ? 1 : which - 1));
    note(i3);
    note(r3);
  }
}

void test_profile_rejections() {
  const Party device = make_party(kNode, device_key(), sak());
  const Party peer = make_party(kPeer, other_key(), sak());
  std::uint64_t rng_i = 7;
  std::uint64_t rng_r = 11;

  // Unknown kid: the Initiator does not know the Responder.
  {
    MemberCertCredentials device_creds(device, {});
    MemberCertCredentials peer_creds(peer, {&device});
    edhoc::Session i;
    edhoc::Session r;
    CHECK(i.begin(profile_config(edhoc::Role::Initiator, device_creds, rng_i, 1)).ok());
    CHECK(r.begin(profile_config(edhoc::Role::Responder, peer_creds, rng_r, 2)).ok());
    Transcript t;
    CHECK(run(i, r, t) == 1);
    CHECK(device_creds.rejected == 1);
    CHECK(i.last_error() != EDHOC_SUCCESS);
  }
  // MemberCert not signed by the SAK (forged by another key).
  {
    const Party forged = make_party(kPeer, other_key(), device_ca());
    MemberCertCredentials device_creds(device, {&forged});
    MemberCertCredentials forged_creds(forged, {&device});
    edhoc::Session i;
    edhoc::Session r;
    CHECK(i.begin(profile_config(edhoc::Role::Initiator, device_creds, rng_i, 1)).ok());
    CHECK(r.begin(profile_config(edhoc::Role::Responder, forged_creds, rng_r, 2)).ok());
    Transcript t;
    CHECK(run(i, r, t) == 1);
    CHECK(device_creds.rejected == 1);
  }
  // Right certificate, wrong private key: Signature_or_MAC_2 does not verify.
  {
    Party impostor = peer;
    impostor.priv = verifier_key().priv;
    MemberCertCredentials device_creds(device, {&peer});
    MemberCertCredentials impostor_creds(impostor, {&device});
    edhoc::Session i;
    edhoc::Session r;
    CHECK(i.begin(profile_config(edhoc::Role::Initiator, device_creds, rng_i, 1)).ok());
    CHECK(r.begin(profile_config(edhoc::Role::Responder, impostor_creds, rng_r, 2)).ok());
    Transcript t;
    CHECK(run(i, r, t) == 1);
    CHECK(device_creds.rejected == 0);  // the kid resolved; the signature failed
    CHECK(i.last_error() != EDHOC_SUCCESS);
  }
  // The Responder refuses an Initiator it cannot authenticate (message_3).
  {
    MemberCertCredentials device_creds(device, {&peer});
    MemberCertCredentials peer_creds(peer, {});
    edhoc::Session i;
    edhoc::Session r;
    CHECK(i.begin(profile_config(edhoc::Role::Initiator, device_creds, rng_i, 1)).ok());
    CHECK(r.begin(profile_config(edhoc::Role::Responder, peer_creds, rng_r, 2)).ok());
    Transcript t;
    CHECK(run(i, r, t) == 2);
    CHECK(peer_creds.rejected == 1);
  }
  // A method mismatch (static DH Initiator vs. signature Responder) and an
  // RNG failure stop the exchange.
  {
    MemberCertCredentials device_creds(device, {&peer});
    MemberCertCredentials peer_creds(peer, {&device});
    edhoc::Session i;
    edhoc::Session r;
    auto ic = profile_config(edhoc::Role::Initiator, device_creds, rng_i, 1);
    ic.method = edhoc::Method::StaticStatic;
    CHECK(i.begin(ic).ok());
    CHECK(r.begin(profile_config(edhoc::Role::Responder, peer_creds, rng_r, 2)).ok());
    Transcript t;
    CHECK(run(i, r, t) == 0);

    ScriptedRng empty;
    edhoc::Session i2;
    auto ic2 = profile_config(edhoc::Role::Initiator, device_creds, rng_i, 1);
    ic2.random = &scripted_random;
    ic2.random_ctx = &empty;
    CHECK(i2.begin(ic2).ok());
    std::array<std::uint8_t, 64> out{};
    std::size_t len = 0;
    CHECK(!i2.compose_message_1(MutableByteView{out.data(), out.size()}, len).ok());
  }
  // Too-small output buffers fail cleanly.
  {
    MemberCertCredentials device_creds(device, {&peer});
    edhoc::Session i;
    CHECK(i.begin(profile_config(edhoc::Role::Initiator, device_creds, rng_i, 1)).ok());
    std::array<std::uint8_t, 8> out{};
    std::size_t len = 0;
    CHECK(!i.compose_message_1(MutableByteView{out.data(), out.size()}, len).ok());
    note(i);
  }
}

// Sizing case: the largest CRED_x RouteLoom allows (kRlcw1CertMax = 256 B,
// here an opaque 256-byte CBOR byte string — libedhoc only hashes and MACs
// CRED_x) with a 32-byte kid on both sides. This is what the arena and
// key-store figures in routeloom/edhoc_storage.h are sized against.
class LargeCredentials final : public edhoc::CredentialProvider {
 public:
  LargeCredentials(const routeloom_test::TestKeyPair& self, const routeloom_test::TestKeyPair& peer,
                   const std::uint8_t self_tag, const std::uint8_t peer_tag)
      : self_(self), peer_(peer) {
    fill(self_cred_, self_kid_, self_tag);
    fill(peer_cred_, peer_kid_, peer_tag);
  }
  Status local(edhoc::Role, edhoc::LocalCredential& out) noexcept override {
    out.kid = ByteView{self_kid_.data(), self_kid_.size()};
    out.credential = ByteView{self_cred_.data(), self_cred_.size()};
    out.private_key = self_.priv;
    return Status::success();
  }
  Status peer(edhoc::Role, const ByteView kid, edhoc::PeerCredential& out) noexcept override {
    if (kid.size != peer_kid_.size() || std::memcmp(kid.data, peer_kid_.data(), kid.size) != 0) {
      return Status::error(StatusCode::NotFound, "unknown kid");
    }
    out.credential = ByteView{peer_cred_.data(), peer_cred_.size()};
    out.public_key = peer_.pub;
    return Status::success();
  }

 private:
  static void fill(std::array<std::uint8_t, routeloom::sdkv1::kRlcw1CertMax>& cred,
                   std::array<std::uint8_t, 32>& kid, const std::uint8_t tag) {
    cred.fill(tag);
    cred[0] = 0x59;  // bstr, 2-byte length
    cred[1] = 0x00;
    cred[2] = static_cast<std::uint8_t>(cred.size() - 3);
    kid.fill(tag);
  }
  const routeloom_test::TestKeyPair& self_;
  const routeloom_test::TestKeyPair& peer_;
  std::array<std::uint8_t, routeloom::sdkv1::kRlcw1CertMax> self_cred_{};
  std::array<std::uint8_t, routeloom::sdkv1::kRlcw1CertMax> peer_cred_{};
  std::array<std::uint8_t, 32> self_kid_{};
  std::array<std::uint8_t, 32> peer_kid_{};
};

void test_largest_credentials() {
  LargeCredentials device_creds(device_key(), other_key(), 0x44, 0x55);
  LargeCredentials peer_creds(other_key(), device_key(), 0x55, 0x44);
  std::uint64_t rng_i = 99;
  std::uint64_t rng_r = 101;
  edhoc::Session initiator;
  edhoc::Session responder;
  CHECK(initiator.begin(profile_config(edhoc::Role::Initiator, device_creds, rng_i, 3)).ok());
  CHECK(responder.begin(profile_config(edhoc::Role::Responder, peer_creds, rng_r, 4)).ok());
  Transcript t;
  CHECK(run(initiator, responder, t) == 4);
  note(initiator);
  note(responder);
  std::array<std::uint8_t, 16> a{}, b{};
  CHECK(initiator.exporter(32768, ByteView{}, MutableByteView{a.data(), a.size()}).ok());
  CHECK(responder.exporter(32768, ByteView{}, MutableByteView{b.data(), b.size()}).ok());
  CHECK(a == b);
  note(initiator);
  note(responder);
}

void test_session_config() {
  RfcCredentials creds;
  ScriptedRng rng;
  edhoc::Session s;
  auto good = rfc_config(edhoc::Role::Initiator, creds, rng);
  auto c = good;
  c.credentials = nullptr;
  CHECK(s.begin(c).code == StatusCode::InvalidArgument);
  c = good;
  c.random = nullptr;
  CHECK(s.begin(c).code == StatusCode::InvalidArgument);
  c = good;
  c.suites = {edhoc::kCipherSuite2, 6};  // selected suite must be 2
  CHECK(s.begin(c).code == StatusCode::InvalidArgument);
  c = rfc_config(edhoc::Role::Responder, creds, rng);
  c.suites = {6, edhoc::kCipherSuite2};
  c.suite_count = 2;  // a Responder supports suite 2 only
  CHECK(s.begin(c).code == StatusCode::InvalidArgument);
  c = good;
  const std::uint8_t long_cid[5] = {1, 2, 3, 4, 5};
  c.connection_id = ByteView{long_cid, sizeof(long_cid)};
  CHECK(s.begin(c).code == StatusCode::InvalidArgument);
  c = good;
  const edhoc::AeadCcm no_aead{nullptr, nullptr, nullptr};
  c.aead = &no_aead;
  CHECK(s.begin(c).code == StatusCode::Unsupported);
  CHECK(!s.active());
  std::array<std::uint8_t, 64> out{};
  std::size_t len = 0;
  CHECK(s.compose_message_1(MutableByteView{out.data(), out.size()}, len).code ==
        StatusCode::InvalidState);
  CHECK(s.begin(good).ok());
  CHECK(s.begin(good).code == StatusCode::InvalidState);
  s.end();
  CHECK(s.begin(good).ok());
}

void test_arena() {
  static edhoc::Arena arena;  // large; keep off the test stack
  CHECK(arena.allocate(edhoc::Arena::kCapacity + 1) == nullptr);
  CHECK(arena.failures() == 1);
  void* a = arena.allocate(10);
  void* b = arena.allocate(100);
  void* c = arena.allocate(3);
  CHECK(a != nullptr && b != nullptr && c != nullptr);
  CHECK(reinterpret_cast<std::uintptr_t>(a) % edhoc::Arena::kAlignment == 0);
  CHECK(reinterpret_cast<std::uintptr_t>(b) % edhoc::Arena::kAlignment == 0);
  CHECK(reinterpret_cast<std::uintptr_t>(c) % edhoc::Arena::kAlignment == 0);
  std::memset(b, 0xAB, 100);
  arena.release(b);  // out of order
  CHECK(arena.live_blocks() == 2);
  // The hole is reused (first fit) and handed out zeroed.
  auto* d = static_cast<std::uint8_t*>(arena.allocate(96));
  CHECK(d == b);
  CHECK(std::all_of(d, d + 96, [](std::uint8_t v) { return v == 0; }));
  arena.release(a);
  arena.release(c);
  arena.release(d);
  arena.release(d);  // double free is harmless
  int foreign = 0;
  arena.release(&foreign);  // never touches foreign memory
  CHECK(arena.live_blocks() == 0 && arena.in_use() == 0);
  // Block-table exhaustion.
  std::vector<void*> blocks;
  for (std::size_t i = 0; i < edhoc::Arena::kMaxBlocks; ++i) blocks.push_back(arena.allocate(1));
  CHECK(std::none_of(blocks.begin(), blocks.end(), [](void* p) { return p == nullptr; }));
  CHECK(arena.allocate(1) == nullptr);
  for (void* p : blocks) arena.release(p);
  // Byte exhaustion.
  void* big = arena.allocate(edhoc::Arena::kCapacity - 8);
  CHECK(big != nullptr);
  CHECK(arena.allocate(16) == nullptr);
  CHECK(arena.allocate(8) != nullptr);
  arena.reset();
  CHECK(arena.live_blocks() == 0);

  // Outside a session call libedhoc gets no memory at all.
  CHECK(edhoc_mem_alloc(1) == nullptr);
  edhoc_mem_free(nullptr);
}

void test_key_store() {
  edhoc::KeyStore store;
  std::uint8_t h1[4] = {};
  std::uint8_t h2[4] = {};
  const std::uint8_t key[16] = {1, 2, 3};
  CHECK(store.import(edhoc::KeyUsage::Aead, ByteView{key, sizeof(key)}, h1));
  CHECK(store.find(h1, edhoc::KeyUsage::Aead).size == 16);
  CHECK(store.find(h1, edhoc::KeyUsage::Kdf).size == 0);  // usage is enforced
  CHECK(store.destroy(h1));
  CHECK(store.find(h1, edhoc::KeyUsage::Aead).size == 0);
  CHECK(!store.destroy(h1));  // stale handle
  const std::uint8_t null_handle[4] = {};
  CHECK(store.destroy(null_handle));  // null handle: no-op success
  // A reused slot does not resolve the old handle.
  CHECK(store.import(edhoc::KeyUsage::Kdf, ByteView{key, sizeof(key)}, h2));
  CHECK(std::memcmp(h1, h2, 4) != 0);
  CHECK(store.peek(h1).size == 0 && store.peek(h2).size == 16);
  CHECK(!store.import(edhoc::KeyUsage::Kdf, ByteView{key, 0}, h1));
  std::uint8_t big[33] = {};
  CHECK(!store.import(edhoc::KeyUsage::Kdf, ByteView{big, sizeof(big)}, h1));
  for (std::size_t i = 1; i < edhoc::KeyStore::kSlots; ++i) {
    std::uint8_t h[4] = {};
    CHECK(store.import(edhoc::KeyUsage::Kdf, ByteView{key, sizeof(key)}, h));
  }
  std::uint8_t h3[4] = {};
  CHECK(!store.import(edhoc::KeyUsage::Kdf, ByteView{key, sizeof(key)}, h3));
  store.clear();
  CHECK(store.live() == 0);
}

// Deep-stack measurement: run a whole method-0 handshake (both roles, the
// worst case for ES256) on a thread whose stack is pre-filled with a
// pattern and count the bytes it touched. Host x86-64 figure — an estimate
// only; P2-2 measures the ESP32-C3/S3.
#if defined(__linux__)
struct StackRun {
  bool ok{false};
};

void* stack_body(void* arg) {
  auto* run_state = static_cast<StackRun*>(arg);
  const Party device = make_party(kNode, device_key(), sak());
  const Party peer = make_party(kPeer, other_key(), sak());
  MemberCertCredentials device_creds(device, {&peer});
  MemberCertCredentials peer_creds(peer, {&device});
  std::uint64_t rng_i = 3;
  std::uint64_t rng_r = 5;
  static edhoc::Session initiator;  // sessions are static state, not stack
  static edhoc::Session responder;
  const bool began =
      initiator.begin(profile_config(edhoc::Role::Initiator, device_creds, rng_i, 9)).ok() &&
      responder.begin(profile_config(edhoc::Role::Responder, peer_creds, rng_r, 10)).ok();
  Transcript t;
  run_state->ok = began && run(initiator, responder, t) == 4;
  initiator.end();
  responder.end();
  return nullptr;
}

std::size_t measure_stack() {
  constexpr std::size_t kStack = 256 * 1024;
  static std::uint8_t stack[kStack];
  std::memset(stack, 0xA5, sizeof(stack));
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstack(&attr, stack, sizeof(stack));
  StackRun run_state;
  pthread_t thread;
  if (pthread_create(&thread, &attr, &stack_body, &run_state) != 0) {
    pthread_attr_destroy(&attr);
    return 0;
  }
  pthread_join(thread, nullptr);
  pthread_attr_destroy(&attr);
  CHECK(run_state.ok);
  std::size_t untouched = 0;
  while (untouched < kStack && stack[untouched] == 0xA5) ++untouched;  // grows down
  return kStack - untouched;
}
#endif

// --- Zero-touch join profile with EAD (sdk-v1/02 §3, §6; P3-1) ------------------
//
// Device (Initiator, DevCert) and Site Authority (Responder, SiteCert/SAK),
// method 0 / suite 2, ID_CRED_x = kid. The certificates travel in the
// critical Credential EAD item (label 65541) ahead of SiteOffer (EAD_2) and
// JoinRequest (EAD_3); each side's CredentialProvider resolves the kid to
// the certificate its EadHandler staged from the same message, verifies it
// under the right CA and matches the kid (join_credential_check). EAD_1 is
// the JoinIntent, EAD_4 an Allow JoinResult. The real message lengths are
// checked against the transport budgets (V1-J14, EDHOC-encoder part).

using routeloom::sdkv1::JoinEad;

Bytes item_field(const edhoc::EadItem* items, const std::size_t count, bool& ok) {
  // Rebuild the canonical EAD field from libedhoc's parsed tokens so the
  // strict join walkers apply: only critical join items are acceptable.
  Bytes field;
  ok = true;
  for (std::size_t i = 0; i < count; ++i) {
    const std::int32_t label = items[i].label;
    if (label >= 0 || -static_cast<std::int64_t>(label) < 65537 ||
        -static_cast<std::int64_t>(label) > 65541) {
      ok = false;
      return field;
    }
    routeloom::ByteBuffer<routeloom::sdkv1::kJoinEadItemMax> item{};
    if (!routeloom::sdkv1::join_ead_item_encode(static_cast<JoinEad>(-static_cast<std::int64_t>(label)),
                                                items[i].value, item)
             .ok()) {
      ok = false;
      return field;
    }
    field.insert(field.end(), item.bytes.begin(),
                 item.bytes.begin() + static_cast<std::ptrdiff_t>(item.size));
  }
  return field;
}

edhoc::EadItem ead_item(const JoinEad label, const ByteView value) {
  return edhoc::EadItem{-static_cast<std::int32_t>(static_cast<std::uint32_t>(label)), value};
}

// Stages the peer certificate from EAD_2/EAD_3 and resolves the kid to it.
class JoinCredentials final : public edhoc::CredentialProvider {
 public:
  JoinCredentials(const routeloom::ByteBuffer<routeloom::sdkv1::kRlcw1CertMax>& own_cert,
                  const routeloom::Digest256& own_kid, const std::array<std::uint8_t, 32>& priv,
                  routeloom::sdkv1::CertType peer_type, const routeloom::sdkv1::P256PublicKey& peer_ca)
      : own_cert_(own_cert), own_kid_(own_kid), priv_(priv), peer_type_(peer_type),
        peer_ca_(peer_ca) {}
  Status local(edhoc::Role, edhoc::LocalCredential& out) noexcept override {
    out.kid = ByteView{own_kid_.data(), own_kid_.size()};
    out.credential = own_cert_.view();
    out.private_key = priv_;
    return Status::success();
  }
  Status peer(edhoc::Role, const ByteView kid, edhoc::PeerCredential& out) noexcept override {
    if (staged.size == 0) return Status::error(StatusCode::NotFound, "no staged certificate");
    routeloom::sdkv1::CertClaims claims{};
    Status status = routeloom::sdkv1::join_credential_check(staged.view(), peer_type_, kid, claims);
    if (!status.ok()) {
      ++rejected;
      return status;
    }
    bool verified = false;
    status = routeloom::sdkv1::cert_verify(staged.view(), peer_ca_, claims, verified);
    if (!status.ok() || !verified) {
      ++rejected;
      return Status::error(StatusCode::AuthenticationFailed, "peer certificate chain");
    }
    out.credential = staged.view();
    out.public_key = claims.pubkey;
    peer_claims = claims;
    return Status::success();
  }
  routeloom::ByteBuffer<routeloom::sdkv1::kRlcw1CertMax> staged{};
  routeloom::sdkv1::CertClaims peer_claims{};
  int rejected{0};

 private:
  const routeloom::ByteBuffer<routeloom::sdkv1::kRlcw1CertMax>& own_cert_;
  const routeloom::Digest256& own_kid_;
  std::array<std::uint8_t, 32> priv_;
  routeloom::sdkv1::CertType peer_type_;
  routeloom::sdkv1::P256PublicKey peer_ca_;
};

struct DeviceEad final : edhoc::EadHandler {
  explicit DeviceEad(JoinCredentials& creds) : creds_(creds) {}
  Status compose(const int message, edhoc::EadItem* items, const std::size_t capacity,
                 std::size_t& count) noexcept override {
    count = 0;
    if (message == 1) {
      routeloom::sdkv1::JoinIntent intent{};
      intent.org_hint = routeloom::sdkv1::join_org_hint(site_ca().pub);
      intent.profile_bits = routeloom::sdkv1::kJoinProfileRljoin1;
      if (!routeloom::sdkv1::join_intent_encode(intent, intent_value).ok()) {
        return Status::error(StatusCode::InternalError, "intent");
      }
      items[count++] = ead_item(JoinEad::Intent, intent_value.view());
    } else if (message == 3) {
      if (capacity < 2) return Status::error(StatusCode::NoCapacity, "ead capacity");
      routeloom::sdkv1::JoinRequest request{};
      request.model = 17;
      request.fw_version = 0x01040000;
      if (!routeloom::sdkv1::join_request_encode(request, request_value).ok()) {
        return Status::error(StatusCode::InternalError, "request");
      }
      items[count++] = ead_item(JoinEad::Credential, devcert.view());
      items[count++] = ead_item(JoinEad::Request, request_value.view());
    }
    return Status::success();
  }
  Status process(const int message, const edhoc::EadItem* items,
                 const std::size_t count) noexcept override {
    bool ok = false;
    const Bytes field = item_field(items, count, ok);
    if (!ok) return Status::error(StatusCode::ProtocolError, "ead item");
    if (message == 2) {
      ByteView cert{};
      ByteView value{};
      Status status = routeloom::sdkv1::join_ead_find_with_credential(
          view(field), JoinEad::Offer, cert, value);
      if (!status.ok()) return status;
      status = routeloom::sdkv1::site_offer_decode(value, offer);
      if (!status.ok()) return status;
      // Copy: the item points into libedhoc's buffer, released after the call.
      creds_.staged.clear();
      std::memcpy(creds_.staged.bytes.data(), cert.data, cert.size);
      creds_.staged.size = cert.size;
      return Status::success();
    }
    if (message == 4) {
      ByteView value{};
      Status status = routeloom::sdkv1::join_ead_find(view(field), JoinEad::Result, value);
      if (!status.ok()) return status;
      result_bytes.assign(value.data, value.data + value.size);
      return Status::success();
    }
    return Status::error(StatusCode::ProtocolError, "unexpected ead");
  }
  routeloom::ByteBuffer<routeloom::sdkv1::kRlcw1CertMax> devcert{};
  routeloom::ByteBuffer<routeloom::sdkv1::kJoinIntentSize> intent_value{};
  routeloom::ByteBuffer<routeloom::sdkv1::kJoinRequestSize> request_value{};
  routeloom::sdkv1::SiteOffer offer{};
  Bytes result_bytes;

 private:
  JoinCredentials& creds_;
};

struct AuthorityEad final : edhoc::EadHandler {
  explicit AuthorityEad(JoinCredentials& creds) : creds_(creds) {}
  Status compose(const int message, edhoc::EadItem* items, const std::size_t capacity,
                 std::size_t& count) noexcept override {
    count = 0;
    if (message == 2) {
      if (capacity < 2) return Status::error(StatusCode::NoCapacity, "ead capacity");
      routeloom::sdkv1::SiteOffer offer{};
      offer.site_id = kSiteId;
      offer.network_low32 = kNetworkLow;
      offer.site_epoch = kSiteEpoch;
      if (!routeloom::sdkv1::site_offer_encode(offer, offer_value).ok()) {
        return Status::error(StatusCode::InternalError, "offer");
      }
      items[count++] = ead_item(JoinEad::Credential, credential_cert->view());
      items[count++] = ead_item(JoinEad::Offer, offer_value.view());
    } else if (message == 4) {
      items[count++] = ead_item(JoinEad::Result, result_value.view());
    }
    return Status::success();
  }
  Status process(const int message, const edhoc::EadItem* items,
                 const std::size_t count) noexcept override {
    bool ok = false;
    const Bytes field = item_field(items, count, ok);
    if (!ok) return Status::error(StatusCode::ProtocolError, "ead item");
    if (message == 1) {
      ByteView value{};
      Status status = routeloom::sdkv1::join_ead_find(view(field), JoinEad::Intent, value);
      if (!status.ok()) return status;
      return routeloom::sdkv1::join_intent_decode(value, intent);
    }
    if (message == 3) {
      ByteView cert{};
      ByteView value{};
      Status status = routeloom::sdkv1::join_ead_find_with_credential(
          view(field), JoinEad::Request, cert, value);
      if (!status.ok()) return status;
      status = routeloom::sdkv1::join_request_decode(value, request);
      if (!status.ok()) return status;
      creds_.staged.clear();
      std::memcpy(creds_.staged.bytes.data(), cert.data, cert.size);
      creds_.staged.size = cert.size;
      return Status::success();
    }
    return Status::error(StatusCode::ProtocolError, "unexpected ead");
  }
  const routeloom::ByteBuffer<routeloom::sdkv1::kRlcw1CertMax>* credential_cert{nullptr};
  routeloom::ByteBuffer<routeloom::sdkv1::kSiteOfferSize> offer_value{};
  routeloom::ByteBuffer<routeloom::sdkv1::kJoinResultMax> result_value{};
  routeloom::sdkv1::JoinIntent intent{};
  routeloom::sdkv1::JoinRequest request{};

 private:
  JoinCredentials& creds_;
};

struct JoinFixture {
  routeloom::ByteBuffer<routeloom::sdkv1::kRlcw1CertMax> devcert = issue(devcert_claims(), device_ca());
  routeloom::ByteBuffer<routeloom::sdkv1::kRlcw1CertMax> sitecert = issue(sitecert_claims(), site_ca());
  routeloom::ByteBuffer<routeloom::sdkv1::kRlcw1CertMax> membercert = issue(membercert_claims(), sak());
  routeloom::Digest256 device_kid{};
  routeloom::Digest256 sak_kid{};
  JoinFixture() {
    CHECK(routeloom::sdkv1::cert_subject_kid(devcert_claims(), device_kid).ok());
    CHECK(routeloom::sdkv1::cert_subject_kid(sitecert_claims(), sak_kid).ok());
  }
};

bool encode_allow(const JoinFixture& fx, routeloom::ByteBuffer<routeloom::sdkv1::kJoinResultMax>& out) {
  routeloom::sdkv1::JoinResult result{};
  result.verdict = routeloom::sdkv1::JoinVerdict::Allow;
  result.member_cert = fx.membercert.view();
  routeloom::sdkv1::SitePackage& p = result.site_package;
  p.site_id = kSiteId;
  p.network = kNetwork;
  p.gk_epoch = 1;
  p.gk.fill(0x6B);
  p.channel = 6;
  p.role = routeloom::sdkv1::kMemberRoleEndpoint;
  p.gateway_count = 1;
  p.gateways[0] = 0x00A1000000000001ULL;
  return routeloom::sdkv1::join_result_encode(result, out).ok();
}

void test_join_profile_with_ead() {
  JoinFixture fx;
  JoinCredentials device_creds(fx.devcert, fx.device_kid, device_key().priv,
                               routeloom::sdkv1::CertType::Site, site_ca().pub);
  JoinCredentials authority_creds(fx.sitecert, fx.sak_kid, sak().priv,
                                  routeloom::sdkv1::CertType::Device, device_ca().pub);
  DeviceEad device_ead(device_creds);
  device_ead.devcert = fx.devcert;
  AuthorityEad authority_ead(authority_creds);
  authority_ead.credential_cert = &fx.sitecert;
  CHECK(encode_allow(fx, authority_ead.result_value));
  std::uint64_t rng_i = 0x51;
  std::uint64_t rng_r = 0x53;
  auto initiator_config = profile_config(edhoc::Role::Initiator, device_creds, rng_i, 0x31);
  initiator_config.ead = &device_ead;
  auto responder_config = profile_config(edhoc::Role::Responder, authority_creds, rng_r, 0x32);
  responder_config.ead = &authority_ead;
  edhoc::Session device;
  edhoc::Session authority;
  CHECK(device.begin(initiator_config).ok());
  CHECK(authority.begin(responder_config).ok());
  Transcript t;
  CHECK(run(device, authority, t) == 4);
  note(device);
  note(authority);
  CHECK(device_creds.rejected == 0 && authority_creds.rejected == 0);
  CHECK(authority_creds.peer_claims.subject == kNode);  // the authority learned the DevCert
  CHECK(device_creds.peer_claims.subject == kSiteId);   // the device authenticated the site
  CHECK(authority_ead.intent.org_hint == routeloom::sdkv1::join_org_hint(site_ca().pub));
  CHECK(authority_ead.request.model == 17);
  CHECK(routeloom::sdkv1::site_offer_matches_site_cert(device_ead.offer,
                                                       device_creds.peer_claims)
            .ok());
  // The device's 02 §10.2 check on the received Allow.
  routeloom::sdkv1::JoinResult result{};
  CHECK(routeloom::sdkv1::join_result_decode(view(device_ead.result_bytes), result).ok());
  routeloom::sdkv1::CertClaims member{};
  bool verified = false;
  CHECK(routeloom::sdkv1::join_allow_verify(result, device_creds.peer_claims, kNode,
                                            device_key().pub, false, member, verified)
            .ok());
  CHECK(verified);
  std::printf("zero-touch join (method 0, kid + certificate in EAD): message_1 %zu B, "
              "message_2 %zu B, message_3 %zu B, message_4 %zu B (DevCert %zu B, SiteCert %zu B, "
              "MemberCert %zu B)\n",
              t.m1.size(), t.m2.size(), t.m3.size(), t.m4.size(), fx.devcert.size,
              fx.sitecert.size, fx.membercert.size);
  // Transport budgets (02 §5.3/§6, 02 §5.4): m1 with the 2-byte head and
  // the cookie is one RLD1 frame; every message fits the 960 B ceiling.
  CHECK(routeloom::sdkv1::kJoinObjectHeadSize + routeloom::sdkv1::kJoinCookieSize + t.m1.size() <=
        routeloom::autonomy::kRld1MaxBody);
  for (const Bytes* m : {&t.m2, &t.m3, &t.m4}) {
    CHECK(m->size() <= routeloom::sdkv1::kJoinMessageMax);
    const std::size_t rld1_object = routeloom::sdkv1::kJoinObjectHeadSize + m->size();
    const std::size_t relay_object = routeloom::sdkv1::kRelayHeaderSize + m->size();
    CHECK(routeloom::sdkv1::join_chunk_count(routeloom::sdkv1::JoinCarrier::Rld1, rld1_object) <= 5);
    CHECK(routeloom::sdkv1::join_chunk_count(routeloom::sdkv1::JoinCarrier::WireRelay,
                                             relay_object) <= 4);
  }

  // A SiteCert whose cnf does not hash to ID_CRED_R's kid: the device stops
  // at message_2 and never sends its identity (02 §12 row 2).
  {
    const auto other_site = issue(sitecert_claims(), device_ca());  // signed by the wrong CA
    JoinCredentials d2(fx.devcert, fx.device_kid, device_key().priv,
                       routeloom::sdkv1::CertType::Site, site_ca().pub);
    JoinCredentials a2(fx.sitecert, fx.sak_kid, sak().priv, routeloom::sdkv1::CertType::Device,
                       device_ca().pub);
    DeviceEad dev(d2);
    dev.devcert = fx.devcert;
    AuthorityEad auth(a2);
    auth.credential_cert = &other_site;
    CHECK(encode_allow(fx, auth.result_value));
    auto ic = profile_config(edhoc::Role::Initiator, d2, rng_i, 0x33);
    ic.ead = &dev;
    auto rc = profile_config(edhoc::Role::Responder, a2, rng_r, 0x34);
    rc.ead = &auth;
    edhoc::Session i2;
    edhoc::Session r2;
    CHECK(i2.begin(ic).ok() && r2.begin(rc).ok());
    Transcript t2;
    CHECK(run(i2, r2, t2) == 1);
    CHECK(d2.rejected == 1);
    CHECK(a2.staged.size == 0);  // no DevCert ever reached the authority
    note(i2);
    note(r2);
  }
  // EAD_2 without the Credential item: the device's handler refuses m2.
  {
    JoinCredentials d3(fx.devcert, fx.device_kid, device_key().priv,
                       routeloom::sdkv1::CertType::Site, site_ca().pub);
    JoinCredentials a3(fx.sitecert, fx.sak_kid, sak().priv, routeloom::sdkv1::CertType::Device,
                       device_ca().pub);
    DeviceEad dev(d3);
    dev.devcert = fx.devcert;
    struct NoCredential final : edhoc::EadHandler {
      routeloom::ByteBuffer<routeloom::sdkv1::kSiteOfferSize> offer{};
      Status compose(const int message, edhoc::EadItem* items, std::size_t,
                     std::size_t& count) noexcept override {
        count = 0;
        if (message == 2) {
          routeloom::sdkv1::SiteOffer o{};
          o.site_id = kSiteId;
          o.network_low32 = kNetworkLow;
          o.site_epoch = kSiteEpoch;
          (void)routeloom::sdkv1::site_offer_encode(o, offer);
          items[count++] = ead_item(JoinEad::Offer, offer.view());
        }
        return Status::success();
      }
      Status process(int, const edhoc::EadItem*, std::size_t) noexcept override {
        return Status::success();
      }
    } auth;
    auto ic = profile_config(edhoc::Role::Initiator, d3, rng_i, 0x35);
    ic.ead = &dev;
    auto rc = profile_config(edhoc::Role::Responder, a3, rng_r, 0x36);
    rc.ead = &auth;
    edhoc::Session i3;
    edhoc::Session r3;
    CHECK(i3.begin(ic).ok() && r3.begin(rc).ok());
    Transcript t3;
    CHECK(run(i3, r3, t3) == 1);
    note(i3);
    note(r3);
  }
}

void report_sizes() {
  std::printf("sizeof(edhoc::Session) = %zu B (libedhoc context %zu B of %zu reserved, "
              "arena %zu B, key store %zu B)\n",
              sizeof(edhoc::Session), routeloom_edhoc_context_sizeof(),
              static_cast<std::size_t>(ROUTELOOM_EDHOC_CONTEXT_BYTES), sizeof(edhoc::Arena),
              sizeof(edhoc::KeyStore));
  std::printf("arena high-water %zu B of %zu (max %zu live blocks of %zu); "
              "key-store high-water %zu of %zu slots\n",
              g_arena_high_water, edhoc::Arena::kCapacity, g_arena_max_blocks,
              edhoc::Arena::kMaxBlocks, g_key_high_water, edhoc::KeyStore::kSlots);
  CHECK(routeloom_edhoc_context_sizeof() == edhoc_context_size());
  CHECK(g_arena_high_water > 0 && g_arena_high_water <= edhoc::Arena::kCapacity);
  // Keep at least 25 % headroom over the largest observed use, so a
  // harmless libedhoc update does not silently run the arena to the edge.
  CHECK(g_arena_high_water * 4 <= edhoc::Arena::kCapacity * 3);
  CHECK(g_key_high_water < edhoc::KeyStore::kSlots);
#if defined(__linux__)
  const std::size_t stack = measure_stack();
  std::printf("stack high-water of a full method-0 handshake (both roles, host): %zu B\n",
              stack);
#if !defined(__SANITIZE_ADDRESS__)
#if defined(__has_feature)
#if !__has_feature(address_sanitizer)
  CHECK(stack > 0 && stack < 32 * 1024);
#endif
#else
  CHECK(stack > 0 && stack < 32 * 1024);
#endif
#endif
#endif
}

}  // namespace

int main() {
  CHECK(!tv().empty());
  test_rfc9529_points();
  test_rfc9529_trace();
  test_rfc9529_invalid();
  test_profile_round_trip();
  test_profile_rejections();
  test_largest_credentials();
  test_session_config();
  test_arena();
  test_key_store();
  test_join_profile_with_ead();
  report_sizes();
  if (failures != 0) {
    std::fprintf(stderr, "%d EDHOC check(s) failed\n", failures);
    return 1;
  }
  std::printf("EDHOC tests passed\n");
  return 0;
}
