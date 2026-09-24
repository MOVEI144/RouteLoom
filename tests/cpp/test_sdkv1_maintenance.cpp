// Factory maintenance console engine (sdkv1_maintenance.hpp): keygen + PoP,
// identity-bundle sealing with readback, lock/store gating. The happy path
// composes genuine office bytes from protocol/sdkv1-golden/ (the DevCert,
// anchors and kid the office tooling emits for the 0x54 device key), so the
// console is proven against the real bundle shape, not a mock of it.

#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include "routeloom/config_cose.hpp"
#include "routeloom/device_credential.hpp"
#include "routeloom/sdkv1_maintenance.hpp"
#include "routeloom/sdkv1_pop.hpp"

#include "test_sdkv1.hpp"

extern "C" {
#include "uECC.h"
}

#ifndef ROUTELOOM_SDKV1_GOLDEN_DIR
#define ROUTELOOM_SDKV1_GOLDEN_DIR "protocol/sdkv1-golden"
#endif

namespace {

int failures = 0;
std::string current;
#define CHECK(expr)                                                                  \
  do {                                                                               \
    if (!(expr)) {                                                                   \
      std::fprintf(stderr, "CHECK failed %s:%d [%s]: %s\n", __FILE__, __LINE__,      \
                   current.c_str(), #expr);                                          \
      ++failures;                                                                    \
    }                                                                                \
  } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;
using sdkv1_test::FaultyRecordStorage;

constexpr NodeId kNode = 0x00A1000000001234ULL;
constexpr char kChallenge64[] =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

// Deterministic entropy: refused until ready; the first draw is the golden
// device scalar (0x54 x32) so keygen reproduces the office fixtures, later
// draws are distinct valid scalars.
class FakeEntropy final : public EntropySource {
 public:
  bool ready{true};
  unsigned fills{0};
  Status fill(MutableByteView out) noexcept override {
    if (!ready) return Status::error(StatusCode::InvalidState, "entropy not ready");
    if (out.data == nullptr) {
      return Status::error(StatusCode::InvalidArgument, "null target");
    }
    ++fills;
    if (fills == 1) {
      std::memset(out.data, 0x54, out.size);
    } else {
      for (std::size_t i = 0; i < out.size; ++i) {
        out.data[i] = static_cast<std::uint8_t>((fills + i) & 0xFF);
      }
    }
    return Status::success();
  }
};

std::string read_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  std::ostringstream contents;
  contents << input.rdbuf();
  return contents.str();
}

// Machine-generated flat JSON only: "key": "value" or "key": 123.
std::string json_string(const std::string& text, const std::string& key) {
  const std::string needle = "\"" + key + "\": \"";
  const std::size_t begin = text.find(needle);
  CHECK(begin != std::string::npos);
  if (begin == std::string::npos) return "";
  const std::size_t start = begin + needle.size();
  const std::size_t end = text.find('"', start);
  CHECK(end != std::string::npos);
  return text.substr(start, end - start);
}

std::uint64_t json_number(const std::string& text, const std::string& key) {
  const std::string needle = "\"" + key + "\": ";
  const std::size_t begin = text.find(needle);
  CHECK(begin != std::string::npos);
  if (begin == std::string::npos) return 0;
  return std::strtoull(text.c_str() + begin + needle.size(), nullptr, 10);
}

std::string hex_encode(const std::uint8_t* data, std::size_t size) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (std::size_t i = 0; i < size; ++i) {
    out.push_back(kDigits[data[i] >> 4]);
    out.push_back(kDigits[data[i] & 0xF]);
  }
  return out;
}

std::string hex_encode(const std::string& bytes) {
  return hex_encode(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
}

struct BundleAnchor {
  std::string id_hex;
  std::string kind;
  std::string status;
  std::string pubkey_hex;
};

// The office emitter's exact shape (routeloom-provision sdkv1::office).
std::string bundle_json(const std::string& node_hex, unsigned flags, const std::string& kid_hex,
                        const std::string& pubkey_hex, const std::vector<BundleAnchor>& anchors,
                        const std::string& devcert_hex) {
  std::ostringstream anchors_out;
  for (std::size_t i = 0; i < anchors.size(); ++i) {
    if (i > 0) anchors_out << ",\n";
    anchors_out << "    {\"anchor_id\": \"" << anchors[i].id_hex << "\", \"kind\": \""
                << anchors[i].kind << "\", \"status\": \"" << anchors[i].status
                << "\", \"pubkey_hex\": \"" << anchors[i].pubkey_hex << "\"}";
  }
  std::ostringstream out;
  out << "{\n  \"format\": \"routeloom-identity-bundle-v1\",\n  \"node_id\": \"" << node_hex
      << "\",\n  \"flags\": " << flags << ",\n  \"kid_hex\": \"" << kid_hex
      << "\",\n  \"pubkey_hex\": \"" << pubkey_hex << "\",\n  \"anchors\": [\n"
      << anchors_out.str() << "\n  ],\n  \"devcert_hex\": \"" << devcert_hex << "\"\n}\n";
  return out.str();
}

std::string run(MaintenanceConsole& console, const std::string& line) {
  char response[kMaintenanceResponseMax];
  std::size_t size = 0;
  const Status status = console.process_line(
      ByteView{reinterpret_cast<const std::uint8_t*>(line.data()), line.size()}, response,
      sizeof(response), size);
  CHECK(status.ok());
  if (!status) return "";
  CHECK(size < sizeof(response));
  CHECK(response[size] == '\0');
  return std::string(response, size);
}

std::vector<std::uint8_t> unhex(const std::string& text) {
  std::vector<std::uint8_t> out;
  CHECK(text.size() % 2 == 0);
  for (std::size_t i = 0; i + 1 < text.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>(std::strtoul(text.substr(i, 2).c_str(), nullptr, 16)));
  }
  return out;
}

struct Office {
  std::string devcert_hex;
  std::string kid_hex;
  std::string device_pubkey_hex;
  std::string peer_pubkey_hex;
  std::vector<BundleAnchor> strict_anchors;
  BundleAnchor site_ca;
};

Office load_office() {
  const std::filesystem::path dir(ROUTELOOM_SDKV1_GOLDEN_DIR);
  Office office;
  office.devcert_hex = json_string(read_file(dir / "valid" / "cert_devcert.json"), "cert_hex");
  const std::string rli1 = read_file(dir / "valid" / "rli1_strict_three_anchors.json");
  office.kid_hex = json_string(rli1, "kid_hex");
  office.device_pubkey_hex = json_string(rli1, "pubkey_hex");
  office.peer_pubkey_hex =
      json_string(read_file(dir / "valid" / "cert_membercert_peer.json"), "pubkey_hex");
  for (int i = 0; i < 3; ++i) {
    const std::string prefix = "anchor" + std::to_string(i) + "_";
    char id_hex[17];
    std::snprintf(id_hex, sizeof(id_hex), "%016llx",
                  static_cast<unsigned long long>(json_number(rli1, prefix + "id")));
    BundleAnchor anchor{id_hex,
                        json_number(rli1, prefix + "kind") == 1 ? "site-ca"
                                                               : "assignment-verifier",
                        json_number(rli1, prefix + "status") == 1 ? "active" : "disabled",
                        json_string(rli1, prefix + "pubkey_hex")};
    office.strict_anchors.push_back(anchor);
    if (i == 0) office.site_ca = anchor;
  }
  return office;
}

std::string minimal_bundle(const Office& office, unsigned flags = 0) {
  return bundle_json("00a1000000001234", flags, office.kid_hex, office.device_pubkey_hex,
                     {office.site_ca}, office.devcert_hex);
}

void status_fresh() {
  current = "status_fresh";
  FaultyRecordStorage storage(kIdentitySlotBytes);
  IdentityStore store(storage);
  FakeEntropy entropy;
  MaintenanceConsole console(store, entropy);
  CHECK(run(console, "status") == "OK identity=none pending=0");
}

void keygen_ok() {
  current = "keygen_ok";
  FaultyRecordStorage storage(kIdentitySlotBytes);
  IdentityStore store(storage);
  FakeEntropy entropy;
  MaintenanceConsole console(store, entropy);
  const std::string response = run(console, std::string("keygen 00a1000000001234 ") + kChallenge64);
  CHECK(response.rfind("OK pop_hex=", 0) == 0);
  const std::string pop_hex = response.substr(std::strlen("OK pop_hex="));
  CHECK(pop_hex.size() == 2 * kPopObjectSize);
  // The PoP verifies as the office would check it, under the golden key.
  const std::vector<std::uint8_t> object = unhex(pop_hex);
  const std::vector<std::uint8_t> challenge = unhex(kChallenge64);
  PopClaims claims{};
  bool verified = false;
  CHECK(pop_verify(ByteView{object.data(), object.size()}, kNode,
                   ByteView{challenge.data(), challenge.size()}, claims, verified)
            .ok());
  CHECK(verified);
  CHECK(claims.node == kNode);
  std::array<std::uint8_t, 32> scalar{};
  scalar.fill(0x54);
  P256PublicKey expected{};
  CHECK(uECC_compute_public_key(scalar.data(), expected.data(), uECC_secp256r1()) != 0);
  CHECK(claims.pubkey == expected);
  CHECK(run(console, "status") == "OK identity=none pending=1");
}

void keygen_entropy_not_ready() {
  current = "keygen_entropy_not_ready";
  FaultyRecordStorage storage(kIdentitySlotBytes);
  IdentityStore store(storage);
  FakeEntropy entropy;
  entropy.ready = false;
  MaintenanceConsole console(store, entropy);
  CHECK(run(console, std::string("keygen 00a1000000001234 ") + kChallenge64) ==
        "ERR entropy_not_ready");
  CHECK(run(console, "status") == "OK identity=none pending=0");
  entropy.ready = true;
  CHECK(run(console, std::string("keygen 00a1000000001234 ") + kChallenge64)
            .rfind("OK pop_hex=", 0) == 0);
}

void keygen_rejects_bad_input() {
  current = "keygen_rejects_bad_input";
  FaultyRecordStorage storage(kIdentitySlotBytes);
  IdentityStore store(storage);
  FakeEntropy entropy;
  MaintenanceConsole console(store, entropy);
  const std::string challenge(kChallenge64);
  const std::vector<std::string> bad = {
      "",
      " ",
      "reboot",
      "status x",
      "keygen",
      "keygen 00a1000000001234",
      "keygen 00a1000000001234 " + challenge + " extra",
      "keygen 00a100000000123 " + challenge,    // short node
      "keygen 0000000000000000 " + challenge,   // node 0
      "keygen ffffffffffffffff " + challenge,   // all-ones node
      "keygen 00a100000000123g " + challenge,   // non-hex node
      "keygen 00a1000000001234 " + challenge.substr(0, 62),
      "keygen 00a1000000001234 " + challenge + "00",
      "keygen 00a1000000001234 " + std::string(64, 'z'),
      " keygen 00a1000000001234 " + challenge,  // leading space
      "identity",
  };
  for (const auto& line : bad) {
    CHECK(run(console, line) == "ERR invalid_argument");
  }
  CHECK(run(console, "status") == "OK identity=none pending=0");
}

void identity_ok() {
  current = "identity_ok";
  const Office office = load_office();
  FaultyRecordStorage storage(kIdentitySlotBytes);
  IdentityStore store(storage);
  FakeEntropy entropy;
  MaintenanceConsole console(store, entropy);
  CHECK(run(console, std::string("keygen 00a1000000001234 ") + kChallenge64)
            .rfind("OK pop_hex=", 0) == 0);
  const std::string response =
      run(console, "identity " + hex_encode(minimal_bundle(office)));
  CHECK(response == "OK sealed kid=" + office.kid_hex);
  CHECK(store.has_identity());
  const IdentityRecord& adopted = store.identity();
  CHECK(adopted.node_id == kNode);
  CHECK(adopted.key_location == CredentialKeyLocation::NvsPlaintext);
  CHECK(adopted.flags == 0);
  CHECK(hex_encode(adopted.kid.data(), adopted.kid.size()) == office.kid_hex);
  std::array<std::uint8_t, 32> scalar{};
  scalar.fill(0x54);
  CHECK(adopted.key_material == scalar);
  CHECK(adopted.anchor_count == 1);
  CHECK(adopted.anchors[0].anchor_id == 0x05CA000000000001ULL);
  CHECK(hex_encode(adopted.devcert.bytes.data(), adopted.devcert.size) ==
        office.devcert_hex);
  CHECK(run(console, "status") == "OK identity=sealed pending=0");
  // Sealed: no second key, no second identity.
  CHECK(run(console, std::string("keygen 00a1000000001234 ") + kChallenge64) ==
        "ERR already_provisioned");
  CHECK(run(console, "identity " + hex_encode(minimal_bundle(office))) ==
        "ERR already_provisioned");
}

void identity_reads_back_identical() {
  current = "identity_reads_back_identical";
  const Office office = load_office();
  FaultyRecordStorage storage(kIdentitySlotBytes);
  {
    IdentityStore store(storage);
    FakeEntropy entropy;
    MaintenanceConsole console(store, entropy);
    (void)run(console, std::string("keygen 00a1000000001234 ") + kChallenge64);
    CHECK(run(console, "identity " + hex_encode(minimal_bundle(office))) ==
          "OK sealed kid=" + office.kid_hex);
  }
  // A fresh store over the same slots adopts the identical record bytes.
  IdentityStore boot(storage);
  CHECK(boot.initialize().ok());
  CHECK(boot.has_identity());
  ByteBuffer<kIdentitySlotBytes> first{};
  ByteBuffer<kIdentitySlotBytes> second{};
  // Re-encode through two independent decodes of the twin slots.
  IdentityStore again(storage);
  CHECK(again.initialize().ok());
  CHECK(identity_record_encode(boot.identity(), kIdentitySealCommitted, first).ok());
  CHECK(identity_record_encode(again.identity(), kIdentitySealCommitted, second).ok());
  CHECK(first.size == second.size);
  CHECK(std::memcmp(first.bytes.data(), second.bytes.data(), first.size) == 0);
  CHECK(first.size == kIdentityFixedSize + kIdentityAnchorEntrySize + 4 +
                          unhex(office.devcert_hex).size() + 4);
}

void identity_requires_pending_key() {
  current = "identity_requires_pending_key";
  const Office office = load_office();
  FaultyRecordStorage storage(kIdentitySlotBytes);
  IdentityStore store(storage);
  FakeEntropy entropy;
  MaintenanceConsole console(store, entropy);
  CHECK(run(console, "identity " + hex_encode(minimal_bundle(office))) ==
        "ERR no_pending_key");
}

void identity_checks_node_and_key() {
  current = "identity_checks_node_and_key";
  const Office office = load_office();
  FaultyRecordStorage storage(kIdentitySlotBytes);
  IdentityStore store(storage);
  FakeEntropy entropy;
  MaintenanceConsole console(store, entropy);
  CHECK(run(console, std::string("keygen 00a1000000001234 ") + kChallenge64)
            .rfind("OK pop_hex=", 0) == 0);
  // Bundle for another node.
  const std::string other_node = bundle_json("00a1000000001235", 0, office.kid_hex,
                                             office.device_pubkey_hex, {office.site_ca},
                                             office.devcert_hex);
  CHECK(run(console, "identity " + hex_encode(other_node)) == "ERR node_mismatch");
  // Bundle naming another public key.
  const std::string other_key =
      bundle_json("00a1000000001234", 0, office.kid_hex, office.peer_pubkey_hex,
                  {office.site_ca}, office.devcert_hex);
  CHECK(run(console, "identity " + hex_encode(other_key)) == "ERR key_mismatch");
  // Bundle whose kid is not this key's.
  std::array<std::uint8_t, 32> peer_scalar{};
  peer_scalar.fill(0x56);
  P256PublicKey peer{};
  CHECK(uECC_compute_public_key(peer_scalar.data(), peer.data(), uECC_secp256r1()) != 0);
  Digest256 peer_kid{};
  CHECK(credential_kid(ByteView{peer.data(), peer.size()}, peer_kid).ok());
  const std::string other_kid =
      bundle_json("00a1000000001234", 0, hex_encode(peer_kid.data(), peer_kid.size()),
                  office.device_pubkey_hex, {office.site_ca}, office.devcert_hex);
  CHECK(run(console, "identity " + hex_encode(other_kid)) == "ERR key_mismatch");
  // The pending key survives refused bundles: the right one still seals.
  CHECK(run(console, "identity " + hex_encode(minimal_bundle(office))) ==
        "OK sealed kid=" + office.kid_hex);
}

void identity_rejects_bad_bundles() {
  current = "identity_rejects_bad_bundles";
  const Office office = load_office();
  const std::string good = minimal_bundle(office);
  std::vector<std::string> bad_bundles = {
      "zz",
      "abc",  // odd hex length
      hex_encode(good.substr(0, good.size() - 10)),
      hex_encode(good + "x"),  // trailing garbage after the document
  };
  std::string wrong_format = good;
  wrong_format.replace(wrong_format.find("routeloom-identity-bundle-v1"),
                       std::strlen("routeloom-identity-bundle-v1"), "routeloom-identity-bundle-v2");
  bad_bundles.push_back(hex_encode(wrong_format));
  std::string bad_flags = good;
  bad_flags.replace(bad_flags.find("\"flags\": 0"), std::strlen("\"flags\": 0"), "\"flags\": 300");
  bad_bundles.push_back(hex_encode(bad_flags));
  std::string unknown_kind = good;
  unknown_kind.replace(unknown_kind.find("site-ca"), std::strlen("site-ca"), "root");
  bad_bundles.push_back(hex_encode(unknown_kind));
  std::string unknown_status = good;
  unknown_status.replace(unknown_status.find("active"), std::strlen("active"), "retired");
  bad_bundles.push_back(hex_encode(unknown_status));
  // No anchors, and four anchors (the RLI1 bound is 1..3).
  bad_bundles.push_back(hex_encode(bundle_json("00a1000000001234", 0, office.kid_hex,
                                               office.device_pubkey_hex, {}, office.devcert_hex)));
  bad_bundles.push_back(hex_encode(bundle_json(
      "00a1000000001234", 0, office.kid_hex, office.device_pubkey_hex,
      {office.site_ca, office.site_ca, office.site_ca, office.site_ca}, office.devcert_hex)));
  // Anchor id 0 is not an issuer id.
  BundleAnchor zero_id = office.site_ca;
  zero_id.id_hex = "0000000000000000";
  bad_bundles.push_back(hex_encode(bundle_json("00a1000000001234", 0, office.kid_hex,
                                               office.device_pubkey_hex, {zero_id},
                                               office.devcert_hex)));
  // DevCert for another node: parses, then fails the RLI1 boot checks.
  const std::string other_devcert = json_string(
      read_file(std::filesystem::path(ROUTELOOM_SDKV1_GOLDEN_DIR) / "valid" /
                "cert_devcert_small_ints.json"),
      "cert_hex");
  bad_bundles.push_back(hex_encode(bundle_json("00a1000000001234", 0, office.kid_hex,
                                               office.device_pubkey_hex, {office.site_ca},
                                               other_devcert)));
  // Strict assignment without a verifier anchor: parses, boot checks refuse.
  bad_bundles.push_back(
      hex_encode(bundle_json("00a1000000001234", 0x02, office.kid_hex,
                             office.device_pubkey_hex, {office.site_ca}, office.devcert_hex)));
  // The strict three-anchor office bundle seals with flags 0x03.
  const std::string strict = bundle_json("00a1000000001234", 0x03, office.kid_hex,
                                         office.device_pubkey_hex, office.strict_anchors,
                                         office.devcert_hex);
  for (const auto& bundle : bad_bundles) {
    FaultyRecordStorage storage(kIdentitySlotBytes);
    IdentityStore store(storage);
    FakeEntropy entropy;
    MaintenanceConsole console(store, entropy);
    (void)run(console, std::string("keygen 00a1000000001234 ") + kChallenge64);
    CHECK(run(console, "identity " + bundle) == "ERR invalid_argument");
    CHECK(!store.has_identity());
  }
  FaultyRecordStorage storage(kIdentitySlotBytes);
  IdentityStore store(storage);
  FakeEntropy entropy;
  MaintenanceConsole console(store, entropy);
  (void)run(console, std::string("keygen 00a1000000001234 ") + kChallenge64);
  CHECK(run(console, "identity " + hex_encode(strict)) == "OK sealed kid=" + office.kid_hex);
  CHECK(store.identity().flags == 0x03);
  // Trailing whitespace after the document is tolerated.
  FaultyRecordStorage storage_ws(kIdentitySlotBytes);
  IdentityStore store_ws(storage_ws);
  FakeEntropy entropy_ws;
  MaintenanceConsole console_ws(store_ws, entropy_ws);
  (void)run(console_ws, std::string("keygen 00a1000000001234 ") + kChallenge64);
  CHECK(run(console_ws, "identity " + hex_encode(good + "\n")) ==
        "OK sealed kid=" + office.kid_hex);
}

void console_locked_seals_the_console() {
  current = "console_locked_seals_the_console";
  const Office office = load_office();
  FaultyRecordStorage storage(kIdentitySlotBytes);
  IdentityStore store(storage);
  FakeEntropy entropy;
  MaintenanceConsole console(store, entropy);
  (void)run(console, std::string("keygen 00a1000000001234 ") + kChallenge64);
  CHECK(run(console, "identity " + hex_encode(minimal_bundle(office, 0x01))) ==
        "OK sealed kid=" + office.kid_hex);
  CHECK(run(console, "status") == "ERR locked");
  CHECK(run(console, std::string("keygen 00a1000000001234 ") + kChallenge64) == "ERR locked");
  CHECK(run(console, "identity " + hex_encode(minimal_bundle(office))) == "ERR locked");
}

void impaired_store_is_unavailable() {
  current = "impaired_store_is_unavailable";
  const Office office = load_office();
  // Unreadable slots.
  {
    FaultyRecordStorage storage(kIdentitySlotBytes);
    IdentityStore store(storage);
    FakeEntropy entropy;
    MaintenanceConsole console(store, entropy);
    storage.read_error = true;
    CHECK(run(console, "status") == "ERR store_unavailable");
    CHECK(run(console, std::string("keygen 00a1000000001234 ") + kChallenge64) ==
          "ERR store_unavailable");
  }
  // A damaged twin leaves the sibling unproven: no commits, no console.
  {
    FaultyRecordStorage storage(kIdentitySlotBytes);
    IdentityStore store(storage);
    FakeEntropy entropy;
    MaintenanceConsole console(store, entropy);
    (void)run(console, std::string("keygen 00a1000000001234 ") + kChallenge64);
    (void)run(console, "identity " + hex_encode(minimal_bundle(office)));
    storage.slot(1)[40] ^= 0x01;
    CHECK(run(console, "status") == "ERR store_unavailable");
  }
}

void scalar_and_signature_primitives() {
  current = "scalar_and_signature_primitives";
  // P-256's independent group-order midpoint, not a value derived from
  // the implementation constant being checked.
  const std::array<std::uint8_t, 32> true_half{{
      0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
      0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
      0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8}};
  CHECK(kSecp256r1HalfOrder == true_half);
  Es256Signature boundary{};
  boundary[31] = 1;
  std::memcpy(boundary.data() + 32, true_half.data(), true_half.size());
  CHECK(es256_signature_canonical(ByteView{boundary.data(), boundary.size()}));
  ++boundary[63];
  CHECK(!es256_signature_canonical(ByteView{boundary.data(), boundary.size()}));
  es256_signature_normalize_low_s(boundary);
  CHECK(es256_signature_canonical(ByteView{boundary.data(), boundary.size()}));
  const std::array<std::uint8_t, 32> zero{};
  std::array<std::uint8_t, 32> one{};
  one[31] = 1;
  std::array<std::uint8_t, 32> n_minus_1 = kSecp256r1Order;
  for (std::size_t i = 32; i-- > 0;) {
    if (n_minus_1[i]-- > 0) break;
  }
  CHECK(!p256_scalar_valid(ByteView{zero.data(), zero.size()}));
  CHECK(!p256_scalar_valid(ByteView{kSecp256r1Order.data(), kSecp256r1Order.size()}));
  CHECK(!p256_scalar_valid(ByteView{one.data(), 31}));
  CHECK(p256_scalar_valid(ByteView{one.data(), one.size()}));
  CHECK(p256_scalar_valid(ByteView{n_minus_1.data(), n_minus_1.size()}));

  Es256Signature signature{};
  signature.fill(0x11);
  std::memcpy(signature.data() + 32, n_minus_1.data(), 32);
  CHECK(!es256_signature_canonical(
      ByteView{signature.data(), signature.size()}));  // high-S
  es256_signature_normalize_low_s(signature);
  CHECK(signature[63] == 1);  // n - (n - 1)
  for (std::size_t i = 32; i < 63; ++i) CHECK(signature[i] == 0);
  for (std::size_t i = 0; i < 32; ++i) CHECK(signature[i] == 0x11);  // R untouched
  CHECK(es256_signature_canonical(ByteView{signature.data(), signature.size()}));
  es256_signature_normalize_low_s(signature);  // idempotent
  CHECK(signature[63] == 1);
  // The midpoint stays (canonical includes equality); one past it folds
  // to n - s, which the canonicality rule accepts.
  std::memcpy(signature.data() + 32, kSecp256r1HalfOrder.data(), 32);
  es256_signature_normalize_low_s(signature);
  CHECK(std::memcmp(signature.data() + 32, kSecp256r1HalfOrder.data(), 32) == 0);
  std::array<std::uint8_t, 32> half_plus_1 = kSecp256r1HalfOrder;
  for (std::size_t i = 32; i-- > 0;) {
    if (++half_plus_1[i] != 0) break;
  }
  std::memcpy(signature.data() + 32, half_plus_1.data(), 32);
  CHECK(!es256_signature_canonical(ByteView{signature.data(), signature.size()}));
  es256_signature_normalize_low_s(signature);
  CHECK(es256_signature_canonical(ByteView{signature.data(), signature.size()}));
  CHECK(std::memcmp(signature.data() + 32, half_plus_1.data(), 32) != 0);
  // Garbage stays garbage (still rejected by verifiers, never rewritten).
  std::memset(signature.data() + 32, 0, 32);
  es256_signature_normalize_low_s(signature);
  CHECK(signature[63] == 0);
}

void pop_signatures_verify() {
  current = "pop_signatures_verify";
  for (unsigned seed = 0x40; seed < 0x48; ++seed) {
    std::array<std::uint8_t, 32> scalar{};
    scalar.fill(static_cast<std::uint8_t>(seed));
    std::array<std::uint8_t, 32> challenge{};
    challenge.fill(static_cast<std::uint8_t>(seed ^ 0xA5));
    ByteBuffer<kPopObjectSize> object{};
    P256PublicKey pubkey{};
    CHECK(pop_sign(kNode, CredentialKeyLocation::NvsPlaintext,
                   ByteView{challenge.data(), challenge.size()},
                   ByteView{scalar.data(), scalar.size()}, object, pubkey)
              .ok());
    CHECK(object.size == kPopObjectSize);
    P256PublicKey expected{};
    CHECK(uECC_compute_public_key(scalar.data(), expected.data(), uECC_secp256r1()) != 0);
    CHECK(pubkey == expected);
    PopClaims claims{};
    bool verified = false;
    CHECK(pop_verify(object.view(), kNode, ByteView{challenge.data(), challenge.size()},
                     claims, verified)
              .ok());
    CHECK(verified);
    CHECK(claims.pubkey == expected);
  }
  // Scalars outside [1, n-1] are refused before any curve arithmetic.
  const std::array<std::uint8_t, 32> zero{};
  std::array<std::uint8_t, 32> challenge{};
  ByteBuffer<kPopObjectSize> object{};
  P256PublicKey pubkey{};
  CHECK(!pop_sign(kNode, CredentialKeyLocation::NvsPlaintext,
                  ByteView{challenge.data(), challenge.size()},
                  ByteView{zero.data(), zero.size()}, object, pubkey)
             .ok());
}

void keygen_overwrites_pending() {
  current = "keygen_overwrites_pending";
  FaultyRecordStorage storage(kIdentitySlotBytes);
  IdentityStore store(storage);
  FakeEntropy entropy;
  MaintenanceConsole console(store, entropy);
  const std::string first =
      run(console, std::string("keygen 00a1000000001234 ") + kChallenge64);
  const std::string second_challenge(64, '7');
  const std::string second =
      run(console, "keygen 00a1000000001234 " + second_challenge);
  CHECK(first.rfind("OK pop_hex=", 0) == 0);
  CHECK(second.rfind("OK pop_hex=", 0) == 0);
  CHECK(first != second);
  const std::vector<std::uint8_t> first_object =
      unhex(first.substr(std::strlen("OK pop_hex=")));
  const std::vector<std::uint8_t> second_object =
      unhex(second.substr(std::strlen("OK pop_hex=")));
  const std::vector<std::uint8_t> first_challenge = unhex(kChallenge64);
  const std::vector<std::uint8_t> second_challenge_bytes = unhex(second_challenge);
  // Each PoP verifies under its own challenge only.
  for (const auto& [object, challenge, other] :
       {std::make_tuple(first_object, first_challenge, second_challenge_bytes),
        std::make_tuple(second_object, second_challenge_bytes, first_challenge)}) {
    PopClaims claims{};
    bool verified = false;
    CHECK(pop_verify(ByteView{object.data(), object.size()}, kNode,
                     ByteView{challenge.data(), challenge.size()}, claims, verified)
              .ok());
    CHECK(verified);
    CHECK(pop_verify(ByteView{object.data(), object.size()}, kNode,
                     ByteView{other.data(), other.size()}, claims, verified)
              .ok());
    CHECK(!verified);
  }
}

void uppercase_hex_is_accepted() {
  current = "uppercase_hex_is_accepted";
  const Office office = load_office();
  FaultyRecordStorage storage(kIdentitySlotBytes);
  IdentityStore store(storage);
  FakeEntropy entropy;
  MaintenanceConsole console(store, entropy);
  std::string challenge(kChallenge64);
  for (char& c : challenge) c = static_cast<char>(std::toupper(c));
  CHECK(run(console, "keygen 00A1000000001234 " + challenge).rfind("OK pop_hex=", 0) == 0);
  std::string bundle = hex_encode(minimal_bundle(office));
  for (char& c : bundle) c = static_cast<char>(std::toupper(c));
  CHECK(run(console, "identity " + bundle) == "OK sealed kid=" + office.kid_hex);
}

}  // namespace

int main() {
  status_fresh();
  keygen_ok();
  keygen_entropy_not_ready();
  keygen_rejects_bad_input();
  identity_ok();
  identity_reads_back_identical();
  identity_requires_pending_key();
  identity_checks_node_and_key();
  identity_rejects_bad_bundles();
  console_locked_seals_the_console();
  impaired_store_is_unavailable();
  scalar_and_signature_primitives();
  pop_signatures_verify();
  keygen_overwrites_pending();
  uppercase_hex_is_accepted();
  if (failures != 0) {
    std::fprintf(stderr, "%d maintenance console check(s) failed\n", failures);
    return 1;
  }
  std::puts("routeloom_sdkv1_maintenance_tests: ok");
  return 0;
}
