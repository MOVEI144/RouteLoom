// SDK v1 key schedule golden vectors (plan P1-4; V1-K01 HKDF part, V1-F03):
// every file in protocol/sdkv1-golden/derivations/ was produced by the
// independent Python generator tools/gen_sdkv1_derivation_vectors.py. The C++
// derivations, RLRES1 codecs/transcript and AuthorityEnvelope header must
// reproduce each byte, and every malformed message must be refused with the
// same reason the Rust mirror (host/routeloom-keysched) reports.

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
#include <sstream>
#include <string>
#include <vector>

#include "routeloom/key_schedule.hpp"
#include "routeloom/rlres1.hpp"

#ifndef ROUTELOOM_SDKV1_GOLDEN_DIR
#error "ROUTELOOM_SDKV1_GOLDEN_DIR must point at protocol/sdkv1-golden"
#endif

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

namespace keys = routeloom::keys;
namespace rlres1 = routeloom::rlres1;
using routeloom::ByteView;
using routeloom::MutableByteView;
using routeloom::ScopeDigest;
using Bytes = std::vector<std::uint8_t>;
using Fields = std::map<std::string, std::string>;

// Minimal extractor for the flat "key": value golden objects (strings or
// unsigned integers), same subset as test_autonomy.cpp.
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

template <std::size_t N>
Bytes vec(const std::array<std::uint8_t, N>& a) {
  return Bytes(a.begin(), a.end());
}

Bytes cat(const keys::TrafficKey& k) {
  Bytes out(k.key.begin(), k.key.end());
  out.insert(out.end(), k.iv.begin(), k.iv.end());
  return out;
}

std::vector<std::filesystem::path> list(const char* sub) {
  std::vector<std::filesystem::path> out;
  const auto dir = std::filesystem::path(ROUTELOOM_SDKV1_GOLDEN_DIR) / "derivations" / sub;
  for (const auto& e : std::filesystem::directory_iterator(dir)) {
    if (e.path().extension() == ".json") out.push_back(e.path());
  }
  std::sort(out.begin(), out.end());
  return out;
}

void check_group(const Fields& f) {
  const auto gk = arr<32>(f, "gk_hex");
  ScopeDigest prk{};
  keys::group_prk(u64(f, "network"), gk, prk);
  CHECK(vec(prk) == hex(f, "prk_hex"));
  const auto g = static_cast<std::uint32_t>(u64(f, "gk_epoch"));
  keys::TrafficKey bcast{};
  CHECK(keys::group_bcast_key(prk, g, u64(f, "tx"), static_cast<std::uint32_t>(u64(f, "tx_boot")),
                              bcast)
            .ok());
  CHECK(vec(bcast.key) == hex(f, "bcast_key_hex"));
  CHECK(vec(bcast.iv) == hex(f, "bcast_iv_hex"));
  keys::TrafficKey gend{};
  CHECK(keys::group_end_key(prk, g, u64(f, "group_id"), u64(f, "origin"),
                            static_cast<std::uint32_t>(u64(f, "session")), gend)
            .ok());
  CHECK(vec(gend.key) == hex(f, "gend_key_hex"));
  CHECK(vec(gend.iv) == hex(f, "gend_iv_hex"));
  keys::Secret dsk{};
  CHECK(keys::group_dsk_key(prk, g, dsk).ok());
  CHECK(vec(dsk) == hex(f, "dsk_hex"));
  // Scopes never collide: the three outputs differ pairwise.
  CHECK(cat(bcast) != cat(gend));
  CHECK(Bytes(dsk.begin(), dsk.begin() + 28) != cat(bcast));
}

void check_dev(const Fields& f) {
  const auto psk = arr<32>(f, "psk_hex");
  const routeloom::NetworkId network = u64(f, "network");
  const routeloom::NodeId a = u64(f, "node_a");
  const routeloom::NodeId b = u64(f, "node_b");
  keys::Secret link{};
  CHECK(keys::dev_pair_rms(psk, network, a, b, keys::Purpose::Link, link).ok());
  CHECK(vec(link) == hex(f, "rms_link_hex"));
  keys::Secret end{};
  CHECK(keys::dev_pair_rms(psk, network, a, b, keys::Purpose::End, end).ok());
  CHECK(vec(end) == hex(f, "rms_end_hex"));
  keys::Secret swapped{};
  CHECK(keys::dev_pair_rms(psk, network, b, a, keys::Purpose::Link, swapped).ok());
  CHECK(swapped == link);  // ordered pair: swapped ends agree
  CHECK(link != end);      // purposes never collide
  keys::TrafficKey group{};
  CHECK(keys::dev_group_key(psk, network, u64(f, "origin"),
                            static_cast<std::uint32_t>(u64(f, "boot")), group)
            .ok());
  CHECK(vec(group.key) == hex(f, "group_key_hex"));
  CHECK(vec(group.iv) == hex(f, "group_iv_hex"));
  keys::Secret scope{};
  CHECK(keys::dev_scope_key(psk, network, scope).ok());
  CHECK(vec(scope) == hex(f, "scope_hex"));
}

void check_nonce(const Fields& f) {
  const auto iv = arr<12>(f, "iv_hex");
  keys::AeadNonce nonce{};
  CHECK(keys::aead_nonce(iv, u64(f, "counter"), nonce).ok());
  CHECK(vec(nonce) == hex(f, "nonce_hex"));
}

void check_envelope(const Fields& f) {
  keys::AuthorityEnvelopeHeader header{};
  header.version = static_cast<std::uint8_t>(u64(f, "version"));
  header.type = static_cast<keys::AuthorityEnvelopeType>(u64(f, "type"));
  header.ctx_id = static_cast<std::uint32_t>(u64(f, "ctx_id"));
  header.counter = u64(f, "counter");
  std::array<std::uint8_t, keys::kAuthorityEnvelopeHeaderSize> encoded{};
  CHECK(keys::authority_envelope_header_encode(header, encoded).ok());
  CHECK(vec(encoded) == hex(f, "header_hex"));
  Bytes whole = vec(encoded);
  whole.resize(whole.size() + 5 + routeloom::kAeadTagSize, 0xEE);
  keys::AuthorityEnvelopeHeader back{};
  CHECK(keys::authority_envelope_decode(ByteView{whole.data(), whole.size()}, back) ==
        keys::DecodeError::None);
  CHECK(back.ctx_id == header.ctx_id && back.counter == header.counter && back.type == header.type);
  keys::AeadNonce nonce{};
  CHECK(keys::aead_nonce(arr<12>(f, "iv_hex"), header.counter, nonce).ok());
  CHECK(vec(nonce) == hex(f, "nonce_hex"));
}

void check_hint(const Fields& f) {
  rlres1::R2 hint{};
  hint.status = static_cast<rlres1::R2Status>(u64(f, "status"));
  hint.hint_rid = arr<8>(f, "rid_hex");
  std::array<std::uint8_t, rlres1::kR2Size> buf{};
  std::size_t n = 0;
  CHECK(rlres1::encode_r2(hint, MutableByteView{buf.data(), buf.size()}, n).ok());
  CHECK(Bytes(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n)) == hex(f, "encoded_hex"));
  rlres1::R2 back{};
  const Bytes enc = hex(f, "encoded_hex");
  CHECK(rlres1::decode_r2(ByteView{enc.data(), enc.size()}, back) == keys::DecodeError::None);
  CHECK(back.status == hint.status && back.hint_rid == hint.hint_rid);
}

// Primitive-level transcript check: derives every intermediate from the
// vector's inputs with key_schedule.hpp and compares it byte for byte.
void check_rlres1_primitives(const Fields& f) {
  const auto purpose = static_cast<keys::Purpose>(u64(f, "purpose"));
  const auto rms = arr<32>(f, "rms_hex");
  const std::uint64_t network = u64(f, "network");
  const std::uint64_t node_i = u64(f, "node_i");
  const std::uint64_t node_r = u64(f, "node_r");

  keys::ResumeId rid{};
  keys::resume_id(rms, purpose, rid);
  CHECK(vec(rid) == hex(f, "rid_hex"));
  keys::Secret k_auth{};
  CHECK(keys::resume_auth_key(rms, purpose, network, node_i, node_r, k_auth).ok());
  CHECK(vec(k_auth) == hex(f, "k_auth_hex"));

  ScopeDigest binding{};
  if (f.at("binding_kind") == "link") {
    keys::resume_binding_link(arr<6>(f, "mac_i_hex"), arr<6>(f, "mac_r_hex"),
                              arr<32>(f, "carrier_digest_hex"), binding);
  } else {
    keys::resume_binding_routed(purpose, node_i, node_r, binding);
  }
  CHECK(vec(binding) == hex(f, "binding_hex"));

  // R1 = fields || mac_I, re-encoded from the decoded fields.
  const Bytes r1 = hex(f, "r1_hex");
  rlres1::R1 m1{};
  CHECK(rlres1::decode_r1(ByteView{r1.data(), r1.size()}, m1) == keys::DecodeError::None);
  CHECK(vec(m1.rid) == vec(rid));
  CHECK(vec(m1.nonce_i) == hex(f, "nonce_i_hex"));
  CHECK(m1.cid_i == u64(f, "cid_i"));
  CHECK(m1.epochs.site_epoch == u64(f, "i_site_epoch") && m1.epochs.rs_epoch == u64(f, "i_rs_epoch") &&
        m1.epochs.gk_epoch == u64(f, "i_gk_epoch"));
  CHECK(Bytes(m1.ticket.begin(), m1.ticket.begin() + m1.ticket_size) == hex(f, "ticket_hex"));
  std::array<std::uint8_t, keys::kResumeMacSize> mac{};
  CHECK(keys::resume_mac(ByteView{k_auth.data(), k_auth.size()}, keys::kLabelResumeR1,
                         ByteView{binding.data(), binding.size()},
                         ByteView{r1.data(), r1.size() - 16}, ByteView{}, mac)
            .ok());
  CHECK(mac == m1.mac);
  std::array<std::uint8_t, rlres1::kR1MaxSize> r1_again{};
  std::size_t n = 0;
  CHECK(rlres1::encode_r1(m1, MutableByteView{r1_again.data(), r1_again.size()}, n).ok());
  CHECK(Bytes(r1_again.begin(), r1_again.begin() + static_cast<std::ptrdiff_t>(n)) == r1);

  const Bytes r2 = hex(f, "r2_hex");
  rlres1::R2 m2{};
  CHECK(rlres1::decode_r2(ByteView{r2.data(), r2.size()}, m2) == keys::DecodeError::None);
  CHECK(m2.status == rlres1::R2Status::Ok);
  CHECK(vec(m2.nonce_r) == hex(f, "nonce_r_hex"));
  CHECK(m2.cid_r == u64(f, "cid_r"));
  CHECK(m2.epochs.gk_epoch == u64(f, "r_gk_epoch") && m2.epochs.rs_epoch == u64(f, "r_rs_epoch"));
  CHECK(keys::resume_mac(ByteView{k_auth.data(), k_auth.size()}, keys::kLabelResumeR2,
                         ByteView{binding.data(), binding.size()}, ByteView{r1.data(), r1.size()},
                         ByteView{r2.data(), 36}, mac)
            .ok());
  CHECK(mac == m2.mac);

  ScopeDigest th{};
  {
    routeloom::Sha256 h;
    h.update(ByteView{r1.data(), r1.size()});
    h.update(ByteView{r2.data(), r2.size()});
    h.finish(th);
  }
  CHECK(vec(th) == hex(f, "th_hex"));
  ScopeDigest prk{};
  keys::resume_prk(m1.nonce_i, m2.nonce_r, rms, prk);
  CHECK(vec(prk) == hex(f, "prk_hex"));
  keys::Secret k_conf{};
  CHECK(keys::resume_confirm_key(prk, th, k_conf).ok());
  CHECK(vec(k_conf) == hex(f, "k_conf_hex"));
  CHECK(keys::resume_mac(ByteView{k_conf.data(), k_conf.size()}, keys::kLabelResumeR3,
                         ByteView{th.data(), th.size()}, ByteView{}, ByteView{}, mac)
            .ok());
  CHECK(vec(mac) == hex(f, "r3_hex"));

  const keys::ResumeKeyContext ctx{purpose, network, node_i, node_r, m1.cid_i, m2.cid_r};
  keys::TrafficKey ir{};
  keys::TrafficKey ri{};
  CHECK(keys::resume_traffic_key(prk, ctx, keys::Direction::InitiatorToResponder, th, ir).ok());
  CHECK(keys::resume_traffic_key(prk, ctx, keys::Direction::ResponderToInitiator, th, ri).ok());
  CHECK(vec(ir.key) == hex(f, "key_ir_hex"));
  CHECK(vec(ir.iv) == hex(f, "iv_ir_hex"));
  CHECK(vec(ri.key) == hex(f, "key_ri_hex"));
  CHECK(vec(ri.iv) == hex(f, "iv_ri_hex"));
  // V1-K01 (HKDF part): the two directions never share key or IV.
  CHECK(ir.key != ri.key && ir.iv != ri.iv);
}

// Engine-level transcript check: two Engines driven with the vector's
// nonces/cids must emit exactly the golden R1/R2/R3 and install matching keys.
struct ScriptedEnv final : rlres1::Environment {
  Bytes random_bytes;
  std::size_t random_at{0};
  std::uint32_t cid{0};
  rlres1::Slot slot{};
  bool random(MutableByteView out) noexcept override {
    if (random_at + out.size > random_bytes.size()) return false;
    std::memcpy(out.data, random_bytes.data() + random_at, out.size);
    random_at += out.size;
    return true;
  }
  bool find_slot(keys::Purpose, const keys::ResumeId& rid, rlres1::Slot& out) noexcept override {
    keys::ResumeId mine{};
    keys::resume_id(slot.secret, slot.purpose, mine);
    if (mine != rid) return false;
    out = slot;
    return true;
  }
  bool revoked(routeloom::NodeId, std::uint32_t) noexcept override { return false; }
  bool allocate_context_id(keys::Purpose, routeloom::NodeId, std::uint32_t& out) noexcept override {
    out = cid;
    return cid != 0;
  }
  bool reserve_resume_use(keys::Purpose, const keys::ResumeId&) noexcept override { return true; }
};

void check_rlres1_engine(const Fields& f) {
  const auto purpose = static_cast<keys::Purpose>(u64(f, "purpose"));
  const bool pairwise = purpose == keys::Purpose::Link || purpose == keys::Purpose::End;
  const std::uint64_t network = u64(f, "network");
  const std::uint64_t node_i = u64(f, "node_i");
  const std::uint64_t node_r = u64(f, "node_r");
  const std::uint64_t site_id = pairwise ? 0x5100000000000042ull : node_r;

  rlres1::Carrier carrier{};
  if (f.at("binding_kind") == "link") {
    carrier.kind = rlres1::Carrier::Kind::Link;
    carrier.mac_i = arr<6>(f, "mac_i_hex");
    carrier.mac_r = arr<6>(f, "mac_r_hex");
    carrier.carrier_digest = arr<32>(f, "carrier_digest_hex");
  } else {
    carrier.hops = 3;
  }
  rlres1::Limits limits{};
  limits.responder_purposes = static_cast<std::uint8_t>(1u << static_cast<unsigned>(purpose));

  rlres1::Engine initiator;
  rlres1::Local li{node_i, network, site_id,
                   {static_cast<std::uint32_t>(u64(f, "i_site_epoch")),
                    static_cast<std::uint32_t>(u64(f, "i_rs_epoch")),
                    static_cast<std::uint32_t>(u64(f, "i_gk_epoch"))}};
  CHECK(initiator.configure(li, limits).ok());
  // The responder of authority/pending is the Site Authority; the engine
  // plays it with self = a host-side id distinct from site_id.
  rlres1::Engine responder;
  rlres1::Local lr{pairwise ? node_r : 0x0A0Aull, network, site_id,
                   {static_cast<std::uint32_t>(u64(f, "r_site_epoch")),
                    static_cast<std::uint32_t>(u64(f, "r_rs_epoch")),
                    static_cast<std::uint32_t>(u64(f, "r_gk_epoch"))}};
  CHECK(responder.configure(lr, limits).ok());

  const auto rms = arr<32>(f, "rms_hex");
  const std::uint32_t created = pairwise ? static_cast<std::uint32_t>(u64(f, "i_gk_epoch")) : 0;
  ScriptedEnv ienv;
  ienv.random_bytes = hex(f, "nonce_i_hex");
  ienv.cid = static_cast<std::uint32_t>(u64(f, "cid_i"));
  ScriptedEnv renv;
  renv.random_bytes = hex(f, "nonce_r_hex");
  renv.cid = static_cast<std::uint32_t>(u64(f, "cid_r"));
  renv.slot = rlres1::Slot{purpose, node_i, network, created, 1, rms};

  rlres1::BeginRequest req{};
  req.slot = rlres1::Slot{purpose, pairwise ? node_r : site_id, network, created, 1, rms};
  req.carrier = carrier;
  const Bytes ticket = hex(f, "ticket_hex");
  req.ticket = ByteView{ticket.empty() ? nullptr : ticket.data(), ticket.size()};

  rlres1::Output o1;
  initiator.begin(req, 1000, ienv, o1);
  CHECK(o1.action == rlres1::Action::Send);
  CHECK(Bytes(o1.message.begin(), o1.message.begin() + static_cast<std::ptrdiff_t>(o1.message_size)) ==
        hex(f, "r1_hex"));

  rlres1::Output o2;
  responder.on_r1(ByteView{o1.message.data(), o1.message_size}, carrier, node_i, 1010, renv, o2);
  CHECK(o2.action == rlres1::Action::Send);
  CHECK(Bytes(o2.message.begin(), o2.message.begin() + static_cast<std::ptrdiff_t>(o2.message_size)) ==
        hex(f, "r2_hex"));

  rlres1::Output o3;
  initiator.on_r2(req.slot.peer, purpose, ByteView{o2.message.data(), o2.message_size}, 1020, o3);
  CHECK(o3.action == rlres1::Action::SendAndInstall);
  CHECK(Bytes(o3.message.begin(), o3.message.begin() + static_cast<std::ptrdiff_t>(o3.message_size)) ==
        hex(f, "r3_hex"));
  CHECK(vec(o3.established.tx.key) == hex(f, "key_ir_hex"));
  CHECK(vec(o3.established.rx.key) == hex(f, "key_ri_hex"));
  CHECK(o3.established.rx_context_id == u64(f, "cid_i"));
  CHECK(o3.established.tx_context_id == u64(f, "cid_r"));

  rlres1::Output o4;
  responder.on_r3(node_i, purpose, ByteView{o3.message.data(), o3.message_size}, 1030, o4);
  CHECK(o4.action == rlres1::Action::Install);
  CHECK(vec(o4.established.tx.iv) == hex(f, "iv_ri_hex"));
  CHECK(vec(o4.established.rx.iv) == hex(f, "iv_ir_hex"));
  // V1-K01 (HKDF part): both ends hold the same pair of directional keys.
  CHECK(o4.established.tx.key == o3.established.rx.key);
  CHECK(o4.established.rx.key == o3.established.tx.key);
  CHECK(Bytes(o4.established.ticket.begin(),
              o4.established.ticket.begin() + o4.established.ticket_size) == ticket);
  CHECK(initiator.initiator_in_flight() == 0 && responder.responder_in_flight() == 0);
}

keys::DecodeError decode_named(const std::string& codec, const Bytes& bytes) {
  const ByteView in{bytes.data(), bytes.size()};
  if (codec == "rlres1_r1") {
    rlres1::R1 m{};
    return rlres1::decode_r1(in, m);
  }
  if (codec == "rlres1_r2") {
    rlres1::R2 m{};
    return rlres1::decode_r2(in, m);
  }
  if (codec == "rlres1_r3") {
    rlres1::Mac m{};
    return rlres1::decode_r3(in, m);
  }
  if (codec == "authority_envelope") {
    keys::AuthorityEnvelopeHeader h{};
    return keys::authority_envelope_decode(in, h);
  }
  std::fprintf(stderr, "unknown invalid codec %s\n", codec.c_str());
  ++failures;
  return keys::DecodeError::None;
}

void test_valid_vectors() {
  std::size_t count = 0;
  std::size_t rlres1_count = 0;
  for (const auto& path : list("valid")) {
    const Fields f = parse_flat_json(read_text(path));
    const int before = failures;
    CHECK(f.at("format") == "routeloom-sdkv1-derivations-golden");
    const std::string& codec = f.at("codec");
    if (codec == "group") {
      check_group(f);
    } else if (codec == "aead_nonce") {
      check_nonce(f);
    } else if (codec == "authority_envelope") {
      check_envelope(f);
    } else if (codec == "rlres1_hint") {
      check_hint(f);
    } else if (codec == "rlres1") {
      check_rlres1_primitives(f);
      check_rlres1_engine(f);
      ++rlres1_count;
    } else if (codec == "dev") {
      check_dev(f);
    } else {
      std::fprintf(stderr, "unknown codec %s\n", codec.c_str());
      ++failures;
    }
    if (failures != before) std::fprintf(stderr, "  in %s\n", path.filename().c_str());
    ++count;
  }
  CHECK(count >= 15);
  CHECK(rlres1_count == 4);  // link, end, authority, pending-join
}

void test_invalid_vectors() {
  std::size_t count = 0;
  for (const auto& path : list("invalid")) {
    const Fields f = parse_flat_json(read_text(path));
    const keys::DecodeError got = decode_named(f.at("codec"), hex(f, "encoded_hex"));
    if (std::string(keys::decode_error_name(got)) != f.at("reason")) {
      std::fprintf(stderr, "%s: expected %s, got %s\n", path.filename().c_str(),
                   f.at("reason").c_str(), keys::decode_error_name(got));
      ++failures;
    }
    ++count;
  }
  CHECK(count >= 28);
}

void test_labels_and_bounds() {
  // The frozen label strings (a change here is a protocol change).
  CHECK(std::strcmp(keys::kLabelResumeKey, "RouteLoom/v1/resume-key") == 0);
  CHECK(std::strcmp(keys::kLabelGroupSalt, "RouteLoom/v1/group") == 0);
  keys::AeadNonce nonce{};
  const std::array<std::uint8_t, 12> iv{};
  CHECK(keys::aead_nonce(iv, keys::kMaxAeadCounter + 1, nonce).code ==
        routeloom::StatusCode::CounterExhausted);
  keys::AuthorityEnvelopeHeader h{};
  h.ctx_id = 0;
  std::array<std::uint8_t, 12> out{};
  CHECK(!keys::authority_envelope_header_encode(h, out).ok());
  h.ctx_id = 1;
  h.counter = keys::kMaxAeadCounter + 1;
  CHECK(!keys::authority_envelope_header_encode(h, out).ok());
  std::array<std::uint8_t, 16> mac{};
  const std::array<std::uint8_t, 40> too_long{};
  CHECK(!keys::resume_mac(ByteView{}, keys::kLabelResumeR1, ByteView{too_long.data(), too_long.size()},
                          ByteView{}, ByteView{}, mac)
             .ok());
  // Purposes separate keys: the same RMS/nonces under link vs end differ.
  const keys::Secret rms{};
  keys::ResumeId a{};
  keys::ResumeId b{};
  keys::resume_id(rms, keys::Purpose::Link, a);
  keys::resume_id(rms, keys::Purpose::End, b);
  CHECK(a != b);
  keys::Secret ka{};
  keys::Secret kb{};
  CHECK(keys::resume_auth_key(rms, keys::Purpose::Link, 1, 2, 3, ka).ok());
  CHECK(keys::resume_auth_key(rms, keys::Purpose::End, 1, 2, 3, kb).ok());
  CHECK(ka != kb);
}

}  // namespace

int main() {
  test_valid_vectors();
  test_invalid_vectors();
  test_labels_and_bounds();
  if (failures != 0) {
    std::fprintf(stderr, "%d key schedule check(s) failed\n", failures);
    return 1;
  }
  std::printf("key schedule golden vectors: all passed\n");
  return 0;
}
