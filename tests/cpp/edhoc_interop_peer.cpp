// Cross-implementation EDHOC check: the device-side stack (vendored libedhoc
// v2.3.2 + routeloom::edhoc bounded backend) against the Site Authority's
// Rust implementation (host/routeloom-edhoc), method 0 / suite 2, the SDK v1
// join profile: kid-referenced RLCW1 credentials (kid = SHA-256 of the
// COSE_Key), JoinIntent / SiteOffer / JoinRequest / JoinResult EAD items and
// the certificate-by-value EAD items (docs/design/sdk-v1/08 P3-3).
//
// Two modes over one transcript file (protocol/edhoc-interop/):
//
//   --replay FILE
//       ctest. Direction a (this program = device/Initiator) and direction b
//       (this program = Site Authority/Responder) are re-run from the file's
//       inputs; every message this side composes must equal the recorded
//       bytes, every message the Rust side produced must be accepted, the
//       received EAD items must be the ones sent, and the Exporter output
//       (DAMS label 32771) must match. Ephemeral keys come from the file
//       through the session RNG; ES256 is deterministic on both sides, so
//       the transcript is reproducible byte for byte.
//
//   --live ROLE PREFIX FILE
//       Driven by the Rust test (`ROUTELOOM_EDHOC_PEER=... cargo test -p
//       routeloom-edhoc --test interop`): this side's messages are printed as
//       `m<n> <hex>` and the peer's are read from stdin in the same form.
//
// Test keys only (the transcript's keys are public test material).
//
// Under UBSan the vendored zcbor reports memmove(dst, NULL, 0) for the empty
// external_aad of message_3/message_4 (zcbor_encode.c str_encode) — the same
// recoverable upstream report documented in test_edhoc.cpp; it is left
// visible rather than suppressed.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "libedhoc_api.hpp"
#include "routeloom/edhoc.hpp"

namespace {

using routeloom::ByteView;
using routeloom::MutableByteView;
using routeloom::Status;
using routeloom::StatusCode;
namespace edhoc = routeloom::edhoc;
using Bytes = std::vector<std::uint8_t>;

struct EadToken {
  std::int32_t label{0};
  Bytes value;
};
using EadList = std::vector<EadToken>;

std::string to_hex(const std::uint8_t* data, const std::size_t size) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  for (std::size_t i = 0; i < size; ++i) {
    out.push_back(digits[data[i] >> 4]);
    out.push_back(digits[data[i] & 0x0F]);
  }
  return out;
}

std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }

bool from_hex(const std::string& text, Bytes& out) {
  out.clear();
  if (text.size() % 2 != 0) return false;
  for (std::size_t i = 0; i < text.size(); i += 2) {
    char* end = nullptr;
    const std::string pair = text.substr(i, 2);
    const unsigned long value = std::strtoul(pair.c_str(), &end, 16);
    if (end != pair.c_str() + 2) return false;
    out.push_back(static_cast<std::uint8_t>(value));
  }
  return true;
}

// `none` or `label:hex[,label:hex...]` (label as sent: negative = critical).
bool parse_ead(const std::string& text, EadList& out) {
  out.clear();
  if (text == "none") return true;
  std::stringstream stream(text);
  std::string item;
  while (std::getline(stream, item, ',')) {
    const std::size_t colon = item.find(':');
    if (colon == std::string::npos) return false;
    EadToken token;
    token.label = static_cast<std::int32_t>(std::stol(item.substr(0, colon)));
    if (!from_hex(item.substr(colon + 1), token.value)) return false;
    out.push_back(token);
  }
  return true;
}

std::string format_ead(const EadList& list) {
  if (list.empty()) return "none";
  std::string out;
  for (std::size_t i = 0; i < list.size(); ++i) {
    if (i != 0) out += ",";
    out += std::to_string(list[i].label) + ":" + to_hex(list[i].value);
  }
  return out;
}

using Fields = std::map<std::string, std::string>;

bool load(const char* path, Fields& out) {
  std::ifstream file(path);
  if (!file) return false;
  std::string line;
  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '#') continue;
    const std::size_t eq = line.find(" = ");
    if (eq == std::string::npos) continue;
    out[line.substr(0, eq)] = line.substr(eq + 3);
  }
  return true;
}

// --- one exchange ---------------------------------------------------------------

struct Party {
  Bytes kid;
  Bytes cred;
  Bytes priv;
  Bytes pub;
};

struct Inputs {
  Party local;
  Party peer;
  Bytes cid;        // own connection id
  Bytes ephemeral;  // own ephemeral scalar
  EadList send[4];  // EAD_1..EAD_4 this side composes (unused slots empty)
  EadList expect[4];
  std::uint64_t exporter_label{0};
  Bytes exporter_context;
};

class Credentials final : public edhoc::CredentialProvider {
 public:
  explicit Credentials(const Inputs& in) : in_(in) {}
  Status local(edhoc::Role, edhoc::LocalCredential& out) noexcept override {
    out.kid = ByteView{in_.local.kid.data(), in_.local.kid.size()};
    out.credential = ByteView{in_.local.cred.data(), in_.local.cred.size()};
    std::memcpy(out.private_key.data(), in_.local.priv.data(), out.private_key.size());
    return Status::success();
  }
  Status peer(edhoc::Role, const ByteView kid, edhoc::PeerCredential& out) noexcept override {
    if (kid.size != in_.peer.kid.size() ||
        std::memcmp(kid.data, in_.peer.kid.data(), kid.size) != 0) {
      return Status::error(StatusCode::NotFound, "unknown kid");
    }
    out.credential = ByteView{in_.peer.cred.data(), in_.peer.cred.size()};
    std::memcpy(out.public_key.data(), in_.peer.pub.data(), out.public_key.size());
    return Status::success();
  }

 private:
  const Inputs& in_;
};

struct ScriptedRandom {
  Bytes scalar;
  bool used{false};
};

bool scripted_random(void* ctx, std::uint8_t* out, const std::size_t size) noexcept {
  auto* rng = static_cast<ScriptedRandom*>(ctx);
  if (rng->used || rng->scalar.size() != size) return false;
  std::memcpy(out, rng->scalar.data(), size);
  rng->used = true;
  return true;
}

// libedhoc hands EAD callbacks the session's user context (the Session
// itself); this single-threaded program keeps its EAD state here instead.
struct EadState {
  const EadList* send{nullptr};
  EadList received[4];
};
EadState* g_ead = nullptr;

int ead_compose(void*, const edhoc_call_context* call, edhoc_ead_token* tokens,
                const std::size_t capacity, std::size_t* count) {
  const int index = static_cast<int>(call->message);
  const EadList& list = g_ead->send[index];
  if (list.size() > capacity) return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
  for (std::size_t i = 0; i < list.size(); ++i) {
    tokens[i].label = list[i].label;
    tokens[i].value.value = list[i].value.data();
    tokens[i].value.length = list[i].value.size();
  }
  *count = list.size();
  return EDHOC_SUCCESS;
}

int ead_process(void*, const edhoc_call_context* call, const edhoc_ead_token* tokens,
                const std::size_t count) {
  const int index = static_cast<int>(call->message);
  for (std::size_t i = 0; i < count; ++i) {
    EadToken token;
    token.label = tokens[i].label;
    token.value.assign(tokens[i].value.value, tokens[i].value.value + tokens[i].value.length);
    g_ead->received[index].push_back(token);
  }
  return EDHOC_SUCCESS;
}

const edhoc_ead kEad{&ead_compose, &ead_process};

// Where this side's messages go and the peer's come from.
class Io {
 public:
  virtual ~Io() = default;
  // Returns false to stop (mismatch or I/O failure).
  virtual bool mine(int n, const Bytes& message) = 0;
  virtual bool theirs(int n, Bytes& message) = 0;
  virtual bool exporter(const Bytes& output) = 0;
};

class ReplayIo final : public Io {
 public:
  ReplayIo(const Fields& fields, std::string prefix) : fields_(fields), prefix_(std::move(prefix)) {}
  bool mine(const int n, const Bytes& message) override {
    return compare("m" + std::to_string(n), message);
  }
  bool theirs(const int n, Bytes& message) override {
    return get("m" + std::to_string(n), message);
  }
  bool exporter(const Bytes& output) override { return compare("exporter", output); }

 private:
  bool get(const std::string& name, Bytes& out) const {
    const auto it = fields_.find(prefix_ + name);
    if (it == fields_.end() || !from_hex(it->second, out)) {
      std::fprintf(stderr, "transcript: missing %s%s\n", prefix_.c_str(), name.c_str());
      return false;
    }
    return true;
  }
  bool compare(const std::string& name, const Bytes& got) const {
    Bytes want;
    if (!get(name, want)) return false;
    if (want != got) {
      std::fprintf(stderr, "%s%s mismatch\n  want %s\n  got  %s\n", prefix_.c_str(),
                   name.c_str(), to_hex(want).c_str(), to_hex(got).c_str());
      return false;
    }
    return true;
  }
  const Fields& fields_;
  std::string prefix_;
};

class LiveIo final : public Io {
 public:
  bool mine(const int n, const Bytes& message) override {
    std::printf("m%d %s\n", n, to_hex(message).c_str());
    std::fflush(stdout);
    return true;
  }
  bool theirs(const int n, Bytes& message) override {
    std::string line;
    if (!std::getline(std::cin, line)) return false;
    const std::string head = "m" + std::to_string(n) + " ";
    if (line.compare(0, head.size(), head) != 0) return false;
    return from_hex(line.substr(head.size()), message);
  }
  bool exporter(const Bytes& output) override {
    std::printf("exporter %s\n", to_hex(output).c_str());
    std::fflush(stdout);
    return true;
  }
};

bool fail(const char* what, const Status& status, edhoc::Session& session) {
  std::fprintf(stderr, "%s failed: %s (libedhoc %d; arena high water %zu of %zu B, %zu failures)\n",
               what, status.detail != nullptr ? status.detail : "", session.last_error(),
               session.arena().high_water(), edhoc::Arena::kCapacity, session.arena().failures());
  return false;
}

bool run(const edhoc::Role role, const Inputs& in, Io& io) {
  Credentials credentials(in);
  ScriptedRandom rng{in.ephemeral, false};
  EadState ead;
  ead.send = in.send;
  g_ead = &ead;

  edhoc::SessionConfig config{};
  config.role = role;
  config.method = edhoc::Method::SignatureSignature;
  config.connection_id = ByteView{in.cid.data(), in.cid.size()};
  config.credentials = &credentials;
  config.random = &scripted_random;
  config.random_ctx = &rng;
  edhoc::Session session;
  Status status = session.begin(config);
  if (!status.ok()) return fail("begin", status, session);
  if (edhoc_bind_ead(session.native(), &kEad) != EDHOC_SUCCESS) {
    std::fprintf(stderr, "edhoc_bind_ead failed\n");
    return false;
  }
  std::uint8_t buffer[1024];
  std::size_t length = 0;
  const MutableByteView out{buffer, sizeof(buffer)};
  Bytes message;
  const auto own = [&](const int n) { return io.mine(n, Bytes(buffer, buffer + length)); };
  const auto theirs = [&](const int n) { return io.theirs(n, message); };
  if (role == edhoc::Role::Initiator) {
    if (!(status = session.compose_message_1(out, length)).ok()) return fail("m1", status, session);
    if (!own(1) || !theirs(2)) return false;
    if (!(status = session.process_message_2(ByteView{message.data(), message.size()})).ok())
      return fail("process m2", status, session);
    if (!(status = session.compose_message_3(out, length)).ok()) return fail("m3", status, session);
    if (!own(3) || !theirs(4)) return false;
    if (!(status = session.process_message_4(ByteView{message.data(), message.size()})).ok())
      return fail("process m4", status, session);
  } else {
    if (!theirs(1)) return false;
    if (!(status = session.process_message_1(ByteView{message.data(), message.size()})).ok())
      return fail("process m1", status, session);
    if (!(status = session.compose_message_2(out, length)).ok()) return fail("m2", status, session);
    if (!own(2) || !theirs(3)) return false;
    if (!(status = session.process_message_3(ByteView{message.data(), message.size()})).ok())
      return fail("process m3", status, session);
    if (!(status = session.compose_message_4(out, length)).ok()) return fail("m4", status, session);
    if (!own(4)) return false;
  }
  Bytes exported(32);
  status = session.exporter(in.exporter_label,
                            ByteView{in.exporter_context.data(), in.exporter_context.size()},
                            MutableByteView{exported.data(), exported.size()});
  if (!status.ok()) return fail("exporter", status, session);
  if (!io.exporter(exported)) return false;
  std::fprintf(stderr, "%s: arena high water %zu of %zu B, %zu blocks; key slots high water %zu\n",
               role == edhoc::Role::Initiator ? "initiator" : "responder",
               session.arena().high_water(), edhoc::Arena::kCapacity,
               session.arena().max_live_blocks(), session.keys().high_water());
  bool ok = true;
  for (int i = 0; i < 4; ++i) {
    if (format_ead(ead.received[i]) != format_ead(in.expect[i])) {
      std::fprintf(stderr, "EAD_%d received %s, expected %s\n", i + 1,
                   format_ead(ead.received[i]).c_str(), format_ead(in.expect[i]).c_str());
      ok = false;
    }
  }
  g_ead = nullptr;
  return ok;
}

// Builds the inputs of one side of direction `prefix` ("a_" or "b_").
bool inputs(const Fields& f, const std::string& prefix, const edhoc::Role role, Inputs& in) {
  const auto hex = [&](const std::string& name, Bytes& out) {
    const auto it = f.find(name);
    if (it == f.end() || !from_hex(it->second, out)) {
      std::fprintf(stderr, "missing or bad %s\n", name.c_str());
      return false;
    }
    return true;
  };
  const auto ead = [&](const std::string& name, EadList& out) {
    const auto it = f.find(name);
    if (it == f.end() || !parse_ead(it->second, out)) {
      std::fprintf(stderr, "missing or bad %s\n", name.c_str());
      return false;
    }
    return true;
  };
  const bool initiator = role == edhoc::Role::Initiator;
  const std::string self = initiator ? "device_" : "authority_";
  const std::string other = initiator ? "authority_" : "device_";
  Bytes label;
  bool ok = hex(self + "kid", in.local.kid) && hex(self + "cred", in.local.cred) &&
            hex(self + "priv", in.local.priv) && hex(other + "kid", in.peer.kid) &&
            hex(other + "cred", in.peer.cred) && hex(other + "pub", in.peer.pub) &&
            hex(prefix + (initiator ? "c_i" : "c_r"), in.cid) &&
            hex(prefix + (initiator ? "x" : "y"), in.ephemeral) &&
            hex("exporter_context", in.exporter_context);
  EadList all[4];
  for (int i = 0; i < 4 && ok; ++i) ok = ead(prefix + "ead" + std::to_string(i + 1), all[i]);
  if (!ok) return false;
  for (int i = 0; i < 4; ++i) {
    // The Initiator composes EAD_1/EAD_3, the Responder EAD_2/EAD_4.
    const bool composes = (i % 2 == 0) == initiator;
    (composes ? in.send[i] : in.expect[i]) = all[i];
  }
  const auto label_it = f.find("exporter_label");
  if (label_it == f.end()) return false;
  in.exporter_label = std::stoull(label_it->second);
  return in.local.priv.size() == 32 && in.peer.pub.size() == 64 && in.ephemeral.size() == 32;
}

}  // namespace

int main(const int argc, char** argv) {
  if (argc == 3 && std::strcmp(argv[1], "--replay") == 0) {
    Fields fields;
    if (!load(argv[2], fields)) {
      std::fprintf(stderr, "cannot read %s\n", argv[2]);
      return 1;
    }
    int failures = 0;
    for (const auto& [prefix, role] :
         {std::pair<std::string, edhoc::Role>{"a_", edhoc::Role::Initiator},
          std::pair<std::string, edhoc::Role>{"b_", edhoc::Role::Responder}}) {
      Inputs in;
      ReplayIo io(fields, prefix);
      if (!inputs(fields, prefix, role, in) || !run(role, in, io)) {
        std::fprintf(stderr, "direction %s failed\n", prefix.c_str());
        ++failures;
      } else {
        std::printf("direction %s: libedhoc %s agrees with the transcript byte for byte\n",
                    prefix.c_str(), role == edhoc::Role::Initiator ? "Initiator" : "Responder");
      }
    }
    return failures == 0 ? 0 : 1;
  }
  if (argc == 5 && std::strcmp(argv[1], "--live") == 0) {
    const bool initiator = std::strcmp(argv[2], "initiator") == 0;
    const edhoc::Role role = initiator ? edhoc::Role::Initiator : edhoc::Role::Responder;
    Fields fields;
    Inputs in;
    LiveIo io;
    if (!load(argv[4], fields) || !inputs(fields, argv[3], role, in)) return 2;
    if (!run(role, in, io)) {
      std::printf("fail\n");
      return 1;
    }
    std::printf("ok\n");
    return 0;
  }
  std::fprintf(stderr, "usage: %s --replay FILE | --live initiator|responder PREFIX FILE\n",
               argv[0]);
  return 2;
}
