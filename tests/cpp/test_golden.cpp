// Shared golden-vector harness for the frozen Wire v1 codec. Loads the same
// protocol/golden/*.json files as the Rust routeloom-wire tests and asserts
// byte-for-byte encode and decode equivalence, plus a seeded mutation loop
// that must never crash and must always return a defined Status.

#include <algorithm>
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

#include "routeloom/wire.hpp"

#include "test_security.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::TestSecurity;

#ifndef ROUTELOOM_GOLDEN_DIR
#define ROUTELOOM_GOLDEN_DIR "protocol/golden"
#endif

using Fields = std::map<std::string, std::string>;

// Minimal extractor for the flat "key": value objects used by the golden
// files. Values may be strings or unsigned integers; no nesting or escapes.
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
      while (value_end < text.size() &&
             (std::isdigit(static_cast<unsigned char>(text[value_end])) || text[value_end] == '-')) {
        ++value_end;
      }
      value = text.substr(cursor, value_end - cursor);
      pos = value_end;
    }
    fields[text.substr(key_begin + 1, key_end - key_begin - 1)] = value;
  }
  return fields;
}

std::uint64_t field_u64(const Fields& fields, const char* key, bool& present) {
  const auto it = fields.find(key);
  if (it == fields.end() || it->second.empty()) {
    present = false;
    return 0;
  }
  return std::strtoull(it->second.c_str(), nullptr, 10);
}

int hex_value(const char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool hex_decode(const std::string& hex, std::vector<std::uint8_t>& out) {
  if (hex.size() % 2 != 0) return false;
  out.clear();
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int high = hex_value(hex[i]);
    const int low = hex_value(hex[i + 1]);
    if (high < 0 || low < 0) return false;
    out.push_back(static_cast<std::uint8_t>(high * 16 + low));
  }
  return true;
}

std::string read_file(const std::filesystem::path& path, bool& ok) {
  std::ifstream input(path, std::ios::binary);
  std::ostringstream contents;
  contents << input.rdbuf();
  ok = input.good() || input.eof();
  return contents.str();
}

std::vector<std::filesystem::path> list_json(const std::filesystem::path& dir) {
  std::vector<std::filesystem::path> files;
  if (!std::filesystem::is_directory(dir)) return files;
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (entry.path().extension() == ".json") files.push_back(entry.path());
  }
  std::sort(files.begin(), files.end());
  return files;
}

void check_header(const wire::Header& header, const Fields& fields, const char* name) {
  bool present = true;
  const auto at = [&](const char* key) { return field_u64(fields, key, present); };
  CHECK(static_cast<std::uint8_t>(header.type) == at("type"));
  CHECK(header.flags == at("flags"));
  CHECK(static_cast<std::uint8_t>(header.delivery) == at("delivery"));
  CHECK(header.delivery_round == at("delivery_round"));
  CHECK(header.hop_remaining == at("hop_remaining"));
  CHECK(header.network == at("network"));
  CHECK(header.origin == at("origin"));
  CHECK(header.destination == at("destination"));
  CHECK(header.previous_hop == at("previous_hop"));
  CHECK(header.next_hop == at("next_hop"));
  CHECK(header.message.session == at("session"));
  CHECK(header.message.sequence == at("sequence"));
  CHECK(header.remaining_deadline_ms == at("remaining_deadline_ms"));
  CHECK(header.original_lifetime_ms == at("original_lifetime_ms"));
  CHECK(header.link_epoch == at("link_epoch"));
  CHECK(header.end_epoch == at("end_epoch"));
  if (!present) std::fprintf(stderr, "missing header field in vector %s\n", name);
  CHECK(present);
}

bool same_bytes(const std::vector<std::uint8_t>& expected, const ByteView actual) {
  return expected.size() == actual.size &&
         (expected.empty() || std::memcmp(expected.data(), actual.data, actual.size) == 0);
}

void run_valid_vector(const std::filesystem::path& path) {
  bool ok = false;
  const Fields fields = parse_flat_json(read_file(path, ok));
  CHECK(ok);
  const std::string name = fields.count("name") != 0U ? fields.at("name") : path.filename().string();
  bool present = true;
  const auto at = [&](const char* key) { return field_u64(fields, key, present); };

  wire::PlainFrame plain{};
  plain.header.type = static_cast<FrameType>(at("type"));
  plain.header.flags = static_cast<std::uint8_t>(at("flags"));
  plain.header.delivery = static_cast<DeliveryClass>(at("delivery"));
  plain.header.delivery_round = static_cast<std::uint8_t>(at("delivery_round"));
  plain.header.hop_remaining = static_cast<std::uint8_t>(at("hop_remaining"));
  plain.header.network = at("network");
  plain.header.origin = at("origin");
  plain.header.destination = at("destination");
  plain.header.previous_hop = at("previous_hop");
  plain.header.next_hop = at("next_hop");
  plain.header.message = MessageId{static_cast<std::uint32_t>(at("session")), at("sequence")};
  plain.header.remaining_deadline_ms = static_cast<std::uint32_t>(at("remaining_deadline_ms"));
  plain.header.original_lifetime_ms = static_cast<std::uint32_t>(at("original_lifetime_ms"));
  plain.header.link_epoch = static_cast<std::uint16_t>(at("link_epoch"));
  plain.header.end_epoch = static_cast<std::uint16_t>(at("end_epoch"));
  std::vector<std::uint8_t> payload;
  CHECK(fields.count("payload_hex") != 0U && hex_decode(fields.at("payload_hex"), payload));
  CHECK(payload.size() <= kMaxApplicationPayload);
  plain.payload_size = payload.size();
  if (!payload.empty()) std::memcpy(plain.payload.data(), payload.data(), payload.size());
  std::vector<std::uint8_t> encoded;
  CHECK(fields.count("encoded_hex") != 0U && hex_decode(fields.at("encoded_hex"), encoded));
  if (!present) std::fprintf(stderr, "incomplete vector %s\n", name.c_str());
  CHECK(present);

  // Encode must reproduce the golden bytes exactly (fresh provider, counter 0).
  TestSecurity encode_security;
  wire::EncodedFrame produced{};
  CHECK_OK(wire::encode_new(plain, encode_security, produced));
  CHECK(produced.size <= kMaxEspNowBody);
  CHECK(same_bytes(encoded, produced.view()));

  // Decode at the addressed hop must recover header and protected payload.
  TestSecurity decode_security;
  wire::LinkOpenedFrame opened{};
  const NodeId receiver = plain.header.next_hop;
  CHECK_OK(wire::open_link(ByteView{encoded.data(), encoded.size()}, receiver,
                         decode_security, opened));
  check_header(opened.header, fields, name.c_str());

  if (plain.header.destination == receiver) {
    TestSecurity end_security;
    wire::PlainFrame out{};
    CHECK_OK(wire::open_end(opened, plain.header.destination, end_security, out));
    CHECK(out.payload_size == payload.size());
    CHECK(payload.empty() ||
          std::memcmp(out.payload.data(), payload.data(), payload.size()) == 0);
  } else {
    TestSecurity end_security;
    wire::PlainFrame out{};
    CHECK(wire::open_end(opened, receiver, end_security, out).code ==
          StatusCode::AuthorizationFailed);
  }

  // Optional second hop: the relay re-wraps the link layer only.
  if (fields.count("fwd_encoded_hex") != 0U) {
    const NodeId forwarder = at("fwd_local_node");
    const NodeId forward_next = at("fwd_next_hop");
    const auto forward_budget = static_cast<std::uint32_t>(at("fwd_remaining_deadline_ms"));
    std::vector<std::uint8_t> expected_fwd;
    CHECK(hex_decode(fields.at("fwd_encoded_hex"), expected_fwd));
    CHECK(present);
    TestSecurity forward_security;
    wire::EncodedFrame forwarded{};
    CHECK_OK(wire::forward(opened, forwarder, forward_next, forward_budget,
                           forward_security, forwarded));
    CHECK(same_bytes(expected_fwd, forwarded.view()));

    TestSecurity next_security;
    wire::LinkOpenedFrame at_next{};
    CHECK_OK(wire::open_link(ByteView{expected_fwd.data(), expected_fwd.size()}, forward_next,
                             next_security, at_next));
    CHECK(at_next.header.previous_hop == forwarder);
    CHECK(at_next.header.next_hop == forward_next);
    CHECK(at_next.header.hop_remaining + 1 == plain.header.hop_remaining);
    // End-immutable fields survive the hop rewrite.
    CHECK(at_next.header.origin == plain.header.origin &&
          at_next.header.destination == plain.header.destination &&
          at_next.header.message == plain.header.message &&
          at_next.header.end_counter == plain.header.end_counter);
    if (plain.header.destination == forward_next) {
      TestSecurity end_security;
      wire::PlainFrame out{};
      CHECK_OK(wire::open_end(at_next, plain.header.destination, end_security, out));
      CHECK(out.payload_size == payload.size());
      CHECK(payload.empty() ||
            std::memcmp(out.payload.data(), payload.data(), payload.size()) == 0);
    }
  }
}

void run_invalid_vector(const std::filesystem::path& path) {
  bool ok = false;
  const Fields fields = parse_flat_json(read_file(path, ok));
  CHECK(ok);
  const std::string name = fields.count("name") != 0U ? fields.at("name") : path.filename().string();
  std::vector<std::uint8_t> encoded;
  CHECK(fields.count("encoded_hex") != 0U && hex_decode(fields.at("encoded_hex"), encoded));
  bool present = true;
  const NodeId local = field_u64(fields, "local_node", present);
  CHECK(fields.count("expect") != 0U);
  const std::string expect = fields.count("expect") != 0U ? fields.at("expect") : "";

  TestSecurity security;
  wire::LinkOpenedFrame opened{};
  const Status status =
      wire::open_link(ByteView{encoded.data(), encoded.size()}, local, security, opened);
  if (expect == "link") {
    if (status.ok()) std::fprintf(stderr, "invalid vector %s unexpectedly decoded\n", name.c_str());
    CHECK(!status);
  } else if (expect == "end") {
    // The link layer is intact; only the end-to-end tag must fail.
    CHECK_OK(status);
    const NodeId end_node = field_u64(fields, "end_node", present);
    wire::PlainFrame out{};
    CHECK(!wire::open_end(opened, end_node, security, out));
  } else {
    std::fprintf(stderr, "invalid vector %s has unknown expect=%s\n", name.c_str(), expect.c_str());
    CHECK(false);
  }
  CHECK(present);
}

std::uint64_t rng_state = 0x005eed5eed5eed00ULL;
std::uint64_t next_random() {
  rng_state += 0x9e3779b97f4a7c15ULL;  // splitmix64
  std::uint64_t z = rng_state;
  z = (z ^ (z >> 30U)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27U)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31U);
}

void run_mutation_loop(const std::vector<std::vector<std::uint8_t>>& bases,
                       const std::vector<NodeId>& locals, const int iterations) {
  int decoded = 0;
  int rejected = 0;
  for (int i = 0; i < iterations; ++i) {
    const std::size_t base = next_random() % bases.size();
    std::vector<std::uint8_t> mutated = bases[base];
    const int ops = 1 + static_cast<int>(next_random() % 4);
    for (int op = 0; op < ops; ++op) {
      switch (next_random() % 4) {
        case 0:
          mutated[next_random() % mutated.size()] ^=
              static_cast<std::uint8_t>(1U << (next_random() % 8));
          break;
        case 1:
          mutated[next_random() % mutated.size()] = static_cast<std::uint8_t>(next_random());
          break;
        case 2:
          mutated.resize(1 + next_random() % mutated.size());
          break;
        default:
          mutated.push_back(static_cast<std::uint8_t>(next_random()));
          break;
      }
    }
    const NodeId local = next_random() % 4 == 0 ? NodeId(next_random() % 8 + 1) : locals[base];
    TestSecurity security;
    wire::LinkOpenedFrame opened{};
    const Status status =
        wire::open_link(ByteView{mutated.data(), mutated.size()}, local, security, opened);
    if (status.ok()) {
      ++decoded;
      wire::PlainFrame out{};
      (void)wire::open_end(opened, opened.header.destination, security, out);
    } else {
      ++rejected;
    }
  }
  std::printf("mutation loop: %d decoded, %d rejected of %d\n", decoded, rejected, iterations);
  CHECK(rejected > 0);
}

}  // namespace

int main() {
  const std::filesystem::path golden_dir(ROUTELOOM_GOLDEN_DIR);
  const auto valid_files = list_json(golden_dir / "valid");
  const auto invalid_files = list_json(golden_dir / "invalid");
  CHECK(valid_files.size() >= 6);
  CHECK(invalid_files.size() >= 7);

  std::vector<std::vector<std::uint8_t>> bases;
  std::vector<NodeId> locals;
  for (const auto& path : valid_files) {
    run_valid_vector(path);
    bool ok = false;
    const Fields fields = parse_flat_json(read_file(path, ok));
    std::vector<std::uint8_t> encoded;
    bool present = true;
    const NodeId local = field_u64(fields, "next_hop", present);
    if (fields.count("encoded_hex") != 0U && hex_decode(fields.at("encoded_hex"), encoded) &&
        !encoded.empty()) {
      bases.push_back(encoded);
      locals.push_back(local);
    }
  }
  for (const auto& path : invalid_files) run_invalid_vector(path);

  CHECK(!bases.empty());
  run_mutation_loop(bases, locals, 4000);

  if (failures != 0) {
    std::fprintf(stderr, "%d golden checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom wire v1 golden tests passed");
  return 0;
}
