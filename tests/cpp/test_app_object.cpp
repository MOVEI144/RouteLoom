#include <array>
#include <cassert>
#include <fstream>
#include <string>
#include <vector>
#include "routeloom/app_object_wire.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/object_assembler.hpp"

using namespace routeloom;
namespace {
std::vector<std::uint8_t> golden(const char* name) {
  std::ifstream in(std::string(ROUTELOOM_OBJECT_GOLDEN_DIR) + "/" + name + ".hex");
  assert(in.good());
  std::vector<std::uint8_t> bytes; std::string word;
  while (in >> word) bytes.push_back(static_cast<std::uint8_t>(std::stoul(word, nullptr, 16)));
  return bytes;
}
template<class T> void roundtrip(const char* name) {
  const auto bytes = golden(name); T value{};
  assert(object_wire::decode({bytes.data(), bytes.size()}, value));
  std::array<std::uint8_t, 128> out{}; std::size_t size = 0;
  assert(object_wire::encode(value, {out.data(), out.size()}, size));
  assert(size == bytes.size() && std::equal(bytes.begin(), bytes.end(), out.begin()));
  auto bad = bytes; bad[0] = 2;
  assert(!object_wire::decode({bad.data(), bad.size()}, value));
  assert(!object_wire::decode({bytes.data(), bytes.size() - 1}, value));
}
}
int main() {
  roundtrip<object_wire::Start>("start"); roundtrip<object_wire::Chunk>("chunk");
  roundtrip<object_wire::Ack>("ack");
  std::array<std::uint8_t, 4096> storage{}, data{}; std::array<std::uint8_t, 8> bitmap{};
  for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i % 251);
  ObjectAssembler assembly;
  for (const std::uint16_t total : {1, 121, 122, 2048, 4096}) {
    assert(assembly.begin({storage.data(), storage.size()}, {bitmap.data(), bitmap.size()}, total, 121, 100));
    const auto chunks = (total + 120) / 121;
    for (int i = chunks - 1; i >= 0; --i) {
      const auto offset = static_cast<std::uint16_t>(i * 121);
      const auto count = static_cast<std::size_t>(std::min<int>(121, total - offset));
      assert(assembly.insert(offset, {data.data() + offset, count}, 1));
      const auto progress = assembly.received();
      assert(assembly.insert(offset, {data.data() + offset, count}, 99));
      assert(assembly.received() == progress);
    }
    assert(assembly.complete()); ScopeDigest digest{}; sha256({data.data(), total}, digest);
    assert(assembly.verify({digest.data(), 16})); digest[0] ^= 1;
    assert(assembly.verify({digest.data(), 16}).code == StatusCode::IntegrityError);
    auto conflict = data; conflict[0] ^= 1;
    assert(assembly.insert(0, {conflict.data(), static_cast<std::size_t>(std::min<int>(total, 121))}, 99).code == StatusCode::Conflict);
    assert(assembly.insert(0, {data.data(), static_cast<std::size_t>(std::min<int>(total, 121))}, 100).code == StatusCode::Expired);
    assert(storage[0] == data[0]); assembly.reset();
    for (std::uint16_t i = 0; i < total; ++i) assert(storage[i] == 0);
  }
  assert(!assembly.begin({storage.data(), storage.size()}, {bitmap.data(), bitmap.size()}, 4097, 121, 100));
}
