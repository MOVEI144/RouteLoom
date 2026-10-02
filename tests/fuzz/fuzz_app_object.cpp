#include <array>
#include <cstdlib>
#include <cstring>
#include "routeloom/app_object_wire.hpp"
#include "routeloom/object_assembler.hpp"
#include "fuzz_driver.hpp"
namespace {
template<class T> void check(routeloom::ByteView bytes) {
  T value{};
  if (!routeloom::object_wire::decode(bytes, value)) return;
  std::array<std::uint8_t, 128> out{}; std::size_t size = 0;
  if (!routeloom::object_wire::encode(value, {out.data(), out.size()}, size) ||
      size != bytes.size || std::memcmp(out.data(), bytes.data, size) != 0) std::abort();
}
}
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const routeloom::ByteView bytes{data + 1, size - 1};
  switch (data[0] % 4) {
    case 0: check<routeloom::object_wire::Start>(bytes); break;
    case 1: check<routeloom::object_wire::Chunk>(bytes); break;
    case 2: check<routeloom::object_wire::Ack>(bytes); break;
    case 3: {
      std::array<std::uint8_t, 4096> storage{}; std::array<std::uint8_t, 8> bitmap{};
      routeloom::ObjectAssembler assembly;
      (void)assembly.begin({storage.data(), storage.size()}, {bitmap.data(), bitmap.size()}, 4096, 121, 100);
      routeloom::object_wire::Chunk chunk{};
      if (routeloom::object_wire::decode(bytes, chunk)) {
        const auto offset = static_cast<std::uint16_t>(chunk.index * 121);
        if (assembly.insert(offset, chunk.data, 1)) {
          const auto before = assembly.received();
          if (!assembly.insert(offset, chunk.data, 99) || before != assembly.received()) std::abort();
        }
      }
      assembly.reset(); break;
    }
  }
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
