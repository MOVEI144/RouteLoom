// HKDF-SHA-256 tests (docs/design/sdk-v1/03-key-hierarchy.md §3): the three
// RFC 5869 Appendix A SHA-256 test cases (PRK and OKM), plus the argument
// refusals. The RouteLoom derivation labels are not tested here — they are
// not frozen yet (sdk-v1/08-implementation-plan.md P1).

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "routeloom/kdf.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

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
using routeloom::ScopeDigest;
using routeloom::StatusCode;

std::vector<std::uint8_t> hex(const std::string& text) {
  std::vector<std::uint8_t> out;
  for (std::size_t i = 0; i + 1 < text.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
  }
  return out;
}

std::vector<std::uint8_t> range(unsigned first, unsigned last_inclusive) {
  std::vector<std::uint8_t> out;
  for (unsigned v = first; v <= last_inclusive; ++v) {
    out.push_back(static_cast<std::uint8_t>(v));
  }
  return out;
}

ByteView view(const std::vector<std::uint8_t>& v) { return ByteView{v.data(), v.size()}; }

struct Case {
  const char* name;
  std::vector<std::uint8_t> ikm;
  std::vector<std::uint8_t> salt;
  std::vector<std::uint8_t> info;
  std::size_t length;
  std::string prk;
  std::string okm;
};

void run_case(const Case& c) {
  ScopeDigest prk{};
  routeloom::hkdf_sha256_extract(view(c.salt), view(c.ikm), prk);
  CHECK(std::vector<std::uint8_t>(prk.begin(), prk.end()) == hex(c.prk));

  std::vector<std::uint8_t> okm(c.length, 0xAA);
  CHECK(routeloom::hkdf_sha256_expand(ByteView{prk.data(), prk.size()}, view(c.info),
                                      MutableByteView{okm.data(), okm.size()})
            .ok());
  CHECK(okm == hex(c.okm));

  std::vector<std::uint8_t> one_shot(c.length, 0x55);
  CHECK(routeloom::hkdf_sha256(view(c.salt), view(c.ikm), view(c.info),
                               MutableByteView{one_shot.data(), one_shot.size()})
            .ok());
  CHECK(one_shot == hex(c.okm));
  if (failures != 0) std::fprintf(stderr, "  in %s\n", c.name);
}

void test_rfc5869_vectors() {
  // RFC 5869 Appendix A.1 — basic.
  run_case(Case{"A.1", std::vector<std::uint8_t>(22, 0x0b), range(0x00, 0x0c),
                range(0xf0, 0xf9), 42,
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865"});
  // A.2 — longer inputs/outputs (three T blocks, 82 bytes).
  run_case(Case{"A.2", range(0x00, 0x4f), range(0x60, 0xaf), range(0xb0, 0xff), 82,
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                "cc30c58179ec3e87c14c01d5c1f3434f1d87"});
  // A.3 — zero-length salt and info.
  run_case(Case{"A.3", std::vector<std::uint8_t>(22, 0x0b), {}, {}, 42,
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                "9d201395faa4b61a96c8"});
}

void test_refusals() {
  const std::array<std::uint8_t, 32> prk{};
  std::array<std::uint8_t, 16> out{};

  // PRK shorter than HashLen: refused, output zero-filled (never partial).
  out.fill(0xEE);
  const auto short_prk = routeloom::hkdf_sha256_expand(
      ByteView{prk.data(), 31}, ByteView{}, MutableByteView{out.data(), out.size()});
  CHECK(!short_prk.ok() && short_prk.code == StatusCode::InvalidArgument);
  bool zero = true;
  for (auto b : out) zero = zero && b == 0;
  CHECK(zero);

  // Empty / oversized / null output.
  CHECK(!routeloom::hkdf_sha256_expand(ByteView{prk.data(), prk.size()}, ByteView{},
                                       MutableByteView{out.data(), 0})
             .ok());
  CHECK(!routeloom::hkdf_sha256_expand(ByteView{prk.data(), prk.size()}, ByteView{},
                                       MutableByteView{nullptr, 16})
             .ok());
  std::vector<std::uint8_t> huge(routeloom::kHkdfSha256OutputMax + 1);
  CHECK(!routeloom::hkdf_sha256_expand(ByteView{prk.data(), prk.size()}, ByteView{},
                                       MutableByteView{huge.data(), huge.size()})
             .ok());
  // The exact RFC maximum (255 blocks) is accepted.
  std::vector<std::uint8_t> max(routeloom::kHkdfSha256OutputMax);
  CHECK(routeloom::hkdf_sha256_expand(ByteView{prk.data(), prk.size()}, ByteView{},
                                      MutableByteView{max.data(), max.size()})
            .ok());
  // Null info pointer with a nonzero length is refused.
  CHECK(!routeloom::hkdf_sha256_expand(ByteView{prk.data(), prk.size()},
                                       ByteView{nullptr, 4},
                                       MutableByteView{out.data(), out.size()})
             .ok());

  // Output prefix property: a shorter OKM is a prefix of a longer one.
  std::array<std::uint8_t, 16> a{};
  std::array<std::uint8_t, 48> b{};
  const std::array<std::uint8_t, 3> info{{'r', 'l', '1'}};
  CHECK(routeloom::hkdf_sha256_expand(ByteView{prk.data(), prk.size()},
                                      ByteView{info.data(), info.size()},
                                      MutableByteView{a.data(), a.size()})
            .ok());
  CHECK(routeloom::hkdf_sha256_expand(ByteView{prk.data(), prk.size()},
                                      ByteView{info.data(), info.size()},
                                      MutableByteView{b.data(), b.size()})
            .ok());
  bool prefix = true;
  for (std::size_t i = 0; i < a.size(); ++i) prefix = prefix && a[i] == b[i];
  CHECK(prefix);
}

}  // namespace

int main() {
  test_rfc5869_vectors();
  test_refusals();
  if (failures != 0) {
    std::fprintf(stderr, "%d kdf check(s) failed\n", failures);
    return 1;
  }
  std::printf("kdf tests passed\n");
  return 0;
}
