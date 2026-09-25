#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include "routeloom/key_schedule.hpp"

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "failed: %s:%d: %s\n", __FILE__, __LINE__, #x); std::abort(); } } while (false)

int main() {
  routeloom::keys::Secret psk{};
  for (std::size_t i = 0; i < psk.size(); ++i) psk[i] = static_cast<std::uint8_t>(i);
  constexpr routeloom::NetworkId network = 0x1122334455667788ULL;
  constexpr routeloom::NodeId a = 0x1122, b = 0x3344;
  routeloom::keys::Secret rms{};
  CHECK(routeloom::keys::dev_pair_rms(psk, network, a, b, routeloom::keys::Purpose::Link, rms).ok());
  CHECK(rms == (routeloom::keys::Secret{0x74,0x7f,0x88,0x03,0x77,0x69,0x96,0xd4,
      0x8f,0x7c,0x34,0x64,0xbd,0x33,0x26,0xb8,0xc7,0x53,0x93,0x59,0x81,0x5a,
      0x95,0x82,0x33,0x3e,0xe2,0x68,0x50,0xc9,0xd6,0xeb}));
  auto same = rms;
  CHECK(routeloom::keys::dev_pair_rms(psk, network, b, a, routeloom::keys::Purpose::Link, same).ok());
  CHECK(same == rms);
  CHECK(routeloom::keys::dev_pair_rms(psk, network + (1ULL << 32), a, b,
                                      routeloom::keys::Purpose::Link, same).ok());
  CHECK(same != rms);
  CHECK(routeloom::keys::dev_pair_rms(psk, network, a, b,
                                      routeloom::keys::Purpose::End, same).ok());
  CHECK(same != rms);
  CHECK(routeloom::keys::dev_pair_rms(psk, network, a, a,
                                      routeloom::keys::Purpose::Link, same).code ==
        routeloom::StatusCode::InvalidArgument);
  CHECK(same == routeloom::keys::Secret{});
  routeloom::keys::TrafficKey group{};
  CHECK(routeloom::keys::dev_group_key(psk, network, a, 17, group).ok());
  CHECK(group.key == (std::array<std::uint8_t, 16>{0x51,0xa6,0x2d,0xf1,0x42,0x8e,0xd4,0xe0,
      0xf3,0x2d,0xa1,0xee,0xde,0xc4,0x20,0x70}));
  CHECK(group.iv == (std::array<std::uint8_t, 12>{0xa1,0x6a,0x44,0xb7,0xac,0x23,0x4a,0xf3,
      0x70,0xf6,0x2c,0x3d}));
  auto old = group;
  CHECK(routeloom::keys::dev_group_key(psk, network, a, 18, group).ok());
  CHECK(group.key != old.key && group.iv != old.iv);
  CHECK(routeloom::keys::dev_group_key(psk, network, b, 17, group).ok());
  CHECK(group.key != old.key);
  CHECK(routeloom::keys::dev_group_key(psk, network, a, 0, group).code ==
        routeloom::StatusCode::InvalidArgument);
  CHECK(group.key == (std::array<std::uint8_t, 16>{}));
  return 0;
}
