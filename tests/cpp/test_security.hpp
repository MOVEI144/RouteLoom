#pragma once

// Deterministic test cipher shared by the C++ unit tests and the golden-vector
// harness. It is NOT a production AEAD: it exists so that C++ and Rust produce
// byte-identical ciphertext for cross-language wire vectors. The Rust port lives
// in host/routeloom-wire/src/test_security.rs and must stay byte-for-byte
// equivalent.

#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <tuple>

#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom_test {

inline std::uint64_t mix(std::uint64_t state, std::uint64_t value) {
  state ^= value + 0x9e3779b97f4a7c15ULL + (state << 6U) + (state >> 2U);
  state *= 0xbf58476d1ce4e5b9ULL;
  return state;
}

class TestSecurity final : public routeloom::SecurityProvider {
 public:
  bool ready() const noexcept override { return true; }

  // P5-2 broadcast stand-in for the GK/boot snapshot: nonzero by default,
  // AuthRequired when either is cleared (unknown GK on the TX side).
  routeloom::Status tx_group_link_epochs(std::uint32_t& boot,
                                         std::uint32_t& g) noexcept override {
    if (group_link_boot_ == 0 || group_link_g_ == 0) {
      return routeloom::Status::error(routeloom::StatusCode::AuthRequired,
                                      "test GroupLink epochs unavailable");
    }
    boot = group_link_boot_;
    g = group_link_g_;
    return routeloom::Status::success();
  }
  // Unknown-GK stand-in on the RX side: flip off to refuse every group
  // epoch (the tag still opens — the cipher has no keys — but the node
  // must drop the frame before any route use).
  bool accepts_group_epoch(std::uint32_t /*g*/) const noexcept override {
    return accept_group_epoch_;
  }
  void set_group_link_epochs(std::uint32_t boot, std::uint32_t g) noexcept {
    group_link_boot_ = boot;
    group_link_g_ = g;
  }
  void set_accept_group_epoch(bool accept) noexcept { accept_group_epoch_ = accept; }

  routeloom::Status next_counter(const routeloom::SecurityContext& context,
                                 std::uint64_t& counter) noexcept override {
    auto key = std::make_tuple(static_cast<int>(context.scope), context.network,
                               context.sender, context.receiver, context.epoch);
    counter = counters_[key]++;
    return routeloom::Status::success();
  }

  routeloom::Status seal(const routeloom::SecurityContext& context,
                         const std::uint64_t counter,
                         const routeloom::ByteView aad,
                         const routeloom::ByteView plaintext,
                         const routeloom::MutableByteView ciphertext,
                         std::array<std::uint8_t, routeloom::kAeadTagSize>& tag) noexcept override {
    if (ciphertext.size < plaintext.size) {
      return routeloom::Status::error(routeloom::StatusCode::NoCapacity, "test ciphertext");
    }
    auto state = seed(context, counter);
    for (std::size_t i = 0; i < plaintext.size; ++i) {
      state = mix(state, i + 1);
      ciphertext.data[i] = plaintext.data[i] ^ static_cast<std::uint8_t>(state >> 56U);
    }
    make_tag(context, counter, aad, routeloom::ByteView{ciphertext.data, plaintext.size}, tag);
    return routeloom::Status::success();
  }

  routeloom::Status open(const routeloom::SecurityContext& context,
                         const std::uint64_t counter,
                         const routeloom::ByteView aad,
                         const routeloom::ByteView ciphertext,
                         const std::array<std::uint8_t, routeloom::kAeadTagSize>& tag,
                         const routeloom::MutableByteView plaintext) noexcept override {
    if (plaintext.size < ciphertext.size) {
      return routeloom::Status::error(routeloom::StatusCode::NoCapacity, "test plaintext");
    }
    std::array<std::uint8_t, routeloom::kAeadTagSize> expected{};
    make_tag(context, counter, aad, ciphertext, expected);
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < tag.size(); ++i) diff |= expected[i] ^ tag[i];
    if (diff != 0) {
      return routeloom::Status::error(routeloom::StatusCode::AuthenticationFailed,
                                    "test tag mismatch");
    }
    if (context.scope == routeloom::SecurityScope::Group ||
        context.scope == routeloom::SecurityScope::GroupLink) {
      // Group/GroupLink scope replay (group-delivery.md §7): per (sender,
      // domain, epoch) a counter opens once — the node must dedup a group
      // message on its header BEFORE opening it, so a second open of the
      // same bytes is a defect.
      const auto replay_key = std::make_tuple(context.network, context.sender,
                                              context.receiver, context.epoch, counter);
      if (!group_accepted_.insert(replay_key).second) {
        ++group_replays_;
        return routeloom::Status::error(routeloom::StatusCode::ReplayRejected,
                                        "test group replay");
      }
    }
    auto state = seed(context, counter);
    for (std::size_t i = 0; i < ciphertext.size; ++i) {
      state = mix(state, i + 1);
      plaintext.data[i] = ciphertext.data[i] ^ static_cast<std::uint8_t>(state >> 56U);
    }
    return routeloom::Status::success();
  }

  // Group-scope opens refused as replays (tests assert this stays 0 on the
  // node path: dedup precedes every group open).
  std::uint64_t group_replays() const noexcept { return group_replays_; }

 private:
  std::set<std::tuple<routeloom::NetworkId, routeloom::NodeId, routeloom::NodeId,
                      std::uint32_t, std::uint64_t>>
      group_accepted_{};
  std::uint64_t group_replays_{0};
  std::uint32_t group_link_boot_{1};
  std::uint32_t group_link_g_{1};
  bool accept_group_epoch_{true};
  using Key = std::tuple<int, routeloom::NetworkId, routeloom::NodeId, routeloom::NodeId,
                         std::uint16_t>;
  std::map<Key, std::uint64_t> counters_{};

  static std::uint64_t seed(const routeloom::SecurityContext& context, std::uint64_t counter) {
    std::uint64_t state = 0x726f7574656c6f6fULL;
    state = mix(state, static_cast<std::uint64_t>(context.scope));
    state = mix(state, context.network);
    state = mix(state, context.sender);
    state = mix(state, context.receiver);
    state = mix(state, context.epoch);
    return mix(state, counter);
  }

  static void make_tag(const routeloom::SecurityContext& context, std::uint64_t counter,
                       routeloom::ByteView aad, routeloom::ByteView ciphertext,
                       std::array<std::uint8_t, routeloom::kAeadTagSize>& tag) {
    std::uint64_t left = seed(context, counter);
    std::uint64_t right = mix(left, 0x746167ULL);
    for (std::size_t i = 0; i < aad.size; ++i) left = mix(left, aad.data[i]);
    for (std::size_t i = 0; i < ciphertext.size; ++i) right = mix(right, ciphertext.data[i]);
    for (int i = 0; i < 8; ++i) {
      tag[i] = static_cast<std::uint8_t>(left >> (56 - i * 8));
      tag[8 + i] = static_cast<std::uint8_t>(right >> (56 - i * 8));
    }
  }
};

}  // namespace routeloom_test
