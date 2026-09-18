#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::wire {

constexpr std::uint16_t kMagic = 0x524c;  // "RL"
constexpr std::uint8_t kMajor = 0;
constexpr std::uint8_t kMinor = 1;
constexpr std::size_t kHeaderSize = 88;
constexpr std::uint8_t kFlagEndProtected = 0x01;

struct Header {
  FrameType type{FrameType::Data};
  std::uint8_t flags{0};
  DeliveryClass delivery{DeliveryClass::Reliable};
  std::uint8_t delivery_round{0};
  std::uint8_t hop_remaining{kDefaultHopLimit};
  std::uint16_t payload_length{0};
  NetworkId network{0};  // v0 encodes the low 32 bits; upper bits must be zero.
  NodeId origin{kInvalidNodeId};
  NodeId destination{kInvalidNodeId};
  NodeId previous_hop{kInvalidNodeId};
  NodeId next_hop{kInvalidNodeId};
  MessageId message{};
  std::uint32_t remaining_deadline_ms{0};
  std::uint32_t original_lifetime_ms{0};
  std::uint16_t link_epoch{0};
  std::uint16_t end_epoch{0};
  std::uint64_t link_counter{0};
  std::uint64_t end_counter{0};
};

struct PlainFrame {
  Header header{};
  std::array<std::uint8_t, kMaxApplicationPayload> payload{};
  std::size_t payload_size{0};
};

struct LinkOpenedFrame {
  Header header{};
  std::array<std::uint8_t, kMaxApplicationPayload + kAeadTagSize> protected_payload{};
  std::size_t protected_payload_size{0};
};

using EncodedFrame = ByteBuffer<kMaxEspNowBody>;

Status validate_header(const Header& header) noexcept;
Status encode_new(const PlainFrame& frame,
                  SecurityProvider& security,
                  EncodedFrame& output) noexcept;
Status open_link(ByteView encoded,
                 NodeId local_node,
                 SecurityProvider& security,
                 LinkOpenedFrame& output) noexcept;
Status open_end(const LinkOpenedFrame& frame,
                NodeId local_node,
                SecurityProvider& security,
                PlainFrame& output) noexcept;
Status forward(const LinkOpenedFrame& input,
               NodeId local_node,
               NodeId next_hop,
               std::uint32_t remaining_deadline_ms,
               SecurityProvider& security,
               EncodedFrame& output) noexcept;

}  // namespace routeloom::wire
