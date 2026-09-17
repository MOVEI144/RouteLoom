#pragma once

#include <array>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

using Digest256 = std::array<std::uint8_t, 32>;

struct AuthorityRecord {
  NetworkId network{0};
  NodeId authority{kInvalidNodeId};
  std::uint32_t generation{0};
  std::uint64_t applied_sequence{0};
  Digest256 state_hash{};
};

struct AuthorityOperation {
  NetworkId network{0};
  NodeId authority{kInvalidNodeId};
  std::uint32_t generation{0};
  std::uint64_t sequence{0};
  Digest256 previous_state_hash{};
  Digest256 operation_hash{};
};

class AuthorityStore {
 public:
  virtual ~AuthorityStore() = default;
  virtual Status load(AuthorityRecord& record, bool& found) noexcept = 0;
  virtual Status commit(const AuthorityRecord& record) noexcept = 0;
};

class SingleAuthority {
 public:
  SingleAuthority(NetworkId network, NodeId authority, AuthorityStore& store) noexcept;

  Status initialize() noexcept;
  Status validate(const AuthorityOperation& operation,
                  bool cryptographic_signature_verified) const noexcept;
  Status commit(const AuthorityOperation& operation,
                const Digest256& resulting_state_hash,
                bool cryptographic_signature_verified) noexcept;

  const AuthorityRecord& state() const noexcept { return state_; }

 private:
  NetworkId network_{0};
  NodeId authority_{kInvalidNodeId};
  AuthorityStore& store_;
  AuthorityRecord state_{};
  bool initialized_{false};
};

}  // namespace routeloom
