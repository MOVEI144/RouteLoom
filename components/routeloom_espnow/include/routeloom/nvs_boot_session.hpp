#pragma once

#include "routeloom/sdkv1_boot_session.hpp"

namespace routeloom {

// rlboot lives in system NVS; rlsec failures cannot suppress its advance.
class NvsBootSessionPort final : public sdkv1::BootSessionPort {
 public:
  Status read(std::uint32_t& stored, bool& found) noexcept override;
  Status commit(std::uint32_t value) noexcept override;
};

Status next_boot_session(std::uint32_t& session) noexcept;

}  // namespace routeloom
