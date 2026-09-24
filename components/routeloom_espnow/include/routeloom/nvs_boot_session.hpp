#pragma once

#include "routeloom/sdkv1_boot_session.hpp"
#include "routeloom/sdkv1_store.hpp"

namespace routeloom {

// rlboot lives in system NVS; rlsec failures cannot suppress its advance.
class NvsBootSessionPort final : public sdkv1::BootSessionPort {
 public:
  Status read(std::uint32_t& stored, bool& found) noexcept override;
  Status commit(std::uint32_t value) noexcept override;
};

// Fixed security-partition high-water for future DevRam group epochs.
class NvsDevBootHighWaterPort final : public sdkv1::DevBootHighWaterPort {
 public:
  Status read(std::uint32_t& stored, bool& found) noexcept override;
  Status commit(std::uint32_t value) noexcept override;
};

Status next_dev_group_boot_session(std::uint32_t& session) noexcept;
Status next_boot_session(std::uint32_t& session) noexcept;
// Call after site initialization, before constructing any radio/session owner.
Status reconcile_boot_session(const sdkv1::SiteStore& site,
                              std::uint32_t& session) noexcept;

}  // namespace routeloom
