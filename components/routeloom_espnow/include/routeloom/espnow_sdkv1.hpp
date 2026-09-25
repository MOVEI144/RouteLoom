#pragma once

// SDK v1 device wiring (docs/design/sdk-v1/05 §5, 07 §6, 08 P7): the seven
// `rlsec` stores (rlident/rlsite/rlrevo/rlres plus rlrev/rlres2 for the P4
// member handshake, plus rlmaint for the P6 removal/cutover journal) as
// one firmware-owned object plus the factory maintenance console runner
// over USB Serial/JTAG. The store discipline and the console protocol
// live in the portable core (sdkv1_store.hpp, sdkv1_maintenance.hpp) and
// are host-tested; this file only binds them to NVS, the USB driver and
// FreeRTOS.

#include <cstddef>

#include "routeloom/nvs_sdkv1_store.hpp"
#include "routeloom/sdkv1_blob_storage.hpp"
#include "routeloom/sdkv1_membership.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/status.hpp"

namespace routeloom::espnow {

// The seven SDK v1 stores over `rlsec`, owned statically by the firmware
// (about 7 KiB of .bss for the slot scratch buffers and adopted records —
// see ram-budget.md; nothing is allocated per call). Not thread-safe; the
// owner serializes use.
class Sdkv1Stores {
 public:
  // `resume_slots` is kResumeNodeSlots (16) on a node, kResumeGatewaySlots
  // (160) on a gateway (05 §3.2/§5.1). It sizes both the RLP1 and the RLP2
  // slot ranges; the P4 purpose quotas (12+4 / 32+128) partition the RLP2
  // range.
  explicit Sdkv1Stores(std::size_t resume_slots) noexcept;
  ~Sdkv1Stores() = default;

  Sdkv1Stores(const Sdkv1Stores&) = delete;
  Sdkv1Stores& operator=(const Sdkv1Stores&) = delete;

  // Open the six namespaces on `partition` (kSecurityNvsPartition, already
  // mounted). Half-open namespaces are closed again on failure.
  Status open(const char* partition) noexcept;
  // Initialize all four record stores (the resume caches are stateless and
  // scan on demand). Every store is attempted; the first error is
  // returned while the others still land in their observed state.
  Status initialize() noexcept;
  // One boot-diagnostic line per store (counts and impairment only — no
  // keys, no key material, no digests).
  void log_state(const char* tag) const noexcept;

  sdkv1::IdentityStore& identity() noexcept { return identity_; }
  sdkv1::SiteStore& site() noexcept { return site_; }
  sdkv1::RevocationStore& revocation() noexcept { return revocation_; }
  sdkv1::ResumeCache& resume() noexcept { return resume_; }
  sdkv1::LocalRevocationStore& local_revocation() noexcept { return local_revocation_; }
  sdkv1::ResumeSlotStorage2& resume2() noexcept { return resume2_storage_; }
  sdkv1::LifecycleStore& lifecycle() noexcept { return lifecycle_; }

 private:
  std::size_t resume_slots_;
  NvsBlobNamespace ident_ns_{};
  NvsBlobNamespace site_ns_{};
  NvsBlobNamespace revo_ns_{};
  NvsBlobNamespace resume_ns_{};
  NvsBlobNamespace local_revocation_ns_{};
  NvsBlobNamespace resume2_ns_{};
  NvsBlobNamespace lifecycle_ns_{};
  sdkv1::BlobRecordSlotStorage ident_storage_;
  sdkv1::BlobRecordSlotStorage site_storage_;
  sdkv1::BlobRecordSlotStorage revo_storage_;
  sdkv1::BlobResumeSlotStorage resume_storage_;
  sdkv1::BlobRecordSlotStorage local_revocation_storage_;
  sdkv1::BlobResumeSlotStorage2 resume2_storage_;
  sdkv1::BlobRecordSlotStorage lifecycle_storage_;
  sdkv1::IdentityStore identity_;
  sdkv1::SiteStore site_;
  sdkv1::RevocationStore revocation_;
  sdkv1::ResumeCache resume_;
  sdkv1::LocalRevocationStore local_revocation_;
  sdkv1::LifecycleStore lifecycle_;
};

// Factory maintenance console (07 §6 steps 1-5): installs the USB
// Serial/JTAG driver, starts the console task (8 KiB stack — the engine's
// worst-case frame is about 4 KiB, sdkv1_maintenance.hpp) and suspends the
// caller. The console task then owns the device: it never returns.
// Returns only when the driver or the task cannot be set up (the caller
// fails the boot — a maintenance build that cannot serve the console must
// not silently boot the mesh instead).
//
// Call pre-RF from a CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE build only. Log
// text shares the USB with the protocol on builds whose console is USB;
// the factory tool syncs on the `OK`/`ERR` response prefix and ignores
// anything else. Lines starting with `security legacy-state` are routed
// to the legacy peer-record purge verb (P4 §10.2) instead of the factory
// provisioning console; everything else keeps the factory grammar.
Status run_maintenance_console(Sdkv1Stores& stores) noexcept;

}  // namespace routeloom::espnow
