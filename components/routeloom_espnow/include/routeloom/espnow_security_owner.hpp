#pragma once

// The P4 device security owner (G-SEC P4 §8): the single firmware object
// that binds the portable SecurityCoordinator to the radio (EspNowRuntime
// RLD1 + channel operations), the USB bridge (LocalJoin + relay 0x60/61
// /62), the NVS-backed Sdkv1Stores and member discovery. Shared by the
// reference, bridge and example entries — the three mains only configure
// it (node identity, joiner policy, log tag) and pump it.
//
// Wiring order in main: stores.open/initialize, owner.begin (constructs
// the coordinator with an UNKEYED cookie sealer — the runtime
// constructor below needs the provider view before radio-up entropy
// exists), runtime construction with owner.session_provider(),
// runtime.initialize (radio-only: the provider is not ready yet),
// entropy.begin (post-WiFi radio entropy), owner.attach_runtime,
// owner.attach_usb (gateway builds), owner.boot (rlboot witness; arms
// the cookie sealer from ready entropy — unbegun entropy fails the
// boot). runtime.start stays deferred: the node starts on
// ApplyMemberConfig. The pump then runs bridge.poll (USB downs reach
// the coordinator synchronously on the pump task), runtime.poll_once
// (RLD1 reaches it through the bootstrap sink) and owner.poll
// (coordinator Poll + action drain).
//
// Single-threaded: every entry runs on the pump task. No heap.

#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <type_traits>

#include "routeloom/discovery.hpp"
#include "routeloom/espnow_autonomy.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/psa_session_aead.hpp"
#include "routeloom/sdkv1_join_relay.hpp"
#include "routeloom/sdkv1_security_coordinator.hpp"
#include "routeloom/usb_bridge.hpp"

namespace routeloom::espnow {

class EspNowSecurityOwner final : public BootstrapRld1Sink,
                                   public usb::UsbBridge::SecurityOwnerUsbSink,
                                   public sdkv1::ZtRld1Port,
                                   public sdkv1::CoordinatorMeshPort,
                                   public sdkv1::CoordinatorUsbPort,
                                   public NeighborAuthenticator {
 public:
  struct Config {
    NodeId local_node{kInvalidNodeId};  // Kconfig identity until adoption
    routeloom::MacAddress local_mac{};
    sdkv1::JoinerConfig joiner{};
    const char* log_tag{"sec_owner"};
  };

  EspNowSecurityOwner() noexcept = default;
  ~EspNowSecurityOwner() noexcept override;

  EspNowSecurityOwner(const EspNowSecurityOwner&) = delete;
  EspNowSecurityOwner& operator=(const EspNowSecurityOwner&) = delete;

  // Constructs the coordinator over `stores` (already open +
  // initialized) with an unkeyed cookie sealer; `entropy` may be unbegun
  // (begin runs pre-radio). The stores, entropy and config outlive the
  // owner.
  Status begin(Sdkv1Stores& stores, EspOwnerEntropy& entropy, const Config& config) noexcept;
  // The session provider view for the runtime constructor (unconfigured
  // until the member config lands — the node must not start before).
  SecurityProvider& session_provider() noexcept;
  sdkv1::SecurityCoordinator& coordinator() noexcept;
  // Late bindings (each once, before boot): the radio (RLD1 TX, channel
  // operations, member node adoption) and the USB bridge (LocalJoin +
  // relay ups/downs). A radio-only node skips the bridge: relay ups
  // then refuse and the gateway engine sheds with authority_unreachable.
  Status attach_runtime(EspNowRuntime& runtime) noexcept;
  Status attach_usb(usb::UsbBridge& bridge) noexcept;
  // Boots the coordinator: rlboot_witness/rlboot_prepared describe the
  // rlboot value (prepared=false refuses the boot), usb_direct selects
  // the direct-join transport for a host-attached gateway. Arms the
  // cookie sealer from `entropy` (already begun) before stepping Boot —
  // unready entropy refuses the boot.
  Status boot(std::uint32_t rlboot_witness, bool rlboot_prepared, bool usb_direct,
              MonotonicMs now_ms) noexcept;
  // One pump turn after runtime.poll_once: coordinator Poll, ready radio
  // completions, and the action drain (tune/member/discovery/report).
  void poll(MonotonicMs now_ms) noexcept;
  // The member discovery (null until StartMemberDiscovery constructs it).
  NeighborDiscovery* discovery() noexcept;

  // BootstrapRld1Sink: one observed RLD1 frame from the runtime drain.
  void on_bootstrap_rld1(const sdkv1::JoinRxMeta& meta, std::uint32_t radio_generation,
                         ByteView frame, MonotonicMs received_ms) noexcept override;
  // SecurityOwnerUsbSink: decoded 0x61/0x62 (admission for the 0x63) and
  // session death. Self-addressed downs demux to the LocalJoin attempt.
  Status join_down(NodeId to_proxy, const sdkv1::RelayObject& object, ByteView raw_object,
                   MonotonicMs now_ms) noexcept override;
  Status join_abort(NodeId proxy, sdkv1::RelayToken token, std::uint8_t reason,
                    MonotonicMs now_ms) noexcept override;
  void join_session_down(MonotonicMs now_ms) noexcept override;
  // sdkv1::ZtRld1Port / CoordinatorMeshPort: radio sends (refuse before
  // the runtime attaches).
  Status send_rld1(const routeloom::MacAddress& destination, ByteView frame) noexcept override;
  Status send_bootstrap(NodeId destination, FrameType type, ByteView payload,
                        std::uint32_t lifetime_ms, MonotonicMs now_ms,
                        MessageId& id) noexcept override;
  // CoordinatorUsbPort: 0x60/0x62 staging (refuse before the bridge
  // attaches or without an active session — the bridge decides that).
  Status send_local_join_up(sdkv1::JoinAuthPhase phase, std::uint8_t step,
                            ByteView message) noexcept override;
  Status send_relay_up_to_host(NodeId proxy, std::uint8_t hops,
                               ByteView object) noexcept override;
  Status send_relay_abort_to_host(NodeId proxy, sdkv1::RelayToken token,
                                  sdkv1::RelayAbortReason reason) noexcept override;
  // NeighborAuthenticator (member discovery): OFFER cookies through the
  // coordinator's member cookie box; the handshake path never uses
  // attest/verify/issue_proof (engine-minted proofs instead).
  SecurityProfile security_profile() const noexcept override;
  bool binds_scope() const noexcept override;
  Status cookie_seal(const CookieMaterial& material, AuthTag& out) noexcept override;
  Status cookie_verify(const CookieMaterial& material, const AuthTag& tag) noexcept override;
  Status attest(autonomy::AuthPhase phase, const AuthTranscript& transcript,
                AuthTag& out) noexcept override;
  Status verify(autonomy::AuthPhase phase, const AuthTranscript& transcript,
                const AuthTag& tag) noexcept override;
  Status issue_proof(const AuthTranscript& transcript, NodeId peer, const AuthTag& tag,
                     AuthenticatedPeerProof& out) noexcept override;

 private:
  // One outstanding radio tune: a TuneChannel action (coord_token != 0)
  // or the ApplyMemberConfig channel move (coord_token == 0, reported as
  // the firmware's apply-time ChannelReady).
  struct Tune {
    std::uint32_t coord_token{0};
    OperationToken op{kInvalidOperationToken};
    std::uint8_t channel{0};
    bool active{false};
  };

  sdkv1::HmacJoinCookie& sealer() noexcept;
  sdkv1::StoreCredentialVerifier& verifier() noexcept;
  void drain_actions(MonotonicMs now_ms) noexcept;
  void on_tune_channel(const sdkv1::CoordinatorTune& tune, MonotonicMs now_ms) noexcept;
  void on_member_config(const sdkv1::CoordinatorMemberConfig& member, MonotonicMs now_ms) noexcept;
  void on_start_discovery(MonotonicMs now_ms) noexcept;
  void poll_tune(MonotonicMs now_ms) noexcept;
  void report_tune(const Tune& tune, StatusCode result, MonotonicMs now_ms) noexcept;
  Status request_cutover(std::uint8_t channel, std::uint32_t coord_token,
                         MonotonicMs now_ms) noexcept;

  Config config_{};
  Sdkv1Stores* stores_{nullptr};
  EspOwnerEntropy* entropy_{nullptr};
  EspNowRuntime* runtime_{nullptr};
  usb::UsbBridge* bridge_{nullptr};
  bool begun_{false};
  bool booted_{false};
  std::uint32_t local_join_relay_id_{0};  // 0 = no LocalJoin attempt
  Tune tune_{};
  NodeId adopted_node_{kInvalidNodeId};  // from ApplyMemberConfig (self match)
  NetworkId adopted_network_{0};
  int apply_retries_{0};      // ApplyMemberConfig channel-move retries left
  std::uint8_t apply_channel_{0};  // target operating channel (0 = none)
  alignas(sdkv1::HmacJoinCookie) std::array<std::uint8_t, sizeof(sdkv1::HmacJoinCookie)>
      sealer_box_{};
  alignas(sdkv1::StoreCredentialVerifier)
      std::array<std::uint8_t, sizeof(sdkv1::StoreCredentialVerifier)> verifier_box_{};
  alignas(sdkv1::SecurityCoordinator)
      std::array<std::uint8_t, sizeof(sdkv1::SecurityCoordinator)> coordinator_box_{};
  bool coordinator_live_{false};
  alignas(NeighborDiscovery) std::array<std::uint8_t, sizeof(NeighborDiscovery)> discovery_box_{};
  bool discovery_live_{false};
  EspNowDiscoveryObserver observer_store_{nullptr, nullptr};
};

}  // namespace routeloom::espnow
