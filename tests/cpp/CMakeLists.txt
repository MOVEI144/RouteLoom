add_executable(routeloom_core_tests test_main.cpp)
target_link_libraries(routeloom_core_tests PRIVATE routeloom_core)
target_compile_options(routeloom_core_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_core_tests COMMAND routeloom_core_tests)

add_executable(routeloom_routing_tests test_routing_sims.cpp)
target_link_libraries(routeloom_routing_tests PRIVATE routeloom_core)
target_compile_options(routeloom_routing_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_routing_tests COMMAND routeloom_routing_tests)

# Gateway-scoped routing profile (docs/design/sdk-v1/routing-scale.md): the
# fast unit/small-mesh cases and the 100-node product-timer run are separate
# ctest entries so the long run parallelises with the rest of the suite.
add_executable(routeloom_routing_scale_tests test_routing_scale.cpp)
target_link_libraries(routeloom_routing_scale_tests PRIVATE routeloom_core)
target_include_directories(routeloom_routing_scale_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_routing_scale_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_routing_scale_tests PRIVATE
    ROUTELOOM_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/golden")
add_test(NAME routeloom_routing_scale_unit_tests COMMAND routeloom_routing_scale_tests unit)
add_test(NAME routeloom_routing_scale_100_node_tests COMMAND routeloom_routing_scale_tests scale)

add_executable(routeloom_ledger_tests test_ledger.cpp)
target_link_libraries(routeloom_ledger_tests PRIVATE routeloom_core)
target_compile_options(routeloom_ledger_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_ledger_tests COMMAND routeloom_ledger_tests)

add_executable(routeloom_golden_tests test_golden.cpp)
target_link_libraries(routeloom_golden_tests PRIVATE routeloom_core)
target_compile_options(routeloom_golden_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_golden_tests PRIVATE
    ROUTELOOM_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/golden")
add_test(NAME routeloom_golden_tests COMMAND routeloom_golden_tests)

add_executable(routeloom_host_ops_tests test_host_ops.cpp)
target_link_libraries(routeloom_host_ops_tests PRIVATE routeloom_core)
target_include_directories(routeloom_host_ops_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_host_ops_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_host_ops_tests PRIVATE
    ROUTELOOM_SDKV1_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/sdkv1-golden")
add_test(NAME routeloom_host_ops_tests COMMAND routeloom_host_ops_tests)

add_executable(routeloom_usb_tests test_usb.cpp)
target_link_libraries(routeloom_usb_tests PRIVATE routeloom_core)
target_compile_options(routeloom_usb_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_usb_tests PRIVATE
    ROUTELOOM_USB_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/usb-golden")
add_test(NAME routeloom_usb_tests COMMAND routeloom_usb_tests)

add_executable(routeloom_power_tests test_power.cpp)
target_link_libraries(routeloom_power_tests PRIVATE routeloom_core)
target_compile_options(routeloom_power_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_power_tests COMMAND routeloom_power_tests)

add_executable(routeloom_hardening_tests test_hardening.cpp)
target_link_libraries(routeloom_hardening_tests PRIVATE routeloom_core)
target_include_directories(routeloom_hardening_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_hardening_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_hardening_tests COMMAND routeloom_hardening_tests)

add_executable(routeloom_autonomy_tests test_autonomy.cpp)
target_link_libraries(routeloom_autonomy_tests PRIVATE routeloom_core)
target_compile_options(routeloom_autonomy_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_autonomy_tests PRIVATE
    ROUTELOOM_AUTONOMY_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/autonomy-golden")
add_test(NAME routeloom_autonomy_tests COMMAND routeloom_autonomy_tests)

add_executable(routeloom_endpoint_tests test_endpoint.cpp)
target_link_libraries(routeloom_endpoint_tests PRIVATE routeloom_core)
target_compile_options(routeloom_endpoint_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_endpoint_tests PRIVATE
    ROUTELOOM_ENDPOINT_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/endpoint-golden")
add_test(NAME routeloom_endpoint_tests COMMAND routeloom_endpoint_tests)

add_executable(routeloom_gateway_tests test_gateway.cpp)
target_link_libraries(routeloom_gateway_tests PRIVATE routeloom_core)
target_include_directories(routeloom_gateway_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_gateway_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_gateway_tests COMMAND routeloom_gateway_tests)

add_executable(routeloom_discovery_tests test_discovery.cpp)
target_link_libraries(routeloom_discovery_tests PRIVATE routeloom_core)
target_include_directories(routeloom_discovery_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_discovery_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_discovery_tests COMMAND routeloom_discovery_tests)

add_executable(routeloom_scope_tests test_scope.cpp)
target_link_libraries(routeloom_scope_tests PRIVATE routeloom_core)
target_include_directories(routeloom_scope_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_scope_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_scope_tests COMMAND routeloom_scope_tests)

add_executable(routeloom_telemetry_tests test_telemetry.cpp)
target_link_libraries(routeloom_telemetry_tests PRIVATE routeloom_core)
target_compile_options(routeloom_telemetry_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_telemetry_tests COMMAND routeloom_telemetry_tests)

add_executable(routeloom_congestion_tests test_congestion.cpp)
target_link_libraries(routeloom_congestion_tests PRIVATE routeloom_core)
target_include_directories(routeloom_congestion_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_congestion_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_congestion_tests COMMAND routeloom_congestion_tests)

add_executable(routeloom_load_routing_tests test_routing_load.cpp)
target_link_libraries(routeloom_load_routing_tests PRIVATE routeloom_core)
target_include_directories(routeloom_load_routing_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_load_routing_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_load_routing_tests COMMAND routeloom_load_routing_tests)

add_executable(routeloom_channel_tests test_channel.cpp)
target_link_libraries(routeloom_channel_tests PRIVATE routeloom_core)
target_include_directories(routeloom_channel_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_channel_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_channel_tests COMMAND routeloom_channel_tests)

add_executable(routeloom_migration_tests test_migration.cpp)
target_link_libraries(routeloom_migration_tests PRIVATE routeloom_core)
target_include_directories(routeloom_migration_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_migration_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_migration_tests COMMAND routeloom_migration_tests)

add_executable(routeloom_migration_wire_tests test_migration_wire.cpp)
target_link_libraries(routeloom_migration_wire_tests PRIVATE routeloom_core)
target_include_directories(routeloom_migration_wire_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_migration_wire_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_migration_wire_tests COMMAND routeloom_migration_wire_tests)

add_executable(routeloom_baseline_diff_tests test_baseline_diff.cpp)
target_link_libraries(routeloom_baseline_diff_tests PRIVATE routeloom_core)
target_include_directories(routeloom_baseline_diff_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_baseline_diff_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_baseline_diff_tests COMMAND routeloom_baseline_diff_tests)

add_executable(routeloom_config_tests test_config.cpp)
target_link_libraries(routeloom_config_tests PRIVATE routeloom_core)
target_include_directories(routeloom_config_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_config_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_config_tests COMMAND routeloom_config_tests)

add_executable(routeloom_cose_tests test_config_cose.cpp)
target_link_libraries(routeloom_cose_tests PRIVATE routeloom_core)
target_include_directories(routeloom_cose_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_cose_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_cose_tests COMMAND routeloom_cose_tests)

add_executable(routeloom_config_wire_tests test_config_wire.cpp)
target_link_libraries(routeloom_config_wire_tests PRIVATE routeloom_core)
target_include_directories(routeloom_config_wire_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_config_wire_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_config_wire_tests COMMAND routeloom_config_wire_tests)

# Provisioning-lifecycle portable core (issue #10): RLT1 trust store, RLC1
# device credential, RTM1 trust manifest. The micro-ecc include dir is added
# so the shared fixture can drive real P-256 keypairs/signatures against the
# vendored copy already linked into routeloom_core.
set(ROUTELOOM_UECC_DIR ${CMAKE_SOURCE_DIR}/components/routeloom/third_party/micro-ecc)

add_executable(routeloom_trust_store_tests test_trust_store.cpp)
target_link_libraries(routeloom_trust_store_tests PRIVATE routeloom_core)
target_include_directories(routeloom_trust_store_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_trust_store_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_trust_store_tests COMMAND routeloom_trust_store_tests)

add_executable(routeloom_credential_tests test_device_credential.cpp)
target_link_libraries(routeloom_credential_tests PRIVATE routeloom_core)
target_include_directories(routeloom_credential_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_credential_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_credential_tests COMMAND routeloom_credential_tests)

add_executable(routeloom_trust_manifest_tests test_trust_manifest.cpp)
target_link_libraries(routeloom_trust_manifest_tests PRIVATE routeloom_core)
target_include_directories(routeloom_trust_manifest_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_trust_manifest_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_trust_manifest_tests COMMAND routeloom_trust_manifest_tests)

# SDK v1 key hierarchy building block (docs/design/sdk-v1/03-key-hierarchy.md
# §3): HKDF-SHA-256 pinned by the RFC 5869 SHA-256 test cases.
add_executable(routeloom_kdf_tests test_kdf.cpp)
target_link_libraries(routeloom_kdf_tests PRIVATE routeloom_core)
target_compile_options(routeloom_kdf_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_kdf_tests COMMAND routeloom_kdf_tests)

# SDK v1 frozen derivation labels + RLRES1 transcript (plan P1-4, V1-K01 HKDF
# part, V1-F03): byte-exact against protocol/sdkv1-golden/derivations, which
# the independent tools/gen_sdkv1_derivation_vectors.py generates.
add_executable(routeloom_key_schedule_tests test_key_schedule.cpp)
target_link_libraries(routeloom_key_schedule_tests PRIVATE routeloom_core)
target_compile_options(routeloom_key_schedule_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_key_schedule_tests PRIVATE
    ROUTELOOM_SDKV1_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/sdkv1-golden")
add_test(NAME routeloom_key_schedule_tests COMMAND routeloom_key_schedule_tests)

# Authority channel, device side (G-SEC P5 PR1, V1-K11 crypto/endpoint part):
# body codecs, GK-id and sealed envelopes byte-exact against
# protocol/sdkv1-golden/authority (tools/gen_sdkv1_authority_vectors.py),
# plus a live client round-trip against an in-test fake authority.
add_executable(routeloom_sdkv1_authority_tests test_sdkv1_authority.cpp)
target_link_libraries(routeloom_sdkv1_authority_tests PRIVATE routeloom_core)
target_compile_options(routeloom_sdkv1_authority_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_sdkv1_authority_tests PRIVATE
    ROUTELOOM_SDKV1_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/sdkv1-golden")
add_test(NAME routeloom_sdkv1_authority_tests COMMAND routeloom_sdkv1_authority_tests)

# RLRES1 resume state machine and its attack suite (plan P1-5, V1-F02).
add_executable(routeloom_rlres1_tests test_rlres1.cpp)
target_link_libraries(routeloom_rlres1_tests PRIVATE routeloom_core)
target_compile_options(routeloom_rlres1_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_rlres1_tests COMMAND routeloom_rlres1_tests)

add_executable(routeloom_c_header_test c_api_smoke.c)
target_link_libraries(routeloom_c_header_test PRIVATE routeloom_core)
set_target_properties(routeloom_c_header_test PROPERTIES LINKER_LANGUAGE CXX)
target_compile_options(routeloom_c_header_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_c_header_test COMMAND routeloom_c_header_test)

add_executable(routeloom_trust_view_tests test_trust_view.cpp)
target_link_libraries(routeloom_trust_view_tests PRIVATE routeloom_core)
target_include_directories(routeloom_trust_view_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_trust_view_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_trust_view_tests COMMAND routeloom_trust_view_tests)

# State-machine property tests (issue #19): deterministic seeded random op
# sequences over SimNetwork asserting delivery/dedup invariants.
add_executable(routeloom_property_tests test_properties.cpp)
target_link_libraries(routeloom_property_tests PRIVATE routeloom_core)
target_include_directories(routeloom_property_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_property_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_property_tests COMMAND routeloom_property_tests)

# APPLIED delivery (sdk-completion/01-applied-delivery.md): APP_RESULT body
# codecs, origin/terminal state machines, bounded QUERY recovery, replay and
# refusal discipline, multi-hop traversal.
add_executable(routeloom_applied_tests test_applied.cpp)
target_link_libraries(routeloom_applied_tests PRIVATE routeloom_core)
target_include_directories(routeloom_applied_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_applied_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_applied_tests COMMAND routeloom_applied_tests)

# Cross-cutting fault-injection tests (issue #20): storage corruption/power
# cuts on counter/replay/trust persistence, clock faults, and bounded-pool
# saturation. Needs ${CMAKE_CURRENT_SOURCE_DIR} for the shared fixtures and
# ROUTELOOM_UECC_DIR for test_provisioning.hpp's P-256 key generation.
add_executable(routeloom_fault_tests test_fault_injection.cpp)
target_link_libraries(routeloom_fault_tests PRIVATE routeloom_core)
target_include_directories(routeloom_fault_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_fault_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_fault_tests COMMAND routeloom_fault_tests)

# Dedup capacity classes (sdk-completion/02-dedup-capacity.md, issue #9):
# phase births/eviction order/reserve/upstream cap/evidence cap + replay,
# retention bounds, class-(a) delivery eviction, and continuous-send
# below/above capacity with honest saturation.
add_executable(routeloom_dedup_tests test_dedup.cpp)
target_link_libraries(routeloom_dedup_tests PRIVATE routeloom_core)
target_include_directories(routeloom_dedup_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_dedup_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_dedup_tests COMMAND routeloom_dedup_tests)

add_executable(routeloom_node_status_tests test_node_status.cpp)
target_link_libraries(routeloom_node_status_tests PRIVATE routeloom_core)
target_include_directories(routeloom_node_status_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_node_status_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_node_status_tests COMMAND routeloom_node_status_tests)

# Bounded persistent peer state (issue #37, docs/design/sdk-v1/05-nvs-state-37.md
# §4 / plan P0-2): TX counter sweep behind a durable witness, per-peer caps,
# NVS entry budget arithmetic, and a 200-peer churn against a fixed-capacity
# NVS model (no (key, counter) reuse, no replay re-acceptance, cap never
# exceeded, boot-session partition never blocked).
add_executable(routeloom_peer_state_tests test_peer_state.cpp)
target_link_libraries(routeloom_peer_state_tests PRIVATE routeloom_core)
target_compile_options(routeloom_peer_state_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_peer_state_tests COMMAND routeloom_peer_state_tests)

# Group delivery + per-source ordering (docs/design/sdk-v1/group-delivery.md):
# unit/small-mesh cases and the 100-node ALARM/burst run as separate entries.
add_executable(routeloom_group_tests test_group.cpp)
target_link_libraries(routeloom_group_tests PRIVATE routeloom_core)
target_include_directories(routeloom_group_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_group_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_group_tests PRIVATE
    ROUTELOOM_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/golden")
add_test(NAME routeloom_group_unit_tests COMMAND routeloom_group_tests unit)
add_test(NAME routeloom_group_100_node_tests COMMAND routeloom_group_tests scale)

# Provider-owned sessions (docs/design/sdk-v1/03-key-hierarchy.md §8–§9,
# plan P4-1): tx_epoch/context_state defaults, SessionInstaller, node
# deferral without a session, no counter spent on a refused frame, and V1-K10
# (every Wire v2 golden vector reproduced through the provider-epoch path).
add_executable(routeloom_session_tests test_session.cpp)
target_link_libraries(routeloom_session_tests PRIVATE routeloom_core)
target_include_directories(routeloom_session_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_session_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_session_tests PRIVATE
    ROUTELOOM_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/golden")
add_test(NAME routeloom_session_tests COMMAND routeloom_session_tests)

# SDK v1 records and certificates (docs/design/sdk-v1/08 P1-2/P1-3): RLCW1
# DevCert/SiteCert/MemberCert codec + ES256 verification hook, RLI1/RLS1/
# RRS1/RLP1 codecs, the dual-slot stores under byte-granular power-cut
# injection, and the shared vectors in protocol/sdkv1-golden/ (generated by
# tools/gen_sdkv1_vectors.py, mirrored by host/routeloom-provision).
add_executable(routeloom_sdkv1_golden_tests test_sdkv1_golden.cpp)
target_link_libraries(routeloom_sdkv1_golden_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_golden_tests PRIVATE ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_sdkv1_golden_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_sdkv1_golden_tests PRIVATE
    ROUTELOOM_SDKV1_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/sdkv1-golden")
add_test(NAME routeloom_sdkv1_golden_tests COMMAND routeloom_sdkv1_golden_tests)

# SDK v1 join EAD items (plan P2-3): protocol/sdkv1-golden/ead, generated by
# the independent tools/gen_sdkv1_ead_vectors.py, mirrored by host/routeloom-join.
add_executable(routeloom_sdkv1_ead_tests test_sdkv1_ead.cpp)
target_link_libraries(routeloom_sdkv1_ead_tests PRIVATE routeloom_core)
target_compile_options(routeloom_sdkv1_ead_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_sdkv1_ead_tests PRIVATE
    ROUTELOOM_SDKV1_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/sdkv1-golden")
add_test(NAME routeloom_sdkv1_ead_tests COMMAND routeloom_sdkv1_ead_tests)

# Member session wire (G-SEC P4 §5.3/§5.4): session EAD values, the
# carrier/end bindings, the capability/contexts digests, the 15-element
# Exporter contexts and the RFC 9528 Exporter KDF against
# protocol/sdkv1-golden/handshake/ (generated by the independent
# tools/gen_sdkv1_handshake_vectors.py, mirrored by
# host/routeloom-keysched).
add_executable(routeloom_sdkv1_session_wire_tests test_sdkv1_session_wire.cpp)
target_link_libraries(routeloom_sdkv1_session_wire_tests PRIVATE routeloom_core)
target_compile_options(routeloom_sdkv1_session_wire_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_sdkv1_session_wire_tests PRIVATE
    ROUTELOOM_SDKV1_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/sdkv1-golden")
add_test(NAME routeloom_sdkv1_session_wire_tests COMMAND routeloom_sdkv1_session_wire_tests)

# Member handshake engine (G-SEC P4 §5-§7, PR2): two-engine link EDHOC
# and resume exchanges with issued MemberCerts, the cookie/binding/caps
# gates, re-entry, cancel/timeout, simultaneous open, min-GK, revocation
# at commit, and discovery elevation with the minted proof.
add_executable(routeloom_sdkv1_handshake_tests test_sdkv1_handshake.cpp)
target_link_libraries(routeloom_sdkv1_handshake_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_handshake_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_sdkv1_handshake_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_sdkv1_handshake_tests COMMAND routeloom_sdkv1_handshake_tests)

# SDK v1 join transport (plan P3-1/P3-2): RLD1 body v3, BootstrapAuth
# phases 4-6, the bounded object slot, relay objects and the zero-touch
# admission rules against protocol/sdkv1-golden/join-transport (generated by
# the independent tools/gen_sdkv1_join_transport_vectors.py); then the
# joiner/proxy/gateway engines end to end (V1-J02, V1-J10, V1-J11).
add_executable(routeloom_sdkv1_join_transport_tests test_sdkv1_join_transport.cpp)
target_link_libraries(routeloom_sdkv1_join_transport_tests PRIVATE routeloom_core)
target_compile_options(routeloom_sdkv1_join_transport_tests PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_sdkv1_join_transport_tests PRIVATE
    ROUTELOOM_SDKV1_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/sdkv1-golden")
add_test(NAME routeloom_sdkv1_join_transport_tests COMMAND routeloom_sdkv1_join_transport_tests)

add_executable(routeloom_sdkv1_join_relay_tests test_sdkv1_join_relay.cpp)
target_link_libraries(routeloom_sdkv1_join_relay_tests PRIVATE routeloom_core)
target_compile_options(routeloom_sdkv1_join_relay_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_sdkv1_join_relay_tests COMMAND routeloom_sdkv1_join_relay_tests)

# SDK v1 join handshake driver (plan P3-4 PR 1): a real method-0/suite-2
# exchange against a scripted Site Authority session, the 02 §10.2 Allow
# matrix through decide(), the m2 gate, DAMS exporter context vectors of
# protocol/sdkv1-golden/dams (generated by tools/gen_sdkv1_dams_vectors.py).
add_executable(routeloom_sdkv1_join_handshake_tests test_sdkv1_join_handshake.cpp)
target_link_libraries(routeloom_sdkv1_join_handshake_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_join_handshake_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_sdkv1_join_handshake_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_sdkv1_join_handshake_tests PRIVATE
    ROUTELOOM_SDKV1_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/sdkv1-golden")
add_test(NAME routeloom_sdkv1_join_handshake_tests COMMAND routeloom_sdkv1_join_handshake_tests)

add_executable(routeloom_sdkv1_join_candidates_tests test_sdkv1_join_candidates.cpp)
target_link_libraries(routeloom_sdkv1_join_candidates_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_join_candidates_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_sdkv1_join_candidates_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_sdkv1_join_candidates_tests COMMAND routeloom_sdkv1_join_candidates_tests)

# SDK v1 join FSM (plan P3-4 PR 3): the portable Joiner end to end in the
# two-site simulator (V1-J01, V1-J04-V1-J07, V1-J13, the V1-J12 remainder,
# the V1-J08 FSM fault matrix, re-entrancy, the #109 path, quiescence).
add_executable(routeloom_sdkv1_joiner_tests test_sdkv1_joiner.cpp)
target_link_libraries(routeloom_sdkv1_joiner_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_joiner_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_sdkv1_joiner_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_sdkv1_joiner_tests COMMAND routeloom_sdkv1_joiner_tests)
set_tests_properties(routeloom_sdkv1_joiner_tests PROPERTIES
  ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1")

# Live E2E peer (design P3-4 §10.2): driven by the Rust Site Authority
# test (host/routeloom-host/src/site/joiner_interop.rs), never by ctest.
add_executable(routeloom_joiner_interop_peer joiner_interop_peer.cpp)
target_link_libraries(routeloom_joiner_interop_peer PRIVATE routeloom_core)
target_include_directories(routeloom_joiner_interop_peer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_joiner_interop_peer PRIVATE -Wall -Wextra -Wpedantic -Werror)

# Join stack gate (design P3-4 §9): every stack frame of the two P3-4 join
# translation units stays within 512 B. GCC-only (relies on -fstack-usage).
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  find_package(Python3 COMPONENTS Interpreter QUIET)
  if(Python3_FOUND)
    add_test(NAME routeloom_join_stack_gate
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/check_join_stack.py
        --cxx ${CMAKE_CXX_COMPILER} --root ${CMAKE_SOURCE_DIR})
  endif()
endif()

add_executable(routeloom_sdkv1_records_tests test_sdkv1_records.cpp)
target_link_libraries(routeloom_sdkv1_records_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_records_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_sdkv1_records_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_sdkv1_records_tests COMMAND routeloom_sdkv1_records_tests)

add_executable(routeloom_sdkv1_store_tests test_sdkv1_store.cpp)
target_link_libraries(routeloom_sdkv1_store_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_store_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_sdkv1_store_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_sdkv1_store_tests COMMAND routeloom_sdkv1_store_tests)

# RAM session bank and provider (G-SEC P4 §4, V1-K02/K03/K04): install
# discipline, use budget, replay windows, lifetimes, demand, overlap and
# re-entry. Runs against a deterministic test AEAD and — when OpenSSL is
# available — against real AES-GCM-128 (NIST vectors), since the design
# forbids accepting on the test cipher alone.
add_executable(routeloom_sdkv1_session_bank_tests test_sdkv1_session_bank.cpp)
target_link_libraries(routeloom_sdkv1_session_bank_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_session_bank_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_sdkv1_session_bank_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
  target_link_libraries(routeloom_sdkv1_session_bank_tests PRIVATE OpenSSL::Crypto)
  target_compile_definitions(routeloom_sdkv1_session_bank_tests PRIVATE ROUTELOOM_HAVE_OPENSSL=1)
endif()
add_test(NAME routeloom_sdkv1_session_bank_tests COMMAND routeloom_sdkv1_session_bank_tests)

# P4 membership evidence (G-SEC P4 §3): SdkMembershipHooks over adopted
# RLI1/RLS1/RRS1 with the RLV1 removal gate (V1-R04/R05/R06 local, P4-M01).
add_executable(routeloom_sdkv1_membership_tests test_sdkv1_membership.cpp)
target_link_libraries(routeloom_sdkv1_membership_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_membership_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_sdkv1_membership_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_sdkv1_membership_tests COMMAND routeloom_sdkv1_membership_tests)
# P6 revocation lifecycle, PR A (docs/design/sdk-v1/04 §2-§5, plan P6-1):
# RRS1 acceptance/enforcement/gossip and the traffic gate through fake
# ports (production P4/P5 adapters land later; see sdkv1_revocation.hpp).
add_executable(routeloom_sdkv1_grant_renew_tests test_sdkv1_grant_renew.cpp)
target_link_libraries(routeloom_sdkv1_grant_renew_tests PRIVATE routeloom_core)
target_compile_options(routeloom_sdkv1_grant_renew_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_sdkv1_grant_renew_tests COMMAND routeloom_sdkv1_grant_renew_tests)

add_executable(routeloom_sdkv1_revocation_tests test_sdkv1_revocation.cpp)
target_link_libraries(routeloom_sdkv1_revocation_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_revocation_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_definitions(routeloom_sdkv1_revocation_tests PRIVATE
    ROUTELOOM_SDKV1_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/sdkv1-golden")
target_compile_options(routeloom_sdkv1_revocation_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_sdkv1_revocation_tests COMMAND routeloom_sdkv1_revocation_tests)

# Factory maintenance console engine (sdk-v1/07 §6, 08 P7): keygen + PoP,
# identity-bundle sealing with readback, lock/store gating — against real
# office bytes from protocol/sdkv1-golden/.
add_executable(routeloom_sdkv1_maintenance_tests test_sdkv1_maintenance.cpp)
target_link_libraries(routeloom_sdkv1_maintenance_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_maintenance_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_sdkv1_maintenance_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_sdkv1_maintenance_tests PRIVATE
    ROUTELOOM_SDKV1_GOLDEN_DIR="${CMAKE_SOURCE_DIR}/protocol/sdkv1-golden")
add_test(NAME routeloom_sdkv1_maintenance_tests COMMAND routeloom_sdkv1_maintenance_tests)

add_executable(routeloom_espnow_sdkv1_entropy_tests
    test_espnow_sdkv1_entropy.cpp
    ${CMAKE_SOURCE_DIR}/components/routeloom_espnow/src/espnow_sdkv1_entropy.cpp)
target_link_libraries(routeloom_espnow_sdkv1_entropy_tests PRIVATE routeloom_core)
target_include_directories(routeloom_espnow_sdkv1_entropy_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/stubs/maintenance
    ${CMAKE_SOURCE_DIR}/components/routeloom_espnow/include)
target_compile_options(routeloom_espnow_sdkv1_entropy_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_espnow_sdkv1_entropy_tests COMMAND routeloom_espnow_sdkv1_entropy_tests)

# SDK v1 stores over the key/blob storage port — the portable half of the
# `rlsec` NVS adapter (sdk-v1/05 §5, 08 P7-1), against a fake NVS.
add_executable(routeloom_sdkv1_blob_storage_tests test_sdkv1_blob_storage.cpp)
target_link_libraries(routeloom_sdkv1_blob_storage_tests PRIVATE routeloom_core)
target_include_directories(routeloom_sdkv1_blob_storage_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_sdkv1_blob_storage_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_sdkv1_blob_storage_tests COMMAND routeloom_sdkv1_blob_storage_tests)

# EDHOC (docs/design/sdk-v1/08 P2-1): the vendored libedhoc with RouteLoom's
# bounded backend — RFC 9529 §3 byte for byte and the §4 invalid messages
# (protocol/edhoc-rfc9529, from tools/extract_rfc9529_vectors.py), the
# method-0 RLCW1 MemberCert round trip and its failure cases, arena/key-store
# bounds, and the size/stack report. edhoc_probe.c is C: it reads libedhoc's
# internal key slots (C11-only header) to compare the intermediate PRKs.
find_package(Threads REQUIRED)
add_executable(routeloom_edhoc_tests test_edhoc.cpp edhoc_probe.c)
target_link_libraries(routeloom_edhoc_tests PRIVATE routeloom_core routeloom_edhoc_headers
    Threads::Threads)
target_include_directories(routeloom_edhoc_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${ROUTELOOM_UECC_DIR})
target_compile_options(routeloom_edhoc_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(routeloom_edhoc_tests PRIVATE
    ROUTELOOM_EDHOC_RFC9529_DIR="${CMAKE_SOURCE_DIR}/protocol/edhoc-rfc9529")
add_test(NAME routeloom_edhoc_tests COMMAND routeloom_edhoc_tests)

# EDHOC interop (docs/design/sdk-v1/08 P3-3): the device-side libedhoc stack
# replays the method-0 join transcripts recorded against the Site Authority's
# Rust EDHOC (host/routeloom-edhoc) — both directions, byte for byte,
# including the DAMS exporter output (label 32771). The same program is the
# live peer of `cargo test -p routeloom-edhoc --test interop` when
# ROUTELOOM_EDHOC_PEER points at it. The backend arena is 2048 B, so both
# the kid-only transcript and the full join transcript (certificates by
# value in EAD_2/EAD_3, ~1.4 KiB arena) replay here.
add_executable(routeloom_edhoc_interop_peer edhoc_interop_peer.cpp)
target_link_libraries(routeloom_edhoc_interop_peer PRIVATE routeloom_core routeloom_edhoc_headers)
target_compile_options(routeloom_edhoc_interop_peer PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_edhoc_interop_replay COMMAND routeloom_edhoc_interop_peer --replay
    ${CMAKE_SOURCE_DIR}/protocol/edhoc-interop/method0_join_kid_only.txt)
add_test(NAME routeloom_edhoc_interop_replay_join COMMAND routeloom_edhoc_interop_peer --replay
    ${CMAKE_SOURCE_DIR}/protocol/edhoc-interop/method0_join.txt)
# P4 member handshake (design-p4 §5): the same program replays the member
# transcript — session EAD items (Intent/State/Confirm) and the five
# session Exporter outputs (dir1/dir2 key+IV, RMS) — recorded against
# host/routeloom-edhoc (`cargo test -p routeloom-edhoc --test member`).
add_test(NAME routeloom_edhoc_interop_replay_member COMMAND routeloom_edhoc_interop_peer --replay
    ${CMAKE_SOURCE_DIR}/protocol/edhoc-interop/method0_member.txt)
