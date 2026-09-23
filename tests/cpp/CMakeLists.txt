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
