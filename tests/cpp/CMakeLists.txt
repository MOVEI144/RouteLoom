add_executable(routeloom_core_tests test_main.cpp)
target_link_libraries(routeloom_core_tests PRIVATE routeloom_core)
target_compile_options(routeloom_core_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_core_tests COMMAND routeloom_core_tests)

add_executable(routeloom_routing_tests test_routing_sims.cpp)
target_link_libraries(routeloom_routing_tests PRIVATE routeloom_core)
target_compile_options(routeloom_routing_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_routing_tests COMMAND routeloom_routing_tests)

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

add_executable(routeloom_discovery_tests test_discovery.cpp)
target_link_libraries(routeloom_discovery_tests PRIVATE routeloom_core)
target_include_directories(routeloom_discovery_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_discovery_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_discovery_tests COMMAND routeloom_discovery_tests)

add_executable(routeloom_congestion_tests test_congestion.cpp)
target_link_libraries(routeloom_congestion_tests PRIVATE routeloom_core)
target_include_directories(routeloom_congestion_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(routeloom_congestion_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_congestion_tests COMMAND routeloom_congestion_tests)

add_executable(routeloom_c_header_test c_api_smoke.c)
target_link_libraries(routeloom_c_header_test PRIVATE routeloom_core)
set_target_properties(routeloom_c_header_test PROPERTIES LINKER_LANGUAGE CXX)
target_compile_options(routeloom_c_header_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_c_header_test COMMAND routeloom_c_header_test)
