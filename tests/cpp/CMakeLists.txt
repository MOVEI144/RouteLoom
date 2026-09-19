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

add_executable(routeloom_c_header_test c_api_smoke.c)
target_link_libraries(routeloom_c_header_test PRIVATE routeloom_core)
set_target_properties(routeloom_c_header_test PROPERTIES LINKER_LANGUAGE CXX)
target_compile_options(routeloom_c_header_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME routeloom_c_header_test COMMAND routeloom_c_header_test)
