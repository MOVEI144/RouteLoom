# Parser fuzz harnesses (issue #19). Every fuzz_<target>.cpp defines
# LLVMFuzzerTestOneInput; fuzz_driver.hpp supplies either the real libFuzzer
# entry (when -fsanitize=fuzzer is active) or a dependency-free replay main
# that ctest uses for deterministic corpus regression on any compiler.
#
# ROUTELOOM_BUILD_FUZZERS=ON + Clang => coverage-guided fuzzer binaries.
# Default (any compiler) => replay binaries; the corpus tests below replay
# every seed and run one deterministic seeded mutation round.

option(ROUTELOOM_BUILD_FUZZERS "Build fuzz targets with -fsanitize=fuzzer (Clang only)" OFF)

set(ROUTELOOM_FUZZER_ENABLED OFF)
if(ROUTELOOM_BUILD_FUZZERS)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(ROUTELOOM_FUZZER_ENABLED ON)
  else()
    message(WARNING
      "ROUTELOOM_BUILD_FUZZERS needs Clang for -fsanitize=fuzzer; "
      "building corpus-replay binaries instead")
  endif()
endif()

set(ROUTELOOM_FUZZ_TARGETS
  wire_frame
  usb_codec
  autonomy
  endpoint
  host_ops
  migration
  cose
)

foreach(target ${ROUTELOOM_FUZZ_TARGETS})
  add_executable(fuzz_${target} fuzz_${target}.cpp)
  target_link_libraries(fuzz_${target} PRIVATE routeloom_core)
  target_include_directories(fuzz_${target} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/tests/cpp)
  target_compile_options(fuzz_${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  if(ROUTELOOM_FUZZER_ENABLED)
    target_compile_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
    target_compile_definitions(fuzz_${target} PRIVATE ROUTELOOM_LIBFUZZER=1)
    target_link_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
  endif()
  # Same command line in both modes: replay main walks the directory and
  # runs -runs=1 seeded mutation; libFuzzer loads the corpus then runs one
  # iteration with the same seed. Empty corpora are still safe (runs=1
  # exits immediately).
  add_test(NAME fuzz_${target}_corpus
           COMMAND fuzz_${target}
                   ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${target}
                   -runs=1 -seed=7)
endforeach()
