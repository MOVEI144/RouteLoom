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
  rlres1
  sdkv1
  sdkv1_ead
  sdkv1_join
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

# RLRES1 (sdk-v1 plan P1-5): besides the shared corpus replay + 1 mutation,
# a longer deterministic mutation run over its committed seeds (genuine
# transcripts selected by mode byte) so ctest exercises the forged-message
# invariants on every compiler, not only in the libFuzzer CI job.
add_test(NAME fuzz_rlres1_mutation
         COMMAND fuzz_rlres1 ${CMAKE_CURRENT_SOURCE_DIR}/corpus/rlres1
                 -runs=4000 -seed=11)

# Join EAD codecs (sdk-v1 plan P2-3): a longer deterministic mutation run
# over the seeds tools/gen_sdkv1_ead_vectors.py writes from the golden
# vectors, so the canonical-re-encode invariant runs on every compiler.
add_test(NAME fuzz_sdkv1_ead_mutation
         COMMAND fuzz_sdkv1_ead ${CMAKE_CURRENT_SOURCE_DIR}/corpus/sdkv1_ead
                 -runs=20000 -seed=13)

# Join transport (sdk-v1 plan P3-1/P3-2): a longer deterministic mutation run
# over the seeds tools/gen_sdkv1_join_transport_vectors.py writes (codec
# inputs and complete RLD1 / Wire relay exchange scripts), so the canonical
# re-encode and engine invariants run on every compiler.
add_test(NAME fuzz_sdkv1_join_mutation
         COMMAND fuzz_sdkv1_join ${CMAKE_CURRENT_SOURCE_DIR}/corpus/sdkv1_join
                 -runs=20000 -seed=17)
