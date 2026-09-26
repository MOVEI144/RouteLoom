# routeloom_bench — the bench application protocol/state machine shared by
# firmware/bench_node and the host-side tests (design-devflow.md §5). Portable
# C++17, heap-free, noexcept; it consumes only the public routeloom SDK API.
set(ROUTELOOM_BENCH_SOURCES
  src/protocol.cpp
  src/app.cpp
)

if(COMMAND idf_component_register)
  idf_component_register(
    SRCS ${ROUTELOOM_BENCH_SOURCES}
    INCLUDE_DIRS include
    REQUIRES routeloom
  )
  target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
  target_compile_options(${COMPONENT_LIB} PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra -Wpedantic -Werror>)
else()
  add_library(routeloom_bench STATIC ${ROUTELOOM_BENCH_SOURCES})
  target_include_directories(routeloom_bench PUBLIC include)
  target_link_libraries(routeloom_bench PUBLIC routeloom_core)
  target_compile_features(routeloom_bench PUBLIC cxx_std_17)
  target_compile_options(routeloom_bench PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra -Wpedantic -Werror>)
endif()
