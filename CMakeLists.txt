cmake_minimum_required(VERSION 3.20)
project(RouteLoom LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(ROUTELOOM_BUILD_TESTS "Build portable RouteLoom tests" ON)
option(ROUTELOOM_ENABLE_SANITIZERS "Enable ASan/UBSan in host builds" OFF)

if(ROUTELOOM_ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

add_subdirectory(components/routeloom)

if(ROUTELOOM_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests/cpp)
  add_subdirectory(tests/fuzz)
endif()
