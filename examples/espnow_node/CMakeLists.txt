cmake_minimum_required(VERSION 3.16)

# Consumption style (a) — in-repo build: when this example sits inside a
# RouteLoom checkout, add the repository's components/ directory to the
# component search path. When the example is copied into an external project
# the path is absent and this block is a no-op; consumption style (b) —
# component-manager git dependencies declared in main/idf_component.yml —
# then resolves routeloom/routeloom and routeloom/routeloom_espnow instead.
# See README.md for both flows.
set(_routeloom_repo_components "${CMAKE_CURRENT_LIST_DIR}/../../components")
if(EXISTS "${_routeloom_repo_components}/routeloom/CMakeLists.txt")
  list(APPEND EXTRA_COMPONENT_DIRS "${_routeloom_repo_components}")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(routeloom_espnow_node)
