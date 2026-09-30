# Minimal external consumer (CI cells idf_consumer-<chip> on C3, S3, C5 and
# C6): an ESP-IDF project with a C and a C++ source that only depends on
# routeloom_device through the component manager (main/idf_component.yml) —
# no EXTRA_COMPONENT_DIRS, no Kconfig.projbuild, no include of the SDK tree.
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(routeloom_idf_consumer)
