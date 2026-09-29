# Minimal external consumer (CI cell consumer-esp32c3): an ESP-IDF project
# that only depends on routeloom_device through the component manager
# (main/idf_component.yml) — no EXTRA_COMPONENT_DIRS, no Kconfig.projbuild.
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(routeloom_idf_consumer)
