# Run before ESP-IDF regenerates sdkconfig: an unknown removed choice can
# otherwise become the current default while the old assignment disappears.
if(DEFINED SDKCONFIG AND NOT SDKCONFIG STREQUAL "")
  set(_routeloom_config_path "${SDKCONFIG}")
else()
  set(_routeloom_config_path "${CMAKE_CURRENT_SOURCE_DIR}/sdkconfig")
endif()
file(GLOB _routeloom_config_inputs "${CMAKE_CURRENT_SOURCE_DIR}/sdkconfig.defaults*")
list(APPEND _routeloom_config_inputs "${_routeloom_config_path}")
string(CONCAT _routeloom_retired_mode "CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY" "_FIXTURE=y")
foreach(_routeloom_input IN LISTS _routeloom_config_inputs)
  if(EXISTS "${_routeloom_input}")
    file(STRINGS "${_routeloom_input}" _routeloom_retired_selected
         REGEX "^${_routeloom_retired_mode}$")
    if(_routeloom_retired_selected)
      message(FATAL_ERROR "The retired RouteLoom security mode was explicitly selected")
    endif()
  endif()
endforeach()
