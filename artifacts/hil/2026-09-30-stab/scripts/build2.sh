#!/bin/bash
cd /home/sahur/orca/workspaces/RouteLoom/v2-stab-b
L=artifacts/hil/2026-09-30-stab/build
b(){ lab=$1; shift; rm -rf artifacts/hil/images/$lab; tools/hil/build_image.sh "$@" > $L/$lab.log 2>&1; echo "BUILD $lab rc=$?"; }
M=CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y
EPP="CONFIG_ROUTELOOM_RESOURCE_PROFILE_ENDPOINT=y CONFIG_ROUTELOOM_ROLE_ENDPOINT=y"
TEL="CONFIG_ROUTELOOM_HIL_HEAP_TELEMETRY=y"
FEAT="CONFIG_ROUTELOOM_CONFIG=y CONFIG_ROUTELOOM_MIGRATION=2"
b sb-br-plan bridge_node esp32c3 sb-br-plan $M CONFIG_ROUTELOOM_MIGRATION=2 CONFIG_ROUTELOOM_USB_NODE_STATUS=y CONFIG_ROUTELOOM_CAPABILITY=0x2047 &
b sb-rl-feat reference_node esp32c6 sb-rl-feat $M $TEL $FEAT &
b sb-ep-plan reference_node esp32c6 sb-ep-plan $M $EPP $TEL CONFIG_ROUTELOOM_MIGRATION=2 &
wait
echo FLOW_DONE
