#!/bin/bash
cd /home/sahur/orca/workspaces/RouteLoom/v2-stab-b
L=artifacts/hil/2026-09-30-stab/build
b(){ lab=$1; shift; rm -rf artifacts/hil/images/$lab; tools/hil/build_image.sh "$@" > $L/$lab.log 2>&1; echo "BUILD $lab rc=$?"; }
M=CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y
EPP="CONFIG_ROUTELOOM_RESOURCE_PROFILE_ENDPOINT=y CONFIG_ROUTELOOM_ROLE_ENDPOINT=y"
TEL="CONFIG_ROUTELOOM_HIL_HEAP_TELEMETRY=y"
FEAT="CONFIG_ROUTELOOM_CONFIG=y CONFIG_ROUTELOOM_MIGRATION=2"
DROP_EP='CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="10:bd:a3:b1:47:54"'
DROP_BR='CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="94:a9:90:7a:26:ac"'
b sb-br-plan bridge_node esp32c3 sb-br-plan $M CONFIG_ROUTELOOM_MIGRATION=2 CONFIG_ROUTELOOM_USB_NODE_STATUS=y CONFIG_ROUTELOOM_CAPABILITY=0x2047 &
b sb-rl-feat reference_node esp32c6 sb-rl-feat $M $TEL $FEAT &
b sb-ep-feat reference_node esp32c6 sb-ep-feat $M $EPP $TEL $FEAT &
wait
b sb-br-chain bridge_node esp32c3 sb-br-chain $M CONFIG_ROUTELOOM_CAPABILITY=0x867 CONFIG_ROUTELOOM_USB_NODE_STATUS=y "$DROP_EP" &
b sb-rl-os reference_node esp32c6 sb-rl-os $M $TEL &
b sb-ep-os reference_node esp32c6 sb-ep-os $M $EPP $TEL "$DROP_BR" &
wait
b sb-br-n1 bridge_node esp32c3 sb-br-n1 $M CONFIG_ROUTELOOM_CAPABILITY=0x867 "$DROP_EP" &
wait
echo FLOW_DONE
