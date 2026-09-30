#!/bin/bash
cd /home/sahur/orca/workspaces/RouteLoom/v2-h1
L=artifacts/hil/2026-09-30-h1/build
b(){ lab=$1; shift; rm -rf artifacts/hil/images/$lab; tools/hil/build_image.sh "$@" > $L/$lab.log 2>&1; echo "BUILD $lab rc=$?"; }
M=CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y
OG=CONFIG_COMPILER_OPTIMIZATION_DEBUG=y
EPP="CONFIG_ROUTELOOM_RESOURCE_PROFILE_ENDPOINT=y CONFIG_ROUTELOOM_ROLE_ENDPOINT=y"
TEL="CONFIG_ROUTELOOM_HIL_HEAP_TELEMETRY=y CONFIG_ROUTELOOM_HIL_EDHOC_TIMING=y"
BROBS="CONFIG_ROUTELOOM_CAPABILITY=0x867 CONFIG_ROUTELOOM_USB_NODE_STATUS=y"
DROP_EP='CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="10:bd:a3:b1:47:54"'
DROP_BR='CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="94:a9:90:7a:26:ac"'
b h1-setup-bridge-c3-member bridge_node esp32c3 h1-setup-bridge-c3-member CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE=y $M &
b h1-setup-ref-c6-member reference_node esp32c6 h1-setup-ref-c6-member CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE=y $M &
b h1-br-os bridge_node esp32c3 h1-br-os $M $BROBS "$DROP_EP" &
wait
b h1-br-og bridge_node esp32c3 h1-br-og $M $BROBS "$DROP_EP" $OG &
b h1-rl-os reference_node esp32c6 h1-rl-os $M $TEL &
b h1-rl-og reference_node esp32c6 h1-rl-og $M $TEL $OG &
wait
b h1-ep-os reference_node esp32c6 h1-ep-os $M $EPP $TEL "$DROP_BR" &
b h1-ep-og reference_node esp32c6 h1-ep-og $M $EPP $TEL "$DROP_BR" $OG &
b h1-br-feat bridge_node esp32c3 h1-br-feat $M CONFIG_ROUTELOOM_USB_GATEWAY_ENDPOINT=y CONFIG_ROUTELOOM_USB_NODE_STATUS=y CONFIG_ROUTELOOM_MIGRATION=2 CONFIG_ROUTELOOM_CAPABILITY=0x285f &
wait
b h1-rl-feat reference_node esp32c6 h1-rl-feat $M CONFIG_ROUTELOOM_HIL_HEAP_TELEMETRY=y CONFIG_ROUTELOOM_CONFIG=y CONFIG_ROUTELOOM_MIGRATION=2 CONFIG_ROUTELOOM_HIL_GATEWAY_SEND_COUNT=20 CONFIG_ROUTELOOM_HIL_GATEWAY_WRONG=0x3 &
b h1-ep-feat reference_node esp32c6 h1-ep-feat $M $EPP CONFIG_ROUTELOOM_HIL_HEAP_TELEMETRY=y CONFIG_ROUTELOOM_CONFIG=y CONFIG_ROUTELOOM_MIGRATION=2 CONFIG_ROUTELOOM_HIL_GATEWAY_SEND_COUNT=20 CONFIG_ROUTELOOM_HIL_GATEWAY_WRONG=0x2 &
wait
echo FLOW_DONE
