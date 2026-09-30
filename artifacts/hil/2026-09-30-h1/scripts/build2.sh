#!/bin/bash
cd /home/sahur/orca/workspaces/RouteLoom/v2-h1
L=artifacts/hil/2026-09-30-h1/build
b(){ lab=$1; shift; rm -rf artifacts/hil/images/$lab; tools/hil/build_image.sh "$@" > $L/$lab.log 2>&1; echo "BUILD $lab rc=$?"; }
M=CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y
b h1-br-cfg-ns bridge_node esp32c3 h1-br-cfg-ns $M CONFIG_ROUTELOOM_USB_GATEWAY_ENDPOINT=y CONFIG_ROUTELOOM_USB_NODE_STATUS=y CONFIG_ROUTELOOM_CAPABILITY=0x5f &
b h1-br-cfg bridge_node esp32c3 h1-br-cfg $M CONFIG_ROUTELOOM_USB_GATEWAY_ENDPOINT=y CONFIG_ROUTELOOM_CAPABILITY=0x1f &
wait
b h1-br-plan-ns bridge_node esp32c3 h1-br-plan-ns $M CONFIG_ROUTELOOM_MIGRATION=2 CONFIG_ROUTELOOM_USB_NODE_STATUS=y CONFIG_ROUTELOOM_CAPABILITY=0x2047 &
b h1-br-plan bridge_node esp32c3 h1-br-plan $M CONFIG_ROUTELOOM_MIGRATION=2 CONFIG_ROUTELOOM_CAPABILITY=0x2007 &
wait
echo FLOW_DONE
