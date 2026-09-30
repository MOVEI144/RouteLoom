#!/bin/bash
cd /home/sahur/orca/workspaces/RouteLoom/v2-h1
L=artifacts/hil/2026-09-30-h1/build
b(){ lab=$1; shift; rm -rf artifacts/hil/images/$lab; tools/hil/build_image.sh "$@" > $L/$lab.log 2>&1; echo "BUILD $lab rc=$?"; }
M=CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y
b h1-br-os-obs bridge_node esp32c3 h1-br-os-obs $M CONFIG_ROUTELOOM_CAPABILITY=0x807 'CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="10:bd:a3:b1:47:54"' &
b h1-br-os-plain bridge_node esp32c3 h1-br-os-plain $M 'CONFIG_ROUTELOOM_HIL_DROP_RX_MAC="10:bd:a3:b1:47:54"' &
wait
echo FLOW_DONE
