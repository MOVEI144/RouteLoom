#!/bin/bash
# stop daemon, reset bridge through esptool, start daemon, wait for routes to 2 and 3
R=/home/sahur/orca/workspaces/RouteLoom/v2-h1
pkill -x routeloom-host; sleep 1
esptool --chip esp32c3 --port /dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_94:A9:90:7A:26:AC-if00 chip-id > /dev/null 2>&1
sleep 1
setsid /tmp/routeloom-hil-v2/h1/daemon.sh ${1:-/tmp/routeloom-hil-v2/h1/daemon-restart.log} < /dev/null > /dev/null 2>&1 &
python3 $R/tools/hil/route_convergence.py --ctl $R/host/target/debug/routeloomctl --socket /tmp/routeloom-hil-v2-h1.sock --nodes 2 3 --seconds 90 --out /tmp/routeloom-hil-v2/h1/restart-routes.jsonl | tail -1
