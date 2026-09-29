#!/bin/bash
# usage: daemon.sh <logfile> [extra args]
R=/home/sahur/orca/workspaces/RouteLoom/v2-h1
L=$1; shift
exec $R/host/target/debug/routeloom-host --socket /tmp/routeloom-hil-v2-h1.sock --device /dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_94:A9:90:7A:26:AC-if00 --api-acl-file /tmp/routeloom-hil-v2/h1/acl.json --usb-dev-secret-file /tmp/routeloom-hil-v2/site-h1/usb-dev-secret.key --site-authority /tmp/routeloom-hil-v2/site-h1 --admission-profile bench-v1 "$@" > $L 2>&1
