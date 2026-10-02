#!/bin/bash
cd /tmp/routeloom-hil-v2/stab
for i in 1 2 3 4 5; do
  python3 boot_all.py feat3/s7/rep$i 150
  sleep 152
done
echo FLOW_DONE
