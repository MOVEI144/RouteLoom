#!/bin/bash
R=/home/sahur/orca/workspaces/RouteLoom/v2-h1; cd $R
O=artifacts/hil/2026-09-30-h1/member
CTL=$R/host/target/debug/routeloomctl; S=/tmp/routeloom-hil-v2-h1.sock
for b in ${M06_ROLES:-relay}; do
/tmp/routeloom-hil-v2/h1/restart_bridge.sh $O/daemon-before-m06-$b.log
python3 tools/hil/reset_cycles.py --rig tools/hil/rigs.yaml --bench bench-2026-09-29-h0 --board $b --ctl $CTL --socket $S --destination 3 --cycles 10 --sends 10 --send-gap-s 2 --out $O/m06-reset-$b > $O/m06-reset-$b.out 2>&1
echo "M06 $b rc=$?"
done
echo FLOW_DONE
