#!/bin/bash
# Pre-fix A/B images: this branch minus the handshake flight change, built in a
# standalone scratch copy (its own git, never the worktree's).
set -e
W=/tmp/claude-1000/-home-sahur-dev-RouteLoom/94e9be78-2d5d-4b62-9e0d-5c6717ee4cb7/scratchpad/prefix
R=/home/sahur/orca/workspaces/RouteLoom/v2-stab-b
rm -rf $W; mkdir -p $W
rsync -a --exclude '.git' --exclude '/build*/' --exclude 'firmware/*/build/' --exclude 'host/target' --exclude '/artifacts' $R/ $W/src/
git -C $R show 94dbce55 -- components > $W/fix.patch
cd $W/src && patch -R -p1 < $W/fix.patch
git init -q && git add -A && git -c user.name=x -c user.email=x@x commit -qm "pre-fix of 94dbce55"
M=CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y
L=$R/artifacts/hil/2026-09-30-stab/build
mkdir -p artifacts/hil/images
tools/hil/build_image.sh bridge_node esp32c3 sb-br-plan-pre $M CONFIG_ROUTELOOM_MIGRATION=2 CONFIG_ROUTELOOM_USB_NODE_STATUS=y CONFIG_ROUTELOOM_CAPABILITY=0x2047 > $L/sb-br-plan-pre.log 2>&1 &
tools/hil/build_image.sh reference_node esp32c6 sb-rl-feat-pre $M CONFIG_ROUTELOOM_HIL_HEAP_TELEMETRY=y CONFIG_ROUTELOOM_CONFIG=y CONFIG_ROUTELOOM_MIGRATION=2 > $L/sb-rl-feat-pre.log 2>&1 &
wait
rm -rf $R/artifacts/hil/images/sb-br-plan-pre $R/artifacts/hil/images/sb-rl-feat-pre
cp -r artifacts/hil/images/sb-br-plan-pre artifacts/hil/images/sb-rl-feat-pre $R/artifacts/hil/images/
echo BUILT
