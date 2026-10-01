#!/bin/bash
pkill -f "^[^ ]*python3 /tmp/routeloom-hil-v2/stab/cap.py"
pkill -f "^[^ ]*python3 plan.py"
pkill -f "^[^ ]*python3 [^ ]*join_approve.py"
true
