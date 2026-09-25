#!/bin/sh
# Runs INSIDE the booted, verified, RAM-resident base image as root (PID 1's child of stage 2).
# Exercises the governance stack under a real kernel without a user namespace.
export PATH=/bin:/usr/bin
export JLR_STATE=/run/jlr-state
export JLR_CELL_INIT=/usr/bin/jlr-cell-init
say() { echo "GUEST: $*"; }

say "uid=$(id -u) kernel=$(uname -r) root_is_ro=$(grep ' / ' /proc/mounts | grep -c 'ro[ ,]')"

jlr init > /tmp/init.out 2>&1 && say "init ok" || { say "init FAILED"; cat /tmp/init.out; }
jlr scan /bin /usr/bin > /tmp/scan.out 2>&1 && say "scan ok $(grep -o 'results.*' /tmp/scan.out)" || { say "scan FAILED"; cat /tmp/scan.out; }
jlr status 2>&1 | grep -q 'posture     PROVEN' && say "posture proven"

# An unmanaged program runs only in an observation cell.
jlr run /bin/busybox echo hello-from-cell > /tmp/run.out 2> /tmp/run.err
say "cell stdout=$(cat /tmp/run.out)"
say "cell decision: $(grep -o 'OBSERVED in CELL-0 network=NONE' /tmp/run.err)"
say "cell enforcement: $(grep -o 'enforcement=[A-Za-z]*' /tmp/run.err)"

# What the workload can and cannot do.
jlr run /bin/busybox sh -c 'echo cell-uid=$(id -u); test -e /run/jlr-state && echo STATE-VISIBLE || echo state-hidden; grep -E "^(NoNewPrivs|CapEff):" /proc/self/status | tr "\t" " "; echo x > /usr/evil 2>/dev/null && echo USR-WRITABLE || echo usr-readonly' 2>/dev/null | while read -r l; do say "in-cell: $l"; done

jlr ledger verify 2>&1 | grep -q 'ledger OK' && say "ledger ok"
say "done"
