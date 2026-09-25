#!/bin/sh
# Runs INSIDE the verified RAM base as root: exercises the exec gate (jlrd) under a real kernel.
export PATH=/bin:/usr/bin
export JLR_STATE=/run/jlr-state
export JLR_CELL_INIT=/usr/bin/jlr-cell-init
say() { echo "GUEST: $*"; }
try() { # try NAME PATH: run PATH true and report whether the kernel let it start
  if "$2" true 2>/tmp/err; then say "$1: ran"; else say "$1: BLOCKED ($(cat /tmp/err | tr '\n' ' '))"; fi
}

# BusyBox picks its applet from argv[0], so every copy keeps the file name "busybox".
mkdir -p /tmp/opt/known /tmp/opt/stranger /tmp/opt/stranger2
cp /bin/busybox /tmp/opt/known/busybox
jlr init >/dev/null 2>&1 && say "init ok"
# The verified base image is the installer's trust root: enrol what is on disk now.
jlr baseline enroll /bin /usr /tmp/opt --include-unmanaged 2>&1 | grep -o 'baseline initial-host: [0-9]* members' | sed 's/^/GUEST: /'

# A program that appears AFTER enrolment is unknown.
cp /bin/busybox /tmp/opt/stranger/busybox

jlrd --scan-every 0 > /tmp/jlrd.log 2>&1 &
JLRD=$!
sleep 2
say "gate: $(grep -o 'exec gate active on [0-9]* file systems' /tmp/jlrd.log)"
say "mode: $(jlr status 2>&1 | grep 'exec gate' | tr -s ' ' | cut -c1-40)"

try "audit known" /tmp/opt/known/busybox
try "audit stranger" /tmp/opt/stranger/busybox
sleep 1
say "log: $(grep -c 'audit: would deny /tmp/opt/stranger/busybox' /tmp/jlrd.log) audit line(s) for the stranger"

jlr policy enforce on >/dev/null 2>&1 && say "enforce on"
sleep 2
try "enforce known" /tmp/opt/known/busybox
try "enforce stranger" /tmp/opt/stranger/busybox
cp /bin/busybox /tmp/opt/stranger2/busybox
try "enforce stranger2" /tmp/opt/stranger2/busybox
try "enforce system tool" /bin/busybox

# A file the gate cannot measure (padded past the size limit by whoever owns it) is DENIED, never waved through.
mkdir -p /tmp/opt/padded
cp /bin/busybox /tmp/opt/padded/busybox
truncate -s 600M /tmp/opt/padded/busybox
try "enforce unmeasurable" /tmp/opt/padded/busybox

# A file system mounted AFTER the daemon started is gated as well.
mkdir -p /tmp/late
mount -t tmpfs tmpfs /tmp/late
cp /bin/busybox /tmp/late/busybox
sleep 1
try "late mount stranger" /tmp/late/busybox

# Tamper with an enrolled binary: it must stop being trusted.
echo tampered >> /tmp/opt/known/busybox
try "tampered known" /tmp/opt/known/busybox

# The blocked program can still run, confined, through jlr.
jlr run /tmp/opt/stranger/busybox echo confined-ok 2>&1 | grep -o 'confined-ok\|OBSERVED in CELL-0[^ ]* network=NONE' | while read -r l; do say "jlr run: $l"; done

say "ledger: $(jlr ledger log -n 40 2>&1 | grep -c 'exec gate') exec-gate event(s)"
jlr ledger log -n 40 2>&1 | grep 'exec gate' | grep -o 'exec gate: [a-z: ]* /tmp/opt/[a-z0-9]*/busybox' | sort -u | while read -r l; do say "ledger: $l"; done

kill $JLRD; wait $JLRD 2>/dev/null
sleep 1
try "after stop stranger" /tmp/opt/stranger/busybox
jlr ledger verify 2>&1 | grep -q 'ledger OK' && say "ledger ok"
say "done"
