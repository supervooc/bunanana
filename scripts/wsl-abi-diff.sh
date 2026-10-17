#!/bin/bash
# Cross-ABI differential check on the real Android emulator (WSL + KVM).
#
# Pushes both the 64-bit scanner and the 32-bit (i686) helper to
# /data/local/tmp, then runs the 64-bit scanner with -v.  rd_check_abi_diff()
# finds /data/local/tmp/rootdetect-x86 next to itself and execs it with
# --probe-dump, so the whole report is produced by the real device.
#
# Run from Windows with:
#   cmd /c "wsl -u root -e bash /mnt/c/.../android-rootdetect/scripts/wsl-abi-diff.sh"
#
# Everything (including the full -v output) is appended to out/abi-diff-report.txt.
set -u
ADB=/opt/rx-android/platform-tools/adb
SRC=/mnt/c/Users/86134/Documents/deepseek-harness/default-workspace/android-rootdetect
HOST64=$SRC/out/rootdetect-x86_64
HOST86=$SRC/out/rootdetect-x86
REPORT=$SRC/out/abi-diff-report.txt
# A helper is only executed when its directory is not group/other writable while
# we run as root (see abi_helper_trusted in src/rd_kernel.c): /data/local/tmp is
# drwxrwx--x shell shell, so a root run must use a root-only directory instead.
if [ "$($ADB shell id -u 2>/dev/null | tr -d '\r')" = "0" ]; then
  D=/data/local/rx
  $ADB shell "mkdir -p $D && chmod 700 $D" > /dev/null 2>&1
else
  D=/data/local/tmp
fi
RAW64=/tmp/abi-diff-64.raw
RAW86=/tmp/abi-diff-32.raw

log() { printf '%s\n' "$*" >> "$REPORT"; printf '%s\n' "$*"; }
hr()  { log ""; log "================ $* ================"; }

: > "$REPORT"

hr "environment"
log "date        : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "adb         : $ADB"
log "adb version : $($ADB version 2>&1 | tr -d '\r' | head -1)"
log "host 64-bit : $HOST64 ($(stat -c %s "$HOST64" 2>/dev/null) bytes)"
log "host 32-bit : $HOST86 ($(stat -c %s "$HOST86" 2>/dev/null) bytes)"

hr "device"
log "$($ADB devices -l | tr -d '\r')"
log "ro.product.cpu.abilist   = $($ADB shell getprop ro.product.cpu.abilist | tr -d '\r')"
log "ro.product.cpu.abilist32 = $($ADB shell getprop ro.product.cpu.abilist32 | tr -d '\r')"
log "ro.product.cpu.abilist64 = $($ADB shell getprop ro.product.cpu.abilist64 | tr -d '\r')"
log "ro.zygote                = $($ADB shell getprop ro.zygote | tr -d '\r')"
log "ro.build.version.sdk     = $($ADB shell getprop ro.build.version.sdk | tr -d '\r')"
log "ro.build.type            = $($ADB shell getprop ro.build.type | tr -d '\r')"
log "uid                      = $($ADB shell id | tr -d '\r')"

hr "host ELF headers (python3)"
python3 - "$HOST86" "$HOST64" <<'PY' >> "$REPORT"
import struct, sys
NAMES = {3: 'EM_386', 62: 'EM_X86_64', 40: 'EM_ARM', 183: 'EM_AARCH64'}
for p in sys.argv[1:]:
    b = open(p, 'rb').read()
    cls, data = b[4], b[5]
    is64 = cls == 2
    end = '<' if data == 1 else '>'
    machine = struct.unpack_from(end + 'H', b, 18)[0]
    if is64:
        phoff = struct.unpack_from(end + 'Q', b, 32)[0]
        phentsize, phnum = struct.unpack_from(end + 'HH', b, 54)
    else:
        phoff = struct.unpack_from(end + 'I', b, 28)[0]
        phentsize, phnum = struct.unpack_from(end + 'HH', b, 42)
    interp = []
    for i in range(phnum):
        o = phoff + i * phentsize
        ptype = struct.unpack_from(end + 'I', b, o)[0]
        if ptype == 3:  # PT_INTERP
            if is64:
                off, sz = struct.unpack_from(end + 'QQ', b, o + 8)
            else:
                off, sz = struct.unpack_from(end + 'II', b, o + 4)
            interp.append(b[off:off + sz - 1].decode('ascii', 'replace'))
    print("%-44s class=%s machine=%s(%d) PT_INTERP=%s" % (
        p.rsplit('/', 1)[-1],
        'ELF64' if is64 else 'ELF32',
        NAMES.get(machine, 'unknown'), machine,
        interp if interp else 'none (static)'))
PY

hr "push both binaries"
log "$($ADB push "$HOST64" $D/rootdetect-x86_64 2>&1 | tr -d '\r' | tail -1)"
log "$($ADB push "$HOST86" $D/rootdetect-x86 2>&1 | tr -d '\r' | tail -1)"
$ADB shell "chmod 755 $D/rootdetect-x86_64 $D/rootdetect-x86" > /dev/null 2>&1
log "on device:"
log "$($ADB shell "ls -l $D/rootdetect-x86 $D/rootdetect-x86_64" | tr -d '\r')"

hr "1. can the 32-bit helper execute at all? ($D/rootdetect-x86 --selftest)"
$ADB shell "$D/rootdetect-x86 --selftest" > "$RAW86" 2>&1
rc32=$?
tr -d '\r' < "$RAW86" | while IFS= read -r l; do log "  $l"; done
log "exit status: $rc32"

hr "2. full output of $D/rootdetect-x86_64 -v (64-bit main, 32-bit helper side by side)"
$ADB shell "$D/rootdetect-x86_64 -v" > "$RAW64" 2>&1
rc64=$?
tr -d '\r' < "$RAW64" | while IFS= read -r l; do log "$l"; done
log "exit status: $rc64"

hr "2b. negative control: a lone 64-bit helper next to the 64-bit main"
# Proves the whole path is live: discovery + exec of the helper + parsing of its
# "# rd-probe-dump <abi>" header.  Self directory search wins over
# /data/local/tmp, so this directory's own 64-bit copy is picked as the "helper"
# and the comparison is correctly refused as same-ABI.
RAWCTL=/tmp/abi-diff-ctl.raw
$ADB shell "mkdir -p $D/abi-ctrl" > /dev/null 2>&1
log "$($ADB push "$HOST64" $D/abi-ctrl/rootdetect-x86_64 2>&1 | tr -d '\r' | tail -1)"
$ADB shell "chmod 755 $D/abi-ctrl/rootdetect-x86_64" > /dev/null 2>&1
$ADB shell "$D/abi-ctrl/rootdetect-x86_64 -v" > "$RAWCTL" 2>&1
ctlrc=$?
CTL=$(tr -d '\r' < "$RAWCTL" | grep -A1 -E 'abi-consistency|abi-diff-skipped|abi-consistency-mismatch' || true)
printf '%s\n' "$CTL" | while IFS= read -r l; do log "$l"; done
log "exit status: $ctlrc"
$ADB shell "rm -rf $D/abi-ctrl" > /dev/null 2>&1

hr "2c. same-revision control: both ABIs built from ONE source snapshot"
# src/ is edited concurrently by another teammate, so out/rootdetect-x86_64 (built
# earlier) and out/rootdetect-x86 may not come from the same snapshot.  This
# section uses a private pair built from a single snapshot (vendor/tmp/abi-same)
# so the comparison cannot be explained away by source drift.  Skipped when that
# pair has not been built.
SAME=$SRC/vendor/tmp/abi-same/out
DSAME=$D/abi-same
RAW_SAME=/tmp/abi-diff-same.raw
if [ -f "$SAME/rootdetect-x86_64" ] && [ -f "$SAME/rootdetect-x86" ]; then
  $ADB shell "mkdir -p $DSAME" > /dev/null 2>&1
  log "$($ADB push "$SAME/rootdetect-x86_64" $DSAME/rootdetect-x86_64 2>&1 | tr -d '\r' | tail -1)"
  log "$($ADB push "$SAME/rootdetect-x86" $DSAME/rootdetect-x86 2>&1 | tr -d '\r' | tail -1)"
  $ADB shell "chmod 755 $DSAME/rootdetect-x86_64 $DSAME/rootdetect-x86" > /dev/null 2>&1
  $ADB shell "$DSAME/rootdetect-x86_64 -v" > "$RAW_SAME" 2>&1
  samerc=$?
  SAME_LINES=$(tr -d '\r' < "$RAW_SAME" | grep -A1 -E 'abi-consistency|abi-diff-skipped|abi-consistency-mismatch' || true)
  printf '%s\n' "$SAME_LINES" | while IFS= read -r l; do log "$l"; done
  log "exit status: $samerc"
  $ADB shell "rm -rf $DSAME" > /dev/null 2>&1
else
  log "(skipped: build the pair with vendor/tmp/abi-same-build.ps1 first)"
fi

hr "3. cross-ABI verdict lines"
GREP=$(tr -d '\r' < "$RAW64" | grep -A1 -E 'abi-consistency|abi-diff-skipped|abi-consistency-mismatch' || true)
if [ -n "$GREP" ]; then
  printf '%s\n' "$GREP" | while IFS= read -r l; do log "$l"; done
else
  log "(no abi-* line found in the -v output)"
fi

hr "summary"
if printf '%s\n' "$GREP" | grep -q 'abi-consistency-mismatch'; then
  log "RESULT: MISMATCH - 32-bit and 64-bit views differ (see abi-consistency-mismatch above)"
elif printf '%s\n' "$GREP" | grep -q '^.*abi-consistency[^-]'; then
  log "RESULT: CONSISTENT - cross-ABI diff executed and both ABIs agreed"
elif printf '%s\n' "$GREP" | grep -q 'abi-diff-skipped'; then
  log "RESULT: SKIPPED - helper could not be used (see abi-diff-skipped above)"
else
  log "RESULT: UNKNOWN - no abi-* line at all"
fi
log "report: $REPORT"
