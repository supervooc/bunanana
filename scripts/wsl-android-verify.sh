#!/bin/bash
# Run the detector on the real Android emulator (WSL + KVM) and exercise every
# layer: selftest as the shell user, deep kernel checks as uid 0, and root
# artefacts that a hide module would otherwise cover up.
set -u
SRC=/mnt/c/Users/86134/Documents/deepseek-harness/default-workspace/android-rootdetect
ADB=/opt/rx-android/platform-tools/adb
RX=/data/local/tmp/rx
if [ "$($ADB shell id -u 2>/dev/null | tr -d '\r')" = "0" ]; then
  $ADB shell "mkdir -p /data/local/rx && chmod 700 /data/local/rx" > /dev/null 2>&1
  RX=/data/local/rx/rx
fi
hr() { echo; echo "================ $* ================"; }

hr "device"
$ADB devices -l
for p in ro.build.version.release ro.build.type ro.debuggable ro.secure ro.boot.verifiedbootstate ro.boot.flash.locked; do
  printf '  %-32s %s\n' "$p" "$($ADB shell getprop $p | tr -d '\r')"
done
$ADB shell "id; uname -r"

hr "push the x86_64 scanner"
$ADB push "$SRC/out/rootdetect-x86_64" $RX | tail -1
$ADB shell chmod 755 $RX

hr "1. --selftest on a real Android (shell user)"
$ADB shell $RX --selftest

hr "2. baseline as the shell user (app-equivalent view, verbose)"
$ADB shell $RX -v

hr "3. JSON verdict (shell)"
$ADB shell $RX --json | tr -d '\r' | python3 -c 'import json,sys
d=json.load(sys.stdin)
print("  verdict:", d["verdict"], d["summary"])
for f in d["findings"]:
    if f["severity"] in ("CRITICAL","HIGH","MEDIUM"): print("   ", f["severity"], f["id"], "-", f["title"])'

hr "4. adb root, then the deep kernel checks"
$ADB root > /dev/null 2>&1
sleep 4
$ADB shell id
$ADB shell $RX -v | tr -d '\r' | grep -E '^\[(CRITICAL|HIGH|MEDIUM)|^\[INFO.*(deep|kernel|kcore|hook|susfs)|summary|verdict' || true

hr "5. inject root artefacts (no /system remount needed)"
$ADB shell mkdir -p /data/adb/magisk /data/adb/modules/example
$ADB shell "printf 'MAGISK\n' > /data/adb/magisk/util_functions.sh"
$ADB shell mkdir -p /data/data/com.topjohnwu.magisk
$ADB shell cp /system/bin/toybox /data/local/tmp/su
$ADB shell chmod 755 /data/local/tmp/su
$ADB shell $RX -v | tr -d '\r' | grep -E '^\[(CRITICAL|HIGH|MEDIUM)|summary|verdict' || true

hr "6. JSON verdict with artefacts in place"
$ADB shell $RX --json | tr -d '\r' | python3 -c 'import json,sys
d=json.load(sys.stdin)
print("  verdict:", d["verdict"], d["summary"])' 

hr "7. cleanup"
$ADB shell rm -rf /data/adb /data/data/com.topjohnwu.magisk /data/local/tmp/su
$ADB shell $RX | tr -d '\r' | grep -E 'summary|verdict' || true

hr "emulator boot evidence"
grep -E 'Boot completed|ERROR.*[Aa]db' /tmp/emulator.log | head -3
