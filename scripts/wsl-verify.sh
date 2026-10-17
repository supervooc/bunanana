#!/bin/bash
# Real-kernel verification of rootdetect, run inside WSL (Ubuntu, kernel 5.10).
#
#   wsl -e      bash .../scripts/wsl-verify.sh baseline    # uid 1000: selftest + clean run
#   wsl -u root -e bash .../scripts/wsl-verify.sh fixtures # root: injected root + spoof tests
#   wsl -u root -e bash .../scripts/wsl-verify.sh clean    # remove everything again
#
# The detector expects Android paths, so the fixture mode really does create
# /system/xbin/su, /data/adb/magisk, a tmpfs over /system, and finally bind-mounts
# fake files over /proc/version and /proc/mounts to exercise the adversarial
# cross-view checks against a real kernel.
set -u
MODE="${1:-baseline}"
PROJ=/mnt/c/Users/86134/Documents/deepseek-harness/default-workspace/android-rootdetect
RX=/tmp/rootdetect-verify/rx
HELPER=/tmp/rootdetect-verify/rx-helper

hr()  { echo; echo "================ $* ================"; }
run() { echo "\$ $*"; "$@" ; echo "(exit=$?)"; }

mkdir -p /tmp/rootdetect-verify
cp -f "$PROJ/out/rootdetect-x86_64" "$RX"; chmod 755 "$RX"
# same-ABI helper, to exercise the ABI-differential "same ABI" path
cp -f "$PROJ/out/rootdetect-x86_64" "$HELPER"; chmod 755 "$HELPER"
export ROOTDETECT_ABI_HELPER="$HELPER"

fixture_cleanup() {
  umount /proc/version 2>/dev/null
  umount /proc/mounts 2>/dev/null
  umount /system 2>/dev/null
  rm -rf /system /data /tmp/rootdetect-fixtures
}

case "$MODE" in
baseline)
  hr "0. what are we running"
  echo "uid=$(id -u) kernel=$(uname -r)"
  ls -l "$RX"
  hr "1. --selftest (decision logic + false-positive guards)"
  "$RX" --selftest
  echo "(exit=$?)"
  hr "2. clean baseline, verbose (false-positive check)"
  "$RX" -v
  echo "(exit=$?)"
  hr "3. clean baseline, JSON verdict"
  "$RX" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print("verdict:", d["verdict"]); print("summary:", d["summary"]); [print(" ", f["severity"], f["id"]) for f in d["findings"]]'
  echo "(exit=$?)"
  ;;

fixtures)
  fixture_cleanup
  hr "1. inject Android-style root artefacts (real /system, /data)"
  mkdir -p /system/xbin /system/bin /data/adb/magisk /data/adb/modules/example /data/local/tmp
  printf '#!/system/bin/sh\necho fake-su\n' > /system/xbin/su;   chmod 755 /system/xbin/su
  printf '#!/system/bin/sh\necho ksud\n'    > /system/bin/ksud;   chmod 755 /system/bin/ksud
  printf 'MAGISK\n' > /data/adb/magisk/util_functions.sh
  mkdir -p /data/data/com.topjohnwu.magisk; chmod 700 /data/data/com.topjohnwu.magisk
  ls -l /system/xbin/su /system/bin/ksud /data/adb/magisk
  hr "2. run as uid 0 (deep kernel checks enabled)"
  "$RX" -v
  echo "(exit=$?)"
  hr "3. stack a tmpfs over /system and put the artefacts inside it"
  mount -t tmpfs tmpfs /system
  mkdir -p /system/xbin
  printf '#!/system/bin/sh\necho fake-su\n' > /system/xbin/su; chmod 755 /system/xbin/su
  grep -E '^tmpfs /system ' /proc/mounts
  "$RX" | grep -E 'mount-|summary|verdict' || true
  echo "(exit=$?)"
  hr "4. spoof uname the way SuSFS does: /proc/version no longer matches uname(2)"
  printf 'Linux version 9.9.9-fake-kernel (fake@fake) #1 SMP\n' > /tmp/rootdetect-fixtures-fakever
  mount --bind /tmp/rootdetect-fixtures-fakever /proc/version
  echo "uname -r      : $(uname -r)"
  echo "/proc/version : $(cat /proc/version)"
  "$RX" | grep -E 'spoof-uname|summary|verdict' || true
  umount /proc/version
  hr "5. hide a mount from one view: bind a fake table over /proc/1/mountinfo"
  # /proc/mounts and /proc/self/mountinfo resolve through procfs magic symlinks
  # whose dentries cannot be shadowed by a bind mount; /proc/1/mountinfo is a real
  # dentry, and the detector reads it explicitly as one of its four views.
  printf '/dev/sda1 / ext4 rw,relatime 0 0\n' > /tmp/rootdetect-fixtures-fakemounts
  mount --bind /tmp/rootdetect-fixtures-fakemounts /proc/1/mountinfo
  echo "/proc/mounts lines      : $(wc -l < /proc/mounts)"
  echo "/proc/1/mountinfo lines : $(wc -l < /proc/1/mountinfo)"
  "$RX" | grep -E 'mount-view|summary|verdict' || true
  umount /proc/1/mountinfo
  hr "6. restore"
  fixture_cleanup
  echo "cleaned"
  ;;

clean)
  fixture_cleanup
  rm -rf /tmp/rootdetect-verify
  echo "removed fixtures and helper binaries"
  ;;

*)
  echo "usage: $0 baseline|fixtures|clean"; exit 2;;
esac
