#!/bin/bash
# Press the APK's "Run detection" button through the accessibility tree, then
# screenshot the result - i.e. verify the packaged app really runs the scanner.
set -u
SRC=/mnt/c/Users/86134/Documents/deepseek-harness/default-workspace/android-rootdetect
ADB=/opt/rx-android/platform-tools/adb
hr() { echo; echo "================ $* ================"; }

hr "make sure the activity is in the foreground"
$ADB shell am start -n com.rootdetect.app/.MainActivity 2>&1 | tail -2
sleep 8

hr "accessibility tree before the tap"
$ADB shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1
$ADB pull /sdcard/ui.xml /tmp/ui.xml >/dev/null 2>&1
python3 - <<'PY'
import re
x = open('/tmp/ui.xml').read()
for m in re.finditer(r'<node[^>]*?text="([^"]*)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', x):
    t = m.group(1)
    if t.strip():
        x1, y1, x2, y2 = map(int, m.groups()[1:])
        print("   %-46r center=(%d,%d)" % (t[:44], (x1 + x2) // 2, (y1 + y2) // 2))
PY

hr "tap 'Run detection'"
COORD=$(python3 - <<'PY'
import re
x = open('/tmp/ui.xml').read()
for m in re.finditer(r'<node[^>]*?text="([^"]*)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', x):
    # Android buttons uppercase their label, so match case-insensitively
    if 'run detection' in m.group(1).lower():
        x1, y1, x2, y2 = map(int, m.groups()[1:])
        print((x1 + x2) // 2, (y1 + y2) // 2)
        break
PY
)
echo "   button center: $COORD"
$ADB shell input tap $COORD
sleep 20

hr "logcat around the scan"
$ADB logcat -d -v brief 2>&1 | grep -iE 'rootdetect|avc: *denied|AndroidRuntime|exec' | tail -12

hr "screenshot after the tap"
$ADB shell screencap -p /sdcard/rx2.png && $ADB pull /sdcard/rx2.png /tmp/rx2.png >/dev/null 2>&1
cp /tmp/rx2.png "$SRC/out/apk-screenshot-after.png"
echo "saved: out/apk-screenshot-after.png ($(stat -c%s /tmp/rx2.png) bytes)"

hr "text the app is showing now"
$ADB shell uiautomator dump /sdcard/ui2.xml >/dev/null 2>&1
$ADB pull /sdcard/ui2.xml /tmp/ui2.xml >/dev/null 2>&1
python3 - <<'PY'
import re
x = open('/tmp/ui2.xml').read()
best = ""
for m in re.finditer(r'text="([^"]*)"', x):
    if len(m.group(1)) > len(best):
        best = m.group(1)
print(best[:2600] if best else "  (no text nodes)")
PY
