# Inject root-like artefacts into a clean emulator so the detector's true
# positive path can be exercised without flashing a real root solution.
#
#   pwsh -File scripts/inject-root-fixtures.ps1            # create fixtures
#   pwsh -File scripts/inject-root-fixtures.ps1 -Clean     # remove them again
#
# Requires the emulator to have been started with -writable-system and `adb root`.
param([switch]$Clean)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$adb  = Join-Path $root "vendor\sdk\platform-tools\adb.exe"
$env:TEMP = Join-Path $root "vendor\tmp"; $env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null

function Sh([string]$cmd) {
  Write-Host "  \$ $cmd"
  & $adb shell $cmd
  if ($LASTEXITCODE -ne 0) { Write-Warning "command failed: $cmd" }
}

Write-Host "== remounting /system read-write"
& $adb root | Out-Null
Start-Sleep -Seconds 2
& $adb remount
if ($LASTEXITCODE -ne 0) { throw "adb remount failed - emulator must run with -writable-system" }

if ($Clean) {
  Write-Host "== removing fixtures"
  Sh "rm -f /system/xbin/su /system/xbin/busybox /system/bin/ksud /system/etc/init/magisk.rc"
  Sh "rm -rf /data/adb/magisk /data/adb/modules /data/local/tmp/su"
  Sh "rm -rf /data/data/com.topjohnwu.magisk /data/data/com.kingroot.kinguser"
  Sh "rm -f /data/local/tmp/rootdetect-*"
  Write-Host "done. reboot for a clean state:  scripts\adb.ps1 reboot"
  exit 0
}

Write-Host "== classic superuser binary + toolbox at the paths every checker probes"
Sh "mkdir -p /system/xbin"
Sh "printf '#!/system/bin/sh\necho fake-su\n' > /system/xbin/su"
Sh "chmod 755 /system/xbin/su"
Sh "cp /system/bin/toybox /system/xbin/busybox 2>/dev/null || touch /system/xbin/busybox"
Sh "chmod 755 /system/xbin/busybox"
Sh "printf '#!/system/bin/sh\necho ksud\n' > /system/bin/ksud"
Sh "chmod 755 /system/bin/ksud"
Sh "printf '# magisk init stub\n' > /system/etc/init/magisk.rc"

Write-Host "== Magisk / KernelSU style directories"
Sh "mkdir -p /data/adb/magisk /data/adb/modules/example /data/local/tmp"
Sh "printf 'MAGISK\n' > /data/adb/magisk/util_functions.sh"

Write-Host "== a root manager installed *and* hidden from the package manager"
Write-Host "   (this is the signature of KernelSU's 'hide the app' feature)"
Sh "mkdir -p /data/data/com.topjohnwu.magisk /data/data/com.kingroot.kinguser"
Sh "chmod 700 /data/data/com.topjohnwu.magisk"

Write-Host "== adb is rooted, so service.adb.root=1 becomes visible to every app"
Write-Host "done. run:  scripts\adb.ps1 push out/rootdetect-x86_64 /data/local/tmp/rx"
