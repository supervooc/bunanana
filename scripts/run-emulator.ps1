# Boot the AVD with -writable-system so fixtures can be injected into /system.
#   pwsh -File scripts/run-emulator.ps1 [-Name rootdetect] [-Headless]
param(
  [string]$Name = "rootdetect",
  [switch]$Headless,
  [switch]$Wipe
)
$root    = Split-Path -Parent $PSScriptRoot
$sdk     = Join-Path $root "vendor\sdk"

# Keep every emulator write inside the workspace (no admin, no ~/.android churn).
$env:ANDROID_SDK_ROOT    = $sdk
$env:ANDROID_HOME        = $sdk
$env:ANDROID_AVD_HOME    = Join-Path $root "vendor\avd"
$env:ANDROID_USER_HOME   = Join-Path $root "vendor\android-home"
$env:ANDROID_EMULATOR_HOME = Join-Path $root "vendor\android-home"
$env:ANDROID_TMP         = Join-Path $root "vendor\tmp"
New-Item -ItemType Directory -Force -Path $env:ANDROID_TMP | Out-Null

# The emulator launcher is supposed to extend the child's DLL search path, but
# the backend (qemu-system-x86_64-headless.exe) exits with 0xC0000135
# (STATUS_DLL_NOT_FOUND) when it does not. Doing it here makes the boot
# deterministic instead of relying on the launcher's environment plumbing.
$exe = Join-Path $sdk "emulator\emulator.exe"
$env:PATH = @(
  (Join-Path $sdk "emulator"),
  (Join-Path $sdk "emulator\lib64"),
  (Join-Path $sdk "emulator\lib64\gles_swiftshader"),
  (Join-Path $sdk "emulator\lib64\vulkan"),
  $env:PATH
) -join ";"
$a = @(
  "-avd", $Name,
  "-writable-system",       # allows `adb remount` + fixture injection into /system
  "-no-boot-anim",
  "-no-audio",
  # -gpu off is not a style choice: with gfxstream enabled this host fails
  # "Failed to create Vulkan instance (VK_ERROR_INITIALIZATION_FAILED)" and the
  # emulator exits during VM setup. Guest-side rendering sidesteps the host
  # Vulkan ICD entirely. See README "模拟器启动排错".
  "-gpu", "off",
  "-no-metrics",
  "-netdelay", "none", "-netspeed", "full",
  "-memory", "2048",
  "-cores", "4",
  "-no-snapshot",
  "-timezone", "Asia/Shanghai"
)
if ($Headless) { $a += @("-no-window") }
if ($Wipe)     { $a += @("-wipe-data") }

# adb 1.0.41 writes $TEMP\adb.log; give the emulator + adb a private temp dir.
$env:TEMP = $env:ANDROID_TMP
$env:TMP  = $env:ANDROID_TMP

Write-Host "launching: $exe $($a -join ' ')"
& $exe @a
exit $LASTEXITCODE
