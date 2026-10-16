# Convenience wrapper around the SDK's adb that always finds the right SDK and
# a writable temp dir (adb 1.0.41 logs to $TEMP\adb.log and fails hard when it
# cannot open it).
#
#   pwsh -File scripts/adb.ps1 devices
#   pwsh -File scripts/adb.ps1 shell id
#   pwsh -File scripts/adb.ps1 push out/rootdetect-x86_64 /data/local/tmp/rx
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
$root = Split-Path -Parent $PSScriptRoot
$env:ANDROID_SDK_ROOT      = Join-Path $root "vendor\sdk"
$env:ANDROID_HOME          = $env:ANDROID_SDK_ROOT
$env:ANDROID_AVD_HOME      = Join-Path $root "vendor\avd"
$env:ANDROID_USER_HOME     = Join-Path $root "vendor\android-home"
$env:ANDROID_EMULATOR_HOME = $env:ANDROID_USER_HOME
$env:TEMP                  = Join-Path $root "vendor\tmp"
$env:TMP                   = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null
& (Join-Path $env:ANDROID_SDK_ROOT "platform-tools\adb.exe") @Args
exit $LASTEXITCODE
