# Build bunanana.apk without Gradle: aapt2 + javac + d8 + zipalign + apksigner.
#
#   pwsh -File build/build-apk.ps1
#
# Requires (all fetched into vendor/ by the scripts in vendor/):
#   vendor/jdk/<jdk>                      portable Temurin JDK (javac, keytool)
#   vendor/sdk/build-tools/34.0.0         aapt2, d8, zipalign, apksigner
#   vendor/sdk/platforms/android-34       android.jar
#   out/rootdetect-{arm64,arm,x86_64}     the native scanners
#   apk/res/mipmap-*/                     launcher icons (apk/make-icons.py)
param(
  [switch]$SkipSign
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$out  = Join-Path $root "out"
$work = Join-Path $root "build\apk-work"
$apkSrc = Join-Path $root "apk"
$apkName = "bunanana.apk"          # the app is bunanana; the engine stays rootdetect
$apk = Join-Path $out $apkName

# The shared %TEMP% is not reliably writable from this shell (adb/clang hit this
# too), so give the JDK and build tools a private one.
$env:TMP = Join-Path $root "vendor\tmp"
$env:TEMP = $env:TMP
New-Item -ItemType Directory -Force -Path $env:TMP | Out-Null

$jdk = (Get-ChildItem (Join-Path $root "vendor\jdk") -Directory -ErrorAction SilentlyContinue |
        Select-Object -First 1).FullName
if (-not $jdk) { throw "no JDK in vendor/jdk - run vendor/fetch-jdk.mjs" }
$bt = Join-Path $root "vendor\sdk\build-tools\34.0.0"
$androidJar = (Get-ChildItem (Join-Path $root "vendor\sdk\platforms") -Recurse -Filter android.jar |
               Select-Object -First 1).FullName
if (-not $androidJar) { throw "android.jar not found - run: node vendor/sdkpkg.mjs getall 'platforms;android-34'" }

$env:JAVA_HOME = $jdk
$env:PATH = "$jdk\bin;$bt;$env:PATH"

Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work, "$work\dex", "$work\classes", $out | Out-Null

function Step([string]$name, [scriptblock]$body) {
  Write-Host "==> $name"
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  & $body 2>&1 | ForEach-Object { Write-Host "    $_" }
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prev
  if ($rc -ne 0) { throw "$name failed (exit $rc)" }
}

# C:\x\y -> /mnt/c/x/y, so the WSL python3 helpers can reach the same files
function ToWsl([string]$p) {
  "/mnt/" + $p.Substring(0, 1).ToLower() + ($p.Substring(2) -replace '\\', '/')
}

Step "aapt2 compile (resources: icon, strings)" {
  & "$bt\aapt2.exe" compile --dir "$apkSrc\res" -o "$work\res.zip"
}

Step "aapt2 link (manifest + res -> base.apk)" {
  # The compiled resources go in as a positional input. Using -R would treat them
  # as an overlay and fail with "does not override an existing resource".
  & "$bt\aapt2.exe" link -o "$work\base.apk" -I "$androidJar" `
    --manifest "$apkSrc\AndroidManifest.xml" "$work\res.zip" `
    --min-sdk-version 24 --target-sdk-version 28 `
    --java "$work\gen"
}

Step "javac (java sources -> classes)" {
  $srcs = @(Get-ChildItem "$apkSrc\src" -Recurse -Filter *.java | ForEach-Object { $_.FullName })
  # Quote every path: an unquoted -bootclasspath argument gets mangled by
  # PowerShell's native-command argument handling ("invalid flag: :").
  # -encoding UTF-8: the Activity's UI strings are Chinese (and the sources are
  # UTF-8); without this javac 17 reads them with the platform ANSI codepage on
  # Windows and mangles the literals.
  & "$jdk\bin\javac.exe" -source 8 -target 8 -nowarn -encoding UTF-8 -bootclasspath "$androidJar" `
    -d "$work\classes" @srcs
}

Step "d8 (classes -> classes.dex)" {
  $classes = @(Get-ChildItem "$work\classes" -Recurse -Filter *.class | ForEach-Object { $_.FullName })
  & "$bt\d8.bat" --lib "$androidJar" --min-api 24 --output "$work\dex" @classes
}

Write-Host "==> assembling apk (classes.dex + native scanners)"
$abiMap = @{ "arm64" = "arm64-v8a"; "arm" = "armeabi-v7a"; "x86_64" = "x86_64"; "x86" = "x86" }
$entries = @("classes.dex=$(ToWsl "$work\dex\classes.dex")")
foreach ($a in @("arm64", "arm", "x86_64")) {
  $bin = Join-Path $out "rootdetect-$a"
  if (Test-Path $bin) { $entries += ("lib/{0}/librootdetect.so={1}" -f $abiMap[$a], (ToWsl $bin)) }
}
# A build with zero embedded scanners passes every later check vacuously
# (classes.dex alone is still a valid pair for list_apk.py), so require one.
$libEntries = @($entries | Where-Object { $_ -like 'lib/*' })
if ($libEntries.Count -eq 0) {
  throw "no native scanner embedded: build out/rootdetect-arm64 (build/build.ps1) first"
}
Write-Host ("    embedded scanners: {0} -> {1}" -f $libEntries.Count,
            (($libEntries | ForEach-Object { ($_ -split '=')[0] }) -join ', '))
$pyArgs = @("python3", (ToWsl "$apkSrc\assemble.py"), (ToWsl "$work\unsigned.apk"),
            (ToWsl "$work\base.apk")) + $entries
$cmdline = ($pyArgs | ForEach-Object { if ($_ -match ' ') { '"' + $_ + '"' } else { $_ } }) -join ' '
$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
& cmd /c "wsl -e $cmdline" 2>&1 | ForEach-Object { Write-Host "    $_" }
$rc = $LASTEXITCODE
$ErrorActionPreference = $prev
if ($rc -ne 0) { throw "apk assembly failed (exit $rc)" }

Step "zipalign" {
  & "$bt\zipalign.exe" -f -p 4 "$work\unsigned.apk" "$work\aligned.apk"
}

if (-not $SkipSign) {
  # The keystore lives outside build/apk-work on purpose: that directory is wiped
  # on every build, and regenerating the key made each APK un-installable over the
  # previous one (INSTALL_FAILED_UPDATE_INCOMPATIBLE).
  $keystore = Join-Path $root "build\debug.keystore"
  if (-not (Test-Path $keystore)) {
    Step "keytool (debug keystore)" {
      & "$jdk\bin\keytool.exe" -genkeypair -keystore "$keystore" `
        -storepass android -keypass android -alias bunanana -keyalg RSA -keysize 2048 `
        -validity 10000 -dname "CN=bunanana, OU=dev, O=dsh, L=x, ST=x, C=CN"
    }
  }
  Step "apksigner" {
    & "$bt\apksigner.bat" sign --ks "$keystore" --ks-pass pass:android `
      --key-pass pass:android --v1-signing-enabled true --v2-signing-enabled true `
      --out "$apk" "$work\aligned.apk"
  }
  Step "verify signature" {
    & "$bt\apksigner.bat" verify --print-certs "$apk"
  }
} else {
  $apk = Join-Path $out "bunanana-unsigned.apk"
  Copy-Item "$work\aligned.apk" $apk -Force
}

Step "badging" {
  & "$bt\aapt2.exe" dump badging "$apk"
}

Write-Host "`n==> apk contents and embedded binary check"
# Quote any argument that contains a space: a workspace path like
# "C:\Users\First Last\..." would otherwise be split by `cmd /c`.
$listArgs = @("python3", (ToWsl "$apkSrc\list_apk.py"), (ToWsl "$apk")) + $entries
$listCmd = ($listArgs | ForEach-Object { if ($_ -match ' ') { '"' + $_ + '"' } else { $_ } }) -join ' '
$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
& cmd /c "wsl -e $listCmd" 2>&1 | ForEach-Object { Write-Host "    $_" }
$listRc = $LASTEXITCODE
& "$bt\zipalign.exe" -c -v 4 "$apk" 2>&1 |
  Select-String -Pattern 'Verification|OK' | ForEach-Object { Write-Host "    $_" }
$alignRc = $LASTEXITCODE
$ErrorActionPreference = $prev
# These two are the build's only integrity gate; without checking their exit
# codes a truncated or mismatched scanner shipped with "done: ...".
if ($listRc -ne 0) { throw "embedded binary verification failed (list_apk.py exit $listRc)" }
if ($alignRc -ne 0) { throw "zipalign verification failed (exit $alignRc)" }
Write-Host "`ndone: $apk"
