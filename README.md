> **English version**: this file is the complete English version — the complete Chinese version is [`README.zh-CN.md`](README.zh-CN.md).
> **中文版**：中文完整版见 [`README.zh-CN.md`](README.zh-CN.md)。

# bunanana — Android root / root-hiding detection tool

**bunanana** detects root and root hiding on Android. The APK is only a shell; the actual detection engine is the **statically linked native program `rootdetect`** (C11, no third-party dependencies, four architecture builds).

## 0. Quick start

| I want to… | How |
|---|---|
| **Just install and use it** | Download [`out/bunanana.apk`](out/bunanana.apk) and install it on the phone (unknown sources must be allowed), then open it and tap **RUN DETECTION** |
| **Run it over adb from a PC** | See §7: `adb push out/rootdetect-arm64 /data/local/rx/rx` → `adb shell chmod 755 /data/local/rx/rx` → `adb shell /data/local/rx/rx -v` |
| **Only the command-line scanner** | Build it yourself: `powershell -ExecutionPolicy Bypass -File build/build.ps1 -Abi arm64` |
| **See why it can catch hiding** | §4 detection matrix + §11 field results (real Linux kernel + API 30 emulator + KVM) |
| **Know which blind spots it admits to** | [review/detection-review.md](review/detection-review.md): a red-team view - 15-layer coverage matrix, false-positive and poisoning surfaces, **15 source-code bugs** (16 code changes applied this round) |

In one sentence: conventional checks (`su` files, Magisk directories, `ro.debuggable`) now only catch bare root. The valuable part is **cross-validation** — a hiding module has to hook the kernel's read interfaces, and it cannot cover every interface equally well, so **the interface it missed is the evidence**. The core of this tool is therefore a "cross-validation engine", not a signature list.

> The repository **does not contain** `vendor/` (that is a 20GB SDK/NDK/JDK toolchain, fetched on demand by `vendor/*.mjs`) or `out/rootdetect-*` (reproducible build products); `bunanana.apk` already bundles scanners for three ABIs: **arm64-v8a / armeabi-v7a / x86_64**.

---

## 1. Directory layout

```
android-rootdetect/
├── src/                        # the tool itself (C11, no third-party deps)
│   ├── rd.h                    # types, interfaces, corpus table declarations
│   ├── rd_util.c               # IO / exec / getprop / raw syscall probes / report model
│   ├── rd_checks.c             # environment, paths, package names, mounts, processes
│   ├── rd_kernel.c             # modules, kallsyms, SuSFS nodes, cross-validation, deep root checks
│   ├── rd_selftest.c           # --selftest: logic unit tests + false-positive guards
│   └── main.c                  # CLI
├── build/build.ps1             # NDK cross-compile (x86_64 / arm64 / arm)
├── scripts/
│   ├── sdkpkg.mjs              # fetch Google SDK packages over Node's TLS (see §6)
│   ├── setup-emulator.ps1      # build an AVD by hand, without avdmanager
│   ├── run-emulator.ps1        # start the emulator (with the fixes this host needs)
│   ├── adb.ps1                 # adb wrapper (works around the TEMP permission problem)
│   └── inject-root-fixtures.ps1# inject root traces on a clean emulator for true-positive tests
├── out/                        # products: rootdetect-x86_64 / rootdetect-arm64
└── vendor/                     # SDK, NDK, AVD, temp dirs (the whole directory can be deleted)
```

---

## 2. Build

An Android NDK is required (the script finds `vendor/sdk/android-ndk-*` automatically, or you can point `ANDROID_NDK_HOME` at one):

```powershell
powershell -ExecutionPolicy Bypass -File build/build.ps1                      # x86_64 + arm64
powershell -ExecutionPolicy Bypass -File build/build.ps1 -Abi arm64           # arm64 only (real device)
powershell -ExecutionPolicy Bypass -File build/build.ps1 -Abi x86_64 -DebugBuild
```

* `-static` is a deliberate choice: the binary carries its own libc, so it **does not depend on the linker and is not affected by `LD_PRELOAD`, GOT rewriting or post-`ptrace` injection** — a tool whose job is to find userland tampering must not itself be a hijackable dynamic program.
* The product is ~8.2 MB, API 24+ (Android 7.0 and up).

## 3. Usage

```bash
# push to the device (shell identity: the app's point of view)
adb push out/rootdetect-arm64 /data/local/rx/rx && adb shell chmod 755 /data/local/rx/rx
adb shell /data/local/rx/rx                 # human-readable report
adb shell /data/local/rx/rx --json          # machine-readable
adb shell /data/local/rx/rx -v              # include INFO-level context
adb shell /data/local/rx/rx --selftest      # self-test: logic + false-positive guards
adb root && adb shell /data/local/rx/rx     # uid 0: enables the deep kernel checks
```

| Exit code | Meaning |
|---|---|
| 0 | CLEAN |
| 1 | SUSPICIOUS |
| 2 | ROOT_DETECTED |
| 3 | HIDING_DETECTED (a hiding/spoofing mechanism was observed at work) |

> Run it **once under each identity**: the `shell` identity shows the app's point of view; `adb root`/`su` can see `/proc/kcore`, the kprobe list and the kernel log, covering the `deep-*` checks.

---

## 4. Detection matrix

### A. Conventional root traces

| id | Severity | Method |
|---|---|---|
| `artefact-present` | LOW~HIGH | a corpus of 50+ paths (`su`, `/data/adb/magisk`, `ksud`, `/debug_ramdisk`, `daemonsu`…); every path is probed through **seven interfaces at once: stat / statx / fstatat / access / open(O_PATH) / open(O_RDONLY) / opendir(getdents64)** |
| `artefact-listing` | HIGH | walks `/sbin`, `/system/xbin`, `/system/bin`, `/cache`, `/data/adb` to catch file names nobody guessed |
| `package-roots` | HIGH | compares the full `cmd package list packages` output against 30+ known root manager package names |
| `package-hidden` | **CRITICAL** | `/data/data/<pkg>` exists but the package manager **does not list it** — the deterministic signature of a KernelSU "hidden app" / DenyList rename |
| `env-build` | LOW~HIGH | `ro.debuggable=1`, `ro.secure=0`, `service.adb.root=1`, `verifiedbootstate≠green`, `veritymode≠enforcing`, test-keys |
| `env-prop-identity` | HIGH | full property-table scan: any property name containing magisk/kernelsu/susfs/zygisk/lsposed/riru/apatch/integrityfix… |
| `env-selinux-permissive` | HIGH | `/sys/fs/selinux/enforce=0` |
| `env-selinux-domain` | HIGH | `/proc/self/attr/current` lands in a `:su:` / magisk domain |
| `mount-roots` / `mount-overlay` | HIGH | a mount target name contains framework keywords; system/vendor is overlaid by overlay/tmpfs |
| `proc-cmdline` / `proc-injected-lib` | MEDIUM~HIGH | walks `/proc/*/cmdline` and `/proc/*/maps` looking for ksud/zygiskd/shamiko/frida/xposed/lsposed and friends |

### B. Kernel / module layer

| id | Severity | Method |
|---|---|---|
| `kernel-taint-oe` | HIGH | **bit 12 (OE)** of `/proc/sys/kernel/tainted`: an out-of-tree module was insmod'ed — the unavoidable trace of a hiding LKM (stock devices usually only carry bit 0 for vendor modules) |
| `kernel-module` / `kernel-sysmodule` | HIGH | names in `/proc/modules` and `/sys/module/*` match framework keywords |
| `kernel-module-hidden` | HIGH | **kallsyms tags `[module]` for a module that `/proc/modules` does not list** — the two tables were filtered separately |
| `kernel-kallsyms-symbol` | HIGH | `susfs_` / `ksu_` symbols are still left in `/proc/kallsyms` (SuSFS's `hide_syms` exists precisely for this, and it shows the filter did not take effect) |
| `kernel-syscall-table-patched` | **CRITICAL** | uid 0 only: parse the ELF program headers of `/proc/kcore` to map virtual addresses to file offsets, read `sys_call_table[openat]` and compare it with the kallsyms address of `__x64_sys_openat` — **a rewritten table entry is hard evidence** (SuSFS `susfs_fp_hook` patches exactly this) |
| `hook-kprobe` | **CRITICAL** | read `/sys/kernel/debug/kprobes/list` and tracefs's `kprobe_events`; hits `s_show` / `m_show` / `slow_avc_audit` / `*newuname` / `kallsyms*` and other SuSFS hook points |
| `deep-dmesg-hits` | **CRITICAL** | a framework name appears in the kernel log |

### C. Adversarial: the cross-validation engine (the real focus of this project)

A hiding module must intercept the "read" interfaces, and what it intercepts is a set of **discrete** hooks; an interface it misses contradicts the rest. The tool probes every suspicious path through 7 syscalls at once and compares 4 independent kernel views:

| id | Severity | Principle |
|---|---|---|
| `path-consistency-mismatch` | **CRITICAL** | the same path: `stat` says ENOENT while `open` can see it (or vice versa). SuSFS's kstat layer is a patch dispatched **by syscall number** (`newfstatat`/`fstat`/`statx`); it does not change the VFS itself — as soon as it misses one entry point, the vote splits |
| `path-consistency-control` | **CRITICAL** | the same vote runs on paths that **certainly exist** (`/system/bin/sh`, `/proc/version`…); if even these disagree, the filtering is no longer path-specific |
| `spoof-uname` | **CRITICAL** | the result of `uname(2)` disagrees with `/proc/version`, `/proc/sys/kernel/osrelease` and `/proc/sys/kernel/version`. SuSFS's uname layer is a **kretprobe** on `__arm64_sys_newuname` that only changes the syscall return value, while those `/proc` files print `init_uts_ns` directly — **a mismatch means a kernel-level spoofer is at work** |
| `spoof-cmdline` | HIGH | `/proc/cmdline` disagrees with the `ro.boot.*` properties init derived from it (SuSFS's cmdline layer only changes `/proc/cmdline`; init already copied the properties away) |
| `spoof-open-redirect` | **CRITICAL** | for the same path, `stat()` and `open()+fstat()` report **different dev/ino** — `susfs_opath` only redirects `openat/openat2`, leaving the stat family untouched, so the path points at two different inodes |
| `mount-view-inconsistency` | **CRITICAL** | the mount target sets of `/proc/mounts`(show_vfsmnt) vs `/proc/self/mountinfo`(show_mountinfo) vs `/proc/1/mountinfo` vs `/proc/self/mountstats`(show_vfsstat) must be exactly identical. Four views come from four different functions, so mount hiding exposes itself if any one of them is not covered |
| `spoof-property` | HIGH | compares `/system/build.prop` (the world-readable on-disk truth) with the live `getprop` values — `resetprop`-style tampering shows up here |
| `susfs-node-*` | **CRITICAL** | 8 `/proc/susfs_*` control nodes + `/sys/module/susfs*`, using a vote to distinguish "really absent" from "hidden"; under uid 0 the contents are read directly |

> On "why not simply grep for keywords": modules such as SuSFS have already hidden their keywords, paths, module names and symbol names. The checks above examine **the contradictions left behind by the act of hiding itself**, not its name.

---

## 5. `--selftest`

Runs on the device and verifies two things:

1. **Decision logic**: the verdict the voting table reaches under various combinations, verdict mapping, JSON escaping, buffer bounds, and the flags a verdict implies.
2. **False-positive guards**: on a "clean device" the two most false-positive-prone items must stay silent — `uname()` must equal `/proc/sys/kernel/osrelease`, and `/proc/mounts` and `/proc/self/mountinfo` must list the same mount targets.

```
$ adb shell /data/local/rx/rx --selftest
rootdetect 1.0.0 self-test   uid=2000
-- decision logic --
  PASS  keyword: magisk package name
  ...
-- live filesystem probes --
  ...
-- false-positive guards (must stay silent on a clean device) --
  PASS  uname() agrees with /proc/sys/kernel/osrelease
  PASS  mount views list the same targets

all checks passed
```

---

## 6. Local environment setup notes (conclusions and troubleshooting)

### 6.1 How the SDK / NDK / emulator were installed (no administrator rights anywhere)

* On this machine **all of PowerShell's HTTPS is blocked by the environment** (schannel `SEC_E_NO_CREDENTIALS`), while DNS / plaintext HTTP / **Node.js TLS work fine**. So every download goes through `vendor/sdkpkg.mjs` (Node, with its own OpenSSL), and it parses Google's `repository2-3.xml` / `sys-img2-3.xml` directly, with SHA-1 verification:

  ```powershell
  node vendor/sdkpkg.mjs list "emulator|platform-tools"     # query packages
  node vendor/sdkpkg.mjs getall platform-tools emulator "system-images;android-30;default;x86_64"
  node vendor/sdkpkg.mjs getall "ndk;30.0.16248370"
  ```

* **No JDK needed**: `avdmanager`/`sdkmanager` are Java programs, so the AVD is created by writing `config.ini` + `.ini` by hand instead (`scripts/setup-emulator.ps1`).
* Under `vendor/` are the SDK (~1.1GB) + NDK (~4GB extracted) + images + AVD, all inside the workspace; deleting the directory uninstalls everything.

### 6.2 Pitfalls hit (all reproducible, all fixed in the scripts)

| Symptom | Cause | Fix |
|---|---|---|
| `qemu-system-x86_64-headless.exe` exits with code `0xC0000135` (STATUS_DLL_NOT_FOUND) | the launcher does not effectively extend the child process's DLL search path | `run-emulator.ps1` explicitly adds `emulator`, `lib64`, `lib64\gles_swiftshader`, `lib64\vulkan` to `PATH` |
| the emulator silently exits right after initializing | the system image's `advancedFeatures.ini` says `Vulkan = on`, which overrides the emulator default `off`, and the Vulkan ICD fails to initialize on this host (`VK_ERROR_INITIALIZATION_FAILED`) | change it to `Vulkan = off` inside the image, and use `-gpu off` (guest-side rendering) |
| `adb`: `cannot open %TEMP%\adb.log: Permission denied` | adb 1.0.41 hardcodes `$TEMP\adb.log`, and the shared TEMP is not writable | `scripts/adb.ps1` / `run-emulator.ps1` point `TEMP`/`TMP` at `vendor\tmp` |
| clang: `unable to make temporary file: Permission denied` | same as above, clang's temp directory | `build/build.ps1` points `TMP` at `vendor\tmp` |

### 6.3 Conclusion: on this machine **the emulator currently cannot run**, blocked on hardware acceleration (needs an administrator)

After the four pitfalls above were fixed, the emulator still could not start a VM. The full chain of evidence:

* `emulator -accel-check` reports `WHPX(10.0.22631) is installed and usable`, but when the VM is actually started the process exits immediately:
  * running the qemu backend directly (full `-verbose` log, 707 lines) the last line is `Windows Hypervisor Platform accelerator is operational`, with no output after it;
  * the process exit code is `0xFFFF7001` (in another combination it is `0x40000015` = `STATUS_FATAL_APP_EXIT`);
  * forcing TCG (`ANDROID_I_WANT_MY_TCG=yes -accel off`) exits at the same point;
  * in the only combination that keeps the process alive (`-gpu off`), qemu shows **0 seconds of CPU time and a working set of only 139MB** — guest RAM was never touched, which means the vCPU never started executing.
* Host-side evidence: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\HypervisorLaunchType` is **not set** (i.e. the hypervisor is not configured to launch), `Get-WindowsOptionalFeature` for `HypervisorPlatform` returns *requires elevation*, and `bcdedit` also fails without administrator rights.
* The host CPU is a real `i5-1155G7` (no nested virtualization), 17GB of memory, plenty of disk — ruling out resource problems.
* **The arm64 fallback was pushed to the end as well**: `emulator.exe` refuses outright (`FATAL | Avd's CPU Architecture 'arm64' is not supported by the QEMU2 emulator on x86_64 host`), but that check lives only in the launcher — calling the backend directly, `qemu\windows-x86_64\qemu-system-aarch64-headless.exe -avd rootdetect-arm`, bypasses it, and it really does get as far as the arm64 boot arguments (`androidboot.boot_devices=a003600.virtio_mmio`), after which it **still aborts at the moment the VM starts** (`0x40000015` = `STATUS_FATAL_APP_EXIT`).
* Six combinations have now aborted at the same point: x86_64/arm64 backend × WHPX/forced TCG (`ANDROID_I_WANT_MY_TCG=yes -accel off`) × gfxstream / `-gpu off` / Vulkan disabled (both images' `advancedFeatures.ini` were changed to `Vulkan = off`) × 512/1024/2048MB of memory. **It has nothing to do with architecture, accelerator, Vulkan or memory**; it points at a host-level hypervisor being unavailable. The emulator deletes crash dumps when reporting unauthorized, so `vendor/tmp/AndroidEmulator/emu-crash-37.3.4.db` is empty and no finer stack trace can be obtained.
* In the only combination that keeps the process alive (x86_64 + `-gpu off`), qemu shows **0 seconds of CPU time and a working set of only 139MB**: guest RAM was never touched and the vCPU never ran once.

**Conclusion (superseded by §11.4)**: the Windows path really is a dead end — it depends on Windows' hardware accelerator, which cannot be enabled under the current privileges; Google's QEMU fork does not execute guest instructions even with forced TCG (as the `-d in_asm` log proves). But **WSL2 has a working `/dev/kvm`**, and putting the Linux emulator + the same AOSP image in WSL boots normally under KVM (33 seconds); all field results were produced there, see §11.4.

### 6.4 With administrator rights, one line fixes it

Pick one route, then re-run `powershell -ExecutionPolicy Bypass -File scripts/run-emulator.ps1`:

```powershell
# Route A (recommended): enable Windows Hypervisor Platform + launch the hypervisor, requires a reboot
dism /online /enable-feature /featurename:HypervisorPlatform /all /norestart
bcdedit /set hypervisorlaunchtype auto
shutdown /r /t 0

# Route B: keep Hyper-V off and install Google's AEHD driver instead (also needs an administrator)
#   download and run silent_install.bat from extras;google;Android_Emulator_Hypervisor_Driver
```

After the reboot, self-check:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-emulator.ps1                 # x86_64 AVD (instant if it already exists)
powershell -ExecutionPolicy Bypass -File scripts/run-emulator.ps1                   # start in window mode
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 wait-for-device
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell getprop sys.boot_completed   # expect 1
```

> Also: `-Arch arm64-v8a` (arm64 image + AVD `rootdetect-arm`) is already downloaded and created on this machine, but **it cannot start on an x86_64 host** (QEMU2 requires guest and host to share an architecture, see §6.3). It is only usable on an ARM host; it is kept for a future machine change or for product compatibility checks.

---

## 7. Verifying on a real device (no emulator needed)

```powershell
# Root-only deployment: when the scanner runs as root it must not be executed from
# a directory others can write to (/data/local/tmp is drwxrwx--x shell shell), or
# another adb shell user could replace the binary before it runs.
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 root
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell "mkdir -p /data/local/rx && chmod 700 /data/local/rx"
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 push out/rootdetect-arm64 /data/local/rx/rx
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell chmod 755 /data/local/rx/rx

# 1) Baseline: shell identity, expect no HIGH/CRITICAL (a userdebug device will show the env-build MEDIUM)
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell /data/local/rx/rx

# 2) Self-test: logic + false-positive guards
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell /data/local/rx/rx --selftest

# 3) True positive: run on a rooted device (one with su / Magisk / KernelSU)
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 root
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell /data/local/rx/rx -v
```

If you have a **clean** device, an injection script can create detectable traces (emulator / non-production only):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/inject-root-fixtures.ps1          # create su / magisk dirs / a hidden package
powershell -ExecutionPolicy Bypass -File scripts/inject-root-fixtures.ps1 -Clean    # clean up
```

---

## 8. Known limitations (stated honestly)

* **Without root, SuSFS's path hiding itself cannot be observed directly**: its `/proc/susfs_*` nodes return `-ENOENT` to anyone but uid 0, which is indistinguishable from "really absent" at the errno level. The non-root verdict therefore relies on the contradiction checks in §4C (this is a design necessity, not implementation laziness). Under uid 0 the node contents can be read directly.
* The §4B items that depend on `/proc/kallsyms`, `/proc/kcore` and debugfs are blocked by SELinux on some devices (the tool prints an INFO for `kernel-kallsyms` / `kernel-kcore` saying "could not check", and never treats "could not check" as "clean" or "rooted").
* The mount-view comparison produces differences when **mount namespaces differ**: running as `shell` shares init's namespace and should agree exactly; if you enter a separate namespace with `su --mount-master` or the like, that verdict needs manual review.
* Not implemented: protocol-level evidence (Play Integrity / key attestation), hardware-breakpoint / performance-counter level hook detection.
* The cross-ABI diff (§10) is implemented but **has not yet been field-tested on a device with 32/64-bit mixed support**: it only activates when both ABI products are pushed to `/data/local/tmp`, otherwise it degrades to INFO.
* **End-to-end testing has been done on a real kernel and on real Android**: the WSL2 Linux kernel (self-test, a clean baseline, and positive results from faking `/proc/version` and `/proc/1/mountinfo`) and a KVM-accelerated emulator inside WSL (API 30 x86_64: self-test, injected fixtures, and the APK installed with the button pressed to produce a report) - see §11. **It has still not been verified on a physical device** (an unlocked or rooted phone), and the cross-ABI differential has only run on the emulator.

---

## 9. Code map (where to start when adding a check)

| Want to add | Where to change |
|---|---|
| a new suspicious path / package name / keyword | `RD_ROOT_PATHS`, `RD_ROOT_PACKAGES`, `RD_KEYWORDS` at the top of `rd_checks.c` |
| a new kind of cross-validation | add a function in `rd_kernel.c` and call it from `rd_check_consistency()` |
| a new report item id and its contribution to the verdict | the `rd_add*()` call site + the `id_flags()` table in `rd_util.c` (the verdict only consults that table, which keeps it reproducible) |
| a new deep kernel check | `rd_check_deep()` in `rd_kernel.c` (runs only under uid 0) |

---

## 10. Cross-ABI diff and one-command on-device verification

### 10.1 Principle

A hiding module installs its syscall table patches **per table**: inside SuSFS's `susfs_fp_hook` the native table and the compat table each hold their own wrapper and orig slots, and the entry points of the stat family and getdents are numbered per ABI as well (arm64's `newfstatat`/`fstat`/`statx` vs AArch32's `fstatat64`/`fstat64`). Making every ABI behave exactly the same is where hiding schemes most easily spring a leak.

Hence: **a 64-bit process runs the 32-bit sibling product with `--probe-dump` and compares the seven interfaces item by item for the same batch of paths.**

```bash
adb push out/rootdetect-arm64 /data/local/rx/rx                # main program
adb shell "mkdir -p /data/local/rx && chmod 700 /data/local/rx"   # root-only: helpers are never exec'd from /data/local/tmp as root
adb push out/rootdetect-arm   /data/local/rx/rootdetect-arm       # 32-bit helper
adb shell chmod 755 /data/local/rx/rx /data/local/rx/rootdetect-arm
adb shell /data/local/rx/rx        # auto-discovers the helper and enables the diff
```

* helper found → `abi-consistency` (agree, INFO) or `abi-consistency-mismatch` (disagree, **CRITICAL**, listing the seven probe results of both ABIs per path).
* not found → `abi-diff-skipped` (INFO, with the reason), and it is **not** treated as "clean" or "rooted".
* `ROOTDETECT_ABI_HELPER=/path/to/helper` sets the path explicitly, or `--fast` disables all cross-checks.

### 10.2 Additional lightweight checks (`src/rd_extra.c`)

| id | Severity | What it checks |
|---|---|---|
| `unix-socket-roots` | HIGH | control-channel names in `/proc/net/unix` (Frida linjector / Zygisk / Magisk / LSPosed). They are sockets, not files, so file-system hiding does not make them disappear |
| `self-traced` | HIGH | `TracerPid != 0` in `/proc/self/status`: this process is being ptraced |
| `map-backing-hidden` | **CRITICAL** | a file mmap'ed into this process's own address space cannot be `stat`ed/`open`ed — path hiding did not cover the mmap path |
| `map-deleted-exec` | MEDIUM | the backing file of an executable mapping has been unlinked |
| `env-preload` / `env-ldpath` | MEDIUM / LOW | `LD_PRELOAD` / `LD_LIBRARY_PATH`: the statically linked main binary does not fear preloading, but it shows the caller's environment was injected |

### 10.3 One-command on-device verification

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify-on-device.ps1            # or -Serial <serial>
```

The script will: pick the product per device ABI → push the main program and a helper for the other ABI together → run `--selftest` → run once as `shell` and save `out/report-shell.json` → `adb root` and run again, saving `out/report-root.json` → print the two verdicts side by side and list the findings **visible only to uid 0**. This is the shortest path from "is there root / is there hiding at all" to reviewable evidence.

---

## 11. Field results and false-positive validation (WSL real kernel + APK)

### 11.1 Execution on a real Linux kernel (WSL2, kernel 5.10.16.3)

The Android emulator cannot start on this machine (see §6), but WSL2 provides a **real Linux kernel**, and since the tool is statically linked it can simply be dropped into WSL: path corpora that do not match Android degrade to INFO as they should, while the detection engine itself runs end to end.

```bash
wsl -e      bash android-rootdetect/scripts/wsl-verify.sh baseline    # uid 1000
wsl -u root -e bash android-rootdetect/scripts/wsl-verify.sh fixtures # inject + spoof
```

| Scenario | Measured result |
|---|---|
| `--selftest` | **75 checks, 0 failure(s), 6 skipped** (current binary; the extra skips are the kernel module-list assertions, this WSL kernel exposes no loadable module tags) |
| clean-system baseline (false-positive rate) | **verdict: CLEAN** — 0 critical / 0 high / 0 medium / 0 low (19 INFO items) |
| injected root traces (`/system/xbin/su`, `/system/bin/ksud`, `/data/adb/magisk`) | `artefact-present` + `artefact-listing` = **HIGH**, verdict: ROOT_DETECTED (exit 2) |
| `tmpfs` over `/system` | `mount-overlay` = **HIGH** |
| bind-mounting a fake `/proc/version` (replicating SuSFS's uname layer: the syscall is changed while `/proc` keeps the truth) | `spoof-uname` = **CRITICAL**, verdict: HIDING_DETECTED |
| bind-mounting a fake `/proc/1/mountinfo` (changing only one of the four mount views) | `mount-view-inconsistency` = **CRITICAL** (`/proc/mounts` 33 entries vs `/proc/1/mountinfo` 1 entry), verdict: HIDING_DETECTED |

The last two are the key ones: they prove that **the positive path of the adversarial detection really can be triggered on a real kernel**, not merely that it "should work by design". Full record in [out/wsl-fixtures-report.txt](out/wsl-fixtures-report.txt).

### 11.2 Bugs caught by real execution (all fixed)

| # | Problem | Consequence | Fix |
|---|---|---|---|
| 1 | `/proc/self/mountstats` uses a sentence format (`device X mounted on Y with fstype Z`), but I took the mount point from field 3, which yielded the literal `on` | a clean system suddenly gained 31 mount points → **false-positive CRITICAL / HIDING_DETECTED** | field index changed to 4, plus a `--selftest` regression guard that "all four mount views must agree" |
| 2 | `--selftest` hardcoded Android-only paths (`/system/bin/sh`) and `getprop` | the self-test necessarily FAILs on any Linux | switched to `/proc/version`; Android-only items became SKIP |
| 3 | with no `CONFIG_KALLSYMS_ALL` in the kernel, `sys_call_table` cannot be resolved and the code was **completely silent** | users would assume "the strongest check already ran" | print `kernel-syscall-table-skipped` with the reason |

Item 1 above is especially telling: it was found by **execution validation** (not code review), and it happens to be the one mistake this class of tool must never make — declaring a clean device hidden.

### 11.3 The APK (`out/bunanana.apk`)

App name **bunanana**, icon `apk/icon-source.jpg` (a full set of multi-density resources generated by `apk/make-icons.py`); the detection engine is still called `rootdetect`, shown as a subtitle in the main screen, and the CLI product names are unchanged (`rootdetect-{arm64,arm,x86_64}`).

```powershell
python3 apk/make-icons.py        # only needed after changing the image (WSL / any environment with Pillow)
powershell -ExecutionPolicy Bypass -File build/build-apk.ps1   # produces out/bunanana.apk
```

No Gradle / Android Studio needed: `aapt2 compile res` → `aapt2 link` (manifest + compiled resources) → `javac` → `d8` → assemble the zip (using python3 in WSL, because this machine has no zip tool) → `zipalign` → `apksigner` (the debug keystore is generated on the spot by keytool and **kept persistently** in `build/debug.keystore`). The required JDK is a portable Temurin 17 (`vendor/jdk`).

APK contents (verified item by item):

| Entry | Description |
|---|---|
| `classes.dex` | `com.rootdetect.app.MainActivity` (the dex string table was confirmed to contain the class name) |
| `res/mipmap-*/ic_launcher.png` | 48/72/96/144/192 px legacy icons |
| `res/mipmap-*/ic_launcher_foreground.png` | 108/162/216/324/432 px adaptive-icon foreground (circular mask, background colour `#D3C9C6` sampled from the source image's edge) |
| `res/mipmap-anydpi-v26/ic_launcher.xml` | adaptive icon declaration |
| `lib/arm64-v8a/librootdetect.so` | this is `out/rootdetect-arm64`, and its sha256 **matches item by item** |
| `lib/armeabi-v7a/librootdetect.so` | `out/rootdetect-arm`, same as above |
| `lib/x86_64/librootdetect.so` | `out/rootdetect-x86_64`, same as above |
| Signature | signed with both v1+v2, `zipalign -c` passes; `aapt2 dump badging` shows `application-label:'bunanana'`, `application-icon-*: res/mipmap-anydpi-v26/ic_launcher.xml` |

Product (verified):

- Product: `out/bunanana.apk`, **7,218,732 bytes**, `sha256=c78d49584ddca3719b82dad0be7fc56fd4f806dfe08c21eac39d2089f2cec59b`
- Direct download: https://github.com/supervooc/bunanana/raw/main/out/bunanana.apk

Design points:

* **No resource files at all**; the UI is built entirely in code, so `aapt2 + javac + d8` is all a build needs.
* The static executable ships as `lib/<abi>/librootdetect.so` and is extracted into the app's native library directory on install (that directory is executable); the Activity runs it with `ProcessBuilder` and displays its output.
* `targetSdkVersion=28` is deliberate: Android 10+ forbids apps with targetSdk≥29 from `exec`ing out of their own data directory, and this tool needs to run native code on the device without root; should an OEM also block the native library directory, it degrades to "copy into `filesDir` and execute", and if that fails too it shows the adb command line.
* **Result banner and log export**: the top of the report is now a result banner that states outright whether the device is rooted and whether anything is hidden, plus the risk counts, and lists *which concrete paths* each MEDIUM-or-above problem appears at (absolute paths parsed out of the evidence lines, e.g. `package-hidden -> /data/data/com.topjohnwu.magisk`). An **Export log** button writes the whole log (device header + banner + full report) to `Android/data/com.rootdetect.app/files/bunanana-report-<timestamp>.txt` and then opens the system share sheet (plain-text share, no storage permission; falls back to the app's private files directory when external storage is unavailable).
* **Installation was field-tested on an emulator**: `adb install` succeeded → the Activity displayed normally → pressing "RUN DETECTION" successfully executed the bundled static scanner and rendered the full report in the UI (screenshots: [apk-screenshot.png](out/apk-screenshot.png), [apk-screenshot-after.png](out/apk-screenshot-after.png)). No `avc: denied` blocked execution in the app domain (`untrusted_app_27`); the only things SELinux blocked were `stat` on `/sys/fs/selinux/enforce`, `/proc/sys/kernel/tainted` and `/system/xbin/su` (type `su_exec`), and the tool honestly degrades those to INFO and does **not** misjudge "some interfaces blocked" as hiding — probes rejected by SELinux do not take part in the vote.
* Two build-pipeline pitfalls (both of which turn "looks fixed" into a lie): ① `build/apk-work` is wiped on every build, which used to delete the debug keystore along with it, so the regenerated key made the new package **unable to overwrite-install**, and `adb install` failed silently while the old version kept running (the keystore now lives persistently in `build/debug.keystore`, and the install script has an "uninstall first if the signature differs" fallback); ② the test script matched the button text in lowercase, while Android's `Button` uppercases its label.

---

## 11.4 Real Android emulator field test (WSL + KVM)

The conclusion of §6 **has been superseded by this section**: the Windows-side SDK emulator still cannot start, but **WSL2 has `/dev/kvm`** (`nested=Y`, vmx exposed), so the **Linux emulator + the same AOSP x86_64 image** were installed inside WSL and actually booted under KVM:

```
INFO | Boot completed in 32689 ms                      <- 33-second boot (KVM accelerated)
$ adb devices -l
emulator-5554  device product:sdk_phone_x86_64 model:Android_SDK_built_for_x86_64 device:generic_x86_64
$ adb shell getprop sys.boot_completed ; getprop ro.build.version.release ; getprop ro.build.type
1  ;  11  ;  userdebug
```

Reproduction commands (already scripted):

```bash
wsl -u root -e bash scripts/wsl-emulator.sh setup   # extract + copy the image (Linux emulator)
wsl -u root -e bash scripts/wsl-emulator.sh avd     # create the AVD
wsl -u root -e bash scripts/wsl-emulator.sh boot    # -accel on -no-window -gpu off
wsl -u root -e bash scripts/wsl-android-verify.sh   # push + full verification
```

| Scenario | Measured result |
|---|---|
| `--selftest` (real Android, shell identity) | **77 checks, 0 failure(s), 2 skipped** (as the `shell` user - `/proc/sys/kernel/osrelease` and `version` are unreadable to that domain; as uid 0 the same build reports 0 skips and the same 77 checks) |
| clean emulator baseline (`shell` view) | verdict **ROOT_DETECTED**, exactly 3 HIGH: `ro.debuggable=1`, `service.adb.root=1`, SELinux domain `su`; plus 3 MEDIUM (userdebug build, the `/system/xbin/su` that ships with userdebug, OE taint). **All true positives** — a userdebug image + `adb root` is root-equivalent in itself, and there is no spoofed CRITICAL |
| injecting `/data/data/com.topjohnwu.magisk` (not in the package manager list) | `package-hidden` = **CRITICAL** (the deterministic signature of KernelSU's "hidden app") |
| injecting `/data/adb/magisk`, `/data/local/tmp/su` | `artefact-present` + `artefact-listing` = **HIGH**, verdict **HIDING_DETECTED** |

## 11.5 False positives caught by real execution and fixed (10 in total)

| Environment | Problem | Fix |
|---|---|---|
| WSL | `/proc/self/mountstats` field index error → 31 phantom mount points, **false-positive CRITICAL** | index changed to 4, plus a self-test regression guard |
| WSL | the self-test hardcoded Android paths and `getprop` → necessarily FAILs on Linux | switched to `/proc/version`; Android-only items became SKIP |
| WSL | silent when `sys_call_table` cannot be resolved | print `kernel-syscall-table-skipped` with the reason |
| Android | `stat` can see a path but `open` is denied by SELinux, which was taken as an open-redirect → **false-positive CRITICAL** | only a dev/ino mismatch counts as a redirect |
| Android | the `ro.secure` / `ro.debuggable` comparison was inverted → **false-positive HIGH** | the table now distinguishes `CMP_EQUAL` / `CMP_NOT_EQUAL` explicitly |
| Android | `/debug_ramdisk` is a standard directory on Android 11+ | removed from the corpus |
| Android | `/system/xbin/su` is a build artefact on userdebug | userdebug + `/system/*` downgraded to MEDIUM |
| Android | `kernel-taint-oe` was rated too high (measured `tainted=4096`, caused by a vendor module) | downgraded to MEDIUM with an explanation |
| Android | `kernel-module-hidden` treated the kernel pseudo-module `bpf` as a hidden module → **false-positive HIGH** | the allow-list skips `bpf` |
| Android | `spoof-cmdline` reported HIGH because 3/10 properties never came from cmdline in the first place | switched to a majority rule (report only above 50%) |

This table is the best proof of "why you must actually run it": **4 of these would have declared a clean device HIDING_DETECTED**, and all of them were found by execution validation (not code review).

---

## 11.6 Parallel hardening (Agent Teams) and final acceptance

This round split three non-overlapping workstreams across three teammates, each committing its evidence to a file:

| Role | Task | Result |
|---|---|---|
| **t-abi** | field verification of the cross-ABI diff | added the `i686-linux-android` target → `out/rootdetect-x86` (ELF32 / EM_386 / static). The 32-bit helper **really does execute** on an API 30 x86_64 emulator (the device has `abilist32=x86`, `zygote64_32` and `/system/bin/linker`; `--selftest` → 76 checks / 0 failures / 2 skipped). Official result: `[INFO] abi-consistency — both ABIs agree on every probed path`, **compared 92 paths between x86_64 and /data/local/tmp/rootdetect-x86 (x86)**. Also a negative control (swapping in a same-ABI helper → `abi-diff-skipped`), a same-snapshot comparison (a build in another directory was **byte-for-byte identical**), and a `-Abi x86_64,arm64,arm` regression (0 warnings, existing products' mtimes unchanged). Evidence: [abi-diff-report.txt](out/abi-diff-report.txt), [wsl-abi-diff.sh](scripts/wsl-abi-diff.sh) |
| **t-selftest** | hardening the `--selftest` parser boundaries | added 39 cases (voting combinations, JSON escaping boundaries, trim/appendf sentinel bytes, mount parsing including `\040` escapes, **mount checks end to end**, kernel lists end to end), **75 checks / 0 failures / 6 skipped** on WSL. Mutation testing proves the new cases catch the old field-index bug (changing `field` to `{1,3,3,3}` → the new cases FAIL while the old guard still PASSes) — closing a real blind spot. Output: [selftest-final.txt](build/t2-out/selftest-final.txt) |
| **t-review** | red-team review | [detection-review.md](review/detection-review.md) (460 lines): a 15-layer coverage matrix (4 layers not covered at all, 5 partially), stock/custom-ROM false-positive tables + the **unprivileged poisoning surface**, 3 implementation drafts, **15 source-code bugs** (each with `file:line` + a minimal reproduction), and a separate list of what README §11.5 already fixed so they are not double-counted |

### Red-team case #1: reproduced on a real device and fixed

```
Before: adb shell 'ln -sf /nonexistent /data/local/tmp/su; /data/local/rx/rx -q'
        [CRITICAL] path-consistency-mismatch ...  →  HIDING_DETECTED (exit 3)
After:  ROOT_DETECTED (exit 2) + [MEDIUM] artefact-dangling-symlink
```

Root cause: the voting engine threw `fstatat(AT_SYMLINK_NOFOLLOW)` / `statx(NOFOLLOW)` and the following-semantics `stat/access/open` into **the same vote bucket**, so **any dangling symlink looked like "the kstat layer only patched some interfaces"**; and `/data/local/tmp/su` is in the corpus while that directory is writable by `shell` — effectively handing unprivileged processes a poisoning switch.

### 16 code changes applied this round (the table below groups them into 12 issues)

Every replacement is forced to match **exactly once** (to avoid silent mis-edits), and after a zero-warning rebuild of all four ABIs it was re-verified on a real device:

| Fix | How it was verified / consequence |
|---|---|
| B1 dangling symlinks no longer rate CRITICAL (including the control path `/sdcard`) | real-device reproduction command, after the fix exit 2 + MEDIUM (see above) |
| B2 32-bit builds no longer index the native `sys_call_table` incorrectly | a new `sizeof(void*)!=8` branch reports INFO on its own; otherwise a 32-bit run as root would fake a `kernel-syscall-table-patched` CRITICAL |
| B3 map paths containing spaces are no longer truncated | previously any mapped file with a space in its path would blow up `map-backing-hidden` CRITICAL |
| B4 `spoof-cmdline` tolerates `/proc/bootconfig` | on Android 12+/GKI androidboot.* lives only in bootconfig → on a real device `spoof-cmdline` is back to INFO "agree" |
| B5 the `gadget` keyword in `inj[]` was matching the USB gadget HAL by mistake | changed to `frida-gadget` / `gum-js-loop` |
| B6 `mount-overlay` requires the mount point to really be the system partition | overlayfs's device name is always `overlay`, so arbitrary overlay mounts no longer match |
| B8 the process scan now really reads all of argv | the old loop stopped at the first NUL (it only ever saw argv[0]), so `ksud`/`zygiskd` in argv[1..] were invisible |
| B10 out-of-bounds write on OOM in `find_push` | `cap` is only advanced after a successful `realloc` |
| B11 `deep-dmesg` no longer treats `busybox` as a framework | consistent with the other keyword scans |
| B12 the ABI diff no longer counts `blocked(-1)` as a difference | unified with the voting engine's rule (otherwise a SELinux denial masquerades as an ABI divergence) |
| B15 the userdebug downgrade now also covers `/sbin/`, `/vendor/bin/su` | previously it matched only `/system/` |
| UB reported by t-selftest: `rd_row_inconsistent(.., NULL, 0)` | early return; the original pointer arithmetic was `cons_out + SIZE_MAX` |

### Final acceptance (one command)

```bash
wsl -u root -e bash android-rootdetect/scripts/verify-all.sh
```

Most recent run: **PASS=18 FAIL=0 SKIP=0** (Linux real-kernel self-test + clean baseline; emulator self-test + shell/root dual view; injected fixtures hitting `package-hidden` CRITICAL; cross-ABI diff; APK structure and three-ABI binary hashes). Raw output is in `/tmp/verify-all/`.

> This machine has no PowerShell 7 (`pwsh`), so all `.ps1` files must be invoked as `powershell -ExecutionPolicy Bypass -File` — the examples in this README were corrected accordingly (a documentation problem found by t-abi).
