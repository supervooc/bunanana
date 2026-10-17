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

* Under `vendor/` are the SDK (~1.1GB) + NDK (~4GB extracted) + images + AVD, all inside the workspace; deleting the directory uninstalls everything.

### 6.2 Pitfalls hit (all reproducible, all fixed in the scripts)

| Symptom | Cause | Fix |
|---|---|---|
| `qemu-system-x86_64-headless.exe` exits with code `0xC0000135` (STATUS_DLL_NOT_FOUND) | the launcher does not effectively extend the child process's DLL search path | `run-emulator.ps1` explicitly adds `emulator`, `lib64`, `lib64\gles_swiftshader`, `lib64\vulkan` to `PATH` |
| the emulator silently exits right after initializing | the system image's `advancedFeatures.ini` says `Vulkan = on`, which overrides the emulator default `off`, and the Vulkan ICD fails to initialize on this host (`VK_ERROR_INITIALIZATION_FAILED`) | change it to `Vulkan = off` inside the image, and use `-gpu off` (guest-side rendering) |
| clang: `unable to make temporary file: Permission denied` | same as above, clang's temp directory | `build/build.ps1` points `TMP` at `vendor\tmp` |

## 7. Verifying on a real device (no emulator needed)

```powershell
# Root-only deployment: when the scanner runs as root it must not be executed from
# a directory others can write to (/data/local/tmp is drwxrwx--x shell shell), or
# another adb shell user could replace the binary before it runs.
adb root
adb shell "mkdir -p /data/local/rx && chmod 700 /data/local/rx"
adb push out/rootdetect-arm64 /data/local/rx/rx
adb shell chmod 755 /data/local/rx/rx

# 1) Baseline: shell identity, expect no HIGH/CRITICAL (a userdebug device will show the env-build MEDIUM)
adb shell /data/local/rx/rx

# 2) Self-test: logic + false-positive guards
adb shell /data/local/rx/rx --selftest

# 3) True positive: run on a rooted device (one with su / Magisk / KernelSU)
adb root
adb shell /data/local/rx/rx -v
```

If you have a **clean** device, an injection script can create detectable traces (emulator / non-production only):

```powershell
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
