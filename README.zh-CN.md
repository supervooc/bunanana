> **English version**: [`README.md`](README.md) — this file is the complete Chinese version.
> **中文版**：本文件是完整中文版；英文完整版见 [`README.md`](README.md)。

# bunanana — Android root / root 隐藏检测工具（中文版）

**bunanana** 是一个 Android 上的 root 与「root 隐藏」检测工具。APK 只是外壳，真正的检测引擎是**静态链接的原生程序 `rootdetect`**（C11，无第三方依赖，四个架构产物）。

## 0. 快速开始

| 我想…… | 怎么做 |
|---|---|
| **直接装上用** | 下载 [`out/bunanana.apk`](out/bunanana.apk) 安装到手机（需允许未知来源），打开后点 **RUN DETECTION** |
| **在电脑上用 adb 跑** | 见 §7：`adb push out/rootdetect-arm64 /data/local/rx/rx` → `adb shell chmod 755 /data/local/rx/rx` → `adb shell /data/local/rx/rx -v` |
| **只要命令行扫描器** | 自行构建：`powershell -ExecutionPolicy Bypass -File build/build.ps1 -Abi arm64` |

一句话：常规检测项（`su` 文件、Magisk 目录、`ro.debuggable`）现在只能抓到裸奔的 root。真正有价值的是**交叉验证**——隐藏模块必须 hook 内核的读取接口，而它不可能把每个接口都覆盖得一样完美，**没覆盖到的那个接口就是证据**。本工具的核心因此是一个「交叉验证引擎」，而不是一份特征清单。

> 仓库里**不含** `vendor/`（那是 20GB 的 SDK/NDK/JDK 工具链，由 `vendor/*.mjs` 按需拉取）与 `out/rootdetect-*`（可复现的构建产物）；`bunanana.apk` 内已内置 **arm64-v8a / armeabi-v7a / x86_64** 三个 ABI 的扫描器。

---

## 1. 目录结构

```
android-rootdetect/
├── src/                        # 工具本体（C11，无第三方依赖）
│   ├── rd.h                    # 类型、接口、语料表声明
│   ├── rd_util.c               # IO / exec / getprop / 原始 syscall 探针 / 报告模型
│   ├── rd_checks.c             # 环境、路径、包名、挂载、进程
│   ├── rd_kernel.c             # 模块、kallsyms、SuSFS 节点、交叉验证、root 深度检查
│   ├── rd_selftest.c           # --selftest：逻辑单测 + 误报卫士
│   └── main.c                  # CLI
├── build/build.ps1             # NDK 交叉编译（x86_64 / arm64 / arm）
│   ├── sdkpkg.mjs              # 用 Node 的 TLS 拉 Google SDK 包（见 §6）
│   ├── setup-emulator.ps1      # 不依赖 avdmanager 手工建 AVD
│   ├── run-emulator.ps1        # 启动模拟器（含本机必需的修复）
│   ├── adb.ps1                 # adb 包装（修正 TEMP 权限问题）
│   └── inject-root-fixtures.ps1# 在干净模拟器上注入 root 痕迹做真阳性测试
├── out/                        # 产物：rootdetect-x86_64 / rootdetect-arm64
└── vendor/                     # SDK、NDK、AVD、临时目录（可整目录删除）
```

---

## 2. 构建

需要 Android NDK（脚本会自动找 `vendor/sdk/android-ndk-*`，也可用 `ANDROID_NDK_HOME` 指定）：

```powershell
powershell -ExecutionPolicy Bypass -File build/build.ps1                      # x86_64 + arm64
powershell -ExecutionPolicy Bypass -File build/build.ps1 -Abi arm64           # 只出 arm64（真机）
powershell -ExecutionPolicy Bypass -File build/build.ps1 -Abi x86_64 -DebugBuild
```

* `-static` 是刻意选择：二进制自带 libc，**不依赖 linker、不受 `LD_PRELOAD`、GOT 改写、`ptrace` 后注入的影响**——一个负责发现「用户态被动过手脚」的工具，自己不能是可被劫持的动态程序。
* 产物 ~8.2 MB，API 24+（Android 7.0 起）。

## 3. 使用

```bash
# 推送到设备（shell 身份：应用视角）
adb push out/rootdetect-arm64 /data/local/rx/rx && adb shell chmod 755 /data/local/rx/rx
adb shell /data/local/rx/rx                 # 人类可读报告
adb shell /data/local/rx/rx --json          # 机器可读
adb shell /data/local/rx/rx -v              # 附带 INFO 级上下文
adb shell /data/local/rx/rx --selftest      # 自检：逻辑 + 误报卫士
adb root && adb shell /data/local/rx/rx     # uid 0：开启内核深度检查
```

| 退出码 | 含义 |
|---|---|
| 0 | CLEAN |
| 1 | SUSPICIOUS |
| 2 | ROOT_DETECTED |
| 3 | HIDING_DETECTED（观测到隐藏/伪造机制在工作） |

> 建议**两种身份各跑一次**：`shell` 身份看到的是应用视角；`adb root`/`su` 身份能看到 `/proc/kcore`、kprobe 列表、内核日志，覆盖 `deep-*` 系列检查。

---

## 4. 检测矩阵

### A. 常规 root 痕迹

| id | 级别 | 手段 |
|---|---|---|
| `artefact-present` | LOW~HIGH | 50+ 条路径语料（`su`、`/data/adb/magisk`、`ksud`、`/debug_ramdisk`、`daemonsu`…），每条路径同时用 **stat / statx / fstatat / access / open(O_PATH) / open(O_RDONLY) / opendir(getdents64)** 七种接口探一次 |
| `artefact-listing` | HIGH | 遍历 `/sbin`、`/system/xbin`、`/system/bin`、`/cache`、`/data/adb`，抓没猜到的文件名 |
| `package-roots` | HIGH | `cmd package list packages` 全量比对 30+ 个已知 root 管理器包名 |
| `package-hidden` | **CRITICAL** | `/data/data/<pkg>` 存在但包管理器**不列出**——KernelSU「隐藏应用」/ DenyList 改名的确定性特征 |
| `env-build` | LOW~HIGH | `ro.debuggable=1`、`ro.secure=0`、`service.adb.root=1`、`verifiedbootstate≠green`、`veritymode≠enforcing`、test-keys |
| `env-prop-identity` | HIGH | 全属性表扫描：任何属性名含 magisk/kernelsu/susfs/zygisk/lsposed/riru/apatch/integrityfix… |
| `env-selinux-permissive` | HIGH | `/sys/fs/selinux/enforce=0` |
| `env-selinux-domain` | HIGH | `/proc/self/attr/current` 落在 `:su:` / magisk 域 |
| `mount-roots` / `mount-overlay` | HIGH | 挂载目标名含框架关键字；system/vendor 被 overlay/tmpfs 覆盖 |
| `proc-cmdline` / `proc-injected-lib` | MEDIUM~HIGH | 遍历 `/proc/*/cmdline`、`/proc/*/maps`，找 ksud/zygiskd/shamiko/frida/xposed/lsposed 等 |

### B. 内核 / 模块层

| id | 级别 | 手段 |
|---|---|---|
| `kernel-taint-oe` | HIGH | `/proc/sys/kernel/tainted` 的 **bit 12 (OE)**：有 out-of-tree 模块被 insmod——隐藏 LKM 的必然痕迹（stock 设备通常只有 bit 0 的厂商专有模块） |
| `kernel-module` / `kernel-sysmodule` | HIGH | `/proc/modules` 与 `/sys/module/*` 名称匹配框架关键字 |
| `kernel-module-hidden` | HIGH | **kallsyms 里出现 `[模块名]` 标注，但 `/proc/modules` 里没有该模块**——两张表被分别过滤了 |
| `kernel-kallsyms-symbol` | HIGH | `/proc/kallsyms` 里仍然残留 `susfs_` / `ksu_` 符号（SuSFS 的 `hide_syms` 就是干这个的，它在说明过滤器没生效） |
| `kernel-syscall-table-patched` | **CRITICAL** | 只要 uid 0：解析 `/proc/kcore` 的 ELF program header 做虚拟地址→文件偏移映射，读出 `sys_call_table[openat]` 并与 kallsyms 里 `__x64_sys_openat` 的地址比对——**表项被改写就是铁证**（SuSFS `susfs_fp_hook` 正是改这里） |
| `hook-kprobe` | **CRITICAL** | 读 `/sys/kernel/debug/kprobes/list`、tracefs 的 `kprobe_events`，命中 `s_show` / `m_show` / `slow_avc_audit` / `*newuname` / `kallsyms*` 等 SuSFS 的挂载点 |
| `deep-dmesg-hits` | **CRITICAL** | 内核日志里出现框架名 |

### C. 对抗：交叉验证引擎（本项目真正的重点）

隐藏模块必须拦截「读」的接口，而它拦截的是一组**离散**的钩子，漏掉的接口会自相矛盾。工具对每个可疑路径同时用 7 个 syscall 探，并比对 4 个独立的内核视图：

| id | 级别 | 原理 |
|---|---|---|
| `path-consistency-mismatch` | **CRITICAL** | 同一路径：`stat` 说 ENOENT 而 `open` 看得见（或反之）。SuSFS 的 kstat 层是按 **syscall 号**分发的补丁（`newfstatat`/`fstat`/`statx`），它不改变 VFS 本身——只要它漏了一个入口，投票结果就分裂 |
| `path-consistency-control` | **CRITICAL** | 同样的投票跑在**肯定存在**的普通路径上（`/system/bin/sh`、`/proc/version`…）；如果连这些都不一致，说明过滤已经不分路径了 |
| `spoof-uname` | **CRITICAL** | `uname(2)` 的结果与 `/proc/version`、`/proc/sys/kernel/osrelease`、`/proc/sys/kernel/version` 对不上。SuSFS 的 uname 层是挂在 `__arm64_sys_newuname` 上的 **kretprobe**，只改 syscall 返回值；而 `/proc` 那几个文件直接打印 `init_uts_ns`——**对不上就是内核级伪造器在工作** |
| `spoof-cmdline` | HIGH | `/proc/cmdline` 与 init 从它派生出来的 `ro.boot.*` 属性对不上（SuSFS cmdline 层只改 `/proc/cmdline`，属性早已被 init 抄走） |
| `spoof-open-redirect` | **CRITICAL** | 同一路径 `stat()` 与 `open()+fstat()` 给出**不同的 dev/ino**——`susfs_opath` 只重定向 `openat/openat2`，stat 家族没动，于是路径指向了两个不同的 inode |
| `mount-view-inconsistency` | **CRITICAL** | `/proc/mounts`(show_vfsmnt) vs `/proc/self/mountinfo`(show_mountinfo) vs `/proc/1/mountinfo` vs `/proc/self/mountstats`(show_vfsstat) 的挂载目标集合必须完全一致。四个视图由四个不同函数产出，挂载隐藏只要有任何一个没覆盖就露馅 |
| `spoof-property` | HIGH | `/system/build.prop`（世界可读的磁盘真值）与 `getprop` 的实时值比对——`resetprop` 类篡改会在这里露头 |
| `susfs-node-*` | **CRITICAL** | 8 个 `/proc/susfs_*` 控制节点 + `/sys/module/susfs*`，用投票法区分「真不存在」与「被隐藏」；uid 0 下直接读内容 |

> 关于「为什么不是简单 grep 关键字」：SuSFS 这类模块已经把关键字、路径、模块名、符号名都藏干净了。上面这些项检查的是**它藏东西这个行为本身留下的矛盾**，而不是它的名字。

---

## 5. `--selftest`

在设备上跑，验证两件事：

1. **决策逻辑**：投票表在各种组合下的判定、verdict 映射、JSON 转义、缓冲区边界、verdict 对应的 flag。
2. **误报卫士**：在「干净设备」上，最容易误报的两项必须保持沉默——`uname()` 必须等于 `/proc/sys/kernel/osrelease`，`/proc/mounts` 与 `/proc/self/mountinfo` 的挂载目标集合必须相等。

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

## 6. 本机环境搭建记录（含结论与排错）

### 6.1 SDK / NDK / 模拟器是怎么装上的（全程无管理员）

* 本机 **PowerShell 的 HTTPS 全部被环境挡掉**（schannel `SEC_E_NO_CREDENTIALS`），但 DNS / 明文 HTTP / **Node.js 的 TLS 正常**。因此所有下载走 `vendor/sdkpkg.mjs`（Node，自带 OpenSSL），并且它直接解析 Google 的 `repository2-3.xml` / `sys-img2-3.xml`，带 SHA-1 校验：

  ```powershell
  node vendor/sdkpkg.mjs list "emulator|platform-tools"     # 查包
  node vendor/sdkpkg.mjs getall platform-tools emulator "system-images;android-30;default;x86_64"
  node vendor/sdkpkg.mjs getall "ndk;30.0.16248370"
  ```

* `vendor/` 下面是 SDK(约 1.1GB) + NDK(解压约 4GB) + 镜像 + AVD，全部在 workspace 内，删目录即卸载。

### 6.2 踩到的坑（都可复现，已修在脚本里）

| 现象 | 原因 | 处理 |
|---|---|---|
| `qemu-system-x86_64-headless.exe` 退出码 `0xC0000135`（STATUS_DLL_NOT_FOUND） | 启动器没有有效地给子进程扩展 DLL 搜索路径 | `run-emulator.ps1` 里显式把 `emulator`、`lib64`、`lib64\gles_swiftshader`、`lib64\vulkan` 加到 `PATH` |
| 模拟器初始化完立刻静默退出 | 系统镜像里的 `advancedFeatures.ini` 写着 `Vulkan = on`，覆盖了模拟器默认的 `off`，而本机 Vulkan ICD 初始化失败（`VK_ERROR_INITIALIZATION_FAILED`） | 镜像内改成 `Vulkan = off`，并用 `-gpu off`（guest 侧渲染） |
| clang：`unable to make temporary file: Permission denied` | 同上，clang 的临时目录 | `build/build.ps1` 里把 `TMP` 指到 `vendor\tmp` |

## 7. 在真机上验证（不依赖模拟器）

```powershell
# Root-only deployment: when the scanner runs as root it must not be executed from
# a directory others can write to (/data/local/tmp is drwxrwx--x shell shell), or
# another adb shell user could replace the binary before it runs.
adb root
adb shell "mkdir -p /data/local/rx && chmod 700 /data/local/rx"
adb push out/rootdetect-arm64 /data/local/rx/rx
adb shell chmod 755 /data/local/rx/rx

# 1) 基线：shell 身份，期望没有 HIGH/CRITICAL（userdebug 设备会有 env-build 的 MEDIUM）
adb shell /data/local/rx/rx

# 2) 自检：逻辑 + 误报卫士
adb shell /data/local/rx/rx --selftest

# 3) 真阳性：在 root 设备上跑（有 su / Magisk / KernelSU 的设备）
adb root
adb shell /data/local/rx/rx -v
```

如果手上是**干净**的设备，可以用注入脚本造出可检出的痕迹（仅模拟器/non-production）：

```powershell
```

---

## 8. 已知局限（诚实说明）

* **非 root 身份下，SuSFS 的路径隐藏本身不可直接观测**：它的 `/proc/susfs_*` 节点对非 uid 0 返回 `-ENOENT`，与「真的不存在」在 errno 上无法区分。所以非 root 时的判定依赖 §4C 的矛盾检测（这是设计上的必然，不是实现偷懒）。uid 0 下则可以直接读到节点内容。
* §4B 里依赖 `/proc/kallsyms`、`/proc/kcore`、debugfs 的项在部分设备上会被 SELinux 挡住（工具会打印 `kernel-kallsyms` / `kernel-kcore` 的 INFO 说明「没查成」，不会把「查不到」当成「干净」或「有 root」）。
* mount 视图对比在**挂载命名空间不同**的情况下会产生差异：以 `shell` 身份运行时与 init 同一个 namespace，正常应完全一致；如果你用 `su --mount-master` 之类进入独立 namespace，该判定需要人工复核。
* 未实现：协议层证据（Play Integrity / key attestation）、硬件断点/性能计数器层面的 hook 检测。
* 跨 ABI 差分（§10）已实现但**尚未在有 32/64 位混合支持的设备上实测过**：需要把两个 ABI 的产物都推进 `/data/local/tmp` 才会启用，缺一个就自动降级为 INFO。
* **已在真实内核与真 Android 上完成端到端实测**：WSL2 的真 Linux 内核（自检、干净基线，以及伪造 `/proc/version` 与 `/proc/1/mountinfo` 得到的正阳性）与 WSL 内 KVM 加速的模拟器（API 30 x86_64：自检、注入 fixtures、APK 装机后按下按钮跑出报告）。**仍然没有在物理真机上验证**（未解锁或已 root 的手机），跨 ABI 差分也只在模拟器上跑过。

---

## 9. 代码地图（想改检测项从哪里下手）

| 想加什么 | 改哪里 |
|---|---|
| 新的可疑路径 / 包名 / 关键字 | `rd_checks.c` 顶部 `RD_ROOT_PATHS`、`RD_ROOT_PACKAGES`、`RD_KEYWORDS` |
| 新的一类交叉验证 | 在 `rd_kernel.c` 加函数并在 `rd_check_consistency()` 里调用 |
| 新的报告项 id 与它对 verdict 的贡献 | `rd_add*()` 调用处 + `rd_util.c` 的 `id_flags()` 表（verdict 只认这张表，保证可复现） |
| 新的内核深度检查 | `rd_kernel.c` 的 `rd_check_deep()`（仅在 uid 0 下运行） |

---

## 10. 跨 ABI 差分与一键真机验证

### 10.1 原理

隐藏模块的 syscall 表补丁是**按表**安装的：SuSFS 的 `susfs_fp_hook` 里 native 表与 compat 表各持一份 wrapper 和 orig 槽，stat 家族与 getdents 的入口点也按 ABI 分开编号（arm64 的 `newfstatat`/`fstat`/`statx` vs AArch32 的 `fstatat64`/`fstat64`）。要让每个 ABI 的行为完全一致，是隐藏方案里最容易出漏洞的地方。

于是：**64 位进程把 32 位兄弟产物用 `--probe-dump` 跑一遍，对同一批路径逐项比对 7 个接口的结果。**

```bash
adb push out/rootdetect-arm64 /data/local/rx/rx                # 主程序
adb shell "mkdir -p /data/local/rx && chmod 700 /data/local/rx"   # root-only: helpers are never exec'd from /data/local/tmp as root
adb push out/rootdetect-arm   /data/local/rx/rootdetect-arm       # 32-bit helper
adb shell chmod 755 /data/local/rx/rx /data/local/rx/rootdetect-arm
adb shell /data/local/rx/rx        # 自动发现助手并启用差分
```

* 找到助手 → `abi-consistency`（一致，INFO）或 `abi-consistency-mismatch`（不一致，**CRITICAL**，逐路径列出两个 ABI 的七个探针结果）。
* 没找到 → `abi-diff-skipped`（INFO，并说明原因），**不会**被当成"干净"或"有 root"。
* 可用 `ROOTDETECT_ABI_HELPER=/path/to/helper` 指定路径，或 `--fast` 关掉全部交叉校验。

### 10.2 追加的轻量检查（`src/rd_extra.c`）

| id | 级别 | 内容 |
|---|---|---|
| `unix-socket-roots` | HIGH | `/proc/net/unix` 里的控制通道名（Frida linjector / Zygisk / Magisk / LSPosed）。它们是 socket 不是文件，藏文件系统不会让它们消失 |
| `self-traced` | HIGH | `/proc/self/status` 的 `TracerPid != 0`：本进程正被 ptrace 附加 |
| `map-backing-hidden` | **CRITICAL** | 自己地址空间里 mmap 进来的文件却 `stat`/`open` 不到——路径隐藏没覆盖 mmap 这条路径 |
| `map-deleted-exec` | MEDIUM | 可执行映射的宿主文件已被 unlink |
| `env-preload` / `env-ldpath` | MEDIUM / LOW | `LD_PRELOAD` / `LD_LIBRARY_PATH`：静态链接的本体不怕预加载，但说明调用方环境被注入 |
