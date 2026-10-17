> **中文版**：本文件是完整中文版，也是仓库的默认 README（首页显示这一份）。
> **English version**: the complete English version is [`README.en.md`](README.en.md).

# bunanana — Android root / root 隐藏检测工具

**bunanana** 是一个 Android 上的 root 与「root 隐藏」检测工具。APK 只是外壳，真正的检测引擎是**静态链接的原生程序 `rootdetect`**（C11，无第三方依赖，四个架构产物）。

## 0. 快速开始

| 我想…… | 怎么做 |
|---|---|
| **直接装上用** | 下载 [`out/bunanana.apk`](out/bunanana.apk) 安装到手机（需允许未知来源），打开后点 **RUN DETECTION** |
| **在电脑上用 adb 跑** | 见 §7：`adb push out/rootdetect-arm64 /data/local/rx/rx` → `adb shell chmod 755 /data/local/rx/rx` → `adb shell /data/local/rx/rx -v` |
| **只要命令行扫描器** | 自行构建：`powershell -ExecutionPolicy Bypass -File build/build.ps1 -Abi arm64` |
| **想先看它凭什么能抓到隐藏** | §4 检测矩阵 + §11 实测记录（真 Linux 内核 + API 30 模拟器 + KVM） |
| **想知道它自己有哪些已知盲区** | [review/detection-review.md](review/detection-review.md)：红队视角的 15 层覆盖矩阵、误报与投毒面、**15 条源码 bug**（本轮已修 16 处） |

一句话：常规检测项（`su` 文件、Magisk 目录、`ro.debuggable`）现在只能抓到裸奔的 root。真正有价值的是**交叉验证**——隐藏模块必须 hook 内核的读取接口，而它不可能把每个接口都覆盖得一样完美，**没覆盖到的那个接口就是证据**。本工具的核心因此是一个「交叉验证引擎」，而不是一份特征清单。

> **仓库里有哪些、没有哪些。** 仓库包含 `src/`、`apk/`、`build/`、`out/bunanana.apk` 与两份 README。本文档提到的一些路径**不在**仓库里——它们要么是体积很大的生成产物，要么是与工具本体无关的宿主侧辅助脚本：
> * `vendor/`：20GB 的 SDK/NDK/JDK 工具链，由 `*.mjs` 下载助手按需拉取（见 §6）；
> * `out/rootdetect-*` 与生成的报告（`out/*.txt`、`build/t2-out/*`）：可复现的构建/测试产物；
> * `scripts/`：宿主侧 PowerShell/Node 辅助脚本（建模拟器、adb 包装、注入 root 痕迹、真机验证）；
> * `review/detection-review.md`：下文引用的红队审查报告。
>
> `bunanana.apk` 内已内置 **arm64-v8a / armeabi-v7a / x86_64** 三个 ABI 的扫描器。

---

## 1. 目录结构

```
android-rootdetect/
├── src/                        # 工具本体（C11，无第三方依赖）
│   ├── rd.h                    # 类型、接口、语料表声明
│   ├── rd_util.c               # IO / exec / getprop / 原始 syscall 探针 / 报告模型
│   ├── rd_checks.c             # 环境、路径、包名、挂载、进程
│   ├── rd_kernel.c             # 模块、kallsyms、SuSFS 节点、交叉验证、root 深度检查
│   ├── rd_extra.c              # 低成本额外信号：控制 socket、ptrace、调用方环境、失联映射
│   ├── rd_selftest.c           # --selftest：逻辑单测 + 误报卫士
│   └── main.c                  # CLI
├── apk/                        # Android 应用：MainActivity.java、manifest、资源、图标
│                               #   以及 Python 组装脚本（assemble.py / check_apk.py / list_apk.py）
├── build/
│   ├── build.ps1               # NDK 交叉编译（x86_64 / arm64 / arm）
│   └── build-apk.ps1           # 组装并签名 APK
├── out/bunanana.apk            # 预编译应用（out/rootdetect-* 是构建产物，未提交）
├── scripts/                    # 宿主侧辅助脚本（未提交 —— 见上方说明）
│   ├── sdkpkg.mjs              # 用 Node 的 TLS 拉 Google SDK 包（见 §6）
│   ├── setup-emulator.ps1      # 不依赖 avdmanager 手工建 AVD
│   ├── run-emulator.ps1        # 启动模拟器（含本机必需的修复）
│   ├── adb.ps1                 # adb 包装（修正 TEMP 权限问题）
│   └── inject-root-fixtures.ps1# 在干净模拟器上注入 root 痕迹做真阳性测试
└── vendor/                     # SDK、NDK、AVD、临时目录（未提交；可整目录删除）
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
rootdetect 1.0.1 self-test   uid=2000
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

* **不需要 JDK**：`avdmanager`/`sdkmanager` 是 Java 程序，这里改为手工写 `config.ini` + `.ini` 建 AVD（`scripts/setup-emulator.ps1`）。
* `vendor/` 下面是 SDK(约 1.1GB) + NDK(解压约 4GB) + 镜像 + AVD，全部在 workspace 内，删目录即卸载。

### 6.2 踩到的坑（都可复现，已修在脚本里）

| 现象 | 原因 | 处理 |
|---|---|---|
| `qemu-system-x86_64-headless.exe` 退出码 `0xC0000135`（STATUS_DLL_NOT_FOUND） | 启动器没有有效地给子进程扩展 DLL 搜索路径 | `run-emulator.ps1` 里显式把 `emulator`、`lib64`、`lib64\gles_swiftshader`、`lib64\vulkan` 加到 `PATH` |
| 模拟器初始化完立刻静默退出 | 系统镜像里的 `advancedFeatures.ini` 写着 `Vulkan = on`，覆盖了模拟器默认的 `off`，而本机 Vulkan ICD 初始化失败（`VK_ERROR_INITIALIZATION_FAILED`） | 镜像内改成 `Vulkan = off`，并用 `-gpu off`（guest 侧渲染） |
| `adb`：`cannot open %TEMP%\adb.log: Permission denied` | adb 1.0.41 硬编码写 `$TEMP\adb.log`，共享 TEMP 不可写 | `scripts/adb.ps1` / `run-emulator.ps1` 把 `TEMP`/`TMP` 指到 `vendor\tmp` |
| clang：`unable to make temporary file: Permission denied` | 同上，clang 的临时目录 | `build/build.ps1` 里把 `TMP` 指到 `vendor\tmp` |

### 6.3 结论：本机**当前跑不起模拟器**，卡在硬件加速（需要管理员）

上面四个坑修完后，模拟器仍然启动不了虚拟机。完整证据链：

* `emulator -accel-check` 报 `WHPX(10.0.22631) is installed and usable`，但实际启动虚拟机时进程立刻退出：
  * 直接跑 qemu 后端（`-verbose` 全量日志 707 行）最后一行停在 `Windows Hypervisor Platform accelerator is operational`，之后无任何输出；
  * 进程退出码 `0xFFFF7001`（另一个组合下是 `0x40000015` = `STATUS_FATAL_APP_EXIT`）；
  * 强制 TCG（`ANDROID_I_WANT_MY_TCG=yes -accel off`）同样在该点退出；
  * 唯一让进程存活下来的组合（`-gpu off`）里，qemu **CPU 时间 0 秒、工作集只有 139MB**——guest RAM 从未被触碰，说明 vCPU 根本没开始执行。
* 宿主机侧证据：`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\HypervisorLaunchType` **未设置**（即 hypervisor 没有配置为启动），`Get-WindowsOptionalFeature` 查询 `HypervisorPlatform` 返回 *requires elevation*，`bcdedit` 亦因非管理员失败。
* 本机 CPU 为真机 `i5-1155G7`（非嵌套虚拟化），内存 17GB，磁盘充足——排除了资源问题。
* **arm64 这条退路也走到底了**：`emulator.exe` 会直接拒绝（`FATAL | Avd's CPU Architecture 'arm64' is not supported by the QEMU2 emulator on x86_64 host`），但那个检查只存在于启动器里——直接调用后端 `qemu\windows-x86_64\qemu-system-aarch64-headless.exe -avd rootdetect-arm` 可以绕过去，它确实继续走到了 arm64 的启动参数（`androidboot.boot_devices=a003600.virtio_mmio`），随后**仍然在启动虚拟机的那一刻 abort**（`0x40000015` = `STATUS_FATAL_APP_EXIT`）。
* 在同一个位置 abort 过的组合已经有 6 种：x86_64/arm64 后端 × WHPX/强制 TCG（`ANDROID_I_WANT_MY_TCG=yes -accel off`）× gfxstream / `-gpu off` / 关闭 Vulkan（两个镜像的 `advancedFeatures.ini` 都已改 `Vulkan = off`）× 512/1024/2048MB 内存。**与架构、加速器、Vulkan、内存都无关**，指向宿主层面的 hypervisor 不可用；emulator 在未授权上报时会删掉崩溃转储，所以 `vendor/tmp/AndroidEmulator/emu-crash-37.3.4.db` 是空的，拿不到更细的调用栈。
* 唯一让进程活下来的组合（x86_64 + `-gpu off`）里 qemu **CPU 时间 0 秒、工作集仅 139MB**：guest RAM 从未被触碰，vCPU 一次都没跑。

**结论（已被 §11.4 取代）**：Windows 侧这条路确实走不通——它依赖 Windows 的硬件加速器，而当前权限下无法启用；Google 的 QEMU 分支连强制 TCG 都不执行 guest 指令（`-d in_asm` 记录证实）。但 **WSL2 里带着可用的 `/dev/kvm`**，把 Linux 版模拟器 + 同一份 AOSP 镜像放进 WSL 即可用 KVM 正常开机（33 秒），全部实测都在那里完成，见 §11.4。

### 6.4 你有管理员权限时，一行命令即可修好

任选一条路线，然后重新执行 `powershell -ExecutionPolicy Bypass -File scripts/run-emulator.ps1`：

```powershell
# 路线 A（推荐）：开启 Windows Hypervisor Platform + 启动 hypervisor，需重启
dism /online /enable-feature /featurename:HypervisorPlatform /all /norestart
bcdedit /set hypervisorlaunchtype auto
shutdown /r /t 0

# 路线 B：不启用 Hyper-V，改装 Google 的 AEHD 驱动（也需要管理员）
#   下载并安装 extras;google;Android_Emulator_Hypervisor_Driver 里的 silent_install.bat
```

重启后自检：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-emulator.ps1                 # x86_64 AVD（已建好则秒过）
powershell -ExecutionPolicy Bypass -File scripts/run-emulator.ps1                   # 窗口模式启动
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 wait-for-device
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell getprop sys.boot_completed   # 期望 1
```

> 另：`-Arch arm64-v8a`（arm64 镜像 + AVD `rootdetect-arm`）在本机已下载建好，但**在 x86_64 宿主上无法启动**（QEMU2 强制 guest 与宿主同架构，见 §6.3）。它只在 ARM 宿主机上可用；保留它是为了将来换机器或做产物兼容性检查。

---

## 7. 在真机上验证（不依赖模拟器）

```powershell
# Root-only deployment: when the scanner runs as root it must not be executed from
# a directory others can write to (/data/local/tmp is drwxrwx--x shell shell), or
# another adb shell user could replace the binary before it runs.
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 root
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell "mkdir -p /data/local/rx && chmod 700 /data/local/rx"
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 push out/rootdetect-arm64 /data/local/rx/rx
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell chmod 755 /data/local/rx/rx

# 1) 基线：shell 身份，期望没有 HIGH/CRITICAL（userdebug 设备会有 env-build 的 MEDIUM）
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell /data/local/rx/rx

# 2) 自检：逻辑 + 误报卫士
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell /data/local/rx/rx --selftest

# 3) 真阳性：在 root 设备上跑（有 su / Magisk / KernelSU 的设备）
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 root
powershell -ExecutionPolicy Bypass -File scripts/adb.ps1 shell /data/local/rx/rx -v
```

如果手上是**干净**的设备，可以用注入脚本造出可检出的痕迹（仅模拟器/non-production）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/inject-root-fixtures.ps1          # 造 su / magisk 目录 / 隐藏包
powershell -ExecutionPolicy Bypass -File scripts/inject-root-fixtures.ps1 -Clean    # 清理
```

---

## 8. 已知局限（诚实说明）

* **非 root 身份下，SuSFS 的路径隐藏本身不可直接观测**：它的 `/proc/susfs_*` 节点对非 uid 0 返回 `-ENOENT`，与「真的不存在」在 errno 上无法区分。所以非 root 时的判定依赖 §4C 的矛盾检测（这是设计上的必然，不是实现偷懒）。uid 0 下则可以直接读到节点内容。
* §4B 里依赖 `/proc/kallsyms`、`/proc/kcore`、debugfs 的项在部分设备上会被 SELinux 挡住（工具会打印 `kernel-kallsyms` / `kernel-kcore` 的 INFO 说明「没查成」，不会把「查不到」当成「干净」或「有 root」）。
* mount 视图对比在**挂载命名空间不同**的情况下会产生差异：以 `shell` 身份运行时与 init 同一个 namespace，正常应完全一致；如果你用 `su --mount-master` 之类进入独立 namespace，该判定需要人工复核。
* 未实现：协议层证据（Play Integrity / key attestation）、硬件断点/性能计数器层面的 hook 检测。
* 跨 ABI 差分（§10）已实现但**尚未在有 32/64 位混合支持的设备上实测过**：需要把两个 ABI 的产物都推进 `/data/local/tmp` 才会启用，缺一个就自动降级为 INFO。
* **已在真实内核与真 Android 上完成端到端实测**：WSL2 的真 Linux 内核（自检、干净基线，以及伪造 `/proc/version` 与 `/proc/1/mountinfo` 得到的正阳性）与 WSL 内 KVM 加速的模拟器（API 30 x86_64：自检、注入 fixtures、APK 装机后按下按钮跑出报告），详见 §11。**仍然没有在物理真机上验证**（未解锁或已 root 的手机），跨 ABI 差分也只在模拟器上跑过。

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

### 10.3 一键真机验证

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify-on-device.ps1            # 或 -Serial <序列号>
```

脚本会：按设备 ABI 挑产物 → 主程序 + 另一个 ABI 的助手一起推 → 跑 `--selftest` → 以 `shell` 身份跑一遍存 `out/report-shell.json` → `adb root` 后再跑一遍存 `out/report-root.json` → 打印两次 verdict 对比，并列出**只有 uid 0 才看得到**的发现。这是把"到底有没有 root / 有没有隐藏"落到可复核证据上的最短路径。

---

## 11. 实测与误报率验证（WSL 真实内核 + APK）

### 11.1 在真实 Linux 内核上执行（WSL2, kernel 5.10.16.3）

Android 模拟器在这台机器上起不来（见 §6），但 WSL2 提供的是**真 Linux 内核**，而这个工具是静态链接的，可以直接丢进 WSL 执行：不匹配 Android 的路径语料会如实降级成 INFO，检测引擎本身则完整跑通。

```bash
wsl -e      bash android-rootdetect/scripts/wsl-verify.sh baseline    # uid 1000
wsl -u root -e bash android-rootdetect/scripts/wsl-verify.sh fixtures # 注入 + 伪造
```

| 场景 | 实测结果 |
|---|---|
| `--selftest` | **75 checks, 0 failure(s), 6 skipped**（当前二进制；多出的 SKIP 是内核模块列表相关的结构性断言，本机 WSL 内核无可加载模块标签） |
| 干净系统基线（误报率） | **verdict: CLEAN** —— 0 critical / 0 high / 0 medium / 0 low（19 条 INFO） |
| 注入 root 痕迹（`/system/xbin/su`、`/system/bin/ksud`、`/data/adb/magisk`） | `artefact-present` + `artefact-listing` = **HIGH**，verdict: ROOT_DETECTED（exit 2） |
| `tmpfs` 覆盖 `/system` | `mount-overlay` = **HIGH** |
| bind-mount 伪造 `/proc/version`（复刻 SuSFS uname 层：syscall 被改而 `/proc` 保持真值） | `spoof-uname` = **CRITICAL**，verdict: HIDING_DETECTED |
| bind-mount 伪造 `/proc/1/mountinfo`（只改掉四个挂载视图中的一个） | `mount-view-inconsistency` = **CRITICAL**（`/proc/mounts` 33 条 vs `/proc/1/mountinfo` 1 条），verdict: HIDING_DETECTED |

后两项是关键：它们证明**对抗检测器的正阳性路径在真实内核上确实能被触发**，而不只是"设计上应该能行"。完整记录见 [out/wsl-fixtures-report.txt](out/wsl-fixtures-report.txt)。

### 11.2 真实执行抓出来的 bug（均已修复）

| # | 问题 | 后果 | 修复 |
|---|---|---|---|
| 1 | `/proc/self/mountstats` 是句子式格式（`device X mounted on Y with fstype Z`），我却按第 3 列取挂载点，取到的是字面量 `on` | 干净系统凭空多出 31 个挂载点 → **误报 CRITICAL / HIDING_DETECTED** | 字段索引改为 4，并在 `--selftest` 增加"四个挂载视图必须一致"的回归守卫 |
| 2 | `--selftest` 硬编码了 Android 专属路径（`/system/bin/sh`）和 `getprop` | 在任何 Linux 上自检必然 FAIL | 改用 `/proc/version`；Android 专属项改为 SKIP |
| 3 | 内核未开 `CONFIG_KALLSYMS_ALL` 时 `sys_call_table` 解析不到，代码**完全静默** | 使用者会误以为"最强检查已经跑过" | 输出 `kernel-syscall-table-skipped` 并说明原因 |

第 1 条尤其说明问题：它是**执行验证**（而非代码审查）发现的，而且恰好是这类工具最不能犯的错误——把干净设备判成隐藏。

### 11.3 APK（`out/bunanana.apk`）

应用名 **bunanana**，图标是 `apk/icon-source.jpg`（由 `apk/make-icons.py` 生成全套多密度资源）；检测引擎仍叫 `rootdetect`，在主界面里作为副标题标注，CLI 产物名也不变（`rootdetect-{arm64,arm,x86_64}`）。

```powershell
python3 apk/make-icons.py        # 只在换了图之后需要（WSL/任意有 Pillow 的环境）
powershell -ExecutionPolicy Bypass -File build/build-apk.ps1   # 产出 out/bunanana.apk
```

不需要 Gradle / Android Studio：`aapt2 compile res` → `aapt2 link`（manifest + 编译好的资源）→ `javac` → `d8` → 组装 zip（用 WSL 里的 python3，因为本机没有 zip 工具）→ `zipalign` → `apksigner`（debug keystore 由 keytool 现场生成并**持久保留**在 `build/debug.keystore`）。所需 JDK 是便携版 Temurin 17（`vendor/jdk`）。

APK 内容（已逐项核验）：

| 条目 | 说明 |
|---|---|
| `classes.dex` | `com.rootdetect.app.MainActivity`（dex 字符串表已确认含类名） |
| `res/mipmap-*/ic_launcher.png` | 48/72/96/144/192 px 传统图标 |
| `res/mipmap-*/ic_launcher_foreground.png` | 108/162/216/324/432 px 自适应图标前景（圆形遮罩，背景色 `#D3C9C6` 从原图边缘采样） |
| `res/mipmap-anydpi-v26/ic_launcher.xml` | 自适应图标声明 |
| `lib/arm64-v8a/librootdetect.so` | 就是 `out/rootdetect-arm64`，sha256 **逐一比对一致** |
| `lib/armeabi-v7a/librootdetect.so` | `out/rootdetect-arm`，同上 |
| `lib/x86_64/librootdetect.so` | `out/rootdetect-x86_64`，同上 |
| 签名 | v1+v2 均已签名，`zipalign -c` 通过；`aapt2 dump badging` 显示 `application-label:'bunanana'`、`application-icon-*: res/mipmap-anydpi-v26/ic_launcher.xml` |

产物（已核验）：

- 产物：`out/bunanana.apk`，**2,885,164 字节**，`sha256=8318e0348d12ba509ac8204b67e13a4809a7edbd55f7789ece668d60b8545998`
- 下载直链：https://github.com/supervooc/bunanana/raw/main/out/bunanana.apk

设计要点：

* **没有任何资源文件**，UI 全部用代码搭建，所以只需要 `aapt2 + javac + d8` 就能构建。
* 静态可执行文件以 `lib/<abi>/librootdetect.so` 随包分发，安装时被解压到应用的 native library 目录（该目录可执行），Activity 用 `ProcessBuilder` 运行它并把输出显示出来。
* `targetSdkVersion=28` 是刻意的：Android 10+ 对 targetSdk≥29 的应用禁止从自身数据目录 `exec`，而本工具需要在无 root 的情况下运行设备上的原生代码；万一 native lib 目录也被 OEM 拦截，会退化成"复制到 `filesDir` 再执行"，仍失败则显示 adb 命令行用法。
* **结论区与日志导出**：报告顶部新增一块结论横幅——直接给出"是否 root / 是否存在隐藏"以及风险计数，并列出每条 MEDIUM 及以上问题**出现在哪些具体路径**（从证据行里解析出的绝对路径，例如 `package-hidden -> /data/data/com.topjohnwu.magisk`）；`Export log` 按钮把整份日志（设备头 + 结论 + 完整报告）写到应用外部目录 `Android/data/com.rootdetect.app/files/bunanana-report-<时间戳>.txt`，然后打开系统分享面板（纯文本分享，不需要任何存储权限；外部目录不可用时退回应用私有目录）。
* **已在模拟器上完成装机实测**：`adb install` 成功 → Activity 正常显示 → 按下 "RUN DETECTION" → 包内的静态扫描器被成功执行并在界面渲染出完整报告（截图：[apk-screenshot.png](out/apk-screenshot.png)、[apk-screenshot-after.png](out/apk-screenshot-after.png)）。应用域（`untrusted_app_27`）里没有任何 `avc: denied` 阻断执行；唯一被 SELinux 挡住的是 `/sys/fs/selinux/enforce`、`/proc/sys/kernel/tainted` 和 `/system/xbin/su` 的 `stat`（`su_exec` 类型），工具对此如实降级成 INFO，并且**没有**因为"部分接口被挡住"而误判成隐藏——被 SELinux 拒绝的探针不参与投票。
* 构建流水线的两个坑（都会让"看起来已经修好了"变成假的）：① `build/apk-work` 每次构建被清空，连带删掉 debug keystore，重新生成的密钥让新包**无法覆盖安装**、`adb install` 静默失败并继续跑旧版本（keystore 现已移到持久的 `build/debug.keystore`，安装脚本也加了"签名不符先卸载"的兜底）；② 测试脚本按小写匹配按钮文字，而 Android 的 `Button` 会把标签转成大写。

---

## 11.4 真 Android 模拟器实测（WSL + KVM）

§6 的结论**已被本节取代**：Windows 侧的 SDK 模拟器依然起不来，但 **WSL2 里存在 `/dev/kvm`**（`nested=Y`，vmx 已暴露），于是把 **Linux 版模拟器 + 同一份 AOSP x86_64 镜像**装进 WSL，用 KVM 真正跑起来了：

```
INFO | Boot completed in 32689 ms                      <- 33 秒开机（KVM 加速）
$ adb devices -l
emulator-5554  device product:sdk_phone_x86_64 model:Android_SDK_built_for_x86_64 device:generic_x86_64
$ adb shell getprop sys.boot_completed ; getprop ro.build.version.release ; getprop ro.build.type
1  ;  11  ;  userdebug
```

复现命令（脚本已固化）：

```bash
wsl -u root -e bash scripts/wsl-emulator.sh setup   # 解压 + 复制镜像（Linux 版模拟器）
wsl -u root -e bash scripts/wsl-emulator.sh avd     # 建 AVD
wsl -u root -e bash scripts/wsl-emulator.sh boot    # -accel on -no-window -gpu off
wsl -u root -e bash scripts/wsl-android-verify.sh   # 推送 + 全量验证
```

| 场景 | 实测结果 |
|---|---|
| `--selftest`（真 Android，shell 身份） | **77 checks, 0 failure(s), 2 skipped**（以 `shell` 身份运行时，缺的 2 项是 `/proc/sys/kernel/osrelease` 与 `version` 不可读；以 uid 0 运行时 0 skipped，检查数同为 77） |
| 干净模拟器基线（`shell` 视角） | verdict **ROOT_DETECTED**，恰好 3 条 HIGH：`ro.debuggable=1`、`service.adb.root=1`、SELinux 域为 `su`；另有 3 条 MEDIUM（userdebug 构建、userdebug 自带的 `/system/xbin/su`、OE taint）。**全部为真阳性**——userdebug 镜像 + `adb root` 本身就是 root 等价权限，不含任何伪造的 CRITICAL |
| 注入 `/data/data/com.topjohnwu.magisk`（不在包管理器列表中） | `package-hidden` = **CRITICAL**（KernelSU「隐藏应用」的确定性特征） |
| 注入 `/data/adb/magisk`、`/data/local/tmp/su` | `artefact-present` + `artefact-listing` = **HIGH**，verdict **HIDING_DETECTED** |

## 11.5 真实执行抓出并修掉的误报（共 10 处）

| 环境 | 问题 | 修复 |
|---|---|---|
| WSL | `/proc/self/mountstats` 字段索引错 → 凭空多出 31 个挂载点，**CRITICAL 误报** | 索引改为 4，并加自检回归守卫 |
| WSL | 自检硬编码 Android 路径与 `getprop` → Linux 上必然 FAIL | 改用 `/proc/version`；Android 专属项改 SKIP |
| WSL | `sys_call_table` 解析不到时**静默** | 输出 `kernel-syscall-table-skipped` 说明原因 |
| Android | `stat` 可见但 `open` 被 SELinux 拒绝，被当成 open-redirect → **CRITICAL 误报** | 只有 dev/ino 不一致才算重定向 |
| Android | `ro.secure` / `ro.debuggable` 比较方向写反 → **HIGH 误报** | 表中显式区分 `CMP_EQUAL` / `CMP_NOT_EQUAL` |
| Android | `/debug_ramdisk` 在 Android 11+ 是标准目录 | 从语料中移除 |
| Android | `/system/xbin/su` 在 userdebug 上属构建产物 | userdebug + `/system/*` 降为 MEDIUM |
| Android | `kernel-taint-oe` 定级过高（实测 `tainted=4096` 由厂商模块造成） | 降为 MEDIUM 并说明 |
| Android | `kernel-module-hidden` 把内核伪模块 `bpf` 当成被隐藏模块 → **HIGH 误报** | 允许列表跳过 `bpf` |
| Android | `spoof-cmdline` 因 3/10 个属性本就不来自 cmdline 而报 HIGH | 改为多数规则（>50% 才报） |

这张表是"为什么必须真跑一遍"最好的证明：其中 **4 处会直接把干净设备判成 HIDING_DETECTED**，而它们全部是执行验证（而非代码审查）发现的。

---

## 11.6 并行加固（Agent Teams）与最终验收

这一轮把三块互不重叠的工作并行派给三个队友，各自把证据落成文件：

| 角色 | 任务 | 结果 |
|---|---|---|
| **t-abi** | 跨 ABI 差分真机验证 | 新增 `i686-linux-android` 目标 → `out/rootdetect-x86`（ELF32 / EM_386 / 静态）。32 位助手在 API 30 x86_64 模拟器上**确实可执行**（设备 `abilist32=x86`、`zygote64_32`、`/system/bin/linker` 都在；`--selftest` → 76 checks / 0 failures / 2 skipped）。正式结果：`[INFO] abi-consistency — both ABIs agree on every probed path`，**compared 92 paths between x86_64 and /data/local/tmp/rootdetect-x86 (x86)**。另做了负控（换同 ABI 助手 → `abi-diff-skipped`）、同快照对照（另一目录构建**逐字节相同**）、以及 `-Abi x86_64,arm64,arm` 回归（0 warning、既有产物 mtime 未变）。证据：[abi-diff-report.txt](out/abi-diff-report.txt)、[wsl-abi-diff.sh](scripts/wsl-abi-diff.sh) |
| **t-selftest** | `--selftest` 解析器边界加固 | 新增 39 项用例（投票组合、JSON 转义边界、trim/appendf 哨兵字节、挂载解析含 `\040` 转义、**挂载检查端到端**、内核列表端到端），WSL 上 **75 checks / 0 failures / 6 skipped**。并用**变异测试**证明新用例能抓到旧的字段索引错误（把 `field` 改成 `{1,3,3,3}` → 新用例 FAIL，而旧守卫仍 PASS）——补掉了一个真实盲区。输出：[selftest-final.txt](build/t2-out/selftest-final.txt) |
| **t-review** | 红队审查 | [detection-review.md](review/detection-review.md)（460 行）：15 层覆盖矩阵（4 层完全没覆盖、5 层部分）、stock/定制 ROM 误报表 + **非特权方投毒面**、3 份实现草案、**15 条源码 bug**（每条 `file:line` + 最小复现），并单列了 README §11.5 已修复项以免重复计数 |

### 红队 #1：在真机上复现并修复

```
修复前：adb shell 'ln -sf /nonexistent /data/local/tmp/su; /data/local/rx/rx -q'
        [CRITICAL] path-consistency-mismatch ...  →  HIDING_DETECTED (exit 3)
修复后：ROOT_DETECTED (exit 2) + [MEDIUM] artefact-dangling-symlink
```

根因：投票引擎把 `fstatat(AT_SYMLINK_NOFOLLOW)` / `statx(NOFOLLOW)` 与跟随语义的 `stat/access/open` 扔进**同一个票箱**，于是**任何悬空符号链接都长得像"kstat 层只改了部分接口"**；而 `/data/local/tmp/su` 就在语料里、该目录 `shell` 可写——等于给了非特权进程一个投毒开关。

### 本轮应用的 16 处代码修正（下表按问题归为 12 类）

每处替换都强制校验"恰好命中一次"（避免静默误改），四个 ABI 零警告重建后在真机复验：

| 修复 | 验证方式 / 后果 |
|---|---|
| B1 悬空符号链接不再判 CRITICAL（含控制路径 `/sdcard`） | 真机复现命令，修复后 exit 2 + MEDIUM（见上） |
| B2 32 位构建不再错误索引 native `sys_call_table` | 新增 `sizeof(void*)!=8` 分支单独报 INFO；否则 32 位以 root 运行会伪造 `kernel-syscall-table-patched` CRITICAL |
| B3 maps 路径含空格不再被截断 | 之前任何含空格的映射文件都会自爆 `map-backing-hidden` CRITICAL |
| B4 `spoof-cmdline` 兼容 `/proc/bootconfig` | Android 12+/GKI 上 androidboot.* 只在 bootconfig → 真机 `spoof-cmdline` 回到 INFO "agree" |
| B5 `inj[]` 的 `gadget` 误命中 USB gadget HAL | 改为 `frida-gadget` / `gum-js-loop` |
| B6 `mount-overlay` 要求挂载点确为 system 分区 | overlayfs 的设备名恒为 `overlay`，不再命中任意 overlay 挂载 |
| B8 进程扫描真正读取全部 argv | 原循环在第一个 NUL 处停止（只看得到 argv[0]），`ksud`/`zygiskd` 在 argv[1..] 时不可见 |
| B10 `find_push` 的 OOM 越界写 | `cap` 仅在 `realloc` 成功后推进 |
| B11 `deep-dmesg` 不再把 `busybox` 当框架 | 与其它关键字扫描一致 |
| B12 ABI 差分不再把 `blocked(-1)` 当差异 | 与投票引擎规则统一（否则 SELinux 拒绝会伪装成 ABI 分歧） |
| B15 userdebug 降级覆盖 `/sbin/`、`/vendor/bin/su` | 之前只匹配 `/system/` |
| t-selftest 报告的 UB：`rd_row_inconsistent(.., NULL, 0)` | 提前返回；原指针运算为 `cons_out + SIZE_MAX` |

### 最终验收（一条命令）

```bash
wsl -u root -e bash android-rootdetect/scripts/verify-all.sh
```

最近一次：**PASS=18 FAIL=0 SKIP=0**（Linux 真内核自检 + 干净基线；模拟器自检 + shell/root 双视角；注入 fixtures 命中 `package-hidden` CRITICAL；跨 ABI 差分；APK 结构与三 ABI 二进制哈希）。原始输出在 `/tmp/verify-all/`。

> 本机没有 PowerShell 7（`pwsh`），所有 `.ps1` 请用 `powershell -ExecutionPolicy Bypass -File` 调用——README 里的示例已按此修正（这是 t-abi 发现的文档问题）。
