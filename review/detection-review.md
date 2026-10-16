# rootdetect 红队审查：对抗检测盲区、误报面与源码逻辑 bug

- 任务：`task-3`（红队视角，review 负责人 `t-review`）
- 审查对象（只读，未修改任何文件、未构建、未动模拟器）：
  `src/rd_checks.c`、`src/rd_kernel.c`、`src/rd_extra.c`、`src/rd_util.c`、`src/rd.h`、
  `src/rd_selftest.c`（补查，因为它内含误报守卫）、`README.md` §4/§8/§11。
- 对抗方资料：`susfs-lkm-loading-hooking-brief.md`（下称 **brief**，`§n / L行`）、
  `susfs4ksu-lkm-原理分析.md`（下称 **原理分析**）。
- 行号以本次审查时的文件内容为准（`src/` 未被任何人改动过，行号可直接 grep 核对）。
- 标记约定：**【新】**＝README §11.5 未记录；**【已修复】**＝§11.5/§11.2 已记录并已修，
  本报告只给出残留面，不重复计数。

---

## 0. 结论摘要与最值得立刻动手的一条

**最值得立刻动手：【B1】投票引擎把 `lstat` 语义和 `follow` 语义混在一个票箱里。**

- 依据：`rd_util.c:556-560`（`fstatat(..., AT_SYMLINK_NOFOLLOW)`）、`rd_util.c:562-570`
  （`statx(..., AT_SYMLINK_NOFOLLOW)`）、`rd_util.c:540-548/572-587`（`stat/access/open` 都跟随）、
  合并逻辑 `rd_util.c:631-657`，触发点 `rd_checks.c:212-225`。
- 后果：任何一个**悬空符号链接**放在语料路径上，都会得到
  `fstatat/statx=存在` + `stat/access/open/open_read/opendir=ENOENT` → **CRITICAL
  `path-consistency-mismatch` → verdict HIDING_DETECTED**，而这台机器完全干净。
- 而且它是**可被非特权方主动投毒**的（`/data/local/tmp` 对 `shell` 可写，
  `RD_ROOT_PATHS` 里就有 `/data/local/tmp/su`，`rd_checks.c:19`）。
- 一条命令验证（干净模拟器上跑，跑完删掉）：

  ```bash
  adb shell 'ln -sf /nonexistent /data/local/tmp/su; /data/local/tmp/rx -q; rm -f /data/local/tmp/su'
  # 期望 CLEAN，实际会得到 HIDING_DETECTED（含 CRITICAL path-consistency-mismatch）
  ```

  修法见 §4-B1（把"只有 lstat 类探针看得见"独立成 `artefact-symlink` 之类的 LOW/MEDIUM 项，
  或者把票箱拆成 follow-only / nofollow-only 两组分别判定，不再交叉投票）。

其余高优先项（按我建议的顺序，详见 §3 与 §4）：

1. **supercall 正检测**（§3-草案 A）：`syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, 0x555e2, &payload)`
   是本报告里唯一**确定性**抓到该 LKM 的通道，约 25 行，误报面可控（原理分析 §5.7a L179、§6 L198-199）。
2. **`spoof-cmdline` 看错了文件**（§4-B4）：`rd_kernel.c:457` 读 `/proc/cmdline`，而该 LKM 改的是
   `/proc/bootconfig` 的 `saved_boot_config`（brief §5.7 L173、原理分析 §5.7 L173）——
   既是 Android 12+/GKI 上 HIGH 误报的来源，又完全抓不到真正的 cmdline 层。
3. **投票扩容 `statfs`/`listxattr` + `name_to_handle_at`**（§3-草案 C）：sus_path 的 13 个 LSM 出口里
   `sb_statfs`/`inode_getxattr`/`_listxattr`（brief §5.1 L96）目前**一个都没被探测**；
   `name_to_handle_at` 能对"父目录可搜索的普通文件"绕开路径层，并给出不经过 statbuf 的**真实 ino**。

---

## 1. 未覆盖的隐藏机制（对照 brief 的 15 层）

### 1.1 逐层覆盖矩阵

代码层面"抓到了"的定义：存在某个探针/交叉视图，在该层**实现不完整**时会产出 HIGH/CRITICAL。
层名与顺序取自 brief §1 L9 / 原理分析 §3 L44。

| # | 层 | 现在抓得到吗 | 为什么（依据） | 有可能抓到的通道 | 成本 |
|---|---|---|---|---|---|
| 1 | `ksu_umount_gate` | **否** | 它只决定"哪些进程被 umount"，不产生新的可读物。工具所有 mount 探针都在单一命名空间/单一 uid 视角内：`rd_checks.c:399-410`（4 个文件全是 `/proc/self` 与 `/proc/1`） | 同一批探针在**两个 uid/域**里各跑一次做差分（`/proc/<pid>/mounts`，pid 取 zygote/app 域 vs shell 域）。gate 逻辑见原理分析 §6 L200（`ksu_uid_should_umount`，解析不到则退回 uid≥10000） | 高（需要第二个进程/uid + 稳定基线） |
| 2 | `lsm_hook` | **否**（用户态无法枚举 `security_hook_heads`） | 只能看到它的**效果**。它只能对"DAC 会放行"的对象伪造 ENOENT（brief §5.1 L101），并且 13 个出口各自计数（brief §5.1 L92-97） | 把 `statfs()`/`listxattr()`（meta 出口，brief §5.1 L96）加进 7 探针投票：若这层漏了任一出口，隐藏路径会呈现"stat=ENOENT 但 statfs/listxattr=0" | **低** |
| 3 | `sus_path` | 部分 | 语料 7 探针 + 控制路径：`rd_checks.c:208-235`、`rd_kernel.c:549-579` | ①`name_to_handle_at`（跳过最终组件的权限检查，见 1.2）；②语料外的自定义规则——`RD_ROOT_PATHS`/`RD_HIDING_PATHS` 是固定表（`rd_checks.c:15-50`），规则命中别的文件时工具看不见；③`/proc/<pid>/map_files/*`（brief §5.6a L158 说模块覆盖了它，但工具压根不看） | 低~中 |
| 4 | `opath` | **是** | `rd_probe_open_o_path`（`rd_util.c:577-581`）正好打在 brief §5.3 的那个洞上；模块漏装 wrapper 时 `open_path=0` 而 stat=ENOENT 会分裂投票 | 只差 `openat2` 与 O_PATH fd 的后续利用（`fstatat(fd,"",AT_EMPTY_PATH)`），但那已被 LSM 的 `inode_getattr` 覆盖，价值低 | 低 |
| 5 | `dirent` | 部分 | `opendir` 探针（`rd_util.c:589-597`）+ 关键字目录列举（`rd_checks.c:247-268`） | ①`d_ino==0` 占位记录：brief §5.2 L111 明说"真文件系统不会发 d_ino 0"——扫原始 `getdents64` 即可，见 §3-草案 E；②非关键字名的隐藏项（目录列举只做关键字匹配 `rd_checks.c:258`）；③**按 ABI 的 dirent 泄漏**：ABI 差分只比 7 个"存在/不存在"布尔（`rd_kernel.c:765-776`），不比对目录项集合 | 低 |
| 6 | `uname` | **是**（native） | `check_uname_spoof`，`rd_kernel.c:405-452`，CRITICAL | 但 `--probe-dump` 里**没有 utsname**（`rd_kernel.c:749-776` 只有路径），所以 compat（AArch32）路径是否被 spoof 完全没测：模块的 kretprobe 挂在 `__arm64_sys_newuname`（brief §3 L22），32 位入口是否同一个函数没有验证 | **低** |
| 7 | `kstat` | 部分 | `stat/statx/fstatat` 全在模块的 13 个入口里（brief §5.5 L134），所以"完整"的 kstat 伪装**不会**让投票分裂；`spoof-open-redirect` 只在 open 被重定向时有效（`rd_kernel.c:505-545`） | ①`name_to_handle_at` 返回的 f_handle 里的 ino（`exportfs_encode_fh` 用 `i_ino`，不经过 statbuf）vs `st_ino`；②字段级比对：模块只改 `KSTAT_SPOOF_*` 标记的字段（brief §5.5 L136-137），statx 的其它字段/`stx_mnt_id` 可能露真值；③32 位 `stat64`/`compat_stat` 与 64 位 `statx` 的宽度差异（brief §5.5 L137）——正好是 ABI 差分该覆盖的 | 低~中 |
| 8 | `sus_map` | **否** | 工具只在 `/proc/*/maps` 里做关键字匹配（`rd_checks.c:534-556`），行被删掉就没有任何痕迹；`map-backing-hidden` 只读自己的 maps（`rd_extra.c:78`） | ①`/proc/<pid>/statm`（`task_statm` 用 `mm->total_vm`，不走 `walk_page_range`）× maps 区域大小之和；②`/proc/<pid>/smaps_rollup` vs `/proc/<pid>/status` 的 VmRSS；③`/proc/<pid>/map_files/*` 链接名里的 dev:ino（模块 hook 了它，但只要它漏一个就走漏） | 中（需要干净机基线） |
| 9 | `sus_mount` | 部分 | 4 视图目标集合对比，`rd_checks.c:474-504` | ①**视图为空即跳过**（`rd_checks.c:475`：`if (ns[i]==0 || ns[0]==0) continue;`）——把 mountinfo 清空的隐藏反而无任何 finding；②`/proc/1/mountinfo` 没有命名空间守卫；③**`listmount(2)`/`statmount(2)`**（Linux 6.8+，模块完全没 hook，原理分析 §5.6 L143-150 只列三个 show 函数 + copy_mnt_ns/attach_recursive_mnt；原理分析 §7 L211）——需要 CAP_SYS_ADMIN，放 deep 模式 | ①低、③中 |
| 10 | `cmdline` | **看错文件** | 工具比 `/proc/cmdline`（`rd_kernel.c:457`/`488`），而这个 LKM 改的是 `/proc/bootconfig` 的静态指针 `saved_boot_config`；brief §5.7 L173 与原理分析 §5.7 L173 都明确"被读的文件里**没有** `/proc/cmdline` 的对应实现"。`src/` 内 grep `bootconfig` = 0 命中 | 读 `/proc/bootconfig` 与 `/proc/cmdline` 取**并集**再和 `ro.boot.*` 比，见 §3-草案 B | **低** |
| 11 | `open_redirect` | 部分 | 8 条硬编码路径的 dev/ino 比对，`rd_kernel.c:505-545` | ①**反向面完全没查**：`readlink(/proc/self/fd/N)`、`statfs`、maps 名字列、fdinfo（brief §5.4 L129-130），而 brief L130 自己承认 `__d_path` 曾"注册成功却 0 命中"——正好是工具的空白；②io_uring 的 `OPENAT/OPENAT2`（brief §5.4 L130 明确不覆盖）——这既是模块的洞也是探测器的空白 | ①**低**、②高 |
| 12 | `enable_log` | 不可测 | 纯日志开关，没有可读产物 | 唯一残留：`susfs_init()` 结尾的 `pr_info` **不受**该开关控制（原理分析 §5.8 L194，作者刻意留的"我起来了"证据）→ `deep-dmesg-hits` 是正解，但它只做关键字匹配且要 root（`rd_kernel.c:661-697`） | 低（已有） |
| 13 | `avc_spoof` | **否** | 工具从不解析 `avc: denied` 行（`deep_dmesg` 只做关键字匹配，`rd_kernel.c:686`） | 在 `su` 域里制造一次必然被拒的操作，然后比对 dmesg 行里的 `tcontext=` 与 `/proc/self/attr/current`：spoof 把 tsid 改写成 `priv_app`（brief §5.7 L174），而 `tclass/perm/target` 不变 | 中（root + dmesg + 稳定的"必然被拒"操作） |
| 14 | `supercall` | **否** | `src/` 内 grep `reboot` = 0 命中（除了 `deep_dmesg`/`deep_kprobes` 的字符串） | **最便宜的确定性正检测**：`syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, CMD, &payload)`，`err` 预置 126；命令表见原理分析 §6 L198-199（`SHOW_VERSION 0x555e1`、`SHOW_ENABLED_FEATURES 0x555e2`），uid 0 要求见 §5.7a L179，`SUSFS_LKM_MODULES` 标记见 L181 | **低** |
| 15 | `hide_syms` | 抓不到"隐藏成功" | 它一工作，`/proc/modules` 与 kallsyms 同时干净（brief §5 L40、原理分析 §5.8 L191-194） | `/sys/module` 是 sysfs，模块只能用 sus_path 规则隐藏，且**root 保留访问**（brief §5 L193）。工具的 `kernel-sysmodule`（`rd_kernel.c:199-217`）与 `deep-susfs-node`（`rd_kernel.c:711-725`）已在 root 下覆盖；缺的是 `/proc/modules` × `/sys/module` 的**集合差**——工具只各自做关键字匹配（`rd_kernel.c:180`/`208`），从未比对两个集合 | 低~中（需先验证 built-in 的判别口径） |

### 1.2 按实现成本排序（低→高）

| 序 | 通道 | 覆盖的层 | 成本估计 |
|---|---|---|---|
| 1 | supercall `SHOW_VERSION/SHOW_ENABLED_FEATURES` | supercall（+ enable_log 的存在性） | ~25 行，零新依赖 |
| 2 | `/proc/bootconfig` 并入 `spoof-cmdline` | cmdline | ~40 行 |
| 3 | 投票加 `statfs`/`listxattr` + `name_to_handle_at` | lsm_hook、sus_path、kstat | ~60-80 行 |
| 4 | `readlink(/proc/self/fd/N)` 回读 | open_redirect 反向面 | ~30 行 |
| 5 | `getdents64` 里查 `d_ino==0` | dirent | ~30 行 |
| 6 | `--probe-dump` 加值域（uname/statx 字段/目录项摘要） | uname、kstat、dirent 的 ABI 面 | ~50 行（并直接喂给 t-abi） |
| 7 | `/sys/module` × `/proc/modules` 集合差 | hide_syms | ~40 行 + 干净机基线 |
| 8 | `/proc/self/ns/mnt` vs `/proc/1/ns/mnt` 守卫 | sus_mount（消误报） | ~15 行 |
| 9 | `listmount`/`statmount` | sus_mount | ~120 行，root-only |
| 10 | maps 大小和 vs `statm`/`smaps_rollup` | sus_map | ~80 行 + 基线 |
| 11 | dmesg `tcontext` vs `attr/current` | avc_spoof | ~60 行，root+dmesg |
| 12 | 两个 uid/域的 mount 差分 | ksu_umount_gate | ~150 行 + 第二身份 |

### 1.3 一句话的结构性结论

15 层全部武装好之后，仍然**必然**留下的可测面只有四类：
(1) **supercall**（模块自己提供的确定性应答）；
(2) **没有被 hook 的 syscall**（`name_to_handle_at`、`listmount/statmount`、`statfs/listxattr` 若实现时漏了）；
(3) **跨 ABI 的值域泄漏**（当前 ABI 差分只比布尔，见 §1.1 第 6/7 行）；
(4) **内核自己的日志**（原理分析 §5.8 L194 那条不受 `enable_log` 控制的 `pr_info`）。
工具目前的"矛盾检测"路线（README §4C）在 (2)(3) 之外完全依赖模块自己写漏——这是正确的主线，
但上面四类里目前**只碰了 (4) 的一半**。

---

## 2. 误报面

### 2.1 stock 设备（user 构建、未解锁、无 root）

| # | 检查项 / 级别 | 触发条件 | 依据 | 一条命令验证 |
|---|---|---|---|---|
| S1 | `spoof-cmdline` **HIGH**（→ROOT_DETECTED） | `/proc/cmdline` 里没有 `androidboot.*`（Android 12+/GKI bootconfig 设备）。`checked>=3 && mismatch*2>checked` 的多数规则在这种情况下是 10/10 全中，规则失效 | `rd_kernel.c:457`（读 cmdline）、`rd_kernel.c:488`（多数规则）；brief §5.7 L173；grep `bootconfig` in `src/`=0 | `adb shell 'grep -c androidboot /proc/cmdline; cat /proc/bootconfig 2>/dev/null \| grep -c androidboot'` —— 若前者≈0 而后者>0，就是误报 |
| S2 | `proc-injected-lib` **HIGH**（+`RD_F_ROOT`→ROOT_DETECTED） | `inj[]` 里的 `"gadget"`（`rd_checks.c:537-539`）命中**标准 USB gadget HAL** 的服务名/库名；进程自己的可执行文件在 maps 里也是一行 | `rd_checks.c:537-556`（`strstr(maps, "gadget")`，无边界校验） | `adb shell 'ls /vendor/bin/hw /vendor/lib64 /system/lib64 2>/dev/null \| grep -i gadget'`；`adb root; adb shell 'grep -il gadget /proc/[0-9]*/maps'`（域权限允许时） |
| S3 | `mount-overlay` **HIGH** | `root_dev` 只看**设备串**、不看挂载点（`rd_checks.c:456-459`）：任何 source 为 `overlay` 的 overlayfs 挂载（容器/WSL/部分 ROM）、或设备名含 `mirror`/`worker` 的挂载；另外 `full_partition && fs=="tmpfs"`（`rd_checks.c:453-455`）会命中"/ 由 ramdisk/tmpfs 提供"的镜像 | `rd_checks.c:448-459` | `adb shell "grep -E ' (overlay\|tmpfs) ' /proc/mounts"` —— 干净机上不该有输出 |
| S4 | `kernel-taint-oe` **MEDIUM**（→SUSPICIOUS） | 厂商模块设了 OE 位（bit12）。**【已修复】**级别已从 HIGH 降到 MEDIUM；残留是"纯 stock 机也可能拿不到 CLEAN" | `rd_kernel.c:150-155`；§11.5 第 8 行 | `adb shell cat /proc/sys/kernel/tainted`（4096=OE） |
| S5 | `package-roots` 级别退化 / `package-hidden` 不可达 | 非 root 下 `/data/data/<pkg>` 一定是 EACCES（`rd_checks.c:320` 的 `rd_path_exists` 用 `lstat`，返回 false），于是 listed 分支只给 **MEDIUM**（`rd_checks.c:326`），`package-hidden` 这条 CRITICAL（`rd_checks.c:330`）永远不可达；且没有任何 INFO 说明"该检查被降级"。README §4A（L77-78）声称 HIGH/CRITICAL | `rd_checks.c:317-335` | `adb shell 'ls -ld /data/data/com.topjohnwu.magisk; echo rc=$?'`（shell/app 期望 EACCES） |
| S6 | `unix-socket-roots` **HIGH** / `proc-cmdline` **MEDIUM** 可被**任意进程伪造** | `/proc/net/unix` 整行匹配关键字（`rd_extra.c:18-44`）；进程名同理（`rd_checks.c:518-531`）。任何应用把抽象 socket 命名为 `@magisk`、或把进程名取成关键字即可 | `rd_extra.c:19-43`、`rd_checks.c:526-531` | `adb shell 'ln -sf /nonexistent /data/local/tmp/su'` 是同一类"投毒"的更干净版本（见 S7） |
| S7 | `path-consistency-mismatch` **CRITICAL**（→HIDING_DETECTED） | 悬空符号链接：`statx`/`fstatat` 用 `AT_SYMLINK_NOFOLLOW`，`stat`/`access`/`open`(O_PATH 跟随) /`open_read`/`opendir` 都跟随 → 票箱分裂。语料里 `/data/local/tmp/su` 对 `shell` 可写（`rd_checks.c:19`） | `rd_util.c:556-560`、`562-570`、`631-657`、`rd_checks.c:212-225` | `adb shell 'ln -sf /nonexistent /data/local/tmp/su; /data/local/tmp/rx -q; rm -f /data/local/tmp/su'` → 期望 CLEAN，实测会 HIDING_DETECTED |
| S8 | `path-consistency-control` **CRITICAL** | 同上机制打**控制路径**：`/sdcard`（`rd_kernel.c:553`）在"用户无存储/未挂载"时是悬空链接 → 所有探针里只有 nofollow 类看得见 | `rd_kernel.c:549-575` + `rd_util.c:556-570` | `adb shell 'ls -l /sdcard; readlink -f /sdcard; ls -ld /storage/emulated/0'` |
| S9 | `mount-view-inconsistency` **CRITICAL** | `/proc/self` 与 `/proc/1` 处在不同 mount namespace（应用每应用命名空间、`su --mount-master`、容器）。README §8 L239 已承认这个局限，**但代码没有任何守卫**；同一个假设还在 `--selftest` 的守卫里，所以那种环境下 `--selftest` 会直接 FAIL | `rd_checks.c:399-410`、`474-504`；`rd_selftest.c:176-215`、`234-238` | `adb shell 'readlink /proc/self/ns/mnt; readlink /proc/1/ns/mnt'`（不同则需要人工复核） |
| S10 | `map-backing-hidden` **CRITICAL** | maps 行里的路径在**第一个空格处被截断**（`rd_extra.c:102-105`），只要"本体"落在带空格的目录里就会被判成"映射了看不见的文件" | `rd_extra.c:84-119`（尤其 102-105） | `adb shell 'mkdir -p "/data/local/tmp/my tools"; cp /data/local/tmp/rx "/data/local/tmp/my tools/rx"; "/data/local/tmp/my tools/rx" -q'` → 期望 CLEAN，实测 HIDING_DETECTED |
| S11 | `artefact-present` **HIGH** | `/sbin/su`（`/sbin`→`/system/bin` 的别名）或厂商预置的 `/vendor/bin/su`：userdebug 降级只匹配 `/system/` 前缀（`rd_checks.c:229`），别名/厂商副本绕过。**【部分已修复】**§11.5 修的是 `/system/xbin/su` 本身 | `rd_checks.c:208-235`（229）、`74-82` | `adb shell 'ls -l /sbin /sbin/su /system/bin/su /vendor/bin/su 2>&1'` |
| S12 | `deep-dmesg-hits` **CRITICAL** | dmesg 里出现 `busybox`：`deep_dmesg` 是**唯一**没过滤 busybox 的调用点（其它 5 处都过滤了） | `rd_kernel.c:684-689` vs `rd_checks.c:184`/`259`/`429`/`528`、`rd_extra.c:32` | `adb root; adb shell 'dmesg \| grep -i busybox'` |
| S13 | `hook-kprobe` **CRITICAL** | 厂商调试 kprobe/ftrace 命中 `kallsyms`/`sys_exit`/`s_show`/`m_show`/`newuname` 这些子串 | `rd_kernel.c:634-655`（`interesting` 判定在 640-643） | `adb root; adb shell 'cat /sys/kernel/debug/kprobes/list; head -20 /sys/kernel/tracing/enabled_functions'` |
| S14 | `spoof-property` **HIGH** | `check_buildprop_spoof` 比对**所有**"build.prop 与 getprop 都存在的 key"（`rd_kernel.c:584-611`）；任何 init 的合法运行时覆盖、手工改过的 build.prop、或 CRLF 结尾都会命中 | `rd_kernel.c:591-604` | `adb shell /data/local/tmp/rx -v \| sed -n '/spoof-property/,+4p'`（看它列出的 key 是否确属合法覆盖） |

### 2.2 常见定制 ROM / 非标准环境

| # | 触发条件 | 依据 | 备注 |
|---|---|---|---|
| C1 | `env-build` 的 MEDIUM **叠加**：`ro.boot.veritymode≠enforcing`、`ro.boot.flash.locked≠1`、`ro.build.tags≠release-keys`、`verifiedbootstate≠green` → verdict SUSPICIOUS（干净 ROM） | `rd_checks.c:149-164` | `adb shell getprop \| grep -E 'ro.boot.(veritymode\|flash.locked\|verifiedbootstate)\|ro.build.tags'` |
| C2 | `ro.boot.selinux=permissive` 或该属性缺失 → 视情况 MEDIUM | `rd_checks.c:161-162` | 属性缺失时 `continue`（`rd_checks.c:167`），不会报 |
| C3 | 使用 overlayfs/自研 init 的 ROM，或 source 名含 `mirror`/`worker` 的挂载 → `mount-overlay` HIGH | 同 S3 | `adb shell 'cat /proc/mounts'` |
| C4 | 带 32 位兼容层/容器/独立 mount ns → `mount-view-inconsistency` CRITICAL | 同 S9 | 需人工复核 |
| C5 | 手改过 build.prop 的 ROM → `spoof-property` HIGH | 同 S14 | 看 evidence 里的 key |
| C6 | 预装 KernelSU 系管理器的 ROM：**真阳性**，但要知道 `package-hidden`（CRITICAL）在非 root 下不可达（S5），只会有 MEDIUM/HIGH | `rd_checks.c:317-335` | 判定会被低估 |

### 2.3 可被非特权方**故意**触发的假阳性（对抗性投毒面）

这一类不是"误报"而是"检测器可被噪声淹没"，对一个以"区分干净与隐藏"为卖点的工具是实质威胁：

1. **悬空符号链接**（S7/S8）：`shell` 即可写 `/data/local/tmp`，一条 `ln -s` 就能把干净机变成
   `HIDING_DETECTED`。依据 `rd_util.c:556-570` + `rd_checks.c:19`。
2. **抽象 unix socket / 进程名**（S6）：任意已安装应用即可让 `unix-socket-roots`=HIGH、
   `proc-cmdline`=MEDIUM。依据 `rd_extra.c:19-43`、`rd_checks.c:526-531`。
3. **maps 路径带空格**（S10）：只要把产物放在带空格的目录里，`map-backing-hidden` 就自爆。
   依据 `rd_extra.c:102-105`。
4. 这三条合起来说明一个设计问题：**投票引擎没有"第二次确认"**——除了 `rd_row_inconsistent`
   的 `-1` 忽略规则（`rd_util.c:643-647`）之外，没有"同类证据要 ≥2 个独立视角"的要求。

### 2.4 与 README §11.5 的对照（避免把已修复的当新发现）

| §11.5 条目 | 状态 | 本次审查的残留面 |
|---|---|---|
| mountstats 字段索引 | **已修复**（`rd_checks.c:406-410`，自检 `rd_selftest.c:176-215`） | 残留：`collect_targets`（`rd_checks.c:351-385`）不校验行格式，任何"≥5 个 token 的非挂载行"都会贡献幽灵挂载点（如 NFS 的 per-op 统计块）。概率低，但修法很便宜 |
| 自检硬编码 Android 路径 | **已修复**（`rd_selftest.c:131-136`、241-245） | 残留：自检的 mount 守卫本身**假设同命名空间**（`rd_selftest.c:186-189`），见 S9 |
| `sys_call_table` 解析不到时静默 | **已修复**（`rd_kernel.c:302-311`） | 残留：32 位构建 + root 时**索引用错表**，见 §4-B2（不是"解析不到"，是"解析到了但比错"） |
| stat 可见/open 被 SELinux 拒当 open-redirect | **已修复**（`rd_kernel.c:517-521`） | 无 |
| `ro.secure`/`ro.debuggable` 方向写反 | **已修复**（`rd_checks.c:148-169` 的 `CMP_EQUAL`/`CMP_NOT_EQUAL`） | 无 |
| `/debug_ramdisk` 从语料移除 | **已修复**（`rd_checks.c:28-29`） | 注意 `/debug_ramdisk` 仍在**目录列举**列表里（`rd_checks.c:248`），这是有意的（列举只做关键字匹配），不构成误报 |
| `/system/xbin/su` 在 userdebug 降级 | **已修复**（`rd_checks.c:229`） | 残留：`/sbin/su`、`/vendor/bin/su` 等别名/厂商副本绕过前缀匹配，见 S11 |
| `kernel-taint-oe` 定级过高 | **已修复**（`rd_kernel.c:150-155`） | 见 S4 |
| `kernel-module-hidden` 把 `bpf` 当隐藏模块 | **已修复**（`rd_kernel.c:234-241`） | 残留：按名字 allowlist 天生脆弱（其它内核伪模块/别名），建议改成"标签集合 × `/sys/module`"的三视图判定 |
| `spoof-cmdline` 3/10 属性不来自 cmdline → HIGH | **已修复**（`rd_kernel.c:482-493` 多数规则） | **残留（新）**：设备整体改用 bootconfig 后，多数规则反转成误报，同时该检查抓不到真正的层，见 S1/§4-B4 |

---

## 3. 最值得加的 3 项（实现草案）

### 草案 A：supercall 正检测 → `susfs-supercall` / CRITICAL

- 位置：`rd_kernel.c`，新增 `static void check_supercall(rd_report *rep, int is_root)`，
  在 `rd_check_deep()`（`rd_kernel.c:699-729`）末尾调用（只有 uid 0 才有意义，见原理分析 §5.7a L179）。
- syscall：`syscall(__NR_reboot, 0xDEADBEEF, 0xFAFAFAFA, 0x555e2 /*SHOW_ENABLED_FEATURES*/, &payload)`。
  命令号来自原理分析 §6 L198-199；ABI 布局：`enabled_features` 结构 8196 字节、`err` 在偏移 8192
  （原理分析 §5.7a L181）。`err` 先写 126（"纯用户态哨兵"，原理分析 §6 L198）。
- 判定：`err == 0` 且 buffer 里能找到 `SUSFS` 标记（原理分析 §5.7a L181 说首行是 `SUSFS_LKM_MODULES`）
  → `rd_add_ev(SEV_CRITICAL, "susfs-supercall", ...)`，evidence 打印前 ~200 字节。
  `err == 126`/`EINVAL` → `SEV_INFO "supercall-unclaimed"`（说明"没有模块认领"）。
- 误报避免：① 只发**只读**命令（`SHOW_VERSION`/`SHOW_ENABLED_FEATURES`），绝不发
  `ADD_SUS_PATH`(0x55550)/`SET_UNAME`(0x55590)/`ADD_OPEN_REDIRECT`(0x555c0) 这类会改状态的；
  ② 必须 `err==0` **且** payload 有可识别标记，只满足一个就报 INFO；
  ③ 命令号在 KernelSU 内建 SUSFS 上同样有效（原理分析 §6 L198："预编译的 ksu_susfs 与 SukiSU
  的 ksud 绑定可以不加修改地驱动这个 LKM"），所以命中是"KernelSU/SUSFS 系"的真阳性，
  title 要写清楚是"supercall 被认领"，而不是断言具体某个模块。
- 验证：`adb shell 'su -c "/data/local/tmp/rx --json"' | grep susfs-supercall`。

### 草案 B：cmdline 层改为 `/proc/bootconfig` ∪ `/proc/cmdline` → 修 `spoof-cmdline`

- 位置：`rd_kernel.c:456-499` 的 `check_cmdline_spoof()`（函数体 456-499）。
- 做法：
  1. 先 `rd_slurp("/proc/bootconfig", NULL)`（Linux ≥5.8 + `CONFIG_BOOT_CONFIG`，Android 11+ GKI 起）；
     文件不存在 → 保持现在的单源模式，并 `SEV_INFO "bootconfig-unavailable"`。
  2. 把"某属性有来源"定义为：`strstr(cmdline, "androidboot.<sub>=")` **或**
     bootconfig 内出现 `androidboot.<sub>` 后跟可选空格与 `=`（`/proc/bootconfig` 的格式是
     `key = value`，键名带 `androidboot.` 前缀）。
  3. 现有多数规则（`rd_kernel.c:488`）保留，但只在**两个源都缺**时才计 mismatch；
     另加一条：`bootconfig` 存在且**一条 `androidboot.` 都没有**，而 `ro.boot.*` 有 ≥3 个
     → 新的 `spoof-bootconfig` HIGH（这正是模块"整段改写 `saved_boot_config`"的后果，
     依据 brief §5.7 L173）。
  4. `checked`/`mismatch` 的 INFO 文案里分别打印两个源的命中数，便于现场判断。
- 误报避免：保留 `rd_kernel.c:467-471` 的排除表（baseband/bootloader/hardware/radio/serialno）；
  `avb_version`/`bootreason`/`dynamic_partitions` 一类"非命令行来源"继续靠多数规则兜；
  两个源任一不可读时不升级级别。
- 验证（干净 Android 12+）：`adb shell 'cat /proc/bootconfig | head -30'`，
  确认 androidboot.* 在 bootconfig 里；此时不应再出现 HIGH `spoof-cmdline`。

### 草案 C：投票扩容 —— `statfs`/`listxattr` + `name_to_handle_at`

- 位置：`rd.h:136-140`（`rd_probe_row` 加 `statfs_r`、`xattr_r`、`handle_r`）、
  `rd_util.c:606-620`（`rd_probe_all`）、`rd_util.c:631-657`（`rd_row_inconsistent` 的 probes[]）、
  `rd_kernel.c:765-776`（`abi_fill`，顺带把新字段带进 ABI 差分）。
- 新探针：
  - `statfs(path,&s)` → 0 存在 / ENOENT→1 / 其它→-1。对应 sus_path 的 `sb_statfs` 出口（brief §5.1 L96）。
  - `syscall(__NR_listxattr, path, NULL, 0)` → 返回 0 即"存在且没有 xattr"（**存在**），
    ENOENT/ENOTDIR→1；`EOPNOTSUPP`/`ENOTSUP`→**-2（不投票）**；EACCES/EPERM→-1。
    对应 `inode_getxattr`/`_listxattr` 出口（brief §5.1 L96）。
  - `name_to_handle_at(AT_FDCWD, path, &fh, &mnt_id, 0)`：`fh.handle_bytes=0` 的标准用法
    → 存在则 `-1/EOVERFLOW`（并在 `handle_bytes` 里回填所需长度），不存在则 ENOENT，
    `EOPNOTSUPP`→-2；拿到 handle 后按 `fh.handle_type` 解码 ino（`FILEID_INO32_GEN=1`、
    `_PARENT=2`：前 4 字节小端 ino），与 `stat().st_ino` 比对。
    为什么它能穿过 sus_path：`name_to_handle_at` 的路径解析只对**中间目录**调
    `inode_permission`，最后一级不做权限检查，所以对"父目录可搜索的普通文件"仍然成功
    （对隐藏的**目录**会失败——这一点必须在实现时接受，不要因此把 ENOENT 当证据）。
- 新 id：
  - 扩展 `path-consistency-mismatch`（CRITICAL）：`statfs`/`listxattr` 与 stat 家族分裂。
  - `path-handle-ino-mismatch` **HIGH**：handle 里的 ino ≠ `st_ino`（kstat 改 statbuf 时
    handle 仍用 `i_ino`，原理分析 §5.5 L136-137 只改 `KSTAT_SPOOF_*` 标记的字段）。
  - `path-handle-visible` **CRITICAL**：`stat`=ENOENT 但 handle 存在（sus_path 只覆盖路径层）。
- 误报避免（关键）：
  1. `EOPNOTSUPP/ENOTSUP` 一律 -2，绝不投"不存在"票（`/proc`、`/sys`、devtmpfs 都会如此）；
  2. EACCES/EPERM 一律 -1（与 `rd_util.c:643-647` 的既有规则一致：blocked 不参与投票）；
  3. 新探针**单独**永远不能定性：沿用"至少两个视角一致"的要求，否则只报 LOW/INFO；
  4. handle 只在 `handle_type ∈ {1,2}` 且长度匹配时解码 ino，其它类型只做存在性判定。

### 附加（低成本、建议一起排期）

- **草案 D（直接喂给 t-abi）**：`rd_abi_probe_dump`（`rd_kernel.c:778-790`）目前每行只有 7 个
  布尔（`abi_fill` 765-776）。请把 `uname().release`、`statx` 的 `st_ino/st_dev/st_size`、
  以及 `/sbin`、`/data/adb` 的目录项 `(d_ino,d_name)` 摘要一起 dump，`abi_parse`（793-817）
  相应扩展。这样才能抓到 ABI 级的 kstat/uname/dirent 泄漏（§1.1 第 5/6/7 行）。
- **草案 E（dirent 直接痕迹）**：`d_ino==0` 的占位记录是真文件系统不会产生的
  （brief §5.2 L111）。在 `rd_checks.c` 加一个小函数，用原始 `getdents64` 扫
  `/sbin`、`/system/bin`、`/data/adb`，发现 `d_ino==0` → `dirent-placeholder` **CRITICAL**。
  误报避免：FUSE/NFS 类文件系统可能合法返回 0，先判 `statfs` 的 f_type 白名单（ext4/f2fs/erofs）；
  验证命令：`adb shell 'ls -ai /data/adb | awk "\$1==0"'`。

---

## 4. 源码逻辑 bug

> 按"后果严重度 × 可复现性"排序。每条都给了 file:line、为什么错、最小复现思路。
> 已对照 §11.5/§11.2，**没有一条是已修复项**（已修复项见 §2.4 的对照表）。

### B1【新】投票引擎混用 lstat 与 follow 语义 → CRITICAL 误报 + 可被投毒
- 依据：`rd_util.c:556-560`（`fstatat(AT_SYMLINK_NOFOLLOW)`）、`rd_util.c:562-570`
  （`statx(AT_SYMLINK_NOFOLLOW)`）、`rd_util.c:540-548`/`572-575`/`583-587`（都跟随）、
  汇总 `rd_util.c:631-657`、触发点 `rd_checks.c:212-225`。
- 为什么错：票箱要求"有些人看见、有些人看不见"才算矛盾（`rd_util.c:647`），但
  "符号链接本身存在"和"链接目标存在"是两个不同问题；悬空链接天然制造 2:5 的分裂。
- 最小复现：`adb shell 'ln -sf /nonexistent /data/local/tmp/su; /data/local/tmp/rx -q'`
  → `HIDING_DETECTED`（干净机）。`/sdcard`（`rd_kernel.c:553`）在无存储用户上是同一形态。
- 修法：把"只有 nofollow 类探针可见"单独判定为 `artefact-dangling-symlink`（LOW/MEDIUM，
  因为"语料路径上有个叫 su 的悬空链接"本身可疑但远不到 CRITICAL），或把票箱拆成
  follow-only / nofollow-only 两组各自判一致，再交叉比"链接目标视角"。

### B2【新】32 位构建 + root 时按 32 位 syscall 号读**native** `sys_call_table` → CRITICAL 误报
- 依据：`rd_kernel.c:290-321`（尤其 293-301 的 `#ifndef __NR_openat` 兜底、
  314 的 `kcore_read(sct + __NR_openat*8, ...)`、316-321 的比对）。
- 为什么错：`ksym_find` 找的是 `sys_call_table` 与 `__arm64_sys_openat`/`__x64_sys_openat`
  （native 表与 native 符号），而 `__NR_openat` 是**本进程 ABI**的号：arm64=56、
  **arm(32)=322**、x86_64=257、**i386=295**。32 位进程读 native 表的第 322/295 项
  （那里是 `execveat`/`preadv`），必然 ≠ `__arm64_sys_openat` → `kernel-syscall-table-patched`
  **CRITICAL**。而 293-301 的兜底分支把"其它架构"写死成 56，也是错的（虽然因
  `sys/syscall.h` 已定义 `__NR_openat` 而成为死代码）。
- 可达路径：`rootdetect-arm`/`rootdetect-x86` 以 uid 0 正常运行（例如 `su -c /data/local/tmp/rx32`）
  就会命中；`--probe-dump` 助手模式不会（它不跑检查）。
- 最小复现：`adb shell 'su -c "/data/local/tmp/rx32"'`（32 位产物，arm64 内核）→ 期望
  无 CRITICAL，实际报 `kernel-syscall-table-patched`。
- 修法：`if (sizeof(void*) != 8) skip`（或改成读 `compat_sys_call_table` 并用 compat 号、
  比对 compat 符号），并删掉写死 56 的兜底；`kernel-syscall-table-skipped`/新 INFO 说明原因。

### B3【新】maps 路径在第一个空格处截断 → `map-backing-hidden` CRITICAL 误报
- 依据：`rd_extra.c:102-105`（`snprintf(path,...,"%s",f); strchr(path,' ')` → 截断）、
  `rd_extra.c:116-119`（`stat_r==1 && open_read_r==1` → CRITICAL）。
- 为什么错：`/proc/<pid>/maps` 的 pathname 字段**不做转义**，带空格是合法的（内核只在末尾追加
  `" (deleted)"`）。截断后探测的是一个不存在的路径，于是"映射存在但文件看不见"。
- 最小复现：把产物放到带空格的目录再运行（只扫 `/proc/self/maps`，所以必须是本体的路径）：
  `adb shell 'mkdir -p "/data/local/tmp/my tools"; cp /data/local/tmp/rx "/data/local/tmp/my tools/rx"; "/data/local/tmp/my tools/rx" -q'`
  → HIDING_DETECTED。
- 修法：解析 maps 时把 `" (deleted)"` 之外的全部剩余内容当作路径（只在末尾匹配 `" (deleted)"`），
  不要按空格截断。

### B4【新】`spoof-cmdline` 读的是 `/proc/cmdline`，而该 LKM 改的是 `/proc/bootconfig`
- 依据：`rd_kernel.c:457`（`rd_slurp("/proc/cmdline")`）、`rd_kernel.c:488`（多数规则）；
  对抗方：brief §5.7 L173、原理分析 §5.7 L173（"被读的文件里没有 `/proc/cmdline` 的对应实现"）；
  `grep -r bootconfig src/` = 0 命中。
- 为什么错：①真正的 cmdline 层（改 `saved_boot_config`）完全抓不到 → README §4C L107 的
  "SuSFS cmdline 层只改 /proc/cmdline" 对**这个 LKM** 是错的；②设备整体用 bootconfig 后，
  `/proc/cmdline` 里没有 `androidboot.*`，多数规则反转成 HIGH 误报（见 S1）。
- 最小复现：`adb shell 'grep -c androidboot /proc/cmdline; cat /proc/bootconfig | grep -c androidboot'`
  —— 前者 0、后者 >0 的设备上运行工具 → `spoof-cmdline` HIGH。
- 修法：见 §3-草案 B。

### B5【新】`inj[]` 含 `"gadget"` → `proc-injected-lib` HIGH（并置 `RD_F_ROOT`）
- 依据：`rd_checks.c:537-539`（`inj[] = {"frida","gum-js","gadget",...}`）、
  540-556（`strstr(maps, inj[i])`，无词边界）；flag 表 `rd_util.c:145`。
- 为什么错：`gadget` 是标准 USB gadget HAL 的命名成分（服务/库文件名里都带），
  进程自己的可执行映像在 maps 里也有一行，于是纯 stock 设备被判"注入了用户态框架"。
- 最小复现：`adb shell 'ls /vendor/bin/hw /vendor/lib64 /system/lib64 2>/dev/null | grep -i gadget'`；
  在域权限允许读 `maps` 的环境（如 `adb root`）运行工具 → `proc-injected-lib` HIGH。
- 修法：把匹配改成"路径 basename 里的词边界/前缀匹配"（如 `libgadget*`、`frida-gadget*`），
  或直接去掉 `gadget` 只留 `frida`/`gum-js`。

### B6【新】`root_dev` 只看设备串、不看挂载点 → `mount-overlay` HIGH 误报
- 依据：`rd_checks.c:456-459`（`root_dev` 命中 `magisk|ksu|susfs|worker|mirror|overlay`），
  与 `partition_overlay`（453-455，要求 `full_partition`）是 **OR** 关系。
- 为什么错：overlayfs 的 `source` 字面就是 `overlay`；任何 overlayfs 挂载（容器/WSL/部分 ROM）
  都命中，即使挂载点与 system 分区无关。设计注释（`rd_checks.c:451-452`）说明作者想避开
  "tmpfs 挂在 /system 下面"的误报，但 `root_dev` 这条绕过了那个限定。
- 最小复现：`adb shell "grep -E ' (overlay|tmpfs) ' /proc/mounts"` 有输出 → 工具报 HIGH。
- 修法：`root_dev` 也要求 `full_partition`（或要求挂载点落在
  `/`,`/system`,`/vendor`,`/product`,`/data/adb` 之一），并把 `overlay` 从设备串关键字里去掉。

### B7【新】mount 交叉视图：空视图被跳过、`/proc/1` 无命名空间守卫、行格式不校验
- 依据：`rd_checks.c:474-475`（`if (ns[i]==0 || ns[0]==0) continue;`）、
  `rd_checks.c:399-410`（4 个视图的选取）、`rd_checks.c:351-385`（`collect_targets` 不校验行）、
  `rd_checks.c:413-415`（只有 `/proc/mounts` 为空才有 INFO）。
- 为什么错：①把 `/proc/self/mountinfo` 变成空文件的隐藏**不会触发任何 finding**，
  而"部分过滤"反而触发 CRITICAL——隐藏方只要返回 0 字节就安全；②`/proc/1/mountinfo`
  与 self 不同命名空间时（应用命名空间、`su --mount-master`、容器）会稳定误报 CRITICAL，
  README §8 L239 已承认但没有代码守卫；③`collect_targets` 对非挂载行（如 NFS 的 per-op
  统计块，行内 token ≥5）也会取第 5 个 token 当挂载点。
- 最小复现：①`adb shell 'su --mount-master -c "/data/local/tmp/rx"'`（不同 ns）；
  ②在装了 NFS 挂载的机器上跑（WSL 可测）→ 幽灵挂载点 → CRITICAL。
- 修法：①先 `readlink("/proc/self/ns/mnt")` vs `/proc/1/ns/mnt`，不同则跳过/降级 `/proc/1`
  并报 INFO；②self 视图为空而另一个 self 视图非空 → 直接报 CRITICAL（这是"过滤掉的证据"）；
  ③`collect_targets` 只接受以数字开头的行（mountinfo）/ 以 `device ` 开头的行（mountstats）。

### B8【新】cmdline 的 NUL→空格循环是空操作 → 只看得到 argv[0]
- 依据：`rd_checks.c:522-525`：
  ```c
  char cmd[1024];
  if (!rd_read_small(path, cmd, sizeof(cmd))) return;
  for (size_t i = 0; i < sizeof(cmd) && cmd[i]; i++)
    if (cmd[i] == '\0') cmd[i] = ' ';
  ```
- 为什么错：循环条件在**第一个 NUL 处就退出**，而那个 NUL 正是它想替换的分隔符 →
  一次也不会执行。后果：`cmd` 只含 argv[0]，`proc-cmdline` 的关键字只扫第一个参数，
  evidence 也只打印第一个参数。
- 最小复现：`adb shell 'cat /proc/self/cmdline | tr "\0" " "'` 与工具打印的 evidence 对比。
- 修法：让 `rd_read_small` 回传读取长度（`rd_util.c:319-330` 目前只回 bool），
  或在这里用 `memchr` 扫到 `r` 个字节为止。

### B9【新】`package-*` 的级别取决于 `/data/data/<pkg>` 能否 stat，非 root 下恒降级且无提示
- 依据：`rd_checks.c:317-320`（`rd_path_exists` 走 `lstat`）、326（listed→**MEDIUM**）、
  330（hidden→CRITICAL）、341-343（只在"既没 hit 也没 hidden"时输出 `package-clean`）。
- 为什么错：`shell`/app 域下 `/data/data/<pkg>` 恒 EACCES → `data_dir` 永远 false →
  ①README §4A 承诺的 `package-roots` HIGH 变成 MEDIUM（verdict 从 ROOT_DETECTED 变成 SUSPICIOUS）；
  ②`package-hidden`（KernelSU"隐藏应用"的**确定性特征**，README §4A L78）不可达；
  ③没有任何 INFO 说"这个检查因为权限被降级了"，使用者会以为它跑过了。
- 最小复现：`adb shell 'ls -ld /data/data/com.topjohnwu.magisk; echo rc=$?'`（期望 EACCES）；
  然后以 shell 身份运行工具，看 `package-roots` 的措辞是 "…(no reachable data dir)"。
- 修法：把 data_dir 探测的失败原因区分开（EACCES≠ENOENT），EACCES 时输出
  `package-hidden-skipped` INFO 并保持 listed→HIGH；或在 root 模式下才启用 data_dir 分支。

### B10【新】`find_push` 在 `realloc` 前就改了 `cap` → OOM 时越界写
- 依据：`rd_util.c:62-69`：
  ```c
  if (r->n == r->cap) {
    r->cap *= 2;
    rd_finding *ni = realloc(r->items, r->cap * sizeof(rd_finding));
    if (!ni) return NULL;
    ...
  }
  rd_finding *f = &r->items[r->n++];
  ```
- 为什么错：realloc 失败后 `r->cap` 已是新值、`r->items` 还是旧块；下一次 `r->n != r->cap`
  于是跳过 realloc，直接写 `r->items[r->n]`（超出旧的 `cap`）→ 堆越界写。
- 最小复现：把 `cap` 起始值改小（例如 2）并让分配失败（或注入 fault），或静态审计；
  正常路径不会触发（只影响 OOM 分支）。
- 修法：先算 `newcap`，realloc 成功后再赋值 `r->cap`；失败即返回。

### B11【新】`deep_dmesg` 是唯一不过滤 `busybox` 的调用点 → CRITICAL 误报
- 依据：`rd_kernel.c:684-689`（`has_kw(line,...)` 后直接计数），对比
  `rd_checks.c:184`/`259`/`429`/`528`、`rd_extra.c:32` 都显式跳过 `busybox`。
- 为什么错：`busybox` 在 RD_KEYWORDS 里（`rd_util.c:505`）是为了路径/文件名场景，但
  "dmesg 里提到 busybox"不足以证明加载了隐藏框架；不一致的过滤策略说明这是个遗漏。
- 最小复现：`adb root; adb shell 'dmesg | grep -i busybox'` 有输出时运行工具（root）→
  `deep-dmesg-hits` CRITICAL → HIDING_DETECTED。
- 修法：与其它调用点一致地跳过 `busybox`（或给它单独的 LOW 项）。

### B12【新】ABI 差分把 `blocked(-1)` 当差异 → 与自家投票规则矛盾，CRITICAL 误报
- 依据：`rd_kernel.c:900-905`（`if (lr->r[f] != remote[i].r[f]) any = true;` → 922-928 CRITICAL），
  对比 `rd_util.c:643-647`（投票引擎明确忽略 `-1`：blocked 不是"不存在"的证据）。
- 为什么错：同一个"探针不可用"状态，一个引擎当作噪声、另一个当作矛盾。两个 ABI 的
  SELinux 域/seccomp 过滤器可能不同（Android 的 32 位应用域 `untrusted_app_25` 与 64 位域不同；
  继承的 seccomp 过滤器是按 ABI 编号的），一个探针在一侧 -1、另一侧 0/1 完全可能，
  于是 `abi-consistency-mismatch` CRITICAL 会在干净设备上出现。
- 最小复现：`adb shell 'ROOTDETECT_ABI_HELPER=/data/local/tmp/rx32 /data/local/tmp/rx -v'`，
  看 evidence 里是否出现 `xxx=blocked` 与另一侧 `exists/ENOENT` 成对的行。
- 修法：比对前两边都要求 `!= -1`；任一为 -1 则该字段不计入 `any`，并在 INFO 里统计
  "因 blocked 跳过的字段数"。

### B13【新】`rd_run` 输出写满后关管道 → 子进程 SIGPIPE → 被当成"不可读"
- 依据：`rd_util.c:385-405`（`if (n + 1 >= outsz) break;` 之后 `close(pfd[0])` 再 `waitpid`）、
  调用方 `rd_kernel.c:674-679`（`rc != 0 || !out[0]` → `deep-dmesg` "kernel log not readable"）。
- 为什么错：父进程停止读取后关闭读端，子进程（`dmesg`）继续写会拿到 SIGPIPE 而死，
  `WIFEXITED` 为假 → `rd_run` 返回 -1 → 上层把"输出超过 1MB"误报成"日志不可读"，
  于是最强的 `deep-dmesg-hits` 检查被静默跳过。
- 最小复现：在有 >1MiB dmesg 的设备（长 uptime）上 `su -c 'rx -v'`，看是否打印
  `deep-dmesg: kernel log not readable`，同时 `dmesg | wc -c` 明明可读。
- 修法：读满后继续 drain（丢弃）到 EOF 再 waitpid；或把"截断"与"不可读"分成两个 id。

### B14【新/小】语料里的幽灵路径与死标志
- `RD_HIDING_PATHS` 的 `/proc/susfs_uname`（`rd_checks.c:45`）不是该 LKM 创建的节点：
  brief §1 L10 与原理分析 §6 L201 列出的 8 个节点里没有它（`kstat|open_redirect|enable_log|
  avc_spoof|hide_modules|hide_mounts|path|opath`）。无害（多一次探针），但会让 README §4C
  "8 个 /proc/susfs_*" 的计数对不上，建议删掉或换成 `/proc/susfs_hide_mounts` 之外的其它真实节点。
- `rd_checks.c:116` 设的 `RD_F_ADBROOT` 会被 `rd_finalize()` 的 `r->flags = 0`（`rd_util.c:159`）
  清掉，而且 `src/` 内没有任何地方读它 → 死标志（JSON 输出里也没有 flags 字段）。

### B15【新/小】userdebug 降级只匹配 `/system/` 前缀 → 别名/厂商副本仍报 HIGH
- 依据：`rd_checks.c:229`（`rd_starts_with(p, "/system/")`）+ 语料 `rd_checks.c:17-19`/`32`。
- 为什么错：`/sbin` 在 Android 11+ 的部分 GKI 设备上是 `/system/bin` 的符号链接（用
  `ls -l /sbin` 现场确认），`/vendor/bin/su` 是
  厂商分区里的另一个副本；两者都不以 `/system/` 开头，于是同一份 userdebug `su` 通过别名
  仍然拿 HIGH → verdict ROOT_DETECTED。
- 最小复现：`adb shell 'ls -l /sbin; ls -l /sbin/su /system/bin/su /vendor/bin/su'`。
- 修法：降级判定基于**解析后**的路径（`realpath`）或以 `(/system|/sbin|/vendor|/system/xbin)`
  的白名单 + "该分区由 userdebug 构建自带"的判定；或干脆把 sev_for_artefact 的 `/su` 分支
  再分一层（"系统分区自带" vs "用户区/临时区"）。

---

## 附 A：本次审查用到的核对命令（全部只读）

```bash
# 行号核对（本地）
grep -n 'AT_SYMLINK_NOFOLLOW\|__NR_openat\|gadget\|inj\[\]\|"ksud"' android-rootdetect/src/*.c
grep -rn 'bootconfig' android-rootdetect/src/            # 期望 0 命中
grep -rn 'reboot\|name_to_handle\|listmount\|statmount' android-rootdetect/src/   # 期望 0 命中

# 设备侧（干净机，注意每条都会改动设备状态，请在临时目录里做并清理）
adb shell 'ln -sf /nonexistent /data/local/tmp/su; /data/local/tmp/rx -q; rm -f /data/local/tmp/su'
adb shell 'mkdir -p "/data/local/tmp/my tools"; cp /data/local/tmp/rx "/data/local/tmp/my tools/rx"; "/data/local/tmp/my tools/rx" -q'
adb shell 'grep -c androidboot /proc/cmdline; cat /proc/bootconfig 2>/dev/null | grep -c androidboot'
adb shell 'ls /vendor/bin/hw /vendor/lib64 /system/lib64 2>/dev/null | grep -i gadget'
adb shell "grep -E ' (overlay|tmpfs) ' /proc/mounts"
adb shell 'readlink /proc/self/ns/mnt; readlink /proc/1/ns/mnt'
adb shell 'ls -ld /data/data/com.topjohnwu.magisk; echo rc=$?'
adb shell 'su -c "/data/local/tmp/rx32"'        # B2：32 位 + root
adb root && adb shell 'dmesg | grep -ci busybox; cat /proc/sys/kernel/tainted'
```

## 附 B：我没有做的事

- 没有修改 `src/`、`build/`、`scripts/` 下任何文件；本目录下唯一新增文件是本报告。
- 没有构建，没有启动/连接模拟器（有队友在用）。
- 没有验证 §3 草案里的新 syscall 语义（`name_to_handle_at` 的 EOVERFLOW 用法、
  `listmount` 的 CAP_SYS_ADMIN 要求）在目标内核上的实际行为——这些必须在实现时
  用 `--selftest` 式的干净机守卫先确认，再允许它们影响 verdict。
