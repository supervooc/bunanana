/* rootdetect - user-space checks: build state, root artefacts, manager packages,
 * mount views and running processes. */
#include "rd.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* --------------------------------------------------------------- corpora */

const char *const RD_ROOT_PATHS[] = {
    /* classic superuser binaries */
    "/system/bin/su", "/system/xbin/su", "/system/sbin/su", "/sbin/su", "/su/bin/su",
    "/vendor/bin/su", "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
    "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su", "/data/local/tmp/su",
    "/cache/su", "/dev/su", "/data/su",
    /* Magisk / KernelSU / APatch layout */
    "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/magisk_simple",
    "/data/adb/ksu", "/data/adb/ksud", "/data/adb/modules", "/data/adb/post-fs-data.d",
    "/data/adb/service.d", "/data/adb/lspd", "/data/adb/ap", "/data/adb/apd",
    "/data/adb/susfs", "/data/adb/susfs4ksu",
    "/sbin/.magisk", "/dev/.magisk", "/dev/.magisk.unblock", "/cache/.magisk",
    "/cache/magisk.log", "/init.magisk.rc",
    /* /debug_ramdisk is deliberately absent: stock Android 11+ creates it, so
     * its existence alone proves nothing (Magisk merely reuses it). */
    "/system/etc/init/magisk", "/system/etc/init/kernelsu.rc", "/system/etc/init/susfs.rc",
    "/system/bin/ksud", "/system/bin/susfs", "/sbin/ksud", "/sbin/susfs",
    "/system/xbin/daemonsu", "/system/bin/daemonsu", "/system/app/Superuser.apk",
    "/system/app/SuperSU", "/system/etc/init.d/99SuperSUDaemon",
    "/data/local/tmp/magisk", "/data/local/tmp/ksud",
    /* generic toolboxes frequently shipped by root solutions */
    "/system/xbin/busybox", "/system/bin/busybox", "/system/xbin/sqlite3", "/system/xbin/tcpdump",
};
const size_t RD_ROOT_PATH_COUNT = sizeof(RD_ROOT_PATHS) / sizeof(RD_ROOT_PATHS[0]);

/* Paths that only exist when an *anti-detection* layer is present, or that the
 * layer has to intercept in order to hide anything at all. */
const char *const RD_HIDING_PATHS[] = {
    "/proc/susfs_path", "/proc/susfs_kstat", "/proc/susfs_open_redirect",
    "/proc/susfs_enable_log", "/proc/susfs_avc_spoof", "/proc/susfs_hide_modules",
    "/proc/susfs_hide_mounts", "/proc/susfs_opath", "/proc/susfs_uname",
    "/sys/module/susfs_guard_lkm", "/sys/module/susfs", "/sys/module/kernelsu",
    "/sys/module/kernel_umount", "/sys/module/ksu_guard", "/sys/module/shamiko",
    "/data/adb/susfs/config", "/data/adb/susfs/boot_completed",
};
const size_t RD_HIDING_PATH_COUNT = sizeof(RD_HIDING_PATHS) / sizeof(RD_HIDING_PATHS[0]);

/* Installer/loader layout of the susfs_guard_lkm LKM
 * (github.com/inforcqb/susfs4ksu-lkm). Kept out of the generic corpora so that
 * "a su binary exists" (which may predate rooting) and "this exact hiding LKM
 * is installed" stay distinguishable findings. Paths verified against the
 * project's module/customize.sh, module/load.sh, module/early-dispatch.sh,
 * tools/pack_module.py and README:
 *  - the flashable KernelSU module installs to /data/adb/modules/susfs_guard_lkm
 *    with lib/susfs_guard_lkm-<kmi>.ko, bin/susfs_insmod, module.prop
 *    (id=susfs_guard_lkm) and an optional early_load marker;
 *  - customize.sh also installs /data/adb/post-fs-data.d/00-susfs-guard-lkm.sh;
 *  - the manual route in the README loads /data/adb/loader/susfs_guard_lkm.ko
 *    (KernelSU: `ksud insmod`, otherwise the susfs_insmod loader).
 * The KMI-suffixed .ko names under .../lib are found by a directory scan in
 * rd_check_susfs_lkm(), not by this table, because the suffix is open-ended. */
const char *const RD_SUSFS_LKM_PATHS[] = {
    "/data/adb/modules/susfs_guard_lkm",
    "/data/adb/modules/susfs_guard_lkm/module.prop",
    "/data/adb/modules/susfs_guard_lkm/load.log",
    "/data/adb/modules/susfs_guard_lkm/early_load",
    "/data/adb/modules/susfs_guard_lkm/skip_mount",
    "/data/adb/modules/susfs_guard_lkm/bin/susfs_insmod",
    "/data/adb/modules/susfs_guard_lkm/kmi.sh",
    "/data/adb/modules_update/susfs_guard_lkm",
    "/data/adb/post-fs-data.d/00-susfs-guard-lkm.sh",
    "/data/adb/loader/susfs_guard_lkm.ko",
    "/data/adb/loader/susfs_insmod",
    "/data/local/tmp/susfs_guard_lkm.ko",
    "/data/local/tmp/susfs_insmod",
    "/sdcard/susfs_guard_lkm.ko",
};
const size_t RD_SUSFS_LKM_PATH_COUNT = sizeof(RD_SUSFS_LKM_PATHS) / sizeof(RD_SUSFS_LKM_PATHS[0]);

const char *const RD_ROOT_PACKAGES[] = {
    "com.topjohnwu.magisk", "io.github.huskydg.magisk", "io.github.vvb2060.magisk",
    "me.weishu.kernelsu", "com.rifsxd.ksunext", "me.bmax.apatch", "me.garfieldhan.apatch.next",
    "com.kingroot.kinguser", "com.kingo.root", "com.qihoo.root", "com.zhiqupk.root",
    "com.koushikdutta.superuser", "com.noshufou.android.su", "com.noshufou.android.su.elite",
    "eu.chainfire.supersu", "com.thirdparty.superuser", "com.yellowes.su", "me.phh.superuser",
    "com.alephzain.framaroot", "com.zachspong.temprootremovejb", "com.ramdroid.appquarantine",
    "com.devadvance.rootcloak", "com.devadvance.rootcloakplus", "com.formyhm.hideroot",
    "com.amphoras.hidemyroot", "com.notanumberone.rootcloak", "com.saurik.substrate",
    "org.lsposed.manager", "de.robv.android.xposed.installer", "org.meowcat.edxposed.manager",
    "com.solohsu.android.edxp.manager", "org.lsposed.lspatch", "com.tsng.mat",
};
const size_t RD_ROOT_PACKAGE_COUNT = sizeof(RD_ROOT_PACKAGES) / sizeof(RD_ROOT_PACKAGES[0]);

/* Single source of truth for "what looks like a root framework" lives in
 * rd_util.c (rd_has_keyword); keeping one list avoids the two halves of the
 * detector disagreeing about what is suspicious. */
static bool has_keyword_ci(const char *s, const char **which) {
  return rd_has_keyword(s, which);
}

/* Severity for finding a file/dir from the artefact corpus. */
static rd_sev sev_for_artefact(const char *path) {
  if (rd_contains(path, "busybox") || rd_contains(path, "sqlite3") || rd_contains(path, "tcpdump"))
    return SEV_LOW;
  if (rd_contains(path, "/su") || rd_contains(path, "su/")) return SEV_HIGH;
  if (rd_contains_ci(path, "magisk") || rd_contains_ci(path, "ksu") || rd_contains_ci(path, "susfs") ||
      rd_contains_ci(path, "lspd") || rd_contains_ci(path, "daemonsu") || rd_contains_ci(path, "apd"))
    return SEV_HIGH;
  return SEV_MEDIUM;
}

/* ------------------------------------------------------------ small helpers */

static void scan_dir(const char *dir, void (*cb)(const char *dir, const char *name, void *ud),
                     void *ud) {
  DIR *d = opendir(dir);
  if (!d) return;
  struct dirent *e;
  while ((e = readdir(d))) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
    cb(dir, e->d_name, ud);
  }
  closedir(d);
}

static bool read_first_line(const char *path, char *buf, size_t bufsz) {
  if (!rd_read_small(path, buf, bufsz)) return false;
  char *nl = strchr(buf, '\n');
  if (nl) *nl = '\0';
  rd_trim(buf);
  return true;
}

/* ------------------------------------------------------------------ context */

/* Running as root from a directory that others can write to means the binary
 * itself (or anything it loads) could have been replaced before this run, so a
 * correct report proves nothing. Same trust principle as abi_helper_trusted(). */
static void check_self_executable(rd_ctx *c, rd_report *rep) {
  if (!c->is_root) return;
  char self[512] = "", dir[512] = "";
  if (rd_read_link("/proc/self/exe", self, sizeof(self)) < 0) return;
  if (!rd_dir_writable_by_others(self, dir, sizeof(dir))) return;
  rd_add(rep, SEV_MEDIUM, "self-executable-in-writable-dir",
         "running as root from a directory that others can write to",
         "%s lives in %s, which is group/other writable, so another user could replace this "
         "binary before it runs and any verdict it prints would be meaningless. Run it from a "
         "root-only directory instead: adb root; mkdir -m 700 /data/local/rx; cp %s "
         "/data/local/rx/rx; chmod 755 /data/local/rx/rx; /data/local/rx/rx -v",
         self, dir[0] ? dir : "?", self);
}

void rd_check_environment(rd_ctx *c, rd_report *rep) {
  check_self_executable(c, rep);
  char buf[512];

  rd_add(rep, SEV_INFO, "env-context", "execution context",
         "uid=%d pid=%d abi=%s root_mode=%s", (int)c->uid, (int)c->pid, c->abi,
         c->is_root ? "yes" : "no");

  if (c->is_root) {
    rd_add(rep, SEV_INFO, "env-uid0", "running as uid 0",
           "An adb-root/su shell can see the raw kernel state; deep checks are enabled. "
           "Re-run as the `shell` user for the app-equivalent view.");
  }

  /* SELinux */
  if (read_first_line("/sys/fs/selinux/enforce", buf, sizeof(buf))) {
    if (strcmp(buf, "0") == 0)
      rd_add(rep, SEV_HIGH, "env-selinux-permissive", "SELinux is permissive",
             "/sys/fs/selinux/enforce=0 - mandatory access control is disabled, which is a "
             "standard step of rooting guides and lets root-hiding modules operate freely.");
    else
      rd_add(rep, SEV_INFO, "env-selinux", "SELinux enforcing", "enforce=%s", buf);
  } else {
    rd_add(rep, SEV_INFO, "env-selinux", "SELinux state unavailable",
           "could not read /sys/fs/selinux/enforce");
  }
  if (read_first_line("/proc/self/attr/current", buf, sizeof(buf))) {
    if (rd_contains(buf, ":su:") || rd_contains(buf, "magisk"))
      rd_add(rep, SEV_HIGH, "env-selinux-domain", "process runs in a root SELinux domain",
             "attr/current=%s", buf);
    else
      rd_add(rep, SEV_INFO, "env-selinux-domain", "SELinux domain", "%s", buf);
  }

  /* Build state - an unlocked/verifiable-boot-broken device is not root by
   * itself, but it is the precondition every root method needs. */
  /* Build state. The comparison direction matters: for ro.debuggable/ro.secure it
   * is the *presence* of a specific value that is suspicious, for the others any
   * deviation from the stock value is. Getting this backwards made a pristine
   * userdebug emulator report "adbd runs with a root shell" for ro.secure=1. */
  enum { CMP_EQUAL, CMP_NOT_EQUAL };
  const struct { const char *key; const char *val; int mode; rd_sev sev; const char *why; } build[] = {
      {"ro.debuggable", "1", CMP_EQUAL, SEV_HIGH, "debuggable build: `adb root` is available"},
      {"ro.secure", "0", CMP_EQUAL, SEV_HIGH, "adbd runs without the secure flag"},
      {"service.adb.root", "1", CMP_EQUAL, SEV_HIGH, "adbd is currently rooted"},
      {"ro.build.type", "user", CMP_NOT_EQUAL, SEV_MEDIUM, "non-user build (userdebug/eng)"},
      {"ro.boot.verifiedbootstate", "green", CMP_NOT_EQUAL, SEV_MEDIUM,
       "bootloader state is not `green`"},
      {"ro.boot.flash.locked", "1", CMP_NOT_EQUAL, SEV_MEDIUM, "bootloader is not locked"},
      {"ro.boot.vbmeta.device_state", "locked", CMP_NOT_EQUAL, SEV_MEDIUM,
       "vbmeta device state is not `locked`"},
      {"ro.boot.veritymode", "enforcing", CMP_NOT_EQUAL, SEV_MEDIUM,
       "dm-verity is not enforcing"},
      {"ro.boot.selinux", "enforcing", CMP_NOT_EQUAL, SEV_MEDIUM,
       "`ro.boot.selinux` is not enforcing"},
      {"ro.build.tags", "release-keys", CMP_NOT_EQUAL, SEV_LOW,
       "build is not signed with release-keys"},
  };
  for (size_t i = 0; i < sizeof(build) / sizeof(build[0]); i++) {
    const char *v = rd_prop(&c->props, build[i].key);
    /* An empty value means the property is not set on this build at all
     * (`getprop` prints "[]" for it). Comparing "" against the stock value
     * declared a deviation - e.g. ro.boot.veritymode is empty on devices whose
     * bootloader does not export it even though dm-verity is enforcing - and
     * turned a clean device into a MEDIUM. */
    if (!v || !*v) continue;
    bool bad = (build[i].mode == CMP_EQUAL) ? (strcmp(v, build[i].val) == 0)
                                           : (strcmp(v, build[i].val) != 0);
    if (bad)
      rd_add(rep, build[i].sev, "env-build", build[i].why, "%s=%s", build[i].key, v);
    else
      rd_add(rep, SEV_INFO, "env-build", "build state ok", "%s=%s", build[i].key, v);
  }

  /* Explicit identity properties: hiding modules are usually careful, but any
   * leftover naming a root framework is conclusive. */
  int prop_hits = 0;
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  for (size_t i = 0; i < c->props.n; i++) {
    const char *which = NULL;
    if (!has_keyword_ci(c->props.keys[i], &which)) continue;
    if (strcmp(which, "busybox") == 0) continue; /* property named busybox is not a thing */
    prop_hits++;
    if (strlen(ev) < sizeof(ev) - 128)
      rd_appendf(ev, sizeof(ev), "%s=%s\n", c->props.keys[i], c->props.vals[i]);
  }
  if (prop_hits)
    rd_add_ev(rep, SEV_HIGH, "env-prop-identity", "root framework identity exposed in properties",
              ev, "%d system properties name a root/hiding framework.", prop_hits);
}

/* ------------------------------------------------------------------- paths */

void rd_check_paths(rd_ctx *c, rd_report *rep) {
  int found = 0, inconsistent = 0, dangling = 0;
  rd_sev worst = SEV_LOW;
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  /* A userdebug/eng build ships /system/xbin/su on purpose - it is what makes
   * `adb root` work. On such a build that path is a consequence of the build
   * type (already reported by env-build), not independent evidence of rooting,
   * so it is downgraded instead of claiming HIGH. */
  const char *dbg = rd_prop(&c->props, "ro.debuggable");
  bool userdebug = dbg && strcmp(dbg, "1") == 0;

  for (size_t i = 0; i < RD_ROOT_PATH_COUNT; i++) {
    const char *p = RD_ROOT_PATHS[i];
    rd_probe_row row;
    rd_probe_all(p, &row);
    bool exists = row.stat_r == 0 || row.open_read_r == 0 || row.access_r == 0 ||
                  row.open_path_r == 0 || row.fstatat_r == 0 || row.statx_r == 0 ||
                  row.opendir_r == 0;
    char cons[256];
    if (rd_row_inconsistent(&row, cons, sizeof(cons))) {
      if (rd_is_dangling_symlink(p)) {
        /* Nofollow probes see it, follow probes do not - that is a dangling
         * symlink, not a kstat layer (review B1). */
        rd_add(rep, SEV_MEDIUM, "artefact-dangling-symlink",
               "root artefact path is a symlink to a missing target",
               "%s is a dangling symlink; the nofollow probes see it and the follow probes do "
               "not, which is not by itself evidence of hiding.", p);
        dangling++;
        continue;
      }
      inconsistent++;
      char line[512];
      rd_format_row(p, &row, line, sizeof(line));
      rd_add_ev(rep, SEV_CRITICAL, "path-consistency-mismatch",
                "syscall results disagree for a root artefact",
                line, "%s exists from one syscall and not from another: %s. A hide module "
                      "(kstat/sus_path layer) is intercepting a subset of the stat/getdents "
                      "interfaces for exactly this path.", p, cons);
    }
    if (exists) {
      found++;
      rd_sev s = sev_for_artefact(p);
      /* Only the stock su locations are legitimately shipped by a userdebug
       * build; the old "/system/" prefix also downgraded /system/bin/ksud,
       * /system/etc/init/magisk, ... which never ship on a stock image. */
      bool build_ships_su = strcmp(p, "/system/bin/su") == 0 || strcmp(p, "/system/xbin/su") == 0 ||
                            strcmp(p, "/system/sbin/su") == 0 || strcmp(p, "/sbin/su") == 0 ||
                            strcmp(p, "/vendor/bin/su") == 0;
      if (userdebug && s >= SEV_HIGH && build_ships_su) s = SEV_MEDIUM;
      if (s > worst) worst = s;
      char line[512];
      rd_format_row(p, &row, line, sizeof(line));
      if (strlen(ev) < sizeof(ev) - 600) rd_appendf(ev, sizeof(ev), "%s\n", line);
    }
  }
  if (found)
    rd_add_ev(rep, worst, "artefact-present", "root artefacts present on the filesystem", ev,
              "%d/%zu probed root artefact paths exist.", found, RD_ROOT_PATH_COUNT);
  else
    rd_add(rep, SEV_INFO, "artefact-absent", "no root artefacts found",
           "probed %zu known su/Magisk/KernelSU/SuSFS paths, none reachable.",
           RD_ROOT_PATH_COUNT);

  /* Directory listings: catches artefacts whose exact name we did not guess.
   * getdents64 is one of the interfaces hide modules intercept, so this is also
   * a useful cross-check against the stat-based result above. */
  static const char *const dirs[] = {"/sbin", "/system/xbin", "/system/bin", "/system/sbin",
                                     "/data/local/tmp", "/cache", "/debug_ramdisk", "/data/adb"};
  char list_ev[RD_MAXEVID];
  list_ev[0] = '\0';
  int list_hits = 0;
  for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
    DIR *d = opendir(dirs[i]);
    if (!d) continue;
    struct dirent *e;
    while ((e = readdir(d))) {
      const char *which = NULL;
      if (!has_keyword_ci(e->d_name, &which)) continue;
      if (strcmp(which, "busybox") == 0) continue;
      list_hits++;
      if (strlen(list_ev) < sizeof(list_ev) - 128)
        rd_appendf(list_ev, sizeof(list_ev), "%s/%s\n", dirs[i], e->d_name);
    }
    closedir(d);
  }
  if (list_hits)
    rd_add_ev(rep, SEV_HIGH, "artefact-listing", "root framework files visible in directories",
              list_ev, "%d entries matching root-framework names were listed.", list_hits);

  if (inconsistent == 0 && dangling == 0)
    rd_add(rep, SEV_INFO, "path-consistency", "artefact probes are self-consistent",
           "stat/statx/fstatat/access/open/openat/getdents agreed for all %zu artefacts.",
           RD_ROOT_PATH_COUNT);
  else if (inconsistent == 0)
    /* Do not claim agreement for paths that were deliberately excluded: a
     * dangling symlink made the probes disagree, so it must not be counted as
     * "self-consistent". */
    rd_add(rep, SEV_INFO, "path-consistency", "artefact probes agreed on the remaining paths",
           "%zu artefact path(s) were excluded as dangling symlinks (reported above); the other "
           "%zu agreed across stat/statx/fstatat/access/open/openat/getdents.",
           (size_t)dangling, RD_ROOT_PATH_COUNT - (size_t)dangling);
}

/* ---------------------------------------------------------------- packages */

/* 1 = the path exists, 0 = it does not, -1 = it exists but cannot be stat'ed
 * (EACCES/EPERM). The distinction matters: under SELinux a `shell` uid cannot
 * lstat another app's /data/data/<pkg>, and treating that "unknown" as "absent"
 * downgraded a listed root manager from HIGH to MEDIUM - and a MEDIUM does not
 * set a flag or drive the verdict, so the install was reported as CLEAN. */
static int rd_path_state(const char *path) {
  struct stat st;
  if (lstat(path, &st) == 0) return 1;
  if (errno == EACCES || errno == EPERM) return -1;
  return 0;
}

/* Data directory of `pkg` as seen by *this* user. /data/data is the user-0 view
 * (a symlink to /data/user/0), so probing it unconditionally made a root manager
 * installed in another profile look like a hidden install: a work-profile
 * process saw /data/data/<pkg> for the primary user and reported CRITICAL
 * package-hidden, and the mirror-image direction hid the real one. App uids are
 * user*100000 + appid, so the user id is a division away. */
static void current_user_data_dirs(const char *pkg, char *data, size_t dsz, char *user, size_t usz,
                                   bool *probe_data) {
  unsigned u = (unsigned)getuid() / 100000u;
  snprintf(data, dsz, "/data/data/%s", pkg);
  snprintf(user, usz, "/data/user/%u/%s", u, pkg);
  *probe_data = (u == 0);
}

void rd_check_packages(rd_ctx *c, rd_report *rep) {
  (void)c;
  char *out = (char *)malloc(1 << 21);
  if (!out) return;
  out[0] = '\0';
  int rc = -1;
  const char *cmd = "/system/bin/cmd";
  if (rd_path_exists(cmd)) {
    const char *argv[] = {cmd, "package", "list", "packages", NULL};
    rc = rd_run(argv, out, 1 << 21);
  }
  if (rc != 0 || !strstr(out, "package:")) {
    const char *pm = "/system/bin/pm";
    if (rd_path_exists(pm)) {
      const char *argv[] = {pm, "list", "packages", NULL};
      rc = rd_run(argv, out, 1 << 21);
    }
  }
  if (rc != 0 || !strstr(out, "package:")) {
    /* Enumeration failed. Returning with an INFO was a real detection hole: a root
     * manager hides its package by making `cmd package`/`pm` return nothing, so
     * exactly when the check mattered most it silently disappeared - and the
     * message promised a filesystem fallback that did not exist. Do the filesystem
     * half of the check anyway and report the failure itself. */
    rd_props props;
    rd_props_load(&props);
    const char *sdk = rd_prop(&props, "ro.build.version.sdk");
    bool is_android = sdk && *sdk;
    rd_props_free(&props);
    if (!is_android) {
      rd_add(rep, SEV_INFO, "package-enum", "package manager enumeration not applicable",
             "this is not an Android system (no ro.build.version.sdk), so the package-manager "
             "check cannot run here; the artefact probes cover the same filesystem paths.");
      free(out);
      return;
    }
    int data_dirs = 0;
    for (size_t i = 0; i < RD_ROOT_PACKAGE_COUNT; i++) {
      char dp[256], du[256];
      bool probe_dp;
      current_user_data_dirs(RD_ROOT_PACKAGES[i], dp, sizeof(dp), du, sizeof(du), &probe_dp);
      bool dp_seen = probe_dp && rd_path_exists(dp);
      if (!dp_seen && !rd_path_exists(du)) continue;
      data_dirs++;
      rd_add(rep, SEV_CRITICAL, "package-hidden",
             "root manager data dir exists while the package list is unavailable",
             "%s exists while `cmd package list packages` failed (rc=%d). A root manager that "
             "hides its own package commonly makes enumeration fail or return nothing, so the "
             "data directory is the evidence.", dp_seen ? dp : du, rc);
    }
    if (data_dirs)
      rd_add(rep, SEV_HIGH, "package-enum-blocked",
             "package enumeration failed while root artefacts are visible",
             "`cmd package list packages` failed (rc=%d) and %d known root manager data dir(s) "
             "exist. Blocking enumeration is itself a hiding technique, so this is reported "
             "instead of silently degrading.", rc, data_dirs);
    else
      rd_add(rep, SEV_MEDIUM, "package-enum-blocked", "package enumeration failed",
             "`cmd package list packages` and `pm list packages` both failed (rc=%d), so the "
             "package check could not run. Not proof of hiding, but a tampered package manager "
             "is one cause - cross-check with `pm list packages | wc -l`.", rc);
    free(out);
    return;
  }

  char ev[RD_MAXEVID];
  ev[0] = '\0';
  char unk[RD_MAXEVID];
  unk[0] = '\0';
  int hit = 0, hidden = 0, unknown = 0, definite = 0;
  /* Severity of the aggregate row follows the worst single hit: a name that is
   * only registered (no reachable data dir) is MEDIUM on its own, so the list
   * must not turn it into an "installed" HIGH. */
  rd_sev worst_hit = SEV_MEDIUM;
  for (size_t i = 0; i < RD_ROOT_PACKAGE_COUNT; i++) {
    const char *pkg = RD_ROOT_PACKAGES[i];
    bool listed = false;
    char needle[256];
    snprintf(needle, sizeof(needle), "package:%s", pkg);
    /* exact line match, not substring: com.foo.su must not match com.foo.superx */
    for (char *p = out; (p = strstr(p, needle)) != NULL; p += strlen(needle)) {
      char after = p[strlen(needle)];
      if (after == '\n' || after == '\r' || after == '\0') { listed = true; break; }
    }
    char dp[256], du[256];
    bool probe_dp;
    current_user_data_dirs(pkg, dp, sizeof(dp), du, sizeof(du), &probe_dp);
    int dsp = probe_dp ? rd_path_state(dp) : 0;
    int dsu = rd_path_state(du);
    bool data_dir = dsp == 1 || dsu == 1;
    bool data_unknown = dsp < 0 || dsu < 0;
    /* The path that carried the signal, so the evidence names the directory that
     * was actually probed (dp is the user-0 view and is not probed otherwise). */
    const char *seen = (dsp == 1) ? dp : du;
    if (data_dir || !data_unknown) definite++;
    if (listed && (data_dir || data_unknown)) {
      hit++;
      worst_hit = SEV_HIGH;
      rd_add(rep, SEV_HIGH, "package-roots", "root manager application installed", "%s", pkg);
    } else if (listed) {
      hit++;
      rd_add(rep, SEV_MEDIUM, "package-roots", "root manager package registered",
             "%s (no reachable data dir)", pkg);
    } else if (data_dir) {
      hidden++;
      rd_add(rep, SEV_CRITICAL, "package-hidden",
             "root manager data dir exists but the package is hidden from the package manager",
             "%s: %s exists yet `cmd package list packages` does not list it - the definitive "
             "signature of KernelSU's \"hide the app\" / Magisk DenyList-style renaming.",
             pkg, seen);
    } else if (data_unknown) {
      unknown++;
      if (strlen(unk) < sizeof(unk) - 64) rd_appendf(unk, sizeof(unk), "%s (%s)\n", pkg, du);
    }
    if (listed && strlen(ev) < sizeof(ev) - 64) rd_appendf(ev, sizeof(ev), "%s\n", pkg);
  }
  if (hit && ev[0])
    rd_add_ev(rep, worst_hit, "package-roots-list", "known root managers enumerated", ev,
              worst_hit == SEV_HIGH
                  ? "%d of %zu known root manager packages are installed."
                  : "%d of %zu known root manager packages are registered while their data "
                    "directory is not reachable from this uid.",
              hit, RD_ROOT_PACKAGE_COUNT);
  if (unknown) {
    /* The name is neither listed nor stat-able, so "package-clean" would have
     * been a false negative waiting to happen (a hidden manager whose data dir
     * this uid cannot stat looks exactly like an absent one). Report the
     * inconclusiveness instead.
     *
     * definite > 0 means at least one probed data path was determinable, so an
     * EACCES on these specific names stands out. When the whole data directory
     * is unsearchable every path returns EACCES and no EACCES is informative:
     * "hidden" and "absent" are indistinguishable without root, so that case
     * stays informational instead of pretending to be evidence. */
    if (definite)
      rd_add_ev(rep, SEV_MEDIUM, "package-unverifiable",
                "known root manager package(s) could not be verified", unk,
                "%d known root manager name(s) are neither listed nor readable: their data path "
                "returned EACCES although other paths in the same directory were readable, so a "
                "hidden install cannot be ruled out.", unknown);
    else
      rd_add_ev(rep, SEV_INFO, "package-unverifiable",
                "known root manager package(s) could not be verified", unk,
                "%d known root manager name(s) are neither listed nor readable: this uid cannot "
                "search the app data directory at all (every path returned EACCES), so a hidden "
                "install and an absent one look identical here - run as root for a definitive "
                "answer. A listed manager is reported by package-roots already.", unknown);
  }
  if (!hit && !hidden && !unknown)
    rd_add(rep, SEV_INFO, "package-clean", "no known root manager package",
           "checked %zu package names against the full package list.", RD_ROOT_PACKAGE_COUNT);
  free(out);
}

/* ------------------------------------------------------------------ mounts */

/* Collect the mount target field of every line. field: 1 for /proc/mounts,
 * 4 for mountinfo (0-based). */
static size_t collect_targets(const char *file, int field, char **out, size_t max, bool *truncated) {
  size_t n = 0;
  if (truncated) *truncated = false;
  char *txt = rd_slurp(file, NULL);
  if (!txt) return 0;
  char *save = NULL;
  for (char *line = strtok_r(txt, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    if (n >= max) {
      /* More lines than the caller can hold. Returning silently made a truncated
       * set look complete, and the difference between two differently truncated
       * views was reported as CRITICAL mount-view-inconsistency. */
      if (truncated) *truncated = true;
      break;
    }
    char *p = line;
    for (int f = 0; f < field; f++) {
      while (*p == ' ') p++;
      while (*p && *p != ' ') p++;
    }
    while (*p == ' ') p++;
    /* A mount target is always an absolute path. Requiring the leading '/' also
     * drops the bare-number tokens on filesystems whose show_stats appends
     * continuation lines (nfs_show_stats/cifs_show_stats), which used to become
     * phantom mount targets and a CRITICAL mount-view-inconsistency. */
    if (*p != '/') continue;
    char *end = p;
    while (*end && *end != ' ') end++;
    char saved = *end;
    *end = '\0';
    /* unescape the octal escapes mountinfo uses */
    char dec[512];
    size_t o = 0;
    for (char *q = p; *q && o + 1 < sizeof(dec); q++) {
      if (*q == '\\' && q[1] >= '0' && q[1] <= '7' && q[2] >= '0' && q[2] <= '7' && q[3] >= '0' && q[3] <= '7') {
        dec[o++] = (char)(((q[1] - '0') << 6) | ((q[2] - '0') << 3) | (q[3] - '0'));
        q += 3;
      } else {
        dec[o++] = *q;
      }
    }
    dec[o] = '\0';
    char *dup = strdup(dec);
    if (!dup) break; /* OOM: a NULL entry would reach set_has()'s strcmp() */
    out[n++] = dup;
    *end = saved;
  }
  free(txt);
  return n;
}

size_t rd_collect_mount_targets(const char *file, int field, char **out, size_t max) {
  return collect_targets(file, field, out, max, NULL);
}

static bool set_has(char **set, size_t n, const char *v) {
  for (size_t i = 0; i < n; i++)
    if (strcmp(set[i], v) == 0) return true;
  return false;
}

void rd_check_mounts(rd_ctx *c, rd_report *rep) {
  (void)c;
  static const char *const files[] = {"/proc/mounts", "/proc/self/mountinfo", "/proc/1/mountinfo",
                                      "/proc/self/mountstats"};
  enum { MAXX = 512 };
  char *sets[4][MAXX];
  size_t ns[4] = {0, 0, 0, 0};
  /* Index of the field holding the mount point differs per file:
   *   /proc/mounts          "dev MNT fstype opts 0 0"                    -> 1
   *   mountinfo (self, 1)   "id parent maj:min root MNT opts ..."        -> 4
   *   /proc/self/mountstats "device DEV mounted on MNT with fstype FST"  -> 4
   * Getting one of these wrong invents 30+ phantom mount points and turns a
   * clean device into HIDING_DETECTED - see the mountstats guard in --selftest. */
  const int field[4] = {1, 4, 4, 4};
  bool tr[4] = {false, false, false, false};
  for (int i = 0; i < 4; i++) ns[i] = collect_targets(files[i], field[i], sets[i], MAXX, &tr[i]);

  if (ns[0] == 0) {
    int peers = (ns[1] ? 1 : 0) + (ns[2] ? 1 : 0) + (ns[3] ? 1 : 0);
    if (peers)
      /* The primary view parsed to nothing while a peer view still lists mounts:
       * every cross-check below is then skipped, so the anomaly has to be
       * reported here instead of staying silent. */
      rd_add(rep, SEV_MEDIUM, "mount-view-empty",
             "/proc/mounts is empty while another mount view is not",
             "/proc/mounts parsed to 0 entries but /proc/self/mountinfo=%zu, /proc/1/mountinfo=%zu "
             "and /proc/self/mountstats=%zu list mounts: an emptied primary view defeats every "
             "cross-check.", ns[1], ns[2], ns[3]);
    else
      rd_add(rep, SEV_INFO, "mount-view", "mount views unavailable",
             "could not parse /proc/mounts - a hide module may be filtering it entirely, or the "
             "file is unreadable.");
  } else
    rd_add(rep, SEV_INFO, "mount-view", "mount views readable",
           "/proc/mounts=%zu /proc/self/mountinfo=%zu /proc/1/mountinfo=%zu /proc/self/mountstats=%zu entries",
           ns[0], ns[1], ns[2], ns[3]);

  /* A) known hiding mounts */
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int hits = 0;
  for (size_t i = 0; i < ns[0]; i++) {
    const char *t = sets[0][i];
    const char *which = NULL;
    if (!has_keyword_ci(t, &which)) continue;
    if (strcmp(which, "busybox") == 0) continue;
    hits++;
    if (strlen(ev) < sizeof(ev) - 128) rd_appendf(ev, sizeof(ev), "%s\n", t);
  }
  if (hits)
    rd_add_ev(rep, SEV_HIGH, "mount-roots", "mount point named after a root framework", ev,
              "%d live mount targets reference a root/hiding framework.", hits);

  /* B) overlay/tmpfs stacked over system partitions */
  char ov[RD_MAXEVID];
  ov[0] = '\0';
  int ovhits = 0;
  {
    char *txt = rd_slurp("/proc/mounts", NULL);
    if (txt) {
      char *save = NULL;
      for (char *line = strtok_r(txt, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char dev[256] = "", tgt[512] = "", fs[128] = "";
        if (sscanf(line, "%255s %511s %127s", dev, tgt, fs) != 3) continue;
        bool full_partition = strcmp(tgt, "/system") == 0 || strcmp(tgt, "/vendor") == 0 ||
                              strcmp(tgt, "/product") == 0 || strcmp(tgt, "/") == 0;
        /* A stack of tmpfs/overlay replacing a whole system partition is a root
         * framework. Deliberately NOT flagged: tmpfs mounts below /system
         * (e.g. /sbin, /dev), which are normal on Android 10+. */
        bool partition_overlay =
            full_partition && (rd_contains(fs, "overlay") || strcmp(fs, "tmpfs") == 0 ||
                               rd_contains(fs, "fuse"));
        bool root_dev = rd_contains_ci(dev, "magisk") || rd_contains_ci(dev, "ksu") ||
                        rd_contains_ci(dev, "susfs") || rd_contains_ci(dev, "worker") ||
                        rd_contains_ci(dev, "mirror") || rd_contains_ci(dev, "overlay");
        if (partition_overlay || (full_partition && root_dev)) {
          ovhits++;
          if (strlen(ov) < sizeof(ov) - 256) rd_appendf(ov, sizeof(ov), "%s\n", line);
        }
      }
      free(txt);
    }
  }
  if (ovhits)
    rd_add_ev(rep, SEV_HIGH, "mount-overlay", "system partition is overlaid by a hiding mount", ov,
              "%d overlay/tmpfs mounts cover system partitions.", ovhits);

  /* C) cross-view comparison: the mount hide hooks are wired per proc file
   * (show_vfsmnt / show_mountinfo / show_vfsstat). If one view lost entries the
   * other still has, something is filtering. */
  /* /proc/1/mountinfo is only a meaningful second view when init shares our
   * mount namespace. Per-app mount namespaces, `su --mount-master` and
   * containers make the two differ legitimately, which otherwise produced a
   * CRITICAL mount-view-inconsistency (-> HIDING_DETECTED) on a clean system. */
  char self_ns[64] = "", init_ns[64] = "";
  long self_n = rd_read_link("/proc/self/ns/mnt", self_ns, sizeof(self_ns));
  long init_n = rd_read_link("/proc/1/ns/mnt", init_ns, sizeof(init_ns));
  /* Three states, not two: a readlink() that fails (SELinux, a hide module that
   * filters /proc/1) is not the same thing as "init is in another namespace".
   * Collapsing both into !init_view_ok made a blocked readlink silently disable
   * the /proc/1/mountinfo cross-check while blaming a namespace difference. */
  int ns_state = (self_n <= 0 || init_n <= 0) ? -1 : (strcmp(self_ns, init_ns) == 0);
  int init_view_ok = (ns_state == 1);
  if (ns_state < 0)
    rd_add(rep, SEV_INFO, "mount-view-namespace",
           "cannot tell whether /proc/1 shares this mount namespace",
           "/proc/1/ns/mnt or /proc/self/ns/mnt is not readable from this domain, so "
           "/proc/1/mountinfo is not compared. This is not a statement about hiding - the "
           "cross-check simply cannot run here.");
  else if (!init_view_ok)
    rd_add(rep, SEV_INFO, "mount-view-namespace",
           "/proc/1 is in a different mount namespace",
           "init does not share this process's mount namespace, so /proc/1/mountinfo is not "
           "compared (a difference there would be normal, not hiding).");
  for (int i = 1; i < 4; i++) {
    if (ns[0] == 0) continue;
    if (i == 2 && !init_view_ok) continue;
    if (tr[0] || tr[i]) {
      /* One of the two sets hit the entry cap, so a difference between them can
       * be a truncation artefact rather than filtering. Say so instead of
       * emitting CRITICAL for a benign reason. */
      rd_add(rep, SEV_INFO, "mount-view-truncated",
             "mount view comparison skipped: entry cap reached",
             "%s cannot be compared with /proc/mounts because at least one of them lists more "
             "than %d mounts; the truncated sets would differ for a benign reason, so no "
             "cross-view verdict is issued.", files[i], (int)MAXX);
      continue;
    }
    if (ns[i] == 0) {
      /* An empty peer view while /proc/mounts has entries is anomalous: the
       * cheapest way to defeat a cross-check is to return an empty file, which
       * the old `ns[i] == 0 -> continue` skipped in silence. */
      rd_add(rep, SEV_MEDIUM, "mount-view-empty",
             "a kernel mount view returned no entries",
             "%s parsed to 0 mount targets while /proc/mounts has %zu: an emptied view is "
             "cheaper than a filtered one and conceals the same mounts.", files[i], ns[0]);
      continue;
    }
    size_t missing = 0;
    char miss[RD_MAXEVID];
    miss[0] = '\0';
    for (size_t k = 0; k < ns[0]; k++) {
      if (!set_has(sets[i], ns[i], sets[0][k])) {
        missing++;
        if (strlen(miss) < sizeof(miss) - 128) rd_appendf(miss, sizeof(miss), "%s\n", sets[0][k]);
      }
    }
    size_t extra = 0;
    char ext[1024];
    ext[0] = '\0';
    for (size_t k = 0; k < ns[i]; k++) {
      if (!set_has(sets[0], ns[0], sets[i][k])) {
        extra++;
        if (strlen(ext) < sizeof(ext) - 128) rd_appendf(ext, sizeof(ext), "%s\n", sets[i][k]);
      }
    }
    if (missing || extra) {
      /* Built with bounded appends: one snprintf() from miss (up to 2999 bytes)
       * plus ext could overflow RD_MAXEVID and was truncated by the compiler's
       * own analysis (-Wformat-truncation). rd_appendf() truncates safely. */
      char evidence[RD_MAXEVID];
      evidence[0] = '\0';
      rd_appendf(evidence, sizeof(evidence), "missing from %s (%zu):\n%s\n", files[i], missing, miss);
      rd_appendf(evidence, sizeof(evidence), "only in %s (%zu):\n%s", files[i], extra, ext);
      rd_add_ev(rep, SEV_CRITICAL, "mount-view-inconsistency",
                "the kernel mount views disagree with each other", evidence,
                "/proc/mounts and %s describe different mount tables (%zu vs %zu entries). "
                "A single hook cannot cover every proc file consistently, so this is direct "
                "evidence of mount-list filtering.", files[i], ns[0], ns[i]);
    }
  }

  for (int i = 0; i < 4; i++)
    for (size_t k = 0; k < ns[i]; k++) free(sets[i][k]);
}

/* --------------------------------------------------------------- processes */

typedef struct {
  rd_ctx *c;
  rd_report *rep;
  int count;
  int skipped;
} proc_scan_state;

/* Basename without modifying the source string. */
static const char *path_basename(const char *p) {
  const char *slash = strrchr(p, '/');
  return slash ? slash + 1 : p;
}

static void scan_one_proc(const char *pid, rd_ctx *c, rd_report *rep) {
  char path[512];
  snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
  size_t clen = 0;
  char *cmdbuf = rd_slurp(path, &clen);
  if (!cmdbuf) return;
  char cmd[1024];
  size_t cn = clen < sizeof(cmd) - 1 ? clen : sizeof(cmd) - 1;
  memcpy(cmd, cmdbuf, cn);
  cmd[cn] = '\0';
  char argv0[512];
  size_t a0 = 0;
  while (a0 < cn && cmd[a0] && a0 + 1 < sizeof(argv0)) {
    argv0[a0] = cmd[a0];
    a0++;
  }
  argv0[a0] = '\0';
  free(cmdbuf);
  /* /proc/<pid>/cmdline is NUL separated and the old loop tested cmd[i] in its
   * condition, so it stopped at the first NUL: "ksud"/"zygiskd" in argv[1..] was
   * invisible (review B8). */
  for (size_t i = 0; i < cn; i++)
    if (cmd[i] == '\0') cmd[i] = ' ';

  char self[32];
  snprintf(self, sizeof(self), "%d", (int)getpid());
  bool is_self = strcmp(pid, self) == 0;

  /* Identity evidence only: the executable and argv[0], never the arguments.
   * Matching the whole command line meant `pm install magisk.apk`, a `grep
   * magisk ...` or a script whose path contains a keyword reported SUSPICIOUS on
   * a clean device - argument text is chosen freely by any process and proves
   * nothing about what is running. */
  char exe[512] = "";
  snprintf(path, sizeof(path), "/proc/%s/exe", pid);
  long exe_n = rd_read_link(path, exe, sizeof(exe));
  const char *which = NULL;
  bool ident = false;
  if (exe_n > 0 && !rd_contains(exe, " (deleted)"))
    ident = has_keyword_ci(path_basename(exe), &which);
  if (!ident && argv0[0]) ident = has_keyword_ci(path_basename(argv0), &which);
  if (ident) {
    if (strcmp(which, "busybox") != 0)
      rd_add(rep, SEV_MEDIUM, "proc-cmdline",
             "process executable names a root framework",
             "pid %s: exe=%s argv0=%s", pid, exe_n > 0 ? exe : "?", argv0);
  } else if (!is_self && has_keyword_ci(cmd, &which) && strcmp(which, "busybox") != 0) {
    /* The name only appears in the arguments. Keep it visible - review B8 wanted
     * argv[1..] covered - but informational, because it is not identity. */
    rd_add(rep, SEV_INFO, "proc-cmdline-ref", "command line mentions a root framework",
           "pid %s: %s", pid, cmd);
  }

  /* maps: injected userspace frameworks (Frida, Zygisk, Riru, Xposed). Only an
   * executable, file backed mapping is code, and only the pathname field of the
   * row is matched: the old strstr() over the whole maps text fired on any path
   * that merely contained a keyword, so running the scanner from a directory
   * named "magisk" made a clean host report HIGH proc-injected-lib and
   * ROOT_DETECTED (reproduced). Our own mappings are covered by self-rwx. */
  if (is_self) return;
  snprintf(path, sizeof(path), "/proc/%s/maps", pid);
  char *maps = rd_slurp(path, NULL);
  if (!maps) return;
  static const char *const libs[] = {"gum-js", "libhook", "edxp"}; /* not in RD_KEYWORDS */
  char *save = NULL;
  for (char *line = strtok_r(maps, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    /* "<addr>-<addr> <perms> <offset> <dev> <inode> <pathname>" */
    char *f = line;
    while (*f && *f != ' ') f++;
    while (*f == ' ') f++;
    if (!(f[0] && f[1] && f[2] == 'x')) continue; /* only executable regions are code */
    for (int i = 0; i < 4; i++) {                  /* perms, offset, dev, inode */
      while (*f && *f != ' ') f++;
      while (*f == ' ') f++;
    }
    if (*f != '/') continue; /* anonymous, [vdso], [anon:...], memfd/ashmem */
    if (!has_keyword_ci(f, &which)) {
      which = NULL;
      for (size_t k = 0; k < sizeof(libs) / sizeof(libs[0]) && !which; k++)
        if (rd_contains_ci(f, libs[k])) which = libs[k];
      if (!which) continue;
    }
    rd_add(rep, SEV_HIGH, "proc-injected-lib", "injected userspace framework mapped in a process",
           "pid %s (%s) maps %s", pid, argv0[0] ? argv0 : "?", f);
  }
  free(maps);
  (void)c;
}

static void proc_dir_cb(const char *dir, const char *name, void *ud) {
  (void)dir;
  proc_scan_state *st = (proc_scan_state *)ud;
  for (const char *p = name; *p; p++)
    if (!isdigit((unsigned char)*p)) return;
  if (st->count >= 800) { /* safety cap */
    st->skipped++;
    return;
  }
  st->count++;
  scan_one_proc(name, st->c, st->rep);
}

void rd_check_processes(rd_ctx *c, rd_report *rep) {
  proc_scan_state st;
  st.c = c;
  st.rep = rep;
  st.count = 0;
  st.skipped = 0;
  scan_dir("/proc", proc_dir_cb, &st);
  if (st.skipped)
    /* Silently stopping at the cap meant the checks disappeared without a trace
     * on exactly the busy systems where a hiding daemon is most likely. */
    rd_add(rep, SEV_INFO, "proc-scan-limit", "process scan stopped at the entry cap",
           "%d /proc entries were not scanned (cap 800); root or hiding daemons outside that "
           "window are not examined by this pass.",
           st.skipped);

  /* Our own address space: with a static binary the only way to shadow these
   * checks is an inline hook or a kernel hook, so an unexpected rwx mapping is
   * worth reporting. */
  char *maps = rd_slurp("/proc/self/maps", NULL);
  if (maps) {
    char ev[RD_MAXEVID];
    ev[0] = '\0';
    int rwx = 0;
    char *save = NULL;
    for (char *line = strtok_r(maps, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
      if (strstr(line, "rwx")) {
        rwx++;
        if (strlen(ev) < sizeof(ev) - 256) rd_appendf(ev, sizeof(ev), "%s\n", line);
      }
    }
    if (rwx)
      rd_add_ev(rep, SEV_LOW, "self-rwx", "writable+executable mapping inside the detector itself",
                ev, "%d rwx regions exist in this process; expected only for JIT engines.", rwx);
    free(maps);
  }
}
