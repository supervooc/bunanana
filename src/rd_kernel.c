/* rootdetect - kernel-side and adversarial checks.
 *
 * The interesting part of this file is not "does /system/xbin/su exist". It is
 * the cross-view engine: hiding modules hook a *subset* of the kernel's
 * read-only interfaces (SuSFS installs a kstat dispatcher on the stat family, a
 * getdents hook, an uname kretprobe, mount-list hooks and per-path LSM rules),
 * and every interface they forget to cover becomes a detectable contradiction.
 */
#include "rd.h"

#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

/* ------------------------------------------------------------------ helpers */

/* Thin aliases for the shared helpers in rd_util.c, so the checks below read
 * naturally. */
static bool has_kw(const char *s, const char **which) { return rd_has_keyword(s, which); }
static bool read_first_line_public(const char *p, char *b, size_t s) {
  return rd_read_first_line(p, b, s);
}

/* Bounded copy that always NUL-terminates. Used in place of
 * snprintf(dst, n, "%s", src) so that a long source is truncated explicitly
 * instead of tripping the compiler's -Wformat-truncation analysis. */
static void rd_copy(char *dst, size_t n, const char *src) {
  if (n == 0) return;
  size_t l = strlen(src);
  if (l >= n) l = n - 1;
  memcpy(dst, src, l);
  dst[l] = '\0';
}

static const char *kptr_str(unsigned long long a, char *buf, size_t sz) {
  if (a == 0) { snprintf(buf, sz, "0 (kptr_restrict)"); return buf; }
  snprintf(buf, sz, "0x%llx", a);
  return buf;
}

typedef struct {
  char name[96];
  unsigned long long addr;
  char mod[64];
} ksym;

typedef struct {
  ksym *v;
  size_t n, cap;
} ksym_tab;

static void ksym_add(ksym_tab *t, const char *name, unsigned long long addr, const char *mod) {
  if (t->n == t->cap) {
    t->cap = t->cap ? t->cap * 2 : 512;
    t->v = (ksym *)realloc(t->v, t->cap * sizeof(ksym));
  }
  ksym *k = &t->v[t->n++];
  snprintf(k->name, sizeof(k->name), "%s", name);
  k->addr = addr;
  snprintf(k->mod, sizeof(k->mod), "%s", mod ? mod : "");
}

static unsigned long long ksym_find(const ksym_tab *t, const char *name) {
  for (size_t i = 0; i < t->n; i++)
    if (!t->v[i].mod[0] && strcmp(t->v[i].name, name) == 0) return t->v[i].addr;
  return 0;
}

/* Parse /proc/kallsyms into a table of the symbols we care about + every module
 * tag we see. `want` is a NULL terminated list of names. */
/* Parses one /proc/kallsyms line: "<addr> <type> <name> [module]". Returns false
 * when the line carries no address, type and name. The module tag is optional;
 * an unterminated "[" keeps the name and drops the module. Exposed so --selftest
 * can pin the malformed cases that used to be skipped. */
bool rd_parse_kallsyms_line(const char *line, unsigned long long *addr, char *name, size_t namesz,
                            char *mod, size_t modsz) {
  char addr_s[32] = "", type = '?', nm[256] = "", md[64] = "";
  if (!line || !*line) return false;
  if (sscanf(line, "%31s %c %255s %63s", addr_s, &type, nm, md) < 3) return false;
  /* The address must really be hex: "not a kallsyms line" would otherwise be
   * accepted with strtoull() returning 0. */
  if (!addr_s[0] || strspn(addr_s, "0123456789abcdefABCDEF") != strlen(addr_s)) return false;
  if (addr) *addr = strtoull(addr_s, NULL, 16);
  if (name && namesz) snprintf(name, namesz, "%s", nm);
  if (mod && modsz) {
    mod[0] = '\0';
    /* Only a closed "[module]" tag counts: an unterminated bracket is a
     * malformed line, not a module named "unterminated". */
    if (md[0] == '[') {
      char *e = strchr(md, ']');
      if (e) {
        *e = '\0';
        snprintf(mod, modsz, "%s", md + 1);
      }
    }
  }
  return true;
}

/* Parses the first field of a /proc/modules line ("<name> <size> <refcnt> ...").
 * Returns false for empty or blank lines and copies at most sz-1 bytes. Exposed
 * for the same reason as rd_parse_kallsyms_line(). */
bool rd_parse_proc_modules_line(const char *line, char *name, size_t sz) {
  if (!line) return false;
  const char *p = line;
  while (*p == ' ' || *p == '\t') p++;
  if (!*p) return false;
  size_t n = 0;
  while (p[n] && p[n] != ' ' && p[n] != '\t' && n + 1 < sz) n++;
  if (n == 0) return false;
  if (name && sz) { memcpy(name, p, n); name[n] = '\0'; }
  return true;
}

static ksym_tab *kallsyms_parse(const char *txt, const char *const *want) {
  ksym_tab *t = (ksym_tab *)calloc(1, sizeof(ksym_tab));
  char *copy = strdup(txt);
  if (!copy) { free(t); return NULL; }
  char *save = NULL;
  for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    char name[256] = "", mod[64] = "";
    unsigned long long addr = 0;
    if (!rd_parse_kallsyms_line(line, &addr, name, sizeof(name), mod, sizeof(mod))) continue;
    const char *modname = mod[0] ? mod : NULL;
    /* always record module tags once */
    if (modname) {
      bool seen = false;
      for (size_t i = 0; i < t->n; i++)
        if (t->v[i].mod[0] && strcmp(t->v[i].mod, modname) == 0) { seen = true; break; }
      if (!seen) ksym_add(t, name, addr, modname);
    }
    if (want) {
      for (int i = 0; want[i]; i++) {
        if (strcmp(name, want[i]) == 0) { ksym_add(t, name, addr, modname); break; }
      }
    }
  }
  free(copy);
  return t;
}

static void ksym_free(ksym_tab *t) {
  if (!t) return;
  free(t->v);
  free(t);
}

/* Read `len` bytes of kernel virtual memory `vaddr` through /proc/kcore.
 * Returns false when kcore is unavailable (SELinux denies it on most devices). */
static bool kcore_read(unsigned long long vaddr, void *out, size_t len) {
  int fd = open("/proc/kcore", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  Elf64_Ehdr eh;
  if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh) || memcmp(eh.e_ident, ELFMAG, 4) != 0 ||
      eh.e_ident[EI_CLASS] != ELFCLASS64) {
    close(fd);
    return false;
  }
  Elf64_Phdr *ph = (Elf64_Phdr *)malloc(sizeof(Elf64_Phdr) * (size_t)eh.e_phnum);
  if (!ph) { close(fd); return false; }
  bool ok = false;
  if (pread(fd, ph, sizeof(Elf64_Phdr) * (size_t)eh.e_phnum, (off_t)eh.e_phoff) ==
      (ssize_t)(sizeof(Elf64_Phdr) * (size_t)eh.e_phnum)) {
    for (int i = 0; i < eh.e_phnum; i++) {
      if (ph[i].p_type != PT_LOAD) continue;
      unsigned long long start = ph[i].p_vaddr;
      if (vaddr < start || vaddr + len > start + ph[i].p_memsz) continue;
      off_t off = (off_t)(ph[i].p_offset + (vaddr - start));
      if (pread(fd, out, len, off) == (ssize_t)len) ok = true;
      break;
    }
  }
  free(ph);
  close(fd);
  return ok;
}

/* ------------------------------------------------------------ kernel state */

void rd_check_kernel(rd_ctx *c, rd_report *rep) {
  char buf[512];

  /* --- taint flags: bit 12 (0x1000) is set by every out-of-tree module, which
   * is precisely what a root-hiding LKM is. --- */
  if (read_first_line_public("/proc/sys/kernel/tainted", buf, sizeof(buf))) {
    long t = strtol(buf, NULL, 10);
    if (t == 0)
      rd_add(rep, SEV_INFO, "kernel-taint", "kernel not tainted", "tainted=0");
    else {
      char ev[256];
      snprintf(ev, sizeof(ev), "tainted=%ld (0x%lx)", t, (unsigned long)t);
      if (t & 0x1000)
        rd_add_ev(rep, SEV_MEDIUM, "kernel-taint-oe", "out-of-tree kernel module loaded", ev,
                  "taint bit 12 (OE) is set: something was insmod'ed that does not ship with this "
                  "kernel - the normal state after loading a hiding LKM such as susfs_guard_lkm. "
                  "It is only a MEDIUM because stock devices that load vendor modules "
                  "(wlan.ko, ranchu/mac80211_hwsim on an emulator) set the same bit; the module "
                  "*names* and the syscall table are the decisive evidence.");
      else if (t & 1)
        rd_add_ev(rep, SEV_LOW, "kernel-taint", "kernel tainted by a proprietary module", ev,
                  "taint bit 0 (P): common on stock devices with vendor modules.");
      else
        rd_add_ev(rep, SEV_MEDIUM, "kernel-taint", "kernel is tainted", ev,
                  "a module/condition marked the kernel, which stock builds typically avoid.");
    }
  }

  /* --- /proc/modules and /sys/module --- */
  char mod_ev[RD_MAXEVID];
  mod_ev[0] = '\0';
  int mod_hits = 0, mod_count = 0;
  char *mods = rd_slurp("/proc/modules", NULL);
  char *mod_names[512];
  size_t n_mod_names = 0;
  if (mods) {
    char *save = NULL;
    for (char *line = strtok_r(mods, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
      char name[128] = "";
      if (!rd_parse_proc_modules_line(line, name, sizeof(name))) continue;
      mod_count++;
      if (n_mod_names < 512) mod_names[n_mod_names++] = strdup(name);
      const char *which = NULL;
      if (has_kw(name, &which)) {
        mod_hits++;
        if (strlen(mod_ev) < sizeof(mod_ev) - 256) rd_appendf(mod_ev, sizeof(mod_ev), "%s\n", line);
      }
    }
  }
  if (mod_hits)
    rd_add_ev(rep, SEV_HIGH, "kernel-module", "loaded kernel module names a root framework",
              mod_ev, "%d of %d loaded modules match a hiding-framework name.", mod_hits, mod_count);
  else
    rd_add(rep, SEV_INFO, "kernel-module", "no suspicious module name in /proc/modules",
           "%d modules listed.", mod_count);

  /* /sys/module: names matching a framework, and names whose sysfs node is
   * missing although the module is listed (sus_path only hides the nodes it was
   * told about). */
  char sys_ev[RD_MAXEVID];
  sys_ev[0] = '\0';
  int sys_hits = 0;
  DIR *d = opendir("/sys/module");
  char *sys_names[1024];
  size_t n_sys = 0;
  if (d) {
    struct dirent *e;
    while ((e = readdir(d))) {
      if (e->d_name[0] == '.') continue;
      if (n_sys < 1024) sys_names[n_sys++] = strdup(e->d_name);
      const char *which = NULL;
      if (has_kw(e->d_name, &which)) {
        sys_hits++;
        if (strlen(sys_ev) < sizeof(sys_ev) - 128) rd_appendf(sys_ev, sizeof(sys_ev), "%s\n", e->d_name);
      }
    }
    closedir(d);
  }
  if (sys_hits)
    rd_add_ev(rep, SEV_HIGH, "kernel-sysmodule", "kernel module visible under /sys/module", sys_ev,
              "%d /sys/module entries match a hiding-framework name.", sys_hits);

  /* --- module list cross-check via kallsyms tags ---
   * kallsyms annotates module symbols with [module]. A module that shows up
   * there but not in /proc/modules had its module list filtered. */
  const char *const want[] = {"sys_call_table", "compat_sys_call_table", "kallsyms_lookup_name",
                              "__x64_sys_openat", "__arm64_sys_openat", "__x64_sys_newuname",
                              "__arm64_sys_newuname", "__x64_sys_stat", "__arm64_sys_fstatat",
                              "__x64_sys_getdents64", "__arm64_sys_getdents64", NULL};
  char *ks = rd_slurp("/proc/kallsyms", NULL);
  ksym_tab *ktab = NULL;
  if (ks) {
    ktab = kallsyms_parse(ks, want);
    if (ktab) {
      char mod_ev2[RD_MAXEVID];
      mod_ev2[0] = '\0';
      int hidden_mod = 0, vis_mod = 0;
      for (size_t i = 0; i < ktab->n; i++) {
        if (!ktab->v[i].mod[0]) continue;
        /* The kernel attributes its built-in BPF symbols to a pseudo-module named
         * "bpf" that never appears in /proc/modules; skipping it avoids a false
         * positive on every device with CONFIG_BPF (verified on a pristine
         * emulator, where it was the only mismatch out of 41). */
        if (strcmp(ktab->v[i].mod, "bpf") == 0) continue;
        vis_mod++;
        bool listed = false;
        for (size_t k = 0; k < n_mod_names; k++)
          if (strcmp(mod_names[k], ktab->v[i].mod) == 0) { listed = true; break; }
        if (!listed) {
          hidden_mod++;
          if (strlen(mod_ev2) < sizeof(mod_ev2) - 128)
            rd_appendf(mod_ev2, sizeof(mod_ev2), "%s (symbol %s at %s)\n", ktab->v[i].mod,
                       ktab->v[i].name, kptr_str(ktab->v[i].addr, buf, sizeof(buf)));
        }
      }
      if (hidden_mod)
        rd_add_ev(rep, SEV_HIGH, "kernel-module-hidden",
                  "module symbols visible in kallsyms but the module is missing from /proc/modules",
                  mod_ev2,
                  "%d module name(s) appear in kallsyms yet are absent from the module list: the "
                  "lists are filtered independently and disagree.", hidden_mod);
      else
        rd_add(rep, SEV_INFO, "kernel-module-crosscheck",
               "module lists agree", "%d module(s) seen in kallsyms, all present in /proc/modules.",
               vis_mod);

      /* framework symbols still visible -> the symbol filter is not installed */
      char sym_ev[RD_MAXEVID];
      sym_ev[0] = '\0';
      int sym_hits = 0;
      char *save = NULL;
      char *kcp = strdup(ks);
      for (char *line = kcp ? strtok_r(kcp, "\n", &save) : NULL; line;
           line = strtok_r(NULL, "\n", &save)) {
        char addr_s[32], type, name[256], mod[64] = "";
        if (sscanf(line, "%31s %c %255s %63s", addr_s, &type, name, mod) < 3) continue;
        const char *which = NULL;
        if (has_kw(name, &which)) {
          sym_hits++;
          if (sym_hits <= 40 && strlen(sym_ev) < sizeof(sym_ev) - 128)
            rd_appendf(sym_ev, sizeof(sym_ev), "%s\n", line);
        }
      }
      free(kcp);
      if (sym_hits)
        rd_add_ev(rep, SEV_HIGH, "kernel-kallsyms-symbol",
                  "kernel symbol table still names root-framework symbols", sym_ev,
                  "%d /proc/kallsyms entries match a hiding framework; SuSFS's hide_syms layer "
                  "strips exactly these, so their presence means the symbol filter is off.",
                  sym_hits);

      /* sys_call_table sanity (root only: non-root sees zeroed addresses).
       * A 32-bit build must not index it: kallsyms exposes the native 64-bit
       * table, so the 32-bit syscall numbers (i386 openat=295, arm32=322) would
       * read an unrelated entry and invent a patched table (review B2). */
      if (c->is_root && sizeof(void *) != 8) {
        rd_add(rep, SEV_INFO, "kernel-syscall-table-skipped",
               "32-bit build: the native sys_call_table cannot be indexed safely",
               "Reported instead of a bogus kernel-syscall-table-patched finding.");
      } else if (c->is_root) {
        unsigned long long sct = ksym_find(ktab, "sys_call_table");
        unsigned long long openat = ksym_find(ktab, "__x64_sys_openat");
        if (!openat) openat = ksym_find(ktab, "__arm64_sys_openat");
#ifndef __NR_openat
#if defined(__x86_64__)
#define __NR_openat 257
#elif defined(__aarch64__)
#define __NR_openat 56
#else
#define __NR_openat 56
#endif
#endif
        if (!sct || !openat) {
          /* Never stay silent about the strongest check not running: a kernel
           * built without CONFIG_KALLSYMS_ALL omits data symbols, so
           * sys_call_table simply is not in the table. */
          rd_add(rep, SEV_INFO, "kernel-syscall-table-skipped",
                 "sys_call_table could not be verified",
                 "kallsyms did not resolve %s%s%s. A kernel built without CONFIG_KALLSYMS_ALL omits "
                 "data symbols; Android GKI kernels normally keep it enabled, so on a device this "
                 "check does run.", sct ? "" : "sys_call_table", (!sct && !openat) ? " and " : "",
                 openat ? "" : "the openat syscall symbol");
        } else {
          unsigned long long entry = 0;
          if (kcore_read(sct + (unsigned long long)__NR_openat * 8, &entry, 8)) {
            if (entry != openat)
              rd_add(rep, SEV_CRITICAL, "kernel-syscall-table-patched",
                     "sys_call_table entry does not point at the real syscall",
                     "sys_call_table[%d]=%s but kallsyms says the syscall is at %s - the table "
                     "was rewritten at runtime (SuSFS susfs_fp_hook / any syscall hook).",
                     __NR_openat, kptr_str(entry, buf, sizeof(buf)),
                     kptr_str(openat, buf, sizeof(buf)));
            else
              rd_add(rep, SEV_INFO, "kernel-syscall-table",
                     "sys_call_table[openat] matches kallsyms",
                     "verified through /proc/kcore: %s", kptr_str(entry, buf, sizeof(buf)));
          } else {
            rd_add(rep, SEV_INFO, "kernel-kcore", "/proc/kcore not readable",
                   "cannot verify sys_call_table contents from user space on this device.");
          }
        }
      }
    }
  } else {
    rd_add(rep, SEV_INFO, "kernel-kallsyms", "/proc/kallsyms unreadable",
           "SELinux blocks the symbol table for this domain; cross-checks skipped.");
  }
  free(ks);
  ksym_free(ktab);
  if (mods) free(mods);
  for (size_t i = 0; i < n_mod_names; i++) free(mod_names[i]);
  for (size_t i = 0; i < n_sys; i++) free(sys_names[i]);

  if (read_first_line_public("/proc/sys/kernel/kptr_restrict", buf, sizeof(buf)))
    rd_add(rep, SEV_INFO, "kernel-kptr", "kptr_restrict", "%s", buf);
}

/* ------------------------------------------------------------- SuSFS probes */

void rd_check_susfs(rd_ctx *c, rd_report *rep) {
  (void)c; /* the SuSFS probes are path/view based; uid only matters via rep/context */
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int inconsistent = 0, readable = 0;

  for (size_t i = 0; i < RD_HIDING_PATH_COUNT; i++) {
    const char *p = RD_HIDING_PATHS[i];
    rd_probe_row row;
    rd_probe_all(p, &row);
    char cons[256], line[512];
    if (rd_row_inconsistent(&row, cons, sizeof(cons))) {
      inconsistent++;
      rd_format_row(p, &row, line, sizeof(line));
      rd_add_ev(rep, SEV_CRITICAL, "susfs-node-inconsistency",
                "a hiding control node is visible to some syscalls only", line,
                "%s: %s. The node exists in the dentry tree but the path-hiding layer answers "
                "ENOENT on the other interfaces.", p, cons);
    }
    if (row.open_read_r == 0 || row.stat_r == 0) {
      readable++;
      char content[256] = "";
      if (row.open_read_r == 0) rd_read_small(p, content, sizeof(content));
      if (strlen(ev) < sizeof(ev) - 256)
        rd_appendf(ev, sizeof(ev), "%s%s%s\n", p, content[0] ? " = " : "",
                   content[0] ? content : "(present)");
    }
  }

  if (readable) {
    rd_add_ev(rep, SEV_CRITICAL, "susfs-node-present",
              "SuSFS control node reachable through the filesystem", ev,
              "%d of %zu SuSFS control paths exist; these nodes are registered by the "
              "susfs_guard_lkm module and hidden from every other process.",
              readable, RD_HIDING_PATH_COUNT);
  } else if (inconsistent) {
    /* already reported per path */
  } else {
    rd_add(rep, SEV_INFO, "susfs-node-absent", "no SuSFS control node reachable",
           "all %zu paths answered ENOENT. Note this is also what a non-root process sees when "
           "SuSFS hides them, so absence alone is not evidence of a clean device.",
           RD_HIDING_PATH_COUNT);
  }

  /* SuSFS/LKM present at boot is also visible through the kernel command line. */
  char cmdline[4096];
  if (rd_read_small("/proc/cmdline", cmdline, sizeof(cmdline)) && cmdline[0]) {
    const char *which = NULL;
    if (has_kw(cmdline, &which))
      rd_add(rep, SEV_HIGH, "susfs-cmdline", "kernel command line names a hiding framework",
             "%s", cmdline);
  }
}

/* ------------------------------------------- susfs_guard_lkm LKM specifics
 *
 * Target: github.com/inforcqb/susfs4ksu-lkm - SUSFS ported to a loadable kernel
 * module (`susfs_guard_lkm`) so it can run on a stock GKI kernel, loaded with
 * `ksud insmod` or the release's own susfs_insmod loader.
 *
 * The checks below lean on statements the project makes about itself, not on
 * string luck:
 *  - susfs_main.c's load banner: "This module is filtered out of /proc/modules
 *    for every caller including root, so `lsmod | grep susfs` stays empty -
 *    check /sys/module/susfs_guard_lkm instead." The sysfs directory, its
 *    parameter files and the kallsyms module tag are views that self-filter
 *    does NOT cover, so any of them answering while /proc/modules omits the
 *    module is the filter observed in the act.
 *  - module/load.sh uses `[ -d /sys/module/susfs_guard_lkm ]` as its own
 *    "already loaded" probe; the parameters expose_proc / fail_layer /
 *    opath_test / opath_dump are unique to this port.
 *  - susfs.h: the module name is the .ko file name; releases ship
 *    susfs_guard_lkm-<kmi>.ko, so name lookups here are prefix matches
 *    (susfs_guard_lkm, susfs_guard_lkm_android13_5_15, ...).
 *  - PROC_INTERFACES.md: hide_modules removes the module's own /proc/modules
 *    line only - another module's "used by" column would still name it.
 *  - PROC_INTERFACES.md documents the control-node bodies; the counter/table
 *    shapes are reproduced in rd_susfs_lkm_node_fingerprint().
 */

/* Module parameters this LKM declares (susfs_main.c, susfs_opath.c). Seeing
 * any of them under /sys/module/<name>/parameters/ identifies the port. */
static const char *const lkm_params[] = {"expose_proc", "fail_layer", "opath_test", "opath_dump"};

/* True for the module's sysfs/proc name: equal to the base name, or the name
 * the kernel derived from the .ko file name (dashes become underscores, so
 * susfs_guard_lkm-android13-5.15.ko loads as susfs_guard_lkm_android13_5_15). */
static bool lkm_name(const char *name) {
  size_t n = strlen(RD_SUSFS_LKM_MODULE);
  if (!name || strncmp(name, RD_SUSFS_LKM_MODULE, n) != 0) return false;
  char c = name[n];
  return c == '\0' || c == '_' || c == '-' || c == '.';
}

const char *rd_susfs_lkm_node_fingerprint(const char *path, const char *content) {
  static const struct {
    const char *path; /* the node whose documented body this describes */
    const char *a;    /* required substring */
    const char *b;    /* second required substring, or NULL */
    const char *what; /* short description for the evidence line */
  } t[] = {
      {"/proc/susfs_opath", "opath/", "nr=", "O_PATH wrapper self-test counters"},
      {"/proc/susfs_kstat", "maps: armed=", "stat nr ", "kstat dispatcher counters"},
      {"/proc/susfs_hide_modules", "hide_modules:", "names:", "module-list hide table"},
      {"/proc/susfs_open_redirect", "hooks: forward=", NULL, "open-redirect hook counters"},
      {"/proc/susfs_avc_spoof", "priv_app_sid=", NULL, "AVC audit spoof state"},
      {"/proc/susfs_hide_mounts", "prefixes:", NULL, "mount-hide prefix table"},
      {"/proc/susfs_path", "hide_from_apps=", NULL, "sus_path rule table"},
  };
  if (!path || !content) return NULL;
  for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
    if (strcmp(path, t[i].path) != 0) continue;
    if (!rd_contains(content, t[i].a)) return NULL;
    if (t[i].b && !rd_contains(content, t[i].b)) return NULL;
    return t[i].what;
  }
  return NULL;
}

/* Read the nodes this LKM registers and identify the port from the shape of
 * their bodies. In practice this needs uid 0: with rules armed the sus_path
 * layer answers ENOENT on every interface from anyone else. */
static void lkm_node_fingerprints(rd_report *rep) {
  static const char *const nodes[] = {
      "/proc/susfs_path",  "/proc/susfs_kstat",        "/proc/susfs_open_redirect",
      "/proc/susfs_opath", "/proc/susfs_hide_modules", "/proc/susfs_hide_mounts",
      "/proc/susfs_avc_spoof",
  };
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int hits = 0;
  for (size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
    /* O_NONBLOCK, like rd_read_small(): a node whose read handler blocks must
     * not be able to hang the scan. */
    int fd = open(nodes[i], O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) continue;
    char *txt = rd_slurp_fd(fd, NULL);
    close(fd);
    if (!txt) continue;
    const char *what = rd_susfs_lkm_node_fingerprint(nodes[i], txt);
    if (what) {
      hits++;
      char first[160];
      size_t n = 0;
      while (txt[n] && txt[n] != '\n' && n + 1 < sizeof(first)) n++;
      memcpy(first, txt, n);
      first[n] = '\0';
      if (strlen(ev) < sizeof(ev) - 300)
        rd_appendf(ev, sizeof(ev), "%s: %s\n  %s\n", nodes[i], what, first);
    }
    free(txt);
  }
  if (hits)
    rd_add_ev(rep, SEV_CRITICAL, "susfs-lkm-node-fingerprint",
              "control node bodies match the susfs_guard_lkm interface", ev,
              "%d /proc/susfs_* node(s) answered with the counter/table format this LKM port "
              "documents (stat dispatcher counters, O_PATH self-test, hide tables). The text "
              "identifies the port: these read handlers belong to the module itself.", hits);
}

/* Files this LKM has to keep on disk: the flashable KernelSU module unpacks to
 * /data/adb/modules/susfs_guard_lkm, and the README's manual route puts the .ko
 * under /data/adb/loader. /data/adb is 0700 root, so this half only sees
 * anything as uid 0 - which is what makes it a good after-the-fact check. */
static void lkm_artefacts(rd_report *rep) {
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  char hev[RD_MAXEVID];
  hev[0] = '\0';
  int found = 0, hidden = 0;

  for (size_t i = 0; i < RD_SUSFS_LKM_PATH_COUNT; i++) {
    const char *p = RD_SUSFS_LKM_PATHS[i];
    rd_probe_row row;
    rd_probe_all(p, &row);
    bool exists = row.stat_r == 0 || row.statx_r == 0 || row.fstatat_r == 0 || row.access_r == 0 ||
                  row.open_path_r == 0 || row.open_read_r == 0 || row.opendir_r == 0;
    if (rd_row_inconsistent(&row, NULL, 0) && !rd_is_dangling_symlink(p)) {
      hidden++;
      char line[512];
      rd_format_row(p, &row, line, sizeof(line));
      if (strlen(hev) < sizeof(hev) - 520) rd_appendf(hev, sizeof(hev), "%s\n", line);
    }
    if (exists) {
      found++;
      char line[512];
      rd_format_row(p, &row, line, sizeof(line));
      if (strlen(ev) < sizeof(ev) - 520) rd_appendf(ev, sizeof(ev), "%s\n", line);
    }
  }

  /* KernelSU module directories. The release zip's module id is
   * susfs_guard_lkm, but match on the id wherever it appears instead of the
   * folder name alone: a renamed install still carries the id in module.prop,
   * and the .ko files under lib/ keep the project's file name. */
  static const char *const bases[] = {"/data/adb/modules", "/data/adb/modules_update"};
  for (size_t b = 0; b < sizeof(bases) / sizeof(bases[0]); b++) {
    DIR *d = opendir(bases[b]);
    if (!d) continue;
    struct dirent *e;
    while ((e = readdir(d))) {
      if (e->d_name[0] == '.') continue;
      char dir[512], prop[600], lib[600];
      snprintf(dir, sizeof(dir), "%s/%s", bases[b], e->d_name);
      snprintf(prop, sizeof(prop), "%s/module.prop", dir);
      snprintf(lib, sizeof(lib), "%s/lib", dir);
      char *ptxt = rd_slurp(prop, NULL);
      bool hit = rd_contains_ci(e->d_name, RD_SUSFS_LKM_MODULE) ||
                 (ptxt && rd_contains_ci(ptxt, "id=" RD_SUSFS_LKM_MODULE));
      /* The loader binary and the packaged .ko set name the project directly. */
      char insmod[700];
      snprintf(insmod, sizeof(insmod), "%s/bin/susfs_insmod", dir);
      if (!hit && rd_path_exists(insmod)) hit = true;
      if (!hit) {
        DIR *ld = opendir(lib);
        if (ld) {
          struct dirent *le;
          while ((le = readdir(ld))) {
            if (le->d_name[0] != '.' && rd_contains_ci(le->d_name, RD_SUSFS_LKM_MODULE)) {
              hit = true;
              break;
            }
          }
          closedir(ld);
        }
      }
      if (!hit) {
        free(ptxt);
        continue;
      }
      found++;
      if (strlen(ev) < sizeof(ev) - 700) {
        rd_appendf(ev, sizeof(ev), "%s/\n", dir);
        if (ptxt) rd_appendf(ev, sizeof(ev), "%s", ptxt);
      }
      free(ptxt);
      DIR *ld = opendir(lib);
      if (ld) {
        struct dirent *le;
        while ((le = readdir(ld))) {
          if (le->d_name[0] == '.' || !rd_contains(le->d_name, ".ko")) continue;
          if (strlen(ev) < sizeof(ev) - 200) rd_appendf(ev, sizeof(ev), "%s/%s\n", lib, le->d_name);
        }
        closedir(ld);
      }
    }
    closedir(d);
  }

  /* The manual-load directory from the README (`ksud insmod
   * /data/adb/loader/susfs_guard_lkm.ko`) and the loader next to it. */
  DIR *ld = opendir("/data/adb/loader");
  if (ld) {
    struct dirent *e;
    while ((e = readdir(ld))) {
      if (e->d_name[0] == '.') continue;
      if (!rd_contains_ci(e->d_name, RD_SUSFS_LKM_MODULE) &&
          !rd_contains_ci(e->d_name, "susfs_insmod"))
        continue;
      found++;
      if (strlen(ev) < sizeof(ev) - 200) rd_appendf(ev, sizeof(ev), "/data/adb/loader/%s\n", e->d_name);
    }
    closedir(ld);
  }

  if (hidden)
    rd_add_ev(rep, SEV_CRITICAL, "susfs-lkm-artefact-hidden",
              "susfs_guard_lkm files exist for some interfaces only", hev,
              "%d LKM-specific path(s) answered differently depending on the interface used - "
              "the path-hiding layer intercepts only a subset of stat/getdents for these files.",
              hidden);
  if (found)
    rd_add_ev(rep, SEV_HIGH, "susfs-lkm-artefact",
              "susfs_guard_lkm installer artefacts exist on disk", ev,
              "%d path(s) from this LKM's install/loader layout exist. The .ko must stay on disk "
              "to be re-inserted at boot, so installer files survive hiding rules aimed at the "
              "running kernel.", found);
  else
    rd_add(rep, SEV_INFO, "susfs-lkm-artefact-absent", "no susfs_guard_lkm installer file found",
           "probed %zu LKM-specific paths plus the KernelSU module and loader directories; "
           "nothing matched. /data/adb is unreadable to non-root, so this proves nothing "
           "without uid 0.",
           RD_SUSFS_LKM_PATH_COUNT);
}

void rd_check_susfs_lkm(rd_ctx *c, rd_report *rep) {
  (void)c; /* uid only changes which views are reachable; absence is documented */
  char buf[128];

  /* ---- view A: /proc/modules, the view the module filters ---- */
  bool mods_readable = false, in_modules = false;
  int mod_count = 0, usedby_hits = 0;
  char modline[512] = "";
  char usedby[RD_MAXEVID];
  usedby[0] = '\0';
  char *mods = rd_slurp("/proc/modules", NULL);
  if (mods) {
    mods_readable = true;
    char *save = NULL;
    for (char *line = strtok_r(mods, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
      char name[128] = "";
      if (!rd_parse_proc_modules_line(line, name, sizeof(name))) continue;
      mod_count++;
      if (lkm_name(name)) {
        in_modules = true;
        rd_copy(modline, sizeof(modline), line);
        continue;
      }
      /* hide_modules removes the module's own line only: a dependent module's
       * "used by" column (or any other column) still names it. */
      if (rd_contains_ci(line, "susfs")) {
        usedby_hits++;
        if (strlen(usedby) < sizeof(usedby) - 512) rd_appendf(usedby, sizeof(usedby), "%s\n", line);
      }
    }
  }

  /* ---- view B: /sys/module, the signal the module's own loader uses ---- */
  bool sysfs = false;
  char sysname[128] = "";
  char sysline[512] = "";
  DIR *sm = opendir("/sys/module");
  if (sm) {
    struct dirent *e;
    while ((e = readdir(sm))) {
      if (!lkm_name(e->d_name)) continue;
      sysfs = true;
      rd_copy(sysname, sizeof(sysname), e->d_name);
      break;
    }
    closedir(sm);
  }
  if (!sysfs) {
    /* The listing may be filtered while a direct probe still answers (or the
     * other way around); check the canonical name explicitly too. */
    rd_probe_row row;
    rd_probe_all("/sys/module/" RD_SUSFS_LKM_MODULE, &row);
    if (row.stat_r == 0 || row.statx_r == 0 || row.fstatat_r == 0 || row.access_r == 0 ||
        row.open_path_r == 0 || row.open_read_r == 0 || row.opendir_r == 0) {
      sysfs = true;
      rd_copy(sysname, sizeof(sysname), RD_SUSFS_LKM_MODULE);
    }
  }
  if (sysfs) {
    char dir[256];
    struct stat st;
    snprintf(dir, sizeof(dir), "/sys/module/%s", sysname);
    if (stat(dir, &st) == 0)
      snprintf(sysline, sizeof(sysline), "%s present (mode %o)", dir, (unsigned)(st.st_mode & 07777));
    else
      rd_copy(sysline, sizeof(sysline), dir);
  }

  /* ---- view C: module parameters, names unique to this port ---- */
  char pev[1024];
  pev[0] = '\0';
  int params = 0;
  if (sysname[0]) {
    for (size_t i = 0; i < sizeof(lkm_params) / sizeof(lkm_params[0]); i++) {
      char p[300], val[128] = "";
      snprintf(p, sizeof(p), "/sys/module/%s/parameters/%s", sysname, lkm_params[i]);
      if (!rd_path_exists(p)) continue;
      params++;
      bool have = read_first_line_public(p, val, sizeof(val));
      if (strlen(pev) < sizeof(pev) - 300)
        rd_appendf(pev, sizeof(pev), "%s = %s\n", p, have && val[0] ? val : "(present)");
    }
  }

  /* ---- view D: /proc/kallsyms module tag ---- */
  bool tag = false;
  char tagline[256] = "";
  char *ks = rd_slurp("/proc/kallsyms", NULL);
  if (ks) {
    /* "[susfs_guard_lkm" without the closing bracket also matches a
     * KMI-suffixed name ([susfs_guard_lkm_android13_5_15]). */
    size_t mlen = strlen(RD_SUSFS_LKM_MODULE);
    for (char *p = strstr(ks, "[" RD_SUSFS_LKM_MODULE); p;
         p = strstr(p + 1, "[" RD_SUSFS_LKM_MODULE)) {
      char cc = p[1 + mlen];
      if (cc != ']' && cc != '_' && cc != '-' && cc != '.') continue;
      tag = true;
      char *ls = p;
      while (ls > ks && ls[-1] != '\n') ls--;
      char *le = p;
      while (*le && *le != '\n') le++;
      size_t n = (size_t)(le - ls);
      if (n >= sizeof(tagline)) n = sizeof(tagline) - 1;
      memcpy(tagline, ls, n);
      tagline[n] = '\0';
      break;
    }
    free(ks);
  }

  /* ---- decision ---- */
  bool kernel_view = sysfs || params > 0 || tag;
  if (kernel_view && mods_readable && !in_modules) {
    char ev[RD_MAXEVID];
    ev[0] = '\0';
    if (sysline[0]) rd_appendf(ev, sizeof(ev), "%s\n", sysline);
    if (params) rd_appendf(ev, sizeof(ev), "parameters visible:\n%s", pev);
    if (tag) rd_appendf(ev, sizeof(ev), "kallsyms tag: %s\n", tagline);
    rd_add_ev(rep, SEV_CRITICAL, "susfs-lkm-module-filtered",
              "susfs_guard_lkm is loaded while /proc/modules does not list it", ev,
              "The kernel still answers for this module (sysfs=%s, module parameters=%d, "
              "kallsyms tag=%s) while /proc/modules has no matching line among its %d module(s). "
              "The module removes its own /proc/modules entry for every caller including root - "
              "it says so in its load banner - so this is that self-filter caught in the act, "
              "not a name match.",
              sysfs ? "yes" : "no", params, tag ? "yes" : "no", mod_count);
  } else if (kernel_view && !mods_readable) {
    char ev[RD_MAXEVID];
    ev[0] = '\0';
    if (sysline[0]) rd_appendf(ev, sizeof(ev), "%s\n", sysline);
    if (params) rd_appendf(ev, sizeof(ev), "parameters visible:\n%s", pev);
    if (tag) rd_appendf(ev, sizeof(ev), "kallsyms tag: %s\n", tagline);
    rd_add_ev(rep, SEV_HIGH, "susfs-lkm-module",
              "susfs_guard_lkm answers from the kernel; /proc/modules is unreadable", ev,
              "sysfs=%s, module parameters=%d, kallsyms tag=%s - the module is loaded, but "
              "/proc/modules could not be read, so whether its self-filter is armed could not "
              "be verified.",
              sysfs ? "yes" : "no", params, tag ? "yes" : "no");
  } else if (in_modules) {
    char ev[RD_MAXEVID];
    ev[0] = '\0';
    if (modline[0]) rd_appendf(ev, sizeof(ev), "%s\n", modline);
    if (sysline[0]) rd_appendf(ev, sizeof(ev), "%s\n", sysline);
    if (params) rd_appendf(ev, sizeof(ev), "parameters visible:\n%s", pev);
    rd_add_ev(rep, SEV_HIGH, "susfs-lkm-module", "the susfs_guard_lkm hiding module is loaded", ev,
              "/proc/modules names it%s. Its self-filter is currently off (a fresh load, or its "
              "hide list was cleared), which changes how loudly it hides, not whether a "
              "hiding-capable LKM is loaded.",
              sysline[0] ? " and its /sys/module entry is reachable" : "");
  } else {
    rd_add(rep, SEV_INFO, "susfs-lkm-module-absent", "no kernel view shows susfs_guard_lkm",
           "checked %d module name(s), the /sys/module listing, module parameters and "
           "/proc/kallsyms; no view names the LKM. Under a non-root uid this is also what a "
           "loaded module looks like - its sysfs directory is hidden from non-root callers and "
           "the /proc/susfs_* nodes answer ENOENT - so absence alone proves nothing without "
           "uid 0.",
           mod_count);
  }

  if (usedby_hits && !in_modules)
    rd_add_ev(rep, SEV_HIGH, "susfs-lkm-usedby",
              "another module's line names the LKM missing from the module list", usedby,
              "%d /proc/modules line(s) mention susfs in a column other than a module name. The "
              "self-filter removes only the module's own line, so a dependent's \"used by\" list "
              "still leaks it.",
              usedby_hits);

  /* ---- taint/list ghost: OE set while no module is listed at all ---- */
  if (mods_readable && mod_count == 0 && !in_modules &&
      read_first_line_public("/proc/sys/kernel/tainted", buf, sizeof(buf))) {
    long t = strtol(buf, NULL, 10);
    if (t & 0x1000)
      rd_add(rep, SEV_MEDIUM, "kernel-module-list-ghost",
             "taint says an out-of-tree module was loaded but no module is listed",
             "tainted=%ld has bit 12 (OE) set: the kernel recorded an out-of-tree module load, "
             "yet /proc/modules lists none at all. The bit is sticky - an rmmod leaves it set - "
             "so this is corroboration, not proof; but removing its own line is exactly what "
             "susfs_guard_lkm does, and an emptied list covers that up best.",
             t);
  }

  if (mods) free(mods);

  lkm_artefacts(rep);
  lkm_node_fingerprints(rep);
}

/* ------------------------------------------------------- consistency engine */

/* Compare uname() with the interfaces SuSFS's uname layer does NOT hook. */
static void check_uname_spoof(rd_report *rep) {
  struct utsname u;
  if (uname(&u) != 0) return;
  char file_rel[512] = "", file_ver[1024] = "";
  char sys_rel[512] = "", sys_ver[1024] = "";
  bool have_file = read_first_line_public("/proc/version", file_ver, sizeof(file_ver));
  bool have_sys = read_first_line_public("/proc/sys/kernel/osrelease", sys_rel, sizeof(sys_rel));
  bool have_sysver = read_first_line_public("/proc/sys/kernel/version", sys_ver, sizeof(sys_ver));

  if (have_file) {
    const char *p = strstr(file_ver, "Linux version ");
    if (p) {
      p += strlen("Linux version ");
      size_t n = 0;
      while (p[n] && p[n] != ' ' && n < sizeof(file_rel) - 1) { file_rel[n] = p[n]; n++; }
      file_rel[n] = '\0';
    }
  }

  bool mismatch = false;
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  rd_appendf(ev, sizeof(ev), "uname(2).release      = %s\n", u.release);
  if (have_sys) rd_appendf(ev, sizeof(ev), "/proc/sys/kernel/osrelease = %s\n", sys_rel);
  if (file_rel[0]) rd_appendf(ev, sizeof(ev), "/proc/version (release)    = %s\n", file_rel);

  if (have_sys && strcmp(sys_rel, u.release) != 0) mismatch = true;
  if (file_rel[0] && strcmp(file_rel, u.release) != 0) mismatch = true;

  if (have_sysver) {
    rd_appendf(ev, sizeof(ev), "uname(2).version      = %s\n/proc/sys/kernel/version   = %s\n",
               u.version, sys_ver);
    /* /proc/sys/kernel/version may be truncated to UTS_VERSION_LENGTH, so only
     * a divergence in the leading build id is treated as a spoof. */
    if (sys_ver[0] && strncmp(sys_ver, u.version, 8) != 0) mismatch = true;
  }

  if (mismatch)
    rd_add_ev(rep, SEV_CRITICAL, "spoof-uname",
              "uname(2) disagrees with the kernel's own version files", ev,
              "SuSFS's uname layer answers the uname() syscall with a fake release/version via a "
              "kretprobe on the syscall entry, while /proc/version and "
              "/proc/sys/kernel/{osrelease,version} keep printing init_uts_ns. A disagreement is "
              "therefore direct proof that a kernel-level spoofer is active.");
  else
    rd_add_ev(rep, SEV_INFO, "spoof-uname", "uname() is consistent with /proc", ev,
              "all utsname sources agree.");
}

/* Compare the kernel command line against the ro.boot.* properties init derives
 * from it - this is SuSFS's cmdline layer's blind spot. */
static void check_cmdline_spoof(rd_ctx *c, rd_report *rep) {
  char *cmdline = rd_slurp("/proc/cmdline", NULL);
  if (!cmdline || !cmdline[0]) { free(cmdline); return; }
  size_t clen = strlen(cmdline);
  if (clen < 32) { free(cmdline); return; } /* truncated/empty: nothing to compare */
  /* Android 12+ passes boot parameters through bootconfig, which the cmdline
   * hiding layer does not touch; a match in either file counts. Without this,
   * every property on a GKI device looked missing -> false HIGH (review B4). */
  char *bootconfig = rd_slurp("/proc/bootconfig", NULL);

  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int checked = 0, mismatch = 0;
  for (size_t i = 0; i < c->props.n; i++) {
    const char *k = c->props.keys[i];
    if (strncmp(k, "ro.boot.", 8) != 0) continue;
    const char *sub = k + 8;
    if (strcmp(sub, "baseband") == 0 || strcmp(sub, "bootloader") == 0 ||
        strcmp(sub, "hardware") == 0 || strcmp(sub, "radio") == 0 || strcmp(sub, "serialno") == 0)
      continue; /* not always sourced from the command line */
    char needle[256], needle_bc[256];
    snprintf(needle, sizeof(needle), "androidboot.%s=", sub);
    snprintf(needle_bc, sizeof(needle_bc), "androidboot.%s ", sub);
    checked++;
    if (!strstr(cmdline, needle) &&
        !(bootconfig && (strstr(bootconfig, needle) || strstr(bootconfig, needle_bc)))) {
      mismatch++;
      if (strlen(ev) < sizeof(ev) - 256)
        rd_appendf(ev, sizeof(ev), "%s=%s has no androidboot.%s= in /proc/cmdline\n", k,
                   c->props.vals[i], sub);
    }
  }
  /* A couple of ro.boot.* properties are not sourced from the command line at
   * all (avb_version comes from the AVB metadata, bootreason from the
   * bootloader, dynamic_partitions from the super partition), so a few misses
   * are normal. A cmdline-hiding layer rewrites the file wholesale and misses
   * most of them, hence the majority rule. Measured on a pristine emulator:
   * 3 of 10 missing. */
  if (checked >= 3 && mismatch * 2 > checked)
    rd_add_ev(rep, SEV_HIGH, "spoof-cmdline",
              "property table and kernel command line disagree", ev,
              "%d of %d ro.boot.* properties have no counterpart in /proc/cmdline. SuSFS's cmdline "
              "layer rewrites /proc/cmdline only; init has already copied the real values into "
              "ro.boot.*, so the two views diverge.", mismatch, checked);
  else if (checked)
    rd_add(rep, SEV_INFO, "spoof-cmdline", "command line and ro.boot.* properties agree",
           "%d properties cross-checked, %d without a cmdline counterpart (a few are expected: "
           "avb_version/bootreason/dynamic_partitions are not sourced from the command line).",
           checked, mismatch);
  free(bootconfig);
  free(cmdline);
}

/* stat() vs open()+fstat() on the same path: SuSFS's open-redirect layer
 * (susfs_opath) rewrites openat/openat2 per path, which makes the two views
 * describe different inodes. */
static void check_open_redirect(rd_report *rep) {
  static const char *const paths[] = {"/system/build.prop", "/system/bin/sh", "/proc/version",
                                      "/proc/self/status", "/system/framework/framework.jar",
                                      "/data/local/tmp", "/sbin", "/dev/null", NULL};
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int checked = 0, bad = 0, denied = 0;
  for (int i = 0; paths[i]; i++) {
    struct stat st1, st2;
    if (stat(paths[i], &st1) != 0) continue;
    int fd = open(paths[i], O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      /* stat() sees the file but open() is refused: that is SELinux (the shell
       * domain cannot read /system/build.prop on a stock image), not a redirect
       * layer. Only a dev/ino disagreement is evidence - treating EACCES as a
       * redirect turned a pristine emulator into HIDING_DETECTED. */
      denied++;
      continue;
    }
    if (fstat(fd, &st2) != 0) { close(fd); continue; }
    close(fd);
    checked++;
    if (st1.st_dev != st2.st_dev || st1.st_ino != st2.st_ino) {
      bad++;
      if (strlen(ev) < sizeof(ev) - 256)
        rd_appendf(ev, sizeof(ev), "%s: stat dev/ino=%llu/%llu but open+fstat=%llu/%llu\n",
                   paths[i], (unsigned long long)st1.st_dev, (unsigned long long)st1.st_ino,
                   (unsigned long long)st2.st_dev, (unsigned long long)st2.st_ino);
    }
  }
  if (bad)
    rd_add_ev(rep, SEV_CRITICAL, "spoof-open-redirect",
              "stat() and open() resolve the same path to different files", ev,
              "openat/openat2 are being redirected while the stat family is not (SuSFS "
              "susfs_opath does exactly this), so the path resolves to two different inodes "
              "depending on the syscall.");
  else
    rd_add(rep, SEV_INFO, "spoof-open-redirect", "open() and stat() agree",
           "%d paths resolved to the same dev/ino through both interfaces (%d were not "
           "readable for this domain and were skipped).", checked, denied);
}

/* Control paths that must exist on any Android device: if hiding breaks these,
 * it is not path-targeted any more. */
static void check_control_paths(rd_report *rep) {
  static const char *const ctl[] = {"/system",          "/system/bin",      "/system/bin/sh",
                                    "/system/build.prop", "/proc",           "/proc/self/status",
                                    "/proc/version",    "/proc/mounts",     "/dev", "/dev/null",
                                    "/data",            "/sdcard",          NULL};
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int checked = 0, bad = 0;
  for (int i = 0; ctl[i]; i++) {
    rd_probe_row row;
    rd_probe_all(ctl[i], &row);
    /* Some devices genuinely lack /sdcard (no storage) - only complain when the
     * probes contradict each other, not when all say ENOENT. */
    char cons[256];
    checked++;
    if (rd_row_inconsistent(&row, cons, sizeof(cons))) {
      if (rd_is_dangling_symlink(ctl[i])) continue; /* /sdcard is one on some images */
      bad++;
      char line[512];
      rd_format_row(ctl[i], &row, line, sizeof(line));
      if (strlen(ev) < sizeof(ev) - 512) rd_appendf(ev, sizeof(ev), "%s\n", line);
    }
  }
  if (bad)
    rd_add_ev(rep, SEV_CRITICAL, "path-consistency-control",
              "syscall views disagree for ordinary system paths", ev,
              "%d of %d always-present paths answer differently depending on the syscall used - "
              "the filtering is no longer limited to root artefacts.", bad, checked);
  else
    rd_add(rep, SEV_INFO, "path-consistency-control", "control paths are consistent",
           "%d ordinary paths probed.", checked);
}

/* /system/build.prop is world readable and is the on-disk source of many
 * ro.* properties; comparing it with the live property service catches
 * resetprop-style tampering. */
static void check_buildprop_spoof(rd_ctx *c, rd_report *rep) {
  char *bp = rd_slurp("/system/build.prop", NULL);
  if (!bp) return;
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int checked = 0, bad = 0;
  char *save = NULL;
  for (char *line = strtok_r(bp, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    char *eq = strchr(line, '=');
    if (!eq || line[0] == '#') continue;
    *eq = '\0';
    char key[128];
    snprintf(key, sizeof(key), "%s", line);
    const char *live = rd_prop(&c->props, key);
    if (!live) continue;
    checked++;
    if (strcmp(live, eq + 1) != 0) {
      bad++;
      if (strlen(ev) < sizeof(ev) - 256)
        rd_appendf(ev, sizeof(ev), "%s: build.prop=%s getprop=%s\n", key, eq + 1, live);
    }
  }
  free(bp);
  if (bad)
    rd_add_ev(rep, SEV_HIGH, "spoof-property",
              "live system properties differ from /system/build.prop", ev,
              "%d properties were modified after boot; `resetprop` is what root frameworks use to "
              "fake ro.debuggable/ro.boot.* values.", bad);
  else if (checked)
    rd_add(rep, SEV_INFO, "spoof-property", "properties match build.prop",
           "%d properties cross-checked.", checked);
}

void rd_check_consistency(rd_ctx *c, rd_report *rep) {
  check_uname_spoof(rep);
  check_cmdline_spoof(c, rep);
  check_open_redirect(rep);
  check_control_paths(rep);
  check_buildprop_spoof(c, rep);
}

/* ---------------------------------------------------------------- deep mode */

static void deep_kprobes(rd_report *rep) {
  static const char *const files[] = {"/sys/kernel/debug/kprobes/list",
                                      "/sys/kernel/tracing/kprobe_events",
                                      "/sys/kernel/debug/tracing/kprobe_events",
                                      "/sys/kernel/tracing/enabled_functions", NULL};
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int hits = 0;
  for (int i = 0; files[i]; i++) {
    char *txt = rd_slurp(files[i], NULL);
    if (!txt) continue;
    char *save = NULL;
    for (char *line = strtok_r(txt, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
      bool interesting = has_kw(line, NULL) || rd_contains(line, "s_show") ||
                         rd_contains(line, "m_show") || rd_contains(line, "slow_avc_audit") ||
                         rd_contains(line, "newuname") || rd_contains(line, "kallsyms") ||
                         rd_contains(line, "sys_exit");
      if (!interesting) continue;
      hits++;
      if (hits <= 60 && strlen(ev) < sizeof(ev) - 256) rd_appendf(ev, sizeof(ev), "%s\n", line);
    }
    free(txt);
  }
  if (hits)
    rd_add_ev(rep, SEV_CRITICAL, "hook-kprobe", "live kernel probes are attached to hiding-relevant functions",
              ev,
              "%d entries in the kernel probe/trace interfaces target kallsyms output, module "
              "listing, the uname syscall or SELinux auditing - exactly the hook sites SuSFS "
              "installs via register_kprobe()/tracepoint_probe_register().", hits);
  else
    rd_add(rep, SEV_INFO, "hook-kprobe", "no suspicious kprobe/tracepoint entries found",
           "checked the debugfs/tracefs probe lists (or they are not mounted).");
}

static void deep_dmesg(rd_report *rep) {
  char *out = (char *)malloc(1 << 20);
  if (!out) return;
  out[0] = '\0';
  int rc = -1;
  if (rd_path_exists("/system/bin/dmesg")) {
    const char *argv[] = {"/system/bin/dmesg", NULL};
    rc = rd_run(argv, out, 1 << 20);
  }
  if (rc != 0 && rd_path_exists("/bin/dmesg")) {
    const char *argv[] = {"/bin/dmesg", NULL};
    rc = rd_run(argv, out, 1 << 20);
  }
  if (rc != 0 || !out[0]) {
    free(out);
    rd_add(rep, SEV_INFO, "deep-dmesg", "kernel log not readable",
           "dmesg needs root and an SELinux policy that allows it.");
    return;
  }
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int hits = 0;
  char *save = NULL;
  for (char *line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    const char *which = NULL;
    if (!has_kw(line, &which) || strcmp(which, "busybox") == 0) continue;
    hits++;
    if (hits <= 40 && strlen(ev) < sizeof(ev) - 256) rd_appendf(ev, sizeof(ev), "%s\n", line);
  }
  if (hits)
    rd_add_ev(rep, SEV_CRITICAL, "deep-dmesg-hits",
              "kernel log records a hiding framework being loaded", ev,
              "%d kernel log lines name a root/hiding framework.", hits);
  else
    rd_add(rep, SEV_INFO, "deep-dmesg", "no root framework named in the kernel log", "");
  free(out);
}

void rd_check_deep(rd_ctx *c, rd_report *rep) {
  if (!c->is_root) {
    rd_add(rep, SEV_INFO, "deep-skipped", "deep kernel checks need uid 0",
           "run the tool through `adb root` or `su` to verify the syscall table through "
           "/proc/kcore, list kernel probes and read the kernel log.");
    return;
  }

  /* SuSFS control nodes: their handlers answer uid 0, so a root run reads them. */
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int readable = 0;
  for (size_t i = 0; i < RD_HIDING_PATH_COUNT; i++) {
    const char *p = RD_HIDING_PATHS[i];
    if (!rd_starts_with(p, "/proc/") && !rd_starts_with(p, "/sys/")) continue;
    char content[512] = "";
    if (rd_read_small(p, content, sizeof(content))) {
      readable++;
      if (strlen(ev) < sizeof(ev) - 512)
        rd_appendf(ev, sizeof(ev), "%s = %s\n", p, content[0] ? content : "(present, empty)");
    }
  }
  if (readable)
    rd_add_ev(rep, SEV_CRITICAL, "deep-susfs-node",
              "SuSFS control interfaces answered a uid 0 read", ev,
              "%d control nodes returned data. These are registered by susfs_guard_lkm and "
              "deliberately answer -ENOENT for every other uid.", readable);

  deep_kprobes(rep);
  deep_dmesg(rep);
}

/* -------------------------------------------------------- ABI differential
 *
 * Why this exists: a hide module's syscall-table patch is installed per table.
 * SuSFS's susfs_fp_hook carries a native table and a compat table, and the stat
 * family / getdents entry points differ per ABI as well (arm64 syscall numbers
 * vs AArch32 ones). Covering every ABI identically is the hardest part of
 * hiding reliably, so running the same probes from a 32-bit and a 64-bit
 * process and diffing the answers is a very direct detector.
 */

#define RD_ABI_MAX 128
#define RD_ABI_FIELDS 7

typedef struct {
  char path[192];
  int r[RD_ABI_FIELDS];
} abi_row;

static size_t abi_corpus(const char **out) {
  static const char *const extra[] = {
      "/system",          "/system/bin",     "/system/bin/sh",  "/system/build.prop",
      "/system/framework", "/vendor",       "/product",        "/proc",
      "/proc/version",    "/proc/mounts",    "/proc/self/status", "/proc/modules",
      "/proc/kallsyms",   "/proc/susfs_path", "/sys/module",    "/sbin",
      "/dev/null",        "/data",           "/data/local/tmp", "/data/adb",
      "/system/bin/su",   "/system/xbin",    "/cache",
  };
  size_t n = 0;
  for (size_t i = 0; i < sizeof(extra) / sizeof(extra[0]) && n < RD_ABI_MAX; i++) out[n++] = extra[i];
  for (size_t i = 0; i < RD_ROOT_PATH_COUNT && n < RD_ABI_MAX; i++) out[n++] = RD_ROOT_PATHS[i];
  for (size_t i = 0; i < RD_HIDING_PATH_COUNT && n < RD_ABI_MAX; i++) out[n++] = RD_HIDING_PATHS[i];
  /* The LKM's own installer paths are hiding surfaces too: sus_path rules are
   * armed per path, and the 32-bit and 64-bit halves of the syscall table are
   * patched independently. */
  for (size_t i = 0; i < RD_SUSFS_LKM_PATH_COUNT && n < RD_ABI_MAX; i++)
    out[n++] = RD_SUSFS_LKM_PATHS[i];
  return n;
}

static void abi_fill(const char *path, abi_row *row) {
  rd_probe_row p;
  snprintf(row->path, sizeof(row->path), "%s", path);
  rd_probe_all(path, &p);
  row->r[0] = p.stat_r;
  row->r[1] = p.statx_r;
  row->r[2] = p.fstatat_r;
  row->r[3] = p.access_r;
  row->r[4] = p.open_path_r;
  row->r[5] = p.open_read_r;
  row->r[6] = p.opendir_r;
}

void rd_abi_probe_dump(FILE *out) {
  const char *corpus[RD_ABI_MAX];
  size_t n = abi_corpus(corpus);
  fprintf(out, "# rd-probe-dump 1 %s ptr=%d\n", rd_abi_name(), (int)(sizeof(void *) * 8));
  for (size_t i = 0; i < n; i++) {
    abi_row row;
    abi_fill(corpus[i], &row);
    fputs(row.path, out);
    for (int k = 0; k < RD_ABI_FIELDS; k++) fprintf(out, "\t%d", row.r[k]);
    fputc('\n', out);
  }
  fflush(out);
}

/* Parse a --probe-dump payload. Returns the number of rows, or -1. */
static int abi_parse(char *text, char *helper_abi, size_t abi_sz, abi_row *rows, size_t max) {
  size_t n = 0;
  if (abi_sz) helper_abi[0] = '\0';
  char *save = NULL;
  for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    if (line[0] == '#') {
      char abi[64] = "";
      if (sscanf(line, "# rd-probe-dump %*d %63s", abi) == 1 && abi_sz)
        snprintf(helper_abi, abi_sz, "%s", abi);
      continue;
    }
    if (n >= max) break;
    char *tab = strchr(line, '\t');
    if (!tab) continue;
    *tab = '\0';
    snprintf(rows[n].path, sizeof(rows[n].path), "%s", line);
    char *q = tab + 1;
    for (int k = 0; k < RD_ABI_FIELDS; k++) {
      rows[n].r[k] = (int)strtol(q, &q, 10);
      if (*q == '\t') q++;
    }
    n++;
  }
  return n > 0 ? (int)n : -1;
}

/* Whether the file at `path` may be executed as the ABI helper.
 *
 * This is a security boundary, not a formality. The helper used to be exec'd
 * straight from /data/local/tmp to the names below, but on Android that
 * directory is drwxrwx--x shell shell WITHOUT the sticky bit: any `adb shell`
 * user can create a file named rootdetect-x86 there, or unlink a root-owned one
 * and drop their own, and the next run executes it with this process's
 * privileges (root, in the deep-check run). It could equally feed a forged
 * --probe-dump and fake the verdict. So a helper is only executed when
 *   - it is a regular file (not a symlink or a wrapper),
 *   - it is owned by root (when we run as root) or by us,
 *   - it is not writable by group/others,
 *   - its parent directory is not group/other writable (only enforced when we
 *     run as root: /data/local/tmp itself is group-writable),
 *   - and it really is an ELF (a shell script is what a forged helper is).
 */
static bool abi_helper_trusted(const char *path, char *why, size_t whysz) {
  struct stat st;
  if (whysz) why[0] = '\0';
  if (lstat(path, &st) != 0) { snprintf(why, whysz, "cannot be stat'ed"); return false; }
  if (!S_ISREG(st.st_mode)) { snprintf(why, whysz, "not a regular file"); return false; }
  uid_t me = geteuid();
  if (me == 0 && st.st_uid != 0) {
    snprintf(why, whysz, "owned by uid %d, not root", (int)st.st_uid);
    return false;
  }
  if (me != 0 && st.st_uid != me) {
    snprintf(why, whysz, "owned by uid %d, not by this process", (int)st.st_uid);
    return false;
  }
  if (st.st_mode & (S_IWGRP | S_IWOTH)) {
    snprintf(why, whysz, "writable by group or others");
    return false;
  }
  if (me == 0) {
    char dir[512];
    if (rd_dir_writable_by_others(path, dir, sizeof(dir))) {
      snprintf(why, whysz, "directory %s is group/other writable", dir[0] ? dir : "?");
      return false;
    }
  }
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) { snprintf(why, whysz, "cannot be opened"); return false; }
  unsigned char magic[4] = {0};
  ssize_t n = read(fd, magic, 4);
  close(fd);
  if (n != 4 || magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') {
    snprintf(why, whysz, "not an ELF executable");
    return false;
  }
  return true;
}

/* Picks a helper. Returns false when none is usable; if a file existed but was
 * refused, `out` holds its path and `reason` says why. */
static bool abi_candidate(char *out, size_t sz, char *reason, size_t rsz) {
  if (reason && rsz) reason[0] = '\0';
  if (out && sz) out[0] = '\0';
  const char *e = getenv("ROOTDETECT_ABI_HELPER");
  if (e && *e && rd_path_exists(e)) {
    if (abi_helper_trusted(e, reason, rsz)) {
      snprintf(out, sz, "%s", e);
      return true;
    }
    snprintf(out, sz, "%s", e);
    return false;
  }

  char self[512] = "", dir[512] = "";
  if (rd_read_link("/proc/self/exe", self, sizeof(self)) >= 0) {
    char *slash = strrchr(self, '/');
    if (slash) { *slash = '\0'; snprintf(dir, sizeof(dir), "%s", self); }
  }
  /* Names a user is likely to have pushed side by side. Both directions are
   * listed: a 32-bit build can exec a 64-bit helper and vice versa. */
  static const char *const names[] = {"rootdetect-x86", "rootdetect-arm", "rootdetect-i386",
                                      "rootdetect-armeabi", "rootdetect-arm64",
                                      "rootdetect-x86_64", "rx32", "rx64", NULL};
  static const char *const dirs[] = {NULL /* self dir */, "/data/local/rx" /* root-only */,
                                      "/data/local/tmp" /* only usable unprivileged */, NULL};
  char candidates[16][512];
  size_t nc = 0;
  for (int d = 0; dirs[d] || d == 0; d++) {
    const char *base = (d == 0) ? (dir[0] ? dir : NULL) : dirs[d];
    if (!base) continue;
    for (int i = 0; names[i] && nc < 16; i++) {
      snprintf(candidates[nc], sizeof(candidates[0]), "%s/%s", base, names[i]);
      nc++;
    }
  }
  char rejected[512] = "", reject_why[256] = "";
  for (size_t i = 0; i < nc; i++) {
    if (!rd_path_exists(candidates[i])) continue;
    char why[256] = "";
    if (abi_helper_trusted(candidates[i], why, sizeof(why))) {
      snprintf(out, sz, "%s", candidates[i]);
      return true;
    }
    if (!rejected[0]) {
      snprintf(rejected, sizeof(rejected), "%s", candidates[i]);
      snprintf(reject_why, sizeof(reject_why), "%s", why);
    }
  }
  if (rejected[0]) {
    snprintf(out, sz, "%s", rejected);
    if (reason && rsz) snprintf(reason, rsz, "%s", reject_why);
  }
  return false;
}

void rd_check_abi_diff(rd_ctx *c, rd_report *rep) {
  (void)c;
  char helper[512] = "", why[256] = "";
  if (!abi_candidate(helper, sizeof(helper), why, sizeof(why))) {
    if (helper[0] && why[0]) {
      /* A file exists but is not safe to execute. Report it: on a rooted device
       * this is either a misconfiguration or someone trying to get code run as
       * root, and both deserve visibility. */
      rd_add(rep, geteuid() == 0 ? SEV_MEDIUM : SEV_LOW, "abi-helper-rejected",
             "an ABI helper file was found but refused to be executed",
             "refusing %s: %s. A helper in a group/other-writable directory (/data/local/tmp "
             "is drwxrwx--x shell shell on Android, and not sticky) can be planted or replaced "
             "by any adb shell user while this process may be root, so it is never executed. "
             "Put a root-owned copy in a root-only directory and point ROOTDETECT_ABI_HELPER "
             "at it, e.g.: mkdir -m 700 /data/local/rx; cp rootdetect-x86 /data/local/rx/; "
             "chmod 755 /data/local/rx/rootdetect-x86; "
             "ROOTDETECT_ABI_HELPER=/data/local/rx/rootdetect-x86 rootdetect-x86_64 -v",
             helper, why);
    } else {
      rd_add(rep, SEV_INFO, "abi-diff-skipped", "no second-ABI helper binary found",
             "push the other ABI's build into a root-only directory and point "
             "ROOTDETECT_ABI_HELPER at it to enable the cross-ABI comparison. SuSFS patches the "
             "native and compat syscall tables separately, so this is one of the strongest "
             "checks available. Files under group/other-writable directories such as "
             "/data/local/tmp are deliberately ignored.");
    }
    return;
  }

  char *out = (char *)malloc(1 << 20);
  if (!out) return;
  const char *argv[] = {helper, "--probe-dump", NULL};
  int rc = rd_run(argv, out, 1 << 20);
  if (rc != 0 || !strstr(out, "rd-probe-dump")) {
    rd_add(rep, SEV_INFO, "abi-diff-skipped", "second-ABI helper could not be executed",
           "%s exited with %d (a 32-bit binary needs a 32-bit-capable kernel/zygote, and it must "
           "be chmod 755).", helper, rc);
    free(out);
    return;
  }

  static abi_row remote[RD_ABI_MAX], local[RD_ABI_MAX];
  char helper_abi[64] = "";
  int n_remote = abi_parse(out, helper_abi, sizeof(helper_abi), remote, RD_ABI_MAX);
  free(out);
  if (n_remote < 0) {
    rd_add(rep, SEV_INFO, "abi-diff-skipped", "helper produced no probe data", "%s", helper);
    return;
  }
  if (helper_abi[0] && strcmp(helper_abi, rd_abi_name()) == 0) {
    rd_add(rep, SEV_INFO, "abi-diff-skipped", "helper has the same ABI as this binary",
           "%s reports %s; a cross-ABI comparison needs a different one.", helper, helper_abi);
    return;
  }

  const char *corpus[RD_ABI_MAX];
  size_t n_local = abi_corpus(corpus);
  for (size_t i = 0; i < n_local; i++) abi_fill(corpus[i], &local[i]);

  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int compared = 0, differ = 0;
  for (int i = 0; i < n_remote; i++) {
    const abi_row *lr = NULL;
    for (size_t k = 0; k < n_local; k++)
      if (strcmp(local[k].path, remote[i].path) == 0) { lr = &local[k]; break; }
    if (!lr) continue;
    compared++;
    bool any = false;
    for (int f = 0; f < RD_ABI_FIELDS; f++) {
      /* Refused (-1) or not applicable (-2) on either side is not a difference -
       * the same rule the vote engine uses; counting it made SELinux look like an
       * ABI divergence (review B12). */
      if (lr->r[f] < 0 || remote[i].r[f] < 0) continue;
      if (lr->r[f] != remote[i].r[f]) any = true;
    }
    if (!any) continue;
    differ++;
    if (strlen(ev) < sizeof(ev) - 400) {
      char rl[128] = "", rr[128] = "";
      static const char *const fname[RD_ABI_FIELDS] = {"stat",   "statx", "fstatat",  "access",
                                                       "open_p", "open_r", "opendir"};
      for (int f = 0; f < RD_ABI_FIELDS; f++) {
        char one[24];
        snprintf(one, sizeof(one), "%s=%s ", fname[f], rd_probe_res_name(lr->r[f]));
        strncat(rl, one, sizeof(rl) - strlen(rl) - 1);
        snprintf(one, sizeof(one), "%s=%s ", fname[f], rd_probe_res_name(remote[i].r[f]));
        strncat(rr, one, sizeof(rr) - strlen(rr) - 1);
      }
      rd_appendf(ev, sizeof(ev), "%s\n  %s(%dbit): %s\n  %s(%s): %s\n", remote[i].path,
                 rd_abi_name(), (int)(sizeof(void *) * 8), rl, helper, helper_abi[0] ? helper_abi : "32bit", rr);
    }
  }

  if (differ)
    rd_add_ev(rep, SEV_CRITICAL, "abi-consistency-mismatch",
              "32-bit and 64-bit processes disagree about the same paths", ev,
              "%d of %d probed paths resolve differently depending on the ABI of the calling "
              "process. The kernel is intercepting one ABI's syscall entry points but not the "
              "other's - exactly the hole left by per-table hiding (SuSFS susfs_fp_hook patches "
              "the native and compat syscall tables separately).", differ, compared);
  else
    rd_add(rep, SEV_INFO, "abi-consistency", "both ABIs agree on every probed path",
           "compared %d paths between %s and %s (%s).", compared, rd_abi_name(), helper,
           helper_abi[0] ? helper_abi : "unknown");
}
