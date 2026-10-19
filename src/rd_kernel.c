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

/* Loaded modules as seen through /sys/module/<name>/initstate. Built-in modules
 * have no initstate node; a loadable one reports "live" while it is loaded.
 * Verified on a stock kernel: the set is exactly /proc/modules (14 = 14).
 * This is the fallback for Android app domains, where /proc/modules is denied,
 * and an independent view for the cross-check when both are readable. */
static size_t sysfs_live_modules(char **names, size_t max, size_t *total) {
  size_t n = 0, count = 0;
  DIR *d = opendir("/sys/module");
  if (!d) {
    if (total) *total = 0;
    return 0;
  }
  struct dirent *e;
  while ((e = readdir(d))) {
    if (e->d_name[0] == '.') continue;
    char p[320], b[32];
    snprintf(p, sizeof(p), "/sys/module/%s/initstate", e->d_name);
    if (!read_first_line_public(p, b, sizeof(b))) continue;
    if (strcmp(b, "live") != 0) continue;
    count++;
    if (n < max) {
      char *dup = strdup(e->d_name);
      if (dup) names[n++] = dup;
    }
  }
  closedir(d);
  if (total) *total = count;
  return n;
}

/* Names from a /proc/modules buffer. The buffer is consumed (strtok_r). */
static size_t proc_module_names(char *txt, char **names, size_t max) {
  size_t n = 0;
  char *save = NULL;
  for (char *line = strtok_r(txt, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    char name[128];
    if (!rd_parse_proc_modules_line(line, name, sizeof(name))) continue;
    if (n >= max) continue;
    char *dup = strdup(name);
    if (dup) names[n++] = dup;
  }
  return n;
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
    /* cap advances only on a successful realloc (same rule as find_push()). */
    size_t ncap = t->cap ? t->cap * 2 : 512;
    ksym *nv = (ksym *)realloc(t->v, ncap * sizeof(ksym));
    if (!nv) return;
    t->v = nv;
    t->cap = ncap;
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
  if (!t) return NULL;
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
      else {
        /* Bits that stock / vendor kernels set routinely and that say nothing
         * about "something was loaded into the kernel", which is what this
         * MEDIUM is about: S(2), M(4), B(5), U(6), D(7, an OOPS/BUG happened at
         * some point), A(8), W(9), C(10), I(11), L(14, a soft lockup) and
         * T(17, struct randomization). Leaving D/L/T out of the mask reported a
         * crashed but otherwise stock kernel as suspicious. Module-related bits
         * (F(1), R(3), O(12, handled above), E(13), K(15), X(16)) are not
         * benign; anything else also keeps the MEDIUM. */
        unsigned long benign = (1ul << 2) | (1ul << 4) | (1ul << 5) | (1ul << 6) |
                               (1ul << 7) | (1ul << 8) | (1ul << 9) | (1ul << 10) |
                               (1ul << 11) | (1ul << 14) | (1ul << 17);
        if (((unsigned long)t & ~benign) == 0)
          rd_add_ev(rep, SEV_LOW, "kernel-taint", "kernel tainted by benign conditions", ev,
                    "only taint bits stock/vendor kernels set routinely (S/D/M/B/U/A/W/C/I/L/T) "
                    "are present; no module or hooking bit is set.");
        else
          rd_add_ev(rep, SEV_MEDIUM, "kernel-taint", "kernel is tainted", ev,
                    "a module/condition marked the kernel, which stock builds typically avoid.");
      }
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
      if (n_mod_names < 512) {
        char *dup = strdup(name);
        if (dup) mod_names[n_mod_names++] = dup;
      }
      const char *which = NULL;
      if (has_kw(name, &which)) {
        mod_hits++;
        if (strlen(mod_ev) < sizeof(mod_ev) - 256) rd_appendf(mod_ev, sizeof(mod_ev), "%s\n", line);
      }
    }
  }
  char *sys_names[512];
  size_t sys_total = 0;
  size_t n_sys_names = sysfs_live_modules(sys_names, 512, &sys_total);
  if (!mods && sys_total)
    rd_add(rep, SEV_INFO, "kernel-module", "loaded module list read from /sys/module",
           "/proc/modules is denied to this domain; %zu module(s) report initstate=live under "
           "/sys/module and are used as the loaded-module list for the kallsyms cross-check "
           "below. The /sys/module name scan covers their names.", sys_total);
  else if (!mods)
    rd_add_skip(rep, SEV_INFO, "kernel-module", "/proc/modules unreadable",
                "the loaded-module list could not be read (SELinux restricts it to root on some "
           "devices) and /sys/module exposed no live module either, so the module-name check did "
           "not run - this is not a clean result.");
  else if (mod_hits)
    rd_add_ev(rep, SEV_HIGH, "kernel-module", "loaded kernel module names a root framework",
              mod_ev, "%d of %d loaded modules match a hiding-framework name.", mod_hits, mod_count);
  else
    rd_add(rep, SEV_INFO, "kernel-module", "no suspicious module name in /proc/modules",
           "%d modules listed.", mod_count);

  /* /sys/module: names matching a framework. This view also yields an
   * independent loaded-module list (<name>/initstate == "live"), which the
   * cross-check below uses - sus_path hides the two views independently. */
  char sys_ev[RD_MAXEVID];
  sys_ev[0] = '\0';
  int sys_hits = 0;
  DIR *d = opendir("/sys/module");
  if (d) {
    struct dirent *e;
    while ((e = readdir(d))) {
      if (e->d_name[0] == '.') continue;
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

  /* /proc/modules and /sys/module/<name>/initstate are independent views of the
   * loaded set. A live module absent from /proc/modules had the list filtered
   * (susfs_guard_lkm's self-filter is exactly that). Re-read /proc/modules once
   * before concluding, so a module loading between the two reads cannot produce
   * a false positive. */
  if (mods && n_sys_names) {
    size_t missing = 0;
    for (size_t i = 0; i < n_sys_names; i++) {
      bool listed = false;
      for (size_t k = 0; k < n_mod_names; k++)
        if (strcmp(mod_names[k], sys_names[i]) == 0) { listed = true; break; }
      if (!listed) missing++;
    }
    if (missing) {
      char *again = rd_slurp("/proc/modules", NULL);
      if (!again) {
        rd_add(rep, SEV_INFO, "kernel-module-sysfs-crosscheck",
               "could not re-read /proc/modules, cross-check inconclusive", "");
      } else {
        char *again_names[512];
        size_t n_again = proc_module_names(again, again_names, 512);
        size_t confirmed = 0;
        char mev[RD_MAXEVID];
        mev[0] = '\0';
        for (size_t i = 0; i < n_sys_names; i++) {
          bool listed = false;
          for (size_t k = 0; k < n_mod_names; k++)
            if (strcmp(mod_names[k], sys_names[i]) == 0) { listed = true; break; }
          for (size_t k = 0; !listed && k < n_again; k++)
            if (strcmp(again_names[k], sys_names[i]) == 0) { listed = true; break; }
          if (listed) continue;
          confirmed++;
          if (strlen(mev) < sizeof(mev) - 128) rd_appendf(mev, sizeof(mev), "%s\n", sys_names[i]);
        }
        for (size_t i = 0; i < n_again; i++) free(again_names[i]);
        free(again);
        if (confirmed)
          rd_add_ev(rep, SEV_HIGH, "kernel-module-list-filtered",
                    "live modules are missing from /proc/modules",
                    mev,
                    "%zu module(s) report initstate=live under /sys/module yet are absent from "
                    "/proc/modules in two consecutive reads. The two lists are filtered "
                    "independently; a module-list hider is the only normal explanation (a load "
                    "race would have shown up in the second read).", confirmed);
        else
          rd_add(rep, SEV_INFO, "kernel-module-sysfs-crosscheck",
                 "module appeared in the re-read, not a filter", "");
      }
    } else {
      rd_add(rep, SEV_INFO, "kernel-module-sysfs-crosscheck",
             "sysfs and /proc/modules agree", "%zu live module(s) in both views.", n_sys_names);
    }
  }

  /* kallsyms annotates module symbols with [module]. A module that shows up
   * there but not in the loaded-module list had that list filtered. Use
   * /proc/modules when readable, otherwise the sysfs live list; built-in
   * modules appear in neither view. */
  char **baseline = mod_names;
  size_t n_baseline = n_mod_names;
  const char *baseline_src = "/proc/modules";
  if (n_mod_names == 0 && n_sys_names) {
    baseline = sys_names;
    n_baseline = n_sys_names;
    baseline_src = "/sys/module";
  }
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
        for (size_t k = 0; k < n_baseline; k++)
          if (strcmp(baseline[k], ktab->v[i].mod) == 0) { listed = true; break; }
        if (!listed) {
          hidden_mod++;
          if (strlen(mod_ev2) < sizeof(mod_ev2) - 128)
            rd_appendf(mod_ev2, sizeof(mod_ev2), "%s (symbol %s at %s)\n", ktab->v[i].mod,
                       ktab->v[i].name, kptr_str(ktab->v[i].addr, buf, sizeof(buf)));
        }
      }
      /* Only conclude "hidden" when the baseline list was actually readable
       * AND non-empty. If neither /proc/modules nor /sys/module yielded a
       * list, kallsyms still carries [module] tags and every one of them would
       * be reported as hidden - turning a clean device into HIDING_DETECTED.
       * That is worse than not checking. */
      if (hidden_mod && n_baseline == 0)
        rd_add_skip(rep, SEV_INFO, "kernel-modules-crosscheck-skipped",
                    "module list unavailable or empty, cross-check skipped",
               "neither /proc/modules nor /sys/module yielded a loaded-module list, so the %d "
               "module symbol(s) seen in kallsyms cannot be told apart from a filtered module "
               "list; skipping the hidden-module conclusion.",
               hidden_mod);
      else if (hidden_mod)
        rd_add_ev(rep, SEV_HIGH, "kernel-module-hidden",
                  "module symbols visible in kallsyms but the module is missing from the module list",
                  mod_ev2,
                  "%d module name(s) appear in kallsyms yet are absent from %s: the lists are "
                  "filtered independently and disagree.", hidden_mod, baseline_src);
      else
        rd_add(rep, SEV_INFO, "kernel-module-crosscheck",
               "module lists agree", "%d module(s) seen in kallsyms, all present in %s.",
               vis_mod, baseline_src);

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
        rd_add_skip(rep, SEV_INFO, "kernel-syscall-table-skipped",
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
          rd_add_skip(rep, SEV_INFO, "kernel-syscall-table-skipped",
                      "sys_call_table could not be verified",
                 "kallsyms did not resolve %s%s%s. A kernel built without CONFIG_KALLSYMS_ALL omits "
                 "data symbols; Android GKI kernels normally keep it enabled, so on a device this "
                 "check does run.", sct ? "" : "sys_call_table", (!sct && !openat) ? " and " : "",
                 openat ? "" : "the openat syscall symbol");
        } else {
          unsigned long long entry = 0;
          if (kcore_read(sct + (unsigned long long)__NR_openat * 8, &entry, 8)) {
            if (entry != openat) {
              /* Two distinct buffers: kptr_str() returns its argument, so passing
               * the same buffer twice made both %s read the last-written value
               * (and the two writes were unsequenced). */
              char buf2[64];
              rd_add(rep, SEV_CRITICAL, "kernel-syscall-table-patched",
                     "sys_call_table entry does not point at the real syscall",
                     "sys_call_table[%d]=%s but kallsyms says the syscall is at %s - the table "
                     "was rewritten at runtime (SuSFS susfs_fp_hook / any syscall hook).",
                     __NR_openat, kptr_str(entry, buf, sizeof(buf)),
                     kptr_str(openat, buf2, sizeof(buf2)));
            } else
              rd_add(rep, SEV_INFO, "kernel-syscall-table",
                     "sys_call_table[openat] matches kallsyms",
                     "verified through /proc/kcore: %s", kptr_str(entry, buf, sizeof(buf)));
          } else {
            rd_add_skip(rep, SEV_INFO, "kernel-kcore", "/proc/kcore not readable",
                        "cannot verify sys_call_table contents from user space on this device.");
          }
        }
      }
    }
  } else {
    rd_add_skip(rep, SEV_INFO, "kernel-kallsyms", "/proc/kallsyms unreadable",
                "SELinux blocks the symbol table for this domain; cross-checks skipped.");
  }
  free(ks);
  ksym_free(ktab);
  if (mods) free(mods);
  for (size_t i = 0; i < n_mod_names; i++) free(mod_names[i]);
  for (size_t i = 0; i < n_sys_names; i++) free(sys_names[i]);

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
    rd_add_skip(rep, SEV_INFO, "susfs-node-absent", "no SuSFS control node reachable",
                "all %zu paths answered ENOENT. Note this is also what a non-root process sees when "
                "SuSFS hides them, so absence alone is not evidence of a clean device - the "
                "susfs_guard_lkm section cross-checks exactly this case with its syscall-coverage "
                "oracle.",
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
 * string luck. v2.3.0-r18 (susfs_hide_syms.c) spells the self-filter out; the
 * three views below are present since at least r16, so they are not an r18
 * novelty (only the citations here are from r18.3):
 *  - /proc/modules: its m_show() line is removed "for EVERY reader, root
 *    included, since a checker may well run as root and this listing is what
 *    it compares against";
 *  - /proc/kallsyms: lines whose module tag is in the hide list are filtered,
 *    "also for every reader", so a visible [susfs_guard_lkm] tag means an
 *    older build or a kprobe that failed to arm - bonus evidence only;
 *  - /sys/module/<name>: stat/open/readdir answer ENOENT to EVERY non-root
 *    caller - shell (2000), system (1000) and app uids alike - while "root
 *    keeps access (that is where a module's parameters live)". The sysfs directory,
 *    its parameter files and the /proc/susfs_* bodies are therefore views a
 *    root scan still reaches, and any of them answering while /proc/modules
 *    omits the module is the self-filter observed in the act.
 *  - The default hide list holds just this module ("a built-in SUSFS has no
 *    module entry"), seeded at init; the /proc/susfs_hide_modules body's
 *    names: line therefore carries susfs_guard_lkm on a fresh load (`clear`
 *    is the project's debugging mode).
 *  - susfs_main.c's load banner: "This module is filtered out of /proc/modules
 *    for every caller including root, so `lsmod | grep susfs` stays empty -
 *    check /sys/module/susfs_guard_lkm instead."
 *  - module/load.sh uses `[ -d /sys/module/susfs_guard_lkm ]` as its own
 *    "already loaded" probe; the module's parameter names are unique to this
 *    port (the sentinel subset this file probes is lkm_params[] below).
 *  - susfs.h: the module name is the .ko file name; releases ship
 *    susfs_guard_lkm-<kmi>.ko, so name lookups here are prefix matches
 *    (susfs_guard_lkm, susfs_guard_lkm_android13_5_15, ...).
 *  - PROC_INTERFACES.md: hide_modules removes a listed module's own
 *    /proc/modules line only - another module's "used by" column would still
 *    name it.
 *  - PROC_INTERFACES.md documents the control-node bodies; the counter/table
 *    shapes are reproduced in rd_susfs_lkm_node_fingerprint().
 *  - The self-hiding itself answers through a discrete set of LSM hooks plus,
 *    later, sys_call_table wrappers: stat family (inode_getattr), permission
 *    (inode_permission), setattr, sb_statfs, the xattr hooks, path_notify,
 *    unlink/rmdir/rename/link, getdents64 (dirent filter) and - since r18.3 -
 *    openat/openat2 for O_PATH. Any syscall those layers do not cover still
 *    resolves the very same entry, so a "stat(2) says ENOENT" contradicted by
 *    another call IS the hiding act observed, without root. The oracle below
 *    (lkm_syscall_oracle) uses:
 *      mkdir(2)     EEXIST from filename_create()'s lookup, ahead of every
 *                   permission/LSM decision - no LSM hook can reach it, and no
 *                   release (r16..main) touches mkdir/mknod/symlink/lookup;
 *      readlink(2)  EINVAL on a resolved non-symlink; upstream's own source
 *                   calls the disagreement with stat "the tell" and closed it
 *                   only after v2.3.0-r18.3 (a copy of the inode's i_op whose
 *                   readlink slot answers through the same predicate);
 *      statfs(2)    a coverage hole only before its sb_statfs hook (kept as a
 *                   failed-install detector);
 *      open(O_PATH) a coverage hole before r18.3's sys_call_table wrapper.
 *    A hit cannot be produced by a clean kernel: stat() and the other calls
 *    read the same dentry tree.
 */

/* A sentinel subset of this LKM's module parameters (declared in susfs_main.c,
 * susfs_opath.c, susfs_hide_syms.c, susfs_or_entry.c, susfs_uname.c; the
 * module declares more - none of the chosen names is a stock kernel name).
 * opath_test / opath_dump / or_entry are new in r18; the other four exist
 * since at least r16. Seeing any of them under /sys/module/<name>/parameters/
 * identifies the port. */
static const char *const lkm_params[] = {"expose_proc",    "fail_layer", "opath_test", "opath_dump",
                                         "hide_modules",   "or_entry",   "uname_spoof_enabled"};

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

unsigned rd_susfs_lkm_oracle_tell(int stat_r, int mkdir_r, int readlink_r, int statfs_r,
                                  int opath_r) {
  /* Only the hidden case is interesting: a reachable path is judged by the
   * views above, and a stat() the environment blocked ("-1") says nothing. */
  if (stat_r != 1) return 0;
  unsigned bits = 0;
  if (mkdir_r == 0) bits |= RD_TELL_MKDIR;
  if (readlink_r == 0) bits |= RD_TELL_READLINK;
  if (statfs_r == 0) bits |= RD_TELL_STATFS;
  if (opath_r == 0) bits |= RD_TELL_OPATH;
  return bits;
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
      /* The hide table names what it hides; on a default load that is this
       * module itself - carry the names: line into the evidence. */
      if (strcmp(nodes[i], "/proc/susfs_hide_modules") == 0) {
        const char *nm = strstr(txt, "names:");
        if (nm && strlen(ev) < sizeof(ev) - 300) {
          const char *le = strchr(nm, '\n');
          size_t nl = le ? (size_t)(le - nm) : strlen(nm);
          char nline[224];
          if (nl >= sizeof(nline)) nl = sizeof(nline) - 1;
          memcpy(nline, nm, nl);
          nline[nl] = '\0';
          rd_appendf(ev, sizeof(ev), "  %s\n", nline);
        }
      }
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

/* ---------------------------------------------------- syscall-coverage oracle
 *
 * The one check that works WITHOUT root. With the hiding layer armed, stat(2)
 * on the module's own paths answers ENOENT to every non-root caller - by
 * design (susfs.h: "hides it from EVERY non-root caller, not merely from app
 * processes - otherwise a probe running as system (1000) or shell (2000) reads
 * the node name out of /proc"). That answer comes from discrete hooks; the
 * paths themselves exist and keep resolving for syscalls outside the hook set.
 * Proving existence THROUGH such a syscall while stat(2) denies the same path
 * is contradictory on a clean kernel - the two read the same dentry tree - and
 * lands here as susfs-lkm-node-oracle. See the section comment above for the
 * per-syscall rationale and per-release coverage (mkdir/mknod-family from
 * filename_create() is the leg no release r16..main closes). */
static void lkm_syscall_oracle(rd_report *rep) {
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int hits = 0, probed = 0;
  for (size_t i = 0; i < RD_SUSFS_LKM_SELF_HIDDEN_COUNT; i++) {
    const char *p = RD_SUSFS_LKM_SELF_HIDDEN[i];
    /* Visible (the views above own that case) or blocked by the environment:
     * neither is an oracle case. */
    if (rd_probe_lstat(p) != 1) continue;
    probed++;
    int mk = rd_probe_mkdir_exists(p);
    int rl = rd_probe_readlink_exists(p);
    int fs = rd_probe_statfs_exists(p);
    int op = rd_probe_open_o_path(p);
    unsigned tell = rd_susfs_lkm_oracle_tell(1, mk, rl, fs, op);
    if (!tell) continue;
    /* A module loading while the probes run could race stat() and mkdir():
     * keep the finding only while stat() STILL denies the path afterwards. */
    if (rd_probe_lstat(p) != 1) continue;
    hits++;
    if (strlen(ev) < sizeof(ev) - 320) {
      rd_appendf(ev, sizeof(ev), "%s\n  stat -> ENOENT, but", p);
      if (tell & RD_TELL_MKDIR)
        rd_appendf(ev, sizeof(ev), " mkdir(2) -> EEXIST (filename_create found the entry)");
      if (tell & RD_TELL_READLINK)
        rd_appendf(ev, sizeof(ev), " readlink(2) -> EINVAL (resolved, not a symlink)");
      if (tell & RD_TELL_STATFS)
        rd_appendf(ev, sizeof(ev), " statfs(2) -> resolved (pre-sb_statfs-hook build)");
      if (tell & RD_TELL_OPATH)
        rd_appendf(ev, sizeof(ev), " open(O_PATH) -> resolved (pre-r18.3 build)");
      rd_appendf(ev, sizeof(ev), "\n");
    }
  }
  if (hits)
    rd_add_ev(rep, SEV_CRITICAL, "susfs-lkm-node-oracle",
              "susfs_guard_lkm's hidden control paths exist for syscalls that deny them to stat()",
              ev,
              "%d of %d path(s) this module hides from every non-root caller answered ENOENT to "
              "stat(2) while another system call resolved the same entry from this uid. On a clean "
              "kernel both read the same dentry tree, so this split is a per-caller filter "
              "answering stat(): the module makes its own nodes world-accessible (0777) and relies "
              "on its LSM layer as the only gate, and that discrete hook set misses at least the "
              "syscall named above. This is the module observed from a non-root uid.",
              hits, probed);
  else if (probed)
    rd_add_ev(rep, SEV_INFO, "susfs-lkm-node-oracle-absent",
              "no syscall-coverage contradiction on the self-hidden paths", ev,
              "%d path(s) that stat(2) denies this uid were re-probed with "
              "mkdir(2)/readlink(2)/statfs(2)/open(O_PATH): all answered consistently. That is "
              "what a clean system looks like - and also what a build whose module closed every "
              "tell this oracle knows looks like, so it does NOT prove the paths are absent.",
              probed);
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
    rd_add_skip(rep, SEV_INFO, "susfs-lkm-artefact-absent", "no susfs_guard_lkm installer file found",
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
  int mod_count = 0, usedby_hits = 0, othername_hits = 0;
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
      /* Two different things put "susfs" on a line that is not the LKM's own:
       * a module whose *own* name spells it (a differently named build of the
       * same family - the module name comes from the .ko file name, so a rename
       * is all it takes), and another module's "used by" column, which is the
       * leak hide_modules leaves behind. Only the second one is the self-filter
       * observed in the act, so they are counted apart. */
      if (rd_contains_ci(line, "susfs")) {
        if (rd_contains_ci(name, "susfs"))
          othername_hits++;
        else
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

  /* ---- view D: /proc/kallsyms module tag ----
   * v2.3.0-r18 filters kallsyms lines whose module tag is in the hide list,
   * for every reader, so a hit here now means an older build or a kprobe that
   * failed to arm - extra evidence when present, never required. */
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

  /* ---- decision ----
   * sysfs already implies the parameters: sysname is only filled in when a
   * sysfs view answered, and the parameter loop runs off sysname. */
  bool kernel_view = sysfs || tag;
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
           "loaded module looks like - its sysfs directory answers ENOENT to every non-root "
           "caller and so do the /proc/susfs_* nodes - but that case is not left to trust: the "
           "syscall-coverage oracle below re-probes the self-hidden paths and reports separately "
           "when stat()'s ENOENT is contradicted by another system call.",
           mod_count);
  }

  if (usedby_hits && !in_modules)
    rd_add_ev(rep, SEV_HIGH, "susfs-lkm-usedby",
              "another module's line names the LKM missing from the module list", usedby,
              "%d /proc/modules line(s) mention susfs in a column other than a module name. The "
              "self-filter removes only the module's own line, so a dependent's \"used by\" list "
              "still leaks it.%s",
              usedby_hits,
              othername_hits ? " Other lines carry susfs in a module's own name - those are a "
                               "differently named susfs build, not this LKM." : "");
  else if (othername_hits && !in_modules)
    rd_add_ev(rep, SEV_HIGH, "susfs-lkm-usedby",
              "a susfs module is loaded under a name other than susfs_guard_lkm", usedby,
              "%d /proc/modules line(s) carry susfs in their own module name, so a susfs hiding "
              "module is loaded - just not under the LKM's name (the module name is taken from "
              "the .ko file name, so a renamed build is enough). The self-filter explanation "
              "would be wrong here; the module list never carried this LKM's name to filter.",
              othername_hits);

  /* ---- taint/list ghost: OE set while no module is listed at all ---- */
  if (mods_readable && mod_count == 0 && !in_modules &&
      read_first_line_public("/proc/sys/kernel/tainted", buf, sizeof(buf))) {
    long t = strtol(buf, NULL, 10);
    if (t & 0x1000)
      rd_add(rep, SEV_MEDIUM, "kernel-module-list-ghost",
             "taint says an out-of-tree module was loaded but no module is listed",
             "tainted=%ld has bit 12 (OE) set: the kernel recorded an out-of-tree module load, "
             "yet /proc/modules lists none at all. The bit is sticky, so a stock device whose "
             "only vendor module was rmmod'ed once leaves the same state - this is corroboration, "
             "not proof. It is reported because emptying the list is also what susfs_guard_lkm's "
             "self-filter looks like when nothing else is loaded.",
             t);
  }

  if (mods) free(mods);

  lkm_artefacts(rep);
  lkm_node_fingerprints(rep);
  lkm_syscall_oracle(rep);
}

/* ------------------------------------------------------- consistency engine */

/* Compare uname() with the interfaces SuSFS's uname layer does NOT hook. */
static void check_uname_spoof(rd_report *rep) {
  struct utsname u;
  if (uname(&u) != 0) return;
  char file_rel[512] = "", file_ver[1024] = "";
  char sys_rel[512] = "", sys_ver[1024] = "";
  bool have_file = read_first_line_public("/proc/version", file_ver, sizeof(file_ver)) &&
                   file_ver[0];
  bool have_sys = read_first_line_public("/proc/sys/kernel/osrelease", sys_rel, sizeof(sys_rel)) &&
                  sys_rel[0];
  bool have_sysver = read_first_line_public("/proc/sys/kernel/version", sys_ver, sizeof(sys_ver)) &&
                     sys_ver[0];

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
  int compared = 0;
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  rd_appendf(ev, sizeof(ev), "uname(2).release      = %s\n", u.release);
  if (have_sys) rd_appendf(ev, sizeof(ev), "/proc/sys/kernel/osrelease = %s\n", sys_rel);
  if (file_rel[0]) rd_appendf(ev, sizeof(ev), "/proc/version (release)    = %s\n", file_rel);

  if (have_sys) {
    compared++;
    if (strcmp(sys_rel, u.release) != 0) mismatch = true;
  }
  if (file_rel[0]) {
    compared++;
    if (strcmp(file_rel, u.release) != 0) mismatch = true;
  }

  if (have_sysver) {
    rd_appendf(ev, sizeof(ev), "uname(2).version      = %s\n/proc/sys/kernel/version   = %s\n",
               u.version, sys_ver);
    /* /proc/sys/kernel/version may be truncated to UTS_VERSION_LENGTH, so
     * compare as much as both sides have. The old 8-byte strncmp() only looked
     * at the leading build id: a spoof that keeps "#1 SMP PREEMPT" and rewrites
     * the rest of the string went unnoticed even though the file was complete. */
    size_t n = strlen(sys_ver);
    if (n > strlen(u.version)) n = strlen(u.version);
    if (n >= 8) {
      compared++;
      if (strncmp(sys_ver, u.version, n) != 0) mismatch = true;
    } else {
      rd_appendf(ev, sizeof(ev), "(/proc/sys/kernel/version is too short to compare)\n");
    }
  }

  if (mismatch)
    rd_add_ev(rep, SEV_CRITICAL, "spoof-uname",
              "uname(2) disagrees with the kernel's own version files", ev,
              "SuSFS's uname layer answers the uname() syscall with a fake release/version via a "
              "kretprobe on the syscall entry, while /proc/version and "
              "/proc/sys/kernel/{osrelease,version} keep printing init_uts_ns. A disagreement is "
              "therefore direct proof that a kernel-level spoofer is active.");
  else if (compared == 0)
    /* "All utsname sources agree" was printed even when not a single one of them
     * could be read, which turns "the check did not run" into an apparent clean
     * result (the exact failure mode a hiding layer wants). */
    rd_add_skip_ev(rep, SEV_INFO, "spoof-uname", "uname() could not be cross-checked", ev,
              "none of /proc/version, /proc/sys/kernel/osrelease or /proc/sys/kernel/version were "
              "readable from this domain, so nothing was compared - this is not a consistent "
              "result.");
  else
    rd_add_ev(rep, SEV_INFO, "spoof-uname", "uname() is consistent with /proc", ev,
              "%d readable utsname source(s) agree with the uname(2) syscall.", compared);
}

/* Compare the kernel command line against the ro.boot.* properties init derives
 * from it - this is SuSFS's cmdline layer's blind spot. */
static void check_cmdline_spoof(rd_ctx *c, rd_report *rep) {
  char *cmdline = rd_slurp("/proc/cmdline", NULL);
  if (!cmdline || !cmdline[0]) {
    /* Returning silently hid the fact that the cross-check never ran. */
    rd_add_skip(rep, SEV_INFO, "spoof-cmdline", "/proc/cmdline is not readable",
                "the kernel command line could not be read from this domain (SELinux or a hiding "
           "layer), so the ro.boot.* cross-check did not run - this is not a clean result.");
    free(cmdline);
    return;
  }
  size_t clen = strlen(cmdline);
  if (clen < 32) {
    rd_add_skip(rep, SEV_INFO, "spoof-cmdline", "kernel command line is too short to compare",
                "/proc/cmdline is %zu bytes long, so it carries no androidboot.* parameter to verify "
           "the property table against.", clen);
    free(cmdline);
    return;
  }
  /* Android 12+ passes boot parameters through bootconfig, which the cmdline
   * hiding layer does not touch; a match in either file counts. Without this,
   * every property on a GKI device looked missing -> false HIGH (review B4). */
  char *bootconfig = rd_slurp("/proc/bootconfig", NULL);

  /* A cmdline-hiding layer rewrites one of the two files, but they are only
   * useful as a reference if they expose androidboot.* tokens at all: an
   * app/shell SELinux domain, a vendor that strips them and a non-Android
   * kernel all leave /proc/cmdline without any, and then "no counterpart" says
   * nothing - "hidden here" and "never passed here" are indistinguishable. */
  bool cmd_ref = strstr(cmdline, "androidboot.") != NULL;
  bool bc_ref = bootconfig && strstr(bootconfig, "androidboot.") != NULL;

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
        rd_appendf(ev, sizeof(ev), "%s=%s has no androidboot.%s in /proc/cmdline or "
                                   "/proc/bootconfig\n", k, c->props.vals[i], sub);
    }
  }
  /* A couple of ro.boot.* properties are not sourced from the command line at
   * all (avb_version comes from the AVB metadata, bootreason from the
   * bootloader, dynamic_partitions from the super partition), so a few misses
   * are normal. A cmdline-hiding layer rewrites the file wholesale and misses
   * most of them, hence the majority rule. Measured on a pristine emulator:
   * 3 of 10 missing. */
  if (checked >= 3 && mismatch * 2 > checked && (cmd_ref || bc_ref))
    rd_add_ev(rep, SEV_HIGH, "spoof-cmdline",
              "property table and kernel command line disagree", ev,
              "%d of %d ro.boot.* properties have no counterpart in /proc/cmdline. SuSFS's cmdline "
              "layer rewrites /proc/cmdline only; init has already copied the real values into "
              "ro.boot.*, so the two views diverge.", mismatch, checked);
  else if (checked >= 3 && mismatch * 2 > checked)
    rd_add_skip_ev(rep, SEV_INFO, "spoof-cmdline",
                   "property table and command line cannot be compared", ev,
              "%d of %d ro.boot.* properties have no counterpart, but neither source exposes any "
              "androidboot.* token from this domain (/proc/cmdline: %s; /proc/bootconfig: %s), so "
              "the parameters are not visible here rather than hidden - there is nothing to "
              "compare against.", mismatch, checked, cmd_ref ? "has tokens" : "no tokens",
              bootconfig ? (bc_ref ? "has tokens" : "no tokens") : "unreadable");
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

/* Does `text` contain a line that defines exactly `key` ("key=" at a line
 * start)? Used to find keys a later partition may legitimately override. */
static bool text_defines_key(const char *text, const char *key) {
  if (!text || !key || !*key) return false;
  size_t klen = strlen(key);
  for (const char *p = text; (p = strstr(p, key)) != NULL; p++) {
    if (p != text && p[-1] != '\n') continue;
    if (p[klen] != '=') continue;
    return true;
  }
  return false;
}

/* /system/build.prop is world readable and is the on-disk source of many
 * ro.* properties; comparing it with the live property service catches
 * resetprop-style tampering. */
static void check_buildprop_spoof(rd_ctx *c, rd_report *rep) {
  char *bp = rd_slurp("/system/build.prop", NULL);
  if (!bp) return;
  /* /system/build.prop is only the first of several property files: init reads
   * vendor/, odm/, product/ and system_ext/ build.prop afterwards, and a later
   * declaration wins. Comparing /system alone therefore reported every
   * legitimate override as a resetprop edit (the live value is the vendor's,
   * not /system's), so keys defined by a later partition are skipped. The files
   * that cannot be read simply do not contribute. */
  static const char *const later[] = {"/vendor/build.prop", "/odm/build.prop",
                                      "/product/build.prop", "/system_ext/build.prop", NULL};
  char *later_txt = NULL;
  size_t later_len = 0;
  for (int i = 0; later[i]; i++) {
    size_t n = 0;
    char *t = rd_slurp(later[i], &n);
    if (!t) continue;
    char *nt = (char *)realloc(later_txt, later_len + n + 2);
    if (!nt) {
      free(t);
      break;
    }
    later_txt = nt;
    memcpy(later_txt + later_len, t, n);
    later_len += n;
    later_txt[later_len++] = '\n';
    free(t);
  }
  if (later_txt) later_txt[later_len] = '\0';

  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int checked = 0, bad = 0, overridden = 0;
  char *save = NULL;
  for (char *line = strtok_r(bp, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    while (*line == ' ' || *line == '\t' || *line == '\r') line++; /* build.prop is CRLF sometimes */
    if (!*line || *line == '#') continue;
    char *eq = strchr(line, '=');
    if (!eq || eq == line) continue;
    *eq = '\0';
    char *key = line;
    char *kend = key + strlen(key);
    while (kend > key && (kend[-1] == ' ' || kend[-1] == '\t')) *--kend = '\0';
    char *val = eq + 1;
    while (*val == ' ' || *val == '\t') val++;
    char *vend = val + strlen(val);
    /* getprop trims trailing whitespace; a trailing space in the file is not a
     * property change. */
    while (vend > val && (vend[-1] == ' ' || vend[-1] == '\t' || vend[-1] == '\r')) *--vend = '\0';
    if (!*key || !*val) continue;
    const char *live = rd_prop(&c->props, key);
    if (!live) continue;
    if (text_defines_key(later_txt, key)) {
      overridden++;
      continue; /* a later partition decides this key, /system's copy is unused */
    }
    checked++;
    if (strcmp(live, val) != 0) {
      bad++;
      if (strlen(ev) < sizeof(ev) - 256)
        rd_appendf(ev, sizeof(ev), "%s: /system/build.prop=%s getprop=%s\n", key, val, live);
    }
  }
  free(later_txt);
  free(bp);
  if (bad)
    rd_add_ev(rep, SEV_HIGH, "spoof-property",
              "live system properties differ from /system/build.prop", ev,
              "%d properties were modified after boot; `resetprop` is what root frameworks use to "
              "fake ro.debuggable/ro.boot.* values.", bad);
  else if (checked)
    rd_add(rep, SEV_INFO, "spoof-property", "properties match build.prop",
           "%d properties cross-checked (%d skipped: a later partition redefines them).", checked,
           overridden);
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
    rd_add_skip(rep, SEV_INFO, "deep-dmesg", "kernel log not readable",
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
    rd_add_skip(rep, SEV_INFO, "deep-skipped", "deep kernel checks need uid 0",
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

/* Parse a --probe-dump payload. Returns the number of rows, or -1.
 *
 * The payload comes from a helper we exec (see abi_helper_trusted()), but its
 * shape is still validated: the old field loop ran exactly RD_ABI_FIELDS times
 * even when a line carried fewer numbers, and strtol() then returned 0 for
 * every missing field. A truncated or stale helper therefore looked like "all
 * probes answered ENOENT" and could be compared into a CRITICAL ABI mismatch.
 * A row is accepted only with the full field count, and a payload without a
 * "# rd-probe-dump 1" header is refused instead of being half-read. */
static int abi_parse(char *text, char *helper_abi, size_t abi_sz, abi_row *rows, size_t max) {
  size_t n = 0;
  int malformed = 0;
  bool have_header = false;
  if (abi_sz) helper_abi[0] = '\0';
  char *save = NULL;
  for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    if (line[0] == '#') {
      int ver = 0;
      char abi[64] = "";
      if (sscanf(line, "# rd-probe-dump %d %63s", &ver, abi) != 2)
        continue; /* some other comment */
      if (ver != 1) return -1; /* unknown format: not a payload we can compare */
      have_header = true;
      if (abi_sz) snprintf(helper_abi, abi_sz, "%s", abi);
      continue;
    }
    if (!have_header) continue; /* data before any header: nothing to trust */
    if (n >= max) break;
    if (!line[0]) continue;
    char *tab = strchr(line, '\t');
    if (!tab) {
      malformed++;
      continue;
    }
    *tab = '\0';
    char *q = tab + 1;
    int got = 0;
    for (int k = 0; k < RD_ABI_FIELDS; k++) {
      if (k) {
        if (*q != '\t') break; /* a field is missing */
        q++;
      }
      char *end = NULL;
      long v = strtol(q, &end, 10);
      if (end == q) break; /* not a number */
      rows[n].r[k] = (int)v;
      q = end;
      got++;
    }
    if (got != RD_ABI_FIELDS || (*q && *q != '\t')) {
      malformed++;
      continue;
    }
    snprintf(rows[n].path, sizeof(rows[n].path), "%s", line);
    n++;
  }
  if (!have_header) return -1;
  if (malformed && !n) return -1;
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
      if (whysz) why[0] = '\0';
      rd_appendf(why, whysz, "directory %s is group/other writable", dir[0] ? dir : "?");
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
    if (slash) { *slash = '\0'; rd_copy(dir, sizeof(dir), self); }
  }
  /* Names a user is likely to have pushed side by side. Both directions are
   * listed: a 32-bit build can exec a 64-bit helper and vice versa. */
  static const char *const names[] = {"rootdetect-x86", "rootdetect-arm", "rootdetect-i386",
                                      "rootdetect-armeabi", "rootdetect-arm64",
                                      "rootdetect-x86_64", "rx32", "rx64", NULL};
  static const char *const dirs[] = {NULL /* self dir */, "/data/local/rx" /* root-only */,
                                      "/data/local/tmp" /* only usable unprivileged */, NULL};
  /* 8 names x 3 directories = 24 candidates; the array and the bound must allow
   * all of them or the last directory (/data/local/tmp, the only one usable
   * unprivileged) would never be scanned. */
  enum { RD_ABI_MAXCAND = 40 };
  char candidates[RD_ABI_MAXCAND][512];
  size_t nc = 0;
  for (int d = 0; dirs[d] || d == 0; d++) {
    const char *base = (d == 0) ? (dir[0] ? dir : NULL) : dirs[d];
    if (!base) continue;
    for (int i = 0; names[i] && nc < RD_ABI_MAXCAND; i++) {
      /* Build the path with an explicit length check instead of
       * snprintf("%s/%s"): a silently truncated path would make the cross-ABI
       * diff compare the wrong file. */
      size_t bl = strlen(base), nl = strlen(names[i]);
      if (bl + 1 + nl + 1 > sizeof(candidates[0])) continue;
      memcpy(candidates[nc], base, bl);
      candidates[nc][bl] = '/';
      memcpy(candidates[nc] + bl + 1, names[i], nl + 1);
      nc++;
    }
  }
  char rejected[512] = "", reject_why[256] = "";
  for (size_t i = 0; i < nc; i++) {
    if (!rd_path_exists(candidates[i])) continue;
    char why[256] = "";
    if (abi_helper_trusted(candidates[i], why, sizeof(why))) {
      rd_copy(out, sz, candidates[i]);
      return true;
    }
    if (!rejected[0]) {
      rd_copy(rejected, sizeof(rejected), candidates[i]);
      rd_copy(reject_why, sizeof(reject_why), why);
    }
  }
  if (rejected[0]) {
    rd_copy(out, sz, rejected);
    if (reason && rsz) rd_copy(reason, rsz, reject_why);
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
      rd_add_skip(rep, SEV_INFO, "abi-diff-skipped", "no second-ABI helper binary found",
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
    rd_add_skip(rep, SEV_INFO, "abi-diff-skipped", "second-ABI helper could not be executed",
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
    rd_add_skip(rep, SEV_INFO, "abi-diff-skipped", "helper produced no probe data", "%s", helper);
    return;
  }
  if (helper_abi[0] && strcmp(helper_abi, rd_abi_name()) == 0) {
    rd_add_skip(rep, SEV_INFO, "abi-diff-skipped", "helper has the same ABI as this binary",
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
