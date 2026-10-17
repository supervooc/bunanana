/* rootdetect - utility layer: file IO, process capture, properties, syscall
 * probes and the finding/report model. */
#include "rd.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/stat.h>
#endif

/* ------------------------------------------------------------------- severity */

const char *rd_sev_name(rd_sev s) {
  switch (s) {
    case SEV_CRITICAL: return "CRITICAL";
    case SEV_HIGH: return "HIGH";
    case SEV_MEDIUM: return "MEDIUM";
    case SEV_LOW: return "LOW";
    default: return "INFO";
  }
}

/* ------------------------------------------------------------------- findings */

static char *xstrdup(const char *s) {
  if (!s) return NULL;
  size_t n = strlen(s) + 1;
  char *p = (char *)malloc(n);
  if (p) memcpy(p, s, n);
  return p;
}

void rd_report_init(rd_report *r) {
  memset(r, 0, sizeof(*r));
  r->cap = 16;
  r->items = (rd_finding *)calloc(r->cap, sizeof(rd_finding));
}

void rd_report_free(rd_report *r) {
  for (size_t i = 0; i < r->n; i++) {
    free(r->items[i].id);
    free(r->items[i].title);
    free(r->items[i].detail);
    free(r->items[i].evidence);
  }
  free(r->items);
  free(r->verdict);
  memset(r, 0, sizeof(*r));
}

static rd_finding *find_push(rd_report *r, rd_sev sev, const char *id, const char *title) {
  if (r->n >= r->cap) {
    /* cap must only move on success: updating it before realloc turned an OOM
     * into an out-of-bounds write on the next call (review B10). */
    size_t ncap = r->cap ? r->cap * 2 : 16;
    rd_finding *ni = (rd_finding *)realloc(r->items, ncap * sizeof(rd_finding));
    if (!ni) return NULL;
    memset(ni + r->n, 0, (ncap - r->n) * sizeof(rd_finding));
    r->items = ni;
    r->cap = ncap;
  }
  rd_finding *f = &r->items[r->n++];
  memset(f, 0, sizeof(*f));
  f->sev = sev;
  f->id = xstrdup(id ? id : "unnamed");
  f->title = xstrdup(title ? title : "");
  r->counts[sev]++;
  return f;
}

static void set_detail(rd_finding *f, const char *fmt, va_list ap) {
  char buf[RD_MAXEVID];
  vsnprintf(buf, sizeof(buf), fmt, ap);
  free(f->detail);
  f->detail = xstrdup(buf);
}

void rd_add(rd_report *r, rd_sev sev, const char *id, const char *title, const char *fmt, ...) {
  rd_finding *f = find_push(r, sev, id, title);
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  set_detail(f, fmt ? fmt : "", ap);
  va_end(ap);
}

void rd_add_ev(rd_report *r, rd_sev sev, const char *id, const char *title,
               const char *evidence, const char *fmt, ...) {
  rd_finding *f = find_push(r, sev, id, title);
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  set_detail(f, fmt ? fmt : "", ap);
  va_end(ap);
  if (evidence && *evidence) f->evidence = xstrdup(evidence);
}

static int cmp_sev_desc(const void *a, const void *b) {
  const rd_finding *fa = (const rd_finding *)a, *fb = (const rd_finding *)b;
  if (fa->sev != fb->sev) return (int)fb->sev - (int)fa->sev;
  return strcmp(fa->id, fb->id);
}

/* Which capability does a finding prove? Explicit table beats substring
 * matching: the verdict must be reproducible. */
static unsigned id_flags(const char *id) {
  static const struct { const char *id; unsigned f; } t[] = {
      {"path-consistency-mismatch", RD_F_HIDE},
      {"path-consistency-control", RD_F_HIDE},
      {"susfs-node-inconsistency", RD_F_HIDE},
      {"susfs-node-present", RD_F_HIDE},
      {"susfs-cmdline", RD_F_HIDE},
      {"spoof-uname", RD_F_HIDE},
      {"spoof-cmdline", RD_F_HIDE},
      {"spoof-open-redirect", RD_F_HIDE},
      {"spoof-property", RD_F_ROOT | RD_F_HIDE},
      {"mount-view-inconsistency", RD_F_HIDE},
      {"mount-roots", RD_F_ROOT},
      {"mount-overlay", RD_F_ROOT},
      {"kernel-module", RD_F_HOOK},
      {"kernel-module-hidden", RD_F_HOOK | RD_F_HIDE},
      {"kernel-sysmodule", RD_F_HOOK},
      {"kernel-kallsyms-symbol", RD_F_HOOK},
      {"kernel-syscall-table-patched", RD_F_HOOK | RD_F_HIDE},
      {"kernel-taint-oe", RD_F_HOOK},
      {"hook-kprobe", RD_F_HOOK},
      {"deep-dmesg-hits", RD_F_HOOK | RD_F_ROOT},
      {"deep-susfs-node", RD_F_HIDE},
      {"package-hidden", RD_F_ROOT | RD_F_HIDE},
      {"package-roots", RD_F_ROOT},
      {"package-roots-list", RD_F_ROOT},
      {"artefact-present", RD_F_ROOT},
      {"artefact-listing", RD_F_ROOT},
      {"env-prop-identity", RD_F_ROOT},
      {"env-selinux-permissive", RD_F_ROOT},
      {"env-selinux-domain", RD_F_ROOT},
      {"proc-injected-lib", RD_F_HOOK | RD_F_ROOT},
      {"unix-socket-roots", RD_F_ROOT},
      {"self-traced", RD_F_HOOK},
      {"map-backing-hidden", RD_F_HOOK},
      {"map-deleted-exec", RD_F_HOOK},
      {"abi-consistency-mismatch", RD_F_HIDE},
  };
  for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++)
    if (strcmp(id, t[i].id) == 0) return t[i].f;
  return 0;
}

void rd_finalize(rd_report *r) {
  qsort(r->items, r->n, sizeof(rd_finding), cmp_sev_desc);
  r->flags = 0;
  for (size_t i = 0; i < r->n; i++) {
    if (r->items[i].sev < SEV_HIGH) continue;
    r->flags |= id_flags(r->items[i].id);
  }
  const char *verdict;
  if (r->counts[SEV_CRITICAL] > 0 || (r->flags & RD_F_HIDE))
    verdict = "HIDING_DETECTED";
  else if (r->counts[SEV_HIGH] > 0)
    verdict = "ROOT_DETECTED";
  else if (r->counts[SEV_MEDIUM] > 0)
    verdict = "SUSPICIOUS";
  else
    verdict = "CLEAN";
  free(r->verdict);
  r->verdict = xstrdup(verdict);
}

void rd_json_escape(const char *in, char *out, size_t outsz) {
  size_t o = 0;
  if (!outsz) return;
  for (const unsigned char *p = (const unsigned char *)in; *p && o + 7 < outsz; p++) {
    unsigned char c = *p;
    switch (c) {
      case '"': out[o++] = '\\'; out[o++] = '"'; break;
      case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
      case '\n': out[o++] = '\\'; out[o++] = 'n'; break;
      case '\r': out[o++] = '\\'; out[o++] = 'r'; break;
      case '\t': out[o++] = '\\'; out[o++] = 't'; break;
      default:
        if (c < 0x20) {
          o += (size_t)snprintf(out + o, outsz - o, "\\u%04x", c);
        } else {
          out[o++] = (char)c;
        }
    }
  }
  out[o] = '\0';
}

static void print_finding_text(const rd_finding *f, int use_color) {
  const char *col = "", *rst = "";
  if (use_color) {
    switch (f->sev) {
      case SEV_CRITICAL: col = "\033[1;35m"; break;
      case SEV_HIGH: col = "\033[1;31m"; break;
      case SEV_MEDIUM: col = "\033[1;33m"; break;
      case SEV_LOW: col = "\033[0;36m"; break;
      default: col = "\033[0;90m"; break;
    }
    rst = "\033[0m";
  }
  printf("%s[%-8s]%s %-22s %s\n", col, rd_sev_name(f->sev), rst, f->id, f->title);
  if (f->detail && *f->detail) {
    /* indent multi-line details */
    const char *p = f->detail;
    while (*p) {
      const char *nl = strchr(p, '\n');
      size_t len = nl ? (size_t)(nl - p) : strlen(p);
      printf("           %.*s\n", (int)len, p);
      if (!nl) break;
      p = nl + 1;
    }
  }
  if (f->evidence && *f->evidence) {
    const char *p = f->evidence;
    while (*p) {
      const char *nl = strchr(p, '\n');
      size_t len = nl ? (size_t)(nl - p) : strlen(p);
      printf("           | %.*s\n", (int)len, p);
      if (!nl) break;
      p = nl + 1;
    }
  }
}

void rd_print_text(const rd_report *r, int use_color, int verbose) {
  int shown = 0;
  /* INFO rows are printed exactly once, by the informational block below. The
   * previous condition ("!verbose && sev == INFO") let -v print them twice: the
   * main loop rendered every row and the block then rendered the INFO ones again
   * (46 INFO lines for 23 unique ids). */
  for (size_t i = 0; i < r->n; i++) {
    if (r->items[i].sev == SEV_INFO) continue;
    print_finding_text(&r->items[i], use_color);
    shown++;
  }
  if (!shown) printf("(no findings above INFO)\n");
  if (verbose) {
    printf("\n--- informational ---\n");
    int n_info = 0;
    for (size_t i = 0; i < r->n; i++)
      if (r->items[i].sev == SEV_INFO) {
        print_finding_text(&r->items[i], use_color);
        n_info++;
      }
    if (!n_info) printf("(none)\n");
  }
  printf("\nsummary: %d critical, %d high, %d medium, %d low, %d info\n",
         r->counts[SEV_CRITICAL], r->counts[SEV_HIGH], r->counts[SEV_MEDIUM],
         r->counts[SEV_LOW], r->counts[SEV_INFO]);
  printf("verdict: %s%s%s\n", use_color ? "\033[1;37m" : "", r->verdict ? r->verdict : "?",
         use_color ? "\033[0m" : "");
}

void rd_print_json(const rd_report *r) {
  /* Worst case is six output bytes per input byte ("\u00xx"), and fields can be
   * a full RD_MAXEVID; RD_MAXEVID*2 silently dropped ~2/3 of an escape-heavy
   * field (a 2900-byte LD_PRELOAD of control bytes came out as 1008 chars). */
  char esc[RD_MAXEVID * 6 + 8];
  printf("{\n  \"tool\": \"rootdetect\",\n  \"version\": \"%s\",\n", RD_VERSION);
  printf("  \"verdict\": \"%s\",\n", r->verdict ? r->verdict : "?");
  printf("  \"summary\": {\"critical\": %d, \"high\": %d, \"medium\": %d, \"low\": %d, \"info\": %d},\n",
         r->counts[SEV_CRITICAL], r->counts[SEV_HIGH], r->counts[SEV_MEDIUM],
         r->counts[SEV_LOW], r->counts[SEV_INFO]);
  printf("  \"findings\": [");
  for (size_t i = 0; i < r->n; i++) {
    const rd_finding *f = &r->items[i];
    printf("%s\n    {", i ? "," : "");
    rd_json_escape(f->id, esc, sizeof(esc));
    printf("\"id\": \"%s\", ", esc);
    printf("\"severity\": \"%s\", ", rd_sev_name(f->sev));
    rd_json_escape(f->title, esc, sizeof(esc));
    printf("\"title\": \"%s\", ", esc);
    rd_json_escape(f->detail ? f->detail : "", esc, sizeof(esc));
    printf("\"detail\": \"%s\"", esc);
    if (f->evidence && *f->evidence) {
      rd_json_escape(f->evidence, esc, sizeof(esc));
      printf(", \"evidence\": \"%s\"", esc);
    }
    printf("}");
  }
  printf("\n  ]\n}\n");
}

/* --------------------------------------------------------------------- path IO */

char *rd_slurp_fd(int fd, size_t *len_out) {
  size_t cap = 8192, n = 0;
  char *buf = (char *)malloc(cap + 1);
  if (!buf) return NULL;
  for (;;) {
    if (n + 4096 + 1 > cap) {
      size_t ncap = cap * 2;
      char *nb = (char *)realloc(buf, ncap + 1);
      if (!nb) { free(buf); return NULL; }
      buf = nb;
      cap = ncap;
    }
    ssize_t r = read(fd, buf + n, cap - n);
    if (r < 0) {
      if (errno == EINTR) continue;
      /* A partial read is still useful (e.g. /proc/kcore); stop on error. */
      break;
    }
    if (r == 0) break;
    n += (size_t)r;
    if (cap > (64u << 20)) break; /* sanity: 64 MiB ceiling */
  }
  buf[n] = '\0';
  if (len_out) *len_out = n;
  return buf;
}

char *rd_slurp(const char *path, size_t *len_out) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return NULL;
  char *b = rd_slurp_fd(fd, len_out);
  close(fd);
  return b;
}

bool rd_read_small(const char *path, char *buf, size_t bufsz) {
  if (!bufsz) return false;
  /* O_NONBLOCK: this is also used to read the SuSFS control nodes under
   * /data/adb/susfs/ and /proc/susfs_*. rd_probe_open_read() already opens with
   * O_NONBLOCK, but the re-open here did not, so a FIFO (or an LKM node whose
   * read blocks) made the whole scan hang forever even though the non-blocking
   * probe had just classified it as "present". Regular and procfs files ignore
   * O_NONBLOCK, so this only changes the behaviour for special files. */
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) return false;
  ssize_t r = read(fd, buf, bufsz - 1);
  close(fd);
  if (r < 0) return false;
  buf[r] = '\0';
  size_t t = rd_trim(buf);
  (void)t;
  return true;
}

long rd_read_link(const char *path, char *buf, size_t bufsz) {
  if (!bufsz) return -1;
  ssize_t r = readlink(path, buf, bufsz - 1);
  if (r < 0) return -1;
  buf[r] = '\0';
  return (long)r;
}

bool rd_path_exists(const char *path) {
  struct stat st;
  return lstat(path, &st) == 0;
}

long long rd_path_size(const char *path) {
  struct stat st;
  if (stat(path, &st) != 0) return -1;
  return (long long)st.st_size;
}

size_t rd_trim(char *s) {
  size_t n = strlen(s);
  while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = '\0';
  size_t i = 0;
  while (s[i] == ' ' || s[i] == '\t') i++;
  if (i) memmove(s, s + i, n - i + 1), n -= i;
  return n;
}

/* ------------------------------------------------------------- process capture */

int rd_run(const char *const argv[], char *out, size_t outsz) {
  int pfd[2];
  if (out && outsz) out[0] = '\0';
  if (pipe(pfd) != 0) return -1;
  pid_t pid = fork();
  if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
  if (pid == 0) {
    /* child */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) { dup2(devnull, STDIN_FILENO); }
    if (out) {
      dup2(pfd[1], STDOUT_FILENO);
    } else {
      if (devnull >= 0) dup2(devnull, STDOUT_FILENO);
    }
    if (devnull >= 0) dup2(devnull, STDERR_FILENO);
    close(pfd[0]);
    if (pfd[1] > 2) close(pfd[1]);
    execv(argv[0], (char *const *)argv);
    _exit(127);
  }
  close(pfd[1]);
  size_t n = 0;
  if (out && outsz) {
    int full = 0;
    for (;;) {
      if (n + 1 >= outsz) { full = 1; break; }
      ssize_t r = read(pfd[0], out + n, outsz - 1 - n);
      if (r < 0) {
        if (errno == EINTR) continue;
        break;
      }
      if (r == 0) break;
      n += (size_t)r;
    }
    out[n] = '\0';
    /* The child may still be writing when the buffer is full. Closing the pipe
     * now delivers SIGPIPE to it, so waitpid() reports "killed by signal" and
     * rd_run() returns -1 - i.e. a merely large output (a big dmesg or
     * `getprop`) is misread as "the command could not run" and the caller drops
     * the whole result. Drain the remaining bytes (discarding them) so the child
     * exits normally and the truncation is reported as a normal exit. */
    if (full) {
      char sink[4096];
      while (read(pfd[0], sink, sizeof(sink)) > 0) {}
    }
  } else {
    char sink[4096];
    while (read(pfd[0], sink, sizeof(sink)) > 0) {}
  }
  close(pfd[0]);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  return -1;
}

/* ------------------------------------------------------------------ properties */

static void props_push(rd_props *p, const char *k, const char *v) {
  if (p->n == p->cap) {
    /* Grow both arrays before touching cap: updating cap before a failed realloc
     * would make the next write index past the (still small) allocation. */
    size_t ncap = p->cap ? p->cap * 2 : 128;
    char **nk = (char **)realloc(p->keys, ncap * sizeof(char *));
    if (!nk) return;
    char **nv = (char **)realloc(p->vals, ncap * sizeof(char *));
    if (!nv) { p->keys = nk; return; }
    p->keys = nk;
    p->vals = nv;
    p->cap = ncap;
  }
  p->keys[p->n] = xstrdup(k);
  p->vals[p->n] = xstrdup(v);
  p->n++;
}

void rd_props_load(rd_props *p) {
  memset(p, 0, sizeof(*p));
  char *out = (char *)malloc(1 << 20);
  if (!out) return;
  out[0] = '\0'; /* no getprop binary => out is never written, so NUL it here */
  static const char *const cands[] = {"/system/bin/getprop", "/system/bin/getprop2",
                                      "/vendor/bin/getprop", NULL};
  for (int i = 0; cands[i]; i++) {
    if (!rd_path_exists(cands[i])) continue;
    const char *argv[] = {cands[i], NULL};
    if (rd_run(argv, out, 1 << 20) == 0) break;
  }
  char *save = NULL;
  for (char *line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    char *open_b = strchr(line, '[');
    if (!open_b) continue;
    char *close_b = strchr(open_b, ']');
    if (!close_b) continue;
    char *open_v = strchr(close_b, '[');
    if (!open_v) continue;
    char *close_v = strrchr(open_v, ']');
    if (!close_v || close_v <= open_v) continue;
    *close_b = '\0';
    *close_v = '\0';
    props_push(p, open_b + 1, open_v + 1);
  }
  free(out);
}

void rd_props_free(rd_props *p) {
  for (size_t i = 0; i < p->n; i++) { free(p->keys[i]); free(p->vals[i]); }
  free(p->keys);
  free(p->vals);
  memset(p, 0, sizeof(*p));
}

const char *rd_prop(const rd_props *p, const char *key) {
  for (size_t i = 0; i < p->n; i++)
    if (strcmp(p->keys[i], key) == 0) return p->vals[i];
  return NULL;
}

void rd_props_foreach_prefix(const rd_props *p, const char *prefix,
                             void (*cb)(const char *, const char *, void *), void *ud) {
  size_t pl = strlen(prefix);
  for (size_t i = 0; i < p->n; i++)
    if (strncmp(p->keys[i], prefix, pl) == 0) cb(p->keys[i], p->vals[i], ud);
}

/* ------------------------------------------------------------------- strings */

bool rd_starts_with(const char *s, const char *p) {
  return strncmp(s, p, strlen(p)) == 0;
}

bool rd_contains(const char *hay, const char *needle) {
  return hay && needle && strstr(hay, needle) != NULL;
}

bool rd_contains_ci(const char *hay, const char *needle) {
  if (!hay || !needle || !*needle) return false;
  size_t nl = strlen(needle);
  for (const char *p = hay; *p; p++) {
    size_t i = 0;
    while (i < nl && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) i++;
    if (i == nl) return true;
  }
  return false;
}

void rd_appendf(char *buf, size_t bufsz, const char *fmt, ...) {
  size_t used = strlen(buf);
  if (used + 1 >= bufsz) return;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf + used, bufsz - used, fmt, ap);
  va_end(ap);
}

/* Names used by root / root-hiding frameworks. Kept in one place so every check
 * agrees on what "suspicious" means. */
static const char *const RD_KEYWORDS[] = {
    "magisk",  "kernelsu", "ksud",    "susfs",      "zygisk",   "lsposed",
    "riru",    "shamiko",  "supersu", "daemonsu",   "xposed",   "substrate",
    "rootcloak","apatch",  "kernelpatch", "frida",  "tricky_store", "integrityfix",
    "resetprop", "busybox", "nohello", "hide_root", "hideroot", "kpatch",
};
static const size_t RD_KEYWORD_COUNT = sizeof(RD_KEYWORDS) / sizeof(RD_KEYWORDS[0]);

bool rd_has_keyword(const char *s, const char **which) {
  if (!s) return false;
  for (size_t i = 0; i < RD_KEYWORD_COUNT; i++) {
    if (rd_contains_ci(s, RD_KEYWORDS[i])) {
      if (which) *which = RD_KEYWORDS[i];
      return true;
    }
  }
  return false;
}

bool rd_read_first_line(const char *path, char *buf, size_t bufsz) {
  if (!rd_read_small(path, buf, bufsz)) return false;
  char *nl = strchr(buf, '\n');
  if (nl) *nl = '\0';
  rd_trim(buf);
  return true;
}

/* ------------------------------------------------------------ syscall probes */

const char *rd_probe_res_name(int r) {
  switch (r) {
    case 0: return "exists";
    case 1: return "ENOENT";
    case -1: return "blocked";
    case -2: return "n/a";
    default: return "?";
  }
}

int rd_probe_stat(const char *path, long long *size_out, unsigned *mode_out) {
  struct stat st;
  if (stat(path, &st) == 0) {
    if (size_out) *size_out = (long long)st.st_size;
    if (mode_out) *mode_out = (unsigned)st.st_mode;
    return 0;
  }
  return errno == ENOENT || errno == ENOTDIR ? 1 : -1;
}

int rd_probe_lstat(const char *path) {
  struct stat st;
  if (lstat(path, &st) == 0) return 0;
  return errno == ENOENT || errno == ENOTDIR ? 1 : -1;
}

int rd_probe_fstatat(const char *path) {
  struct stat st;
  if (fstatat(AT_FDCWD, path, &st, AT_SYMLINK_NOFOLLOW) == 0) return 0;
  return errno == ENOENT || errno == ENOTDIR ? 1 : -1;
}

#ifdef __NR_statx
int rd_probe_statx(const char *path) {
  struct statx stx;
  memset(&stx, 0, sizeof(stx));
  long r = syscall(__NR_statx, AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stx);
  if (r == 0) return 0;
  return errno == ENOENT || errno == ENOTDIR ? 1 : -1;
}
#endif

int rd_probe_access(const char *path) {
  if (access(path, F_OK) == 0) return 0;
  return errno == ENOENT || errno == ENOTDIR ? 1 : -1;
}

int rd_probe_open_o_path(const char *path) {
  int fd = open(path, O_PATH | O_CLOEXEC);
  if (fd >= 0) { close(fd); return 0; }
  return errno == ENOENT || errno == ENOTDIR ? 1 : -1;
}

int rd_probe_open_read(const char *path) {
  /* O_NONBLOCK matters: the artefact corpus includes paths under
   * /data/local/tmp/, and that directory is writable by any `adb shell` user.
   * Opening a FIFO there for reading blocks until a writer appears, which let an
   * unprivileged user hang the whole scan (including a root run) indefinitely.
   * With O_NONBLOCK the open returns immediately; the file still counts as
   * present, so the vote is unchanged. */
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd >= 0) { close(fd); return 0; }
  return errno == ENOENT || errno == ENOTDIR ? 1 : -1;
}

int rd_probe_opendir(const char *path) {
  DIR *d = opendir(path);
  if (d) { closedir(d); return 0; }
  /* ENOTDIR means the path exists but is not a directory: the probe does not
   * apply, so it must not vote (otherwise every regular file would look
   * "inconsistent" and produce a CRITICAL false positive). */
  if (errno == ENOTDIR) return -2;
  return errno == ENOENT ? 1 : -1;
}

/* True when the directory holding `path` is writable by group or others, i.e.
 * someone else could replace that file. Fills `dir` with the directory. Used by
 * both the self-executable check and the ABI helper trust check. */
bool rd_dir_writable_by_others(const char *path, char *dir, size_t dirsz) {
  if (dir && dirsz) dir[0] = '\0';
  char tmp[512];
  snprintf(tmp, sizeof(tmp), "%s", path);
  char *slash = strrchr(tmp, '/');
  if (!slash) {
    /* A bare filename is relative to the current directory, not to "/".
     * Returning false here skipped the guard entirely, so pointing
     * ROOTDETECT_ABI_HELPER at ./helper in a world-writable cwd bypassed the
     * "parent directory is not group/other writable" check. */
    if (dir && dirsz) snprintf(dir, dirsz, ".");
    struct stat cwd;
    if (stat(".", &cwd) != 0) return false;
    return (cwd.st_mode & (S_IWGRP | S_IWOTH)) != 0;
  }
  *slash = '\0';
  struct stat ds;
  if (stat(tmp[0] ? tmp : "/", &ds) != 0) return false;
  if (dir && dirsz) snprintf(dir, dirsz, "%s", tmp[0] ? tmp : "/");
  return (ds.st_mode & (S_IWGRP | S_IWOTH)) != 0;
}

int rd_probe_readlink(const char *path) {
  char buf[8];
  ssize_t r = readlink(path, buf, sizeof(buf));
  if (r >= 0) return 0;
  return errno == ENOENT || errno == ENOTDIR ? 1 : -1;
}

/* A symlink whose target does not exist: lstat sees it, stat/open/access do not.
 * That pattern is produced by the nofollow probes disagreeing with the follow
 * probes, which would otherwise be reported as a kstat hiding layer - and any
 * shell user can plant one (review B1: /data/local/tmp/su is writable). */
bool rd_is_dangling_symlink(const char *path) {
  struct stat ls, st;
  if (lstat(path, &ls) != 0 || !S_ISLNK(ls.st_mode)) return false;
  return stat(path, &st) != 0 && errno == ENOENT;
}

void rd_probe_all(const char *path, rd_probe_row *row) {
  memset(row, 0, sizeof(*row));
  row->size = -1;
  row->stat_r = rd_probe_stat(path, &row->size, &row->mode);
#ifndef __NR_statx
  row->statx_r = -2;
#else
  row->statx_r = rd_probe_statx(path);
#endif
  row->fstatat_r = rd_probe_fstatat(path);
  row->access_r = rd_probe_access(path);
  row->open_path_r = rd_probe_open_o_path(path);
  row->open_read_r = rd_probe_open_read(path);
  row->opendir_r = rd_probe_opendir(path);
}

void rd_format_row(const char *path, const rd_probe_row *row, char *buf, size_t bufsz) {
  snprintf(buf, bufsz,
           "%-38s stat=%-7s statx=%-7s fstatat=%-7s access=%-7s open_path=%-7s open_read=%-7s opendir=%-7s",
           path, rd_probe_res_name(row->stat_r), rd_probe_res_name(row->statx_r),
           rd_probe_res_name(row->fstatat_r), rd_probe_res_name(row->access_r),
           rd_probe_res_name(row->open_path_r), rd_probe_res_name(row->open_read_r),
           rd_probe_res_name(row->opendir_r));
}

bool rd_row_inconsistent(const rd_probe_row *row, char *cons_out, size_t cons_sz) {
  /* -2 marks a probe this build cannot perform; blocked (-1) results are not
   * evidence of absence and are ignored for the exists/absent vote. */
  const struct { const char *n; int v; } probes[] = {
      {"stat", row->stat_r},         {"statx", row->statx_r},
      {"fstatat", row->fstatat_r},   {"access", row->access_r},
      {"open_path", row->open_path_r}, {"open_read", row->open_read_r},
      {"opendir", row->opendir_r},
  };
  const char *yes[8];
  const char *no[8];
  size_t ny = 0, nn = 0;
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
    if (probes[i].v == 0) yes[ny++] = probes[i].n;
    else if (probes[i].v == 1) no[nn++] = probes[i].n;
  }
  if (!ny || !nn) return false;
  /* Callers may pass a NULL buffer to ask "is this row inconsistent?". Returning
   * here also removes the cons_sz-1 pointer arithmetic below, which was UB for
   * cons_sz == 0 (cons_out + SIZE_MAX). Found by the t2 self-test review. */
  if (!cons_sz || !cons_out) return true;
  size_t o = 0;
  if (cons_sz) cons_out[0] = '\0';
  for (size_t i = 0; i < ny && o < cons_sz; i++)
    o += (size_t)snprintf(cons_out + o, cons_sz - o, "%s%s sees it", i ? "," : "", yes[i]);
  o += (size_t)snprintf(cons_out + (o < cons_sz ? o : cons_sz - 1),
                        cons_sz > o ? cons_sz - o : 0, " but ");
  for (size_t i = 0; i < nn && o < cons_sz; i++)
    o += (size_t)snprintf(cons_out + o, cons_sz - o, "%s%s says ENOENT", i ? "," : "", no[i]);
  return true;
}

const char *rd_abi_name(void) {
#if defined(__aarch64__)
  return "arm64-v8a";
#elif defined(__x86_64__)
  return "x86_64";
#elif defined(__arm__)
  return "armeabi-v7a";
#elif defined(__i386__)
  return "x86";
#else
  return "unknown";
#endif
}
