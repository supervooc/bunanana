/* rootdetect - self-test.
 *
 * Three kinds of checks:
 *   1. pure logic  - the decision primitives (voting across syscalls, verdict
 *      mapping, escaping) fed with synthetic inputs;
 *   2. live probes - the same primitives against real paths, portable between
 *      Android and a plain Linux kernel (WSL);
 *   3. live guards - the checks that could most easily produce a false positive
 *      are verified to be *silent* here: uname() must agree with
 *      /proc/sys/kernel/osrelease, and all four mount views must list the same
 *      mount points on a clean system.
 *
 * Run it on the target:  ./rootdetect --selftest
 */
#include "rd.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

static int g_checks, g_fails, g_skips;

static void ok(int cond, const char *what, const char *detail) {
  g_checks++;
  if (cond) {
    printf("  PASS  %s\n", what);
  } else {
    g_fails++;
    printf("  FAIL  %s%s%s\n", what, detail && *detail ? "  ->  " : "",
           detail && *detail ? detail : "");
  }
}

/* A check that cannot run in this environment (e.g. properties on a non-Android
 * kernel) is reported as SKIP, never as a failure - otherwise the self-test
 * would cry wolf on any Linux box. */
static void skip(const char *what, const char *why) {
  g_skips++;
  printf("  SKIP  %s%s%s\n", what, why && *why ? "  ->  " : "", why && *why ? why : "");
}

static void set_all(rd_probe_row *r, int v) {
  r->stat_r = r->statx_r = r->fstatat_r = r->access_r = r->open_path_r = r->open_read_r =
      r->opendir_r = v;
}

/* ------------------------------------------------------------ test helpers */

static const rd_finding *find_finding(const rd_report *r, const char *id) {
  for (size_t i = 0; i < r->n; i++)
    if (strcmp(r->items[i].id, id) == 0) return &r->items[i];
  return NULL;
}

static void free_set(char **set, size_t n) {
  for (size_t i = 0; i < n; i++) free(set[i]);
}

static bool set_has(char *const *set, size_t n, const char *v) {
  for (size_t i = 0; i < n; i++)
    if (strcmp(set[i], v) == 0) return true;
  return false;
}

static bool set_eq(char *const *a, size_t na, char *const *b, size_t nb) {
  if (na != nb) return false;
  for (size_t i = 0; i < na; i++)
    if (!set_has(b, nb, a[i])) return false;
  return true;
}

/* One comma separated line describing a parsed target set, for FAIL details. */
static void set_fmt(char *const *a, size_t na, char *out, size_t osz) {
  if (!osz) return;
  out[0] = '\0';
  size_t o = 0;
  for (size_t i = 0; i < na && o + 1 < osz; i++)
    o += (size_t)snprintf(out + o, osz - o, "%s%s", i ? "," : "", a[i]);
}

/* Directory of the running executable. On Android the only writable place for
 * the parser tests is the binary's own dir when the APK ran it from the copy in
 * the app's private files dir (a shell/app uid cannot write /data/local/tmp). */
static const char *exe_dir(void) {
  static char d[512];
  static int done = 0;
  if (!done) {
    done = 1;
    ssize_t n = readlink("/proc/self/exe", d, sizeof d - 1);
    if (n <= 0) { d[0] = '\0'; return d; }
    d[n] = '\0';
    char *s = strrchr(d, '/');
    if (s) *s = '\0';
  }
  return d;
}

/* Create a private temp file with `body` in it. Prefers /data/local/tmp on a
 * device, /tmp (then $TMPDIR, then the exe dir) on a plain Linux kernel. */
static bool tmp_write_file(char *path, size_t psz, const char *body) {
  const char *dirs[4] = {"/data/local/tmp", "/tmp", getenv("TMPDIR"), exe_dir()};
  int fd = -1;
  for (int i = 0; i < 4 && fd < 0; i++) {
    if (!dirs[i] || !dirs[i][0]) continue;
    snprintf(path, psz, "%s/rootdetect-selftest-XXXXXX", dirs[i]);
    fd = mkstemp(path);
  }
  if (fd < 0) { path[0] = '\0'; return false; }
  size_t n = strlen(body), o = 0;
  while (o < n) {
    ssize_t w = write(fd, body + o, n - o);
    if (w <= 0) break;
    o += (size_t)w;
  }
  close(fd);
  if (o != n) { unlink(path); path[0] = '\0'; return false; }
  return true;
}

/* --------------------------------------------------------------- pure logic */

static void test_logic(void) {
  printf("-- decision logic --\n");
  char why[160];

  ok(rd_has_keyword("com.topjohnwu.magisk", NULL), "keyword: magisk package name", NULL);
  ok(rd_has_keyword("/system/xbin/SuSFS", NULL), "keyword: matching is case-insensitive", NULL);
  ok(rd_has_keyword("susfs_guard_lkm", NULL), "keyword: kernel module name", NULL);
  ok(!rd_has_keyword("/system/bin/sh", NULL), "keyword: ordinary path is not flagged", NULL);
  ok(!rd_has_keyword("/system/bin/getprop", NULL), "keyword: getprop is not a root hint", NULL);
  ok(!rd_has_keyword("/data/misc/keystore", NULL), "keyword: keystore is not a root hint", NULL);

  ok(rd_contains_ci("KernelSU-Next", "kernelsu"), "contains_ci: mixed case", NULL);
  ok(!rd_contains_ci("kernel", "kernelsu"), "contains_ci: no false substring match", NULL);

  /* the vote table is what turns a hide module's partial coverage into a finding */
  rd_probe_row r;
  memset(&r, 0, sizeof r);
  set_all(&r, 0);
  ok(!rd_row_inconsistent(&r, why, sizeof why), "vote: all interfaces see it -> consistent", why);
  memset(&r, 0, sizeof r);
  set_all(&r, 1);
  ok(!rd_row_inconsistent(&r, why, sizeof why), "vote: all interfaces say ENOENT -> consistent", why);
  memset(&r, 0, sizeof r);
  set_all(&r, -2);
  ok(!rd_row_inconsistent(&r, why, sizeof why), "vote: no usable probe -> not a finding", why);
  memset(&r, 0, sizeof r);
  set_all(&r, -1);
  ok(!rd_row_inconsistent(&r, why, sizeof why), "vote: everything blocked (SELinux) -> not a finding", why);
  memset(&r, 0, sizeof r);
  set_all(&r, 0);
  r.stat_r = 1; /* kstat layer says "gone" while open() still sees it */
  r.statx_r = 1;
  ok(rd_row_inconsistent(&r, why, sizeof why), "vote: stat family says ENOENT but open sees it -> finding", why);
  ok(rd_contains(why, "stat"), "vote: reason names the disagreeing probes", why);
  memset(&r, 0, sizeof r);
  set_all(&r, 0);
  r.opendir_r = 1; /* opendir on a regular file must be -2, never a vote */
  ok(rd_row_inconsistent(&r, why, sizeof why), "vote: a disagreeing opendir is reported", why);

  /* -2 (probe not applicable) and -1 (probe blocked) are both non-votes: mixing
   * them must never manufacture a finding, and they must not be named in the
   * reason either. */
  memset(&r, 0, sizeof r);
  set_all(&r, -2);
  r.stat_r = -1;
  r.access_r = -1;
  ok(!rd_row_inconsistent(&r, why, sizeof why), "vote: -2/-1 mix alone is not a finding", why);
  /* A single vote cannot contradict anything. */
  memset(&r, 0, sizeof r);
  set_all(&r, -1);
  r.stat_r = 0;
  ok(!rd_row_inconsistent(&r, why, sizeof why), "vote: one lone 'exists' vote is not a finding", why);
  memset(&r, 0, sizeof r);
  set_all(&r, -1);
  r.access_r = 1;
  ok(!rd_row_inconsistent(&r, why, sizeof why), "vote: one lone ENOENT vote is not a finding", why);
  /* The classic hidden signature: the stat family is hooked, access() is not. */
  memset(&r, 0, sizeof r);
  set_all(&r, 1);
  r.access_r = 0;
  ok(rd_row_inconsistent(&r, why, sizeof why), "vote: stat says ENOENT but access sees it -> finding", why);
  ok(rd_contains(why, "access") && rd_contains(why, "stat"),
     "vote: reason names the two disagreeing probes", why);
  memset(&r, 0, sizeof r);
  set_all(&r, -2);
  r.stat_r = 0;
  r.access_r = 1;
  ok(rd_row_inconsistent(&r, why, sizeof why), "vote: disagreement survives surrounding -2 probes", why);
  ok(rd_contains(why, "stat") && rd_contains(why, "access") && !rd_contains(why, "opendir"),
     "vote: -2 probes are left out of the reason", why);
  /* A 4 byte reason buffer must stay NUL terminated and in bounds. */
  memset(&r, 0, sizeof r);
  set_all(&r, 0);
  r.stat_r = 1;
  char tiny[4];
  memset(tiny, '#', sizeof tiny);
  rd_row_inconsistent(&r, tiny, sizeof tiny);
  ok(tiny[sizeof tiny - 1] == '\0', "vote: reason is NUL terminated inside a tiny buffer", tiny);

  char esc[256];
  rd_json_escape("a\"b\\c\nd\te", esc, sizeof esc);
  ok(strcmp(esc, "a\\\"b\\\\c\\nd\\te") == 0, "json escaping of quotes/backslash/control chars", esc);
  rd_json_escape("\x01\x02", esc, sizeof esc);
  ok(strcmp(esc, "\\u0001\\u0002") == 0, "json escaping of raw control bytes", esc);
  /* -j must stay valid UTF-8 (RFC 8259): a well-formed sequence is kept, and a
   * malformed byte is replaced with U+FFFD. */
  rd_json_escape("a\xff b", esc, sizeof esc);
  ok(strcmp(esc, "a\xef\xbf\xbd b") == 0,
     "json escaping replaces an invalid UTF-8 byte with U+FFFD", esc);
  rd_json_escape("\xe4\xbd\xa0\xe5\xa5\xbd", esc, sizeof esc);
  ok(strcmp(esc, "\xe4\xbd\xa0\xe5\xa5\xbd") == 0,
     "json escaping keeps a valid multi-byte UTF-8 sequence intact", esc);
  rd_json_escape("\xe0\x80\x80", esc, sizeof esc); /* overlong NUL */
  ok(strcmp(esc, "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd") == 0,
     "json escaping rejects an overlong sequence byte by byte", esc);

  char buf[16] = "abc";
  rd_appendf(buf, sizeof buf, "%s", "0123456789abcdefghij");
  ok(strlen(buf) == 15, "appendf never overflows its buffer", buf);

  char t[32];
  snprintf(t, sizeof t, "  /proc/version  \n");
  rd_trim(t);
  ok(strcmp(t, "/proc/version") == 0, "trim removes surrounding whitespace/newlines", t);

  /* --- trim boundaries -------------------------------------------------- */
  snprintf(t, sizeof t, "   \t\n");
  ok(rd_trim(t) == 0 && t[0] == '\0', "trim: all whitespace -> empty string", t);
  t[0] = '\0';
  ok(rd_trim(t) == 0, "trim: empty string stays empty", t);
  snprintf(t, sizeof t, "  \t/dev/rd \r\n");
  ok(rd_trim(t) == 7 && strcmp(t, "/dev/rd") == 0, "trim: leading tab and trailing CRLF", t);
  snprintf(t, sizeof t, "/dev/rd");
  ok(rd_trim(t) == 7 && strcmp(t, "/dev/rd") == 0, "trim: no whitespace -> unchanged", t);

  /* --- json escape boundaries ------------------------------------------
   * The worst case for one input byte is "\uXXXX" (6 bytes), so a plain byte
   * needs outsz >= len + 7. These checks pin the exact behaviour at the edge. */
  char e[64];
  memset(e, '#', sizeof e);
  rd_json_escape("abc", e, 10); /* minimal buffer that can hold 3 plain bytes */
  ok(strcmp(e, "abc") == 0, "json: minimal (len+7) buffer keeps the whole string", e);
  ok(e[4] == '#' && e[63] == '#', "json: nothing written past the used bytes", NULL);
  memset(e, '#', sizeof e);
  rd_json_escape("abc", e, 9); /* one byte less -> last byte dropped */
  ok(strcmp(e, "ab") == 0, "json: one byte short truncates the last character", e);
  memset(e, '#', sizeof e);
  rd_json_escape("abc", e, 1); /* only room for the terminator */
  ok(e[0] == '\0' && e[1] == '#', "json: a 1 byte buffer yields an empty string", NULL);
  memset(e, '#', sizeof e);
  rd_json_escape("abc", e, 0); /* size 0: must not touch the buffer at all */
  ok(e[0] == '#', "json: outsz 0 leaves the buffer untouched", NULL);
  memset(e, '#', sizeof e);
  rd_json_escape("", e, sizeof e);
  ok(e[0] == '\0', "json: empty input -> empty output", NULL);
  memset(e, '#', sizeof e);
  rd_json_escape("\"\\\n\x01", e, sizeof e);
  ok(strcmp(e, "\\\"\\\\\\n\\u0001") == 0,
     "json: quote/backslash/newline/control-byte combination", e);
  memset(e, '#', sizeof e);
  rd_json_escape("0123456789012345678901234567890123456789", e, 32);
  ok(strlen(e) > 0 && strlen(e) < 32 && e[32] == '#' && e[63] == '#',
     "json: long string truncated in bounds, sentinel past the buffer intact", e);

  /* --- text escape: the terminal report must not carry live control bytes ---
   * Evidence is built from another process's own files, so ESC/CR/DEL and the
   * 8-bit CSI (0x9B, which a non-UTF-8 locale still honours) have to come out as
   * printable text - otherwise a process can erase the finding that exposes it. */
  char te[64];
  memset(te, '#', sizeof te);
  size_t tn = rd_text_escape("/x/\x1b[2K\rFORGED", 14, te, sizeof te);
  ok(strcmp(te, "/x/\\x1b[2K\\x0dFORGED") == 0, "text escape: ESC and CR become \\xNN", te);
  ok(tn == strlen(te), "text escape: returns the number of bytes written", NULL);
  ok(strchr(te, '\x1b') == NULL && strchr(te, '\r') == NULL,
     "text escape: no live control byte survives", NULL);
  memset(te, '#', sizeof te);
  rd_text_escape("\x7f\x9b\xff", 3, te, sizeof te);
  ok(strcmp(te, "\\x7f\\x9b\\xff") == 0,
     "text escape: DEL, the 8-bit CSI and a lone 0xff are escaped", te);
  memset(te, '#', sizeof te);
  rd_text_escape("\xe4\xbd\xa0\xe5\xa5\xbd", 6, te, sizeof te);
  ok(strcmp(te, "\xe4\xbd\xa0\xe5\xa5\xbd") == 0,
     "text escape: valid UTF-8 (a Chinese path) passes through", te);
  memset(te, '#', sizeof te);
  rd_text_escape("/sbin/su", 8, te, sizeof te);
  ok(strcmp(te, "/sbin/su") == 0, "text escape: an ordinary path is unchanged", te);
  /* Worst case is 4 bytes per input byte, plus the terminator: pin the edge. */
  memset(te, '#', sizeof te);
  rd_text_escape("\x01\x02\x03", 3, te, 13);
  ok(strcmp(te, "\\x01\\x02\\x03") == 0 && te[12] == '\0' && te[13] == '#',
     "text escape: an exact (4*n+1) buffer holds every byte", te);
  memset(te, '#', sizeof te);
  rd_text_escape("\x01\x02\x03", 3, te, 12);
  ok(strcmp(te, "\\x01\\x02") == 0 && te[8] == '\0' && te[12] == '#',
     "text escape: one byte short drops the last escape whole", te);
  memset(te, '#', sizeof te);
  rd_text_escape("abc", 3, te, 0);
  ok(te[0] == '#', "text escape: outsz 0 touches nothing", NULL);

  /* --- appendf / format_row overrun guards ------------------------------ */
  char ab[32];
  memset(ab, '#', sizeof ab);
  snprintf(ab, 8, "abcdefg"); /* exactly full: 7 chars + NUL */
  rd_appendf(ab, 8, "XYZ");
  ok(strcmp(ab, "abcdefg") == 0, "appendf: an already full buffer is left alone", ab);
  memset(ab, '#', sizeof ab);
  ab[0] = '\0';
  rd_appendf(ab, 1, "XYZ");
  ok(ab[0] == '\0' && ab[1] == '#', "appendf: bufsz 1 is a no-op", NULL);
  memset(ab, '#', sizeof ab);
  snprintf(ab, sizeof ab, "abc");
  rd_appendf(ab, sizeof ab, "def");
  ok(strcmp(ab, "abcdef") == 0 && ab[7] == '#', "appendf: appends after existing text", ab);
  memset(ab, '#', sizeof ab);
  ab[0] = '\0';
  rd_appendf(ab, 16, "%s", "0123456789abcdefghij");
  ok(strlen(ab) == 15 && ab[16] == '#', "appendf: truncates at bufsz-1, never writes past", ab);

  rd_probe_row fr;
  memset(&fr, 0, sizeof fr);
  set_all(&fr, 0);
  char row[128];
  memset(row, '#', sizeof row);
  rd_format_row("/x", &fr, row, 64);
  ok(strncmp(row, "/x ", 3) == 0 && strlen(row) < 64 && row[64] == '#',
     "format_row: truncated inside the buffer, sentinel past it intact", row);
  memset(row, '#', sizeof row);
  rd_format_row("/x", &fr, row, 0);
  ok(row[0] == '#', "format_row: bufsz 0 writes nothing", NULL);

  /* verdict mapping: only an explicit mechanism earns the strongest verdict */
  rd_report rep;
  rd_report_init(&rep);
  rd_add(&rep, SEV_INFO, "env-context", "context", "x");
  rd_add(&rep, SEV_MEDIUM, "env-build", "userdebug", "x");
  rd_finalize(&rep);
  ok(strcmp(rep.verdict, "SUSPICIOUS") == 0, "verdict: medium only -> SUSPICIOUS", rep.verdict);
  rd_add(&rep, SEV_HIGH, "artefact-present", "su found", "x");
  rd_finalize(&rep);
  ok(strcmp(rep.verdict, "ROOT_DETECTED") == 0, "verdict: high -> ROOT_DETECTED", rep.verdict);
  ok((rep.flags & RD_F_ROOT) != 0, "flags: artefact sets RD_F_ROOT", NULL);
  rd_add(&rep, SEV_CRITICAL, "spoof-uname", "uname spoofed", "x");
  rd_finalize(&rep);
  ok(strcmp(rep.verdict, "HIDING_DETECTED") == 0, "verdict: critical -> HIDING_DETECTED", rep.verdict);
  ok((rep.flags & RD_F_HIDE) != 0, "flags: spoof sets RD_F_HIDE", NULL);
  rd_report_free(&rep);

  /* coverage bookkeeping: a check that could not run is recorded once, and an
   * ordinary (successful) informational finding never enters the list. */
  rd_report rep3;
  rd_report_init(&rep3);
  rd_add_skip(&rep3, SEV_INFO, "env-selinux", "unavailable", "x");
  rd_add_skip(&rep3, SEV_INFO, "kernel-module", "unreadable", "x");
  rd_add_skip(&rep3, SEV_INFO, "env-selinux", "unavailable", "x");
  rd_add(&rep3, SEV_INFO, "kernel-kallsyms", "readable", "x");
  char skips[128];
  rd_skip_list(&rep3, skips, sizeof(skips));
  ok(rep3.n_skips == 2, "coverage: skipped ids are deduplicated", skips);
  ok(strcmp(skips, "env-selinux, kernel-module") == 0,
     "coverage: skipped ids are listed in scan order", skips);
  rd_report_free(&rep3);

  /* susfs_guard_lkm ids feed the right capabilities: a loaded LKM is a HOOK
   * artefact, its observed self-filter is HIDING, installer files are ROOT. */
  rd_report rep2;
  rd_report_init(&rep2);
  rd_add(&rep2, SEV_HIGH, "susfs-lkm-module", "lkm", "x");
  rd_finalize(&rep2);
  ok((rep2.flags & RD_F_HOOK) != 0 && (rep2.flags & RD_F_HIDE) == 0,
     "flags: loaded susfs_guard_lkm -> RD_F_HOOK", NULL);
  rd_add(&rep2, SEV_CRITICAL, "susfs-lkm-module-filtered", "lkm self-filter", "x");
  rd_finalize(&rep2);
  ok((rep2.flags & RD_F_HIDE) != 0 && strcmp(rep2.verdict, "HIDING_DETECTED") == 0,
     "flags: observed /proc/modules self-filter -> HIDING_DETECTED", rep2.verdict);
  rd_report_free(&rep2);
  rd_report_init(&rep2);
  rd_add(&rep2, SEV_HIGH, "susfs-lkm-artefact", "lkm files", "x");
  rd_finalize(&rep2);
  ok((rep2.flags & RD_F_ROOT) != 0, "flags: lkm installer files -> RD_F_ROOT", NULL);
  rd_report_free(&rep2);
  rd_report_init(&rep2);
  rd_add(&rep2, SEV_CRITICAL, "susfs-lkm-node-oracle", "syscall split", "x");
  rd_finalize(&rep2);
  ok((rep2.flags & RD_F_HIDE) != 0 && (rep2.flags & RD_F_HOOK) != 0 &&
         strcmp(rep2.verdict, "HIDING_DETECTED") == 0,
     "flags: non-root oracle tell -> HIDING_DETECTED", rep2.verdict);
  rd_report_free(&rep2);

  /* node-body fingerprints: match the documented counter shapes, reject
   * everything else (wrong node, missing counters, plain 0/1 bodies). */
  ok(rd_susfs_lkm_node_fingerprint(
         "/proc/susfs_opath",
         "[1] opath/openat nr=56 nr_compat=0 installed=1 wrapper=ffffffc0 orig=ffffffc0\n"
         "seen=4940 opath=1078 hidden=5 deny=5 err=0 (opath_test=0 opath_dump=0)") != NULL,
     "lkm fingerprint: /proc/susfs_opath counter block", NULL);
  ok(rd_susfs_lkm_node_fingerprint(
         "/proc/susfs_kstat",
         "/data/local/tmp/x ino=981881 dev=65099 flags=0xff3\nmaps: armed=1 hits=0 rewrites=0\n"
         "stat nr newfstatat (79): ok=3 rw=2") != NULL,
     "lkm fingerprint: /proc/susfs_kstat dispatcher counters", NULL);
  ok(rd_susfs_lkm_node_fingerprint("/proc/susfs_hide_modules",
                                   "hide_modules: 1/16 name(s)\nnames: susfs_guard_lkm") != NULL,
     "lkm fingerprint: /proc/susfs_hide_modules name list", NULL);
  ok(rd_susfs_lkm_node_fingerprint("/proc/susfs_path", "hide_from_apps=1  enoent: getattr=5") != NULL,
     "lkm fingerprint: /proc/susfs_path rule table", NULL);
  ok(rd_susfs_lkm_node_fingerprint("/proc/susfs_opath", "0\n1\n") == NULL,
     "lkm fingerprint: plain numbers are not a counter block", NULL);
  ok(rd_susfs_lkm_node_fingerprint("/proc/susfs_uname", "opath/openat nr=56") == NULL,
     "lkm fingerprint: a match on an unexpected path is rejected", NULL);
  ok(rd_susfs_lkm_node_fingerprint("/proc/susfs_enable_log", "1") == NULL,
     "lkm fingerprint: enable_log stays unidentifiable (plain 0/1)", NULL);
  ok(rd_susfs_lkm_node_fingerprint("/proc/susfs_kstat", "maps: armed=1 hits=0") == NULL,
     "lkm fingerprint: kstat needs both the maps line and a stat counter", NULL);
  ok(rd_susfs_lkm_node_fingerprint("/proc/susfs_kstat", "stat nr fstat (80): ok=1") == NULL,
     "lkm fingerprint: kstat without the maps line is rejected", NULL);
  /* v2.3.0-r18 bodies, verbatim from its PROC_INTERFACES.md sample output. */
  ok(rd_susfs_lkm_node_fingerprint(
         "/proc/susfs_hide_modules",
         "hide_modules: 1/16 name(s), /sys/module rules=1 (failed=0), /proc/modules lines removed=0, "
         "kallsyms lines removed=0\nnames: susfs_guard_lkm") != NULL,
     "lkm fingerprint: hide_modules body with the r18 counters", NULL);
  ok(rd_susfs_lkm_node_fingerprint(
         "/proc/susfs_hide_mounts",
         "mount prefixes: 2/64, rescans=1, recorded=0, hidden_by_identity=0, learned_ids=0\n"
         "prefixes: /data/adb/ /data/local/tmp/") != NULL,
     "lkm fingerprint: /proc/susfs_hide_mounts prefix table", NULL);
  ok(rd_susfs_lkm_node_fingerprint(
         "/proc/susfs_open_redirect",
         "(empty)\nhooks: forward=0 dpath=0 statfs=0 maps=0 fdinfo=0 | rev hits: dpath=0 statfs=0 "
         "maps=0/0/0 fdinfo=0/0 | su_sid=2907") != NULL,
     "lkm fingerprint: /proc/susfs_open_redirect hook counters", NULL);

  /* syscall-coverage oracle: a tell exists only when stat() denies a path and
   * another syscall resolves the SAME entry; -1 ("blocked") never votes, and a
   * reachable path is never a tell even when the other probes see it too. */
  ok(rd_susfs_lkm_oracle_tell(1, -1, 1, 1, 1) == 0,
     "oracle: all probes agree on ENOENT -> no tell", NULL);
  ok(rd_susfs_lkm_oracle_tell(0, 0, 0, 0, 0) == 0,
     "oracle: a reachable path is never a tell", NULL);
  ok(rd_susfs_lkm_oracle_tell(-1, 0, 0, 0, 0) == 0,
     "oracle: a blocked stat() cannot raise a tell", NULL);
  ok(rd_susfs_lkm_oracle_tell(1, 0, 1, 1, 1) == RD_TELL_MKDIR,
     "oracle: mkdir(2) EEXIST while stat() says ENOENT -> mkdir tell", NULL);
  ok(rd_susfs_lkm_oracle_tell(1, -1, 0, 1, 1) == RD_TELL_READLINK,
     "oracle: readlink(2) resolves while stat() says ENOENT -> readlink tell", NULL);
  ok(rd_susfs_lkm_oracle_tell(1, -1, 1, 0, 1) == RD_TELL_STATFS,
     "oracle: statfs(2) resolves while stat() says ENOENT -> statfs tell", NULL);
  ok(rd_susfs_lkm_oracle_tell(1, -1, 1, 1, 0) == RD_TELL_OPATH,
     "oracle: open(O_PATH) resolves while stat() says ENOENT -> O_PATH tell", NULL);
  ok(rd_susfs_lkm_oracle_tell(1, 0, 0, 0, 0) ==
         (RD_TELL_MKDIR | RD_TELL_READLINK | RD_TELL_STATFS | RD_TELL_OPATH),
     "oracle: several resolving syscalls -> combined bitmask", NULL);
}

/* --------------------------------------------------------------- live probes */

static void test_live_probes(void) {
  printf("-- live filesystem probes --\n");
  char why[160];
  rd_probe_row r;

  /* /proc/version exists on Android and on a plain Linux kernel alike. */
  rd_probe_all("/proc/version", &r);
  ok(!rd_row_inconsistent(&r, why, sizeof why), "real file: probes agree", why);
  ok(r.stat_r == 0 && r.open_read_r == 0 && r.access_r == 0,
     "real file: stat/open/access all see /proc/version", NULL);
  ok(r.opendir_r == -2, "real regular file: opendir votes 'not applicable' (-2)", NULL);

  rd_probe_all("/proc/rootdetect-definitely-not-here", &r);
  ok(!rd_row_inconsistent(&r, why, sizeof why), "absent file: probes agree it is absent", why);
  ok(r.stat_r == 1 && r.open_read_r == 1, "absent file: stat and open both say ENOENT", NULL);

  /* Pick the first writable staging directory: a device has /data/local/tmp, a
   * plain Linux boot (the QEMU/WSL harness) has /tmp. */
  const char *tmpdirs[4] = {"/data/local/tmp", "/tmp", getenv("TMPDIR"), exe_dir()};
  char p[320] = "";
  int fd = -1;
  for (size_t i = 0; i < 4; i++) {
    if (!tmpdirs[i] || !tmpdirs[i][0]) continue;
    snprintf(p, sizeof p, "%s/rootdetect-self-XXXXXX", tmpdirs[i]);
    fd = mkstemp(p);
    if (fd >= 0) break;
  }
  if (fd >= 0) {
    close(fd);
    rd_probe_all(p, &r);
    ok(!rd_row_inconsistent(&r, why, sizeof why), "created file: probes agree", why);
    ok(r.stat_r == 0 && r.open_read_r == 0 && r.opendir_r == -2,
       "created file: file serves stat/open, opendir is not applicable (-2)", NULL);
    unlink(p);
    rd_probe_all(p, &r);
    ok(r.stat_r == 1, "unlinked file: stat reports ENOENT again", NULL);
  } else {
    skip("created file probes", "no writable /data/local/tmp, /tmp or $TMPDIR");
  }

  char link[64];
  long lr = rd_read_link("/proc/self/exe", link, sizeof link);
  ok(lr >= 0, "readlink(/proc/self/exe) works", lr < 0 ? strerror(errno) : link);

  /* Oracle probe plumbing: an absent path must never be reported as existing,
   * and the create-family probe must never leave anything behind. */
  const char *absent = "/sys/module/rootdetect-selftest-absent";
  int mk = rd_probe_mkdir_exists(absent);
  ok(mk != 0, "oracle probe: an absent /sys/module entry never answers EEXIST",
     mk == -1 ? "probe refused (parent writable by this caller)" : "ENOENT/EACCES path");
  ok(rd_probe_lstat(absent) == 1, "oracle probe: the mkdir probe created nothing", NULL);
  ok(rd_probe_statfs_exists("/proc") == 0, "oracle probe: statfs resolves an existing directory", NULL);
  ok(rd_probe_statfs_exists("/proc/rootdetect-selftest-absent") == 1,
     "oracle probe: statfs on an absent /proc name votes ENOENT", NULL);
  ok(rd_probe_readlink_exists("/proc/self/exe") == 0,
     "oracle probe: readlink resolves the /proc/self/exe symlink", NULL);
  ok(rd_probe_readlink_exists("/proc/rootdetect-selftest-absent") == 1,
     "oracle probe: readlink on an absent /proc name votes ENOENT", NULL);
}

/* ---------------------------------------------------- mount parser bounds */

/* Regression guard for the bug that produced a CRITICAL false positive: the
 * mountinfo / mountstats mount-point field (4) must yield exactly the same
 * target set as /proc/mounts (field 1), octal escapes included. The synthetic
 * mountinfo lines deliberately use a *different* root field (/subtree) so that
 * a wrong field index cannot pass this test. */
static void test_mount_parsers(void) {
  printf("-- mount target parsers --\n");
  static const char *mounts_body =
      "/dev/block/sda1 / ext4 rw,relatime 0 0\n"
      "tmpfs /dev tmpfs rw,nosuid 0 0\n"
      "/dev/block/sda2 /mnt/with\\040space ext4 rw 0 0\n"
      "/dev/block/sda3 /mnt/tab\\011sep ext4 rw 0 0\n"
      "/dev/block/sda4 /mnt/back\\134slash ext4 rw 0 0\n"
      "overlay /system overlay rw 0 0\n";
  static const char *mountinfo_body =
      "36 1 8:1 / / rw,relatime shared:1 - ext4 /dev/block/sda1 rw\n"
      "37 1 0:5 / /dev rw,nosuid shared:2 - tmpfs tmpfs rw\n"
      "38 1 8:2 /subtree /mnt/with\\040space rw,relatime shared:3 - ext4 /dev/block/sda2 rw\n"
      "39 1 8:3 /subtree /mnt/tab\\011sep rw,relatime shared:4 - ext4 /dev/block/sda3 rw\n"
      "40 1 8:4 /subtree /mnt/back\\134slash rw,relatime shared:5 - ext4 /dev/block/sda4 rw\n"
      "41 1 0:26 / /system rw shared:6 - overlay overlay rw\n";
  static const char *mountstats_body =
      "device /dev/block/sda1 mounted on / with fstype ext4\n"
      "device tmpfs mounted on /dev with fstype tmpfs\n"
      "device /dev/block/sda2 mounted on /mnt/with\\040space with fstype ext4\n"
      "device /dev/block/sda3 mounted on /mnt/tab\\011sep with fstype ext4\n"
      "device /dev/block/sda4 mounted on /mnt/back\\134slash with fstype ext4\n"
      "device overlay mounted on /system with fstype overlay\n";
  char *want[] = {"/", "/dev", "/mnt/with space", "/mnt/tab\tsep", "/mnt/back\\slash",
                  "/system"};
  const size_t nwant = sizeof(want) / sizeof(want[0]);

  char pm[320] = "", pi[320] = "", ps[320] = "";
  if (!tmp_write_file(pm, sizeof pm, mounts_body) ||
      !tmp_write_file(pi, sizeof pi, mountinfo_body) ||
      !tmp_write_file(ps, sizeof ps, mountstats_body)) {
    if (pm[0]) unlink(pm);
    if (pi[0]) unlink(pi);
    if (ps[0]) unlink(ps);
    skip("mount target parsing (mounts/mountinfo/mountstats)",
         "no writable /data/local/tmp, /tmp or $TMPDIR");
    return;
  }

  enum { MAXM = 64 };
  char *a[MAXM], *b[MAXM], *c[MAXM], *wrong[MAXM], *cap[MAXM], *none[MAXM];
  size_t na = rd_collect_mount_targets(pm, 1, a, MAXM);
  size_t nb = rd_collect_mount_targets(pi, 4, b, MAXM);
  size_t nc = rd_collect_mount_targets(ps, 4, c, MAXM);
  size_t nw = rd_collect_mount_targets(pi, 3, wrong, MAXM); /* the wrong-field control */
  size_t ncap = rd_collect_mount_targets(pm, 1, cap, 3);
  size_t nnone = rd_collect_mount_targets("/proc/rootdetect-no-such-mounts", 1, none, MAXM);

  char d[512], d2[512], d3[256], d4[1024];
  set_fmt(a, na, d, sizeof d);
  set_fmt(b, nb, d2, sizeof d2);
  set_fmt(c, nc, d3, sizeof d3);
  snprintf(d4, sizeof d4, "mounts=%s | mountstats=%s", d, d3);
  ok(na == nwant, "mounts(field=1): every mount point parsed exactly once", d);
  int decoded = 1;
  for (size_t i = 0; i < nwant; i++)
    if (!set_has(a, na, want[i])) decoded = 0;
  ok(decoded, "mounts: \\040 \\011 \\134 unescaped to space/tab/backslash", d);
  ok(set_eq(a, na, b, nb), "mountinfo(field=4) yields the same target set as mounts(field=1)", d2);
  ok(set_eq(a, na, c, nc), "mountstats(field=4) yields the same target set as mounts(field=1)", d4);
  ok(!set_has(b, nb, "/subtree"),
     "mountinfo(field=4): the root field is not read as the mount point", d2);
  ok(nw > 0 && !set_eq(a, na, wrong, nw),
     "control: field=3 returns the root field set, i.e. a wrong index is detectable", NULL);
  ok(ncap == 3, "target collection respects max (3 of 6 lines)", NULL);
  ok(nnone == 0, "unreadable mount file -> 0 targets", NULL);

  free_set(a, na);
  free_set(b, nb);
  free_set(c, nc);
  free_set(wrong, nw);
  free_set(cap, ncap);
  free_set(none, nnone);
  unlink(pm);
  unlink(pi);
  unlink(ps);
}

/* ------------------------------------------------- kernel parser end-to-end */

/* kallsyms_parse() (rd_kernel.c:67) and the /proc/modules first-field split are
 * static, so they are exercised end-to-end through rd_check_kernel(): the
 * expectation is recomputed from the raw files with an independent scan and
 * compared with what the check reports. Their malformed-input edges need an
 * exposed interface and are reported as SKIP. */
static void test_kernel_parsers(void) {
  printf("-- kernel list parsers (end-to-end) --\n");
  rd_ctx c;
  memset(&c, 0, sizeof c);
  c.is_root = (getuid() == 0);
  rd_report rep;
  rd_report_init(&rep);
  rd_check_kernel(&c, &rep);

  /* --- /proc/modules: first whitespace separated field --- */
  char *raw_mods = rd_slurp("/proc/modules", NULL);
  if (!raw_mods) {
    skip("/proc/modules first-field parse", "/proc/modules unreadable");
  } else {
    size_t lines = 0;
    char *save = NULL;
    for (char *l = strtok_r(raw_mods, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
      const char *p = l;
      while (*p == ' ' || *p == '\t') p++;
      if (*p) lines++;
    }
    free(raw_mods);
    const rd_finding *fm = find_finding(&rep, "kernel-module");
    /* rd_check_kernel emits SEV_HIGH with the "N of M ... match" detail when a
     * module name matches a keyword, and SEV_INFO with "N modules listed"
     * otherwise. sscanf("%d modules listed") also matched the HIGH form's first
     * %d (it returns 1 after failing the literal), so the guard must be the
     * severity plus the exact format - otherwise the "total" was compared with
     * mod_hits and the check FAILed on any host with a keyword-named module. */
    char dm[160] = "";
    int reported = -1;
    if (fm && fm->sev == SEV_INFO && fm->detail &&
        sscanf(fm->detail, "%d modules listed", &reported) == 1) {
      snprintf(dm, sizeof dm, "sscanf=%d independent=%zu", reported, lines);
      ok((size_t)reported == lines, "/proc/modules first field counted once per line", dm);
    } else {
      skip("/proc/modules count cross-check",
           fm && fm->sev == SEV_HIGH ? "a loaded module name matches a hiding keyword"
                                     : "/proc/modules not readable as a plain list");
    }
    if (lines == 0)
      skip("/proc/modules first-field split on real data", "this kernel lists no loadable modules");
  }

  /* --- /proc/kallsyms [module] tags vs /proc/modules --- */
  char *ks = rd_slurp("/proc/kallsyms", NULL);
  if (!ks) {
    skip("kallsyms [module] tags vs /proc/modules", "/proc/kallsyms unreadable");
  } else {
    enum { MAXK = 512 };
    char *tags[MAXK] = {0}, *names[MAXK] = {0};
    size_t nt = 0, nn = 0;
    int bpf_tag = 0;
    char *save = NULL;
    for (char *l = strtok_r(ks, "\n", &save); l && nt < MAXK; l = strtok_r(NULL, "\n", &save)) {
      char addr[64], ty, nm[256], md[128] = "";
      if (sscanf(l, "%63s %c %255s %127s", addr, &ty, nm, md) < 3) continue;
      if (md[0] != '[') continue;
      char *e = strchr(md, ']');
      if (!e) continue; /* unterminated tag: the check ignores it too */
      *e = '\0';
      if (strcmp(md + 1, "bpf") == 0) { bpf_tag = 1; continue; }
      if (md[1] && !set_has(tags, nt, md + 1)) tags[nt++] = strdup(md + 1);
    }
    bool have_mods = false;
    char *mods2 = rd_slurp("/proc/modules", NULL);
    if (mods2) {
      have_mods = true;
      char *sv2 = NULL;
      for (char *l = strtok_r(mods2, "\n", &sv2); l && nn < MAXK; l = strtok_r(NULL, "\n", &sv2)) {
        char nm[128] = "";
        if (sscanf(l, "%127s", nm) != 1) continue;
        if (!set_has(names, nn, nm)) names[nn++] = strdup(nm);
      }
      free(mods2);
    }
    size_t missing = 0;
    char miss[256] = "";
    size_t mo = 0;
    for (size_t i = 0; i < nt; i++) {
      if (set_has(names, nn, tags[i])) continue;
      missing++;
      if (mo + 1 < sizeof miss)
        mo += (size_t)snprintf(miss + mo, sizeof miss - mo, "%s%s", missing > 1 ? "," : "", tags[i]);
    }
    char dk[384];
    if (missing)
      snprintf(dk, sizeof dk, "%zu of %zu tags absent from /proc/modules: %s", missing, nt, miss);
    else
      snprintf(dk, sizeof dk, "all %zu kallsyms module tags are in /proc/modules%s", nt,
               bpf_tag ? " (bpf pseudo-module exempt)" : "");

    const rd_finding *fh = find_finding(&rep, "kernel-module-hidden");
    if (!have_mods) {
      skip("kallsyms tags vs /proc/modules", "/proc/modules unreadable");
    } else if (missing == 0) {
      ok(fh == NULL, "kallsyms tags all present in /proc/modules -> no hidden-module finding", dk);
    } else if (nn == 0) {
      /* /proc/modules is readable but lists nothing. The detector deliberately
       * reports that as kernel-modules-crosscheck-skipped instead of
       * kernel-module-hidden, because an emptied module list cannot be told
       * apart from a filtered one without a second source. Asserting fh != NULL
       * here contradicted the implementation. */
      ok(fh == NULL, "empty /proc/modules -> cross-check skipped, no hidden-module finding", dk);
    } else {
      ok(fh != NULL, "kallsyms tags missing from /proc/modules are reported", dk);
    }
    /* The cross-check only runs when /proc/modules is readable AND non-empty
     * (nn > 0); with an empty module list rd_check_kernel deliberately reports
     * kernel-modules-crosscheck-skipped, which is not kernel-module-crosscheck. */
    if (have_mods && nn > 0 && fh == NULL) {
      const rd_finding *fx = find_finding(&rep, "kernel-module-crosscheck");
      int vis = -1;
      char dv[160] = "";
      if (fx && fx->detail && sscanf(fx->detail, "%d module(s)", &vis) == 1)
        snprintf(dv, sizeof dv, "reported=%d independent=%zu", vis, nt);
      int vis_ok = vis >= 0 && (nt ? (size_t)vis >= nt : vis == 0);
      ok(fx != NULL && vis_ok, "kallsyms [module] tags all seen by the cross-check, bpf exempt", dv);
    }
    free_set(tags, nt);
    free_set(names, nn);
    free(ks);
    if (nt == 0)
      skip("kallsyms [module] tag formatting",
           "this kernel has no loadable module tags in /proc/kallsyms");
  }

  /* The two kernel-list parsers, malformed cases included. These used to be
   * skipped because the parsers were static; they are exposed now, so the skip
   * would only hide a regression. */
  {
    unsigned long long a = 0;
    char nm[64] = "", md[64] = "";
    ok(rd_parse_kallsyms_line("ffffffff81000000 T do_exit", &a, nm, sizeof nm, md, sizeof md) &&
         a == 0xffffffff81000000ULL && strcmp(nm, "do_exit") == 0 && md[0] == '\0',
       "kallsyms line: address, type and symbol name", nm);
    ok(rd_parse_kallsyms_line("ffffffffc0000000 t helper [mymod]", &a, nm, sizeof nm, md, sizeof md) &&
         strcmp(nm, "helper") == 0 && strcmp(md, "mymod") == 0,
       "kallsyms line: [module] tag stripped", md);
    ok(rd_parse_kallsyms_line("ffffffffc0000000 t broken [unterminated", &a, nm, sizeof nm, md, sizeof md) &&
         strcmp(nm, "broken") == 0 && md[0] == '\0',
       "kallsyms line: unterminated [module tag keeps the name, drops the module", nm);
    ok(!rd_parse_kallsyms_line("", &a, nm, sizeof nm, md, sizeof md) &&
         !rd_parse_kallsyms_line("not a kallsyms line", &a, nm, sizeof nm, md, sizeof md),
       "kallsyms line: empty and malformed lines are rejected", "");
    char m1[16] = "";
    ok(rd_parse_proc_modules_line("my_module 16384 1 - Live 0xffffffffc0000000", m1, sizeof m1) &&
         strcmp(m1, "my_module") == 0,
       "/proc/modules line: first field is the module name", m1);
    char m2[16] = "";
    ok(rd_parse_proc_modules_line("\tleading_tab 4096 0 - Live 0x0", m2, sizeof m2) &&
         strcmp(m2, "leading_tab") == 0,
       "/proc/modules line: a leading tab is not part of the name", m2);
    char m3[16] = "";
    ok(!rd_parse_proc_modules_line("", m3, sizeof m3) &&
         !rd_parse_proc_modules_line("   ", m3, sizeof m3),
       "/proc/modules line: empty and blank lines are rejected", "");
    char m4[8] = "";
    ok(rd_parse_proc_modules_line("abcdefghijklmnop 1 0 - Live 0x0", m4, sizeof m4) &&
         strlen(m4) == 7,
       "/proc/modules line: a short buffer truncates instead of overflowing", m4);
  }
  rd_report_free(&rep);
}

/* ---------------------------------------- susfs_guard_lkm check e2e */

/* rd_check_susfs_lkm() reads four independent kernel views (/proc/modules,
 * /sys/module, the module parameters and /proc/kallsyms). The expectation is
 * recomputed here from the raw sources with an independent scan and compared:
 *  - module listed in /proc/modules -> the HIGH finding and *not* the
 *    "self-filtered" claim;
 *  - a kernel view answering while the list omits it -> the CRITICAL
 *    self-filter claim (the module's own documented behaviour);
 *  - nothing anywhere -> the check must stay silent.
 * On a device that really runs the LKM the same recomputation has to hold, so
 * this doubles as the field cross-check. */
static void test_susfs_lkm_e2e(void) {
  printf("-- susfs_guard_lkm LKM check (end-to-end) --\n");
  rd_ctx c;
  memset(&c, 0, sizeof c);
  c.is_root = (getuid() == 0);
  rd_report rep;
  rd_report_init(&rep);
  rd_check_susfs_lkm(&c, &rep);

  /* independent recomputation straight from the sources */
  const size_t mlen = strlen(RD_SUSFS_LKM_MODULE);
  bool mods_readable = false, in_mods = false, sysfs = false, tag = false, params = false;
  size_t mods_lines = 0;
  char *raw = rd_slurp("/proc/modules", NULL);
  if (raw) {
    mods_readable = true;
    char *save = NULL;
    for (char *l = strtok_r(raw, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
      while (*l == ' ' || *l == '\t') l++;
      if (!*l) continue;
      mods_lines++;
      if (strncmp(l, RD_SUSFS_LKM_MODULE, mlen) == 0) {
        char cc = l[mlen];
        if (cc == '\0' || cc == ' ' || cc == '\t' || cc == '_' || cc == '-' || cc == '.')
          in_mods = true;
      }
    }
    free(raw);
  }
  DIR *sd = opendir("/sys/module");
  if (sd) {
    struct dirent *e;
    while ((e = readdir(sd))) {
      if (strncmp(e->d_name, RD_SUSFS_LKM_MODULE, mlen) == 0) {
        sysfs = true;
        break;
      }
    }
    closedir(sd);
  }
  char *ks = rd_slurp("/proc/kallsyms", NULL);
  if (ks) {
    tag = strstr(ks, "[" RD_SUSFS_LKM_MODULE) != NULL;
    free(ks);
  }
  params = rd_path_exists("/sys/module/" RD_SUSFS_LKM_MODULE "/parameters/expose_proc") ||
           rd_path_exists("/sys/module/" RD_SUSFS_LKM_MODULE "/parameters/fail_layer");

  char d[256];
  snprintf(d, sizeof d, "list %s (%zu line(s)) in_list=%d sysfs=%d kallsyms=%d params=%d",
           mods_readable ? "readable" : "unreadable", mods_lines, in_mods, sysfs, tag, params);
  const rd_finding *ff = find_finding(&rep, "susfs-lkm-module-filtered");
  const rd_finding *fm = find_finding(&rep, "susfs-lkm-module");
  if (in_mods) {
    ok(fm != NULL && fm->sev == SEV_HIGH && ff == NULL,
       "listed module -> HIGH finding, no self-filter claim", d);
  } else if ((sysfs || tag || params) && mods_readable) {
    ok(ff != NULL && ff->sev == SEV_CRITICAL && fm == NULL,
       "kernel view without the list line -> self-filter CRITICAL", d);
  } else if ((sysfs || tag || params) && !mods_readable) {
    ok(fm != NULL && ff == NULL, "unreadable list + kernel view -> loaded HIGH, no filter claim", d);
  } else {
    ok(fm == NULL && ff == NULL, "no kernel view shows the LKM -> the check stays silent", d);
  }

  /* Oracle wiring: recompute the probes straight from the corpus and demand
   * the report agree - a contradiction must be reported, and any reported one
   * must reproduce. Holds on a clean system and on an infected one alike. */
  int tell_paths = 0;
  for (size_t i = 0; i < RD_SUSFS_LKM_SELF_HIDDEN_COUNT; i++) {
    const char *p = RD_SUSFS_LKM_SELF_HIDDEN[i];
    if (rd_probe_lstat(p) != 1) continue;
    int mk2 = rd_probe_mkdir_exists(p);
    int rl2 = rd_probe_readlink_exists(p);
    int fs2 = rd_probe_statfs_exists(p);
    int op2 = rd_probe_open_o_path(p);
    if (rd_susfs_lkm_oracle_tell(1, mk2, rl2, fs2, op2) && rd_probe_lstat(p) == 1) tell_paths++;
  }
  const rd_finding *fo = find_finding(&rep, "susfs-lkm-node-oracle");
  ok((tell_paths > 0) == (fo != NULL && fo->sev == SEV_CRITICAL),
     "oracle: report matches an independent probe pass", d);
  rd_report_free(&rep);
}

/* --------------------------------------------- mount cross-view check e2e */

/* test_mount_parsers() pins rd_collect_mount_targets() with the field index in
 * the *test*; this pins the constants rd_check_mounts() itself uses. On a system
 * whose four mount views agree (already asserted by the guard below) the check
 * must not invent a CRITICAL cross-view mismatch - a wrong field index in
 * rd_check_mounts() makes /proc/mounts and mountinfo describe different "mount
 * points" and turns a clean device into HIDING_DETECTED. */
static void test_mount_check_e2e(void) {
  printf("-- mount cross-view check (end-to-end) --\n");
  rd_ctx c;
  memset(&c, 0, sizeof c);
  rd_report rep;
  rd_report_init(&rep);
  rd_check_mounts(&c, &rep);

  const rd_finding *fv = find_finding(&rep, "mount-view");
  size_t c0 = 0, c1 = 0, c2 = 0, c3 = 0;
  int got = 0;
  if (fv && fv->detail)
    got = sscanf(fv->detail,
                 "/proc/mounts=%zu /proc/self/mountinfo=%zu /proc/1/mountinfo=%zu "
                 "/proc/self/mountstats=%zu entries",
                 &c0, &c1, &c2, &c3);
  char d[192];
  snprintf(d, sizeof d, "mounts=%zu mountinfo=%zu init-mountinfo=%zu mountstats=%zu", c0, c1, c2, c3);
  const rd_finding *fi = find_finding(&rep, "mount-view-inconsistency");
  if (got != 4 || !c0 || !c1) {
    skip("mount-view-inconsistency stays silent on a consistent table",
         "a mount view could not be parsed here");
  } else if (!c2 || !c3) {
    ok(fi == NULL, "mount-view-inconsistency silent for the readable mount views", d);
  } else {
    ok(fi == NULL, "mount-view-inconsistency stays silent when all four views agree", d);
  }
  rd_report_free(&rep);
}

/* ----------------------------------------------------- false-positive guards */

/* Every mount view must describe the same mount table. This guard exists
 * because a wrong field index in one of the four formats once turned a clean
 * system into HIDING_DETECTED. */

/* Bounded append that keeps *off inside dsz. The naive
 * `off += snprintf(dst + off, dsz - off, ...)` is unsafe: snprintf() returns the
 * length it *would* have written, so as soon as off exceeds dsz the next
 * `dsz - off` underflows to SIZE_MAX and the write runs far past the buffer. It
 * tripped glibc's fortify ("buffer overflow detected") and ASan
 * (stack-buffer-overflow) once the disagreement evidence exceeded dsz. */
static void appends(char *dst, size_t dsz, size_t *off, const char *fmt, ...) {
  if (!dsz || *off >= dsz - 1) return;
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(dst + *off, dsz - *off, fmt, ap);
  va_end(ap);
  if (n > 0) {
    *off += (size_t)n;
    if (*off > dsz - 1) *off = dsz - 1;
  }
}

static int mount_views_agree(char *detail, size_t dsz) {
  static char *base[512], *other[512];
  size_t nb = rd_collect_mount_targets("/proc/mounts", 1, base, 512);
  if (!nb) {
    snprintf(detail, dsz, "/proc/mounts unreadable");
    return -1;
  }
  int all_same = 1;
  size_t off = 0;
  appends(detail, dsz, &off, "/proc/mounts=%zu", nb);
  /* /proc/1/mountinfo is only a second view of the SAME table when init shares
   * this process's mount namespace (per-app namespaces / su --mount-master /
   * containers make it legitimately different). rd_check_mounts() guards this;
   * the self-test must too, or it FAILs on a clean device when run from the app. */
  char self_ns[64] = "", init_ns[64] = "";
  int init_view_ok = rd_read_link("/proc/self/ns/mnt", self_ns, sizeof self_ns) > 0 &&
                     rd_read_link("/proc/1/ns/mnt", init_ns, sizeof init_ns) > 0 &&
                     strcmp(self_ns, init_ns) == 0;
  const char *files[3] = {"/proc/self/mountinfo", "/proc/1/mountinfo", "/proc/self/mountstats"};
  const int fields[3] = {4, 4, 4};
  for (int f = 0; f < 3; f++) {
    if (f == 1 && !init_view_ok) {
      appends(detail, dsz, &off, " /proc/1/mountinfo=skipped (different mount namespace)");
      continue;
    }
    size_t no = rd_collect_mount_targets(files[f], fields[f], other, 512);
    int same = (no == nb);
    for (size_t i = 0; same && i < nb; i++) {
      int found = 0;
      for (size_t k = 0; k < no; k++)
        if (strcmp(base[i], other[k]) == 0) { found = 1; break; }
      if (!found) same = 0;
    }
    size_t shown = 0;
    if (!same) {
      for (size_t i = 0; i < nb && shown < 3; i++) {
        int found = 0;
        for (size_t k = 0; k < no; k++)
          if (strcmp(base[i], other[k]) == 0) { found = 1; break; }
        if (!found) {
          appends(detail, dsz, &off, "; absent from %s: %s", files[f], base[i]);
          shown++;
        }
      }
      all_same = 0;
    }
    appends(detail, dsz, &off, " %s=%zu%s", files[f], no, same ? "" : " MISMATCH");
    for (size_t k = 0; k < no; k++) free(other[k]);
  }
  for (size_t k = 0; k < nb; k++) free(base[k]);
  return all_same ? 1 : 0;
}

static void test_false_positive_guards(void) {
  printf("-- false-positive guards (must stay silent on a clean system) --\n");

  /* guard 1: the uname-spoof detector must not fire on an honest kernel */
  struct utsname u;
  char rel[256] = "";
  if (uname(&u) == 0 && rd_read_first_line("/proc/sys/kernel/osrelease", rel, sizeof rel)) {
    ok(strcmp(u.release, rel) == 0, "uname() agrees with /proc/sys/kernel/osrelease", rel);
  } else {
    skip("uname() vs /proc/sys/kernel/osrelease", "not readable");
  }
  char ver[512] = "";
  if (uname(&u) == 0 && rd_read_first_line("/proc/sys/kernel/version", ver, sizeof ver))
    ok(strncmp(u.version, ver, 8) == 0, "uname() agrees with /proc/sys/kernel/version", ver);
  else
    skip("uname() vs /proc/sys/kernel/version", "not readable");

  /* guard 2: the mount cross-view detector must not fire on an honest kernel */
  char detail[1024];
  int mv = mount_views_agree(detail, sizeof detail);
  if (mv < 0) skip("mount views list the same targets", detail);
  else ok(mv == 1, "all four mount views list the same targets", detail);

  /* guard 3: property plumbing - Android only */
  if (!rd_path_exists("/system/bin/getprop")) {
    skip("getprop table parsed", "not an Android system");
    skip("ro.build.version.sdk is visible", "not an Android system");
    return;
  }
  rd_props p;
  rd_props_load(&p);
  ok(p.n > 20, "getprop table parsed", NULL);
  ok(rd_prop(&p, "ro.build.version.sdk") != NULL, "ro.build.version.sdk is visible", NULL);
  rd_props_free(&p);
}

int rd_selftest(void) {
  printf("rootdetect %s self-test   uid=%d\n", RD_VERSION, (int)getuid());
  test_logic();
  test_mount_parsers();
  test_mount_check_e2e();
  test_kernel_parsers();
  test_susfs_lkm_e2e();
  test_live_probes();
  test_false_positive_guards();
  printf("\n%d checks, %d failure(s), %d skipped\n", g_checks, g_fails, g_skips);
  return g_fails ? 1 : 0;
}
