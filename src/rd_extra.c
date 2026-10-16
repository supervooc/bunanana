/* rootdetect - extra low-cost signals.
 *
 * These are the cheap checks that do not deserve a whole module but catch a lot
 * of real-world instrumentation: control sockets, ptrace, the caller's
 * environment, and mappings whose backing file is not visible any more.
 */
#include "rd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ----------------------------------------------------------------- sockets */

/* Root and instrumentation frameworks keep a control channel as an abstract
 * unix socket: Frida's linjector, Zygisk's daemon, Magisk's socket, LSPosed. */
static void check_unix_sockets(rd_report *rep) {
  char *txt = rd_slurp("/proc/net/unix", NULL);
  if (!txt) {
    rd_add(rep, SEV_INFO, "unix-sockets", "/proc/net/unix not readable",
           "SELinux may restrict this file for the current domain.");
    return;
  }
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int hits = 0;
  char *save = NULL;
  for (char *line = strtok_r(txt, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    const char *which = NULL;
    if (!rd_has_keyword(line, &which)) continue;
    if (strcmp(which, "busybox") == 0) continue;
    hits++;
    if (strlen(ev) < sizeof(ev) - 256) rd_appendf(ev, sizeof(ev), "%s\n", line);
  }
  free(txt);
  if (hits)
    rd_add_ev(rep, SEV_HIGH, "unix-socket-roots",
              "unix socket name references a root/instrumentation framework", ev,
              "%d socket names matched; these are control channels, not files, so hiding the "
              "filesystem does not remove them.", hits);
  else
    rd_add(rep, SEV_INFO, "unix-sockets", "no suspicious unix socket names", "");
}

/* ------------------------------------------------------- tracer / environment */

static void check_tracer_and_env(rd_report *rep) {
  char buf[4096];
  if (rd_read_small("/proc/self/status", buf, sizeof(buf))) {
    char *p = strstr(buf, "TracerPid:");
    if (p) {
      long t = strtol(p + strlen("TracerPid:"), NULL, 10);
      if (t > 0)
        rd_add(rep, SEV_HIGH, "self-traced", "this process is being traced",
               "TracerPid=%ld - a ptrace-based tool is attached (frida-server, gdb, or a "
               "hooking framework).", t);
      else
        rd_add(rep, SEV_INFO, "self-traced", "not traced", "TracerPid=0");
    }
  }

  const char *pre = getenv("LD_PRELOAD");
  if (pre && *pre)
    rd_add(rep, SEV_MEDIUM, "env-preload", "LD_PRELOAD is set in the environment",
           "LD_PRELOAD=%s. This binary is statically linked so it cannot be preloaded itself, "
           "but the caller's environment is instrumented.", pre);
  const char *lp = getenv("LD_LIBRARY_PATH");
  if (lp && *lp) rd_add(rep, SEV_LOW, "env-ldpath", "LD_LIBRARY_PATH is set", "%s", lp);
}

/* ------------------------------------------------------------ map backing */

/* A mapped file that cannot be stat()ed any more, or an executable mapping of a
 * deleted file, means code is running from something the filesystem no longer
 * describes - the classic shape of an injected or unhooked-away library. */
static void check_map_backing(rd_report *rep) {
  char *txt = rd_slurp("/proc/self/maps", NULL);
  if (!txt) return;
  char ev[RD_MAXEVID];
  ev[0] = '\0';
  int missing = 0, deleted = 0;
  char *save = NULL;
  for (char *line = strtok_r(txt, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    char *sp = strchr(line, ' ');
    if (!sp) continue;
    char *f = sp;
    while (*f == ' ') f++;
    int exec = (f[0] && f[1] && f[2] == 'x');
    /* walk past perms, offset, dev, inode to reach the pathname */
    for (int i = 0; i < 4; i++) {
      while (*f && *f != ' ') f++;
      while (*f == ' ') f++;
    }
    if (*f != '/') continue; /* [vdso], [stack], [anon:...] and anonymous maps */
    /* Anonymous shared memory is not a filesystem object: stat() on it either
     * fails or is meaningless, so it must not be judged as "hidden". */
    if (rd_starts_with(f, "/dev/ashmem") || rd_starts_with(f, "/memfd:") ||
        rd_starts_with(f, "/dev/dma_heap") || rd_contains(f, "kgsl"))
      continue;

    char path[512];
    snprintf(path, sizeof(path), "%s", f);
    /* Strip only the kernel's " (deleted)" suffix: truncating at the first space
     * made every mapped file whose path contains a space look hidden (review B3). */
    char *del = strstr(path, " (deleted)");
    if (del) *del = '\0';

    if (rd_contains(f, "(deleted)")) {
      if (exec) {
        deleted++;
        if (strlen(ev) < sizeof(ev) - 256) rd_appendf(ev, sizeof(ev), "%s\n", line);
      }
      continue;
    }
    rd_probe_row row;
    rd_probe_all(path, &row);
    if (row.stat_r == 1 && row.open_read_r == 1) {
      missing++;
      if (strlen(ev) < sizeof(ev) - 256) rd_appendf(ev, sizeof(ev), "%s\n", line);
    }
  }
  free(txt);
  if (missing)
    rd_add_ev(rep, SEV_CRITICAL, "map-backing-hidden",
              "mapped file is not visible to stat/open", ev,
              "%d mapped files exist in this address space but are hidden from the filesystem "
              "interfaces - a per-path hiding layer that does not cover the mmap path.", missing);
  if (deleted)
    rd_add_ev(rep, SEV_MEDIUM, "map-deleted-exec",
              "executable mapping backed by a deleted file", ev,
              "%d executable regions come from files that were unlinked after mapping.", deleted);
  if (!missing && !deleted)
    rd_add(rep, SEV_INFO, "map-backing", "all mapped files are visible on disk", "");
}

void rd_check_extra(rd_ctx *c, rd_report *rep) {
  (void)c;
  check_tracer_and_env(rep);
  check_unix_sockets(rep);
  check_map_backing(rep);
}
