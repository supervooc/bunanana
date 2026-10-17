/* rootdetect - extra low-cost signals.
 *
 * These are the cheap checks that do not deserve a whole module but catch a lot
 * of real-world instrumentation: control sockets, ptrace, the caller's
 * environment, and mappings whose backing file is not visible any more.
 */
#include "rd.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ----------------------------------------------------------------- sockets */

/* A /proc/net/unix row is "Num RefCount Protocol Flags Type St Inode [Path]"
 * with the path optional, so the inode is the seventh whitespace field. */
static bool unix_row_inode(const char *line, char *out, size_t outsz) {
  char ino[64] = "";
  if (sscanf(line, "%*s %*s %*s %*s %*s %*s %63s", ino) != 1 || !ino[0]) return false;
  for (const char *p = ino; *p; p++)
    if (!isdigit((unsigned char)*p)) return false; /* header line, or a path with no inode */
  snprintf(out, outsz, "%s", ino);
  return true;
}

/* uid of the process holding socket:[inode], or -1 when it cannot be found.
 *
 * /proc/net/unix is a system wide table with no owner column, and an abstract
 * socket name needs no filesystem permission at all: any process can bind
 * "@magisk" and make a clean device report ROOT_DETECTED. Walking the fd tables
 * for the inode is the only way to tell a real framework channel from a forged
 * name, so do it - but only for a name match (rare) and bounded. */
static long socket_owner_uid(const char *inode, char *how, size_t howsz) {
  char want[80];
  snprintf(want, sizeof(want), "socket:[%s]", inode);
  DIR *pd = opendir("/proc");
  if (!pd) {
    snprintf(how, howsz, "owner unknown, /proc not readable");
    return -1;
  }
  struct dirent *e;
  long uid = -1;
  int scanned = 0;
  while (uid < 0 && scanned < 2000 && (e = readdir(pd)) != NULL) {
    /* Only digit names are pids. Copied by hand into a short buffer so every
     * path built from it is provably in bounds (a dirent name is up to 255
     * bytes and -Wformat-truncation rightly complains about the snprintf()s). */
    char pid[24];
    size_t pl = 0;
    for (const char *p = e->d_name; *p; p++) {
      if (*p < '0' || *p > '9') {
        pl = 0;
        break;
      }
      if (pl + 1 < sizeof(pid)) pid[pl++] = *p;
    }
    if (!pl) continue;
    pid[pl] = '\0';
    scanned++;
    char fddir[48];
    snprintf(fddir, sizeof(fddir), "/proc/%s/fd", pid);
    DIR *fd = opendir(fddir);
    if (!fd) continue; /* another uid's fd table */
    struct dirent *f;
    int nf = 0;
    while (uid < 0 && nf++ < 512 && (f = readdir(fd)) != NULL) {
      char link[320], tgt[48];
      snprintf(link, sizeof(link), "%s/%s", fddir, f->d_name);
      if (rd_read_link(link, tgt, sizeof(tgt)) <= 0) continue;
      if (strcmp(tgt, want) != 0) continue;
      char st[4096];
      snprintf(link, sizeof(link), "/proc/%s/status", pid);
      if (rd_read_small(link, st, sizeof(st))) {
        char *u = strstr(st, "Uid:");
        if (u) {
          uid = strtol(u + 4, NULL, 10);
          if (uid >= 0) snprintf(how, howsz, "owner pid %s uid %ld", pid, uid);
        }
      }
    }
    closedir(fd);
  }
  closedir(pd);
  if (uid < 0) snprintf(how, howsz, "owner unknown");
  return uid;
}

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
  int hits = 0, root_owned = 0, nonroot_owned = 0;
  char *save = NULL;
  for (char *line = strtok_r(txt, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    const char *which = NULL;
    if (!rd_has_keyword(line, &which)) continue;
    if (strcmp(which, "busybox") == 0) continue;
    hits++;
    char how[96] = "owner unknown";
    long uid = -1;
    char ino[64];
    if (unix_row_inode(line, ino, sizeof(ino))) uid = socket_owner_uid(ino, how, sizeof(how));
    if (uid == 0)
      root_owned++;
    else if (uid > 0)
      nonroot_owned++;
    if (strlen(ev) < sizeof(ev) - 256) rd_appendf(ev, sizeof(ev), "%s [%s]\n", line, how);
  }
  free(txt);
  if (!hits) {
    rd_add(rep, SEV_INFO, "unix-sockets", "no suspicious unix socket names", "");
    return;
  }
  /* A bare name match proves nothing: the table has no owner column and any
   * process may take an abstract name, so one unprivileged bind() was enough to
   * turn this finding into ROOT_DETECTED (reproduced). Only a socket that can be
   * attributed to uid 0 earns HIGH. */
  rd_sev sev = root_owned ? SEV_HIGH : SEV_MEDIUM;
  rd_add_ev(rep, sev, "unix-socket-roots",
            "unix socket name references a root/instrumentation framework", ev,
            root_owned
                ? "%d socket name(s) matched and at least one is held by uid 0, so it is a control "
                  "channel of a root process (a socket name, not a file, so hiding the filesystem "
                  "does not remove it)."
                : nonroot_owned
                      ? "%d socket name(s) matched but none are held by uid 0: every match belongs "
                        "to a non-root process, and any process can bind an abstract name such as "
                        "\"@magisk\", so this is not proof of root."
                      : "%d socket name(s) matched but the owning process could not be determined "
                        "from this domain (no /proc/<pid>/fd access), so the name alone is not "
                        "proof of root.",
            hits);
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
  /* Two separate accumulators: the hidden-mapping and the deleted-mapping
   * findings are independent, and sharing one buffer mixed their evidence. */
  char ev_missing[RD_MAXEVID];
  ev_missing[0] = '\0';
  char ev_deleted[RD_MAXEVID];
  ev_deleted[0] = '\0';
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

    /* /proc/self/maps pathnames are bounded by PATH_MAX (4096). Probing a
     * truncation of a longer path would report a real file as hidden, so skip
     * anything that does not fit instead. */
    char path[4096];
    if (strlen(f) >= sizeof(path)) continue;
    snprintf(path, sizeof(path), "%s", f);
    /* Strip only the kernel's " (deleted)" suffix: truncating at the first space
     * made every mapped file whose path contains a space look hidden (review B3). */
    char *del = strstr(path, " (deleted)");
    if (del) *del = '\0';

    if (rd_contains(f, "(deleted)")) {
      if (exec) {
        deleted++;
        if (strlen(ev_deleted) < sizeof(ev_deleted) - 256)
          rd_appendf(ev_deleted, sizeof(ev_deleted), "%s\n", line);
      }
      continue;
    }
    rd_probe_row row;
    rd_probe_all(path, &row);
    if (row.stat_r == 1 && row.open_read_r == 1) {
      /* Before blaming a hiding layer, look at the directory: when the whole
       * mount is gone from this mount namespace (a file mapped before /data was
       * unmounted, a path under a mount that is no longer there) the parent is
       * missing as well, which is normal and not a hidden path. A per-path
       * hiding layer leaves the directory in place, so that stays CRITICAL. */
      char parent[4096];
      snprintf(parent, sizeof(parent), "%s", path);
      char *slash = strrchr(parent, '/');
      struct stat pst;
      bool parent_gone = false;
      if (slash && slash != parent) {
        *slash = '\0';
        parent_gone = (stat(parent, &pst) != 0);
      }
      if (!parent_gone) {
        missing++;
        if (strlen(ev_missing) < sizeof(ev_missing) - 256)
          rd_appendf(ev_missing, sizeof(ev_missing), "%s\n", line);
      }
    }
  }
  free(txt);
  if (missing)
    rd_add_ev(rep, SEV_CRITICAL, "map-backing-hidden",
              "mapped file is not visible to stat/open", ev_missing,
              "%d mapped files exist in this address space but are hidden from the filesystem "
              "interfaces - a per-path hiding layer that does not cover the mmap path.", missing);
  if (deleted)
    rd_add_ev(rep, SEV_MEDIUM, "map-deleted-exec",
              "executable mapping backed by a deleted file", ev_deleted,
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
