/* rootdetect - extra low-cost signals.
 *
 * These are the cheap checks that do not deserve a whole module but catch a lot
 * of real-world instrumentation: control sockets, ptrace, the caller's
 * environment, and mappings whose backing file is not visible any more.
 */
#include "rd.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>

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

/* Collects suspicious socket names from either view in one pass.
 *
 * A device can expose a complete /proc/net/unix, a complete netlink table, or
 * either one filtered. Matches are merged by socket inode so a socket seen in
 * both views is counted once. The netlink view is collected first: it is the
 * only one that carries UNIX_DIAG_UID, and that UID must win over the
 * /proc/<pid>/fd walk, which cannot see a root process from an app domain. */
typedef struct {
  int hits;
  int root_owned;
  int nonroot_owned;
  unsigned int seen[256];
  size_t n_seen;
  char ev[RD_MAXEVID];
} unix_scan;

/* True when this inode was already counted. A zero inode is never merged
 * because there is nothing to compare. */
static bool unix_seen(unix_scan *sc, unsigned int ino) {
  if (!ino) return false;
  for (size_t i = 0; i < sc->n_seen; i++)
    if (sc->seen[i] == ino) return true;
  if (sc->n_seen < sizeof(sc->seen) / sizeof(sc->seen[0])) sc->seen[sc->n_seen++] = ino;
  return false;
}

/* Record one name match. `display` is what the evidence line shows, `match` is
 * the text searched for the keywords, and `uid` is the already-known owner when
 * have_uid is true. */
static void unix_account(unix_scan *sc, const char *display, const char *match,
                         unsigned int ino, long uid, bool have_uid) {
  const char *which = NULL;
  if (!rd_has_keyword(match, &which)) return;
  if (strcmp(which, "busybox") == 0) return;
  if (unix_seen(sc, ino)) return;
  sc->hits++;
  char how[96] = "owner unknown";
  if (have_uid) {
    snprintf(how, sizeof(how), "netlink uid %ld", uid);
  } else if (ino) {
    char ino_s[32];
    snprintf(ino_s, sizeof(ino_s), "%u", ino);
    uid = socket_owner_uid(ino_s, how, sizeof(how));
  }
  if (uid == 0)
    sc->root_owned++;
  else if (uid > 0)
    sc->nonroot_owned++;
  if (strlen(sc->ev) < sizeof(sc->ev) - 256)
    rd_appendf(sc->ev, sizeof(sc->ev), "%s [%s]\n", display, how);
}

typedef void (*unix_diag_cb)(void *ud, const char *name, unsigned int uid,
                             bool have_uid, unsigned int ino);

enum {
  UNIX_DUMP_OK = 0,
  UNIX_DUMP_ERR = -1,
  UNIX_DUMP_INCOMPLETE = -2
};

/* Enumerate AF_UNIX sockets through NETLINK_SOCK_DIAG.
 *
 * /proc/net/unix is denied to apps on Android 11+ (SELinux), which used to make
 * the whole socket-name check a skip. The kernel exposes the same table over
 * sock_diag, and modern kernels include UNIX_DIAG_UID, so the owner of a name
 * can be known without walking /proc/<pid>/fd (which an app cannot do for root
 * processes anyway). The table is streamed to `cb` instead of being stored in a
 * fixed-size array: busy hosts can have far more than 256 named sockets, and
 * the old cap silently dropped every match past it.
 *
 * Only messages from the kernel (port 0), with our sequence number and a
 * complete unix_diag_msg header, are accepted. A dump that ends with
 * NLM_F_DUMP_INTR, a truncated datagram, a recv error before NLMSG_DONE, or an
 * NLMSG_ERROR is reported as incomplete instead of being mistaken for a
 * complete table. Returns UNIX_DUMP_OK, UNIX_DUMP_ERR or
 * UNIX_DUMP_INCOMPLETE; `why` explains anything but OK. */
static int unix_diag_dump(unix_diag_cb cb, void *ud, char *why, size_t whysz) {
  if (whysz) why[0] = '\0';
  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
  if (fd < 0) {
    snprintf(why, whysz, "socket: %s", strerror(errno));
    return UNIX_DUMP_ERR;
  }
  /* Never let a wedged kernel hang the whole scan: the tool has a watchdog,
   * but a two-second cap keeps the check itself bounded. */
  struct timeval tv;
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    snprintf(why, whysz, "bind: %s", strerror(errno));
    close(fd);
    return UNIX_DUMP_ERR;
  }

  struct {
    struct nlmsghdr nlh;
    struct unix_diag_req req;
  } msg;
  memset(&msg, 0, sizeof(msg));
  const unsigned int seq = 1;
  msg.nlh.nlmsg_len = sizeof(msg);
  msg.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
  msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  msg.nlh.nlmsg_seq = seq;
  msg.req.sdiag_family = AF_UNIX;
  msg.req.udiag_states = 0xffffffffu;
  /* NAME gives the path; UID is what turns a bare name into a root-owned
   * control channel. Kernels predating UNIX_DIAG_UID ignore the bit. */
  msg.req.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_UID;
  if (send(fd, &msg, sizeof(msg), 0) < 0) {
    snprintf(why, whysz, "send: %s", strerror(errno));
    close(fd);
    return UNIX_DUMP_ERR;
  }

  bool done = false, intr = false, failed = false, saw_msg = false;
  while (!done && !failed) {
    char buf[8192];
    struct sockaddr_nl from;
    memset(&from, 0, sizeof(from));
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_name = &from;
    mh.msg_namelen = sizeof(from);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    ssize_t got = recvmsg(fd, &mh, 0);
    if (got < 0) {
      if (errno == EINTR) continue;
      snprintf(why, whysz, "recv: %s", strerror(errno));
      break;
    }
    if (got == 0) {
      snprintf(why, whysz, "netlink closed before NLMSG_DONE");
      break;
    }
    /* Kernel replies come from port 0. A user process can send to our port but
     * cannot spoof the source, so anything else is not the kernel's table. */
    if (mh.msg_namelen < sizeof(from) || from.nl_family != AF_NETLINK || from.nl_pid != 0) {
      intr = true;
      continue;
    }
    /* A truncated datagram can still contain complete messages, but the rest
     * of the table is lost: parse it, then force the incomplete return. */
    if (mh.msg_flags & MSG_TRUNC) intr = true;
    unsigned int left = (unsigned int)got;
    for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, left); h = NLMSG_NEXT(h, left)) {
      if (h->nlmsg_seq != seq) continue; /* late reply from an earlier dump, if any */
      if (h->nlmsg_flags & NLM_F_DUMP_INTR) intr = true;
      if (h->nlmsg_type == NLMSG_DONE) {
        done = true;
        break;
      }
      if (h->nlmsg_type == NLMSG_ERROR) {
        if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
          snprintf(why, whysz, "short NLMSG_ERROR");
          failed = true;
          break;
        }
        struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);
        if (e->error) {
          snprintf(why, whysz, "netlink error %d", e->error);
          failed = true;
          break;
        }
        continue; /* ACK; the dump still ends with NLMSG_DONE */
      }
      if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct unix_diag_msg))) {
        intr = true;
        continue;
      }
      struct unix_diag_msg *d = (struct unix_diag_msg *)NLMSG_DATA(h);
      int alen = (int)h->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*d));
      const char *name = NULL;
      size_t nlen = 0;
      unsigned int uid = 0;
      bool have_uid = false;
      for (struct rtattr *a = (struct rtattr *)(d + 1); RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
        if (a->rta_type == UNIX_DIAG_NAME) {
          name = (const char *)RTA_DATA(a);
          nlen = (size_t)RTA_PAYLOAD(a);
        } else if (a->rta_type == UNIX_DIAG_UID && RTA_PAYLOAD(a) >= (int)sizeof(uid)) {
          memcpy(&uid, RTA_DATA(a), sizeof(uid));
          have_uid = true;
        }
      }
      saw_msg = true;
      if (!name || nlen == 0) continue;
      bool abstract = name[0] == '\0';
      size_t off = abstract ? 1 : 0;
      size_t copy = nlen - off;
      char pretty[192];
      if (copy > sizeof(pretty) - 2) copy = sizeof(pretty) - 2;
      if (abstract) pretty[0] = '@';
      memcpy(pretty + (abstract ? 1 : 0), name + off, copy);
      pretty[(abstract ? 1 : 0) + copy] = '\0';
      cb(ud, pretty, uid, have_uid, d->udiag_ino);
    }
  }
  close(fd);
  if (done && !intr) return UNIX_DUMP_OK;
  if (done || intr || saw_msg) {
    if (!why[0]) snprintf(why, whysz, "%s", intr ? "dump was interrupted" : "dump did not finish");
    return UNIX_DUMP_INCOMPLETE;
  }
  if (!why[0]) snprintf(why, whysz, "no netlink reply");
  return UNIX_DUMP_ERR;
}

static void unix_diag_collect(void *ud, const char *name, unsigned int uid,
                              bool have_uid, unsigned int ino) {
  unix_account((unix_scan *)ud, name, name, ino, have_uid ? (long)uid : -1, have_uid);
}

/* Root and instrumentation frameworks keep a control channel as an abstract
 * unix socket: Frida's linjector, Zygisk's daemon, Magisk's socket, LSPosed. */
static void check_unix_sockets(rd_report *rep) {
  unix_scan sc;
  memset(&sc, 0, sizeof(sc));
  char why[160] = "";
  int rc = unix_diag_dump(unix_diag_collect, &sc, why, sizeof(why));
  if (rc == UNIX_DUMP_INCOMPLETE) {
    /* One retry covers the common transient case (a dump racing a table
     * change); the inode merge keeps the first attempt's matches from being
     * counted twice. */
    char why2[160] = "";
    int rc2 = unix_diag_dump(unix_diag_collect, &sc, why2, sizeof(why2));
    if (rc2 == UNIX_DUMP_OK) {
      rc = UNIX_DUMP_OK;
    } else {
      rc = UNIX_DUMP_INCOMPLETE;
      if (why2[0]) snprintf(why, sizeof(why), "%s", why2);
    }
  }

  /* /proc/net/unix is merged after the kernel table: a name that both views
   * see is counted once, with the kernel's UID taking precedence. A socket
   * that only the proc view still exposes is added, and vice versa. This
   * closes the gap where a filtered proc view with a plausible row count was
   * trusted and the netlink fallback never ran. */
  int proc_rows = 0;
  char *txt = rd_slurp("/proc/net/unix", NULL);
  if (txt) {
    char *save = NULL;
    for (char *line = strtok_r(txt, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
      char ino_s[64] = "";
      if (!unix_row_inode(line, ino_s, sizeof(ino_s))) continue;
      proc_rows++;
      unix_account(&sc, line, line, (unsigned int)strtoul(ino_s, NULL, 10), -1, false);
    }
    free(txt);
  }

  if (rc == UNIX_DUMP_ERR && proc_rows == 0) {
    rd_add_skip(rep, SEV_INFO, "unix-sockets",
                "/proc/net/unix unavailable and the netlink dump failed",
                "/proc/net/unix is denied to this domain or returned no rows, and "
                "NETLINK_SOCK_DIAG returned no table (%s), so the socket-name check could not "
                "run. This is not a clean result.", why);
    return;
  }
  if (rc == UNIX_DUMP_INCOMPLETE) {
    rd_add_skip(rep, SEV_INFO, "unix-sockets",
                "the netlink socket table dump was incomplete",
                "The NETLINK_SOCK_DIAG cross-check was interrupted, truncated or timed out (%s). "
                "Any match below is real, but a missing name is not proof of a clean device.",
                why);
    if (!sc.hits) return;
  }
  if (!sc.hits) {
    rd_add(rep, SEV_INFO, "unix-sockets", "no suspicious unix socket names", "");
    return;
  }
  /* A bare name match proves nothing: the table has no owner column and any
   * process may take an abstract name, so one unprivileged bind() was enough to
   * turn this finding into ROOT_DETECTED (reproduced). Only a socket that can be
   * attributed to uid 0 earns HIGH. */
  rd_sev sev = sc.root_owned ? SEV_HIGH : SEV_MEDIUM;
  rd_add_ev(rep, sev, "unix-socket-roots",
            "unix socket name references a root/instrumentation framework", sc.ev,
            sc.root_owned
                ? "%d socket name(s) matched and at least one is held by uid 0, so it is a control "
                  "channel of a root process (a socket name, not a file, so hiding the filesystem "
                  "does not remove it)."
                : sc.nonroot_owned
                      ? "%d socket name(s) matched but none are held by uid 0: every match belongs "
                        "to a non-root process, and any process can bind an abstract name such as "
                        "\"@magisk\", so this is not proof of root."
                      : "%d socket name(s) matched but the owning process could not be determined "
                        "from this domain (no /proc/<pid>/fd access), so the name alone is not "
                        "proof of root.",
            sc.hits);
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
