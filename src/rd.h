/*
 * rootdetect - Android root / root-hiding detector (native CLI)
 *
 * Design goals
 *  - Build statically so the tool itself cannot be fooled by LD_PRELOAD, GOT
 *    patching or a hijacked linker, and so it needs no runtime deps.
 *  - Never trust a single source. Every "absent" answer is cross-checked with a
 *    second syscall / second file / second namespace view, because root-hiding
 *    modules (SuSFS, KernelSU, Magisk, Zygisk) hook a *subset* of the kernel's
 *    interfaces and their coverage holes are what we detect.
 *  - Report confidence, not just a boolean: severity + evidence + the exact
 *    probe that produced it.
 */
#ifndef RD_H
#define RD_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RD_VERSION "1.0.1"
#define RD_MAXEVID 3000

/* ------------------------------------------------------------------ severity */

typedef enum {
  SEV_INFO = 0,   /* context, or a check that could not be completed */
  SEV_LOW = 1,    /* weak/ambiguous signal */
  SEV_MEDIUM = 2, /* strong signal, plausible benign explanation */
  SEV_HIGH = 3,   /* root or active hiding with little doubt */
  SEV_CRITICAL = 4 /* definitive: a hiding mechanism was observed working */
} rd_sev;

const char *rd_sev_name(rd_sev s);

/* ------------------------------------------------------------------- findings */

typedef struct {
  rd_sev sev;
  char *id;
  char *title;
  char *detail;
  char *evidence; /* may be NULL */
} rd_finding;

typedef struct {
  rd_finding *items;
  size_t n, cap;
  int counts[5];
  char *verdict;   /* filled by rd_finalize() */
  unsigned flags;  /* RD_F_* */
} rd_report;

#define RD_F_ROOT (1u << 0)   /* something established root access exists */
#define RD_F_HIDE (1u << 1)   /* a hiding/spoofing mechanism was observed */
#define RD_F_HOOK (1u << 2)   /* kernel or libc hooking artefacts observed */

void rd_add(rd_report *r, rd_sev sev, const char *id, const char *title,
            const char *fmt, ...);
/* Same, but with an evidence blob that is printed verbatim (already escaped by
 * the caller when it contains user-controlled bytes). */
void rd_add_ev(rd_report *r, rd_sev sev, const char *id, const char *title,
               const char *evidence, const char *fmt, ...);
void rd_report_init(rd_report *r);
void rd_report_free(rd_report *r);
void rd_finalize(rd_report *r);
void rd_print_text(const rd_report *r, int use_color, int verbose);
void rd_print_json(const rd_report *r);

/* -------------------------------------------------------------------- utility */

/* File IO. All return NULL / -1 on failure and set errno as the syscall did. */
char *rd_slurp(const char *path, size_t *len_out);
char *rd_slurp_fd(int fd, size_t *len_out);
/* Reads a small file into buf, NUL terminated, strips the trailing newline.
 * Returns false when the file cannot be opened at all. */
bool rd_read_small(const char *path, char *buf, size_t bufsz);
bool rd_path_exists(const char *path);
long long rd_path_size(const char *path);
/* readlink() into buf; returns -1 on error, else the link length. */
long rd_read_link(const char *path, char *buf, size_t bufsz);

/* Run argv[0] with argv, capturing stdout (NUL terminated). Returns the exit
 * status, or -1 when the process could not be started. */
int rd_run(const char *const argv[], char *out, size_t outsz);

/* Whole getprop table, parsed once. Keys not found return NULL. */
typedef struct {
  char **keys;
  char **vals;
  size_t n, cap;
} rd_props;
void rd_props_load(rd_props *p);
void rd_props_free(rd_props *p);
const char *rd_prop(const rd_props *p, const char *key);
/* Matches "ro.boot." style prefixes; calls cb for each hit. */
void rd_props_foreach_prefix(const rd_props *p, const char *prefix,
                             void (*cb)(const char *k, const char *v, void *ud),
                             void *ud);

/* String helpers. */
bool rd_starts_with(const char *s, const char *p);
bool rd_contains(const char *hay, const char *needle);
/* Case-insensitive ASCII substring search (hiding tools love case games). */
bool rd_contains_ci(const char *hay, const char *needle);
/* Does `s` name a root/hiding framework? `which` receives the matched keyword. */
bool rd_has_keyword(const char *s, const char **which);
/* First line of a small file, trimmed. */
bool rd_read_first_line(const char *path, char *buf, size_t bufsz);
void rd_appendf(char *buf, size_t bufsz, const char *fmt, ...);
/* HTML/JSON-ish escaping into out. */
void rd_json_escape(const char *in, char *out, size_t outsz);
size_t rd_trim(char *s);

/* Syscall-level probes: each answers "does this path exist from this angle?"
 *  0 = definitely exists, 1 = definitely absent, -1 = the probe itself failed
 *  (blocked by SELinux, unsupported, ...) in which case errno is left set. */
int rd_probe_stat(const char *path, long long *size_out, unsigned *mode_out);
int rd_probe_lstat(const char *path);
int rd_probe_fstatat(const char *path);
#ifdef __NR_statx
int rd_probe_statx(const char *path);
#endif
int rd_probe_access(const char *path);
int rd_probe_open_o_path(const char *path);
int rd_probe_open_read(const char *path);
int rd_probe_opendir(const char *path); /* getdents64 */
int rd_probe_readlink(const char *path);
/* True when `path` is a symlink pointing at a non-existent target. */
bool rd_is_dangling_symlink(const char *path);
/* True when the directory holding `path` is group/other writable; fills `dir`. */
bool rd_dir_writable_by_others(const char *path, char *dir, size_t dirsz);
/* Parsers (exposed for --selftest): one /proc/kallsyms line and one /proc/modules line. */
bool rd_parse_kallsyms_line(const char *line, unsigned long long *addr, char *name, size_t namesz,
                            char *mod, size_t modsz);
bool rd_parse_proc_modules_line(const char *line, char *name, size_t sz);

/* Probe table used by the consistency engine. */
typedef struct {
  int stat_r, statx_r, fstatat_r, access_r, open_path_r, open_read_r, opendir_r;
  long long size;
  unsigned mode;
} rd_probe_row;

/* Fill a row for `path`. Fields are 0/1/-1 as above (-2 when the probe is not
 * available on this build). */
void rd_probe_all(const char *path, rd_probe_row *row);
const char *rd_probe_res_name(int r);
/* "path stat=exists statx=ENOENT ..." one-liner used as evidence. */
void rd_format_row(const char *path, const rd_probe_row *row, char *buf, size_t bufsz);
/* True when the row is internally contradictory (some probes see the path,
 * others do not). cons_out receives a human readable reason. */
bool rd_row_inconsistent(const rd_probe_row *row, char *cons_out, size_t cons_sz);

/* ------------------------------------------------------------------- modules */

typedef struct {
  rd_props props;
  uid_t uid;
  pid_t pid;
  bool is_root;      /* running as uid 0 */
  const char *abi;   /* "x86_64", "aarch64", ... */
  bool verbose;
} rd_ctx;

/* Each check appends findings to `rep`. */
void rd_check_environment(rd_ctx *c, rd_report *rep);   /* build state, selinux */
void rd_check_paths(rd_ctx *c, rd_report *rep);         /* su binaries, artefacts */
void rd_check_packages(rd_ctx *c, rd_report *rep);      /* root manager apps */
void rd_check_mounts(rd_ctx *c, rd_report *rep);        /* mount cross-checks */
void rd_check_kernel(rd_ctx *c, rd_report *rep);        /* modules, kallsyms, lsm */
void rd_check_susfs(rd_ctx *c, rd_report *rep);         /* SuSFS-specific probes */
void rd_check_processes(rd_ctx *c, rd_report *rep);      /* cmdline/maps scan */
/* Cheap extra signals: unix control sockets, ptrace, LD_* env, map backing. */
void rd_check_extra(rd_ctx *c, rd_report *rep);
void rd_check_consistency(rd_ctx *c, rd_report *rep);   /* spoofing engine */
void rd_check_deep(rd_ctx *c, rd_report *rep);          /* needs uid 0 */

/* Mount target parsing shared by the mount check and the self-test.
 * field: 1 = /proc/mounts layout; 4 = mountinfo and 4 = mountstats layout. */
size_t rd_collect_mount_targets(const char *file, int field, char **out, size_t max);

/* Deterministic self-test of the detector's decision logic plus live
 * false-positive guards. Returns the number of failed checks (0 = all good). */
int rd_selftest(void);

/* ------------------------------------------------------------------ ABI diff
 *
 * SuSFS installs its syscall-table hooks (susfs_fp_hook) once per table: the
 * native table and the compat (AArch32 / 32-bit) table are patched
 * independently, and so are the per-ABI stat and getdents entry points. A 32-bit
 * process and a 64-bit process can therefore disagree about the very same path.
 * The 64-bit binary runs its 32-bit sibling with --probe-dump and compares.
 */
const char *rd_abi_name(void);
void rd_abi_probe_dump(FILE *out); /* child mode: one line per probed path */
void rd_check_abi_diff(rd_ctx *c, rd_report *rep);

/* Shared corpus of interesting paths (root artefacts + hiding surfaces). */
extern const char *const RD_ROOT_PATHS[];
extern const size_t RD_ROOT_PATH_COUNT;
extern const char *const RD_HIDING_PATHS[];
extern const size_t RD_HIDING_PATH_COUNT;
extern const char *const RD_ROOT_PACKAGES[];
extern const size_t RD_ROOT_PACKAGE_COUNT;

#endif /* RD_H */
