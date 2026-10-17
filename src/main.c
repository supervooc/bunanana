/* rootdetect - CLI entry point.
 *
 * Exit status: 0 clean, 1 suspicious, 2 root found, 3 hiding mechanism observed,
 * 64 usage error (unknown option).
 */
#include "rd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void usage(const char *argv0) {
  printf(
      "rootdetect " RD_VERSION " - Android root & root-hiding detector\n"
      "\n"
      "usage: %s [options]\n"
      "  -j, --json        machine readable report\n"
      "  -v, --verbose     include informational findings\n"
      "  -q, --quiet       only print the verdict line\n"
      "      --no-color    disable ANSI colours\n"
      "      --fast        skip the slower cross-view checks\n"
      "      --selftest    verify the decision logic and the false-positive guards\n"
      "  -h, --help        this text\n"
      "\n"
      "Exit status: 0 clean | 1 suspicious | 2 root detected | 3 hiding detected | 64 usage error\n"
      "\n"
      "Run it as the `shell` user for the app-equivalent view, and again through\n"
      "`adb root`/`su` for the deep kernel checks (syscall table via /proc/kcore,\n"
      "kernel probe lists, kernel log).\n",
      argv0);
}

static const char *detect_abi(void) {
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

int main(int argc, char **argv) {
  /* Child mode for the ABI differential check: dump probe results and exit. */
  if (argc > 1 && !strcmp(argv[1], "--probe-dump")) {
    rd_abi_probe_dump(stdout);
    return 0;
  }

  bool json = false, verbose = false, quiet = false, color = true, fast = false;

  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    if (!strcmp(a, "-j") || !strcmp(a, "--json")) json = true;
    else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) verbose = true;
    else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) quiet = true;
    else if (!strcmp(a, "--no-color")) color = false;
    else if (!strcmp(a, "--fast")) fast = true;
    else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
    else if (!strcmp(a, "--selftest")) return rd_selftest();
    else { fprintf(stderr, "rootdetect: unknown option %s\n", a); usage(argv[0]); return 64; }
  }
  if (!isatty(STDOUT_FILENO)) color = false;

  rd_ctx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.uid = getuid();
  ctx.pid = getpid();
  ctx.is_root = (ctx.uid == 0);
  ctx.abi = detect_abi();
  rd_props_load(&ctx.props);

  rd_report rep;
  rd_report_init(&rep);

  if (!json && !quiet) {
    printf("rootdetect %s  -  uid=%d(%s) abi=%s pid=%d\n",
           RD_VERSION, (int)ctx.uid, ctx.is_root ? "root" : "non-root", ctx.abi, (int)ctx.pid);
    printf("--------------------------------------------------------------------------\n");
  }

  rd_check_environment(&ctx, &rep);
  rd_check_paths(&ctx, &rep);
  rd_check_packages(&ctx, &rep);
  rd_check_mounts(&ctx, &rep);
  rd_check_kernel(&ctx, &rep);
  rd_check_susfs(&ctx, &rep);
  rd_check_processes(&ctx, &rep);
  rd_check_extra(&ctx, &rep);
  if (!fast) rd_check_consistency(&ctx, &rep);
  if (!fast) rd_check_abi_diff(&ctx, &rep);
  rd_check_deep(&ctx, &rep);

  rd_finalize(&rep);

  if (json) {
    rd_print_json(&rep);
  } else if (quiet) {
    printf("%s\n", rep.verdict ? rep.verdict : "?");
  } else {
    rd_print_text(&rep, color, verbose);
  }

  int rc = 0;
  if (rep.counts[SEV_CRITICAL] > 0 || (rep.flags & RD_F_HIDE)) rc = 3;
  else if (rep.counts[SEV_HIGH] > 0) rc = 2;
  else if (rep.counts[SEV_MEDIUM] > 0) rc = 1;

  rd_report_free(&rep);
  rd_props_free(&ctx.props);
  return rc;
}
