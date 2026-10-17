#!/bin/bash
# Probe the WSL userland: can it build/run the detector, and what is available?
echo "== identity =="; id
echo "== kernel =="; uname -a
echo "== distro =="; head -2 /etc/os-release
echo "== tools =="
for t in gcc clang cc make ld javac java keytool zip unzip python3 aapt2; do
  printf '%-10s %s\n' "$t" "$(command -v "$t" 2>/dev/null || echo MISSING)"
done
echo "== proc surfaces the deep checks need =="
ls -l /proc/kcore /proc/kallsyms 2>&1 | head -4
echo "tainted=$(cat /proc/sys/kernel/tainted 2>&1)"
echo "kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>&1)"
echo "modules: $(wc -l < /proc/modules 2>&1) lines"
echo "== unrelated pieces =="
ls -l /dev/fuse 2>&1
echo "mount count: $(wc -l < /proc/mounts)"
