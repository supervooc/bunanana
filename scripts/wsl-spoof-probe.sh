#!/bin/bash
# Why did the /proc/kcore syscall-table check stay silent, and which /proc views
# can actually be bind-mounted to exercise the mount cross-view detector?
echo "== kallsyms symbols the deep check needs =="
for s in sys_call_table compat_sys_call_table __x64_sys_openat __x64_sys_newuname kallsyms_lookup_name; do
  printf '%-24s %s\n' "$s" "$(grep -m1 -E " ${s}\$" /proc/kallsyms || echo 'NOT FOUND')"
done
echo "kallsyms lines   : $(wc -l < /proc/kallsyms)"
echo "kallsyms readable: $(head -1 /proc/kallsyms)"
echo "kptr_restrict    : $(cat /proc/sys/kernel/kptr_restrict)"
printf 'kcore magic      : '; head -c 4 /proc/kcore | od -An -c
echo
echo "== bind-mount a fake table over each mount view =="
printf '/dev/sda1 / ext4 rw,relatime 0 0\n' > /tmp/fake-mounts
for t in /proc/mounts /proc/self/mountinfo /proc/self/mountstats; do
  if mount --bind /tmp/fake-mounts "$t" 2>/tmp/mounterr; then
    echo "$t: bind OK -> now $(wc -l < "$t") line(s)"
    umount "$t" 2>/dev/null && echo "   unmounted"
  else
    echo "$t: bind FAILED -> $(cat /tmp/mounterr)"
  fi
done
