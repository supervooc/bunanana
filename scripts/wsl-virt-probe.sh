#!/bin/bash
# Preconditions for running an Android emulator inside WSL.
echo "== CPU virtualization exposed to WSL =="
echo "vmx flags : $(grep -c vmx /proc/cpuinfo)"
echo "kvm device: $(ls -l /dev/kvm 2>&1)"
echo "kvm module: $(lsmod 2>/dev/null | grep -c kvm)"
echo "nested    : $(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || echo 'no kvm_intel module')"
echo
echo "== WSL resources =="
free -m | head -2
echo "cpus: $(nproc)"
echo "disk: $(df -h / | tail -1)"
echo
echo "== what can we install (network + apt)? =="
timeout 8 bash -c 'echo > /dev/tcp/archive.ubuntu.com/80' 2>/dev/null && echo "archive.ubuntu.com: reachable" || echo "archive.ubuntu.com: NOT reachable"
command -v apt-get >/dev/null && echo "apt-get: present" || echo "apt-get: missing"
command -v qemu-system-x86_64 >/dev/null && echo "qemu: present" || echo "qemu: not installed"
