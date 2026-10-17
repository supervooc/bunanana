#!/usr/bin/env python3
"""Sanity check the built APK: dex contents and manifest entry points."""
import sys
import zipfile

apk = sys.argv[1] if len(sys.argv) > 1 else "out/rootdetect.apk"
try:
    z = zipfile.ZipFile(apk)
except (OSError, zipfile.BadZipFile) as e:
    raise SystemExit("not a readable zip: %s (%s)" % (apk, e))

# e_machine values we care about; the label was previously computed and dropped.
MACHINES = {0xB7: "ARM64", 0x3E: "x86-64", 0x28: "ARM", 0x03: "x86"}

with z:
    names = z.namelist()
    print("== entries ==")
    for n in names:
        print("   " + n)
    try:
        dex = z.read("classes.dex")
    except KeyError:
        dex = b""
    if dex:
        print("== classes.dex (%d bytes) ==" % len(dex))
        for s in [b"MainActivity", b"com/rootdetect/app/MainActivity", b"librootdetect.so",
                  b"Run detection", b"nativeLibraryDir"]:
            print(("   found   " if s in dex else "   MISSING ") + s.decode())
    else:
        print("== classes.dex MISSING ==")
    print("== native libs ==")
    for n in names:
        if n.startswith("lib/"):
            data = z.read(n)
            if len(data) >= 20 and data[:4] == b"\x7fELF":
                machine = int.from_bytes(data[18:20], "little")
                kind = MACHINES.get(machine, "?")
            else:
                machine, kind = -1, "not-ELF"
            print("   %-40s %9d bytes  %-7s elf_machine=%d" % (n, len(data), kind, machine))
