#!/usr/bin/env python3
"""Sanity check the built APK: dex contents and manifest entry points."""
import sys
import zipfile

apk = sys.argv[1] if len(sys.argv) > 1 else "out/rootdetect.apk"
with zipfile.ZipFile(apk) as z:
    names = z.namelist()
    print("== entries ==")
    for n in names:
        print("   " + n)
    dex = z.read("classes.dex")
    print("== classes.dex (%d bytes) ==" % len(dex))
    for s in [b"MainActivity", b"com/rootdetect/app/MainActivity", b"librootdetect.so",
              b"Run detection", b"nativeLibraryDir"]:
        print(("   found   " if s in dex else "   MISSING ") + s.decode())
    print("== native libs ==")
    for n in names:
        if n.startswith("lib/"):
            data = z.read(n)
            kind = "ARM64" if b"\xb7" in data[:20] else "?"
            print("   %-40s %9d bytes  elf_machine=%d" % (n, len(data), int.from_bytes(data[18:20], "little")))
