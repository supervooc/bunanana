#!/usr/bin/env python3
"""Assemble an APK: aapt2's output + classes.dex + lib/<abi>/librootdetect.so.

    assemble.py OUT.apk BASE.apk [ARCNAME=PATH ...]

Python's zipfile is used because none of zip/7z are available on this host and
PowerShell cannot add entries at arbitrary paths to an existing archive.
"""
import os
import sys
import zipfile


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    out, base = sys.argv[1], sys.argv[2]
    entries = sys.argv[3:]

    if os.path.exists(out):
        os.remove(out)

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        with zipfile.ZipFile(base) as b:
            for info in b.infolist():
                z.writestr(info, b.read(info.filename))
        for spec in entries:
            if "=" not in spec:
                raise SystemExit("bad entry (want ARCNAME=PATH): " + spec)
            arc, path = spec.split("=", 1)
            if not arc or arc.startswith("/") or "\\" in arc or ":" in arc:
                raise SystemExit("bad archive name: " + arc)
            if not os.path.exists(path):
                raise SystemExit("missing input: " + path)
            z.write(path, arc)
    print("assembled %s (%d bytes)" % (out, os.path.getsize(out)))


if __name__ == "__main__":
    main()
