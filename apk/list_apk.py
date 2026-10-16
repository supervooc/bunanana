#!/usr/bin/env python3
"""List APK contents and verify the embedded scanners are the real binaries.

    list_apk.py APK [ARCNAME=LOCALPATH ...]

Prints a table of every entry and, for each ARCNAME=LOCALPATH pair, the sha256
of the entry next to the sha256 of the file it should have come from.
"""
import hashlib
import os
import sys
import zipfile


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    apk = sys.argv[1]
    expect = dict(s.split("=", 1) for s in sys.argv[2:])

    with zipfile.ZipFile(apk) as z:
        print("%-44s %10s  %s" % ("entry", "size", "storage"))
        for i in z.infolist():
            print("%-44s %10d  %s" % (i.filename, i.file_size,
                                      "stored  " if i.compress_type == 0 else "deflated"))
        print()
        ok = True
        for name, path in expect.items():
            try:
                data = z.read(name)
            except KeyError:
                print("MISSING in apk: %s" % name)
                ok = False
                continue
            a = sha(data)
            b = sha(open(path, "rb").read())
            same = a == b
            ok = ok and same
            print("%-40s %s\n    apk   %s\n    local %s (%s)" %
                  (name, "MATCH" if same else "MISMATCH", a, b, os.path.basename(path)))
        print("\nembedded binaries verified: %s" % ("yes" if ok else "NO"))


if __name__ == "__main__":
    main()
