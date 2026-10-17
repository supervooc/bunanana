#!/usr/bin/env python3
"""List APK contents and verify the embedded scanners are the real binaries.

    list_apk.py APK [ARCNAME=LOCALPATH ...]

Prints a table of every entry and, for each ARCNAME=LOCALPATH pair, the sha256
of the entry next to the sha256 of the file it should have come from.

Exits non-zero when a pair does not match, so the build can actually fail on a
mismatched or truncated embedded scanner.
"""
import hashlib
import os
import sys
import zipfile


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    apk = sys.argv[1]
    expect = {}
    for s in sys.argv[2:]:
        if "=" not in s:
            raise SystemExit("bad spec (want ARCNAME=LOCALPATH): " + s)
        arc, path = s.split("=", 1)
        expect[arc] = path
    if not expect:
        raise SystemExit("no ARCNAME=LOCALPATH pairs given: nothing would be verified")

    ok = True
    try:
        z = zipfile.ZipFile(apk)
    except (OSError, zipfile.BadZipFile) as e:
        raise SystemExit("cannot open %s as a zip: %s" % (apk, e))

    with z:
        print("%-44s %10s  %s" % ("entry", "size", "storage"))
        for i in z.infolist():
            print("%-44s %10d  %s" % (i.filename, i.file_size,
                                      "stored  " if i.compress_type == 0 else "deflated"))
        print()
        for name, path in expect.items():
            try:
                data = z.read(name)
            except KeyError:
                print("MISSING in apk: %s" % name)
                ok = False
                continue
            a = sha(data)
            try:
                with open(path, "rb") as fh:
                    local = fh.read()
            except OSError as e:
                print("MISSING locally: %s (%s)" % (path, e))
                ok = False
                continue
            b = sha(local)
            same = a == b
            ok = ok and same
            print("%-40s %s\n    apk   %s\n    local %s (%s)" %
                  (name, "MATCH" if same else "MISMATCH", a, b, os.path.basename(path)))
        print("\nembedded binaries verified: %s" % ("yes" if ok else "NO"))

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
