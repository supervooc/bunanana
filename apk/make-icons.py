#!/usr/bin/env python3
"""Generate the bunanana launcher icon at every density from apk/icon-source.jpg.

    python3 apk/make-icons.py

Produces:
  apk/res/mipmap-{mdpi..xxxhdpi}/ic_launcher.png            legacy square icon
  apk/res/mipmap-{mdpi..xxxhdpi}/ic_launcher_foreground.png adaptive foreground
  apk/res/values/ic_launcher_background.xml                 colour sampled from the art
The adaptive icon XML (mipmap-anydpi-v26) is checked in by hand.
"""
import os
import sys

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "icon-source.jpg")
RES = os.path.join(HERE, "res")

LEGACY = [("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)]
ADAPTIVE = [("mdpi", 108), ("hdpi", 162), ("xhdpi", 216), ("xxhdpi", 324), ("xxxhdpi", 432)]


def square(im):
    w, h = im.size
    s = min(w, h)
    return im.crop(((w - s) // 2, (h - s) // 2, (w - s) // 2 + s, (h - s) // 2 + s))


def edge_colour(im):
    """Average colour of the border - used as the adaptive icon background so the
    foreground blends into the platform-provided mask."""
    small = im.resize((32, 32), Image.LANCZOS)
    px = small.load()
    r = g = b = n = 0
    for y in range(32):
        for x in range(32):
            if 3 < x < 28 and 3 < y < 28:
                continue
            r0, g0, b0 = px[x, y][:3]
            r += r0
            g += g0
            b += b0
            n += 1
    return (r // n, g // n, b // n)


def main():
    if not os.path.exists(SRC):
        sys.exit("missing " + SRC)
    im = square(Image.open(SRC).convert("RGB"))

    for d, px in LEGACY:
        out = os.path.join(RES, "mipmap-" + d)
        os.makedirs(out, exist_ok=True)
        im.resize((px, px), Image.LANCZOS).save(os.path.join(out, "ic_launcher.png"))
        print("  mipmap-%-8s ic_launcher.png %dx%d" % (d, px, px))

    bg = edge_colour(im)
    for d, px in ADAPTIVE:
        out = os.path.join(RES, "mipmap-" + d)
        os.makedirs(out, exist_ok=True)
        canvas = Image.new("RGBA", (px, px), (0, 0, 0, 0))
        # the adaptive safe zone is the inner ~66%; keep a little margin inside it
        inner = int(px * 0.70)
        art = im.resize((inner, inner), Image.LANCZOS).convert("RGBA")
        mask = Image.new("L", (inner, inner), 0)
        ImageDraw.Draw(mask).ellipse((0, 0, inner - 1, inner - 1), fill=255)
        canvas.paste(art, ((px - inner) // 2, (px - inner) // 2), mask)
        canvas.save(os.path.join(out, "ic_launcher_foreground.png"))
        print("  mipmap-%-8s ic_launcher_foreground.png %dx%d" % (d, px, px))

    vals = os.path.join(RES, "values")
    os.makedirs(vals, exist_ok=True)
    with open(os.path.join(vals, "ic_launcher_background.xml"), "w") as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
                '    <color name="ic_launcher_background">#%02X%02X%02X</color>\n</resources>\n' % bg)
    print("  values/ic_launcher_background.xml  #%02X%02X%02X" % bg)


if __name__ == "__main__":
    main()
