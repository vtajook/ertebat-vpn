#!/usr/bin/env python3
"""Draws a simple original logo (logo.png: ring + lock + name, icon.png: ring + lock + monogram) for a brand folder."""
import json, math, os, sys
from PIL import Image, ImageDraw, ImageFilter, ImageFont

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
S = 1024


def glow(layer, color, radius):
    return layer.filter(ImageFilter.GaussianBlur(radius))


def draw(name, mono, color):
    img = Image.new("RGB", (S, S), (0, 0, 0))
    c = tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))
    ring = Image.new("RGB", (S, S), (0, 0, 0))
    d = ImageDraw.Draw(ring)
    d.ellipse((60, 60, S - 60, S - 60), outline=c, width=26)
    d.ellipse((110, 110, S - 110, S - 110), outline=tuple(v // 2 for v in c), width=8)
    # lock
    cx, cy = S // 2, 430
    d.rounded_rectangle((cx - 120, cy - 20, cx + 120, cy + 170), radius=34, fill=c)
    d.arc((cx - 80, cy - 150, cx + 80, cy + 30), 180, 360, fill=c, width=36)
    d.ellipse((cx - 22, cy + 40, cx + 22, cy + 84), fill=(0, 0, 0))
    d.rectangle((cx - 9, cy + 70, cx + 9, cy + 130), fill=(0, 0, 0))
    img = Image.blend(img, ring, 1.0)
    from PIL import ImageChops
    img = ImageChops.add(img, glow(ring, c, 18))
    return img


def logo(name, color):
    img = draw(name, None, color)
    c = tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))
    d = ImageDraw.Draw(img)
    size = 150
    f = ImageFont.truetype(FONT, size)
    while d.textlength(name, font=f) > 600:
        size -= 6
        f = ImageFont.truetype(FONT, size)
    w = d.textlength(name, font=f)
    d.text(((S - w) / 2, 665), name, font=f, fill=c)
    d.rectangle((S // 2 - 120, 830, S // 2 + 120, 836), fill=c)
    return img


def icon(name, color):
    img = draw(name, None, color)
    d = ImageDraw.Draw(img)
    f = ImageFont.truetype(FONT, 200)
    w = d.textlength(name[0].upper(), font=f)
    d.text(((S - w) / 2, 630), name[0].upper(), font=f, fill=(245, 245, 245))
    return img


if __name__ == "__main__":
    folder, color = sys.argv[1], sys.argv[2]
    cfg = json.load(open(os.path.join(folder, "brand.json"), encoding="utf-8"))
    logo(cfg["name"], color).save(os.path.join(folder, "logo.png"))
    icon(cfg["name"], color).save(os.path.join(folder, "icon.png"))
