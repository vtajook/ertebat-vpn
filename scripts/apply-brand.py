#!/usr/bin/env python3
"""Applies brands/<id> to the Android sources of the working tree and prints the Gradle -P arguments.

Usage (from the repository root): python3 scripts/apply-brand.py <id>
Run `git checkout -- V2rayNG/app/src/main/res` first when another brand was applied before.
"""
import glob
import json
import os
import re
import sys

from PIL import Image, ImageDraw
import numpy as np

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
res = os.path.join(root, "V2rayNG/app/src/main/res")


def main(brand_id):
    folder = os.path.join(root, "brands", brand_id)
    cfg = json.load(open(os.path.join(folder, "brand.json"), encoding="utf-8"))
    for key in ("id", "name", "applicationId", "apkPrefix", "bot", "channel"):
        if not cfg.get(key):
            sys.exit(f"brands/{brand_id}/brand.json: '{key}' is missing")
    if not re.fullmatch(r"[A-Za-z0-9]+", cfg["apkPrefix"]):
        sys.exit("apkPrefix must be letters and digits only")
    bot = cfg["bot"].lstrip("@")

    # texts: app name and the bot name in the "Telegram bot" menu entry
    for path in glob.glob(os.path.join(res, "values*/strings.xml")):
        text = open(path, encoding="utf-8").read()
        text = re.sub(r'(<string name="app_name" translatable="false">)[^<]*(</string>)',
                      lambda m: m.group(1) + cfg["name"].replace("&", "&amp;") + m.group(2), text)
        text = text.replace("@egnvpnbot", "@" + bot)
        open(path, "w", encoding="utf-8").write(text)

    if cfg.get("replaceIcon", True):
        logo_path = next((p for p in glob.glob(os.path.join(folder, "logo.*"))), None)
        if not logo_path:
            sys.exit(f"brands/{brand_id}/logo.png is missing")
        logo = Image.open(logo_path).convert("RGB")
        side = min(logo.size)
        logo = logo.crop(((logo.width - side) // 2, (logo.height - side) // 2,
                          (logo.width + side) // 2, (logo.height + side) // 2))
        write_icons(logo, cfg.get("iconBackground", "#000000"))
        write_watermark(logo)

    print(f"-PbrandAppId={cfg['applicationId']} -PbrandPrefix={cfg['apkPrefix']} "
          f"-PbrandBot={bot} -PbrandChannel={cfg['channel']}")


def circle(img):
    mask = Image.new("L", img.size, 0)
    ImageDraw.Draw(mask).ellipse((0, 0, img.width - 1, img.height - 1), fill=255)
    out = img.convert("RGBA")
    out.putalpha(mask)
    return out


def write_icons(logo, background):
    sizes = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
    for dpi, px in sizes.items():
        folder = os.path.join(res, f"mipmap-{dpi}")
        square = logo.resize((px, px), Image.LANCZOS)
        square.save(os.path.join(folder, "ic_launcher.png"))
        circle(square).save(os.path.join(folder, "ic_launcher_round.png"))
        fpx = px * 108 // 48
        fg = Image.new("RGBA", (fpx, fpx), (0, 0, 0, 0))
        inner = int(fpx * 0.66)
        fg.alpha_composite(circle(logo.resize((inner, inner), Image.LANCZOS)), ((fpx - inner) // 2, (fpx - inner) // 2))
        fg.save(os.path.join(folder, "ic_launcher_foreground.png"))
    bg = os.path.join(res, "values/ic_launcher_background.xml")
    text = open(bg, encoding="utf-8").read()
    text = re.sub(r'(<color name="ic_launcher_background">)[^<]*(</color>)', lambda m: m.group(1) + background + m.group(2), text)
    open(bg, "w", encoding="utf-8").write(text)


def write_watermark(logo):
    """Faint background picture: black becomes transparent, only the coloured artwork stays."""
    a = np.asarray(logo.resize((512, 512), Image.LANCZOS)).astype(np.float32)
    alpha = np.clip((a.max(axis=2) - 18) / (255 - 18), 0, 1)
    color = np.where(alpha[..., None] > 0, a / np.maximum(alpha[..., None] * 255, 1) * 255, 0)
    out = np.dstack([np.clip(color, 0, 255), alpha * 255]).astype(np.uint8)
    Image.fromarray(out, "RGBA").save(os.path.join(res, "drawable-nodpi/egn_watermark.webp"), quality=90)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
