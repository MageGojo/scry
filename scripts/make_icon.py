#!/usr/bin/env python3
"""把 assets/icon/scry.png 处理成 macOS 应用图标 AppIcon.icns。

流程:
  1. 裁成正方形(取中心),从四角 floodfill 把白色背景键控成透明
     (只影响与边缘连通的白,水晶球内部高光/眼睛巩膜不受影响)。
  2. 由干净的 1024 RGBA 生成标准 .iconset 各尺寸(LANCZOS 缩放)。
  3. 调用 iconutil 合成 AppIcon.icns。

仅依赖 Pillow + macOS 自带 iconutil。可重复执行(幂等)。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ICON_DIR = ROOT / "assets" / "icon"
SRC = ICON_DIR / "scry.png"
CLEAN = ICON_DIR / "AppIcon-1024.png"
ICONSET = ICON_DIR / "AppIcon.iconset"
ICNS = ICON_DIR / "AppIcon.icns"

# 标准 macOS iconset 尺寸表: (文件名, 边长像素)
SIZES = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
]


def make_clean_1024() -> Image.Image:
    """裁中心正方形 + 抠掉白色背景 -> 1024 RGBA(四角透明)。"""
    im = Image.open(SRC).convert("RGB")
    w, h = im.size
    side = min(w, h)
    left = (w - side) // 2
    top = (h - side) // 2
    im = im.crop((left, top, left + side, top + side))

    # 从四角向内 floodfill 白色背景为标记色(品红),阈值容忍渐变白边。
    mark = (255, 0, 255)
    s = im.size[0]
    for seed in [(1, 1), (s - 2, 1), (1, s - 2), (s - 2, s - 2)]:
        ImageDraw.floodfill(im, seed, mark, thresh=60)

    rgba = im.convert("RGBA")
    datas = rgba.getdata()
    out = []
    for r, g, b, a in datas:
        if (r, g, b) == mark:
            out.append((0, 0, 0, 0))
        else:
            out.append((r, g, b, 255))
    rgba.putdata(out)

    if rgba.size != (1024, 1024):
        rgba = rgba.resize((1024, 1024), Image.LANCZOS)
    rgba.save(CLEAN)
    return rgba


def build_iconset(base: Image.Image) -> None:
    if ICONSET.exists():
        for p in ICONSET.iterdir():
            p.unlink()
    else:
        ICONSET.mkdir(parents=True, exist_ok=True)
    for name, px in SIZES:
        base.resize((px, px), Image.LANCZOS).save(ICONSET / name)


def build_icns() -> None:
    subprocess.run(
        ["iconutil", "-c", "icns", str(ICONSET), "-o", str(ICNS)],
        check=True,
    )


def main() -> int:
    if not SRC.exists():
        print(f"找不到源图: {SRC}", file=sys.stderr)
        return 1
    base = make_clean_1024()
    build_iconset(base)
    build_icns()
    print(f"OK -> {ICNS} ({ICNS.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
