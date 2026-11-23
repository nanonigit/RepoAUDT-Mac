#!/usr/bin/env python3
"""Generate RepoAUDT Mac AppIcon.icns with a code-audit magnifying glass motif."""

from __future__ import annotations

import argparse
import math
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ICONSET_SPECS = [
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


def load_bold_mono_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Load a bold monospace or sans-serif font available on macOS."""
    candidates = [
        "/System/Library/Fonts/SFNSMono.ttf",
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial Bold.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size=size, index=1 if path.endswith(".ttc") else 0)
            except Exception:
                try:
                    return ImageFont.truetype(path, size=size)
                except Exception:
                    continue
    return ImageFont.load_default()


def render_master_icon(size: int = 1024) -> Image.Image:
    """Render a 1024x1024 macOS-style squircle icon showing code lines inspected by a </> lens."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Outer macOS rounded-square card (matching WebTPDF clarity)
    pad = 72
    card_rect = [pad, pad, size - pad, size - pad]
    draw.rounded_rectangle(
        card_rect,
        radius=196,
        fill=(248, 249, 251, 255),
        outline=(214, 219, 226, 255),
        width=12,
    )

    navy = (34, 42, 74, 255)
    paper = (255, 255, 255, 255)
    header_pink = (242, 180, 194, 255)
    crimson = (204, 34, 82, 255)
    gutter_bg = (241, 244, 249, 255)
    grid_line = (212, 218, 230, 255)
    code_bar = (118, 128, 152, 255)
    code_accent = (74, 98, 168, 255)
    stroke = 28

    # Code sheet / table card on the left-center
    sheet_left, sheet_top = 185, 165
    sheet_right, sheet_bottom = 725, 845
    header_h = 105
    gutter_x = 290

    # Sheet background
    draw.rounded_rectangle(
        [sheet_left, sheet_top, sheet_right, sheet_bottom],
        radius=42,
        fill=paper,
    )

    # Left line-number gutter
    draw.rectangle(
        [sheet_left + 14, sheet_top + header_h, gutter_x, sheet_bottom - 14],
        fill=gutter_bg,
    )

    # Pink header bar (matching reference motif)
    draw.rounded_rectangle(
        [sheet_left, sheet_top, sheet_right, sheet_top + header_h + 24],
        radius=42,
        fill=header_pink,
    )
    draw.rectangle(
        [sheet_left, sheet_top + header_h, sheet_right, sheet_top + header_h + 26],
        fill=paper,
    )

    # Subtle row dividers + gutter divider
    draw.line([(gutter_x, sheet_top + header_h), (gutter_x, sheet_bottom)], fill=grid_line, width=10)
    row_top = sheet_top + header_h
    row_count = 5
    row_h = (sheet_bottom - row_top) / row_count
    for i in range(row_count):
        y = int(row_top + i * row_h)
        if i == 0:
            draw.line([(sheet_left, y), (sheet_right, y)], fill=navy, width=stroke)
        else:
            draw.line([(sheet_left + 14, y), (sheet_right - 14, y)], fill=grid_line, width=8)

        # Line-number dot/tick in gutter
        cy = int(y + row_h / 2)
        draw.rounded_rectangle([sheet_left + 38, cy - 10, gutter_x - 32, cy + 10], radius=10, fill=(176, 184, 202, 255))

        # Indented code bars inside each row
        indent = [0, 36, 72, 36, 0][i]
        bar_len = [245, 210, 175, 225, 190][i]
        bar_color = code_accent if i in (1, 3) else code_bar
        bx1 = gutter_x + 34 + indent
        bx2 = min(sheet_right - 34, bx1 + bar_len)
        draw.rounded_rectangle([bx1, cy - 13, bx2, cy + 13], radius=13, fill=bar_color)

    # Outer navy border of code sheet
    draw.rounded_rectangle(
        [sheet_left, sheet_top, sheet_right, sheet_bottom],
        radius=42,
        outline=navy,
        width=stroke,
    )

    # Magnifying glass overlapping bottom-right
    cx, cy = 640, 625
    radius = 185
    angle = math.radians(45)

    # Handle (crimson fill with bold navy outline)
    hx1 = cx + int((radius - 6) * math.cos(angle))
    hy1 = cy + int((radius - 6) * math.sin(angle))
    hx2 = cx + int((radius + 175) * math.cos(angle))
    hy2 = cy + int((radius + 175) * math.sin(angle))
    draw.line([(hx1, hy1), (hx2, hy2)], fill=navy, width=68)
    # Round end caps for navy handle outline
    draw.ellipse([hx1 - 34, hy1 - 34, hx1 + 34, hy1 + 34], fill=navy)
    draw.ellipse([hx2 - 34, hy2 - 34, hx2 + 34, hy2 + 34], fill=navy)
    draw.line([(hx1, hy1), (hx2, hy2)], fill=crimson, width=28)
    draw.ellipse([hx1 - 14, hy1 - 14, hx1 + 14, hy1 + 14], fill=crimson)
    draw.ellipse([hx2 - 14, hy2 - 14, hx2 + 14, hy2 + 14], fill=crimson)

    # Lens circle (white fill + bold navy ring)
    draw.ellipse(
        [cx - radius, cy - radius, cx + radius, cy + radius],
        fill=(255, 255, 255, 248),
        outline=navy,
        width=stroke,
    )

    # Bold "</>" code symbol inside the lens (crisp vector strokes for Dock legibility)
    sym_w = 24
    # Left chevron '<'
    lx1, ly1 = cx - 72, cy - 48
    lx2, ly2 = cx - 122, cy
    lx3, ly3 = cx - 72, cy + 48
    draw.line([(lx1, ly1), (lx2, ly2), (lx3, ly3)], fill=crimson, width=sym_w, joint="curve")
    for px, py in ((lx1, ly1), (lx2, ly2), (lx3, ly3)):
        draw.ellipse([px - sym_w // 2, py - sym_w // 2, px + sym_w // 2, py + sym_w // 2], fill=crimson)

    # Center slash '/'
    sx1, sy1 = cx + 22, cy - 64
    sx2, sy2 = cx - 22, cy + 64
    draw.line([(sx1, sy1), (sx2, sy2)], fill=crimson, width=sym_w)
    for px, py in ((sx1, sy1), (sx2, sy2)):
        draw.ellipse([px - sym_w // 2, py - sym_w // 2, px + sym_w // 2, py + sym_w // 2], fill=crimson)

    # Right chevron '>'
    rx1, ry1 = cx + 72, cy - 48
    rx2, ry2 = cx + 122, cy
    rx3, ry3 = cx + 72, cy + 48
    draw.line([(rx1, ry1), (rx2, ry2), (rx3, ry3)], fill=crimson, width=sym_w, joint="curve")
    for px, py in ((rx1, ry1), (rx2, ry2), (rx3, ry3)):
        draw.ellipse([px - sym_w // 2, py - sym_w // 2, px + sym_w // 2, py + sym_w // 2], fill=crimson)

    return img


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iconset-dir", required=True, help="Output .iconset directory")
    parser.add_argument("--preview-png", help="Optional preview PNG path")
    args = parser.parse_args()

    out_dir = Path(args.iconset_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    master = render_master_icon(1024)

    if args.preview_png:
        master.resize((512, 512), Image.Resampling.LANCZOS).save(args.preview_png, "PNG")

    for filename, px in ICONSET_SPECS:
        resized = master.resize((px, px), Image.Resampling.LANCZOS)
        resized.save(out_dir / filename, "PNG")


if __name__ == "__main__":
    main()
