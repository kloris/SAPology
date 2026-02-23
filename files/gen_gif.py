from PIL import Image, ImageDraw, ImageFont
import os

# --- Config ---
WIDTH = 800
HEIGHT = 260
BG = (12, 12, 12)
SCANLINE_COLOR = (0, 255, 65, 8)

# Colors (matching the HTML)
GREEN_BRIGHT = (0, 255, 65)
GREEN_MID    = (0, 170, 0)
GREEN_DARK   = (0, 85, 0)
GREEN_SUB    = (0, 204, 51)
GREEN_DIM    = (0, 102, 34)
GREEN_PROTO  = (0, 68, 0)
GREEN_AUTH   = (0, 51, 0)
GREEN_CMD    = (26, 74, 26)
GREEN_BORDER = (10, 42, 10)

# Fonts
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FONT_OBLIQUE_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Oblique.ttf"

font_cmd    = ImageFont.truetype(FONT_PATH, 13)
font_title  = ImageFont.truetype(FONT_BOLD_PATH, 52)
font_sub    = ImageFont.truetype(FONT_PATH, 16)
font_sub_it = ImageFont.truetype(FONT_OBLIQUE_PATH, 15)
font_proto  = ImageFont.truetype(FONT_PATH, 12)
font_author = ImageFont.truetype(FONT_PATH, 12)


def draw_scanlines(img):
    """Add very subtle CRT-style scanlines via compositing"""
    overlay = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    for y in range(0, HEIGHT, 4):
        od.line([(0, y), (WIDTH, y)], fill=(0, 255, 65, 6), width=1)
    return Image.alpha_composite(img, overlay)


def render_title(draw, cursor_on=True):
    """Render the [SAP.ology] title with colored parts"""
    x = 50
    y = 60

    # [
    draw.text((x, y), "[", fill=GREEN_DARK, font=font_title)
    x += draw.textlength("[", font=font_title)

    # SAP
    draw.text((x, y), "SAP", fill=GREEN_BRIGHT, font=font_title)
    x += draw.textlength("SAP", font=font_title)

    # .
    draw.text((x, y), ".", fill=GREEN_MID, font=font_title)
    x += draw.textlength(".", font=font_title)

    # ology
    draw.text((x, y), "ology", fill=GREEN_BRIGHT, font=font_title)
    x += draw.textlength("ology", font=font_title)

    # ]
    draw.text((x, y), "]", fill=GREEN_DARK, font=font_title)
    x += draw.textlength("]", font=font_title)

    # Blinking cursor
    if cursor_on:
        cursor_x = x + 6
        cursor_y = y + 8
        draw.rectangle([cursor_x, cursor_y, cursor_x + 12, cursor_y + 40], fill=GREEN_BRIGHT)


def render_frame(cursor_on=True):
    from PIL import ImageFilter
    import numpy as np

    # Shaded background: dark with green-tinted radial vignette
    ys, xs = np.mgrid[0:HEIGHT, 0:WIDTH]
    cx, cy = WIDTH * 0.35, HEIGHT * 0.45
    dist = np.sqrt(((xs - cx) / WIDTH) ** 2 + ((ys - cy) / HEIGHT) ** 2)
    brightness = np.clip(1.0 - dist * 0.8, 0, 1)

    bg = np.zeros((HEIGHT, WIDTH, 4), dtype=np.uint8)
    bg[:, :, 0] = (8 + brightness * 6).astype(np.uint8)
    bg[:, :, 1] = (10 + brightness * 14).astype(np.uint8)
    bg[:, :, 2] = (8 + brightness * 4).astype(np.uint8)
    bg[:, :, 3] = 255

    img = Image.fromarray(bg, 'RGBA')
    draw = ImageDraw.Draw(img)

    # Title glow layer (render first, behind everything)
    glow_layer = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow_layer)
    glow_color = (0, 255, 65, 20)
    for dx in range(-2, 3):
        for dy in range(-2, 3):
            gd.text((50 + dx, 60 + dy), "[SAP.ology]", fill=glow_color, font=font_title)
    glow_layer = glow_layer.filter(ImageFilter.GaussianBlur(radius=10))
    img = Image.alpha_composite(img, glow_layer)

    # Redraw on composited image
    draw = ImageDraw.Draw(img)

    # Command line at top
    draw.text((16, 14), "$ python sapology --hail-mary", fill=GREEN_CMD, font=font_cmd)

    # Top border
    draw.line([(16, 42), (WIDTH - 16, 42)], fill=GREEN_BORDER, width=1)

    # Title (crisp, on top of glow)
    render_title(draw, cursor_on=cursor_on)

    # Bottom border
    draw.line([(16, 130), (WIDTH - 16, 130)], fill=GREEN_BORDER, width=1)

    # Subtitle row
    draw.text((50, 145), "SAP Network Topology", fill=GREEN_SUB, font=font_sub)
    draw.text((460, 147), "Sorry for scanning you ;-)", fill=GREEN_DIM, font=font_sub_it)

    # Protocols
    draw.text((50, 180), "FLUENT IN DIAG \u00b7 RFC \u00b7 GATEWAY \u00b7 MS \u00b7 ICM \u00b7 J2EE", fill=GREEN_PROTO, font=font_proto)

    # Author
    draw.text((50, 205), "by Joris van de Vis", fill=GREEN_AUTH, font=font_author)

    # Subtle green glow top-right
    glow2 = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
    gd2 = ImageDraw.Draw(glow2)
    for r in range(60, 0, -1):
        alpha = int(1.5 * (60 - r) / 60)
        cx, cy = WIDTH - 80, 50
        gd2.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(0, 255, 65, alpha))
    img = Image.alpha_composite(img, glow2)

    # Scanlines
    img = draw_scanlines(img)

    return img.convert("RGB")


def round_corners(img, radius=16):
    """Apply rounded corners with transparent background and green border"""
    img = img.convert("RGBA")
    mask = Image.new("L", img.size, 0)
    md = ImageDraw.Draw(mask)
    md.rounded_rectangle([0, 0, img.width, img.height], radius=radius, fill=255)
    img.putalpha(mask)

    # Draw green rounded border on top
    border_layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    bd = ImageDraw.Draw(border_layer)
    # #1a3a1a border from the HTML version
    bd.rounded_rectangle(
        [0, 0, img.width - 1, img.height - 1],
        radius=radius,
        outline=(26, 58, 26, 255),
        width=2
    )
    img = Image.alpha_composite(img, border_layer)
    return img


# Generate frames
frame_on = round_corners(render_frame(cursor_on=True))
frame_off = round_corners(render_frame(cursor_on=False))

# GIF doesn't support alpha - composite onto black
def to_gif_frame(frame):
    bg = Image.new("RGBA", frame.size, (0, 0, 0, 255))
    return Image.alpha_composite(bg, frame).convert("RGB")

gif_on = to_gif_frame(frame_on)
gif_off = to_gif_frame(frame_off)

# Save animated GIF - cursor blinks every 500ms
output = "/home/claude/sapology-banner.gif"
gif_on.save(
    output,
    save_all=True,
    append_images=[gif_off],
    duration=[500, 500],
    loop=0,
    optimize=True,
)
print(f"Saved to {output}")
print(f"Size: {os.path.getsize(output) / 1024:.1f} KB")

# Also save a PNG with transparent corners
png_output = "/home/claude/sapology-banner.png"
frame_on.save(png_output)
print(f"PNG saved to {png_output}")
print(f"PNG size: {os.path.getsize(png_output) / 1024:.1f} KB")
