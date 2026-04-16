from __future__ import annotations

import math
import textwrap
from pathlib import Path

import imageio.v2 as imageio
import imageio_ffmpeg
import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "output" / "media"
SCREENSHOT_DIR = OUTPUT_DIR / "screenshots"
VIDEO_PATH = OUTPUT_DIR / "scan2pddl_alfa_demo.mp4"

WIDTH = 1600
HEIGHT = 912

BG_TOP = "#f5f8fc"
BG_BOTTOM = "#dce9f9"
INK = "#102a43"
MUTED = "#52667a"
ACCENT = "#1f5f9a"
ACCENT_SOFT = "#e8f1fb"
CARD = "#ffffff"
CARD_BORDER = "#d7e2ef"
TERMINAL_BG = "#0f1724"
TERMINAL_TEXT = "#dbe7f5"
SUCCESS = "#15b26b"


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(name, size=size)


FONT_SANS = str(Path(r"C:\Windows\Fonts\segoeui.ttf"))
FONT_SANS_BOLD = str(Path(r"C:\Windows\Fonts\segoeuib.ttf"))
FONT_MONO = str(Path(r"C:\Windows\Fonts\consola.ttf"))
FONT_MONO_BOLD = str(Path(r"C:\Windows\Fonts\consolab.ttf"))


def make_canvas() -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG_TOP)
    draw = ImageDraw.Draw(image)
    for y in range(HEIGHT):
        blend = y / max(HEIGHT - 1, 1)
        color = tuple(
            round(int(BG_TOP[i : i + 2], 16) * (1 - blend) + int(BG_BOTTOM[i : i + 2], 16) * blend)
            for i in (1, 3, 5)
        )
        draw.line((0, y, WIDTH, y), fill=color)

    orb = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
    orb_draw = ImageDraw.Draw(orb)
    orb_draw.ellipse((WIDTH - 430, 40, WIDTH - 60, 410), fill=(67, 125, 205, 34))
    orb_draw.ellipse((80, HEIGHT - 330, 430, HEIGHT + 20), fill=(49, 111, 191, 24))
    orb = orb.filter(ImageFilter.GaussianBlur(26))
    image = Image.alpha_composite(image.convert("RGBA"), orb).convert("RGB")
    return image


def rounded_card(base: Image.Image, box: tuple[int, int, int, int], fill: str = CARD) -> None:
    shadow = Image.new("RGBA", base.size, (0, 0, 0, 0))
    shadow_draw = ImageDraw.Draw(shadow)
    x0, y0, x1, y1 = box
    shadow_draw.rounded_rectangle((x0 + 8, y0 + 14, x1 + 8, y1 + 14), radius=28, fill=(25, 57, 95, 22))
    shadow = shadow.filter(ImageFilter.GaussianBlur(18))
    base_rgba = Image.alpha_composite(base.convert("RGBA"), shadow)
    draw = ImageDraw.Draw(base_rgba)
    draw.rounded_rectangle(box, radius=28, fill=fill, outline=CARD_BORDER, width=2)
    base.paste(base_rgba.convert("RGB"))


def draw_text_block(
    draw: ImageDraw.ImageDraw,
    text: str,
    *,
    xy: tuple[int, int],
    width: int,
    font_path: str,
    size: int,
    fill: str,
    line_gap: int = 6,
) -> int:
    typeface = font(font_path, size)
    lines: list[str] = []
    for paragraph in text.splitlines() or [""]:
        if not paragraph:
            lines.append("")
            continue
        current = ""
        for word in paragraph.split():
            probe = word if not current else f"{current} {word}"
            if draw.textlength(probe, font=typeface) <= width:
                current = probe
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
    x, y = xy
    ascent, descent = typeface.getmetrics()
    line_height = ascent + descent + line_gap
    for line in lines:
        draw.text((x, y), line, font=typeface, fill=fill)
        y += line_height
    return y


def pill(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, fill: str, fg: str) -> int:
    typeface = font(FONT_SANS_BOLD, 22)
    pad_x = 18
    pad_y = 10
    bbox = draw.textbbox((0, 0), text, font=typeface)
    width = (bbox[2] - bbox[0]) + pad_x * 2
    height = (bbox[3] - bbox[1]) + pad_y * 2
    x, y = xy
    draw.rounded_rectangle((x, y, x + width, y + height), radius=height // 2, fill=fill)
    draw.text((x + pad_x, y + pad_y - 1), text, font=typeface, fill=fg)
    return width


def code_panel(
    base: Image.Image,
    box: tuple[int, int, int, int],
    title: str,
    code: str,
    footer: str | None = None,
    dark: bool = False,
) -> None:
    fill = TERMINAL_BG if dark else "#f7fafc"
    border = "#253447" if dark else "#d7e2ef"
    rounded_card(base, box, fill=fill)
    draw = ImageDraw.Draw(base)
    x0, y0, x1, y1 = box
    draw.rounded_rectangle(box, radius=28, outline=border, width=2)
    if dark:
        for idx, color in enumerate(("#fb7185", "#fbbf24", "#34d399")):
            cx = x0 + 26 + idx * 26
            cy = y0 + 28
            draw.ellipse((cx - 6, cy - 6, cx + 6, cy + 6), fill=color)
    title_font = font(FONT_SANS_BOLD, 24)
    draw.text((x0 + 34, y0 + 22), title, font=title_font, fill="#d9e7f7" if dark else INK)
    if footer:
        footer_font = font(FONT_SANS, 18)
        footer_w = draw.textlength(footer, font=footer_font)
        draw.text((x1 - footer_w - 30, y0 + 25), footer, font=footer_font, fill="#88a2bd" if dark else MUTED)
    code_font = font(FONT_MONO, 22)
    code_color = TERMINAL_TEXT if dark else "#243b53"
    y = y0 + 70
    for line in code.splitlines():
        draw.text((x0 + 34, y), line, font=code_font, fill=code_color)
        y += 30


def section_title(draw: ImageDraw.ImageDraw, x: int, y: int, title: str, body: str, width: int) -> int:
    y = draw_text_block(
        draw,
        title,
        xy=(x, y),
        width=width,
        font_path=FONT_SANS_BOLD,
        size=52,
        fill=INK,
        line_gap=8,
    )
    y += 10
    return draw_text_block(draw, body, xy=(x, y), width=width, font_path=FONT_SANS, size=24, fill=MUTED, line_gap=10)


def create_slide_overview() -> Image.Image:
    image = make_canvas()
    draw = ImageDraw.Draw(image)
    pill(draw, (84, 60), "Early prototype", ACCENT_SOFT, ACCENT)
    end_y = section_title(
        draw,
        84,
        122,
        "From scan output to ALFA-Chains-style PDDL",
        "A compact demo of how Scan2PDDL-ALFA turns observed hosts, services, and versions into a planner-facing problem file.",
        1180,
    )

    left = (84, end_y + 30, 520, 650)
    mid = (582, end_y + 30, 1018, 650)
    right = (1080, end_y + 30, 1516, 650)
    rounded_card(image, left)
    rounded_card(image, mid)
    rounded_card(image, right)

    card_draw = ImageDraw.Draw(image)
    for box, heading, body, chip in [
        (left, "Input", "Nmap XML plus a lightweight overlay for segmented topology and target selection.", "Observed network"),
        (mid, "Transform", "Normalize products, versions, and service exposure into ALFA-style objects and predicates.", "Structured model"),
        (right, "Output", "Emit a motivating-example PDDL problem file aligned to the paper's public representation.", "Planner-facing file"),
    ]:
        x0, y0, x1, y1 = box
        pill(card_draw, (x0 + 24, y0 + 24), chip, ACCENT_SOFT, ACCENT)
        card_draw.text((x0 + 24, y0 + 88), heading, font=font(FONT_SANS_BOLD, 34), fill=INK)
        draw_text_block(
            card_draw,
            body,
            xy=(x0 + 24, y0 + 138),
            width=(x1 - x0) - 48,
            font_path=FONT_SANS,
            size=23,
            fill=MUTED,
            line_gap=8,
        )

    flow_box = (84, 690, 1516, 848)
    rounded_card(image, flow_box)
    draw = ImageDraw.Draw(image)
    draw.text((114, 720), "Example flow", font=font(FONT_SANS_BOLD, 30), fill=INK)
    flow_text = "examples/alfa_motivating_scan.xml  +  examples/alfa_motivating_overlay.json  ->  scan2pddl-alfa  ->  examples/alfa_motivating_problem.pddl"
    draw_text_block(
        draw,
        flow_text,
        xy=(114, 766),
        width=1280,
        font_path=FONT_MONO,
        size=20,
        fill="#314a68",
        line_gap=7,
    )
    return image


def create_slide_cli() -> Image.Image:
    image = make_canvas()
    draw = ImageDraw.Draw(image)
    pill(draw, (84, 60), "CLI demo", ACCENT_SOFT, ACCENT)
    end_y = section_title(
        draw,
        84,
        122,
        "Generate the motivating-example PDDL in one command",
        "Committed scan plus overlay in, planner-facing .pddl out.",
        860,
    )

    summary_box = (1048, 122, 1516, 372)
    rounded_card(image, summary_box)
    draw = ImageDraw.Draw(image)
    x0, y0, x1, y1 = summary_box
    draw.text((x0 + 28, y0 + 26), "Demo inputs", font=font(FONT_SANS_BOLD, 30), fill=INK)
    summary_rows = [
        ("Scan", "examples/alfa_motivating_scan.xml"),
        ("Overlay", "examples/alfa_motivating_overlay.json"),
        ("Output", "output/pddl/problem.pddl"),
    ]
    row_y = y0 + 82
    label_font = font(FONT_SANS_BOLD, 18)
    value_font = font(FONT_MONO, 15)
    for label, value in summary_rows:
        draw.rounded_rectangle((x0 + 28, row_y - 2, x0 + 110, row_y + 30), radius=16, fill=ACCENT_SOFT)
        draw.text((x0 + 44, row_y + 4), label, font=label_font, fill=ACCENT)
        draw.text((x0 + 128, row_y + 4), value, font=value_font, fill="#314a68")
        row_y += 50

    code_panel(
        image,
        (84, 384, 1516, 674),
        "PowerShell",
        "PS C:\\Users\\Administrator\\Desktop\\scan2pddl-alfa> scan2pddl-alfa examples\\alfa_motivating_scan.xml \\\n"
        "   --overlay examples\\alfa_motivating_overlay.json \\\n"
        "   --output output\\pddl\\problem.pddl\n"
        "\n"
        "done: wrote output\\pddl\\problem.pddl\n"
        "check: public-paper structural alignment confirmed\n"
        "scope: early prototype, not a full domain-file pipeline",
        footer="Windows PowerShell",
        dark=True,
    )

    bottom_cards = [
        ((84, 706, 520, 902), "Scan facts", "Observed hosts, versions, and exposed services come from the committed Nmap XML."),
        ((582, 706, 1018, 902), "Topology hint", "A lightweight overlay supplies dmz / lan semantics and the target host selection."),
        ((1080, 706, 1516, 902), "Result", "The command emits an ALFA-Chains-style problem file ready for paper-level alignment review."),
    ]
    for box, heading, body in bottom_cards:
        rounded_card(image, box)
        draw = ImageDraw.Draw(image)
        x0, y0, x1, y1 = box
        draw.text((x0 + 24, y0 + 24), heading, font=font(FONT_SANS_BOLD, 30), fill=INK)
        draw_text_block(
            draw,
            body,
            xy=(x0 + 24, y0 + 78),
            width=(x1 - x0) - 48,
            font_path=FONT_SANS,
            size=18,
            fill=MUTED,
            line_gap=6,
        )
    return image


def create_slide_alignment() -> Image.Image:
    image = make_canvas()
    draw = ImageDraw.Draw(image)
    pill(draw, (84, 60), "Public paper alignment", ACCENT_SOFT, ACCENT)
    end_y = section_title(
        draw,
        84,
        122,
        "Generated PDDL aligned to the paper's public representation",
        "The screenshot below uses the actual motivating-example output committed in the repository.",
        1260,
    )
    pddl_snippet = "\n".join(
        [
            ";; excerpt from examples/alfa_motivating_problem.pddl",
            "(is_compromised attacker_host agent ROOT_PRIVILEGES)",
            "(connected_to_network attacker_host dmz)",
            "(connected_to_network web_server dmz)",
            "(connected_to_network web_server lan)",
            "(has_product web_server a--drupal--drupal)",
            "(has_version web_server a--drupal--drupal ma8 mi6 pa9)",
            "(TCP_listen db_server a--apache--couchdb)",
            "(:goal",
            "  (is_compromised db_server agent ROOT_PRIVILEGES)",
            ")",
        ]
    )
    code_panel(image, (84, end_y + 24, 910, 808), "examples/alfa_motivating_problem.pddl", pddl_snippet)

    rounded_card(image, (950, end_y + 24, 1516, 808))
    draw = ImageDraw.Draw(image)
    draw.text((980, end_y + 56), "Aligned public elements", font=font(FONT_SANS_BOLD, 34), fill=INK)
    bullets = [
        "Initial foothold and goal clause",
        "connected_to_network topology",
        "has_product and has_version config",
        "TCP_listen exposure",
    ]
    y = end_y + 120
    for bullet in bullets:
        draw.ellipse((980, y + 8, 994, y + 22), fill=ACCENT)
        draw_text_block(
            draw,
            bullet,
            xy=(1008, y),
            width=470,
            font_path=FONT_SANS,
            size=20,
            fill=MUTED,
            line_gap=6,
        )
        y += 78

    draw_text_block(
        draw,
        "Scope: paper-level structural alignment to the public representation, not verified drop-in compatibility.",
        xy=(980, 732),
        width=500,
        font_path=FONT_SANS,
        size=18,
        fill=MUTED,
        line_gap=7,
    )
    return image


def save_slides(slides: list[tuple[str, Image.Image]]) -> list[Path]:
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for filename, image in slides:
        path = SCREENSHOT_DIR / filename
        image.save(path, quality=95)
        paths.append(path)
    return paths


def blend_frames(first: Image.Image, second: Image.Image, steps: int) -> list[Image.Image]:
    frames: list[Image.Image] = []
    for step in range(steps):
        alpha = step / max(steps - 1, 1)
        frames.append(Image.blend(first, second, alpha))
    return frames


def write_video(images: list[Image.Image]) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    fps = 24
    writer = imageio.get_writer(
        VIDEO_PATH,
        fps=fps,
        codec="libx264",
        format="FFMPEG",
        ffmpeg_log_level="error",
        macro_block_size=16,
    )
    try:
        for idx, current in enumerate(images):
            hold = 2.8 if idx == 0 else 3.2
            for _ in range(int(math.ceil(hold * fps))):
                writer.append_data(np.asarray(current))
            if idx + 1 < len(images):
                for frame in blend_frames(current, images[idx + 1], steps=18):
                    writer.append_data(np.asarray(frame))
        last = images[-1]
        for _ in range(int(1.6 * fps)):
            writer.append_data(np.asarray(last))
    finally:
        writer.close()
    return VIDEO_PATH


def main() -> None:
    slides = [
        ("01_overview.png", create_slide_overview()),
        ("02_cli_demo.png", create_slide_cli()),
        ("03_pddl_alignment.png", create_slide_alignment()),
    ]
    paths = save_slides(slides)
    video_path = write_video([image for _, image in slides])
    print("Screenshots:")
    for path in paths:
        print(path)
    print("Video:")
    print(video_path)
    print("FFmpeg binary:")
    print(imageio_ffmpeg.get_ffmpeg_exe())


if __name__ == "__main__":
    main()
