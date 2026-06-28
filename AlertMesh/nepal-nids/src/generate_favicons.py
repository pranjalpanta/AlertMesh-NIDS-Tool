#!/usr/bin/env python3
"""
Generate favicon PNG files.

Run this script to create favicon_32.png, favicon_64.png, and favicon_256.png
inside the static directory.
"""

from pathlib import Path

try:
    from PIL import Image, ImageDraw
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Pillow is not available. Install with: pip install Pillow")


def create_favicon_png(size):
    """Create a PNG favicon of the specified size."""
    if not PIL_AVAILABLE:
        print(f"Cannot create favicon_{size}.png without Pillow")
        return False

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    cyan = (0, 255, 255, 255)
    dark = (0, 16, 31, 255)
    light_cyan = (74, 212, 255, 255)
    scale = size / 512

    head_left = int(256 * scale - 78 * scale)
    head_top = 0
    head_right = int(256 * scale + 78 * scale)
    head_bottom = int(69 * scale)
    draw.rectangle([head_left, head_top, head_right, head_bottom], fill=cyan)

    body_left = int(120 * scale)
    body_top = int(122 * scale)
    body_right = int(392 * scale)
    body_bottom = int(223 * scale)
    draw.rectangle(
        [body_left, body_top, body_right, body_bottom],
        fill=dark,
        outline=cyan,
        width=max(1, int(10 * scale)),
    )

    eye_radius = int(42 * scale)
    for eye_x in (int(180 * scale), int(330 * scale)):
        eye_y = int(300 * scale)
        draw.ellipse(
            [eye_x - eye_radius, eye_y - eye_radius, eye_x + eye_radius, eye_y + eye_radius],
            fill=light_cyan,
        )

    static_dir = Path(__file__).parent / "static"
    static_dir.mkdir(exist_ok=True)

    output_path = static_dir / f"favicon_{size}.png"
    img.save(output_path, "PNG")
    print(f"Created {output_path.name}")
    return True


def main():
    print("Generating favicon PNG files...")
    success = all(create_favicon_png(size) for size in (32, 64, 256))

    if success:
        print("All favicons created successfully.")
    else:
        print("Install Pillow for PNG generation: pip install Pillow")


if __name__ == "__main__":
    main()
