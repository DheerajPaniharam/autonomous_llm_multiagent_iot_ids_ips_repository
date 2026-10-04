from PIL import Image, ImageDraw, ImageFont

W, H = 4200, 2360
FONT_PATH = "C:/Windows/Fonts/segoeui.ttf"
FONT_BOLD_PATH = "C:/Windows/Fonts/segoeuib.ttf"
FONT_SEMIBOLD_PATH = "C:/Windows/Fonts/seguisb.ttf"

f_tier_num = ImageFont.truetype(FONT_BOLD_PATH, 34)
f_tier_name = ImageFont.truetype(FONT_BOLD_PATH, 23)

img = Image.new("RGBA", (W, H), "#FFFFFF")
draw = ImageDraw.Draw(img)

# Geometry
L_TAB_L = 40
L_TAB_R = 360
tab_w = L_TAB_R - L_TAB_L

tabs = [
    ("Tab 1", ["LAYER 1", "PRESENTATION"]),
    ("Tab 2", ["LAYER 2", "APPLICATION &", "MULTI-AGENT"]),
    ("Tab 3", ["LAYER 3", "AI / COGNITIVE", "REASONING"]),
    ("Tab 4", ["LAYER 4", "DATA & KERNEL", "INFRASTRUCTURE"])
]

all_passed = True
print("=== TABS VERIFICATION ===")
for name, lines in tabs:
    for l in lines:
        font = f_tier_num if l.startswith("LAYER") else f_tier_name
        b = draw.textbbox((0,0), l, font=font)
        w = b[2] - b[0]
        pad = (tab_w - w) / 2
        print(f'{name} line "{l}": width={w}px, Pad={pad:.1f}px (Tab width={tab_w}px)')
        if pad < 35:
            all_passed = False
            print("  >>> FAILED: Tight margin!")

print(f"\nOverall Tab Status: {'ALL PASSED' if all_passed else 'FAILED'}")
