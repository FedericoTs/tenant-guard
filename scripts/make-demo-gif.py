#!/usr/bin/env python3
"""
Render the README hero GIF from REAL tenant-guard output.

    FORCE_COLOR=1 npm run demo > demo.ansi
    python scripts/make-demo-gif.py demo.ansi assets/demo.gif

Nothing here invents output. It parses the ANSI that `examples/demo/demo.mjs`
actually printed, wraps it, and animates it into a terminal window — so the GIF
cannot drift from what the tool does, and anyone can reproduce it with
`npm run demo`.

Needs Pillow, fontTools, and a monospace TTF. On Windows it prefers Cascadia
Mono, which carries the check glyph; Segoe UI Symbol fills in the few glyphs no
monospace font here has (the ballot X), drawn centred in its cell so the grid
still lines up.
"""
import os
import re
import sys

from PIL import Image, ImageDraw, ImageFont

try:
    from fontTools.ttLib import TTFont
except ImportError:
    TTFont = None

# ── terminal look ────────────────────────────────────────────────────
SCALE = 2                      # render at 2x, downsample for crisp text
COLS = 94                      # wrap width in characters
VIEW_ROWS = 23                 # visible rows
FONT_PX = 15
PAD = 18
TITLEBAR = 30
PALETTE_COLORS = 48            # a terminal needs nowhere near 256

BG = (13, 17, 23)
TITLE_BG = (22, 27, 34)
FG = (201, 209, 217)
DIM = (125, 133, 144)
RED = (248, 81, 73)
GREEN = (63, 185, 80)
YELLOW = (210, 153, 34)
BOLD_FG = (255, 255, 255)
PROMPT = (88, 166, 255)

FRAME_MS = 130
LINES_PER_FRAME = 3            # scrolling defeats GIF delta-compression, so
                               # every scrolled frame costs a full frame
HOLD_END_MS = 3400

SGR = {'0': 'reset', '1': 'bold', '2': 'dim', '31': RED, '32': GREEN, '33': YELLOW}

MONO_CANDIDATES = [
    r'C:\Windows\Fonts\CascadiaMono.ttf',
    r'C:\Windows\Fonts\consola.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
    '/System/Library/Fonts/Menlo.ttc',
]
FALLBACK_CANDIDATES = [
    r'C:\Windows\Fonts\seguisym.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
]


def first_existing(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def cmap_of(path):
    """The set of codepoints a font can actually draw (empty = assume all)."""
    if TTFont is None or not path:
        return None
    try:
        return set(TTFont(path, fontNumber=0).getBestCmap().keys())
    except Exception:
        return None


def parse_ansi(text):
    """ANSI SGR -> [[(chars, colour, bold, dim), ...], ...], one list per line."""
    lines = []
    colour, bold, dim = FG, False, False
    for raw in text.split('\n'):
        spans, buf = [], ''
        i = 0
        while i < len(raw):
            m = re.match(r'\x1b\[([0-9;]*)m', raw[i:])
            if m:
                if buf:
                    spans.append((buf, colour, bold, dim))
                    buf = ''
                for code in (m.group(1) or '0').split(';'):
                    v = SGR.get(code)
                    if v == 'reset':
                        colour, bold, dim = FG, False, False
                    elif v == 'bold':
                        bold = True
                    elif v == 'dim':
                        dim = True
                    elif isinstance(v, tuple):
                        colour = v
                i += m.end()
                continue
            buf += raw[i]
            i += 1
        if buf:
            spans.append((buf, colour, bold, dim))
        lines.append(spans)
    return lines


def wrap(lines, cols):
    """
    Wrap to `cols`, preserving each line's own indentation and its styling.

    The leading whitespace has to be carried explicitly: splitting on words
    discards it, and losing it flattens the report's structure — which is most of
    how the output is readable at all.
    """
    out = []
    for spans in lines:
        plain = ''.join(s[0] for s in spans)
        if len(plain) <= cols:
            out.append(spans)
            continue

        indent = len(plain) - len(plain.lstrip(' '))
        pad = ' ' * indent
        hang = ' ' * min(indent + 2, max(cols - 20, 0))

        cur, width, first = [], 0, True
        if indent:
            cur.append((pad, DIM, False, False))
            width = indent

        for text, colour, bold, dim in spans:
            body = text[indent:] if first and not cur[1:] and text.startswith(pad) else text
            if first and body is not text:
                pass  # the indent was hoisted into `pad` above
            for word in re.findall(r'\S+\s*', body) or []:
                limit = cols if first else cols - len(hang)
                if width + len(word) > limit and any(w[0].strip() for w in cur):
                    out.append(cur)
                    first = False
                    cur = [(hang, DIM, False, False)]
                    width = len(hang)
                    word = word.lstrip(' ')
                    if not word:
                        continue
                cur.append((word, colour, bold, dim))
                width += len(word)
        if any(w[0].strip() for w in cur):
            out.append(cur)
    return out


class Renderer:
    def __init__(self, mono_path, fallback_path, px):
        self.font = ImageFont.truetype(mono_path, px)
        self.mono_cmap = cmap_of(mono_path)
        # Segoe UI Symbol's ballot glyphs are lighter than the mono stroke at the
        # same size, so nudge them up to match visually.
        self.fallback = ImageFont.truetype(fallback_path, int(px * 1.15)) if fallback_path else None
        probe = ImageDraw.Draw(Image.new('RGB', (1, 1)))
        self.cw = probe.textlength('M', font=self.font)
        self.ch = int(px * 1.42)

    def _drawable(self, ch):
        return self.mono_cmap is None or ord(ch) in self.mono_cmap

    def text(self, d, x, y, s, fill):
        """Draw a run, dropping to the fallback font for glyphs the mono lacks."""
        if self.fallback is None or all(self._drawable(c) for c in s):
            d.text((x, y), s, font=self.font, fill=fill)
            return x + self.cw * len(s)
        for ch in s:
            if self._drawable(ch):
                d.text((x, y), ch, font=self.font, fill=fill)
            else:
                w = d.textlength(ch, font=self.fallback)
                d.text((x + (self.cw - w) / 2, y), ch, font=self.fallback, fill=fill)
            x += self.cw
        return x

    def frame(self, lines, top, size, title):
        img = Image.new('RGB', size, BG)
        d = ImageDraw.Draw(img)

        d.rectangle([0, 0, size[0], TITLEBAR * SCALE], fill=TITLE_BG)
        for idx, dot in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
            cx, cy, r = (PAD + 6 + idx * 16) * SCALE, (TITLEBAR // 2) * SCALE, 5 * SCALE
            d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=dot)
        tw = d.textlength(title, font=self.font)
        d.text(((size[0] - tw) / 2, (TITLEBAR // 2) * SCALE - self.ch / 2), title, font=self.font, fill=DIM)

        y = (TITLEBAR + PAD) * SCALE
        for spans in lines[top:top + VIEW_ROWS]:
            x = PAD * SCALE
            for text, colour, bold, dim in spans:
                x = self.text(d, x, y, text, BOLD_FG if bold else (DIM if dim else colour))
            y += self.ch
        return img


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else 'demo.ansi'
    dst = sys.argv[2] if len(sys.argv) > 2 else 'assets/demo.gif'

    mono = first_existing(MONO_CANDIDATES)
    if not mono:
        raise SystemExit('no monospace TTF found')
    fallback = first_existing(FALLBACK_CANDIDATES)

    with open(src, 'r', encoding='utf-8') as fh:
        raw = fh.read()

    r = Renderer(mono, fallback, FONT_PX * SCALE)
    body = wrap(parse_ansi(raw.rstrip('\n')), COLS)

    cmd = 'npm run demo'
    prompt = [('$ ', PROMPT, True, False)]
    lines = [prompt + [(cmd, FG, False, False)], []] + body

    size = (int(PAD * 2 * SCALE + r.cw * COLS), (TITLEBAR + PAD * 2) * SCALE + r.ch * VIEW_ROWS)
    title = 'tenant-guard'

    frames, durations = [], []
    for k in range(len(cmd) + 1):
        frames.append(r.frame([prompt + [(cmd[:k], FG, False, False)]], 0, size, title))
        durations.append(35)
    durations[-1] = 450

    n = 2
    while n <= len(lines):
        frames.append(r.frame(lines[:n], max(0, n - VIEW_ROWS), size, title))
        durations.append(FRAME_MS)
        n += LINES_PER_FRAME
    if frames and len(lines) % LINES_PER_FRAME:
        frames.append(r.frame(lines, max(0, len(lines) - VIEW_ROWS), size, title))
        durations.append(FRAME_MS)
    durations[-1] = HOLD_END_MS

    small = [f.resize((size[0] // SCALE, size[1] // SCALE), Image.LANCZOS) for f in frames]

    # One shared palette across every frame: a terminal uses a handful of colours,
    # and a global palette compresses far better than per-frame adaptive ones.
    master = small[-1].quantize(colors=PALETTE_COLORS, method=Image.MEDIANCUT)
    out = [f.quantize(palette=master, dither=Image.NONE) for f in small]

    out[0].save(dst, save_all=True, append_images=out[1:], duration=durations,
                loop=0, optimize=True, disposal=1)
    print(f'{dst}: {out[0].size[0]}x{out[0].size[1]}, {len(out)} frames, '
          f'{os.path.getsize(dst) / 1024:.0f} KB  [{os.path.basename(mono)}]')


if __name__ == '__main__':
    main()
