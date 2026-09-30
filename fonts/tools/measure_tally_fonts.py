#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project
"""Measure Sofia Sans Tally against Roboto, and against the prototype's emulation of it.

For each size and weight: the x-height and cap height (the top of x and H), the width of the
audit's test string shaped with HarfBuzz (kerning on) and its average advance, and the line height
Android gives a line of text (ascent to descent, plus the line gap) with the top and bottom it
uses when a view includes font padding. Sizes are in px at 1 px per sp, as the prototype measures.

  emulation  upstream Sofia Sans at 1.08 times the size with -0.0125 em letter spacing per
             character, as the prototype draws it (design/prototypes/tally/app.css --fk, --trk)
  fork       Sofia Sans Tally at the size itself

Needs uharfbuzz and fontTools (requirements.txt), and a Roboto file, for example the phone's
/system/fonts/Roboto-Regular.ttf:
  python3 measure_tally_fonts.py --roboto Roboto-Regular.ttf
"""
from __future__ import annotations

import argparse
from pathlib import Path

import uharfbuzz as hb
from fontTools.ttLib import TTFont

FONT_DIR = Path(__file__).resolve().parent.parent
# The string of the 2026-09 third-party audit (canvas measureText in the prototype).
TEXT = ('Lentil & squash stew · 35 min · serves 4 · Remind me near a shop · '
        'Search recipes · Vegetarian Under 30 min')
SIZES = ((16, 400), (16, 500), (14, 400), (14, 500))
STEP, TRACKING_EM = 1.08, -0.0125


class Face:
    def __init__(self, path: Path):
        self.path = path
        self.blob = hb.Blob.from_file_path(str(path))
        self.tt = TTFont(path)
        self.upem = self.tt['head'].unitsPerEm
        hhea, head = self.tt['hhea'], self.tt['head']
        self.ascent, self.descent, self.gap = hhea.ascent, hhea.descent, hhea.lineGap
        self.top, self.bottom = head.yMax, head.yMin

    def font(self, weight: int) -> hb.Font:
        font = hb.Font(hb.Face(self.blob))
        axes = {a.axisTag for a in self.tt['fvar'].axes} if 'fvar' in self.tt else set()
        font.set_variations({'wght': weight} if 'wght' in axes else {})
        return font

    def top_of(self, font: hb.Font, char: str) -> float:
        gid = font.get_nominal_glyph(ord(char))
        extents = font.get_glyph_extents(gid)
        return extents.y_bearing / self.upem

    def width(self, font: hb.Font, text: str) -> float:
        buf = hb.Buffer()
        buf.add_str(text)
        buf.guess_segment_properties()
        hb.shape(font, buf, {'kern': True, 'liga': True})
        return sum(p.x_advance for p in buf.glyph_positions) / self.upem


def measure(face: Face, size: float, weight: int, step: float = 1.0, tracking: float = 0.0):
    font = face.font(weight)
    drawn = size * step
    width = face.width(font, TEXT) * drawn + tracking * drawn * len(TEXT)
    return {
        'x': face.top_of(font, 'x') * drawn,
        'H': face.top_of(font, 'H') * drawn,
        'width': width,
        'advance': width / len(TEXT),
        'line': (face.ascent - face.descent + face.gap) / face.upem * drawn,
        'padded': (face.top - face.bottom) / face.upem * drawn,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--roboto', type=Path, required=True, help='a Roboto-Regular.ttf')
    parser.add_argument('--upstream', type=Path, default=FONT_DIR / 'SofiaSans-Regular.ttf')
    parser.add_argument('--fork', type=Path, default=FONT_DIR / 'SofiaSansTally-Regular.ttf')
    args = parser.parse_args()
    roboto, upstream, fork = Face(args.roboto), Face(args.upstream), Face(args.fork)

    print(f'{"size":>9} {"font":<10} {"x-height":>9} {"cap":>7} {"width":>8} {"vs Roboto":>9} '
          f'{"advance":>8} {"line":>6} {"padded":>7}')
    for size, weight in SIZES:
        base = measure(roboto, size, weight)
        rows = (
            ('Roboto', base),
            ('upstream', measure(upstream, size, weight)),
            ('emulation', measure(upstream, size, weight, STEP, TRACKING_EM)),
            ('fork', measure(fork, size, weight)),
        )
        for label, m in rows:
            delta = (m['width'] / base['width'] - 1) * 100
            print(f'{size:>3}sp {weight:>4} {label:<10} {m["x"]:9.2f} {m["H"]:7.2f} '
                  f'{m["width"]:8.1f} {delta:+8.2f}% {m["advance"]:8.3f} {m["line"]:6.2f} '
                  f'{m["padded"]:7.2f}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
