#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project
"""Build Sofia Sans Tally, the metric-adjusted Sofia Sans that DiamaneOS uses as its system font.

Sofia Sans draws its lowercase smaller than Roboto (x-height 0.488 em against 0.528), so at the
same size it looks about 8 % smaller. Each output font is the unmodified upstream file (listed in
../source.json) with five changes:

- Every glyph is drawn 1.08 times larger against the em, with its advance, kerning and mark
  positions, so the x-height matches Roboto's (0.527 against 0.528 em). The em becomes 2048
  units, as Roboto's.
- Every spacing glyph is 0.0125 of the drawn size narrower (0.0135 em, 28 units; a ligature once
  for each letter it stands for), so a line of text is as long as in Roboto. This is the Tally
  prototype's size step and tracking (design/prototypes/tally/README.md, "Type") built into the
  font.
- The vertical metrics are Roboto's, so text takes the same line height and padding as it does
  in Roboto: ascent 1900, descent 500 and no line gap (hhea, and OS/2 typo with USE_TYPO_METRICS
  set, so every text engine agrees), and a font box at least as tall as Roboto's (head yMax 2163,
  yMin -555; OS/2 win 2146 and 555), which Android reads as the top and bottom of the line when
  a view includes font padding.
- Characters text needs that Sofia Sans lacks, where no new drawing is needed: THIN SPACE and
  NARROW NO-BREAK SPACE (U+2009, U+202F: ICU puts the latter before AM and PM in English 12-hour
  times and before French punctuation) as empty glyphs a sixth of the drawn em wide at every
  weight, the six-per-em width, so they stay narrower than the word space (0.19 to 0.27 em over
  the wght axis); HYPHEN and NON-BREAKING HYPHEN (U+2010, U+2011) as the hyphen's glyph, and
  DIVISION SLASH (U+2215) as the slash's. Without them each fell back to Roboto.
- The family is named Sofia Sans Tally (PostScript SofiaSansTally), so it is never mistaken for
  the upstream font. The fonts are under the SIL Open Font License 1.1 as the originals (OFL.txt);
  Sofia Sans has no Reserved Font Name, so the licence does not require the new name.

Everything else is kept: the wght axis (1 to 1000) and its named instances, every OpenType feature
(tnum, case, locl, smcp, ss01, ...), the glyph set, the gasp and prep tables (the upstream fonts
carry no other hinting) and the head timestamps, so the build is reproducible.

Usage, with fontTools and uharfbuzz as pinned in requirements.txt:
  python3 build_tally_fonts.py           verify the inputs' SHA-256, write the fonts into ..
  python3 build_tally_fonts.py --check   build in memory; exit 1 if a file in .. differs
"""
from __future__ import annotations

import argparse
import hashlib
import io
from pathlib import Path
import sys

from fontTools.misc.fixedTools import otRound
from fontTools.ttLib import TTFont
from fontTools.ttLib.scaleUpem import ScalerVisitor
from fontTools.ttLib.tables._g_l_y_f import Glyph
from fontTools.ttLib.tables.otBase import USE_HARFBUZZ_REPACKER

FONT_DIR = Path(__file__).resolve().parent.parent

# The size step and tracking of the Tally prototype (--fk, --trk).
SCALE = 1.08
TRACKING_EM = -0.0125
UPM = 2048
TRACKING = otRound(TRACKING_EM * SCALE * UPM)  # -28: of the drawn size, in the new em

# Roboto 3.015 as Android 17 installs it (/system/fonts/Roboto-Regular.ttf), 2048 units per em.
ROBOTO_ASCENT = 1900
ROBOTO_DESCENT = -500
ROBOTO_LINE_GAP = 0
ROBOTO_Y_MAX = 2163
ROBOTO_Y_MIN = -555
ROBOTO_WIN_ASCENT = 2146
ROBOTO_WIN_DESCENT = 555

USE_TYPO_METRICS = 1 << 7

# Spaces added as empty glyphs (character: glyph name), a sixth of the em wide in the upstream em,
# with no variation, before the size step and tracking.
NARROW_SPACES = {0x2009: 'uni2009', 0x202F: 'uni202F'}
NARROW_SPACE_EM = 1 / 6
# Characters drawn with a glyph the font has (character: glyph name).
ALIASES = {0x2010: 'hyphen', 0x2011: 'hyphen', 0x2215: 'slash'}

# (input, its SHA-256 as source.json records it, output)
FONTS = (
    ('SofiaSans-Regular.ttf',
     'a3e1019b8867e21b75d26a7b59d4eb2c81d1acf6b69b9ae6cedca269fb68e291',
     'SofiaSansTally-Regular.ttf'),
    ('SofiaSans-Italic.ttf',
     'c0e69116d34100212881b5f993225ff0c3ea23e2c147f4c0853389923c9ab6a5',
     'SofiaSansTally-Italic.ttf'),
    ('SofiaSansSemiCondensed-Regular.ttf',
     '7942e1c0b370cb5fe8dbf3584a3f38a913ad84a27e13e74ccd0e547e43d57a1f',
     'SofiaSansTallySemiCondensed-Regular.ttf'),
    ('SofiaSansSemiCondensed-Italic.ttf',
     'ac7f4f8e5cee9c63c722c52e6cb73c97a7894992746e90a0ee8286291e4dfaff',
     'SofiaSansTallySemiCondensed-Italic.ttf'),
)

FAMILY, FAMILY_NEW = 'Sofia Sans', 'Sofia Sans Tally'
PS_FAMILY, PS_FAMILY_NEW = 'SofiaSans', 'SofiaSansTally'
MANUFACTURER = 'The DiamaneOS Project'
VENDOR_URL = 'https://diamaneos.de'
VENDOR_ID = 'NONE'
DESCRIPTION = (
    'Sofia Sans by lettersoup (Botio Nikoltchev, Ani Petrova), metric-adjusted for DiamaneOS: '
    'glyphs drawn 1.08 times larger, tracking -0.0125 of the drawn size, and the vertical '
    "metrics of Roboto, so that it sets text at Roboto's size and length."
)


def ligature_lengths(font: TTFont) -> dict[str, int]:
    """How many characters each ligature glyph stands for, from GSUB's ligature lookups."""
    lengths: dict[str, int] = {}
    if 'GSUB' not in font:
        return lengths
    for lookup in font['GSUB'].table.LookupList.Lookup:
        for subtable in lookup.SubTable:
            if lookup.LookupType == 7:
                subtable = subtable.ExtSubTable
            if getattr(subtable, 'LookupType', lookup.LookupType) != 4:
                continue
            for ligatures in subtable.ligatures.values():
                for ligature in ligatures:
                    n = len(ligature.Component) + 1
                    lengths[ligature.LigGlyph] = max(n, lengths.get(ligature.LigGlyph, 1))
    return lengths


def add_characters(font: TTFont) -> None:
    """Adds NARROW_SPACES and ALIASES to the font's Unicode cmaps (and the spaces' glyphs)."""
    for tag in font.keys():
        font[tag]  # read with the glyph order the file has, before it grows
    order = font.getGlyphOrder()
    missing = [n for n in ALIASES.values() if n not in order]
    taken = [n for n in NARROW_SPACES.values() if n in order]
    if missing or taken:
        raise ValueError(f'unexpected glyph set: missing {missing}, already there {taken}')
    width = otRound(font['head'].unitsPerEm * NARROW_SPACE_EM)
    # A row of zero deltas in the advance widths' variation store: a constant advance.
    hvar = font['HVAR'].table
    data = hvar.VarStore.VarData[0]
    data.Item.append([0] * data.VarRegionCount)
    data.ItemCount = len(data.Item)
    constant = len(data.Item) - 1  # outer index 0
    font.setGlyphOrder(order + list(NARROW_SPACES.values()))
    for name in NARROW_SPACES.values():
        font['glyf'][name] = Glyph()
        font['hmtx'].metrics[name] = (width, 0)
        font['gvar'].variations[name] = []
        hvar.AdvWidthMap.mapping[name] = constant
    for table in font['cmap'].tables:
        if table.isUnicode():
            table.cmap.update(NARROW_SPACES)
            table.cmap.update(ALIASES)


def rename(font: TTFont) -> str:
    """Names the font Sofia Sans Tally; returns the new PostScript name."""
    name = font['name']
    ps_name = str(name.getName(6, 3, 1, 0x409)).replace(PS_FAMILY, PS_FAMILY_NEW, 1)
    version = str(name.getName(5, 3, 1, 0x409))
    revision = version.removeprefix('Version ')
    for record in name.names:
        text = record.toUnicode()
        if record.nameID in (1, 4, 16, 18, 21):
            text = text.replace(FAMILY, FAMILY_NEW, 1)
        elif record.nameID in (6, 20, 25):
            text = text.replace(PS_FAMILY, PS_FAMILY_NEW, 1)
        elif record.nameID == 3:
            text = f'{revision};DiamaneOS;{ps_name}'
        elif record.nameID == 5:
            text = f'{version}; metric-adjusted for DiamaneOS'
        elif record.nameID == 8:
            text = MANUFACTURER
        elif record.nameID == 11:
            text = VENDOR_URL
        else:
            continue
        record.string = text
    name.setName(DESCRIPTION, 10, 3, 1, 0x409)
    font['OS/2'].achVendID = VENDOR_ID
    return ps_name


# fontTools packs GSUB and GPOS with HarfBuzz's repacker if uharfbuzz is installed, else with its
# own serializer, and the bytes differ. The recorded SHA-256 come from the repacker: require it,
# so a build without uharfbuzz stops (ImportError) instead of writing different fonts.
FONTTOOLS_CFG = {USE_HARFBUZZ_REPACKER: True}


def build(source: bytes) -> tuple[bytes, str]:
    font = TTFont(io.BytesIO(source), recalcBBoxes=True, recalcTimestamp=False,
                  cfg=FONTTOOLS_CFG)
    ligatures = ligature_lengths(font)
    marks = set()
    if 'GDEF' in font and font['GDEF'].table.GlyphClassDef:
        marks = {g for g, c in font['GDEF'].table.GlyphClassDef.classDefs.items() if c == 3}
    add_characters(font)

    # Draw everything SCALE times larger against a UPM em: outlines, their variations, advances
    # and their variations (HVAR), kerning, anchors and the other metrics.
    ScalerVisitor(SCALE * UPM / font['head'].unitsPerEm).visit(font)
    font['head'].unitsPerEm = UPM

    # The tracking, on every glyph that takes up space.
    hmtx = font['hmtx'].metrics
    for glyph, (advance, lsb) in hmtx.items():
        if advance > 0 and glyph not in marks:
            hmtx[glyph] = (max(0, advance + TRACKING * ligatures.get(glyph, 1)), lsb)

    hhea, os2 = font['hhea'], font['OS/2']
    hhea.ascent, hhea.descent, hhea.lineGap = ROBOTO_ASCENT, ROBOTO_DESCENT, ROBOTO_LINE_GAP
    os2.sTypoAscender, os2.sTypoDescender = ROBOTO_ASCENT, ROBOTO_DESCENT
    os2.sTypoLineGap = ROBOTO_LINE_GAP
    os2.fsSelection |= USE_TYPO_METRICS
    ps_name = rename(font)

    # First save: fontTools computes the glyph boxes, the font box, hhea's extents and the
    # average width from the new outlines and advances.
    first = io.BytesIO()
    font.save(first)

    # Then the font box and the win metrics grow to Roboto's where they are smaller, and are kept
    # as set.
    font = TTFont(io.BytesIO(first.getvalue()), recalcBBoxes=False, recalcTimestamp=False,
                  cfg=FONTTOOLS_CFG)
    head, os2 = font['head'], font['OS/2']
    y_max, y_min = head.yMax, head.yMin
    head.yMax, head.yMin = max(y_max, ROBOTO_Y_MAX), min(y_min, ROBOTO_Y_MIN)
    os2.usWinAscent = max(y_max, ROBOTO_WIN_ASCENT)
    os2.usWinDescent = max(-y_min, ROBOTO_WIN_DESCENT)
    out = io.BytesIO()
    font.save(out)
    return out.getvalue(), ps_name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--check', action='store_true',
                        help='build in memory and compare with the fonts in the directory')
    args = parser.parse_args(argv)

    failed = False
    for source_name, sha256, output_name in FONTS:
        source = (FONT_DIR / source_name).read_bytes()
        if hashlib.sha256(source).hexdigest() != sha256:
            print(f'{source_name}: SHA-256 differs from the pinned upstream file', file=sys.stderr)
            return 1
        data, ps_name = build(source)
        digest = hashlib.sha256(data).hexdigest()
        target = FONT_DIR / output_name
        if args.check:
            same = target.is_file() and target.read_bytes() == data
            failed |= not same
            print(f'{output_name}: {"same" if same else "DIFFERS"} ({digest})')
        else:
            target.write_bytes(data)
            print(f'{output_name}: {ps_name}, {len(data)} bytes, sha256 {digest}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
