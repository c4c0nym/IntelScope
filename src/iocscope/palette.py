"""Colour palette shared by the terminal output and the HTML report.

Colours come from Sanzo Wada's *A Dictionary of Color Combinations*
(https://colors.elwyn.co/), combinations #11, #12 and #15.
"""

from __future__ import annotations

from rich.theme import Theme

# Combination #11
IVORY_BUFF = "#ebd3a2"
MINERAL_GRAY = "#a2b0ad"
# Combination #12
ISABELLA = "#c5a56e"
GREEN_BLUE = "#099197"
# Combination #15
BENZOL_GREEN = "#00978d"
GRAYISH_LAVENDER = "#b5b1d8"

# Neutral text colour used on top of the palette (not part of the palette itself).
INK = "#1f2a2b"
PAPER = "#fbf7ee"

PALETTE = {
    "Ivory Buff": IVORY_BUFF,
    "Mineral Gray": MINERAL_GRAY,
    "Isabella Color": ISABELLA,
    "Green Blue": GREEN_BLUE,
    "Benzol Green": BENZOL_GREEN,
    "Grayish Lavender": GRAYISH_LAVENDER,
}

# The palette has no red, so severity is carried by glyphs as well as colour.
# That also keeps the output readable for colour-blind analysts and in plain text.
VERDICT_COLOURS = {
    "malicious": ISABELLA,
    "suspicious": IVORY_BUFF,
    "low": GRAYISH_LAVENDER,
    "benign": BENZOL_GREEN,
    "unknown": MINERAL_GRAY,
}

VERDICT_GLYPHS = {
    "malicious": "▲▲▲",
    "suspicious": "▲▲",
    "low": "▲",
    "benign": "✓",
    "unknown": "?",
}

THEME = Theme(
    {
        "accent": f"bold {GREEN_BLUE}",
        "muted": MINERAL_GRAY,
        "info": GRAYISH_LAVENDER,
        "warn": ISABELLA,
        "error": f"bold {ISABELLA}",
        "verdict.malicious": f"bold {INK} on {ISABELLA}",
        "verdict.suspicious": f"bold {INK} on {IVORY_BUFF}",
        "verdict.low": f"{INK} on {GRAYISH_LAVENDER}",
        "verdict.benign": f"bold {INK} on {BENZOL_GREEN}",
        "verdict.unknown": f"{INK} on {MINERAL_GRAY}",
        "score.malicious": f"bold {ISABELLA}",
        "score.suspicious": f"bold {IVORY_BUFF}",
        "score.low": GRAYISH_LAVENDER,
        "score.benign": BENZOL_GREEN,
        "score.unknown": MINERAL_GRAY,
        "provider": f"bold {GRAYISH_LAVENDER}",
        "bar.complete": GREEN_BLUE,
        "bar.finished": BENZOL_GREEN,
        "progress.percentage": IVORY_BUFF,
    }
)
