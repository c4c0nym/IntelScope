"""Regenerate docs/demo.svg and docs/sample-report.html from the offline demo data.

    python scripts/make_demo_assets.py
"""

from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console
from rich.terminal_theme import TerminalTheme

from iocscope.allowlist import load_allowlist
from iocscope.demo import DEMO_IOCS, build_demo_providers
from iocscope.detect import parse_iocs
from iocscope.enrich import Enricher, triage_order
from iocscope.export import to_html
from iocscope.palette import (
    BENZOL_GREEN,
    GRAYISH_LAVENDER,
    GREEN_BLUE,
    INK,
    ISABELLA,
    IVORY_BUFF,
    THEME,
)
from iocscope.providers import REGISTRY
from iocscope.render import render_table


def _rgb(hex_colour: str) -> tuple[int, int, int]:
    h = hex_colour.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


ansi = [_rgb(c) for c in (INK, ISABELLA, BENZOL_GREEN, IVORY_BUFF, GREEN_BLUE,
                          GRAYISH_LAVENDER, GREEN_BLUE, IVORY_BUFF)]
TERMINAL = TerminalTheme(_rgb("#182223"), _rgb("#f3ead6"), ansi, ansi)

DOCS = Path(__file__).resolve().parent.parent / "docs"


def main() -> None:
    iocs, _ = parse_iocs(DEMO_IOCS)
    enricher = Enricher(build_demo_providers(list(REGISTRY)),
                        allowlist=load_allowlist(skip_reserved=False))
    results = triage_order(enricher.enrich(iocs))

    console = Console(record=True, width=132, theme=THEME, file=io.StringIO(),
                      force_terminal=True, color_system="truecolor")
    console.print("[muted]$[/] iocscope -f iocs.txt -o report.html")
    render_table(console, results)
    console.print("[accent]wrote[/] report.html [muted](html)[/]")
    DOCS.mkdir(exist_ok=True)
    console.save_svg(str(DOCS / "demo.svg"), title="iocscope", theme=TERMINAL)

    (DOCS / "sample-report.html").write_text(to_html(results), encoding="utf-8")
    print(f"wrote {DOCS / 'demo.svg'} and {DOCS / 'sample-report.html'}")


if __name__ == "__main__":
    main()
