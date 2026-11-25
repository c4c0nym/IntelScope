"""Regenerate docs/demo.svg, docs/sample-report.html and the dashboard demo data.

    python scripts/make_demo_assets.py
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

from rich.console import Console
from rich.terminal_theme import TerminalTheme

from intelscope.allowlist import load_allowlist
from intelscope.demo import DEMO_IOCS, build_demo_providers
from intelscope.detect import parse_iocs
from intelscope.enrich import Enricher, triage_order
from intelscope.export import to_html
from intelscope.palette import (
    BENZOL_GREEN,
    GRAYISH_LAVENDER,
    GREEN_BLUE,
    INK,
    ISABELLA,
    IVORY_BUFF,
    THEME,
)
from intelscope.providers import REGISTRY
from intelscope.render import render_table


def _rgb(hex_colour: str) -> tuple[int, int, int]:
    h = hex_colour.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


ansi = [_rgb(c) for c in (INK, ISABELLA, BENZOL_GREEN, IVORY_BUFF, GREEN_BLUE,
                          GRAYISH_LAVENDER, GREEN_BLUE, IVORY_BUFF)]
TERMINAL = TerminalTheme(_rgb("#182223"), _rgb("#f3ead6"), ansi, ansi)

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
DASHBOARD = ROOT / "src" / "intelscope" / "web" / "dashboard.html"


def main() -> None:
    iocs, _ = parse_iocs(DEMO_IOCS)
    enricher = Enricher(build_demo_providers(list(REGISTRY)),
                        allowlist=load_allowlist(skip_reserved=False))
    results = triage_order(enricher.enrich(iocs))

    console = Console(record=True, width=132, theme=THEME, file=io.StringIO(),
                      force_terminal=True, color_system="truecolor")
    console.print("[muted]$[/] intelscope -f iocs.txt -o report.html")
    render_table(console, results)
    console.print("[accent]wrote[/] report.html [muted](html)[/]")
    DOCS.mkdir(exist_ok=True)
    console.save_svg(str(DOCS / "demo.svg"), title="IntelScope", theme=TERMINAL)

    (DOCS / "sample-report.html").write_text(to_html(results), encoding="utf-8")

    # The dashboard embeds the same demo results, so "Load demo" works with no server.
    page = DASHBOARD.read_text(encoding="utf-8")
    blob = json.dumps([r.to_dict() for r in results], ensure_ascii=False, separators=(",", ":"))
    blob = blob.replace("</", "<" + chr(92) + "/")
    page, n = re.subn(r"/\*DEMO\*/.*?/\*END\*/", lambda _m: f"/*DEMO*/{blob}/*END*/", page, flags=re.S)
    assert n == 1, "demo markers not found in dashboard.html"
    DASHBOARD.write_text(page, encoding="utf-8")
    print(f"wrote {DOCS / 'demo.svg'}, {DOCS / 'sample-report.html'} and the dashboard demo data")


if __name__ == "__main__":
    main()
