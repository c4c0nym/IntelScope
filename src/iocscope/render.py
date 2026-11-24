"""Terminal output (rich)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from iocscope.models import EnrichedIOC, Verdict
from iocscope.palette import GREEN_BLUE, MINERAL_GRAY, VERDICT_GLYPHS
from iocscope.providers import LABELS


def verdict_badge(verdict: Verdict) -> Text:
    glyph = VERDICT_GLYPHS[verdict.value]
    return Text(f" {glyph} {verdict.value.upper()} ", style=f"verdict.{verdict.value}")


def _evidence(item: EnrichedIOC) -> Text:
    text = Text()
    lines: list[Text] = []
    if item.allowlisted:
        lines.append(Text.assemble(("allowlist ", "provider"), (item.reasons[0], "muted")))
    for r in item.results:
        label = LABELS.get(r.provider, r.provider)
        if r.ok:
            line = Text.assemble((f"{label} ", "provider"), r.summary)
            if r.cached:
                line.append(" (cached)", style="muted")
        else:
            line = Text.assemble((f"{label} ", "provider"), (f"error: {r.error}", "muted italic"))
        lines.append(line)
    for reason in item.reasons:
        if reason.startswith("conflict:"):
            lines.append(Text(reason, style="warn"))
    if not lines:
        lines.append(Text("no data", style="muted"))
    for i, line in enumerate(lines):
        if i:
            text.append("\n")
        text.append_text(line)
    return text


def render_table(console: Console, items: Sequence[EnrichedIOC]) -> None:
    table = Table(
        title=Text("iocscope · enrichment results", style="accent"),
        box=box.SIMPLE_HEAD,
        header_style=f"bold {GREEN_BLUE}",
        border_style=MINERAL_GRAY,
        pad_edge=False,
        show_lines=True,
    )
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Indicator", overflow="fold", max_width=48)
    table.add_column("Type", style="muted", no_wrap=True)
    table.add_column("Evidence", overflow="fold")

    for item in items:
        indicator = Text(item.ioc.value)
        if item.ioc.original != item.ioc.value:
            indicator.append(f"\n{item.ioc.original}", style="muted")
        table.add_row(
            verdict_badge(item.verdict),
            Text(str(item.score), style=f"score.{item.verdict.value}"),
            indicator,
            item.ioc.type.value,
            _evidence(item),
        )
    console.print(table)
    console.print(summary_line(items))


def summary_line(items: Sequence[EnrichedIOC]) -> Text:
    counts = Counter(i.verdict for i in items)
    text = Text(f"{len(items)} indicators  ", style="bold")
    for verdict in (
        Verdict.MALICIOUS,
        Verdict.SUSPICIOUS,
        Verdict.LOW,
        Verdict.UNKNOWN,
        Verdict.BENIGN,
    ):
        text.append(f" {VERDICT_GLYPHS[verdict.value]} {counts.get(verdict, 0)} {verdict.value} ",
                    style=f"score.{verdict.value}")
    return text
