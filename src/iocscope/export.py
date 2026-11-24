"""Output formats: JSON, CSV, STIX 2.1 and a self-contained HTML report."""

from __future__ import annotations

import csv
import html
import io
import json
import uuid
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timezone
from string import Template

from iocscope import __version__
from iocscope.models import EnrichedIOC, IOCType, Verdict
from iocscope.palette import (
    BENZOL_GREEN,
    GRAYISH_LAVENDER,
    GREEN_BLUE,
    INK,
    ISABELLA,
    IVORY_BUFF,
    MINERAL_GRAY,
    PAPER,
    VERDICT_GLYPHS,
)
from iocscope.providers import LABELS

FORMATS = ("table", "json", "csv", "stix", "html")

# Fixed namespace so the same indicator always maps to the same STIX id across runs.
STIX_NAMESPACE = uuid.UUID("6f1c3f6e-2b7a-4d43-9a49-0c8f3b8f1a52")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stix_time(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def infer_format(path: str | None) -> str | None:
    if not path:
        return None
    lower = path.lower()
    if lower.endswith((".stix.json", ".stix")):
        return "stix"
    for ext, fmt in ((".json", "json"), (".csv", "csv"), (".html", "html"), (".htm", "html")):
        if lower.endswith(ext):
            return fmt
    return None


# --------------------------------------------------------------------------- JSON
def to_json(items: Sequence[EnrichedIOC]) -> str:
    doc = {
        "tool": f"iocscope {__version__}",
        "generated": _now().isoformat(timespec="seconds"),
        "count": len(items),
        "results": [i.to_dict() for i in items],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- CSV
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: object) -> object:
    """Neutralise spreadsheet formula injection: indicators are attacker-controlled."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def to_csv(items: Sequence[EnrichedIOC]) -> str:
    providers: list[str] = []
    for item in items:
        for r in item.results:
            if r.provider not in providers:
                providers.append(r.provider)

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["indicator", "type", "verdict", "score", "allowlisted", "reasons", *providers])
    for item in items:
        by_name = {r.provider: r for r in item.results}
        cells = []
        for name in providers:
            r = by_name.get(name)
            cells.append("" if r is None else (r.summary if r.ok else f"error: {r.error}"))
        row = [
            item.ioc.value,
            item.ioc.type.value,
            item.verdict.value,
            item.score,
            item.allowlisted,
            " | ".join(item.reasons),
            *cells,
        ]
        writer.writerow([_csv_safe(v) for v in row])
    return buf.getvalue()


# --------------------------------------------------------------------------- STIX 2.1
def _stix_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(item: EnrichedIOC) -> str:
    v = _stix_escape(item.ioc.value)
    t = item.ioc.type
    if t is IOCType.IPV4:
        return f"[ipv4-addr:value = '{v}']"
    if t is IOCType.IPV6:
        return f"[ipv6-addr:value = '{v}']"
    if t is IOCType.DOMAIN:
        return f"[domain-name:value = '{v}']"
    if t is IOCType.URL:
        return f"[url:value = '{v}']"
    hash_key = {IOCType.MD5: "MD5", IOCType.SHA1: "'SHA-1'", IOCType.SHA256: "'SHA-256'"}[t]
    return f"[file:hashes.{hash_key} = '{v}']"


def to_stix(
    items: Sequence[EnrichedIOC],
    include: tuple[Verdict, ...] = (Verdict.MALICIOUS, Verdict.SUSPICIOUS),
) -> str:
    """STIX 2.1 bundle of Indicator objects for actionable verdicts only."""
    ts = _stix_time(_now())
    identity_id = f"identity--{uuid.uuid5(STIX_NAMESPACE, 'iocscope')}"
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": ts,
            "modified": ts,
            "name": "iocscope",
            "identity_class": "system",
        }
    ]
    for item in items:
        if item.verdict not in include:
            continue
        key = f"{item.ioc.type.value}:{item.ioc.value}"
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(STIX_NAMESPACE, key)}",
                "created_by_ref": identity_id,
                "created": ts,
                "modified": ts,
                "name": f"{item.verdict.value.title()} {item.ioc.type.value}: {item.ioc.value}",
                "description": "; ".join(item.reasons),
                "indicator_types": [
                    "malicious-activity"
                    if item.verdict is Verdict.MALICIOUS
                    else "anomalous-activity"
                ],
                "pattern": stix_pattern(item),
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": ts,
                "confidence": item.score,
                "labels": [item.verdict.value],
            }
        )
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    return json.dumps(bundle, indent=2) + "\n"


# --------------------------------------------------------------------------- HTML
_HTML = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iocscope report · $generated</title>
<style>
  :root {
    --ivory: $ivory; --mineral: $mineral; --isabella: $isabella;
    --greenblue: $greenblue; --benzol: $benzol; --lavender: $lavender;
    --ink: $ink; --paper: $paper;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--paper); color: var(--ink);
         font: 15px/1.5 "Segoe UI", system-ui, -apple-system, Helvetica, Arial, sans-serif; }
  header { background: var(--greenblue); color: var(--ivory); padding: 36px 48px 28px; }
  header h1 { margin: 0; font-size: 30px; letter-spacing: .5px; }
  header h1 span { color: var(--lavender); font-weight: 400; }
  header p { margin: 6px 0 0; color: #e6f2f1; }
  .stripe { display: flex; height: 8px; }
  .stripe i { flex: 1; }
  main { max-width: 1240px; margin: 0 auto; padding: 32px 48px 56px; }
  .tiles { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px;
           margin-bottom: 30px; }
  .tile { background: #fff; border: 1px solid #e3dccb; border-top: 6px solid var(--c);
          border-radius: 10px; padding: 14px 18px; }
  .tile b { display: block; font-size: 30px; line-height: 1.1; }
  .tile span { text-transform: uppercase; font-size: 12px; letter-spacing: 1px; color: #5b6766; }
  table { width: 100%; border-collapse: separate; border-spacing: 0; background: #fff;
          border: 1px solid #e3dccb; border-radius: 10px; overflow: hidden; }
  th { background: var(--ivory); text-align: left; font-size: 12px; text-transform: uppercase;
       letter-spacing: 1px; padding: 11px 14px; }
  td { padding: 12px 14px; border-top: 1px solid #efe8d8; vertical-align: top; }
  tr:hover td { background: #fdfaf3; }
  code { font: 13px/1.4 ui-monospace, "Cascadia Code", Consolas, monospace; word-break: break-all; }
  .orig { color: #6e7b79; font-size: 12px; margin-top: 2px; }
  .pill { display: inline-block; white-space: nowrap; padding: 3px 10px; border-radius: 999px;
          font-size: 12px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase;
          background: var(--c); color: var(--ink); }
  .score { display: flex; align-items: center; gap: 8px; min-width: 110px; }
  .bar { flex: 1; height: 8px; background: #eee7d7; border-radius: 99px; overflow: hidden; }
  .bar i { display: block; height: 100%; background: var(--c); }
  ul.src { list-style: none; margin: 0; padding: 0; font-size: 13px; }
  ul.src li { margin: 1px 0; }
  ul.src b { color: var(--greenblue); font-weight: 600; }
  ul.src .err { color: #8a7a55; font-style: italic; }
  .type { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #5b6766; }
  footer { color: #6e7b79; font-size: 12px; margin-top: 26px; display: flex;
           justify-content: space-between; gap: 16px; flex-wrap: wrap; }
  .swatches i { display: inline-block; width: 12px; height: 12px; border-radius: 3px;
                vertical-align: -2px; margin-left: 3px; }
  @media (max-width: 800px) { .tiles { grid-template-columns: repeat(2, 1fr); }
                              header, main { padding-left: 18px; padding-right: 18px; } }
</style>
</head>
<body>
<header>
  <h1>iocscope <span>enrichment report</span></h1>
  <p>$count indicators · generated $generated</p>
</header>
<div class="stripe"><i style="background:var(--ivory)"></i><i style="background:var(--mineral)"></i><i style="background:var(--isabella)"></i><i style="background:var(--greenblue)"></i><i style="background:var(--benzol)"></i><i style="background:var(--lavender)"></i></div>
<main>
  <section class="tiles">$tiles</section>
  <table>
    <thead><tr><th>Verdict</th><th>Score</th><th>Indicator</th><th>Type</th><th>Evidence</th></tr></thead>
    <tbody>
$rows
    </tbody>
  </table>
  <footer>
    <span>iocscope v$version · verdicts are decision support, not ground truth. Verify before blocking.</span>
    <span class="swatches">Palette: Sanzo Wada #11 · #12 · #15
      <i style="background:var(--ivory)"></i><i style="background:var(--mineral)"></i><i style="background:var(--isabella)"></i><i style="background:var(--greenblue)"></i><i style="background:var(--benzol)"></i><i style="background:var(--lavender)"></i></span>
  </footer>
</main>
</body>
</html>
""")

_VERDICT_VARS = {
    Verdict.MALICIOUS: "var(--isabella)",
    Verdict.SUSPICIOUS: "var(--ivory)",
    Verdict.LOW: "var(--lavender)",
    Verdict.BENIGN: "var(--benzol)",
    Verdict.UNKNOWN: "var(--mineral)",
}


def _html_row(item: EnrichedIOC) -> str:
    e = html.escape
    colour = _VERDICT_VARS[item.verdict]
    glyph = VERDICT_GLYPHS[item.verdict.value]
    original = ""
    if item.ioc.original != item.ioc.value:
        original = f'<div class="orig">submitted as <code>{e(item.ioc.original)}</code></div>'

    evidence = []
    if item.allowlisted:
        evidence.append(f"<li><b>Allowlist</b> {e(item.reasons[0])}</li>")
    for r in item.results:
        label = e(LABELS.get(r.provider, r.provider))
        if r.ok:
            cached = " <span class='orig'>(cached)</span>" if r.cached else ""
            evidence.append(f"<li><b>{label}</b> {e(r.summary)}{cached}</li>")
        else:
            evidence.append(f"<li><b>{label}</b> <span class='err'>{e(r.error or 'error')}</span></li>")
    conflicts = [x for x in item.reasons if x.startswith("conflict:")]
    evidence += [f"<li class='err'>{e(c)}</li>" for c in conflicts]

    return (
        f'      <tr style="--c:{colour}">'
        f'<td><span class="pill">{glyph} {e(item.verdict.value)}</span></td>'
        f'<td><div class="score"><div class="bar"><i style="width:{item.score}%"></i></div>'
        f"<b>{item.score}</b></div></td>"
        f"<td><code>{e(item.ioc.value)}</code>{original}</td>"
        f'<td class="type">{e(item.ioc.type.value)}</td>'
        f'<td><ul class="src">{"".join(evidence) or "<li>no data</li>"}</ul></td></tr>'
    )


def to_html(items: Sequence[EnrichedIOC]) -> str:
    counts = Counter(i.verdict for i in items)
    tiles = "".join(
        f'<div class="tile" style="--c:{_VERDICT_VARS[v]}"><b>{counts.get(v, 0)}</b>'
        f"<span>{VERDICT_GLYPHS[v.value]} {v.value}</span></div>"
        for v in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.LOW, Verdict.UNKNOWN, Verdict.BENIGN)
    )
    return _HTML.substitute(
        ivory=IVORY_BUFF,
        mineral=MINERAL_GRAY,
        isabella=ISABELLA,
        greenblue=GREEN_BLUE,
        benzol=BENZOL_GREEN,
        lavender=GRAYISH_LAVENDER,
        ink=INK,
        paper=PAPER,
        generated=_now().strftime("%Y-%m-%d %H:%M UTC"),
        count=len(items),
        tiles=tiles,
        rows="\n".join(_html_row(i) for i in items),
        version=__version__,
    )


def render(fmt: str, items: Sequence[EnrichedIOC]) -> str:
    if fmt == "json":
        return to_json(items)
    if fmt == "csv":
        return to_csv(items)
    if fmt == "stix":
        return to_stix(items)
    if fmt == "html":
        return to_html(items)
    raise ValueError(f"cannot render format '{fmt}' to text")
