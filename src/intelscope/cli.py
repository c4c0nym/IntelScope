"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from dotenv import find_dotenv, load_dotenv
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from intelscope import __version__, settings
from intelscope.allowlist import load_allowlist
from intelscope.cache import Cache, default_cache_path
from intelscope.cli_tools import add_meta_args, keys_main, track_main
from intelscope.demo import DEMO_IOCS, build_demo_providers
from intelscope.detect import parse_iocs
from intelscope.enrich import Enricher, triage_order
from intelscope.export import FORMATS, infer_format, render
from intelscope.models import Verdict
from intelscope.palette import THEME
from intelscope.providers import REGISTRY, build_providers, resolve_names
from intelscope.render import render_table
from intelscope.tracker import Tracker, normalize_date, normalize_tlp

EPILOG = """\
examples:
  intelscope 8.8.8.8 "hxxps://evil[.]example/login" 44d88612fea8a8f36de82e1278abb02f
  intelscope -f iocs.txt -o report.html
  cat iocs.txt | intelscope - --format stix > indicators.stix.json
  intelscope -f iocs.txt --providers vt,abuseipdb --fail-on malicious
  intelscope --demo                      # offline sample run, no API keys needed
  intelscope serve --open                # the dashboard, with live enrichment
  intelscope -f iocs.txt --track --tlp AMBER --source "CERT report 12" --context "phishing wave"
  intelscope track add 198.51.100[.]23 --tlp GREEN --source "feed X" --context "C2 seen in logs"
  intelscope track export -o iocs.md     # Markdown table: IOC, type, TLP, source, date, context
  intelscope keys set censys             # enter an API key (asked for, never put in a command)
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="intelscope",
        description="Enrich, score and triage indicators of compromise "
        "(IPs, domains, URLs, file hashes) across threat intel sources.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("iocs", nargs="*", help="indicators to check (defanged is fine); '-' reads stdin")
    p.add_argument("-f", "--file", action="append", default=[], metavar="PATH",
                   help="file with indicators, one or more per line (repeatable)")
    p.add_argument("-o", "--output", metavar="PATH",
                   help="write results to a file; format inferred from extension "
                   "(.json, .csv, .html, .md, .stix.json)")
    p.add_argument("--format", choices=FORMATS, help="output format (default: table)")
    p.add_argument("-p", "--providers", metavar="LIST",
                   help=f"comma-separated providers (default: all configured): {', '.join(REGISTRY)}")
    p.add_argument("--list-providers", action="store_true", help="show providers and key status")
    p.add_argument("--allowlist", metavar="PATH", help="extra allowlist file (IPs, CIDRs, domains)")
    p.add_argument("--asn-blocklist", metavar="PATH",
                   help="your own ASN blocklist, one ASN per line (checked with Spamhaus ASN-DROP)")
    p.add_argument("--no-allowlist", action="store_true", help="disable known-benign filtering")
    p.add_argument("--no-cache", action="store_true", help="ignore and don't update the result cache")
    p.add_argument("--cache-ttl", type=float, default=24.0, metavar="HOURS",
                   help="reuse cached lookups younger than this (default: 24)")
    p.add_argument("--min-verdict", choices=[v.value for v in Verdict],
                   help="only output results at or above this verdict")
    p.add_argument("--fail-on", choices=["malicious", "suspicious"],
                   help="exit with status 1 if any indicator reaches this verdict")
    p.add_argument("-w", "--workers", type=int, default=8, help="concurrent lookups (default: 8)")
    p.add_argument("--demo", action="store_true",
                   help="run offline against canned sample data (no keys, no network)")
    p.add_argument("--track", action="store_true",
                   help="also add every checked indicator to the IOC tracker (see 'intelscope track')")
    add_meta_args(p)
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress and warnings")
    p.add_argument("--version", action="version", version=f"intelscope {__version__}")
    return p


def _read_input(args: argparse.Namespace) -> list[str]:
    lines: list[str] = []
    for item in args.iocs:
        if item == "-":
            lines.extend(sys.stdin.read().splitlines())
        else:
            lines.append(item)
    for path in args.file:
        lines.extend(Path(path).read_text(encoding="utf-8-sig").splitlines())
    if not lines and not args.iocs and not args.file and not sys.stdin.isatty() and not args.demo:
        lines.extend(sys.stdin.read().splitlines())
    if not lines and args.demo:
        lines = list(DEMO_IOCS)
    return lines


def _list_providers(console: Console) -> None:
    table = Table(title="providers", title_style="accent", header_style="accent")
    for col in ("name", "source", "indicator types", "API key", "status"):
        table.add_column(col)
    for name, cls in REGISTRY.items():
        provider = cls.from_env()
        fields = cls.credential_fields()
        if not fields and cls.env_key is None:
            key, status = "not needed", "[score.benign]ready[/]"
        elif not fields:
            key = f"not needed (own list: {cls.env_key})"
            status = "[score.benign]ready[/]"
        else:
            key = ", ".join(f.env for f in fields if f.required) or ", ".join(f.env for f in fields)
            if not provider.configured:
                status = "[muted]missing key[/]"
            elif provider.api_key or provider.extra:
                status = "[score.benign]ready[/]"
            else:
                status = "[info]ready (no key)[/]"
        types = ", ".join(sorted(t.value for t in cls.supports))
        table.add_row(name, cls.label, types, key, status)
    console.print(table)


def _serve_main(argv: Sequence[str]) -> int:
    from intelscope.server import serve

    p = argparse.ArgumentParser(
        prog="intelscope serve",
        description="Open the intelscope dashboard on 127.0.0.1 with live enrichment.",
    )
    p.add_argument("--port", type=int, default=8765, help="port to listen on (default: 8765)")
    p.add_argument("--demo", action="store_true", help="canned offline data, no keys or network")
    p.add_argument("--no-cache", action="store_true", help="ignore and don't update the result cache")
    p.add_argument("-w", "--workers", type=int, default=8, help="concurrent lookups (default: 8)")
    p.add_argument("--open", action="store_true", help="open the dashboard in your browser")
    args = p.parse_args(argv)
    err = Console(theme=THEME, stderr=True)
    try:
        httpd = serve(args.port, args.demo, not args.no_cache, args.workers, args.open)
    except OSError as exc:
        err.print(f"[error]error:[/] cannot listen on 127.0.0.1:{args.port} ({exc.strerror or exc})")
        return 2
    mode = "demo data" if args.demo else "live lookups"
    err.print(
        f"[accent]intelscope[/] dashboard on http://127.0.0.1:{args.port}/ "
        f"[muted]({mode}, ctrl+c to stop)[/]"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        err.print("[muted]stopped[/]")
    finally:
        httpd.server_close()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    load_dotenv(find_dotenv(usecwd=True))
    for stream in (sys.stdout, sys.stderr):  # a legacy console must not crash on a glyph
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "serve":
        return _serve_main(raw[1:])
    if raw and raw[0] == "keys":
        return keys_main(raw[1:])
    if raw and raw[0] == "track":
        return track_main(raw[1:])
    args = build_parser().parse_args(raw)
    err = Console(theme=THEME, stderr=True)
    out = Console(theme=THEME)

    if args.list_providers:
        _list_providers(out)
        return 0

    fmt = args.format or infer_format(args.output) or "table"
    if args.output and fmt == "table":
        err.print("[error]error:[/] choose --format json, csv, stix, html or md when using --output")
        return 2

    try:
        lines = _read_input(args)
        names = resolve_names(args.providers)
        if args.track:  # fail before spending any API quota
            normalize_tlp(args.tlp)
            normalize_date(args.date)
        if args.asn_blocklist and not Path(args.asn_blocklist).is_file():
            raise ValueError(f"ASN blocklist not found: {args.asn_blocklist}")
        allowlist = (
            None
            if args.no_allowlist
            else load_allowlist(args.allowlist, skip_reserved=not args.demo)
        )
    except (OSError, ValueError) as exc:
        err.print(f"[error]error:[/] {exc}")
        return 2

    iocs, rejected = parse_iocs(lines)
    if rejected and not args.quiet:
        sample = ", ".join(rejected[:5]) + (" …" if len(rejected) > 5 else "")
        err.print(f"[warn]skipped {len(rejected)} unrecognised token(s):[/] [muted]{sample}[/]")
    if not iocs:
        err.print("[error]error:[/] no valid indicators given (try --help or --demo)")
        return 2

    providers = (
        build_demo_providers(names)
        if args.demo
        else build_providers(",".join(names), asn_blocklist=args.asn_blocklist)
    )
    active = [p for p in providers if p.configured]
    skipped = [p for p in providers if not p.configured]
    if skipped and not args.quiet:
        hints = ", ".join(f"{p.label} (intelscope keys set {p.name})" for p in skipped)
        err.print(f"[muted]not configured, skipping: {hints}[/]")
    if not active:
        err.print("[error]error:[/] no providers available. Add API keys to .env "
                  "(see .env.example) or try --demo")
        return 2

    cache = None
    if not (args.no_cache or args.demo):
        cache = Cache(default_cache_path(), ttl_seconds=args.cache_ttl * 3600)
    enricher = Enricher(active, allowlist=allowlist, cache=cache, max_workers=args.workers)

    try:
        if args.quiet:
            results = enricher.enrich(iocs)
        else:
            progress = Progress(
                TextColumn("[accent]enriching[/]"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=err,
                transient=True,
            )
            with progress:
                task = progress.add_task("lookups", total=None)

                def update(done: int, total: int) -> None:
                    progress.update(task, completed=done, total=total)

                results = enricher.enrich(iocs, on_progress=update)
    except KeyboardInterrupt:
        err.print("[warn]interrupted[/]")
        return 130
    finally:
        if cache:
            cache.save()

    results = triage_order(results)
    if args.track:
        try:
            tracker = Tracker(settings.tracker_path())
            normalize_tlp(args.tlp)
            normalize_date(args.date)
            for item in results:
                tracker.add(item.ioc.value, tlp=args.tlp, context=args.context, source=args.source,
                            when=args.date, verdict=item.verdict.value, score=item.score)
            if not args.quiet:
                err.print(f"[accent]tracked[/] {len(results)} indicator(s) [muted]({tracker.path})[/]")
        except (ValueError, OSError) as exc:
            err.print(f"[error]error:[/] could not track: {exc}")
            return 2
    shown = results
    if args.min_verdict:
        floor = Verdict(args.min_verdict).rank
        shown = [r for r in results if r.verdict.rank >= floor]

    if args.output:
        newline = "" if fmt == "csv" else None
        Path(args.output).write_text(render(fmt, shown), encoding="utf-8", newline=newline)
        if not args.quiet:
            render_table(out, shown)
            err.print(f"[accent]wrote[/] {args.output} [muted]({fmt})[/]")
    elif fmt == "table":
        render_table(out, shown)
    else:
        sys.stdout.write(render(fmt, shown))

    if args.fail_on:
        threshold = Verdict(args.fail_on).rank
        if any(r.verdict.rank >= threshold for r in results):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
