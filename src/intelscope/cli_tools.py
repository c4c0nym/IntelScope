"""`intelscope keys ...` (API credentials) and `intelscope track ...` (the IOC tracker)."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.table import Table

from intelscope import settings
from intelscope.detect import parse_iocs
from intelscope.palette import THEME
from intelscope.providers import REGISTRY, resolve_names
from intelscope.tracker import TLP_LEVELS, Tracker, to_markdown

# --------------------------------------------------------------------------- keys


def _origin(provider: str, field_name: str, env: str, stored: dict[str, dict[str, str]]) -> str:
    if stored.get(provider, {}).get(field_name):
        return "saved file"
    if env and os.environ.get(env):
        return f"environment ({env})"
    return ""


def keys_list(out: Console) -> int:
    stored = settings.load_stored()
    table = Table(title="API credentials", title_style="accent", header_style="accent")
    for col in ("source", "field", "set", "from"):
        table.add_column(col)
    for name, cls in REGISTRY.items():
        for f in cls.credential_fields():
            origin = _origin(name, f.name, f.env, stored)
            missing = "[muted]no[/]" if f.required else "[muted]optional[/]"
            state = "[score.benign]yes[/]" if origin else missing
            table.add_row(cls.label, f.label, state, origin or "-")
    out.print(table)
    out.print(f"[muted]saved file: {settings.credentials_path()}[/]")
    return 0


def keys_set(name: str, err: Console) -> int:
    try:
        (provider,) = resolve_names(name)
    except ValueError as exc:
        err.print(f"[error]error:[/] {exc}")
        return 2
    cls = REGISTRY[provider]
    fields = cls.credential_fields()
    if not fields:
        err.print(f"[error]error:[/] {cls.label} takes no credentials")
        return 2
    if not sys.stdin.isatty():
        err.print("[error]error:[/] run this in a terminal: secrets are asked for, not read from arguments, "
                  "so they stay out of your shell history")
        return 2
    err.print(f"[accent]{cls.label}[/] [muted]{cls.note}[/]")
    values: dict[str, str] = {}
    for f in fields:
        label = f"{f.label}{'' if f.required else ' (optional)'}"
        prompt = f"  {label}: "
        try:
            raw = getpass.getpass(prompt) if f.secret else input(prompt)
        except (EOFError, KeyboardInterrupt):
            err.print("\n[warn]cancelled, nothing saved[/]")
            return 130
        if not raw.strip():
            continue
        try:
            values[f.name] = settings.clean_value(raw, f.kind)
        except ValueError as exc:
            err.print(f"[error]error:[/] {f.label} {exc}")
            return 2
    if not values:
        err.print("[muted]nothing entered, nothing saved[/]")
        return 0
    settings.set_stored(provider, values)
    err.print(f"[accent]saved[/] {cls.label} to {settings.credentials_path()} "
              "[muted](plain text, readable by anyone who can read your files)[/]")
    return 0


def keys_remove(name: str, err: Console) -> int:
    try:
        (provider,) = resolve_names(name)
    except ValueError as exc:
        err.print(f"[error]error:[/] {exc}")
        return 2
    if settings.remove_stored(provider):
        err.print(f"[accent]removed[/] the saved credentials for {REGISTRY[provider].label}")
    else:
        err.print(f"[muted]nothing saved for {REGISTRY[provider].label}[/]")
    return 0


def keys_main(argv: Sequence[str]) -> int:
    p = argparse.ArgumentParser(
        prog="intelscope keys",
        description="Manage API credentials. Saved keys are used by the CLI and the dashboard; "
        "environment variables and .env still work.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="show which sources have credentials, and where they come from")
    s = sub.add_parser("set", help="enter credentials for one source (asked for, not passed as arguments)")
    s.add_argument("provider")
    r = sub.add_parser("remove", help="delete the saved credentials of one source")
    r.add_argument("provider")
    args = p.parse_args(argv)
    out, err = Console(theme=THEME), Console(theme=THEME, stderr=True)
    if args.cmd == "list":
        return keys_list(out)
    if args.cmd == "set":
        return keys_set(args.provider, err)
    return keys_remove(args.provider, err)


# --------------------------------------------------------------------------- track

def add_meta_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--tlp", default="", metavar="LEVEL",
                   help=f"handling label: {', '.join(TLP_LEVELS)} (default: AMBER)")
    p.add_argument("--context", default="", help="why it matters: campaign, report, ticket, what you saw")
    p.add_argument("--source", default="", help="where it came from: a report, feed, person or case")
    p.add_argument("--date", default="", metavar="YYYY-MM-DD", help="date observed (default: today)")


def _tracker(args: argparse.Namespace) -> Tracker:
    return Tracker(args.db or settings.tracker_path())


def _rows_table(rows: list) -> Table:
    table = Table(title="IOC tracker", title_style="accent", header_style="accent")
    for col in ("id", "ioc", "type", "tlp", "source", "date", "context"):
        table.add_column(col, overflow="fold")
    for e in rows:
        table.add_row(str(e.id), e.ioc, e.type, e.tlp, e.source or "-", e.date, e.context or "-")
    return table


def track_main(argv: Sequence[str]) -> int:
    p = argparse.ArgumentParser(
        prog="intelscope track",
        description="Keep track of indicators: IOC, TLP, context, source and date. Export as Markdown.",
    )
    p.add_argument("--db", metavar="PATH", help=f"tracker file (default: {settings.tracker_path()})")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="add indicators (defanged is fine; '-' reads stdin)")
    a.add_argument("iocs", nargs="*")
    a.add_argument("-f", "--file", action="append", default=[], metavar="PATH", help="file with indicators")
    add_meta_args(a)

    ls = sub.add_parser("list", help="show tracked indicators")
    ls.add_argument("--tlp", default="")
    ls.add_argument("--source", default="", help="substring of the source")
    ls.add_argument("--search", default="", help="substring of the indicator, context or source")

    e = sub.add_parser("edit", help="change the TLP, context, source or date of one row")
    e.add_argument("id", type=int)
    e.add_argument("--tlp")
    e.add_argument("--context")
    e.add_argument("--source")
    e.add_argument("--date")

    rm = sub.add_parser("remove", help="delete rows by id")
    rm.add_argument("ids", nargs="+", type=int)

    ex = sub.add_parser("export", help="write the tracker as a Markdown table")
    ex.add_argument("-o", "--output", metavar="PATH", help="file to write (default: standard output)")
    ex.add_argument("--max-tlp", default="", metavar="LEVEL",
                    help="only rows up to this label, for sharing (e.g. GREEN leaves out AMBER and RED)")
    ex.add_argument("--raw", action="store_true", help="do not defang indicators")
    ex.add_argument("--title", default="IOC tracker")

    args = p.parse_args(argv)
    out, err = Console(theme=THEME), Console(theme=THEME, stderr=True)
    try:
        tr = _tracker(args)
        if args.cmd == "add":
            lines = list(args.iocs)
            if "-" in lines:
                lines.remove("-")
                lines += sys.stdin.read().splitlines()
            for path in args.file:
                lines += Path(path).read_text(encoding="utf-8-sig").splitlines()
            iocs, rejected = parse_iocs(lines)
            if rejected:
                sample = ", ".join(rejected[:5])
                err.print(f"[warn]skipped {len(rejected)} unrecognised token(s):[/] [muted]{sample}[/]")
            if not iocs:
                err.print("[error]error:[/] no valid indicators given")
                return 2
            created = updated = 0
            for ioc in iocs:
                _, new = tr.add(ioc.value, tlp=args.tlp, context=args.context,
                                source=args.source, when=args.date)
                created += new
                updated += not new
            err.print(f"[accent]tracked[/] {created} new, {updated} updated [muted]({tr.path})[/]")
            return 0
        if args.cmd == "list":
            rows = tr.search(tlp=args.tlp or None, source=args.source or None, text=args.search or None)
            out.print(_rows_table(sorted(rows, key=lambda r: (r.date, r.id), reverse=True)))
            return 0
        if args.cmd == "edit":
            fields = {k: v for k, v in (("tlp", args.tlp), ("context", args.context),
                                        ("source", args.source), ("date", args.date)) if v is not None}
            if not fields:
                err.print("[error]error:[/] give at least one of --tlp, --context, --source, --date")
                return 2
            tr.update(args.id, **fields)
            err.print(f"[accent]updated[/] row {args.id}")
            return 0
        if args.cmd == "remove":
            n = tr.remove(args.ids)
            err.print(f"[accent]removed[/] {n} row{'s' if n != 1 else ''}")
            return 0 if n else 1
        rows = tr.search(max_tlp=args.max_tlp or None)
        text = to_markdown(rows, defanged=not args.raw, title=args.title, max_tlp=args.max_tlp or None)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8", newline="\n")
            err.print(f"[accent]wrote[/] {args.output} [muted]({len(rows)} rows)[/]")
        else:
            sys.stdout.write(text)
        return 0
    except KeyError:
        err.print("[error]error:[/] no row with that id")
        return 1
    except (ValueError, OSError) as exc:
        err.print(f"[error]error:[/] {exc}")
        return 2
