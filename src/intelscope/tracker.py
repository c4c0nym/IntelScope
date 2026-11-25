"""A small, local IOC tracker: what you decided to keep an eye on, and why.

Every row is one indicator seen from one source:

    IOC · type · TLP · context · source · date

The same indicator from two different sources is two rows, because each source has its own
handling label, context and date. Re-adding the same indicator from the same source updates that
row instead of duplicating it. Rows live in one JSON file (see ``settings.tracker_path``) and can
be exported as a Markdown table for notes, tickets or a handover.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import threading
import time
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from intelscope import __version__, settings
from intelscope.detect import classify

TLP_LEVELS = ("CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED")
"""TLP 2.0, least to most restricted."""
TLP_RANK = {level: i for i, level in enumerate(TLP_LEVELS)}

MAX_CONTEXT = 2000
MAX_SOURCE = 200
MAX_ENTRIES = 50_000

_TLP_ALIASES = {"WHITE": "CLEAR", "AMBER-STRICT": "AMBER+STRICT", "AMBER STRICT": "AMBER+STRICT",
                "AMBERSTRICT": "AMBER+STRICT", "AMBER_STRICT": "AMBER+STRICT"}


def normalize_tlp(value: str | None) -> str:
    """'tlp:amber', 'Amber', 'white' ... -> one of TLP_LEVELS. Empty means the safe default, AMBER."""
    raw = (value or "").strip().upper()
    raw = re.sub(r"^TLP\s*[:\-]?\s*", "", raw)
    if not raw:
        return "AMBER"
    raw = _TLP_ALIASES.get(raw, raw)
    if raw not in TLP_RANK:
        raise ValueError(f"unknown TLP '{value}' (use {', '.join(TLP_LEVELS)})")
    return raw


def normalize_date(value: str | None) -> str:
    """YYYY-MM-DD; empty means today."""
    raw = (value or "").strip()
    if not raw:
        return date.today().isoformat()
    try:
        return date.fromisoformat(raw[:10]).isoformat()
    except ValueError:
        raise ValueError(f"date must look like 2026-11-25, got '{value}'") from None


def _text(value: str | None, limit: int, label: str) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", (value or "").strip())
    if len(text) > limit:
        raise ValueError(f"{label} is longer than {limit} characters")
    return text


def defang(value: str) -> str:
    """hxxps://evil[.]example/x . Hashes are left alone."""
    if re.fullmatch(r"[0-9a-fA-F]{32,64}", value):
        return value
    out = re.sub(r"^http", "hxxp", value, flags=re.I)
    return out.replace(".", "[.]")


@dataclass
class Entry:
    id: int
    ioc: str
    type: str
    tlp: str
    context: str
    source: str
    date: str
    added: str
    updated: str
    verdict: str = ""
    score: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextlib.contextmanager
def _file_lock(path: Path, timeout: float = 10.0):
    """An exclusive lock shared by every process (and every Tracker object) using this file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path.with_name(path.name + ".lock"), "a+b")  # noqa: SIM115  (closed in the finally below)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise ValueError(f"the tracker file {path} is locked by another program") from None
                time.sleep(0.01)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                fh.seek(0)
                with contextlib.suppress(OSError):
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            fh.close()


class Tracker:
    """JSON-file backed. `path=None` keeps everything in memory (demo mode, tests)."""

    def __init__(self, path: Path | str | None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._mem: dict[str, Any] = {"version": 1, "next_id": 1, "entries": []}

    def _guard(self):
        """Serialise a read-modify-write: threads of this process, then other processes."""
        stack = contextlib.ExitStack()
        stack.enter_context(self._lock)
        if self.path is not None:
            stack.enter_context(_file_lock(self.path))
        return stack

    # -- storage
    def _load(self) -> dict[str, Any]:
        if self.path is None:
            return self._mem
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"version": 1, "next_id": 1, "entries": []}
        except (OSError, ValueError) as exc:
            raise ValueError(f"cannot read tracker file {self.path}: {exc}") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
            raise ValueError(f"{self.path} is not an IntelScope tracker file")
        doc.setdefault("next_id", 1 + max((e.get("id", 0) for e in doc["entries"]), default=0))
        return doc

    def _save(self, doc: dict[str, Any]) -> None:
        if self.path is None:
            self._mem = doc
            return
        settings.write_private(self.path, json.dumps(doc, indent=2, ensure_ascii=False) + "\n")

    @staticmethod
    def _entry(raw: dict[str, Any]) -> Entry:
        known = {k: raw[k] for k in Entry.__dataclass_fields__ if k in raw}
        return Entry(**known)

    # -- reading
    def entries(self) -> list[Entry]:
        with self._lock:
            return [self._entry(e) for e in self._load()["entries"]]

    def search(self, *, tlp: str | None = None, source: str | None = None, text: str | None = None,
               max_tlp: str | None = None) -> list[Entry]:
        rows = self.entries()
        if tlp:
            want = normalize_tlp(tlp)
            rows = [e for e in rows if e.tlp == want]
        if max_tlp:
            ceiling = TLP_RANK[normalize_tlp(max_tlp)]
            rows = [e for e in rows if TLP_RANK[e.tlp] <= ceiling]
        if source:
            rows = [e for e in rows if source.lower() in e.source.lower()]
        if text:
            needle = text.lower()
            rows = [e for e in rows if needle in e.ioc.lower() or needle in e.context.lower()
                    or needle in e.source.lower()]
        return rows

    # -- writing
    def add(self, value: str, *, tlp: str = "", context: str = "", source: str = "",
            when: str = "", verdict: str = "", score: int | None = None) -> tuple[Entry, bool]:
        """Add one indicator. Returns (entry, created). Same indicator + same source updates the row."""
        ioc = classify(value)
        if ioc is None:
            raise ValueError(f"not a recognised indicator: {value[:80]}")
        level = normalize_tlp(tlp)
        context = _text(context, MAX_CONTEXT, "context")
        source = _text(source, MAX_SOURCE, "source")
        when_iso = normalize_date(when)
        with self._guard():
            doc = self._load()
            for raw in doc["entries"]:
                if raw["type"] == ioc.type.value and raw["ioc"] == ioc.value \
                        and raw.get("source", "").lower() == source.lower():
                    raw["tlp"] = level
                    if context:
                        raw["context"] = context
                    if when:
                        raw["date"] = when_iso
                    if verdict:
                        raw["verdict"], raw["score"] = verdict, score
                    raw["updated"] = _now()
                    self._save(doc)
                    return self._entry(raw), False
            if len(doc["entries"]) >= MAX_ENTRIES:
                raise ValueError(f"the tracker is full ({MAX_ENTRIES} rows)")
            now = _now()
            raw = Entry(id=doc["next_id"], ioc=ioc.value, type=ioc.type.value, tlp=level, context=context,
                        source=source, date=when_iso, added=now, updated=now, verdict=verdict,
                        score=score).to_dict()
            doc["next_id"] += 1
            doc["entries"].append(raw)
            self._save(doc)
            return self._entry(raw), True

    def update(self, entry_id: int, **fields: str) -> Entry:
        """Change tlp, context, source or date of one row."""
        unknown = set(fields) - {"tlp", "context", "source", "date"}
        if unknown:
            raise ValueError("cannot edit " + ", ".join(sorted(unknown)))
        with self._guard():
            doc = self._load()
            for raw in doc["entries"]:
                if raw["id"] == entry_id:
                    if "tlp" in fields:
                        raw["tlp"] = normalize_tlp(fields["tlp"])
                    if "context" in fields:
                        raw["context"] = _text(fields["context"], MAX_CONTEXT, "context")
                    if "source" in fields:
                        new_source = _text(fields["source"], MAX_SOURCE, "source")
                        clash = any(o is not raw and o["type"] == raw["type"] and o["ioc"] == raw["ioc"]
                                    and o.get("source", "").lower() == new_source.lower()
                                    for o in doc["entries"])
                        if clash:
                            raise ValueError("that indicator already has a row for that source")
                        raw["source"] = new_source
                    if "date" in fields:
                        raw["date"] = normalize_date(fields["date"])
                    raw["updated"] = _now()
                    self._save(doc)
                    return self._entry(raw)
        raise KeyError(entry_id)

    def remove(self, ids: list[int]) -> int:
        wanted = set(ids)
        with self._guard():
            doc = self._load()
            kept = [e for e in doc["entries"] if e["id"] not in wanted]
            removed = len(doc["entries"]) - len(kept)
            if removed:
                doc["entries"] = kept
                self._save(doc)
            return removed

    def import_markdown(self, text: str) -> dict[str, Any]:
        """Add the rows of a Markdown table (this tool's own export, or any table with an IOC column).

        Existing rows (same indicator, same source) are updated. A row that cannot be used is reported
        and skipped, never fatal. Raises ValueError when the text holds no table with an IOC column.
        """
        rows = parse_markdown(text)
        if not rows:
            raise ValueError("no table with an IOC column found (expected columns like "
                             "IOC | Type | TLP | Source | Date | Context)")
        added = updated = 0
        errors: list[str] = []
        for number, row in enumerate(rows, start=1):
            try:
                _, created = self.add(row["ioc"], tlp=row.get("tlp", ""), context=row.get("context", ""),
                                      source=row.get("source", ""), when=row.get("date", ""))
            except ValueError as exc:
                errors.append(f"row {number}: {exc}")
                continue
            added += created
            updated += not created
        return {"added": added, "updated": updated, "errors": errors}


# --------------------------------------------------------------------------- Markdown

_HEADER_ALIASES = {"ioc": "ioc", "indicator": "ioc", "value": "ioc", "tlp": "tlp", "source": "source",
                   "date": "date", "context": "context", "notes": "context", "note": "context",
                   "description": "context"}
_PIPE = re.compile(r"(?<!\\)\|")
_SEPARATOR_CELL = re.compile(r"^:?-{1,}:?$")


def _split_row(line: str) -> list[str]:
    body = line.strip()
    body = body[1:] if body.startswith("|") else body
    body = body[:-1] if body.endswith("|") and not body.endswith("\\|") else body
    return [c.strip() for c in _PIPE.split(body)]


def _unescape(cell: str) -> str:
    text = re.sub(r"\\([\\|])", r"\1", cell)
    text = text.replace("&lt;", "<").replace("&gt;", ">")
    return "" if text.strip() == "-" else text.strip()


def parse_markdown(text: str) -> list[dict[str, str]]:
    """Rows of every table that has an IOC column. Column order does not matter; extra columns are ignored."""
    rows: list[dict[str, str]] = []
    columns: list[str | None] | None = None
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            columns = None  # a table ends at the first line that is not part of it
            continue
        cells = _split_row(line)
        if columns is None:
            names = [_HEADER_ALIASES.get(c.strip("` :*").lower()) for c in cells]
            columns = names if "ioc" in names else []
            continue
        if not columns or all(_SEPARATOR_CELL.match(c) for c in cells if c):
            continue
        row = {name: _unescape(cell) for name, cell in zip(columns, cells, strict=False) if name}
        row["ioc"] = row.get("ioc", "").strip("`").strip()
        if row["ioc"]:
            rows.append(row)
    return rows

_URL_IN_TEXT = re.compile(r"https?://[^\s|<>]+", re.I)


def _cell(value: str, defanged: bool = False) -> str:
    """One table cell: no pipes, no line breaks, no raw HTML. Defanged mode also defangs links in the text."""
    text = re.sub(r"\s+", " ", value).strip()
    if defanged:
        text = _URL_IN_TEXT.sub(lambda m: defang(m.group(0)), text)
    text = text.replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")
    return text or "-"


def _code(value: str) -> str:
    return "`" + value.replace("`", "%60") + "`"


def to_markdown(entries: list[Entry], *, defanged: bool = True, title: str = "IOC tracker",
                max_tlp: str | None = None) -> str:
    """A Markdown table, newest first. Defanged by default so a viewer never makes a link live."""
    rows = sorted(entries, key=lambda e: (e.date, e.id), reverse=True)
    today = date.today().isoformat()
    lines = [f"# {title}", ""]
    if rows:
        top = max(rows, key=lambda e: TLP_RANK[e.tlp]).tlp
        counts = {lvl: sum(1 for e in rows if e.tlp == lvl) for lvl in TLP_LEVELS}
        mix = ", ".join(f"{n} {lvl}" for lvl, n in counts.items() if n)
        lines.append(f"> **TLP:{top}**: handle this whole file at the highest label it contains.")
        lines.append(f"> {len(rows)} row{'s' if len(rows) != 1 else ''} ({mix}). "
                     f"Exported {today} by IntelScope {__version__}."
                     + (f" Only rows up to TLP:{normalize_tlp(max_tlp)}." if max_tlp else ""))
        lines.append(">")
        lines.append("> Indicators are defanged." if defanged else "> Indicators are live: do not click.")
        lines += ["", "| IOC | Type | TLP | Source | Date | Context |", "|---|---|---|---|---|---|"]
        for e in rows:
            value = defang(e.ioc) if defanged else e.ioc
            source, context = _cell(e.source, defanged), _cell(e.context, defanged)
            cells = [_code(value), e.type, e.tlp, source, e.date, context]
            lines.append("| " + " | ".join(cells) + " |")
    else:
        lines += [f"> Exported {today} by IntelScope {__version__}.", "", "No indicators tracked yet."]
    return "\n".join(lines) + "\n"
