"""Local web server: serves the dashboard and a small API for enrichment, API keys and the IOC tracker.

    intelscope serve            # http://127.0.0.1:8765, live lookups with your keys
    intelscope serve --demo     # same UI, canned offline data, nothing stored

The API keys stay on this machine: the browser only ever talks to 127.0.0.1, and the
server talks to the threat-intel sources. Only standard-library HTTP is used.
Every route except the page and /api/health needs the per-run token.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

from intelscope import __version__, settings
from intelscope.allowlist import load_allowlist
from intelscope.cache import Cache, default_cache_path
from intelscope.demo import DEMO_IOCS, build_demo_providers
from intelscope.detect import parse_iocs
from intelscope.enrich import Enricher, triage_order
from intelscope.models import IOC, IOCType
from intelscope.providers import REGISTRY, build_providers
from intelscope.tracker import (
    TLP_LEVELS,
    Tracker,
    normalize_confidence,
    normalize_date,
    normalize_tlp,
    to_markdown,
)

MAX_BODY = 256 * 1024
MAX_IOCS = 500


class ApiError(Exception):
    def __init__(self, message: str, code: int = 400) -> None:
        super().__init__(message)
        self.code = code


def dashboard_html() -> bytes:
    return resources.files("intelscope").joinpath("web/dashboard.html").read_bytes()


def provider_status(providers: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": p.name,
            "label": p.label,
            "configured": bool(p.configured),
            "types": sorted(t.value for t in p.supports),
        }
        for p in providers
    ]


class _State:
    """Everything a request needs, built once at start-up."""

    def __init__(self, demo: bool, use_cache: bool, workers: int, tracker_path: str | None = None) -> None:
        self.demo = demo
        self.session_keys: dict[str, dict[str, str]] = {}  # typed into the dashboard, never written to disk
        self.enrich_jobs: dict[str, dict[str, Any]] = {}
        self._jobs_lock = threading.Lock()
        self.providers = self._build()
        self.allowlist = load_allowlist(skip_reserved=not demo)
        self.cache = None if (demo or not use_cache) else Cache(default_cache_path(), ttl_seconds=24 * 3600)
        self.workers = workers
        self.tracker = Tracker(None if demo else (tracker_path or settings.tracker_path()))
        # Per-run token: the page reads it from /api/health, so a random site in another
        # tab (which cannot read our responses) cannot trigger lookups with your keys.
        self.token = secrets.token_urlsafe(16)

    def _build(self) -> list[Any]:
        if self.demo:
            return build_demo_providers(list(REGISTRY))
        return build_providers(session_keys=self.session_keys)

    # -- enrichment
    def enrich(self, lines: list[str], on_progress: Any = None) -> dict[str, Any]:
        iocs, rejected = parse_iocs(lines)
        active = [p for p in self.providers if p.configured]
        enricher = Enricher(
            active, allowlist=self.allowlist, cache=self.cache, max_workers=self.workers
        )
        results = triage_order(enricher.enrich(iocs, on_progress)) if iocs else []
        if self.cache:
            self.cache.save()
        return {
            "tool": f"intelscope {__version__}",
            "count": len(results),
            "rejected": rejected,
            "results": [r.to_dict() for r in results],
        }

    def start_enrich(self, lines: list[str]) -> str:
        """Run a check in the background so the page can show progress (free tiers make big lists slow)."""
        iocs, _ = parse_iocs(lines)
        if not iocs:
            raise ApiError("no valid indicators found")
        job: dict[str, Any] = {"state": "running", "done": 0, "total": 0, "result": None, "error": ""}
        job_id = secrets.token_hex(6)
        with self._jobs_lock:
            self.enrich_jobs[job_id] = job
            for old in list(self.enrich_jobs)[:-20]:  # keep the last twenty
                del self.enrich_jobs[old]

        def progress(done: int, total: int) -> None:
            job["done"], job["total"] = done, total

        def run() -> None:
            try:
                job["result"] = self.enrich(lines, progress)
                job["state"] = "done"
            except Exception as exc:  # the page shows the message; the server keeps running
                job["state"], job["error"] = "error", f"{exc.__class__.__name__}: {exc}"

        threading.Thread(target=run, daemon=True).start()
        return job_id

    def enrich_status(self, job_id: str) -> dict[str, Any]:
        job = self.enrich_jobs.get(job_id)
        if job is None:
            raise ApiError("unknown job", 404)
        return {"state": job["state"], "done": job["done"], "total": job["total"], "error": job["error"],
                "result": job["result"] if job["state"] == "done" else None}

    # -- API keys
    def settings_view(self) -> dict[str, Any]:
        stored = settings.load_stored()
        out = []
        live = {p.name: p for p in self.providers}
        for name, cls in REGISTRY.items():
            fields = cls.credential_fields()
            if not fields:
                continue
            rows = []
            for f in fields:
                shared = [cls.shares_key_with] if cls.shares_key_with and f.name == "api_key" else []
                owners = [name, *shared]
                mine = next((v for o in owners if (v := self.session_keys.get(o, {}).get(f.name, ""))), "")
                saved = next((v for o in owners if (v := stored.get(o, {}).get(f.name, ""))), "")
                env = os.environ.get(f.env, "") if f.env else ""
                value = mine or saved or env
                rows.append({
                    "name": f.name, "label": f.label, "secret": f.secret, "required": f.required,
                    "kind": f.kind, "hint": f.hint, "set": bool(value),
                    "origin": "session" if mine else "saved" if saved else "environment" if env else "",
                    "preview": settings.mask(value) if (value and f.secret) else "",
                    "value": "" if (f.secret or not value) else value,
                })
            out.append({"name": name, "label": cls.label, "note": cls.note,
                        "types": sorted(t.value for t in cls.supports),
                        "configured": bool(live[name].configured) if name in live else False,
                        "fields": rows})
        return {"providers": out, "path": str(settings.credentials_path()), "demo": self.demo}

    def apply_settings(self, provider: str, values: dict[str, Any], persist: bool) -> None:
        if self.demo:
            raise ApiError("demo mode does not store keys")
        cls = REGISTRY.get(provider)
        if cls is None or not cls.credential_fields():
            raise ApiError(f"unknown provider '{provider}'")
        fields = {f.name: f for f in cls.credential_fields()}
        clean: dict[str, str] = {}
        for key, raw in values.items():
            if key not in fields:
                raise ApiError(f"{provider} has no field '{key}'")
            if not isinstance(raw, str):
                raise ApiError(f"{fields[key].label} must be text")
            try:
                clean[key] = settings.clean_value(raw, fields[key].kind)
            except ValueError as exc:
                raise ApiError(f"{fields[key].label} {exc}") from exc
        if not clean:
            raise ApiError("nothing to save")
        mine = self.session_keys.setdefault(provider, {})
        for key, value in clean.items():
            if not value:  # clearing removes the field everywhere
                mine.pop(key, None)
            elif not persist:
                mine[key] = value
        if persist:
            settings.set_stored(provider, clean)
            for key, value in clean.items():
                if value:
                    mine.pop(key, None)  # the saved copy now wins; no stale session copy
        else:
            cleared = {k: "" for k, v in clean.items() if not v}
            if cleared:
                settings.set_stored(provider, cleared)
        if not mine:
            self.session_keys.pop(provider, None)
        self.providers = self._build()

    def test_provider(self, name: str) -> dict[str, Any]:
        provider = next((p for p in self.providers if p.name == name), None)
        if provider is None:
            raise ApiError(f"unknown provider '{name}'")
        if not provider.configured:
            return {"ok": False, "message": "not configured yet"}
        result = provider.lookup(IOC("8.8.8.8", IOCType.IPV4))
        return {"ok": result.ok, "message": result.error or result.summary or "reachable"}

    # -- tracker
    def tracker_add(self, doc: dict[str, Any]) -> dict[str, Any]:
        try:
            tlp = normalize_tlp(str(doc.get("tlp") or ""))
            when = normalize_date(str(doc.get("date") or ""))
            confidence = normalize_confidence(str(doc.get("confidence") or ""))
        except ValueError as exc:
            raise ApiError(str(exc)) from exc
        context, source = str(doc.get("context") or ""), str(doc.get("source") or "")
        items: list[dict[str, Any]] = []
        rejected: list[str] = []
        if isinstance(doc.get("text"), str):
            iocs, rejected = parse_iocs(doc["text"].splitlines())
            known = doc.get("known") if isinstance(doc.get("known"), dict) else {}
            for i in iocs:
                hint = known.get(i.value) if isinstance(known.get(i.value), dict) else {}
                items.append({"ioc": i.original, "verdict": hint.get("verdict"), "score": hint.get("score")})
        for it in doc.get("items") or []:
            if isinstance(it, str):
                items.append({"ioc": it})
            elif isinstance(it, dict) and isinstance(it.get("ioc"), str):
                items.append(it)
        if not items:
            raise ApiError("no valid indicators to add")
        if len(items) > MAX_IOCS:
            raise ApiError(f"at most {MAX_IOCS} indicators per request", 413)
        added = updated = 0
        errors: list[str] = []
        for it in items:
            score = it.get("score")
            try:
                _, created = self.tracker.add(
                    it["ioc"], tlp=tlp, context=context, source=source, when=when, confidence=confidence,
                    verdict=str(it.get("verdict") or ""),
                    score=int(score) if isinstance(score, (int, float)) else None,
                )
            except ValueError as exc:
                errors.append(str(exc))
                continue
            added += created
            updated += not created
        if errors and not (added or updated):
            raise ApiError(errors[0])
        return {"added": added, "updated": updated, "rejected": rejected, "errors": errors}

    def tracker_export(self, doc: dict[str, Any]) -> dict[str, Any]:
        max_tlp = str(doc.get("max_tlp") or "")
        try:
            rows = self.tracker.search(max_tlp=max_tlp or None)
        except ValueError as exc:
            raise ApiError(str(exc)) from exc
        ids = doc.get("ids")
        if isinstance(ids, list):
            wanted = {i for i in ids if isinstance(i, int)}
            rows = [r for r in rows if r.id in wanted]
        text = to_markdown(rows, defanged=doc.get("defang", True) is not False, max_tlp=max_tlp or None)
        return {"markdown": text, "rows": len(rows), "filename": f"ioc-tracker-{date.today().isoformat()}.md"}


def make_handler(state: _State) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"intelscope/{__version__}"

        def log_message(self, fmt: str, *args: Any) -> None:  # keep the terminal quiet
            return

        # -- helpers
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, doc: Any) -> None:
            self._send(code, json.dumps(doc).encode(), "application/json")

        def _host_ok(self) -> bool:
            # Blocks DNS-rebinding: the Host header must be our own loopback address.
            port = self.server.server_address[1]
            return self.headers.get("Host", "") in {f"127.0.0.1:{port}", f"localhost:{port}"}

        def _token_ok(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-Intelscope-Token", ""), state.token)

        def _body(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ApiError("bad length") from None
            if length <= 0 or length > MAX_BODY:
                raise ApiError("body too large or empty", 413)
            try:
                doc = json.loads(self.rfile.read(length))
            except ValueError:
                raise ApiError("expected a JSON object") from None
            if not isinstance(doc, dict):
                raise ApiError("expected a JSON object")
            return doc

        # -- routes
        def do_GET(self) -> None:
            if not self._host_ok():
                return self._json(403, {"error": "bad host"})
            path = urlsplit(self.path).path
            if path in ("/", "/index.html"):
                return self._send(200, dashboard_html(), "text/html; charset=utf-8")
            if path == "/api/health":
                return self._json(
                    200,
                    {
                        "tool": "intelscope",
                        "version": __version__,
                        "demo": state.demo,
                        "token": state.token,
                        "providers": provider_status(state.providers),
                        "demo_iocs": DEMO_IOCS if state.demo else [],
                        "tlp_levels": list(TLP_LEVELS),
                    },
                )
            if path in ("/api/settings", "/api/tracker"):
                if not self._token_ok():
                    return self._json(403, {"error": "bad token"})
                if path == "/api/settings":
                    return self._json(200, state.settings_view())
                return self._json(200, {
                    "entries": [e.to_dict() for e in state.tracker.entries()],
                    "tlp_levels": list(TLP_LEVELS),
                    "path": "memory (demo)" if state.tracker.path is None else str(state.tracker.path),
                })
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._host_ok():
                return self._json(403, {"error": "bad host"})
            route = urlsplit(self.path).path
            if not route.startswith("/api/"):
                return self._json(404, {"error": "not found"})
            if not self._token_ok():
                return self._json(403, {"error": "bad token"})
            try:
                self._json(200, self._dispatch(route, self._body()))
            except ApiError as exc:
                self._json(exc.code, {"error": str(exc)})
            except KeyError:
                self._json(404, {"error": "not found"})

        def _dispatch(self, route: str, doc: dict[str, Any]) -> dict[str, Any]:
            if route == "/api/enrich":
                lines = doc.get("iocs")
                if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
                    raise ApiError('expected {"iocs": ["..."]}')
                if len(lines) > MAX_IOCS:
                    raise ApiError(f"at most {MAX_IOCS} indicators per request", 413)
                return state.enrich(lines)
            if route == "/api/enrich/start":
                lines = doc.get("iocs")
                if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
                    raise ApiError('expected {"iocs": ["..."]}')
                if len(lines) > MAX_IOCS:
                    raise ApiError(f"at most {MAX_IOCS} lines per request", 413)
                return {"id": state.start_enrich(lines)}
            if route == "/api/enrich/status":
                return state.enrich_status(str(doc.get("id") or ""))
            if route == "/api/tracker/import":
                text = doc.get("markdown")
                if not isinstance(text, str):
                    raise ApiError('expected {"markdown": "..."}')
                try:
                    return state.tracker.import_markdown(text)
                except ValueError as exc:
                    raise ApiError(str(exc)) from exc
            if route == "/api/settings":
                values = doc.get("values")
                if not isinstance(doc.get("provider"), str) or not isinstance(values, dict):
                    raise ApiError('expected {"provider": "...", "values": {...}}')
                state.apply_settings(doc["provider"], values, bool(doc.get("persist")))
                return state.settings_view()
            if route == "/api/settings/test":
                return state.test_provider(str(doc.get("provider") or ""))
            if route == "/api/tracker/add":
                return state.tracker_add(doc)
            if route == "/api/tracker/update":
                fields = {k: str(v) for k, v in (doc.get("fields") or {}).items() if k in
                          ("tlp", "confidence", "context", "source", "date")}
                try:
                    entry = state.tracker.update(int(doc.get("id")), **fields)
                except (TypeError, ValueError) as exc:
                    raise ApiError(str(exc)) from exc
                return {"entry": entry.to_dict()}
            if route == "/api/tracker/delete":
                ids = doc.get("ids")
                if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids):
                    raise ApiError('expected {"ids": [1, 2]}')
                return {"removed": state.tracker.remove(ids)}
            if route == "/api/tracker/export":
                return state.tracker_export(doc)
            raise KeyError(route)

    return Handler


def serve(
    port: int = 8765,
    demo: bool = False,
    use_cache: bool = True,
    workers: int = 8,
    open_browser: bool = False,
    tracker_path: str | None = None,
) -> ThreadingHTTPServer:
    """Create the server (bound to loopback only) and return it, not yet serving."""
    state = _State(demo, use_cache, workers, tracker_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    httpd.intelscope_state = state  # type: ignore[attr-defined]  # for tests and embedding
    if open_browser:
        import webbrowser

        webbrowser.open(f"http://127.0.0.1:{port}/")
    return httpd
