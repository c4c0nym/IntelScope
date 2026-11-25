"""Local web server: serves the dashboard and a small enrichment API.

    intelscope serve            # http://127.0.0.1:8765, live lookups with your .env keys
    intelscope serve --demo     # same UI, canned offline data

The API keys stay on this machine: the browser only ever talks to 127.0.0.1, and the
server talks to the threat-intel sources. Only standard-library HTTP is used.
"""

from __future__ import annotations

import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

from intelscope import __version__
from intelscope.allowlist import load_allowlist
from intelscope.cache import Cache, default_cache_path
from intelscope.demo import DEMO_IOCS, build_demo_providers
from intelscope.detect import parse_iocs
from intelscope.enrich import Enricher, triage_order
from intelscope.providers import REGISTRY, build_providers

MAX_BODY = 256 * 1024
MAX_IOCS = 500


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

    def __init__(self, demo: bool, use_cache: bool, workers: int) -> None:
        self.demo = demo
        names = list(REGISTRY)
        self.providers = build_demo_providers(names) if demo else build_providers()
        self.allowlist = load_allowlist(skip_reserved=not demo)
        self.cache = None if (demo or not use_cache) else Cache(default_cache_path(), ttl_seconds=24 * 3600)
        self.workers = workers
        # Per-run token: the page reads it from /api/health, so a random site in another
        # tab (which cannot read our responses) cannot trigger lookups with your keys.
        self.token = secrets.token_urlsafe(16)

    def enrich(self, lines: list[str]) -> dict[str, Any]:
        iocs, rejected = parse_iocs(lines)
        active = [p for p in self.providers if p.configured]
        enricher = Enricher(
            active, allowlist=self.allowlist, cache=self.cache, max_workers=self.workers
        )
        results = triage_order(enricher.enrich(iocs)) if iocs else []
        if self.cache:
            self.cache.save()
        return {
            "tool": f"intelscope {__version__}",
            "count": len(results),
            "rejected": rejected,
            "results": [r.to_dict() for r in results],
        }


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
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, doc: Any) -> None:
            self._send(code, json.dumps(doc).encode(), "application/json")

        def _host_ok(self) -> bool:
            # Blocks DNS-rebinding: the Host header must be our own loopback address.
            port = self.server.server_address[1]
            return self.headers.get("Host", "") in {f"127.0.0.1:{port}", f"localhost:{port}"}

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
                    },
                )
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._host_ok():
                return self._json(403, {"error": "bad host"})
            if urlsplit(self.path).path != "/api/enrich":
                return self._json(404, {"error": "not found"})
            if not secrets.compare_digest(self.headers.get("X-Intelscope-Token", ""), state.token):
                return self._json(403, {"error": "bad token"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._json(400, {"error": "bad length"})
            if length <= 0 or length > MAX_BODY:
                return self._json(413, {"error": "body too large or empty"})
            try:
                doc = json.loads(self.rfile.read(length))
                lines = doc["iocs"]
                if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                return self._json(400, {"error": 'expected {"iocs": ["..."]}'})
            if len(lines) > MAX_IOCS:
                return self._json(413, {"error": f"at most {MAX_IOCS} indicators per request"})
            self._json(200, state.enrich(lines))

    return Handler


def serve(
    port: int = 8765,
    demo: bool = False,
    use_cache: bool = True,
    workers: int = 8,
    open_browser: bool = False,
) -> ThreadingHTTPServer:
    """Create the server (bound to loopback only) and return it, not yet serving."""
    state = _State(demo, use_cache, workers)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    if open_browser:
        import webbrowser

        webbrowser.open(f"http://127.0.0.1:{port}/")
    return httpd
