from conftest import StubProvider, ioc, result

from iocscope.allowlist import load_allowlist
from iocscope.cache import Cache
from iocscope.enrich import Enricher, triage_order
from iocscope.models import IOCType, Verdict
from iocscope.ratelimit import RateLimiter


def test_enrich_scores_and_orders():
    vt = StubProvider("vt", {"1.1.1.2": result("vt", 96), "9.9.9.8": result("vt", 0)})
    out = Enricher([vt]).enrich([ioc("9.9.9.8"), ioc("1.1.1.2")])
    assert [o.verdict for o in out] == [Verdict.LOW, Verdict.MALICIOUS]
    assert [o.ioc.value for o in triage_order(out)] == ["1.1.1.2", "9.9.9.8"]


def test_unsupported_types_are_not_queried():
    ip_only = StubProvider("abuse", {}, supports=frozenset({IOCType.IPV4}))
    Enricher([ip_only]).enrich([ioc("evil.test", IOCType.DOMAIN)])
    assert ip_only.calls == []


def test_allowlisted_iocs_skip_lookups():
    vt = StubProvider("vt", {})
    out = Enricher([vt], allowlist=load_allowlist()).enrich([ioc("8.8.8.8")])
    assert vt.calls == []
    assert out[0].allowlisted and out[0].verdict is Verdict.BENIGN


def test_provider_crash_is_isolated():
    broken = StubProvider("broken", {"1.2.3.4": RuntimeError("boom")})
    good = StubProvider("good", {"1.2.3.4": result("good", 80)})
    out = Enricher([broken, good]).enrich([ioc("1.2.3.4")])
    errors = [r for r in out[0].results if not r.ok]
    assert errors and errors[0].error == "internal error (RuntimeError)"
    assert out[0].verdict is Verdict.MALICIOUS


def test_progress_callback():
    vt = StubProvider("vt", {})
    seen = []
    Enricher([vt]).enrich([ioc("1.2.3.4"), ioc("5.6.7.8")], on_progress=lambda d, t: seen.append((d, t)))
    assert seen[0] == (0, 2) and seen[-1] == (2, 2)


def test_cache_round_trip_and_expiry(tmp_path):
    now = [1000.0]
    path = tmp_path / "c.json"
    vt = StubProvider("vt", {"1.2.3.4": result("vt", 50)})

    cache = Cache(path, ttl_seconds=60, clock=lambda: now[0])
    Enricher([vt], cache=cache).enrich([ioc("1.2.3.4")])
    cache.save()
    assert vt.calls == ["1.2.3.4"]

    cache = Cache(path, ttl_seconds=60, clock=lambda: now[0] + 30)
    out = Enricher([vt], cache=cache).enrich([ioc("1.2.3.4")])
    assert vt.calls == ["1.2.3.4"]  # served from cache
    assert out[0].results[0].cached

    cache = Cache(path, ttl_seconds=60, clock=lambda: now[0] + 120)
    Enricher([vt], cache=cache).enrich([ioc("1.2.3.4")])
    assert vt.calls == ["1.2.3.4", "1.2.3.4"]  # expired, looked up again


def test_failures_are_not_cached(tmp_path):
    cache = Cache(tmp_path / "c.json", ttl_seconds=60)
    cache.put("vt", ioc("1.2.3.4"), result("vt", ok=False, summary="quota"))
    assert cache.get("vt", ioc("1.2.3.4")) is None


def test_corrupt_cache_file_is_ignored(tmp_path):
    path = tmp_path / "c.json"
    path.write_text("{not json")
    assert Cache(path, ttl_seconds=60).get("vt", ioc("1.2.3.4")) is None


def test_rate_limiter_spaces_calls():
    clock = [0.0]
    slept = []
    limiter = RateLimiter(4, 60.0, clock=lambda: clock[0], sleep=slept.append)
    for _ in range(3):
        limiter.wait()
    assert slept == [15.0, 30.0]
