from conftest import result

from iocscope.models import Verdict
from iocscope.scoring import assess

W = {"vt": 1.0, "abuse": 0.9, "gn": 0.7}


def test_allowlisted_short_circuits():
    score, verdict, reasons = assess([result("vt", 100)], W, "allowlisted IP")
    assert (score, verdict) == (0, Verdict.BENIGN)
    assert reasons == ["allowlisted: allowlisted IP"]


def test_corroboration_bonus():
    score, verdict, _ = assess([result("vt", 60), result("abuse", 100)], W)
    # top = 90 (100 * 0.9), one corroborating source above 50 -> +10
    assert (score, verdict) == (100, Verdict.MALICIOUS)


def test_single_weak_signal_is_low():
    score, verdict, _ = assess([result("vt", 24), result("gn", None)], W)
    assert (score, verdict) == (24, Verdict.LOW)


def test_suspicious_band():
    score, verdict, _ = assess([result("vt", 48)], W)
    assert verdict is Verdict.SUSPICIOUS and score == 48


def test_benign_overrides_weak_signals():
    score, verdict, reasons = assess([result("vt", 12), result("gn", 0, benign=True)], W)
    assert (score, verdict) == (0, Verdict.BENIGN)
    assert reasons[0].startswith("gn:")


def test_benign_conflict_with_strong_signal_is_flagged():
    score, verdict, reasons = assess([result("vt", 96), result("gn", 0, benign=True)], W)
    assert score == 76 and verdict is Verdict.MALICIOUS
    assert any(r.startswith("conflict:") for r in reasons)


def test_nothing_found_is_unknown():
    score, verdict, _ = assess([result("vt", found=False), result("abuse", found=False)], W)
    assert (score, verdict) == (0, Verdict.UNKNOWN)


def test_all_errors_is_unknown_with_reasons():
    score, verdict, reasons = assess([result("vt", ok=False, summary="quota")], W)
    assert verdict is Verdict.UNKNOWN
    assert reasons == ["vt: quota"]


def test_seen_but_clean_is_low_zero():
    score, verdict, reasons = assess([result("vt", 0)], W)
    assert (score, verdict) == (0, Verdict.LOW)
    assert "none flag it" in reasons[0]
