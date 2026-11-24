"""Combine per-source opinions into one score and verdict.

The method is deliberately simple and explainable, so an analyst can defend it:

1. Each source's score (0-100) is multiplied by a source weight that reflects how
   directly it measures maliciousness (e.g. GreyNoise "malicious" means mass scanning,
   which is weaker evidence than a URLhaus payload hit).
2. The strongest weighted signal sets the base score.
3. Every additional source that independently reaches >= 50 adds 10 (corroboration).
4. A source that positively asserts "benign" (RIOT, AbuseIPDB whitelist) overrides
   weak signals, and pulls strong ones down by 20 while flagging the conflict.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from iocscope.models import ProviderResult, Verdict

MALICIOUS_AT = 70
SUSPICIOUS_AT = 40
CORROBORATION_AT = 50
CORROBORATION_BONUS = 10
CONFLICT_PENALTY = 20


def verdict_for(score: float) -> Verdict:
    if score >= MALICIOUS_AT:
        return Verdict.MALICIOUS
    if score >= SUSPICIOUS_AT:
        return Verdict.SUSPICIOUS
    return Verdict.LOW


def assess(
    results: Sequence[ProviderResult],
    weights: Mapping[str, float],
    allowlist_reason: str | None = None,
) -> tuple[int, Verdict, list[str]]:
    if allowlist_reason:
        return 0, Verdict.BENIGN, [f"allowlisted: {allowlist_reason}"]

    ok = [r for r in results if r.ok]
    if not ok:
        errors = [f"{r.provider}: {r.error}" for r in results if r.error]
        return 0, Verdict.UNKNOWN, errors or ["no source could be queried"]
    if not any(r.found for r in ok):
        return 0, Verdict.UNKNOWN, ["no source has a record of this indicator"]

    signals = sorted(
        ((r.score * weights.get(r.provider, 1.0), r) for r in ok if r.score),
        key=lambda pair: pair[0],
        reverse=True,
    )
    reasons = [f"{r.provider}: {r.summary}" for _, r in signals]
    top = signals[0][0] if signals else 0.0
    corroborating = sum(1 for weighted, _ in signals if weighted >= CORROBORATION_AT)
    score = top + CORROBORATION_BONUS * max(0, corroborating - 1)

    benign_votes = [r for r in ok if r.benign]
    if benign_votes:
        benign_reasons = [f"{r.provider}: {r.summary}" for r in benign_votes]
        if top < CORROBORATION_AT:
            return 0, Verdict.BENIGN, benign_reasons + reasons
        names = ", ".join(r.provider for r in benign_votes)
        score -= CONFLICT_PENALTY
        reasons.append(f"conflict: {names} report this as benign")

    score = int(round(max(0.0, min(100.0, score))))
    if not signals:
        reasons = ["seen by sources, but none flag it as malicious"]
    return score, verdict_for(score), reasons
