"""T2.16 acceptance: property tests — monotonic, bounded, stable ordering."""

import random

from app.vendor.dbdoctor.engine.rules.base import Finding
from app.vendor.dbdoctor.engine.score import CATEGORY_CAP, FLOOR, compute_score

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
CATEGORIES = list(CATEGORY_CAP)


def _finding(i: int, rng: random.Random) -> Finding:
    return Finding(
        rule_id=f"R-X{i}",
        severity=rng.choice(SEVERITIES),
        title="t",
        affected_object=f"obj{i}",
        suggested_action="a",
        engine="postgres",
        category=rng.choice(CATEGORIES),
        impact=rng.random() * 1000,
    )


def _random_findings(rng: random.Random, n: int) -> list[Finding]:
    return [_finding(i, rng) for i in range(n)]


def test_empty_is_perfect():
    assert compute_score([]).score == 100


def test_bounded_for_many_random_cases():
    rng = random.Random(42)
    for _ in range(200):
        findings = _random_findings(rng, rng.randint(0, 60))
        s = compute_score(findings).score
        assert FLOOR <= s <= 100


def test_monotonic_adding_a_finding_never_raises_score():
    rng = random.Random(7)
    for _ in range(200):
        findings = _random_findings(rng, rng.randint(0, 40))
        base = compute_score(findings).score
        extra = _finding(999, rng)
        assert compute_score([*findings, extra]).score <= base


def test_order_independent():
    rng = random.Random(13)
    findings = _random_findings(rng, 30)
    a = compute_score(findings)
    shuffled = findings[:]
    rng.shuffle(shuffled)
    b = compute_score(shuffled)
    assert a.score == b.score
    assert a.category_deductions == b.category_deductions
    # top findings are ordering-stable thanks to deterministic tie-breakers
    assert [(f.rule_id, f.affected_object) for f in a.top_findings] == [
        (f.rule_id, f.affected_object) for f in b.top_findings
    ]


def test_one_category_cannot_zero_the_score():
    findings = [
        Finding(
            rule_id=f"R-Q{i}",
            severity="CRITICAL",
            title="t",
            affected_object=f"q{i}",
            suggested_action="a",
            engine="postgres",
            category="queries",
        )
        for i in range(20)  # 20 * 15 = 300 raw points, capped at 30
    ]
    result = compute_score(findings)
    assert result.score == 70
    assert result.category_deductions == {"queries": 30}


def test_deduction_arithmetic():
    findings = [
        Finding(
            rule_id="a",
            severity="CRITICAL",
            title="t",
            affected_object="x",
            suggested_action="a",
            engine="postgres",
            category="queries",
        ),
        Finding(
            rule_id="b",
            severity="HIGH",
            title="t",
            affected_object="x",
            suggested_action="a",
            engine="postgres",
            category="indexes",
        ),
        Finding(
            rule_id="c",
            severity="MEDIUM",
            title="t",
            affected_object="x",
            suggested_action="a",
            engine="postgres",
            category="config",
        ),
        Finding(
            rule_id="d",
            severity="LOW",
            title="t",
            affected_object="x",
            suggested_action="a",
            engine="postgres",
            category="ops",
        ),
        Finding(
            rule_id="e",
            severity="INFO",
            title="t",
            affected_object="x",
            suggested_action="a",
            engine="postgres",
            category="maintenance",
        ),
    ]
    result = compute_score(findings)
    assert result.score == 100 - 15 - 8 - 3 - 1
    assert len(result.top_findings) == 5
