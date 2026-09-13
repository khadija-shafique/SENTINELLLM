"""
Tests for the risk scoring engine.
"""

import pytest
from app.security.risk_engine import (
    calculate_risk_score,
    compute_severity,
    severity_from_score,
)


class TestSeverityMapping:
    def test_low(self):
        assert severity_from_score(0) == "LOW"
        assert severity_from_score(10) == "LOW"
        assert severity_from_score(24) == "LOW"

    def test_medium(self):
        assert severity_from_score(25) == "MEDIUM"
        assert severity_from_score(49) == "MEDIUM"

    def test_high(self):
        assert severity_from_score(50) == "HIGH"
        assert severity_from_score(74) == "HIGH"

    def test_critical(self):
        assert severity_from_score(75) == "CRITICAL"
        assert severity_from_score(100) == "CRITICAL"


class TestRiskScore:
    def test_pass_gives_low_score(self):
        score = calculate_risk_score(
            result="PASS",
            category="Prompt Injection",
            confidence=0.95,
        )
        assert 0 <= score <= 24

    def test_inconclusive_gives_medium_score(self):
        score = calculate_risk_score(
            result="INCONCLUSIVE",
            category="Prompt Injection",
            confidence=0.50,
        )
        assert 25 <= score <= 49

    def test_fail_gives_high_or_critical(self):
        score = calculate_risk_score(
            result="FAIL",
            category="Prompt Injection",
            confidence=0.90,
        )
        assert score >= 50

    def test_fail_with_high_confidence_higher_score(self):
        score_high = calculate_risk_score(
            result="FAIL",
            category="Sensitive Information Disclosure",
            confidence=0.99,
        )
        score_low = calculate_risk_score(
            result="FAIL",
            category="Sensitive Information Disclosure",
            confidence=0.50,
        )
        # Higher confidence in FAIL should give >= score
        assert score_high >= score_low

    def test_score_within_bounds(self):
        for result in ("PASS", "FAIL", "INCONCLUSIVE"):
            for category in (
                "Prompt Injection",
                "Jailbreak Resistance",
                "System Prompt Leakage",
                "Sensitive Information Disclosure",
            ):
                score = calculate_risk_score(
                    result=result,
                    category=category,
                    confidence=0.80,
                )
                assert 0 <= score <= 100

    def test_deterministic_hint_used_for_fail(self):
        score = calculate_risk_score(
            result="FAIL",
            category="Prompt Injection",
            confidence=0.90,
            deterministic_risk_hint=90,
        )
        assert score >= 60  # High hint → high score
