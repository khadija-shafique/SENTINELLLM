"""
Tests for security integrity calculation.
"""

import pytest
from app.security.integrity import calculate_integrity


def test_no_findings_full_integrity():
    score = calculate_integrity([])
    assert score == 100.0


def test_pass_findings_no_deduction():
    findings = [
        {"result": "PASS", "risk_score": 10, "severity": "LOW"},
        {"result": "PASS", "risk_score": 5, "severity": "LOW"},
    ]
    score = calculate_integrity(findings)
    assert score == 100.0


def test_fail_findings_reduce_integrity():
    findings = [
        {"result": "FAIL", "risk_score": 80, "severity": "CRITICAL"},
    ]
    score = calculate_integrity(findings)
    assert score < 100.0


def test_multiple_fails_compound():
    findings_one = [
        {"result": "FAIL", "risk_score": 50, "severity": "HIGH"},
    ]
    findings_two = [
        {"result": "FAIL", "risk_score": 50, "severity": "HIGH"},
        {"result": "FAIL", "risk_score": 70, "severity": "HIGH"},
    ]
    score_one = calculate_integrity(findings_one)
    score_two = calculate_integrity(findings_two)
    assert score_two < score_one


def test_critical_deducts_more_than_low():
    findings_low = [
        {"result": "FAIL", "risk_score": 50, "severity": "LOW"},
    ]
    findings_critical = [
        {"result": "FAIL", "risk_score": 50, "severity": "CRITICAL"},
    ]
    score_low = calculate_integrity(findings_low)
    score_critical = calculate_integrity(findings_critical)
    assert score_critical < score_low


def test_integrity_never_below_zero():
    findings = [
        {"result": "FAIL", "risk_score": 100, "severity": "CRITICAL"}
        for _ in range(20)
    ]
    score = calculate_integrity(findings)
    assert score >= 0.0


def test_inconclusive_no_deduction():
    findings = [
        {"result": "INCONCLUSIVE", "risk_score": 40, "severity": "MEDIUM"},
    ]
    score = calculate_integrity(findings)
    assert score == 100.0
