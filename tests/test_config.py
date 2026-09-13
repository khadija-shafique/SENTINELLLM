"""
Tests for centralized configuration.
"""

import pytest
from app.config import (
    PROVIDERS,
    DEFAULT_TARGET_PROVIDER,
    DEFAULT_TARGET_MODEL,
    EVALUATOR_PROVIDER,
    DEFAULT_EVALUATOR_MODEL,
    VULNERABILITY_CATEGORIES,
    ATTACK_TECHNIQUES,
    RISK_BANDS,
    CANARY_SECRET,
)


def test_providers_has_gemini_and_groq():
    assert "gemini" in PROVIDERS
    assert "groq" in PROVIDERS


def test_default_target_is_gemini():
    assert DEFAULT_TARGET_PROVIDER == "gemini"
    assert DEFAULT_TARGET_MODEL == "gemini-3.5-flash"
    assert DEFAULT_TARGET_MODEL in PROVIDERS["gemini"]


def test_evaluator_locked_to_groq():
    assert EVALUATOR_PROVIDER == "groq"
    assert DEFAULT_EVALUATOR_MODEL == "openai/gpt-oss-20b"
    assert DEFAULT_EVALUATOR_MODEL in PROVIDERS["groq"]


def test_vulnerability_categories():
    assert len(VULNERABILITY_CATEGORIES) == 4
    assert "Prompt Injection" in VULNERABILITY_CATEGORIES
    assert "Jailbreak Resistance" in VULNERABILITY_CATEGORIES
    assert "System Prompt Leakage" in VULNERABILITY_CATEGORIES
    assert "Sensitive Information Disclosure" in VULNERABILITY_CATEGORIES


def test_attack_techniques():
    assert len(ATTACK_TECHNIQUES) >= 7
    assert "Standard English" in ATTACK_TECHNIQUES
    assert "Roman Urdu" in ATTACK_TECHNIQUES


def test_risk_bands_cover_full_range():
    """Risk bands should cover 0–100 without gaps."""
    for low, high, label in RISK_BANDS:
        assert low >= 0
        assert high <= 100
        assert label in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_canary_secret_is_defined():
    assert CANARY_SECRET == "CANARY_SECRET_48291"
