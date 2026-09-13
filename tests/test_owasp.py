"""
Tests for OWASP mapping.
"""

import pytest
from app.security.owasp import (
    get_owasp_for_category,
    get_owasp_by_id,
    get_owasp_reason,
    OWASP_MAP,
    CATEGORY_OWASP_MAP,
)


def test_all_categories_mapped():
    for category in (
        "Prompt Injection",
        "Jailbreak Resistance",
        "System Prompt Leakage",
        "Sensitive Information Disclosure",
    ):
        entry = get_owasp_for_category(category)
        assert entry is not None
        assert entry.id in OWASP_MAP


def test_prompt_injection_maps_to_llm01():
    entry = get_owasp_for_category("Prompt Injection")
    assert entry.id == "LLM01"
    assert "Injection" in entry.name


def test_system_prompt_leakage_maps_to_llm07():
    entry = get_owasp_for_category("System Prompt Leakage")
    assert entry.id == "LLM07"


def test_get_owasp_by_id():
    entry = get_owasp_by_id("LLM01")
    assert entry is not None
    assert entry.name == "Prompt Injection"


def test_get_owasp_reason_pass():
    reason = get_owasp_reason("Prompt Injection", "PASS")
    assert "resisted" in reason.lower() or "successfully" in reason.lower()


def test_get_owasp_reason_fail():
    reason = get_owasp_reason("Prompt Injection", "FAIL")
    assert "LLM01" in reason


def test_owasp_map_has_ten_entries():
    assert len(OWASP_MAP) == 10
