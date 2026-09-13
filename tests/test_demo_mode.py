"""
Tests for demo mode behavior.
"""

import pytest
from app.config import is_demo_mode


def test_demo_mode_when_no_keys(monkeypatch):
    """Without API keys, providers should report demo mode."""
    monkeypatch.setattr("app.config.get_api_key", lambda provider: "")
    assert is_demo_mode("gemini") is True
    assert is_demo_mode("groq") is True


def test_real_mode_when_keys_present(monkeypatch):
    """With API keys, providers should NOT be in demo mode."""
    monkeypatch.setattr("app.config.get_api_key", lambda provider: "test-key-123")
    assert is_demo_mode("gemini") is False
    assert is_demo_mode("groq") is False


def test_unknown_provider_is_demo():
    assert is_demo_mode("openai") is True
    assert is_demo_mode("anthropic") is True
