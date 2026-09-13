"""
Tests for API endpoints (no real API calls — all provider calls mocked).
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database.database import init_database

# Initialize DB for tests
init_database()

client = TestClient(app)


# ---------------------------------------------------------------------------
# System endpoints
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_returns_200(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "SentinelLLM"


class TestModelsEndpoint:
    def test_models_returns_structure(self):
        resp = client.get("/models")
        assert resp.status_code == 200
        data = resp.json()
        assert "target_providers" in data
        assert "gemini" in data["target_providers"]
        assert "groq" in data["target_providers"]
        assert data["evaluator"]["provider"] == "groq"
        assert data["evaluator"]["locked"] is True


class TestTestsEndpoint:
    def test_tests_returns_categories(self):
        resp = client.get("/tests")
        assert resp.status_code == 200
        data = resp.json()
        assert "categories" in data
        assert "techniques" in data
        assert "test_cases" in data
        assert len(data["test_cases"]) > 0


# ---------------------------------------------------------------------------
# Scan validation
# ---------------------------------------------------------------------------

class TestScanValidation:
    def test_invalid_provider_returns_400(self):
        resp = client.post("/scan", json={
            "provider": "openai",
            "model": "gpt-4",
            "vulnerability": "Prompt Injection",
            "attack_technique": "Standard English",
        })
        assert resp.status_code == 400
        assert "Unsupported provider" in resp.json()["detail"]

    def test_invalid_model_returns_400(self):
        resp = client.post("/scan", json={
            "provider": "gemini",
            "model": "nonexistent-model",
            "vulnerability": "Prompt Injection",
            "attack_technique": "Standard English",
        })
        assert resp.status_code == 400
        assert "not available" in resp.json()["detail"]

    def test_non_groq_evaluator_returns_400(self):
        resp = client.post("/scan", json={
            "provider": "gemini",
            "model": "gemini-3.5-flash",
            "evaluator_provider": "openai",
            "vulnerability": "Prompt Injection",
            "attack_technique": "Standard English",
        })
        assert resp.status_code == 400
        assert "groq" in resp.json()["detail"].lower()

    def test_invalid_vulnerability_returns_400(self):
        resp = client.post("/scan", json={
            "provider": "gemini",
            "model": "gemini-3.5-flash",
            "vulnerability": "SQL Injection",
            "attack_technique": "Standard English",
        })
        assert resp.status_code == 400
        assert "Unknown vulnerability" in resp.json()["detail"]

    def test_invalid_technique_returns_400(self):
        resp = client.post("/scan", json={
            "provider": "gemini",
            "model": "gemini-3.5-flash",
            "vulnerability": "Prompt Injection",
            "attack_technique": "Hypnosis",
        })
        assert resp.status_code == 400
        assert "Unknown attack technique" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Scan execution (demo mode)
# ---------------------------------------------------------------------------

class TestScanDemoMode:
    def test_scan_demo_mode_returns_result(self, monkeypatch):
        """Demo mode should return a valid result without API keys."""
        monkeypatch.setattr("app.config.get_api_key", lambda provider: "")
        resp = client.post("/scan", json={
            "provider": "gemini",
            "model": "gemini-3.5-flash",
            "vulnerability": "Prompt Injection",
            "attack_technique": "Standard English",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert data["mode"] == "DEMO"
        assert data["target"]["provider"].lower() == "gemini"
        assert data["result"]["status"] in ("PASS", "FAIL", "INCONCLUSIVE")
        assert 0 <= data["result"]["risk_score"] <= 100
        assert data["result"]["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert "owasp" in data
        assert "evidence" in data

    def test_scan_groq_target_demo(self, monkeypatch):
        monkeypatch.setattr("app.config.get_api_key", lambda provider: "")
        resp = client.post("/scan", json={
            "provider": "groq",
            "model": "openai/gpt-oss-20b",
            "vulnerability": "Jailbreak Resistance",
            "attack_technique": "Standard English",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["mode"] == "DEMO"
