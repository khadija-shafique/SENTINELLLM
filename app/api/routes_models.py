"""
API routes: GET /health, GET /models, GET /tests
"""

from __future__ import annotations

from fastapi import APIRouter

from app.config import (
    PROVIDERS,
    DEFAULT_TARGET_PROVIDER,
    DEFAULT_TARGET_MODEL,
    EVALUATOR_PROVIDER,
    DEFAULT_EVALUATOR_MODEL,
    VULNERABILITY_CATEGORIES,
    ATTACK_TECHNIQUES,
    GEMINI_API_KEY,
    GROQ_API_KEY,
)
from app.security.test_cases import get_all_test_cases, list_available_tests

router = APIRouter()


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

@router.get("/health", tags=["System"])
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "SentinelLLM",
        "version": "1.0.0",
        "providers": {
            "gemini": "configured" if GEMINI_API_KEY else "demo_mode",
            "groq": "configured" if GROQ_API_KEY else "demo_mode",
        },
    }


# ---------------------------------------------------------------------------
# GET /models
# ---------------------------------------------------------------------------

@router.get("/models", tags=["Configuration"])
async def list_models():
    """
    List available target providers/models and the locked evaluator config.
    """
    return {
        "target_providers": PROVIDERS,
        "defaults": {
            "provider": DEFAULT_TARGET_PROVIDER,
            "model": DEFAULT_TARGET_MODEL,
        },
        "evaluator": {
            "provider": EVALUATOR_PROVIDER,
            "model": DEFAULT_EVALUATOR_MODEL,
            "locked": True,
        },
    }


# ---------------------------------------------------------------------------
# GET /tests
# ---------------------------------------------------------------------------

@router.get("/tests", tags=["Configuration"])
async def list_tests():
    """
    List all available security test cases and category→technique mappings.

    Callers can use this to discover what tests are available and
    orchestrate their own assessment loop.
    """
    return {
        "categories": VULNERABILITY_CATEGORIES,
        "techniques": ATTACK_TECHNIQUES,
        "available_tests": list_available_tests(),
        "test_cases": get_all_test_cases(),
    }
