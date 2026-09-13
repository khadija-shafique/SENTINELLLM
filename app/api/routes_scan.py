"""
API routes: POST /scan, POST /evaluate
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, HTTPException, Request, Body

from app.api.rate_limit import rate_limit

from app.config import (
    PROVIDERS,
    EVALUATOR_PROVIDER,
    DEFAULT_TARGET_PROVIDER,
    DEFAULT_TARGET_MODEL,
    DEFAULT_EVALUATOR_MODEL,
    VULNERABILITY_CATEGORIES,
    ATTACK_TECHNIQUES,
)
from app.schemas.scan import ScanRequest, ScanResponse, EvaluateRequest, EvaluateResponse
from app.security.attack_engine import execute_scan
from app.security.evaluator import run_llm_evaluation
from app.security.risk_engine import calculate_risk_score, compute_severity

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_provider_model(provider: str, model: str) -> None:
    """Validate that the provider/model combination is supported."""
    provider_lower = provider.lower()
    if provider_lower not in PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider '{provider}'. Valid providers: {list(PROVIDERS.keys())}",
        )
    if model not in PROVIDERS[provider_lower]:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Model '{model}' is not available for provider '{provider}'. "
                f"Available models: {PROVIDERS[provider_lower]}"
            ),
        )


def _validate_evaluator_provider(evaluator_provider: str | None) -> None:
    """Reject any evaluator_provider that is not 'groq'."""
    if evaluator_provider and evaluator_provider.lower() != EVALUATOR_PROVIDER:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Evaluator provider must be 'groq' (locked for this deployment). "
                f"Received: '{evaluator_provider}'. The evaluator is fixed to Groq "
                f"to ensure consistent, cross-provider grading."
            ),
        )


def _validate_vulnerability(vulnerability: str) -> None:
    if vulnerability not in VULNERABILITY_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown vulnerability category '{vulnerability}'. "
                f"Valid categories: {VULNERABILITY_CATEGORIES}"
            ),
        )


def _validate_technique(technique: str) -> None:
    if technique not in ATTACK_TECHNIQUES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown attack technique '{technique}'. "
                f"Valid techniques: {ATTACK_TECHNIQUES}"
            ),
        )


# ---------------------------------------------------------------------------
# POST /scan
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=ScanResponse, tags=["Security Testing"])
async def run_scan(request: Request, req: ScanRequest = Body(...)):
    """
    Execute a single controlled security test against a target LLM.

    Runs one vulnerability category + one attack technique per call.
    """
    # Validate inputs
    _validate_provider_model(req.provider, req.model)
    _validate_evaluator_provider(req.evaluator_provider)
    _validate_vulnerability(req.vulnerability)
    _validate_technique(req.attack_technique)

    # Only validated requests consume the caller's rate budget
    await rate_limit(request)

    eval_model = req.evaluator_model or DEFAULT_EVALUATOR_MODEL

    try:
        result = await execute_scan(
            provider=req.provider.lower(),
            model=req.model,
            vulnerability=req.vulnerability,
            attack_technique=req.attack_technique,
            system_prompt=req.system_prompt or "You are a helpful AI assistant.",
            evaluator_model=eval_model,
        )

        # Check for engine-level errors
        if result.get("error"):
            logger.error("Scan engine error: %s", result["error"])
            raise HTTPException(status_code=500, detail="Scan could not be completed.")

        return result

    except HTTPException:
        raise
    except Exception:
        logger.exception("Scan execution failed")
        raise HTTPException(status_code=500, detail="Internal scan error.")


# ---------------------------------------------------------------------------
# POST /evaluate (standalone evaluator)
# ---------------------------------------------------------------------------

@router.post("/evaluate", response_model=EvaluateResponse, tags=["Evaluation"])
async def evaluate(request: Request, req: EvaluateRequest = Body(...)):
    """
    Run the evaluator on already-collected data (without calling a target model).
    Useful for re-evaluating a previously captured response.
    """
    _validate_vulnerability(req.vulnerability)
    await rate_limit(request)

    try:
        eval_result = await run_llm_evaluation(
            category=req.vulnerability,
            technique=req.attack_technique,
            test_prompt=req.test_prompt,
            target_response=req.target_response,
            expected_behavior=req.expected_behavior,
        )

        risk_score = calculate_risk_score(
            result=eval_result.result,
            category=req.vulnerability,
            confidence=eval_result.confidence,
            evaluator_risk_hint=eval_result.risk_score,
        )

        return EvaluateResponse(
            result=eval_result.result,
            risk_score=risk_score,
            severity=compute_severity(risk_score),
            reason=eval_result.reason,
            evidence=eval_result.evidence,
            confidence=eval_result.confidence,
            needs_review=eval_result.needs_review,
        )

    except Exception:
        logger.exception("Evaluation failed")
        raise HTTPException(status_code=500, detail="Evaluation error.")
