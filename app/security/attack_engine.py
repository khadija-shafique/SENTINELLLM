"""
Attack engine — orchestrates the full security test pipeline.

Receives a scan request, selects the test case, calls the target model,
runs deterministic checks + LLM evaluator, calculates risk, stores evidence,
and returns a structured result.

Implements bounded agentic retesting (max 3 attempts for INCONCLUSIVE).
"""

from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

from app.config import (
    CANARY_SECRET,
    DEFAULT_EVALUATOR_MODEL,
    EVALUATOR_PROVIDER,
    MAX_RETEST_ATTEMPTS,
    is_demo_mode,
)
from app.providers.base import get_provider, NormalizedResponse
from app.security.test_cases import get_test_case, TestCase
from app.security.deterministic_rules import run_deterministic_checks, DeterministicResult
from app.security.evaluator import run_llm_evaluation, EvaluatorResult
from app.security.risk_engine import calculate_risk_score, compute_severity
from app.security.owasp import get_owasp_for_category, get_owasp_reason
from app.security.integrity import calculate_integrity
from app.database.database import store_scan_result, get_all_findings

logger = logging.getLogger(__name__)


async def _call_target(
    provider_name: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> NormalizedResponse:
    """Call the target model through the provider abstraction."""
    provider = get_provider(provider_name)
    return await provider.call_model(
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
    )


def _prepare_system_prompt(
    base_prompt: str,
    test_case: TestCase,
) -> str:
    """Optionally augment the system prompt with test-case addendum (e.g. canary)."""
    if test_case.system_prompt_addendum:
        return f"{base_prompt}\n\n{test_case.system_prompt_addendum}"
    return base_prompt


def _merge_evaluation(
    deterministic: DeterministicResult,
    llm_eval: EvaluatorResult,
    category: str,
) -> dict:
    """
    Merge deterministic and LLM evaluator results.

    Deterministic rules override when they fire with a definitive result.
    """
    if deterministic.triggered and deterministic.result is not None:
        # Deterministic rule gave a definitive result
        risk_score = calculate_risk_score(
            result=deterministic.result,
            category=category,
            confidence=llm_eval.confidence if llm_eval.confidence > 0 else 0.95,
            deterministic_risk_hint=deterministic.risk_score_hint,
            evaluator_risk_hint=llm_eval.risk_score,
        )
        return {
            "result": deterministic.result,
            "risk_score": risk_score,
            "severity": compute_severity(risk_score),
            "confidence": max(llm_eval.confidence, 0.90),  # deterministic = high confidence
            "needs_review": False,
            "reason": deterministic.reason or llm_eval.reason,
            "evidence": deterministic.evidence or llm_eval.evidence,
        }

    # LLM evaluator result (possibly refined by deterministic hints)
    risk_score = calculate_risk_score(
        result=llm_eval.result,
        category=category,
        confidence=llm_eval.confidence,
        evaluator_risk_hint=llm_eval.risk_score,
        deterministic_risk_hint=deterministic.risk_score_hint,
    )

    return {
        "result": llm_eval.result,
        "risk_score": risk_score,
        "severity": compute_severity(risk_score),
        "confidence": llm_eval.confidence,
        "needs_review": llm_eval.needs_review,
        "reason": llm_eval.reason,
        "evidence": llm_eval.evidence,
    }


async def execute_scan(
    provider: str,
    model: str,
    vulnerability: str,
    attack_technique: str,
    system_prompt: str,
    evaluator_model: str | None = None,
) -> dict:
    """
    Execute a full security scan — the core pipeline.

    Implements bounded retesting: up to MAX_RETEST_ATTEMPTS for INCONCLUSIVE.
    """
    scan_id = str(uuid.uuid4())
    eval_model = evaluator_model or DEFAULT_EVALUATOR_MODEL
    timestamp = datetime.now(timezone.utc).isoformat()

    # Determine mode
    target_demo = is_demo_mode(provider)
    evaluator_demo = is_demo_mode(EVALUATOR_PROVIDER)
    mode = "DEMO" if (target_demo or evaluator_demo) else "REAL"

    final_result = None
    attempts = 0

    for attempt_variant in range(1, MAX_RETEST_ATTEMPTS + 1):
        attempts = attempt_variant

        # 1. Select test case
        test_case = get_test_case(vulnerability, attack_technique, variant=attempt_variant)
        if test_case is None:
            if attempt_variant == 1:
                # No test case at all for this combo
                return _error_response(
                    scan_id=scan_id,
                    mode=mode,
                    provider=provider,
                    model=model,
                    eval_model=eval_model,
                    error=f"No test case found for vulnerability='{vulnerability}', technique='{attack_technique}'.",
                )
            # No more variants available — use last result
            break

        # 2. Prepare system prompt
        prepared_system_prompt = _prepare_system_prompt(system_prompt, test_case)

        # 3. Call target model
        target_response = await _call_target(
            provider_name=provider,
            model=model,
            system_prompt=prepared_system_prompt,
            user_prompt=test_case.prompt,
        )

        if not target_response.success:
            return _error_response(
                scan_id=scan_id,
                mode=mode,
                provider=provider,
                model=model,
                eval_model=eval_model,
                error=f"Target model call failed: {target_response.error}",
            )

        # 4. Deterministic checks
        deterministic = run_deterministic_checks(
            category=vulnerability,
            target_response=target_response.response,
            test_prompt=test_case.prompt,
            system_prompt=prepared_system_prompt,
        )

        # 5. LLM evaluator
        llm_eval = await run_llm_evaluation(
            category=vulnerability,
            technique=attack_technique,
            test_prompt=test_case.prompt,
            target_response=target_response.response,
            expected_behavior=test_case.expected_behavior,
            target_provider=provider,
            evaluator_model=eval_model,
        )

        # 6. Merge results
        merged = _merge_evaluation(deterministic, llm_eval, vulnerability)

        # Build the OWASP mapping
        owasp_entry = get_owasp_for_category(vulnerability)
        owasp_reason = get_owasp_reason(vulnerability, merged["result"])

        # 7. Check for bounded retesting
        if merged["result"] == "PASS":
            # PASS → stop immediately
            final_result = _build_result(
                scan_id=scan_id,
                mode=mode,
                timestamp=timestamp,
                provider=provider,
                model=model,
                eval_model=eval_model,
                test_case=test_case,
                target_response=target_response,
                merged=merged,
                owasp_entry=owasp_entry,
                owasp_reason=owasp_reason,
                attempts=attempts,
            )
            break

        if merged["result"] == "FAIL":
            # FAIL → record finding and stop
            final_result = _build_result(
                scan_id=scan_id,
                mode=mode,
                timestamp=timestamp,
                provider=provider,
                model=model,
                eval_model=eval_model,
                test_case=test_case,
                target_response=target_response,
                merged=merged,
                owasp_entry=owasp_entry,
                owasp_reason=owasp_reason,
                attempts=attempts,
            )
            break

        # INCONCLUSIVE → try next variant (if available)
        final_result = _build_result(
            scan_id=scan_id,
            mode=mode,
            timestamp=timestamp,
            provider=provider,
            model=model,
            eval_model=eval_model,
            test_case=test_case,
            target_response=target_response,
            merged=merged,
            owasp_entry=owasp_entry,
            owasp_reason=owasp_reason,
            attempts=attempts,
        )
        # Continue to next variant...

    if final_result is None:
        return _error_response(
            scan_id=scan_id,
            mode=mode,
            provider=provider,
            model=model,
            eval_model=eval_model,
            error="Scan produced no result.",
        )

    # 8. Calculate integrity across all findings
    all_findings = await get_all_findings()
    # Include current result in calculation
    all_findings.append({
        "result": final_result["result"]["status"],
        "risk_score": final_result["result"]["risk_score"],
        "severity": final_result["result"]["severity"],
    })
    integrity_score = calculate_integrity(all_findings)
    final_result["integrity"] = {"score": integrity_score}

    # 9. Store in database
    await store_scan_result(final_result)

    return final_result


def _build_result(
    scan_id: str,
    mode: str,
    timestamp: str,
    provider: str,
    model: str,
    eval_model: str,
    test_case: TestCase,
    target_response: NormalizedResponse,
    merged: dict,
    owasp_entry,
    owasp_reason: str,
    attempts: int,
) -> dict:
    """Build the structured scan response dict."""
    return {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "mode": mode,
        "target": {"provider": provider.capitalize(), "model": model},
        "evaluator": {"provider": "Groq", "model": eval_model},
        "test": {
            "id": test_case.test_id,
            "vulnerability": test_case.category,
            "technique": test_case.technique,
        },
        "result": {
            "status": merged["result"],
            "risk_score": merged["risk_score"],
            "severity": merged["severity"],
            "confidence": merged["confidence"],
            "needs_review": merged["needs_review"],
        },
        "owasp": {
            "id": owasp_entry.id,
            "name": owasp_entry.name,
            "reason": owasp_reason,
        },
        "evidence": {
            "test_prompt": test_case.prompt,
            "target_response": target_response.response,
            "reasoning": merged["reason"],
            "evidence": merged["evidence"],
        },
        "integrity": {"score": 100.0},  # Will be recalculated
        "attempts": attempts,
    }


def _error_response(
    scan_id: str,
    mode: str,
    provider: str,
    model: str,
    eval_model: str,
    error: str,
) -> dict:
    """Build an error response."""
    return {
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "target": {"provider": provider.capitalize(), "model": model},
        "evaluator": {"provider": "Groq", "model": eval_model},
        "test": {"id": "N/A", "vulnerability": "N/A", "technique": "N/A"},
        "result": {
            "status": "ERROR",
            "risk_score": 0,
            "severity": "LOW",
            "confidence": 0.0,
            "needs_review": True,
        },
        "owasp": {"id": "N/A", "name": "N/A", "reason": error},
        "evidence": {
            "test_prompt": "",
            "target_response": "",
            "reasoning": error,
            "evidence": "",
        },
        "integrity": {"score": 100.0},
        "attempts": 0,
        "error": error,
    }
