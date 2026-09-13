"""
Pydantic v2 schemas for scan requests and responses.
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional


# ---------------------------------------------------------------------------
# Sub-models used in the scan response
# ---------------------------------------------------------------------------

class TargetInfo(BaseModel):
    provider: str
    model: str


class EvaluatorInfo(BaseModel):
    provider: str
    model: str


class TestInfo(BaseModel):
    id: str
    vulnerability: str
    technique: str


class ResultInfo(BaseModel):
    status: str  # PASS | FAIL | INCONCLUSIVE
    risk_score: int = Field(ge=0, le=100)
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float = Field(ge=0.0, le=1.0)
    needs_review: bool = False


class OWASPInfo(BaseModel):
    id: str
    name: str
    reason: str


class EvidenceInfo(BaseModel):
    test_prompt: str
    target_response: str
    reasoning: str
    evidence: str


class IntegrityInfo(BaseModel):
    score: float


# ---------------------------------------------------------------------------
# Scan Request
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Request body for POST /scan."""
    provider: str = "gemini"
    model: str = "gemini-3.5-flash"
    evaluator_provider: Optional[str] = "groq"
    evaluator_model: Optional[str] = None
    vulnerability: str
    attack_technique: str
    system_prompt: Optional[str] = Field(
        default="You are a helpful AI assistant.",
        description="The system prompt to configure the target LLM with."
    )


# ---------------------------------------------------------------------------
# Scan Response
# ---------------------------------------------------------------------------

class ScanResponse(BaseModel):
    """Stable JSON contract for a completed scan."""
    scan_id: str
    timestamp: Optional[str] = None
    mode: str  # REAL | DEMO
    target: TargetInfo
    evaluator: EvaluatorInfo
    test: TestInfo
    result: ResultInfo
    owasp: OWASPInfo
    evidence: EvidenceInfo
    integrity: IntegrityInfo
    attempts: int = 1


# ---------------------------------------------------------------------------
# Evaluate Request (standalone evaluator endpoint)
# ---------------------------------------------------------------------------

class EvaluateRequest(BaseModel):
    """Request body for POST /evaluate — run evaluator on already-collected data."""
    vulnerability: str
    attack_technique: str
    test_prompt: str
    target_response: str
    expected_behavior: str


class EvaluateResponse(BaseModel):
    result: str
    risk_score: int
    severity: str
    reason: str
    evidence: str
    confidence: float
    needs_review: bool
