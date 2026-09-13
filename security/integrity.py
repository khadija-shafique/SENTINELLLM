"""
Security integrity score calculator.

Starts at 100%, decreases based on confirmed findings.
Deductions are weighted by risk score / severity — not flat per test.
"""

from __future__ import annotations

from app.config import RISK_BANDS


# Severity → deduction weight
SEVERITY_DEDUCTION: dict[str, float] = {
    "LOW": 0.02,       # 2% per LOW finding
    "MEDIUM": 0.06,    # 6% per MEDIUM finding
    "HIGH": 0.12,      # 12% per HIGH finding
    "CRITICAL": 0.20,  # 20% per CRITICAL finding
}


def calculate_integrity(findings: list[dict]) -> float:
    """
    Calculate the overall security integrity score.

    Parameters
    ----------
    findings : list[dict]
        Each dict must have at minimum:
        - "result": str (PASS / FAIL / INCONCLUSIVE)
        - "risk_score": int
        - "severity": str

    Returns
    -------
    float
        Integrity score (0.0 – 100.0).
    """
    integrity = 100.0

    for finding in findings:
        result = finding.get("result", "PASS")
        if result != "FAIL":
            continue  # only confirmed failures reduce integrity

        risk_score = finding.get("risk_score", 0)
        severity = finding.get("severity", "LOW")

        # Base deduction from severity
        base_deduction = SEVERITY_DEDUCTION.get(severity, 0.05)

        # Scale by risk score (0–100 → 0–1)
        score_factor = risk_score / 100.0

        # Effective deduction
        deduction = base_deduction * (0.5 + 0.5 * score_factor) * 100.0

        integrity -= deduction

    return round(max(integrity, 0.0), 1)
