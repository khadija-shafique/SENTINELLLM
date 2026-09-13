"""
OWASP Top 10 for LLM Applications mapping.

Maintains a centralized, easily updated taxonomy.  SentinelLLM uses these
IDs for *classification only* — the PASS/FAIL rules and risk formula are
defined by SentinelLLM's own evaluation engine, not by OWASP.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OWASPEntry:
    id: str
    name: str
    description: str


# ---------------------------------------------------------------------------
# OWASP Top 10 for LLM Applications (2025 revision)
# ---------------------------------------------------------------------------

OWASP_MAP: dict[str, OWASPEntry] = {
    "LLM01": OWASPEntry(
        id="LLM01",
        name="Prompt Injection",
        description=(
            "Manipulating LLMs via crafted inputs to override intended "
            "instructions, potentially causing unauthorized actions or "
            "data exposure."
        ),
    ),
    "LLM02": OWASPEntry(
        id="LLM02",
        name="Sensitive Information Disclosure",
        description=(
            "Unintended revelation of confidential data through LLM "
            "outputs, risking privacy violations and security breaches."
        ),
    ),
    "LLM03": OWASPEntry(
        id="LLM03",
        name="Supply Chain Vulnerabilities",
        description=(
            "Risks from compromised components, services, or datasets "
            "in LLM supply chains, affecting system integrity."
        ),
    ),
    "LLM04": OWASPEntry(
        id="LLM04",
        name="Data and Model Poisoning",
        description=(
            "Manipulating training or fine-tuning data to introduce "
            "vulnerabilities, biases, or backdoors into the model."
        ),
    ),
    "LLM05": OWASPEntry(
        id="LLM05",
        name="Improper Output Handling",
        description=(
            "Insufficient validation of LLM outputs leading to "
            "downstream security issues like XSS, SSRF, or code execution."
        ),
    ),
    "LLM06": OWASPEntry(
        id="LLM06",
        name="Excessive Agency",
        description=(
            "Granting LLMs too much autonomy or access to sensitive "
            "functions, enabling unintended harmful actions."
        ),
    ),
    "LLM07": OWASPEntry(
        id="LLM07",
        name="System Prompt Leakage",
        description=(
            "Risk of revealing confidential system-level instructions, "
            "configuration, or policies embedded in the LLM's prompt."
        ),
    ),
    "LLM08": OWASPEntry(
        id="LLM08",
        name="Vector and Embedding Weaknesses",
        description=(
            "Vulnerabilities in RAG vector stores and embedding pipelines "
            "that can be exploited to inject or retrieve unauthorized data."
        ),
    ),
    "LLM09": OWASPEntry(
        id="LLM09",
        name="Misinformation",
        description=(
            "LLMs generating false or misleading content that can cause "
            "harm, erode trust, or enable social engineering."
        ),
    ),
    "LLM10": OWASPEntry(
        id="LLM10",
        name="Unbounded Consumption",
        description=(
            "LLMs consuming excessive resources or costs due to "
            "unrestricted queries, leading to denial of service."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Category → OWASP mapping
# ---------------------------------------------------------------------------

CATEGORY_OWASP_MAP: dict[str, str] = {
    "Prompt Injection": "LLM01",
    "Jailbreak Resistance": "LLM09",
    "System Prompt Leakage": "LLM07",
    "Sensitive Information Disclosure": "LLM02",
}


def get_owasp_for_category(category: str) -> OWASPEntry:
    """Look up the OWASP entry for a vulnerability category."""
    owasp_id = CATEGORY_OWASP_MAP.get(category, "LLM01")
    return OWASP_MAP.get(owasp_id, OWASP_MAP["LLM01"])


def get_owasp_by_id(owasp_id: str) -> OWASPEntry | None:
    """Look up an OWASP entry by its ID."""
    return OWASP_MAP.get(owasp_id)


def get_owasp_reason(category: str, result: str) -> str:
    """Generate a human-readable OWASP mapping reason."""
    entry = get_owasp_for_category(category)
    if result == "PASS":
        return (
            f"Tested against {entry.id} ({entry.name}). "
            f"The target model successfully resisted this attack vector."
        )
    elif result == "FAIL":
        return (
            f"Finding maps to {entry.id} ({entry.name}). "
            f"{entry.description}"
        )
    else:
        return (
            f"Tested against {entry.id} ({entry.name}). "
            f"Result is inconclusive — additional review recommended."
        )
