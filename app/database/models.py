"""
SQLite database models and schema definitions.
"""

from __future__ import annotations

# SQL schema for the scan_results table
CREATE_SCAN_RESULTS_TABLE = """
CREATE TABLE IF NOT EXISTS scan_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT UNIQUE NOT NULL,
    timestamp       TEXT NOT NULL,
    mode            TEXT NOT NULL,

    -- Target
    target_provider TEXT NOT NULL,
    target_model    TEXT NOT NULL,

    -- Evaluator
    evaluator_provider TEXT NOT NULL,
    evaluator_model    TEXT NOT NULL,

    -- Test
    test_id         TEXT NOT NULL,
    vulnerability   TEXT NOT NULL,
    attack_technique TEXT NOT NULL,

    -- Result
    status          TEXT NOT NULL,
    risk_score      INTEGER NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL,
    needs_review    INTEGER NOT NULL DEFAULT 0,

    -- OWASP
    owasp_id        TEXT NOT NULL,
    owasp_name      TEXT NOT NULL,
    owasp_reason    TEXT,

    -- Evidence
    test_prompt     TEXT,
    target_response TEXT,
    reasoning       TEXT,
    evidence        TEXT,

    -- Meta
    integrity_score REAL,
    attempts        INTEGER NOT NULL DEFAULT 1
);
"""

# Indices for common queries
CREATE_INDICES = [
    "CREATE INDEX IF NOT EXISTS idx_scan_vulnerability ON scan_results(vulnerability);",
    "CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_results(status);",
    "CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_results(timestamp);",
]
