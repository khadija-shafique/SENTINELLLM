"""
SQLite database operations.

Keeps all database logic separate from API routes.
"""

from __future__ import annotations

import json
import sqlite3
import logging
import asyncio
from typing import Optional
from contextlib import contextmanager

from app.config import DATABASE_PATH
from app.database.models import CREATE_SCAN_RESULTS_TABLE, CREATE_INDICES

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


@contextmanager
def _db():
    conn = _get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_database():
    """Create tables and indices if they don't exist."""
    with _db() as conn:
        conn.execute(CREATE_SCAN_RESULTS_TABLE)
        for idx_sql in CREATE_INDICES:
            conn.execute(idx_sql)
    logger.info(f"Database initialised at {DATABASE_PATH}")


# ---------------------------------------------------------------------------
# CRUD operations (wrapped in asyncio.to_thread for async routes)
# ---------------------------------------------------------------------------

def _store_scan_result_sync(result: dict) -> None:
    """Store a completed scan result."""
    with _db() as conn:
        conn.execute(
            """
            INSERT INTO scan_results (
                scan_id, timestamp, mode,
                target_provider, target_model,
                evaluator_provider, evaluator_model,
                test_id, vulnerability, attack_technique,
                status, risk_score, severity, confidence, needs_review,
                owasp_id, owasp_name, owasp_reason,
                test_prompt, target_response, reasoning, evidence,
                integrity_score, attempts
            ) VALUES (
                ?, ?, ?,
                ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?
            )
            """,
            (
                result["scan_id"],
                result.get("timestamp", ""),
                result["mode"],
                result["target"]["provider"],
                result["target"]["model"],
                result["evaluator"]["provider"],
                result["evaluator"]["model"],
                result["test"]["id"],
                result["test"]["vulnerability"],
                result["test"]["technique"],
                result["result"]["status"],
                result["result"]["risk_score"],
                result["result"]["severity"],
                result["result"]["confidence"],
                1 if result["result"].get("needs_review", False) else 0,
                result["owasp"]["id"],
                result["owasp"]["name"],
                result["owasp"].get("reason", ""),
                result["evidence"]["test_prompt"],
                result["evidence"]["target_response"],
                result["evidence"]["reasoning"],
                result["evidence"]["evidence"],
                result["integrity"]["score"],
                result.get("attempts", 1),
            ),
        )


async def store_scan_result(result: dict) -> None:
    await asyncio.to_thread(_store_scan_result_sync, result)


def _get_all_findings_sync() -> list[dict]:
    """Return minimal finding data for integrity calculation."""
    with _db() as conn:
        rows = conn.execute(
            "SELECT status, risk_score, severity FROM scan_results"
        ).fetchall()

    return [
        {
            "result": r["status"],
            "risk_score": r["risk_score"],
            "severity": r["severity"],
        }
        for r in rows
    ]


async def get_all_findings() -> list[dict]:
    return await asyncio.to_thread(_get_all_findings_sync)
