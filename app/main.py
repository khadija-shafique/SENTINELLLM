"""
SentinelLLM — FastAPI Application Entry Point.

AI Red Teaming and LLM Security Assessment Platform.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import ALLOWED_ORIGINS
from app.database.database import init_database

# Import provider modules to trigger registration
import app.providers.gemini  # noqa: F401
import app.providers.groq    # noqa: F401

# Import route modules
from app.api.routes_scan import router as scan_router
from app.api.routes_models import router as models_router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("sentinellm")


# ---------------------------------------------------------------------------
# Lifespan (startup / shutdown)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("SentinelLLM starting up...")
    init_database()
    logger.info("Database initialised.")

    from app.config import GEMINI_API_KEY, GROQ_API_KEY
    if not GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set — Gemini targets run in DEMO mode.")
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY not set — Groq targets and evaluator run in DEMO mode.")

    yield

    # Shutdown
    logger.info("SentinelLLM shutting down.")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SentinelLLM",
    description=(
        "AI Red Teaming & LLM Security Assessment Platform.\n\n"
        "Tests target LLMs against controlled security test cases across "
        "four vulnerability categories: Prompt Injection, Jailbreak Resistance, "
        "System Prompt Leakage, and Sensitive Information Disclosure.\n\n"
        "**Evaluator is locked to Groq.** Target models can be Gemini or Groq."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — origins set via ALLOWED_ORIGINS env var (default "*" for local dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Mount routers
# ---------------------------------------------------------------------------

app.include_router(models_router)
app.include_router(scan_router)
