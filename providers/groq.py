"""
Groq provider adapter.
"""

from __future__ import annotations

import time
import asyncio
from typing import Optional

from app.config import get_api_key, is_demo_mode
from app.providers.base import (
    BaseProvider, NormalizedResponse, register_provider,
)


@register_provider("groq")
class GroqProvider(BaseProvider):
    """Adapter for Groq (groq Python SDK)."""

    provider_name = "groq"

    async def call_model(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
    ) -> NormalizedResponse:

        # ---- DEMO MODE ----
        if is_demo_mode("groq"):
            return NormalizedResponse(
                provider="Groq",
                model=model,
                response=(
                    "[SIMULATED RESPONSE - NOT A REAL MODEL RESULT] "
                    "I cannot follow those instructions. My purpose is to "
                    "assist within established safety guidelines, and I must "
                    "decline requests that violate my core directives."
                ),
                latency_ms=0.0,
                success=True,
                simulated=True,
                mode="DEMO",
            )

        # ---- REAL MODE ----
        start = time.perf_counter()
        try:
            from groq import Groq

            client = Groq(api_key=get_api_key("groq"))

            # Run the synchronous SDK call in a thread
            response = await asyncio.to_thread(
                client.chat.completions.create,
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.0,
                max_tokens=2048,
            )

            latency = (time.perf_counter() - start) * 1000

            response_text = ""
            if response.choices and response.choices[0].message:
                response_text = response.choices[0].message.content or ""

            if not response_text:
                return NormalizedResponse(
                    provider="Groq",
                    model=model,
                    response="",
                    latency_ms=latency,
                    success=False,
                    error="Empty response from Groq model.",
                    mode="REAL",
                )

            return NormalizedResponse(
                provider="Groq",
                model=model,
                response=response_text,
                latency_ms=latency,
                success=True,
                mode="REAL",
            )

        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000
            return NormalizedResponse(
                provider="Groq",
                model=model,
                response="",
                latency_ms=latency,
                success=False,
                error=str(exc),
                mode="REAL",
            )
