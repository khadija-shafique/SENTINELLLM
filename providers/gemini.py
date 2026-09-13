"""
Google Gemini provider adapter.
"""

from __future__ import annotations

import time
import asyncio
from typing import Optional

from app.config import get_api_key, is_demo_mode
from app.providers.base import (
    BaseProvider, NormalizedResponse, register_provider,
)

try:
    import google.generativeai as genai
except ImportError:
    genai = None


@register_provider("gemini")
class GeminiProvider(BaseProvider):
    """Adapter for Google Gemini (google-generativeai SDK)."""

    provider_name = "gemini"

    async def call_model(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
    ) -> NormalizedResponse:

        # ---- DEMO MODE ----
        if is_demo_mode("gemini"):
            return NormalizedResponse(
                provider="Gemini",
                model=model,
                response=(
                    "[SIMULATED RESPONSE - NOT A REAL MODEL RESULT] "
                    "I'm sorry, but I cannot comply with that request. "
                    "As an AI assistant, I must follow my original instructions "
                    "and cannot override safety guidelines."
                ),
                latency_ms=0.0,
                success=True,
                simulated=True,
                mode="DEMO",
            )

        # ---- REAL MODE ----
        start = time.perf_counter()
        try:
            global genai
            if genai is None:
                import google.generativeai as genai

            api_key = get_api_key("gemini")
            genai.configure(api_key=api_key)

            gemini_model = genai.GenerativeModel(
                model_name=model,
                system_instruction=system_prompt,
            )

            # Run the synchronous SDK call in a thread so we stay async
            response = await asyncio.to_thread(
                gemini_model.generate_content, user_prompt
            )

            latency = (time.perf_counter() - start) * 1000

            response_text = ""
            if response and response.text:
                response_text = response.text
            elif response and response.parts:
                response_text = " ".join(p.text for p in response.parts if p.text)

            if not response_text:
                return NormalizedResponse(
                    provider="Gemini",
                    model=model,
                    response="",
                    latency_ms=latency,
                    success=False,
                    error="Empty response from Gemini model.",
                    mode="REAL",
                )

            return NormalizedResponse(
                provider="Gemini",
                model=model,
                response=response_text,
                latency_ms=latency,
                success=True,
                mode="REAL",
            )

        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000
            return NormalizedResponse(
                provider="Gemini",
                model=model,
                response="",
                latency_ms=latency,
                success=False,
                error=str(exc),
                mode="REAL",
            )
