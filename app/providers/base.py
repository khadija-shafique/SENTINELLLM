"""
Abstract base for LLM provider adapters.

Every provider must implement `call_model` and normalise its response
into a `NormalizedResponse`.  The security engine never contains
provider-specific logic — it only talks through this interface.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NormalizedResponse:
    """Common response structure returned by every provider adapter."""
    provider: str
    model: str
    response: str
    latency_ms: float
    success: bool
    error: Optional[str] = None
    simulated: bool = False
    mode: str = "REAL"  # REAL | DEMO

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model,
            "response": self.response,
            "latency_ms": self.latency_ms,
            "success": self.success,
            "error": self.error,
            "simulated": self.simulated,
            "mode": self.mode,
        }


class BaseProvider(ABC):
    """Abstract LLM provider adapter."""

    provider_name: str = "base"

    @abstractmethod
    async def call_model(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
    ) -> NormalizedResponse:
        """Send a prompt to the model and return a normalised response."""
        ...


# ---------------------------------------------------------------------------
# Provider registry — allows adding providers without touching the engine
# ---------------------------------------------------------------------------

_PROVIDER_REGISTRY: dict[str, type[BaseProvider]] = {}


def register_provider(name: str):
    """Decorator to register a provider class under a canonical name."""
    def wrapper(cls: type[BaseProvider]):
        _PROVIDER_REGISTRY[name.lower()] = cls
        return cls
    return wrapper


def get_provider(name: str) -> BaseProvider:
    """Instantiate and return a provider by name."""
    key = name.lower()
    if key not in _PROVIDER_REGISTRY:
        raise ValueError(
            f"Unknown provider '{name}'. "
            f"Registered providers: {list(_PROVIDER_REGISTRY.keys())}"
        )
    return _PROVIDER_REGISTRY[key]()
