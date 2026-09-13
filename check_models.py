"""
One-off diagnostic: probe every configured Gemini / Groq(Llama) model
through the real provider adapters and report reachability.
"""

import asyncio
import sys

sys.path.insert(0, r"d:\backendcorrect\backend1")

from app.config import PROVIDERS
from app.providers.gemini import GeminiProvider
from app.providers.groq import GroqProvider

PROBE_SYSTEM = "You are a connectivity probe. Answer tersely."
PROBE_USER = "Reply with exactly the word: PONG"


async def main() -> None:
    providers = {"gemini": GeminiProvider(), "groq": GroqProvider()}
    rows = []

    for pname, models in PROVIDERS.items():
        provider = providers[pname]
        for model in models:
            try:
                r = await asyncio.wait_for(
                    provider.call_model(model, PROBE_SYSTEM, PROBE_USER),
                    timeout=90,
                )
                rows.append((
                    pname, model, r.mode, r.success, r.simulated,
                    round(r.latency_ms, 0), r.error, (r.response or "")[:80],
                ))
            except Exception as exc:
                rows.append((
                    pname, model, "TIMEOUT/CRASH", False, False,
                    None, f"{type(exc).__name__}: {exc}", "",
                ))

    print("=" * 78)
    print("MODEL CONNECTIVITY REPORT  (target = Gemini, target = Groq/Llama)")
    print("=" * 78)
    for pname, model, mode, ok, sim, lat, err, reply in rows:
        if sim:
            verdict = "DEMO-MODE (no real call)"
        elif ok:
            verdict = "WORKING"
        else:
            verdict = "FAILED"
        print(f"\n[{verdict}] {pname} :: {model}")
        print(f"    mode={mode}  simulated={sim}  latency={lat} ms")
        if reply:
            print(f"    reply: {reply!r}")
        if err:
            print(f"    error: {err}")
    print("\n" + "=" * 78)
    working = sum(1 for r in rows if r[3] and not r[4])
    print(f"SUMMARY: {working}/{len(rows)} models reachable in REAL mode")
    print("=" * 78)


if __name__ == "__main__":
    asyncio.run(main())
