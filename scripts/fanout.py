#!/usr/bin/env python3
"""
Minimal multi-agent orchestrator hitting litellm.

Usage:
    ./fanout.py "Find bugs in src/foo.py" --agents 3
    ./fanout.py "Review this code" --perspectives "security,performance,correctness"
"""
import argparse
import asyncio
import os
import httpx

LITELLM_URL = os.environ.get("LITELLM_URL", "http://heft:4000/v1")
LITELLM_KEY = os.environ.get("LITELLM_KEY", "sk-litellm-local")
DEFAULT_MODEL = os.environ.get("LITELLM_MODEL", "ox-alpha")


async def call_agent(client: httpx.AsyncClient, prompt: str, label: str, model: str) -> dict:
    """Single agent call to litellm."""
    resp = await client.post(
        f"{LITELLM_URL}/chat/completions",
        headers={"Authorization": f"Bearer {LITELLM_KEY}"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=300,
    )
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"]
    return {"label": label, "response": content}


async def fanout(prompts: list[tuple[str, str]], model: str) -> list[dict]:
    """Fan out to multiple agents in parallel."""
    async with httpx.AsyncClient() as client:
        tasks = [call_agent(client, prompt, label, model) for label, prompt in prompts]
        return await asyncio.gather(*tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description="Fan out to multiple LLM agents")
    parser.add_argument("task", help="The task to perform")
    parser.add_argument("--agents", "-n", type=int, default=3, help="Number of parallel agents")
    parser.add_argument("--perspectives", "-p", help="Comma-separated perspectives (overrides --agents)")
    parser.add_argument("--model", "-m", default=DEFAULT_MODEL, help="Model to use")
    args = parser.parse_args()

    if args.perspectives:
        perspectives = [p.strip() for p in args.perspectives.split(",")]
        prompts = [
            (p, f"You are reviewing from a {p} perspective.\n\nTask: {args.task}")
            for p in perspectives
        ]
    else:
        prompts = [
            (f"agent-{i}", args.task)
            for i in range(args.agents)
        ]

    print(f"Fanning out to {len(prompts)} agents on {args.model}...\n")
    results = asyncio.run(fanout(prompts, args.model))

    for r in results:
        if isinstance(r, Exception):
            print(f"ERROR: {r}\n")
        else:
            print(f"=== {r['label']} ===")
            print(r["response"])
            print()


if __name__ == "__main__":
    main()
