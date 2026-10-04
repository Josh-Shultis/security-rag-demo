from __future__ import annotations

import json
import os
import time
import urllib.request

ALLOWED_LOCAL_TASKS = {
    "extraction",
    "tagging",
    "summarization",
    "artifact classification",
    "timeline assistance",
    "duplicate detection",
    "simple code analysis",
    "grounded question answering",
    "broad evidence triage",
    "corpus evidence scan",
    "corpus scan synthesis",
}

OPTIONAL_CLOUD_TASKS = {
    "deep vulnerability reasoning",
    "severity analysis",
    "report review",
    "proof-gap analysis",
}


def local_llm_available() -> bool:
    return bool(os.environ.get("LOCAL_LLM_MODEL"))


def run_local_task(
    task: str,
    prompt: str,
    *,
    system: str = "",
    temperature: float = 0,
    max_tokens: int | None = None,
    timeout: int | None = None,
    retries: int = 1,
) -> str:
    if task not in ALLOWED_LOCAL_TASKS:
        raise ValueError("task is not approved for local model routing")
    model = os.environ.get("LOCAL_LLM_MODEL", "")
    if not model:
        raise RuntimeError("LOCAL_LLM_MODEL is not configured")
    base = os.environ.get("LOCAL_LLM_BASE_URL", "http://127.0.0.1:8080/v1").rstrip("/")
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload = {"model": model, "messages": messages, "temperature": temperature}
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    body = json.dumps(payload).encode()
    req_timeout = timeout or int(os.environ.get("LOCAL_LLM_TIMEOUT", "120"))
    max_attempts = max(1, retries + 1)
    last_error: Exception | None = None
    for attempt in range(max_attempts):
        req = urllib.request.Request(f"{base}/chat/completions", data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=req_timeout) as resp:
                data = json.loads(resp.read().decode())
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            last_error = exc
            if attempt + 1 < max_attempts:
                time.sleep(0.5 * (attempt + 1))
    raise RuntimeError(f"local model call failed after {max_attempts} attempt(s): {last_error}")


def cloud_enabled() -> bool:
    return os.environ.get("SECURITY_RAG_CLOUD_ENABLED", "false").lower() == "true"
