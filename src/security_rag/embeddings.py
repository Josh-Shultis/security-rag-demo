from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from collections import Counter
from dataclasses import dataclass

TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")
DEFAULT_BACKEND = "local-tfidf"
DEFAULT_MODEL = "security-rag-local-tfidf-v1"
DEFAULT_VERSION = "1"


@dataclass(frozen=True)
class EmbeddingConfig:
    backend: str
    model: str
    device: str
    version: str
    dimension: int


def embedding_config() -> EmbeddingConfig:
    backend = os.environ.get("EMBEDDING_BACKEND", DEFAULT_BACKEND)
    model = os.environ.get("EMBEDDING_MODEL", DEFAULT_MODEL)
    device = os.environ.get("EMBEDDING_DEVICE", "cpu")
    version = os.environ.get("EMBEDDING_VERSION", DEFAULT_VERSION)
    # local-tfidf stores sparse token weights, so dimension is variable.
    dimension = -1 if backend == "local-tfidf" else int(os.environ.get("EMBEDDING_DIMENSION", "0") or 0)
    return EmbeddingConfig(backend, model, device, version, dimension)


def tokenize(text: str) -> list[str]:
    return [t.lower() for t in TOKEN_RE.findall(text)]


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def embed(text: str, cfg: EmbeddingConfig | None = None) -> dict[str, float]:
    cfg = cfg or embedding_config()
    if cfg.backend != "local-tfidf":
        raise RuntimeError(
            f"embedding backend {cfg.backend!r} is not installed/configured. "
            "Current dependency-free backend is local-tfidf."
        )
    counts: Counter[str] = Counter(tokenize(text))
    if not counts:
        return {}
    # Sublinear local TF weighting. IDF is intentionally not baked into stored vectors
    # so ranking can be recomputed deterministically as the case corpus changes.
    weighted = {token: 1.0 + math.log(count) for token, count in counts.items()}
    norm = math.sqrt(sum(v * v for v in weighted.values())) or 1.0
    return {token: value / norm for token, value in weighted.items()}


def dumps(vector: dict[str, float]) -> str:
    return json.dumps(vector, sort_keys=True, separators=(",", ":"))


def loads(raw: str) -> dict[str, float]:
    return {str(k): float(v) for k, v in json.loads(raw).items()}


def cosine(a: dict[str, float], b: dict[str, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(v * b.get(k, 0.0) for k, v in a.items())


def timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())