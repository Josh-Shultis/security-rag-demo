"""Offline, synthetic evidence demo. Run in a standalone process, not a server."""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from . import store


@contextmanager
def demo_environment(root: Path):
    # These settings are process-global. Never run this inside a live web worker.
    overrides = {"SECURITY_RAG_ROOT": str(root), "EMBEDDING_BACKEND": "local-tfidf"}
    previous = {key: os.environ.get(key) for key in overrides}
    try:
        os.environ.update(overrides)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def require(condition: bool, message: str) -> None:
    # Keep checks active even when Python is run with -O.
    if not condition:
        raise RuntimeError(f"Synthetic demo check failed: {message}")


def run_demo() -> dict:
    """Create only synthetic files in a fresh temporary root, then remove it."""
    with TemporaryDirectory(prefix="security-rag-demo-") as directory:
        root = Path(directory).resolve()
        with demo_environment(root):
            store.init_project(root)
            sources = {}
            ingested = {}
            for case, label in (("DEMO-A", "ALPHA-ONLY"), ("DEMO-B", "BRAVO-ONLY")):
                store.init_case(case, vendor="Example Lab", product="Synthetic Notes")
                source = root / "cases" / case / "raw" / "observation.txt"
                source.write_text(
                    "Synthetic observation; not a vendor finding.\n"
                    "2026-01-01T00:00:01Z DEMO-NOTE-001 recorded in a local fixture.\n"
                    f"case label: {label}\n"
                    "The identifier alone does not establish a relationship between cases.\n",
                    encoding="utf-8",
                )
                sources[case] = (source, hashlib.sha256(source.read_bytes()).hexdigest())
                ingested[case] = store.ingest_path(str(source), case)[0]
                require(ingested[case]["status"] == "ingested", "first ingestion")

            source_a, _ = sources["DEMO-A"]
            before = store.search("DEMO-NOTE-001", case_id="DEMO-A", mode="exact")
            repeated = store.ingest_path(str(source_a), "DEMO-A")[0]
            after = store.search("DEMO-NOTE-001", case_id="DEMO-A", mode="exact")
            require(repeated["status"] == "duplicate", "duplicate recognized")
            require(repeated["artifact_id"] == ingested["DEMO-A"]["artifact_id"], "artifact reused")
            require([r["chunk_id"] for r in before] == [r["chunk_id"] for r in after], "no duplicate search rows")

            evidence = []
            for case, (source, digest) in sources.items():
                require(hashlib.sha256(source.read_bytes()).hexdigest() == digest, "source unchanged")
                for mode in ("exact", "semantic", "hybrid"):
                    rows = store.search("DEMO-NOTE-001", case_id=case, mode=mode)
                    require(bool(rows), f"{mode} returned evidence")
                    require(all(row["case_id"] == case for row in rows), f"{mode} case scope")
                row = rows[0]
                require(row["artifact_id"] == ingested[case]["artifact_id"], "source artifact link")
                require(row["sha256"] == digest, "source hash link")
                require(bool(row["chunk_id"]) and row["source_path"] == str(source), "chunk source link")
                evidence.append({
                    "case_id": case,
                    "artifact_id": row["artifact_id"],
                    "chunk_id": row["chunk_id"],
                    "sha256": digest,
                    "source": source.relative_to(root).as_posix(),
                })

            both = store.search("DEMO-NOTE-001", all_cases=True)
            require({row["case_id"] for row in both} == set(sources), "explicit cross-case retrieval")
            context = store.context_packet("DEMO-NOTE-001", "DEMO-A")
            require("UNTRUSTED RETRIEVED EVIDENCE" in context, "context labels evidence untrusted")
            require("ALPHA-ONLY" in context and "BRAVO-ONLY" not in context, "context case scope")
            return {
                "dataset": "synthetic-only",
                "model_required": False,
                "checks": {
                    "source_bytes_unchanged": True,
                    "duplicate_ingestion_reuses_artifact_and_chunks": True,
                    "case_scoping_in_all_three_search_modes": True,
                    "explicit_cross_case_search": True,
                    "source_artifact_chunk_hash_links": True,
                    "untrusted_context_label_and_scope": True,
                },
                "evidence": evidence,
                "limitations": "Smoke checks, not an LLM safety evaluation or proof of a vulnerability.",
            }


def main() -> int:
    print(json.dumps(run_demo(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
