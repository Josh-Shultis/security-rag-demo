"""Reproduce and index a supplied synthetic case; no network or real evidence."""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from . import store
from .mock_notes import scenario


CASE_ID = "SYNTH-001"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / CASE_ID


@contextmanager
def isolated_root(root: Path):
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


def run() -> dict:
    expected = scenario()
    with TemporaryDirectory(prefix="security-rag-synth-") as directory:
        root = Path(directory).resolve()
        with isolated_root(root):
            store.init_project(root)
            store.init_case(CASE_ID, vendor="Synthetic Lab", product="Mock Notes")
            evidence_dir = root / "cases" / CASE_ID / "notes"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            references = []
            for name, result in sorted(expected.items()):
                fixture = FIXTURE_DIR / name
                if not fixture.is_file() or json.loads(fixture.read_text(encoding="utf-8")) != result:
                    raise RuntimeError(f"Fixture differs from mock service: {name}")
                copied = evidence_dir / name
                copied.write_bytes(fixture.read_bytes())
                item = store.ingest_path(str(copied), CASE_ID)[0]
                if item["status"] != "ingested":
                    raise RuntimeError(f"Ingestion failed: {name}")
                digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
                if item["sha256"] != digest:
                    raise RuntimeError(f"Source hash mismatch: {name}")
                references.append({"source": f"src/security_rag/fixtures/{CASE_ID}/{name}", "sha256": digest, "artifact_id": item["artifact_id"]})

            hits = store.search("SYNTH-CANARY-B-7", case_id=CASE_ID, mode="exact")
            response_hits = [row for row in hits if row["source_file"] == "03_vulnerable_response.json"]
            if not response_hits:
                raise RuntimeError("RAG failed to retrieve the decisive response")
            hit = response_hits[0]
            response_ref = next(item for item in references if item["source"].endswith("03_vulnerable_response.json"))
            if hit["sha256"] != response_ref["sha256"] or hit["artifact_id"] != response_ref["artifact_id"]:
                raise RuntimeError("RAG source reference mismatch")
            if "SYNTH-CANARY-B-7" not in hit["content"]:
                raise RuntimeError("Retrieved chunk lacks the simulated private value")
            if expected["03_vulnerable_response.json"]["status"] != 200:
                raise RuntimeError("Vulnerable response changed")
            if expected["04_fixed_response.json"]["status"] != 403:
                raise RuntimeError("Fixed response changed")
            if expected["05_owner_control.json"]["status"] != 200:
                raise RuntimeError("Owner control changed")
            if expected["06_missing_note_control.json"]["status"] != 404:
                raise RuntimeError("Missing-note control changed")

            return {
                "case_id": CASE_ID,
                "scope": "deliberately vulnerable in-memory mock; no real service or accounts",
                "question": "Can simulated Account A read Account B's owner-only note by ID?",
                "conclusion": "In this mock, the vulnerable read returns Account B's canary to Account A; the fixed read returns 403.",
                "decisive_retrieval": {"source": response_ref["source"], "sha256": hit["sha256"], "artifact_id": hit["artifact_id"], "chunk_id": hit["chunk_id"]},
                "source_artifacts": references,
                "negative_results": {"fixed_cross_account_read": 403, "missing_note": 404},
                "not_proven": ["a vulnerability in any real product", "real account identity or ACL behavior", "source authenticity beyond supplied fixture bytes"],
            }


def main() -> int:
    print(json.dumps(run(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
