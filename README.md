# Security RAG: reproducible synthetic security investigation

[![Validate synthetic investigation](https://github.com/Josh-Shultis/security-rag-demo/actions/workflows/validate.yml/badge.svg)](https://github.com/Josh-Shultis/security-rag-demo/actions/workflows/validate.yml)

This is a public, offline demo of how I work a security case from a precise question to the decisive artifact, a control, and a fix. It uses a deliberately vulnerable in-memory mock and synthetic evidence so the full chain can be reviewed without exposing private vendor material.

## What this demonstrates

- A controlled security test with one clear question.
- A vulnerable path and a fixed control using the same note and requester.
- Evidence traced back to exact source files, SHA-256 values, artifact IDs, and chunk IDs.
- Regression tests that verify the vulnerable and fixed behavior.
- A local workflow that runs without a model, API key, vendor account, or network connection.

The point of the demo is not the mock bug itself. The point is to make the investigation reviewable end to end.

## Try it in five minutes

Requires Python 3.11+ and Git.

```text
git clone https://github.com/Josh-Shultis/security-rag-demo.git
cd security-rag-demo
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m security_rag.investigation
```

Linux or macOS:

```sh
.venv/bin/python -m pip install -e .
.venv/bin/python -m security_rag.investigation
```

The investigation prints the decisive fixture, its full SHA-256, the indexed artifact ID, the retrieved chunk ID, the controls, and the final narrow conclusion.

To run the separate retrieval smoke demo and tests:

```powershell
.\.venv\Scripts\python.exe -m security_rag.demo
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
.\.venv\Scripts\python.exe -m pytest -q
```

On Linux or macOS, replace `.\.venv\Scripts\python.exe` with `.venv/bin/python`. The demos use temporary data roots and do not touch an existing `SECURITY_RAG_ROOT`.

## The investigation

**Question:** Can simulated Account A read Account B's owner-only note by guessing its ID?

The [case study](docs/CASE-STUDY.md) walks through the role, request, vulnerable operation, result, fixed control, source files, and conclusion.

The decisive artifact is [`03_vulnerable_response.json`](src/security_rag/fixtures/SYNTH-001/03_vulnerable_response.json). The runner regenerates the result from the mock, checks it against the tracked fixture, ingests the evidence, retrieves the synthetic canary, and verifies that the indexed result points back to the same source bytes.

That produces a review path like this:

```text
security question
    -> controlled request
    -> observed response
    -> source artifact
    -> SHA-256 / artifact ID / chunk ID
    -> fixed control
    -> regression test
```

## What to review in the code

| Area | Where to review |
| --- | --- |
| Deliberate ownership bug and fixed control | [`mock_notes.py`](src/security_rag/mock_notes.py) |
| Fixture verification, ingestion, retrieval, and source-hash check | [`investigation.py`](src/security_rag/investigation.py) |
| Case-scoped search and source-linked indexing | [`store.py`](src/security_rag/store.py) |
| Redaction rules and safe path handling | [`security.py`](src/security_rag/security.py) |
| Offline and regression checks | [`tests/`](tests/) |

## Walkthrough

[Watch the three-minute walkthrough](media/walkthrough.mp4).

The narration script and exact scene timings are in [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md). The script is written in first person so I can record a replacement narration in my own voice without changing the technical content.

## Scope

This repository is a curated public export. The case is synthetic and the vulnerable service is a local mock. It does not represent a finding in a real product.

The original Security RAG project and private research evidence remain private. No raw Burp or HAR captures, authenticated sessions, or vendor report material belong in this repository.

The retrieval engine is a single-user research tool. Case filters are retrieval controls, not multi-user authorization. Its `semantic` mode uses sparse local term weights rather than a neural embedding model.

## Authorship

I developed the private Security RAG project as part of my research workflow. Codex assisted with parts of this public export, the mock investigation, tests, documentation, and walkthrough. The security question, evidence standard, case framing, and final conclusions are decisions I can explain and defend independently.

The [release review](docs/RELEASE-REVIEW.md) records the checks performed before publication.

MIT licensed. Runtime code uses the Python standard library; `pytest` is an optional test dependency.
