# Security RAG: one synthetic investigation

An offline, reproducible example of how I link a security conclusion to source evidence. It uses a deliberately vulnerable **in-memory mock**, six supplied synthetic artifacts, and a focused export of my private Security RAG retrieval code. It is a demonstration of investigation and engineering, **not a report about a real product**.

## Try it in five minutes

Requires Python 3.11+ and Git. The case runs without a model, API key, vendor account, or network connection. Installation may download the Python build tools.

```text
git clone https://github.com/Josh-Shultis/security-rag-demo.git
cd security-rag-demo
python -m venv .venv
```

Then use the new environment's Python. On Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m security_rag.investigation
```

On Linux or macOS:

```sh
.venv/bin/python -m pip install -e .
.venv/bin/python -m security_rag.investigation
```

The output names the decisive fixture, its full SHA-256, the indexed artifact ID, and the retrieved chunk ID. It also prints the negative controls and what the case cannot establish. To run the separate two-case retrieval smoke demo and tests:

```powershell
.\.venv\Scripts\python.exe -m security_rag.demo
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
.\.venv\Scripts\python.exe -m pytest -q
```

On Linux or macOS, replace `.\.venv\Scripts\python.exe` with `.venv/bin/python`. Both demos create and remove temporary data roots. They do not use an existing `SECURITY_RAG_ROOT`.

## The investigation

**Question:** Can simulated Account A read Account B's owner-only note by guessing its ID?

The [case study](docs/CASE-STUDY.md) walks through the role, request, mock operation, result, fixed control, source files, and limits. The [six fixtures](src/security_rag/fixtures/SYNTH-001/) are checked against the mock's actual output before indexing. The decisive artifact is [`03_vulnerable_response.json`](src/security_rag/fixtures/SYNTH-001/03_vulnerable_response.json). The retrieval result traces its content to its source bytes. A source hash proves byte identity within this demo; it does not prove a real application's behavior or an artifact's authority.

## What the code shows

| Area | Where to review |
| --- | --- |
| Deliberate ownership bug and fixed control | [`mock_notes.py`](src/security_rag/mock_notes.py) |
| Fixture verification, ingestion, retrieval, and source hash check | [`investigation.py`](src/security_rag/investigation.py) |
| Case-scoped search and source-linked indexing | [`store.py`](src/security_rag/store.py) |
| Redaction rules and safe path handling | [`security.py`](src/security_rag/security.py) |
| Offline and regression checks | [`tests/`](tests/) |

The original Security RAG engine is a single-user research prototype. Case filters are retrieval controls, not multi-user authorization. Its `semantic` mode uses sparse local term weights, not a neural embedding model or corpus-wide IDF. The exported engine contains optional local-model functions, but this investigation does not call them. Do not expose its storage or API as a multi-user service.

## Walkthrough

[Watch the three-minute narrated walkthrough](media/walkthrough.mp4). The narration script and exact scene timings are in [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md).

## Release scope and authorship

This is a **new, curated Git history** containing only selected engine source files, synthetic fixtures, tests, documentation, and the walkthrough. The private research repository and its history remain private. No raw Burp/HAR captures or real case evidence belong in this Git repository; keep originals in a dedicated local directory outside every Git checkout.

The retrieval engine was developed in Josh's private Security RAG project. Codex assisted with this public export, mock investigation, tests, documentation, and walkthrough. Earlier AI assistance on the private engine was not independently inventoried. The [release review](docs/RELEASE-REVIEW.md) records the checks and their limits.

The code is MIT licensed. Runtime code in this demo uses the Python standard library; `pytest` is an optional test dependency.
