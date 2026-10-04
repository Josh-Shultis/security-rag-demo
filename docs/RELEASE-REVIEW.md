# Public release review

Reviewed on 2026-10-04 (America/Denver). This review covers **this clean export**, not permission to expose the private Security RAG repository.

## Git history and scope

- Source: selected `app/security_rag` files from private `security-rag` branch `hardening-v1` at `f42daba538d4fd2e08a11ed68ebafacbf186626f`.
- Public destination: new `security-rag-demo` repository with a fresh history. No private commit, branch, tag, or full repository snapshot is included.
- Added for this release: the in-memory mock, synthetic fixtures, investigation runner, focused tests, case study, walkthrough, and generic publication check.
- The private repository remains private. Its complete history was not cleared for publication and must not be made public as a shortcut.

## Private data review

- The committed fixture set contains six small synthetic JSON files under `src/security_rag/fixtures/SYNTH-001/`.
- No source captures, private report text, real case packages, databases, indexes, or local output bundles are included.
- The generic publication check scans proposed Git files for blocked evidence paths/types, selected credential patterns, personal email addresses, and user-home paths. It reported **0 blockers** before initial publication.
- A second targeted text search found only the safety checker's own pattern definitions. The video was rendered from the documented script and synthetic slides; its metadata contained only standard container/encoder fields. A representative frame was inspected.
- These checks are limited. They cannot certify every possible secret or permission to disclose material. The source allowlist and new history are the main boundary.

## Installation, tests, and dependencies

- A fresh Windows Python 3.14 virtual environment installed a wheel built from this export. The investigation ran from outside the source checkout, confirming that its six fixture files were packaged.
- Eight focused tests passed locally, including the vulnerable and fixed paths, fixture-tamper rejection, offline operation, source-hash linkage, and preservation of an existing data root.
- The two-case retrieval demo and publication checker are included in CI for Windows and Ubuntu on Python 3.11 and 3.13. Read the actual workflow result before claiming that matrix passed.
- Runtime dependencies: **none beyond Python's standard library**. Optional tests use [`pytest`](https://github.com/pytest-dev/pytest/blob/main/LICENSE), which is MIT licensed. Build isolation uses [`setuptools`](https://github.com/pypa/setuptools/blob/main/LICENSE) and `wheel`; these are build tools, not runtime imports. Pillow, ffmpeg, and Windows SAPI were used only to render the optional video.
- The project carries an MIT license. The private engine's earlier authorship and AI-assistance history were not independently inventoried; the release-specific Codex assistance is disclosed in the README and walkthrough.

## Limits

The mock's Account A and Account B are simulated identities. Fixture status 200 and 403 are results of the mock methods, not network captures. The source hash links bytes within this demonstration and does not prove vendor behavior or evidence authority. This is a single-user prototype, not a multi-user evidence service or a validated prompt-injection defense.
