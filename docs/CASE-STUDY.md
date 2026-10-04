# Case study: owner-only note in a mock service

This is a controlled, **synthetic** investigation. Account A and Account B are simulated string identities inside [`mock_notes.py`](../src/security_rag/mock_notes.py). There are no real accounts, network requests, vendor systems, or private records.

## Question and test

Can Account A obtain Account B's owner-only note by supplying its ID? The attacker-controlled input in this mock is the requested note ID, `SYNTH-NOTE-B-1`. The prerequisite is that Account A knows that ID. The independent variable is whether the read method checks ownership. The note and requester stay the same.

| Stage | Direct source |
| --- | --- |
| Account B owns the owner-only note | [`01_owner_state.json`](../src/security_rag/fixtures/SYNTH-001/01_owner_state.json) and mock initialization |
| Account A requests that note | [`02_attacker_request.json`](../src/security_rag/fixtures/SYNTH-001/02_attacker_request.json) |
| Deliberately vulnerable method returns status 200 and `SYNTH-CANARY-B-7` | [`03_vulnerable_response.json`](../src/security_rag/fixtures/SYNTH-001/03_vulnerable_response.json) |
| Fixed method returns 403 to Account A | [`04_fixed_response.json`](../src/security_rag/fixtures/SYNTH-001/04_fixed_response.json) |
| Fixed method still returns 200 to owner Account B | [`05_owner_control.json`](../src/security_rag/fixtures/SYNTH-001/05_owner_control.json) |
| Unknown note returns 404 | [`06_missing_note_control.json`](../src/security_rag/fixtures/SYNTH-001/06_missing_note_control.json) |

The runner regenerates each result from the mock and compares it to the tracked fixture. It copies those fixtures into a fresh temporary Security RAG root, ingests them, searches for the canary, and verifies the decisive search hit against the source file's SHA-256 and indexed artifact ID. The JSON output includes the chunk ID so a reviewer can trace **conclusion → retrieval hit → indexed artifact → exact supplied file**.

## Conclusion

**Verified in this mock:** the vulnerable method returns Account B's canary to simulated Account A. The method has no ownership check. The fixed method rejects that same read with 403 and still permits Account B to read its own note. The missing-note 404 is a separate negative control; it is not evidence that ownership was checked.

**Limits:** this demonstrates a deliberate bug and its regression test in our local mock only. It does not prove a real product vulnerability, real account identity, a real ACL, exploitability beyond this model, or source authenticity beyond supplied fixture bytes. Security RAG retrieves and links evidence; the human researcher makes the security judgment.

The stronger test for a real case would require native source ownership/ACL evidence, the exact authenticated requester, a captured request and successful response, a persistent or directly observable destination, and an attacker-side read. Those artifacts are deliberately absent here.
