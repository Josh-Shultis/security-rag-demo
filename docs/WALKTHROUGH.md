# Three-minute walkthrough script

The [video](../media/walkthrough.mp4) uses a synthetic narrator. Codex drafted the narration and slides; it is not a recording of Josh speaking. The repository code and fixtures remain the authoritative material.

## Scene 1 — What this shows

This is Security RAG, a local evidence retrieval tool, shown through one fully synthetic investigation. I chose a deliberately vulnerable mock note service because it lets a reviewer inspect the complete path from an input to an output without exposing any private case. Clone the public repository, create a Python virtual environment, install the package, and run the investigation module. The demo needs no account, model, API key, or network connection. It builds a temporary index and deletes it when the run finishes.

## Scene 2 — The security question

The question is precise: can simulated Account A read a note owned by simulated Account B using its ID? The mock's owner state says the note belongs to Account B and is owner only. Account A controls the requested note ID. The vulnerable read method looks up the note but never checks whether the requester owns it. The fixed method adds that check. These are string identities in an in-memory model, not real logins or access control lists.

## Scene 3 — The decisive evidence

The supplied request names Account A and the target note. The vulnerable response has status two hundred and includes Account B's synthetic canary. The runner regenerates that response from the mock and compares it to the checked-in fixture before indexing it. This gives us a reproducible observation within this mock. A response file by itself would not prove who sent a real request, which account owned a real object, or what a vendor backend did. Here, the mock code and test setup define those facts explicitly.

## Scene 4 — Trace the conclusion

Security RAG ingests the fixture files and searches for the canary inside the selected synthetic case. The result names the source file, its full SHA-256, an artifact ID, and a chunk ID. The runner independently hashes the supplied file and checks that the index points to those same bytes. That is the key design choice: a reviewer can move from a conclusion back to exact source bytes, instead of trusting a model's summary. A hash proves byte identity in this run, not truth or origin.

## Scene 5 — Controls and limits

The fixed read returns four-oh-three to Account A, while still returning two hundred to the rightful owner. An unknown note returns four-oh-four. That last result is a negative control, not proof that authorization works. The supported conclusion is narrow: the deliberately vulnerable mock discloses the canary, and this particular fix blocks that read. The demo does not establish a bug in any real product, real account identity, or a real attacker benefit. Those would need authenticated captures and native account and ownership evidence.

## Scene 6 — Engineering and authorship

I kept the public release as a fresh export of selected retrieval code, with only synthetic fixtures. The private research history and raw Burp or HAR captures stay outside it. Tests check the vulnerable and fixed paths, source linking, offline execution, and preservation of an existing data root. The code uses a single-user research model; case filters help retrieval, but are not multi-user authorization. Codex assisted with this release demo and documentation, and prior AI assistance on the private engine has not been fully inventoried. What I can defend here is the test design, the exact artifacts, and the limits of the conclusion.
