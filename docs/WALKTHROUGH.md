# Three-minute walkthrough script

The current video uses a synthetic narrator. This script is written in first person so I can replace that narration with my own voice later without changing the technical content.

## Scene 1 — What this project is

This is Security RAG, a local tool I use to keep security conclusions tied back to the evidence that supports them.

For this public demo I built a completely synthetic case around a deliberately vulnerable note service. That gives me something I can show end to end without publishing any private vendor evidence.

The demo runs locally. There is no API key, model account, vendor login, or network dependency. It builds a temporary evidence index, runs the case, and removes the temporary data when it is done.

## Scene 2 — The question

The test is simple: can simulated Account A read an owner-only note that belongs to simulated Account B if Account A knows the note ID?

I keep the note, requester, and target ID the same. The thing I change is the authorization check.

The vulnerable method looks up the note and returns it without checking the owner. The fixed method checks ownership before returning the note.

Because this is a local mock, the account identities are just controlled strings. The point is the test design, not pretending these are real accounts.

## Scene 3 — What proves the behavior

The request fixture shows Account A asking for Account B's note.

The vulnerable response returns HTTP 200 and contains the synthetic canary from Account B's note.

The runner regenerates that response from the code and checks it against the tracked fixture before the evidence is indexed. So I am not asking the reviewer to trust a screenshot or a summary. They can inspect the request, the response, and the code that produced it.

## Scene 4 — Trace the conclusion back to evidence

This is the part I care about most.

Security RAG ingests the supplied artifacts, finds the canary, and returns the exact source file, SHA-256, artifact ID, and chunk ID.

The runner then hashes the source file independently and checks that the indexed result points back to those same bytes.

That gives me a chain from the conclusion back to the original evidence instead of relying on whatever an AI model says happened.

The hash proves which bytes were used in this demo. It does not prove that the contents are true just because they have a hash.

## Scene 5 — Controls and fix

The fixed method returns 403 to Account A for the same note.

The owner control still returns 200 to Account B, so the fix did not simply break all reads.

I also test an unknown note, which returns 404. I treat that as a separate control, not as proof that authorization is working.

The conclusion stays narrow: the vulnerable version exposes the canary in this controlled mock, and the ownership check blocks that same read.

## Scene 6 — Why I built it this way

This is basically how I try to work real security cases: narrow the question, preserve the original artifacts, keep exact IDs and timestamps, test a control, and separate what I observed from what I am only inferring.

The public repository contains synthetic fixtures and selected retrieval code only. My private research history, Burp captures, HAR files, and vendor reports stay private.

Codex helped with parts of the public export, tests, documentation, and walkthrough. I still make the final call on what the evidence supports, what remains unproven, and how the case should be framed.

What I want a reviewer to see here is not a flashy mock vulnerability. It is the way I make a security conclusion traceable and reviewable.
