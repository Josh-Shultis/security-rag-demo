"""Deliberately vulnerable in-memory service for a synthetic investigation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Note:
    note_id: str
    owner: str
    body: str


class MockNotes:
    def __init__(self) -> None:
        self.notes = {
            "SYNTH-NOTE-B-1": Note("SYNTH-NOTE-B-1", "Account B", "SYNTH-CANARY-B-7"),
        }

    def read_vulnerable(self, requester: str, note_id: str) -> dict:
        """Bug: a known note ID is enough to read its body."""
        note = self.notes.get(note_id)
        if note is None:
            return {"requester": requester, "status": 404, "body": {"error": "not_found"}}
        return {"requester": requester, "status": 200, "body": {"note_id": note.note_id, "owner": note.owner, "text": note.body}}

    def read_fixed(self, requester: str, note_id: str) -> dict:
        note = self.notes.get(note_id)
        if note is None:
            return {"requester": requester, "status": 404, "body": {"error": "not_found"}}
        if note.owner != requester:
            return {"requester": requester, "status": 403, "body": {"error": "forbidden"}}
        return {"requester": requester, "status": 200, "body": {"note_id": note.note_id, "owner": note.owner, "text": note.body}}


def scenario() -> dict[str, dict]:
    service = MockNotes()
    target = "SYNTH-NOTE-B-1"
    return {
        "01_owner_state.json": {"note_id": target, "owner": "Account B", "visibility": "owner_only"},
        "02_attacker_request.json": {"requester": "Account A", "operation": "read", "note_id": target},
        "03_vulnerable_response.json": service.read_vulnerable("Account A", target),
        "04_fixed_response.json": service.read_fixed("Account A", target),
        "05_owner_control.json": service.read_fixed("Account B", target),
        "06_missing_note_control.json": service.read_vulnerable("Account A", "SYNTH-NOTE-MISSING"),
    }
