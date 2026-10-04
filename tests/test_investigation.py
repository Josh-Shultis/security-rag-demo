from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path

import pytest

from security_rag import investigation
from security_rag.mock_notes import MockNotes, scenario


def test_mock_exposes_vulnerable_read_and_fixed_control():
    service = MockNotes()
    assert service.read_vulnerable("Account A", "SYNTH-NOTE-B-1")["body"]["text"] == "SYNTH-CANARY-B-7"
    assert service.read_fixed("Account A", "SYNTH-NOTE-B-1")["status"] == 403
    assert service.read_fixed("Account B", "SYNTH-NOTE-B-1")["status"] == 200
    assert service.read_vulnerable("Account A", "SYNTH-NOTE-MISSING")["status"] == 404


def test_investigation_links_decisive_hit_to_supplied_bytes(monkeypatch, tmp_path):
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("leave this alone", encoding="utf-8")
    monkeypatch.setenv("SECURITY_RAG_ROOT", str(tmp_path))

    def no_network(*args, **kwargs):
        raise AssertionError("The investigation must stay offline")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    result = investigation.run()
    decisive = result["decisive_retrieval"]
    source = Path(__file__).resolve().parents[1] / decisive["source"]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == decisive["sha256"]
    assert decisive["artifact_id"].startswith("art-SYNTH-001-")
    assert decisive["chunk_id"].startswith("chk-SYNTH-001-")
    assert result["negative_results"] == {"fixed_cross_account_read": 403, "missing_note": 404}
    assert len(result["source_artifacts"]) == len(scenario())
    assert sentinel.read_text(encoding="utf-8") == "leave this alone"
    assert list(tmp_path.iterdir()) == [sentinel]
    assert str(tmp_path) == investigation.os.environ["SECURITY_RAG_ROOT"]


def test_changed_fixture_is_rejected(monkeypatch, tmp_path):
    for name in scenario():
        source = investigation.FIXTURE_DIR / name
        (tmp_path / name).write_bytes(source.read_bytes())
    changed = tmp_path / "03_vulnerable_response.json"
    value = json.loads(changed.read_text(encoding="utf-8"))
    value["status"] = 403
    changed.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(investigation, "FIXTURE_DIR", tmp_path)
    with pytest.raises(RuntimeError, match="Fixture differs"):
        investigation.run()
