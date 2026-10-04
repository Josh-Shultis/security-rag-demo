from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest

from security_rag import demo
from security_rag.config import default_root, settings


def test_demo_is_offline_repeatable_and_preserves_existing_root(tmp_path, monkeypatch):
    sentinel = tmp_path / "untouched.txt"
    sentinel.write_text("existing corpus", encoding="utf-8")
    monkeypatch.setenv("SECURITY_RAG_ROOT", str(tmp_path))
    monkeypatch.setenv("EMBEDDING_BACKEND", "not-installed")

    def no_network(*args, **kwargs):
        raise AssertionError("The synthetic demo must not open a network connection")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    first = demo.run_demo()
    assert first == demo.run_demo()
    assert all(first["checks"].values())
    assert {item["case_id"] for item in first["evidence"]} == {"DEMO-A", "DEMO-B"}
    assert all(len(item["sha256"]) == 64 for item in first["evidence"])
    assert os.environ["SECURITY_RAG_ROOT"] == str(tmp_path)
    assert os.environ["EMBEDDING_BACKEND"] == "not-installed"
    assert sentinel.read_text(encoding="utf-8") == "existing corpus"
    assert list(tmp_path.iterdir()) == [sentinel]


def test_demo_restores_unset_environment_on_failure(tmp_path, monkeypatch):
    monkeypatch.delenv("SECURITY_RAG_ROOT", raising=False)
    monkeypatch.delenv("EMBEDDING_BACKEND", raising=False)
    with pytest.raises(RuntimeError, match="deliberate"):
        with demo.demo_environment(tmp_path):
            raise RuntimeError("deliberate")
    assert "SECURITY_RAG_ROOT" not in os.environ
    assert "EMBEDDING_BACKEND" not in os.environ


def test_demo_removes_temporary_files_on_failure(monkeypatch):
    roots = []

    def fail(root):
        roots.append(root)
        (root / "temporary.txt").write_text("synthetic", encoding="utf-8")
        raise RuntimeError("deliberate")

    monkeypatch.setattr(demo.store, "init_project", fail)
    with pytest.raises(RuntimeError, match="deliberate"):
        demo.run_demo()
    assert roots and not roots[0].exists()


def test_default_root_uses_current_user_home(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert default_root() == tmp_path / "security-rag"


def test_config_explicit_root_takes_precedence(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_RAG_ROOT", str(tmp_path / "configured"))
    assert settings().root == (tmp_path / "configured").resolve()
    assert settings(tmp_path / "explicit").root == (tmp_path / "explicit").resolve()
