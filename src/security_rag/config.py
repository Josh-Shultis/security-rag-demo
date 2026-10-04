from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def default_root() -> Path:
    return Path.home() / "security-rag"


DEFAULT_ROOT_VALUE = str(default_root())


@dataclass(frozen=True)
class Settings:
    root: Path = default_root()

    @property
    def db_path(self) -> Path:
        return self.root / "index" / "security_rag.sqlite"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def cloud_enabled(self) -> bool:
        return os.environ.get("SECURITY_RAG_CLOUD_ENABLED", "false").lower() == "true"

    @property
    def local_llm_base_url(self) -> str:
        return os.environ.get("LOCAL_LLM_BASE_URL", "http://127.0.0.1:8080/v1")

    @property
    def local_llm_model(self) -> str:
        return os.environ.get("LOCAL_LLM_MODEL", "")


def settings(root: str | Path | None = None) -> Settings:
    return Settings(Path(root).resolve() if root else Path(os.environ.get("SECURITY_RAG_ROOT", DEFAULT_ROOT_VALUE)).resolve())
