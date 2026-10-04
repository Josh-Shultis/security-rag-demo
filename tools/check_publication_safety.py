"""Small release gate for this synthetic-only public repository."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


BLOCKED_SUFFIXES = {".har", ".burp", ".saz", ".pcap", ".pcapng", ".sqlite", ".db", ".key", ".pem", ".p12", ".pfx", ".zip", ".7z"}
BLOCKED_PARTS = {"raw", "private", "captures", "burp", "screenshots", "takeout", "logs", "index", "output", "build"}
PATTERNS = {
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "absolute home path": re.compile(r"(?:[A-Z]:\\Users\\[^\\\s]+|/ho" + r"me/[^/\s]+/)", re.I),
    "non-example email": re.compile(r"\b[A-Za-z0-9._%+-]+@(?!example\.(?:com|test)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.I),
}


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=repo, text=True).splitlines()
    problems: list[str] = []
    for name in sorted(set(names)):
        rel = PurePosixPath(name.replace("\\", "/"))
        if rel.suffix.lower() in BLOCKED_SUFFIXES or set(part.lower() for part in rel.parts) & BLOCKED_PARTS:
            problems.append(f"blocked path: {name}")
        path = repo / name
        if path.suffix.lower() == ".mp4":
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            problems.append(f"unreadable file: {name}")
            continue
        for label, pattern in PATTERNS.items():
            if pattern.search(content):
                problems.append(f"{label}: {name}")
    print(f"files scanned: {len(names)}; blockers: {len(problems)}")
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
