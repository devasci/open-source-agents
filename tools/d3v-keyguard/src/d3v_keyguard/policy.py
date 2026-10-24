"""Deny-by-default policy: which tools may receive which secrets."""

from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path


class Policy:
    def __init__(self, rules: dict[str, list[str]] | None = None):
        self.rules = {tool: list(patterns) for tool, patterns in (rules or {}).items()}

    def allows(self, tool_name: str, secret_name: str) -> bool:
        return any(fnmatch.fnmatchcase(secret_name, p) for p in self.rules.get(tool_name, []))

    @classmethod
    def from_file(cls, path: str | os.PathLike) -> "Policy":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not all(
            isinstance(v, list) and all(isinstance(p, str) for p in v) for v in data.values()
        ):
            raise ValueError("policy file must map tool names to lists of glob patterns")
        return cls(data)

    @classmethod
    def from_env(cls) -> "Policy":
        path = os.environ.get("KEYGUARD_POLICY_FILE")
        return cls.from_file(path) if path else cls()
