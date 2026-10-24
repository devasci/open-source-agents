"""Masking, handles, and scrubbing of known secret values."""

from __future__ import annotations

import base64
import re
import threading
import urllib.parse
from typing import Any

HANDLE_PREFIX = "keyguard://"
NAME_RE = r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}"
HANDLE_RE = re.compile(r"keyguard://(" + NAME_RE + r")")
_NAME_FULL = re.compile(r"^" + NAME_RE + r"$")


def valid_name(name: str) -> bool:
    return bool(_NAME_FULL.match(name or ""))


def handle(name: str) -> str:
    return HANDLE_PREFIX + name


def mask(value: str) -> str:
    """Masked preview: at most 4 leading chars, and only for secrets of 12+ chars."""
    n = len(value)
    if n < 12:
        return f"****[{n} chars]"
    return f"{value[:4]}****[{n} chars]"


class SecretValue:
    """Wraps a plaintext secret; str/repr/format are masked. Call reveal() deliberately."""

    __slots__ = ("_name", "_value")

    def __init__(self, name: str, value: str):
        self._name = name
        self._value = value

    @property
    def name(self) -> str:
        return self._name

    def reveal(self) -> str:
        return self._value

    def masked(self) -> str:
        return mask(self._value)

    def __repr__(self) -> str:
        return f"SecretValue({self._name!r}, {self.masked()!r})"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return repr(self)

    def __reduce__(self):
        raise TypeError("SecretValue cannot be pickled")


class Redactor:
    """Replaces any known secret value (raw, base64, URL-encoded) with a placeholder."""

    MIN_LEN = 4

    def __init__(self) -> None:
        self._known: dict[str, str] = {}
        self._lock = threading.Lock()

    def add(self, name: str, value: str) -> None:
        if len(value) < self.MIN_LEN:
            return
        variants = {value, urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value)}
        raw = value.encode("utf-8")
        variants.add(base64.b64encode(raw).decode("ascii").rstrip("="))
        variants.add(base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="))
        with self._lock:
            for v in variants:
                if len(v) >= self.MIN_LEN:
                    self._known[v] = name

    def clear(self) -> None:
        with self._lock:
            self._known.clear()

    def __bool__(self) -> bool:
        return bool(self._known)

    def scrub_text(self, text: str) -> str:
        with self._lock:
            items = sorted(self._known.items(), key=lambda kv: -len(kv[0]))
        for value, name in items:
            if value in text:
                text = text.replace(value, f"[REDACTED:{handle(name)}]")
        return text

    def scrub(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.scrub_text(obj)
        if isinstance(obj, dict):
            return {self.scrub(k): self.scrub(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return type(obj)(self.scrub(v) for v in obj)
        if isinstance(obj, SecretValue):
            return repr(obj)
        return obj
