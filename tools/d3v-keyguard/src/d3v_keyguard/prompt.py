"""Out-of-band secure input: never through the LLM chat.

GUI mode runs a tkinter dialog in an isolated subprocess (thread-safe under async
servers like `adk web`); TTY mode uses getpass. KEYGUARD_PROMPT=auto|gui|tty.
"""

from __future__ import annotations

import getpass
import json
import os
import subprocess
import sys
from typing import Protocol

from .errors import PromptCancelled

MAX_REASON = 200


def sanitize(text: str | None, limit: int = MAX_REASON) -> str:
    text = "".join(ch if ch.isprintable() else " " for ch in (text or ""))
    return text[:limit]


class PromptProvider(Protocol):
    def ask_secret(self, title: str, message: str) -> str: ...

    def confirm(self, title: str, message: str) -> bool: ...


def _tty() -> bool:
    try:
        return sys.stdin.isatty() and sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


class TtyPrompt:
    def ask_secret(self, title: str, message: str) -> str:
        if not _tty():
            raise PromptCancelled("no interactive terminal available for secure input")
        print(f"\n[{title}]\n{message}", file=sys.stderr)
        value = getpass.getpass("> ")
        if not value:
            raise PromptCancelled("cancelled")
        return value

    def confirm(self, title: str, message: str) -> bool:
        if not _tty():
            return False
        print(f"\n[{title}]\n{message}", file=sys.stderr)
        return input("Approve? [y/N] ").strip().lower() in ("y", "yes")


class GuiPrompt:
    def __init__(self, timeout: float = 300):
        self.timeout = timeout

    def _run(self, request: dict) -> dict:
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-m", "d3v_keyguard._prompt_helper"],
                input=json.dumps(request),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env={k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "PATH", "DISPLAY", "WAYLAND_DISPLAY", "TCL_LIBRARY", "TK_LIBRARY", "PYTHONPATH", "HOME", "USERPROFILE", "LOCALAPPDATA", "TEMP", "TMP")},
            )
        except subprocess.TimeoutExpired:
            raise PromptCancelled("secure prompt timed out") from None
        if proc.returncode != 0:
            raise PromptCancelled("secure prompt unavailable or cancelled")
        return json.loads(proc.stdout)

    def ask_secret(self, title: str, message: str) -> str:
        value = self._run({"kind": "secret", "title": title, "message": message}).get("value")
        if not value:
            raise PromptCancelled("cancelled")
        return value

    def confirm(self, title: str, message: str) -> bool:
        return bool(self._run({"kind": "confirm", "title": title, "message": message}).get("ok"))


class AutoPrompt:
    """GUI dialog first, falling back to a hidden terminal prompt."""

    def __init__(self):
        self._gui, self._tty = GuiPrompt(), TtyPrompt()

    def ask_secret(self, title: str, message: str) -> str:
        try:
            return self._gui.ask_secret(title, message)
        except PromptCancelled as exc:
            if str(exc) == "cancelled" or not _tty():
                raise
            return self._tty.ask_secret(title, message)

    def confirm(self, title: str, message: str) -> bool:
        try:
            return self._gui.confirm(title, message)
        except PromptCancelled:
            return self._tty.confirm(title, message)


def default_prompt() -> PromptProvider:
    mode = os.environ.get("KEYGUARD_PROMPT", "auto").lower()
    if mode == "gui":
        return GuiPrompt()
    if mode == "tty":
        return TtyPrompt()
    return AutoPrompt()
