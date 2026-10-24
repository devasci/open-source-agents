"""d3v-keyguard command line."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading

from .errors import KeyguardError, PromptCancelled
from .prompt import TtyPrompt, _tty, default_prompt
from .redact import HANDLE_RE, Redactor, handle
from .vault import Vault


def _prompt():
    return TtyPrompt() if _tty() else default_prompt()


def _ask(title: str, message: str) -> str:
    return _prompt().ask_secret(title, message)


def _unlock(vault: Vault, *, human_reset: bool = False) -> None:
    pending = vault.unlock(_ask("d3v-keyguard", "Enter vault PIN/password:"), human_reset=human_reset)
    if pending:
        msg = "Secrets stored while locked (approve only ones YOU added):\n- " + "\n- ".join(pending)
        if _prompt().confirm("d3v-keyguard: pending secrets", msg):
            vault.approve(pending)


def cmd_init(vault: Vault, a) -> int:
    pin = _ask("d3v-keyguard init", "Choose a vault PIN/password (min 6 chars):")
    if pin != _ask("d3v-keyguard init", "Repeat PIN/password:"):
        print("PINs do not match", file=sys.stderr)
        return 1
    vault.create(pin)
    print(f"vault created at {vault.path}")
    return 0


def cmd_add(vault: Vault, a) -> int:
    value = _ask("d3v-keyguard add", f"Value for '{a.name}' (input hidden):")
    state = vault.put(a.name, value, {"description": a.description} if a.description else None)
    print(f"stored {handle(a.name)} ({state})")
    return 0


def cmd_list(vault: Vault, a) -> int:
    for item in vault.list():
        desc = item["metadata"].get("description", "")
        print(f"{handle(item['name'])}\t{item['status']}\t{desc}")
    return 0


def cmd_rm(vault: Vault, a) -> int:
    ok = vault.delete(a.name)
    print("deleted" if ok else "not found")
    return 0 if ok else 1


def cmd_status(vault: Vault, a) -> int:
    print(json.dumps(vault.status(), indent=2))
    return 0


def cmd_lock(vault: Vault, a) -> int:
    vault.lock()
    print("each CLI invocation is its own process; nothing stays unlocked after it exits")
    return 0


def cmd_approve(vault: Vault, a) -> int:
    pending_before = vault.pending()
    if not pending_before:
        print("no pending secrets")
        return 0
    _unlock(vault)
    left = vault.pending()
    print(f"approved {len(pending_before) - len(left)}, still pending {len(left)}")
    return 0


def cmd_change_pin(vault: Vault, a) -> int:
    old = _ask("d3v-keyguard", "Current PIN/password:")
    new = _ask("d3v-keyguard", "New PIN/password (min 6 chars):")
    if new != _ask("d3v-keyguard", "Repeat new PIN/password:"):
        print("PINs do not match", file=sys.stderr)
        return 1
    vault.change_pin(old, new)
    print("PIN changed")
    return 0


def cmd_reset_lockout(vault: Vault, a) -> int:
    if not (_tty() and sys.stdout.isatty()):
        print("reset-lockout must be run by a human in an interactive terminal", file=sys.stderr)
        return 2
    vault.unlock(TtyPrompt().ask_secret("d3v-keyguard", "Enter vault PIN/password:"), human_reset=True)
    print("lockout cleared")
    return 0


def cmd_reveal(vault: Vault, a) -> int:
    if not (_tty() and sys.stdout.isatty()):
        print("reveal only works in an interactive terminal (refused for piped/agent use)", file=sys.stderr)
        return 2
    vault.unlock(TtyPrompt().ask_secret("d3v-keyguard", "Enter vault PIN/password:"))
    print(vault.get(a.name).reveal())
    return 0


def _pump(src, dst, redactor: Redactor) -> None:
    for line in iter(src.readline, ""):
        dst.write(redactor.scrub_text(line))
        dst.flush()
    src.close()


def cmd_exec(vault: Vault, a) -> int:
    cmd = list(a.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("usage: d3v-keyguard exec --env VAR=keyguard://name -- command [args]", file=sys.stderr)
        return 2
    mapping = {}
    for spec in a.env or []:
        var, _, ref = spec.partition("=")
        m = HANDLE_RE.fullmatch(ref)
        if not var or not m:
            print(f"bad --env {var!r}: expected VAR=keyguard://name", file=sys.stderr)
            return 2
        mapping[var] = m.group(1)
    env = dict(os.environ)
    redactor = Redactor()
    if mapping:
        _unlock(vault)
        for var, name in mapping.items():
            value = vault.get(name).reveal()
            env[var] = value
            redactor.add(name, value)
        vault.lock()
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace")
    threads = [
        threading.Thread(target=_pump, args=(proc.stdout, sys.stdout, redactor), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, sys.stderr, redactor), daemon=True),
    ]
    for t in threads:
        t.start()
    code = proc.wait()
    for t in threads:
        t.join()
    return code


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="d3v-keyguard", description="PIN-protected secret vault for LLM agents")
    p.add_argument("--vault", help="vault file path (default: KEYGUARD_VAULT_PATH or per-user data dir)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create a new vault").set_defaults(fn=cmd_init)
    s = sub.add_parser("add", help="store a secret (value read via hidden prompt)")
    s.add_argument("name")
    s.add_argument("--description", default="")
    s.set_defaults(fn=cmd_add)
    sub.add_parser("list", help="list secret handles and status").set_defaults(fn=cmd_list)
    s = sub.add_parser("rm", help="delete a secret")
    s.add_argument("name")
    s.set_defaults(fn=cmd_rm)
    sub.add_parser("status", help="show vault status").set_defaults(fn=cmd_status)
    sub.add_parser("lock", help="lock (informational for CLI)").set_defaults(fn=cmd_lock)
    sub.add_parser("approve", help="review and approve pending secrets").set_defaults(fn=cmd_approve)
    sub.add_parser("change-pin", help="change the vault PIN/password").set_defaults(fn=cmd_change_pin)
    sub.add_parser("reset-lockout", help="clear wrong-PIN lockout (interactive terminal only)").set_defaults(
        fn=cmd_reset_lockout
    )
    s = sub.add_parser("reveal", help="print a secret (interactive terminal only)")
    s.add_argument("name")
    s.set_defaults(fn=cmd_reveal)
    s = sub.add_parser("exec", help="run a command with secrets injected as env vars; output is redacted")
    s.add_argument("--env", action="append", metavar="VAR=keyguard://name")
    s.add_argument("cmd", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_exec)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    vault = Vault(a.vault) if a.vault else Vault()
    try:
        return a.fn(vault, a)
    except PromptCancelled as exc:
        print(f"cancelled: {exc}", file=sys.stderr)
        return 130
    except (KeyguardError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        vault.lock()


if __name__ == "__main__":
    sys.exit(main())
