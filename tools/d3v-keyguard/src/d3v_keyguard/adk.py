"""Google ADK integration: LLM-facing tools + callbacks that keep plaintext out of the model.

The LLM only ever handles `keyguard://<name>` handles. Real values are substituted into
tool arguments inside `before_tool_callback` (policy-checked), captured/scrubbed from tool
results in `after_tool_callback`, and scrubbed from outbound requests in
`before_model_callback`.
"""

from __future__ import annotations

import os
from typing import Any

from .errors import KeyguardError, PromptCancelled
from .policy import Policy
from .prompt import PromptProvider, default_prompt, sanitize
from .redact import HANDLE_RE, Redactor, handle, valid_name
from .vault import Vault

TOOL_NAMES = {"vault_status", "list_secrets", "store_secret", "unlock_vault", "lock_vault", "describe_secret"}


def _err(message: str) -> dict:
    return {"status": "error", "error": message}


class KeyguardADK:
    def __init__(
        self,
        vault: Vault | None = None,
        policy: Policy | None = None,
        capture: dict[str, dict[str, str]] | None = None,
        prompt: PromptProvider | None = None,
    ):
        self.vault = vault or Vault()
        self.policy = policy if policy is not None else Policy.from_env()
        self.capture = capture or {}
        self.prompt = prompt or default_prompt()
        self.redactor = Redactor()
        self.vault.on_lock.append(self.redactor.clear)
        self.tools = self._build_tools()

    # ---------------------------------------------------------------- unlock
    def _unlock(self, reason: str, requester: str) -> dict | None:
        """Prompt the user out-of-band. Returns an error dict, or None on success."""
        if self.vault.is_unlocked():
            return None
        try:
            pin = self.prompt.ask_secret(
                "d3v-keyguard: unlock vault",
                f"Requested by: {sanitize(requester, 80)}\n"
                f"Agent-provided reason (unverified): {sanitize(reason)}\n\n"
                "Enter your vault PIN/password. Never type it into the chat.",
            )
            pending = self.vault.unlock(pin)
            del pin
        except PromptCancelled:
            return _err("user did not unlock the vault")
        except KeyguardError as exc:
            return _err(str(exc))
        if pending and self.prompt.confirm(
            "d3v-keyguard: approve pending secrets",
            "These secrets were stored while the vault was locked.\n"
            "Approve only ones YOU added:\n\n- " + "\n- ".join(pending[:50]),
        ):
            self.vault.approve(pending)
        return None

    # ----------------------------------------------------------------- tools
    def _build_tools(self) -> list:
        kg = self

        def vault_status() -> dict:
            """Show whether the secret vault exists, is unlocked, and how many secrets it holds. Never returns secret values."""
            try:
                return {"status": "success", **kg.vault.status()}
            except KeyguardError as exc:
                return _err(str(exc))

        def list_secrets() -> dict:
            """List stored secret names, their status (active/pending/tampered) and metadata. Use the returned 'handle' (keyguard://name) wherever another tool needs the secret; the real value is injected automatically. Never returns secret values."""
            try:
                items = kg.vault.list()
            except KeyguardError as exc:
                return _err(str(exc))
            for item in items:
                item["handle"] = handle(item["name"])
            return {"status": "success", "secrets": items}

        def store_secret(name: str, description: str = "", value: str = "") -> dict:
            """Store a secret under `name`. Leave `value` empty: a secure dialog asks the USER to type or paste the value, so it never enters the conversation. Never ask the user to paste secrets in chat. Returns the handle keyguard://name."""
            if not valid_name(name):
                return _err("invalid name: use letters, digits, '_', '-', '.' (max 128)")
            if value and os.environ.get("KEYGUARD_ALLOW_LLM_VALUES") != "1":
                return _err("passing values through the model is disabled; call again without `value`")
            exposed = bool(value)
            if not value:
                try:
                    value = kg.prompt.ask_secret(
                        "d3v-keyguard: store a secret",
                        f"Paste the value for secret '{name}'.\n"
                        f"Agent-provided description (unverified): {sanitize(description)}",
                    )
                except PromptCancelled:
                    return _err("user cancelled secret entry")
            try:
                state = kg.vault.put(name, value, {"description": sanitize(description)} if description else None)
            except (KeyguardError, ValueError) as exc:
                return _err(str(exc))
            result = {"status": "success", "handle": handle(name), "state": state}
            if state == "pending":
                result["note"] = "stored while locked; usable after the user approves it at next unlock"
            if exposed:
                kg.redactor.add(name, value)
                result["warning"] = "value passed through the model context; advise the user to rotate it"
            return result

        def unlock_vault(reason: str) -> dict:
            """Ask the user to unlock the vault via a secure OS dialog (never via chat). Give a short honest `reason`. Usually unnecessary: using a keyguard:// handle in a tool call unlocks on demand."""
            error = kg._unlock(reason, "agent (unlock_vault tool)")
            return error or {"status": "success", "unlocked": True}

        def lock_vault() -> dict:
            """Lock the vault immediately, wiping keys from memory."""
            kg.vault.lock()
            return {"status": "success", "unlocked": False}

        def describe_secret(name: str) -> dict:
            """Return a MASKED preview (never the value) and metadata of a secret. Requires the vault to be unlocked."""
            error = kg._unlock(f"preview metadata of {name}", "agent (describe_secret tool)")
            if error:
                return error
            try:
                secret = kg.vault.get(name)
            except KeyguardError as exc:
                return _err(str(exc))
            return {"status": "success", "handle": handle(name), "preview": secret.masked()}

        return [vault_status, list_secrets, store_secret, unlock_vault, lock_vault, describe_secret]

    # ------------------------------------------------------------- callbacks
    def _handles_in(self, obj: Any, found: set) -> None:
        if isinstance(obj, str):
            found.update(HANDLE_RE.findall(obj))
        elif isinstance(obj, dict):
            for v in obj.values():
                self._handles_in(v, found)
        elif isinstance(obj, list):
            for v in obj:
                self._handles_in(v, found)

    def _substitute(self, obj: Any, values: dict[str, str]) -> Any:
        if isinstance(obj, str):
            return HANDLE_RE.sub(lambda m: values[m.group(1)], obj)
        if isinstance(obj, dict):
            return {k: self._substitute(v, values) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._substitute(v, values) for v in obj]
        return obj

    def before_tool_callback(self, tool, args: dict[str, Any], tool_context) -> dict | None:
        name = getattr(tool, "name", "")
        if name in TOOL_NAMES:
            return None
        found: set[str] = set()
        self._handles_in(args, found)
        if not found:
            return None
        denied = sorted(s for s in found if not self.policy.allows(name, s))
        if denied:
            return _err(f"policy denies tool '{name}' access to: {', '.join(denied)}")
        error = self._unlock(f"tool '{name}' needs {', '.join(sorted(found))}", f"tool '{name}'")
        if error:
            return error
        try:
            values = {s: self.vault.get(s).reveal() for s in found}
        except KeyguardError as exc:
            return _err(str(exc))
        for s, v in values.items():
            self.redactor.add(s, v)
        new_args = self._substitute(args, values)
        args.clear()
        args.update(new_args)
        return None

    def after_tool_callback(self, tool, args: dict[str, Any], tool_context, tool_response) -> dict | None:
        name = getattr(tool, "name", "")
        if not isinstance(tool_response, dict):
            return None
        response = dict(tool_response)
        changed = False
        for field, secret_name in self.capture.get(name, {}).items():
            value = response.get(field)
            if isinstance(value, str) and value:
                try:
                    self.vault.put(secret_name, value, {"captured_from": name})
                    response[field] = handle(secret_name)
                except (KeyguardError, ValueError):
                    response[field] = "[REDACTED: capture failed]"
                self.redactor.add(secret_name, value)
                changed = True
        if self.redactor:
            scrubbed = self.redactor.scrub(response)
            if scrubbed != response:
                response, changed = scrubbed, True
        return response if changed else None

    def before_model_callback(self, callback_context, llm_request) -> None:
        if not self.redactor:
            return None
        for content in getattr(llm_request, "contents", None) or []:
            for part in getattr(content, "parts", None) or []:
                if getattr(part, "text", None):
                    part.text = self.redactor.scrub_text(part.text)
                fc = getattr(part, "function_call", None)
                if fc is not None and fc.args:
                    fc.args = self.redactor.scrub(dict(fc.args))
                fr = getattr(part, "function_response", None)
                if fr is not None and fr.response:
                    fr.response = self.redactor.scrub(dict(fr.response))
        return None
