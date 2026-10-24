"""Offline end-to-end demo: a real ADK Runner + d3v-keyguard, driven by a scripted model.

No API key needed. The scripted model stands in for Gemini and records every request
it receives, so we can prove no plaintext secret ever reached "the model".
The PIN prompt is scripted and the OS keyring is in-memory so the demo has no side effects.

Run:  python examples/offline_adk_demo.py
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import AsyncGenerator

from google.adk.agents import Agent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

from d3v_keyguard import Policy, Vault
from d3v_keyguard.adk import KeyguardADK

API_KEY = "sk-demo-4f9a1c7e2b8d6035"  # fake value used only by this demo
PIN = "demo-pin-2468"
SEEN_REQUESTS: list[str] = []
RECEIVED: dict = {}


class InMemoryKeyring:
    def __init__(self):
        self._d = {}

    def get_password(self, s, u):
        return self._d.get((s, u))

    def set_password(self, s, u, p):
        self._d[(s, u)] = p


class ScriptedPrompt:
    """Stands in for the secure OS dialog where the human types the PIN."""

    def ask_secret(self, title, message):
        print(f"  [secure dialog] {title}\n    " + message.replace("\n", "\n    "))
        return PIN

    def confirm(self, title, message):
        print(f"  [secure dialog] {title} -> user clicks Yes")
        return True


SCRIPT = [
    ("login", {"username": "alice"}),
    ("list_secrets", {}),
    ("call_api", {"url": "https://api.example.com/v1/me", "authorization": "Bearer keyguard://demo_api"}),
]


class ScriptedModel(BaseLlm):
    model: str = "scripted-demo"

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        SEEN_REQUESTS.append(json.dumps([c.model_dump(mode="json") for c in llm_request.contents]))
        turn = sum(1 for c in llm_request.contents for p in (c.parts or []) if p.function_response)
        if turn < len(SCRIPT):
            name, args = SCRIPT[turn]
            part = types.Part(function_call=types.FunctionCall(name=name, args=args))
        else:
            part = types.Part(text="Done: logged in, and called the API with your demo_api key (by handle).")
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


def login(username: str) -> dict:
    """Log in and obtain a session token."""
    RECEIVED["session_token"] = "sess-7d41a9e0c3b25f86"
    return {"status": "success", "user": username, "session_token": RECEIVED["session_token"]}


def call_api(url: str, authorization: str) -> dict:
    """Call an HTTP API; pass authorization as 'Bearer keyguard://<name>'."""
    RECEIVED["authorization"] = authorization
    return {"status": "success", "url": url, "echoed_header": authorization}


async def main() -> None:
    tmp = Path(tempfile.mkdtemp())
    vault = Vault(tmp / "vault.json", keyring_backend=InMemoryKeyring())
    vault.create(PIN)
    vault.lock()
    print("1) Developer stores demo_api while the vault is LOCKED (no PIN):",
          vault.put("demo_api", API_KEY, {"description": "demo API key"}))

    kg = KeyguardADK(vault=vault, policy=Policy({"call_api": ["demo_*"]}),
                     capture={"login": {"session_token": "demo_session"}}, prompt=ScriptedPrompt())
    agent = Agent(name="keyguard_demo", model=ScriptedModel(), instruction="Use secrets only by handle.",
                  tools=[login, call_api, *kg.tools], before_tool_callback=kg.before_tool_callback,
                  after_tool_callback=kg.after_tool_callback, before_model_callback=kg.before_model_callback)
    runner = InMemoryRunner(agent=agent, app_name="demo")
    session = await runner.session_service.create_session(app_name="demo", user_id="u")

    print("2) Agent run (what the LLM and session history see):")
    msg = types.Content(role="user", parts=[types.Part(text="Log me in as alice and call /v1/me.")])
    async for event in runner.run_async(user_id="u", session_id=session.id, new_message=msg):
        for part in (event.content.parts if event.content else []) or []:
            if part.function_call:
                print(f"  LLM  -> {part.function_call.name}({json.dumps(part.function_call.args)})")
            elif part.function_response:
                print(f"  tool -> {part.function_response.name}: {json.dumps(part.function_response.response)}")
            elif part.text:
                print(f"  LLM  : {part.text}")

    stored = await runner.session_service.get_session(app_name="demo", user_id="u", session_id=session.id)
    history = json.dumps([e.model_dump(mode="json") for e in stored.events])
    secrets = [API_KEY, RECEIVED["session_token"]]
    print("3) Verification:")
    print("  call_api received the real key        :", RECEIVED["authorization"] == f"Bearer {API_KEY}")
    print("  login token captured into the vault   :", [s["name"] for s in vault.list()])
    print("  plaintext in any model request        :", any(s in r for r in SEEN_REQUESTS for s in secrets))
    print("  plaintext in persisted session history:", any(s in history for s in secrets))
    print("  plaintext in vault file on disk       :", any(s in vault.path.read_text() for s in secrets))


if __name__ == "__main__":
    asyncio.run(main())
