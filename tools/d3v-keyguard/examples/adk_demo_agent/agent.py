"""Demo ADK agent: uses secrets by handle; plaintext never reaches the model."""

import os

from google.adk.agents import Agent

from d3v_keyguard.adk import KeyguardADK
from d3v_keyguard.policy import Policy


def call_api(url: str, authorization: str) -> dict:
    """Call an HTTP API. Pass `authorization` as a keyguard:// handle, e.g. 'Bearer keyguard://demo_api'."""
    # Mock: a real tool would send the request. Echoing proves the redaction works.
    return {"status": "success", "url": url, "sent_header": authorization}


def login(username: str) -> dict:
    """Log in to the demo service and obtain a session token."""
    return {"status": "success", "user": username, "session_token": "demo-session-" + os.urandom(8).hex()}


kg = KeyguardADK(
    policy=Policy({"call_api": ["demo_*"]}),
    capture={"login": {"session_token": "demo_session"}},
)

root_agent = Agent(
    name="keyguard_demo",
    model=os.getenv("MODEL_NAME", "gemini-2.5-flash"),
    instruction=(
        "You help the user call APIs. Secrets are referenced only by keyguard:// handles "
        "(see list_secrets). Never ask the user to type secrets or PINs in chat; use store_secret, "
        "which opens a secure dialog. Never try to reveal secret values."
    ),
    tools=[call_api, login, *kg.tools],
    before_tool_callback=kg.before_tool_callback,
    after_tool_callback=kg.after_tool_callback,
    before_model_callback=kg.before_model_callback,
)
