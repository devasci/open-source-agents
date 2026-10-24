# d3v-keyguard: Google ADK integration

## Install

```bash
pip install -e "tools/d3v-keyguard[adk]"   # pulls google-adk>=2.13
d3v-keyguard init                          # one-time; the user sets a PIN
```

## Components of `KeyguardADK`

```python
from d3v_keyguard.adk import KeyguardADK
from d3v_keyguard.policy import Policy

kg = KeyguardADK(
    policy=Policy({"call_api": ["demo_*"], "deploy": ["deploy_token"]}),
    capture={"login": {"session_token": "demo_session"}},
)
```

| Member | Wire to | What it does |
| :--- | :--- | :--- |
| `kg.tools` | `Agent(tools=[..., *kg.tools])` | `vault_status`, `list_secrets`, `store_secret(name, description)`, `unlock_vault(reason)`, `lock_vault`, `describe_secret(name)` |
| `kg.before_tool_callback` | `Agent(before_tool_callback=...)` | Finds `keyguard://<name>` handles in tool arguments, checks the policy, and substitutes the real values |
| `kg.after_tool_callback` | `Agent(after_tool_callback=...)` | Seals the configured output fields into the vault and replaces them with handles. Scrubs any echoed secret values from the result. |
| `kg.before_model_callback` | `Agent(before_model_callback=...)` | Final redaction pass over the outbound LLM request |

Wire **all three callbacks**. Without `before_tool_callback`, your tools receive literal `keyguard://` strings. Without the other two, secrets returned by tools can reach the model.

## Full example

```python
import os
from google.adk.agents import Agent
from d3v_keyguard.adk import KeyguardADK
from d3v_keyguard.policy import Policy

def call_api(path: str, api_key: str) -> dict:
    """Call the demo API. api_key must be a keyguard:// handle."""
    ...  # receives the real key here, after substitution

def login(username: str, password: str) -> dict:
    """Log in; returns {'session_token': ...}."""
    ...

kg = KeyguardADK(
    policy=Policy({"call_api": ["demo_*"], "login": ["demo_password"]}),
    capture={"login": {"session_token": "demo_session"}},
)

root_agent = Agent(
    name="demo",
    model=os.getenv("MODEL_NAME", "gemini-2.5-flash"),
    instruction=(
        "Credentials are referenced only as keyguard://<name> handles. "
        "Never ask the user to type secrets or PINs in chat; use store_secret and unlock_vault."
    ),
    tools=[call_api, login, *kg.tools],
    before_tool_callback=kg.before_tool_callback,
    after_tool_callback=kg.after_tool_callback,
    before_model_callback=kg.before_model_callback,
)
```

If you also use a `call_api` with a `session` argument, allow it: `Policy({"call_api": ["demo_*"]})` already covers `demo_session`.

## Policy

- **Deny by default**: a tool receives a secret only if the tool name maps to a matching pattern. Patterns are glob-style (`prod_*`, `*_token`, exact names).
- Denied substitutions raise a policy error to the model instead of calling the tool with a value.
- Load from a file with `KEYGUARD_POLICY_FILE=/path/policy.json`:
  ```json
  { "call_api": ["prod_*", "demo_*"], "login": ["demo_password"] }
  ```
- Keep policies narrow. Do not give generic tools such as `http_get` or `run_shell` broad patterns like `*`, because the model chooses the URL or command.

## Capture

`capture={tool_name: {output_field: secret_name}}`

- After `tool_name` returns, `output_field` is sealed into the vault as `secret_name`, and the result the model sees contains `keyguard://secret_name` in its place.
- Captured entries are created by the agent process while it is unlocked. Entries stored while locked are subject to pending approval as usual.
- Any known secret value echoed elsewhere in a tool result is scrubbed.

## LLM-supplied values

`store_secret(name, value=...)` is accepted only when `KEYGUARD_ALLOW_LLM_VALUES=1`. The value has then passed through the model provider and the transcript, so the tool returns a warning to rotate the secret. Keep this off.

## Unlock flow inside ADK

1. The model calls `unlock_vault(reason="...")`, or a callback needs a secret while the vault is locked.
2. A masked tkinter PIN dialog opens in an isolated subprocess (`KEYGUARD_PROMPT=auto|gui|tty`, with a hidden terminal prompt as fallback). The agent-supplied reason is labeled as unverified.
3. Any pending entries are shown for approval. Approved entries get an HMAC endorsement tag.
4. Keys stay in the agent process memory until idle timeout (`KEYGUARD_IDLE_TIMEOUT`, 300 s), maximum session length (`KEYGUARD_MAX_SESSION`, 3600 s) or `lock_vault()`.

The prompt blocks the event loop while it waits, so the ADK web UI stalls until the dialog closes. This is a known limitation.

## Non-ADK Python code

```python
from d3v_keyguard import Vault
from d3v_keyguard.prompt import default_prompt

vault = Vault()
vault.unlock(default_prompt().ask_secret("d3v-keyguard", "Vault PIN:"))
secret = vault.get("demo_api_key")   # SecretValue
print(secret)                        # masked
requests.get(url, headers={"Authorization": f"Bearer {secret.reveal()}"})
```

Call `.reveal()` only at the point of use, and never log its result.

## Running the demo

```bash
# examples/adk_demo_agent/.env
GOOGLE_API_KEY=...
MODEL_NAME=gemini-2.5-flash

cd tools/d3v-keyguard/examples
adk web                 # or: adk run adk_demo_agent
```

Status: the demo has not been live-tested against a model yet. The unit tests (`pytest tests`) cover the callbacks offline with a fake keyring and fake prompts.

## Troubleshooting

| Symptom | Cause / fix |
| :--- | :--- |
| Tool receives the literal `keyguard://x` | `before_tool_callback` is not wired |
| Policy denied | Add a `tool -> pattern` rule for that tool |
| Secret pending | The user approves it at the next unlock (or with `d3v-keyguard approve`) |
| Locked out | A human runs `d3v-keyguard reset-lockout` at a terminal |
| Insecure keyring backend | Install or enable a real OS keyring (Secret Service on Linux) |
| No dialog appears | tkinter is missing or there is no display; set `KEYGUARD_PROMPT=tty` |
