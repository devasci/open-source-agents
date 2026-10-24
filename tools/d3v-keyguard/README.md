# d3v-keyguard

> A PIN-protected local secret vault for LLM agents. Agents can store and use passwords, API keys, tokens and session ids without the model ever seeing the plaintext.

---

## Overview

### Problem Statement & Intended Users
- **Problem**: Agents need credentials to call APIs, log in, and run commands. The usual approaches (pasting secrets into chat, `.env` files the agent can read, secrets echoed back in tool output) put plaintext into the model context, logs and transcripts, where prompt injection can exfiltrate it.
- **Intended Users**: Developers building agents with Google ADK (primary target), and users of shell-based agent harnesses (Claude Code, Codex, Gemini CLI) that support Agent Skills.

### Key Features
- **Handles, not values**: the LLM only sees `keyguard://<name>` handles and masked previews. Real values are substituted at tool-call time, outside the model.
- **Store without PIN, use with PIN**: entries are sealed to the vault's public key, so an agent can save a new secret while the vault is locked. Using a secret requires unlocking with the PIN.
- **Secure PIN entry**: the PIN is never typed into the chat. A masked tkinter dialog opens in an isolated subprocess, with a hidden terminal prompt as fallback.
- **Pending approval**: entries stored while locked stay unusable until the user approves them at the next unlock. This blocks planted entries.
- **Deny-by-default policy**: each tool may receive only the secrets you allow, e.g. `Policy({"call_api": ["prod_*"]})`.
- **Output capture and scrubbing**: session tokens returned by tools (for example a `login` tool) are sealed into the vault and replaced with handles. Echoed secret values are scrubbed, and a final redaction pass runs on every outbound LLM request.
- **`exec` for shell harnesses**: `d3v-keyguard exec --env VAR=keyguard://name -- cmd` injects secrets into a child process environment and redacts them from its output.
- **Lockout**: backoff after 3 wrong PINs. After 10, agent-driven unlocks are refused until a human runs `d3v-keyguard reset-lockout` at a terminal.

---

## Technical Stack

- **Language & Runtime**: Python 3.10+
- **Agent Framework / Core Library**: Google ADK (`google-adk>=2.13`, optional `[adk]` extra); Agent Skills standard (`skills/d3v-keyguard/SKILL.md`)
- **Crypto / OS integration**: `cryptography>=44` (Argon2id, X25519, HKDF-SHA256, AES-256-GCM, HMAC), `keyring>=25` (Windows Credential Manager/DPAPI, macOS Keychain, Linux Secret Service)
- **Models**: model-agnostic. The demo uses `gemini-2.5-flash` by default.
- **UI**: tkinter (masked PIN and secret input dialogs)

---

## Architecture & Data Flow

```
                    +---------------- OS keyring ----------------+
                    |  32-byte random pepper (per vault)         |
                    +--------------------+-----------------------+
                                         |
 PIN (secure dialog) --> Argon2id(PIN, salt, secret=pepper) = KEK
                                         |
                    KEK AES-256-GCM-unwraps: X25519 private key,
                    pinned public key, endorsement key
                                         |
 store (no PIN): value --seal to public key--> vault.json entry (PENDING if locked)
 use   (PIN)   : entry --open with private key--> plaintext in process memory only

 ADK flow:
 [LLM] --tool call with keyguard://name--> before_tool_callback
            (policy check, substitute real value) --> [your tool]
 [your tool] --result--> after_tool_callback
            (capture token fields -> seal -> handle; scrub echoed values) --> [LLM]
 [outbound LLM request] --> before_model_callback (final redaction)
```

**Crypto details**
- Pepper: 32 random bytes in the OS keyring. Insecure keyring backends are refused.
- KEK: Argon2id (RFC 9106, pepper passed as the secret), 16-byte salt, 64 MiB, 3 iterations, 4 lanes.
- Entries: ephemeral X25519 + HKDF-SHA256 + AES-256-GCM. The AAD binds the format version, vault id, entry name and key fingerprint, so entries cannot be swapped or renamed.
- Integrity: approved entries carry an HMAC endorsement tag. Public-key substitution is detected at unlock against the pinned copy. A header MAC keyed from the pepper detects offline tampering.
- Session: unlocked keys exist only in process memory. The vault auto-locks after 300 s idle and after 3600 s total.

---

## Prerequisites

- Python 3.10+ and pip
- A working OS keyring (Windows Credential Manager, macOS Keychain, or a Linux Secret Service such as GNOME Keyring or KWallet)
- tkinter for the GUI prompt (optional; a hidden terminal prompt is used otherwise)
- For the ADK demo: a `GOOGLE_API_KEY`

---

## Installation & Setup

1. **Navigate to the project directory:**
   ```bash
   cd tools/d3v-keyguard
   ```

2. **Set up the virtual environment and install dependencies:**
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate

   pip install -r requirements.txt
   # or, from the repository root (editable, with ADK support):
   pip install -e "tools/d3v-keyguard[adk]"
   ```

3. **Create the vault** (you choose a PIN in a secure dialog):
   ```bash
   d3v-keyguard init
   ```

4. **Install the Agent Skill** (optional, for skill-aware harnesses):
   ```bash
   # Claude Code, per user:
   cp -r skills/d3v-keyguard ~/.claude/skills/
   # or per project:
   cp -r skills/d3v-keyguard <project>/.claude/skills/
   ```
   For other Agent-Skills harnesses, copy the `skills/d3v-keyguard` folder into that harness's skills directory.

5. **For the ADK demo**, create `examples/adk_demo_agent/.env`:
   ```bash
   GOOGLE_API_KEY=your-key-here
   MODEL_NAME=gemini-2.5-flash
   ```

---

## Configuration & Environment Variables

| Variable Name | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `KEYGUARD_VAULT_PATH` | No | OS data dir (see below) | Path of `vault.json` |
| `KEYGUARD_PROMPT` | No | `auto` | PIN prompt mode: `auto`, `gui`, `tty` |
| `KEYGUARD_IDLE_TIMEOUT` | No | `300` | Seconds of inactivity before auto-lock |
| `KEYGUARD_MAX_SESSION` | No | `3600` | Maximum unlocked session length in seconds |
| `KEYGUARD_POLICY_FILE` | No | *None* | JSON policy file mapping tool names to allowed secret name patterns |
| `KEYGUARD_ALLOW_LLM_VALUES` | No | `0` | `1` allows `store_secret(name, value=...)` from the LLM. Not recommended; rotate any such secret. |
| `KEYGUARD_STORE_REQUIRES_UNLOCK` | No | `0` | `1` = strict mode: storing also requires an unlocked vault |
| `GOOGLE_API_KEY` | Demo only | *None* | Gemini API key for the ADK demo |
| `MODEL_NAME` | Demo only | `gemini-2.5-flash` | Model used by the ADK demo |

Default vault location:
- Windows: `%LOCALAPPDATA%\d3v-keyguard\vault.json`
- macOS: `~/Library/Application Support/d3v-keyguard/`
- Linux: `$XDG_DATA_HOME/d3v-keyguard/` (usually `~/.local/share/d3v-keyguard/`)

Example policy file:
```json
{ "call_api": ["prod_*"], "deploy": ["deploy_token"] }
```

---

## How to Run

### CLI (`d3v-keyguard` or `python -m d3v_keyguard`)

```bash
d3v-keyguard init                         # create a vault and choose a PIN
d3v-keyguard add github_token --description "GitHub PAT"   # value entered in a secure prompt
d3v-keyguard list                         # handles, status (active/pending/tampered), descriptions
d3v-keyguard status                       # locked/unlocked, pending count, lockout state
d3v-keyguard approve                      # review and approve PENDING entries
d3v-keyguard rm github_token
d3v-keyguard change-pin
d3v-keyguard reset-lockout                # human-only, interactive terminal
d3v-keyguard reveal github_token          # interactive terminal only; refused when piped
d3v-keyguard lock                         # no-op note: each CLI process locks on exit

# Run a command with secrets injected into its environment:
d3v-keyguard exec --env GITHUB_TOKEN=keyguard://github_token -- gh repo list
```

`exec` redacts secret values from the child's output and returns the child's exit code. Each CLI call is a separate process, so each one asks for the PIN.

### Google ADK

```python
import os
from google.adk.agents import Agent
from d3v_keyguard.adk import KeyguardADK
from d3v_keyguard.policy import Policy

kg = KeyguardADK(
    policy=Policy({"call_api": ["demo_*"]}),
    capture={"login": {"session_token": "demo_session"}},
)

root_agent = Agent(
    name="demo",
    model=os.getenv("MODEL_NAME", "gemini-2.5-flash"),
    instruction="Use keyguard:// handles for credentials. Never ask for secrets in chat.",
    tools=[call_api, login, *kg.tools],
    before_tool_callback=kg.before_tool_callback,
    after_tool_callback=kg.after_tool_callback,
    before_model_callback=kg.before_model_callback,
)
```

Run the offline end-to-end demo (real ADK `InMemoryRunner`, scripted stand-in model, no API key needed):
```bash
cd tools/d3v-keyguard
python examples/offline_adk_demo.py
```

Run the live demo agent with Gemini (put `GOOGLE_API_KEY` in `examples/adk_demo_agent/.env`):
```bash
cd tools/d3v-keyguard/examples
adk web                 # or: adk run adk_demo_agent
```

See [skills/d3v-keyguard/references/adk-integration.md](skills/d3v-keyguard/references/adk-integration.md) for full wiring details.

### Plain Python

```python
from d3v_keyguard import Vault
from d3v_keyguard.prompt import default_prompt

vault = Vault()  # default per-user path, or Vault("path/to/vault.json")
vault.unlock(default_prompt().ask_secret("d3v-keyguard", "Vault PIN:"))  # PIN via secure dialog
secret = vault.get("github_token")   # SecretValue; str()/repr() are masked
headers = {"Authorization": f"Bearer {secret.reveal()}"}
```

---

## Example Input & Output

This is the **genuine, unedited output** of `python examples/offline_adk_demo.py` on Windows 11, Python 3.13, google-adk 2.13.0. It drives a real ADK `InMemoryRunner` with the real keyguard callbacks. Three things are scripted so it runs offline with no side effects, and the script says so:
- the model, which replays a fixed sequence of tool calls;
- the human's answers in the PIN dialog;
- the OS keyring, which is in-memory.

The script records every request sent to the model, plus the persisted session history, and checks both for plaintext.

### Example Input
```
User: Log me in as alice and call /v1/me.
(Before the run, the developer stored demo_api = a fake API key while the vault was LOCKED.)
Policy: {"call_api": ["demo_*"]}    Capture: {"login": {"session_token": "demo_session"}}
```

### Example Output
```
1) Developer stores demo_api while the vault is LOCKED (no PIN): pending
2) Agent run (what the LLM and session history see):
  LLM  -> login({"username": "alice"})
  tool -> login: {"status": "success", "user": "alice", "session_token": "keyguard://demo_session"}
  LLM  -> list_secrets({})
  tool -> list_secrets: {"status": "success", "secrets": [{"name": "demo_api", "status": "pending", "metadata": {"description": "demo API key"}, "created": 1792832239, "handle": "keyguard://demo_api"}, {"name": "demo_session", "status": "pending", "metadata": {"captured_from": "login"}, "created": 1792832240, "handle": "keyguard://demo_session"}]}
  LLM  -> call_api({"url": "https://api.example.com/v1/me", "authorization": "Bearer keyguard://demo_api"})
  [secure dialog] d3v-keyguard: unlock vault
    Requested by: tool 'call_api'
    Agent-provided reason (unverified): tool 'call_api' needs demo_api

    Enter your vault PIN/password. Never type it into the chat.
  [secure dialog] d3v-keyguard: approve pending secrets -> user clicks Yes
  tool -> call_api: {"status": "success", "url": "https://api.example.com/v1/me", "echoed_header": "Bearer [REDACTED:keyguard://demo_api]"}
  LLM  : Done: logged in, and called the API with your demo_api key (by handle).
3) Verification:
  call_api received the real key        : True
  login token captured into the vault   : ['demo_api', 'demo_session']
  plaintext in any model request        : False
  plaintext in persisted session history: False
  plaintext in vault file on disk       : False
```

What this shows:
- **Capture:** the session token from `login` was sealed into the vault and replaced by a handle before the model saw it.
- **Injection:** `call_api` received the real key, substituted in-process and allowed by the policy.
- **Redaction:** when the tool echoed the key back, it was redacted.
- **Approval:** both entries were stored while locked, so they were *pending* and only became usable after the user approved them in the unlock dialog.
- **No leaks:** no plaintext appears in model requests, session history, or the vault file.

---

## How to Test

```bash
cd tools/d3v-keyguard
pip install -r requirements.txt     # installs the package (editable) + google-adk + pytest
pytest -v                           # 17 tests, offline, ~10 s
python examples/offline_adk_demo.py # end-to-end ADK run; all three "plaintext in ..." lines must be False
```

Verified result (Windows 11, Python 3.13.9, google-adk 2.13.0, cryptography 46.0.7): **17 passed**.

| Area | Tests (`tests/`) |
| :--- | :--- |
| Vault crypto & lifecycle | storing while locked gives *pending*, which becomes usable after approve; no plaintext on disk; PIN change; idle auto-lock |
| Tamper resistance | public-key substitution, swapped ciphertext between entries, and downgraded Argon2 settings are all detected |
| Brute force | back-off after 3 wrong PINs, lockout after 10, human reset |
| ADK | handle injection; policy denial for an unlisted tool; redaction of tool output and outbound model request; login-token capture; no tool return contains plaintext; ADK `FunctionTool` declarations build; full `InMemoryRunner` end-to-end run with no plaintext in model requests or session history |
| CLI | `exec` injects env vars, redacts child output, and propagates the exit code; `list` shows handles only; `reveal` is refused when piped; bad `--env` specs are rejected |

The tests use an in-memory keyring and scripted prompts. A low Argon2 cost is passed through the constructor only, and production defaults can't be weakened through environment variables.

Manual check with the real OS keyring and dialog (run in your own terminal; this creates a `d3v-keyguard` entry in your OS credential store):
1. `d3v-keyguard init`, then `d3v-keyguard add demo_key`.
2. `d3v-keyguard list` shows `keyguard://demo_key  active`.
3. `d3v-keyguard exec --env K=keyguard://demo_key -- python -c "import os; print(os.environ['K'])"` prints `[REDACTED:keyguard://demo_key]`, not the plaintext.

---

## Known Limitations

- Zeroizing Python memory is best-effort. Copies of plaintext may stay in memory until garbage collection.
- Active malware running as the same user (keyloggers, reading process memory while the vault is unlocked) is out of scope. The tool protects against offline theft of the vault, and against other same-user processes silently reading the vault file or keyring entry.
- The CLI prompts for the PIN on every invocation. An ssh-agent style unlock broker is future work.
- The PIN prompt blocks the agent's event loop while it waits.
- There is no cross-process file locking yet, so concurrent writers can race.
- Tested on Windows only. macOS and Linux are untested.
- The ADK flow is verified end to end with a scripted stand-in model (`examples/offline_adk_demo.py`). The live Gemini demo agent (`examples/adk_demo_agent`) has not been run against a real model yet.
- The real tkinter dialog and OS keyring are exercised only by the manual check above, not by the automated tests.

---

## Security & Privacy Considerations

- **Secrets Handling**: Secrets are encrypted at rest (sealed to an X25519 public key, with a private key wrapped by an Argon2id-derived KEK that also depends on a pepper in the OS keyring). Plaintext exists only in process memory while the vault is unlocked, and only reaches tools that the policy allows.
- **Data Privacy**: The LLM provider receives handles and masked previews only. `before_model_callback` redacts known secret values from every outbound request as a safety net. The vault itself makes no network calls.
- **Safety**: `exec` runs the command you give it with secrets in its environment, so only run commands you trust. `reveal` refuses non-interactive use so agents cannot read values through a pipe. LLM-supplied secret values are disabled by default. Entries planted while the vault is locked need explicit user approval. After 10 failed PINs, agent unlocks are refused until a human resets the lockout.

---

## Future Improvements

- [ ] MCP server so non-ADK agents get the same handle-based tools
- [ ] Unlock broker daemon (ssh-agent style) so CLI calls share one session
- [ ] TPM / Secure Enclave key protection
- [ ] Cloud KMS backends
- [ ] Cross-process file locking
- [ ] macOS and Linux test coverage; live-tested ADK demo

---

## License

*This project is contributed under the repository's open-source license.*
