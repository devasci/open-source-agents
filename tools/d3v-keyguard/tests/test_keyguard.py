import json
import types

import pytest

from d3v_keyguard.adk import KeyguardADK
from d3v_keyguard.crypto import KdfParams
from d3v_keyguard.errors import LockedOut, SecretPending, TamperDetected, VaultLocked, WrongPin
from d3v_keyguard.policy import Policy
from d3v_keyguard.redact import SecretValue, mask
from d3v_keyguard.vault import Vault

FAST = KdfParams(iterations=1, lanes=1, memory_cost=8)
PIN = "correct-horse"
SECRET = "sk-live-1234567890abcdef"


class FakeKeyring:
    def __init__(self):
        self.store = {}

    def get_password(self, service, user):
        return self.store.get((service, user))

    def set_password(self, service, user, pw):
        self.store[(service, user)] = pw


class FakePrompt:
    def __init__(self, answers=None, confirm=True):
        self.answers = list(answers or [])
        self.asked = []
        self._confirm = confirm

    def ask_secret(self, title, message):
        self.asked.append(message)
        return self.answers.pop(0)

    def confirm(self, title, message):
        return self._confirm


@pytest.fixture
def vault(tmp_path):
    v = Vault(tmp_path / "vault.json", keyring_backend=FakeKeyring(), kdf_params=FAST)
    v.create(PIN)
    return v


def test_store_locked_is_pending_then_approved(vault):
    vault.lock()
    assert vault.put("api", SECRET) == "pending"
    with pytest.raises(VaultLocked):
        vault.get("api")
    assert vault.unlock(PIN) == ["api"]
    with pytest.raises(SecretPending):
        vault.get("api")
    assert vault.approve(["api"]) == ["api"]
    assert vault.get("api").reveal() == SECRET


def test_store_unlocked_is_active_and_plaintext_not_on_disk(vault):
    assert vault.put("api", SECRET) == "active"
    assert SECRET not in vault.path.read_text()
    assert vault.get("api").reveal() == SECRET


def test_wrong_pin_backoff_and_lockout(vault):
    vault.lock()
    for _ in range(3):
        with pytest.raises(WrongPin):
            vault.unlock("wrong-pin")
    with pytest.raises(LockedOut):
        vault.unlock(PIN)
    data = json.loads(vault.path.read_text())
    data["failed_attempts"] = 10
    vault.path.write_text(json.dumps(data))  # counter is outside the header MAC by design
    with pytest.raises(LockedOut):
        vault.unlock(PIN)
    vault.unlock(PIN, human_reset=True)
    assert vault.is_unlocked()


def test_public_key_substitution_detected(vault, tmp_path):
    other = Vault(tmp_path / "other.json", keyring_backend=FakeKeyring(), kdf_params=FAST)
    other.create(PIN)
    data = json.loads(vault.path.read_text())
    data["public_key"] = json.loads(other.path.read_text())["public_key"]
    vault.path.write_text(json.dumps(data))
    with pytest.raises(TamperDetected):
        vault.put("x", SECRET)


def test_planted_entry_and_swapped_ciphertext_rejected(vault):
    vault.put("a", SECRET)
    vault.put("b", "another-secret-value-xyz")
    data = json.loads(vault.path.read_text())
    data["entries"]["a"]["box"] = data["entries"]["b"]["box"]
    vault.path.write_text(json.dumps(data))
    with pytest.raises(TamperDetected):
        vault.get("a")


def test_kdf_downgrade_rejected(tmp_path):
    kr = FakeKeyring()
    weak = Vault(tmp_path / "v.json", keyring_backend=kr, kdf_params=FAST)
    weak.create(PIN)
    with pytest.raises(TamperDetected):
        Vault(tmp_path / "v.json", keyring_backend=kr).status()


def test_change_pin(vault):
    vault.put("api", SECRET)
    vault.change_pin(PIN, "new-pin-123")
    vault.lock()
    with pytest.raises(WrongPin):
        vault.unlock(PIN)
    vault.unlock("new-pin-123")
    assert vault.get("api").reveal() == SECRET


def test_idle_timeout_locks(tmp_path):
    now = [0.0]
    v = Vault(tmp_path / "v.json", keyring_backend=FakeKeyring(), kdf_params=FAST,
              idle_timeout=10, clock=lambda: now[0])
    v.create(PIN)
    assert v.is_unlocked()
    now[0] = 11
    assert not v.is_unlocked()


def test_secret_value_masked():
    s = SecretValue("api", SECRET)
    assert SECRET not in repr(s) and SECRET not in str(s) and SECRET not in f"{s}"
    assert mask("short") == "****[5 chars]"


class Tool:
    def __init__(self, name):
        self.name = name


def test_adk_injection_policy_and_redaction(vault):
    vault.put("demo_api", SECRET)
    vault.lock()
    prompt = FakePrompt([PIN])
    kg = KeyguardADK(vault=vault, policy=Policy({"call_api": ["demo_*"]}), prompt=prompt)

    args = {"url": "https://x", "headers": {"Authorization": "Bearer keyguard://demo_api"}}
    assert kg.before_tool_callback(Tool("call_api"), args, None) is None
    assert args["headers"]["Authorization"] == f"Bearer {SECRET}"

    denied = kg.before_tool_callback(Tool("web_fetch"), {"q": "keyguard://demo_api"}, None)
    assert denied["status"] == "error" and SECRET not in json.dumps(denied)

    out = kg.after_tool_callback(Tool("call_api"), args, None, {"echo": f"token={SECRET}"})
    assert SECRET not in json.dumps(out)

    from google.genai import types as gt
    req = types.SimpleNamespace(contents=[gt.Content(role="user", parts=[gt.Part(text=f"leak {SECRET}")])])
    kg.before_model_callback(None, req)
    assert SECRET not in req.contents[0].parts[0].text


def test_adk_capture_and_tools_never_return_plaintext(vault):
    kg = KeyguardADK(vault=vault, policy=Policy(), capture={"login": {"session_token": "sess"}},
                     prompt=FakePrompt([SECRET]))
    out = kg.after_tool_callback(Tool("login"), {}, None, {"session_token": "tok-abcdefghijklmnop"})
    assert out["session_token"] == "keyguard://sess"
    tools = {t.__name__: t for t in kg.tools}
    stored = tools["store_secret"]("gh", "github token")
    assert stored["status"] == "success"
    for result in (tools["list_secrets"](), tools["describe_secret"]("gh"), tools["vault_status"]()):
        dumped = json.dumps(result)
        assert SECRET not in dumped and "tok-abcdefghijklmnop" not in dumped
    assert tools["store_secret"]("x", value="leaky-value")["status"] == "error"


def test_adk_function_tools_build():
    from google.adk.tools import FunctionTool

    kg = KeyguardADK(vault=Vault("unused.json", keyring_backend=FakeKeyring()), policy=Policy(),
                     prompt=FakePrompt())
    for fn in kg.tools:
        assert FunctionTool(fn)._get_declaration().name == fn.__name__
