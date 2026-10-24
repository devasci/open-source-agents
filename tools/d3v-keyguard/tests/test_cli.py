import sys

import pytest

from d3v_keyguard import cli
from d3v_keyguard.crypto import KdfParams
from d3v_keyguard.vault import Vault

from test_keyguard import FakeKeyring, FakePrompt

PIN = "correct-horse"
SECRET = "ghp_cli0123456789abcdefXYZ"


@pytest.fixture
def cli_vault(tmp_path, monkeypatch):
    kr = FakeKeyring()
    path = tmp_path / "vault.json"
    v = Vault(path, keyring_backend=kr, kdf_params=KdfParams(1, 1, 8))
    v.create(PIN)
    v.put("gh", SECRET)
    v.lock()
    monkeypatch.setattr(cli, "Vault", lambda *a, **k: Vault(path, keyring_backend=kr, kdf_params=KdfParams(1, 1, 8)))
    monkeypatch.setattr(cli, "_prompt", lambda: FakePrompt([PIN, PIN, PIN]))
    return path


def test_exec_injects_env_and_redacts_output(cli_vault, capfd):
    code = cli.main([
        "exec", "--env", "TOKEN=keyguard://gh", "--",
        sys.executable, "-c", "import os,sys; print('got', os.environ['TOKEN']); sys.exit(3)",
    ])
    out = capfd.readouterr().out
    assert code == 3
    assert SECRET not in out and "[REDACTED:keyguard://gh]" in out


def test_list_shows_handles_not_values(cli_vault, capfd):
    assert cli.main(["list"]) == 0
    out = capfd.readouterr().out
    assert "keyguard://gh\tactive" in out and SECRET not in out


def test_reveal_refused_when_piped(cli_vault, capfd):
    assert cli.main(["reveal", "gh"]) == 2
    captured = capfd.readouterr()
    assert SECRET not in captured.out + captured.err


def test_exec_rejects_bad_env_spec(cli_vault, capfd):
    assert cli.main(["exec", "--env", "TOKEN=gh", "--", sys.executable, "-c", "0"]) == 2
