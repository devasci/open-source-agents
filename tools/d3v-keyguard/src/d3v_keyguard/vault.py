"""PIN-protected envelope vault.

Storing seals to the vault public key (no PIN). Retrieval needs the private key,
which is only available after unlocking with PIN + OS-keyring pepper (Argon2id).
"""

from __future__ import annotations

import atexit
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import uuid
import weakref
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import crypto
from .crypto import DEFAULT_KDF, FORMAT, KdfParams, b64d, b64e, canonical
from .errors import (
    InsecureBackend,
    LockedOut,
    SecretNotFound,
    SecretPending,
    TamperDetected,
    VaultExists,
    VaultLocked,
    VaultNotFound,
    WrongPin,
)
from .redact import SecretValue, valid_name

SERVICE = "d3v-keyguard"
BACKOFF_AFTER = 3
LOCKOUT_AFTER = 10
_SECURE_BACKENDS = {
    "keyring.backends.Windows",
    "keyring.backends.macOS",
    "keyring.backends.SecretService",
    "keyring.backends.libsecret",
    "keyring.backends.kwallet",
}
_OPEN_VAULTS: "weakref.WeakSet[Vault]" = weakref.WeakSet()


def default_vault_path() -> Path:
    env = os.environ.get("KEYGUARD_VAULT_PATH")
    if env:
        return Path(env)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "d3v-keyguard" / "vault.json"


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def secure_keyring_backend():
    """Return the platform keyring backend, refusing insecure/plaintext ones."""
    import keyring

    backend = keyring.get_keyring()
    candidates = getattr(backend, "backends", [backend])  # unwrap ChainerBackend
    for b in candidates:
        if type(b).__module__ in _SECURE_BACKENDS:
            return b
    raise InsecureBackend(
        f"no secure OS keyring backend available (found {type(backend).__module__}); refusing to run"
    )


class Vault:
    def __init__(
        self,
        path: str | os.PathLike | None = None,
        *,
        keyring_backend: Any = None,
        kdf_params: KdfParams | None = None,
        idle_timeout: float | None = None,
        max_session: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.path = Path(path) if path else default_vault_path()
        self._backend = keyring_backend
        # Lower-cost KDF params are only accepted via this explicit constructor argument (tests).
        self._kdf = kdf_params or DEFAULT_KDF
        self.idle_timeout = idle_timeout if idle_timeout is not None else _env_float("KEYGUARD_IDLE_TIMEOUT", 300)
        self.max_session = max_session if max_session is not None else _env_float("KEYGUARD_MAX_SESSION", 3600)
        self._clock = clock
        self._lock = threading.RLock()
        self._priv: bytearray | None = None
        self._endorse: bytearray | None = None
        self._pub: bytes | None = None
        self._unlocked_at = 0.0
        self._last_used = 0.0
        self.on_lock: list[Callable[[], None]] = []
        _OPEN_VAULTS.add(self)

    # ---------------------------------------------------------------- storage
    def _keyring(self):
        if self._backend is None:
            self._backend = secure_keyring_backend()
        return self._backend

    def _pepper(self, vault_id: str, create: bool = False) -> bytes:
        account = f"pepper:{vault_id}"
        value = self._keyring().get_password(SERVICE, account)
        if value is None:
            if not create:
                raise TamperDetected("OS keyring pepper for this vault is missing")
            raw = secrets.token_bytes(32)
            self._keyring().set_password(SERVICE, account, b64e(raw))
            return raw
        return b64d(value)

    def exists(self) -> bool:
        return self.path.exists()

    def _read(self) -> dict:
        if not self.path.exists():
            raise VaultNotFound(f"no vault at {self.path}; run 'd3v-keyguard init'")
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if data.get("format") != FORMAT:
            raise TamperDetected("unsupported or altered vault format")
        params = KdfParams(**data["kdf"]["params"])
        if not params.at_least(self._kdf):
            raise TamperDetected("vault KDF parameters are weaker than required (possible downgrade)")
        pepper = self._pepper(data["vault_id"])
        if not crypto.mac_ok(self._header_key(pepper), self._header_bytes(data), data["header_mac"]):
            raise TamperDetected("vault header MAC mismatch (file modified outside d3v-keyguard)")
        return data

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.path.parent, 0o700)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".vault-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            if os.name == "posix":
                os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    @staticmethod
    def _header_key(pepper: bytes) -> bytes:
        return crypto.hkdf(pepper, b"d3v-keyguard/1 header-mac")

    @staticmethod
    def _header_bytes(data: dict) -> bytes:
        return canonical(data["format"], data["vault_id"], data["kdf"], data["public_key"], data["wrapped"])

    @staticmethod
    def _wrap_aad(data: dict) -> bytes:
        return canonical("wrap", data["format"], data["vault_id"], data["kdf"])

    @staticmethod
    def _entry_aad(data: dict, name: str, fp: str) -> bytes:
        return canonical("entry", data["format"], data["vault_id"], name, fp)

    @staticmethod
    def _endorse_bytes(data: dict, name: str, e: dict) -> bytes:
        return canonical("endorse", data["vault_id"], name, e["box"], e["fp"], e["metadata"], e["created"])

    # ------------------------------------------------------------- lifecycle
    def create(self, pin: str) -> None:
        with self._lock:
            if self.path.exists():
                raise VaultExists(f"vault already exists at {self.path}")
            _check_pin(pin)
            vault_id = str(uuid.uuid4())
            pepper = self._pepper(vault_id, create=True)
            priv = X25519PrivateKey.generate()
            pub_raw = crypto.pub_bytes(priv.public_key())
            endorse = secrets.token_bytes(32)
            salt = secrets.token_bytes(16)
            data: dict = {
                "format": FORMAT,
                "vault_id": vault_id,
                "kdf": {"alg": "argon2id", "salt": b64e(salt), "params": self._kdf.as_dict()},
                "public_key": b64e(pub_raw),
                "entries": {},
                "failed_attempts": 0,
                "last_failed_at": 0,
            }
            kek = crypto.derive_kek(pin, salt, pepper, self._kdf)
            inner = json.dumps(
                {"priv": b64e(crypto.priv_bytes(priv)), "pub": b64e(pub_raw), "endorse": b64e(endorse)}
            ).encode()
            data["wrapped"] = crypto.aead_encrypt(kek, inner, self._wrap_aad(data))
            data["header_mac"] = crypto.mac(self._header_key(pepper), self._header_bytes(data))
            self._write(data)
            self._set_session(crypto.priv_bytes(priv), endorse, pub_raw)

    def _set_session(self, priv: bytes, endorse: bytes, pub: bytes) -> None:
        self._priv, self._endorse, self._pub = bytearray(priv), bytearray(endorse), pub
        self._unlocked_at = self._last_used = self._clock()

    def is_unlocked(self) -> bool:
        with self._lock:
            if self._priv is None:
                return False
            now = self._clock()
            if now - self._last_used > self.idle_timeout or now - self._unlocked_at > self.max_session:
                self.lock()
                return False
            return True

    def lock(self) -> None:
        with self._lock:
            crypto.wipe(self._priv)
            crypto.wipe(self._endorse)
            self._priv = self._endorse = self._pub = None
            for cb in list(self.on_lock):
                cb()

    def unlock(self, pin: str, *, human_reset: bool = False) -> list[str]:
        """Unlock with the PIN. Returns names of pending entries awaiting approval."""
        with self._lock:
            data = self._read()
            fails = int(data.get("failed_attempts", 0))
            if fails >= LOCKOUT_AFTER and not human_reset:
                raise LockedOut(
                    f"{fails} failed attempts; run 'd3v-keyguard reset-lockout' in a terminal"
                )
            if fails >= BACKOFF_AFTER and not human_reset:
                wait = min(2 ** (fails - BACKOFF_AFTER) * 5, 900) - (time.time() - data.get("last_failed_at", 0))
                if wait > 0:
                    raise LockedOut(f"too many failed attempts; retry in {int(wait) + 1}s")
            pepper = self._pepper(data["vault_id"])
            kek = crypto.derive_kek(
                pin, b64d(data["kdf"]["salt"]), pepper, KdfParams(**data["kdf"]["params"])
            )
            try:
                inner = json.loads(crypto.aead_decrypt(kek, data["wrapped"], self._wrap_aad(data)))
            except InvalidTag:
                data["failed_attempts"] = fails + 1
                data["last_failed_at"] = time.time()
                self._write(data)
                raise WrongPin(f"wrong PIN ({fails + 1} consecutive failures)") from None
            priv_raw, pinned_pub = b64d(inner["priv"]), b64d(inner["pub"])
            derived = crypto.pub_bytes(X25519PrivateKey.from_private_bytes(priv_raw).public_key())
            if derived != pinned_pub or b64d(data["public_key"]) != pinned_pub:
                raise TamperDetected("vault public key was substituted; do not store new secrets")
            if fails:
                data["failed_attempts"] = 0
                data["last_failed_at"] = 0
                self._write(data)
            self._set_session(priv_raw, b64d(inner["endorse"]), pinned_pub)
            return self._pending_names(data)

    def change_pin(self, old_pin: str, new_pin: str) -> None:
        with self._lock:
            _check_pin(new_pin)
            self.unlock(old_pin)
            data = self._read()
            pepper = self._pepper(data["vault_id"])
            salt = secrets.token_bytes(16)
            data["kdf"] = {"alg": "argon2id", "salt": b64e(salt), "params": self._kdf.as_dict()}
            kek = crypto.derive_kek(new_pin, salt, pepper, self._kdf)
            inner = json.dumps(
                {"priv": b64e(bytes(self._priv)), "pub": b64e(self._pub), "endorse": b64e(bytes(self._endorse))}
            ).encode()
            data["wrapped"] = crypto.aead_encrypt(kek, inner, self._wrap_aad(data))
            data["header_mac"] = crypto.mac(self._header_key(pepper), self._header_bytes(data))
            self._write(data)

    # --------------------------------------------------------------- entries
    def _entry_state(self, data: dict, name: str, e: dict) -> str:
        if e.get("fp") != crypto.fingerprint(b64d(data["public_key"])):
            return "tampered"
        if not e.get("tag"):
            return "pending"
        if self._endorse is not None and not crypto.mac_ok(
            bytes(self._endorse), self._endorse_bytes(data, name, e), e["tag"]
        ):
            return "tampered"
        return "active"

    def _pending_names(self, data: dict) -> list[str]:
        return sorted(n for n, e in data["entries"].items() if self._entry_state(data, n, e) == "pending")

    def put(self, name: str, value: str, metadata: dict | None = None) -> str:
        """Seal a secret. Returns 'active', or 'pending' if stored while locked."""
        if not valid_name(name):
            raise ValueError("invalid secret name (use letters, digits, '_', '-', '.')")
        if not isinstance(value, str) or not value:
            raise ValueError("secret value must be a non-empty string")
        meta = {str(k): str(v)[:200] for k, v in (metadata or {}).items()}
        with self._lock:
            unlocked = self.is_unlocked()
            if not unlocked and os.environ.get("KEYGUARD_STORE_REQUIRES_UNLOCK") == "1":
                raise VaultLocked("strict mode: unlock the vault before storing secrets")
            data = self._read()
            pub = self._pub if unlocked else b64d(data["public_key"])
            fp = crypto.fingerprint(pub)
            entry = {
                "box": crypto.seal(pub, value.encode("utf-8"), self._entry_aad(data, name, fp)),
                "fp": fp,
                "metadata": meta,
                "created": int(time.time()),
                "tag": None,
            }
            if unlocked:
                entry["tag"] = crypto.mac(bytes(self._endorse), self._endorse_bytes(data, name, entry))
                self._last_used = self._clock()
            data["entries"][name] = entry
            self._write(data)
            return "active" if unlocked else "pending"

    def list(self) -> list[dict]:
        with self._lock:
            self.is_unlocked()
            data = self._read()
            return [
                {
                    "name": n,
                    "status": self._entry_state(data, n, e),
                    "metadata": e.get("metadata", {}),
                    "created": e.get("created"),
                }
                for n, e in sorted(data["entries"].items())
            ]

    def get(self, name: str) -> SecretValue:
        with self._lock:
            if not self.is_unlocked():
                raise VaultLocked("vault is locked")
            data = self._read()
            e = data["entries"].get(name)
            if e is None:
                raise SecretNotFound(f"no secret named {name!r}")
            state = self._entry_state(data, name, e)
            if state == "pending":
                raise SecretPending(f"{name!r} is pending approval ('d3v-keyguard approve')")
            if state != "active":
                raise TamperDetected(f"{name!r} failed integrity checks")
            try:
                value = crypto.unseal(bytes(self._priv), e["box"], self._entry_aad(data, name, e["fp"]))
            except InvalidTag:
                raise TamperDetected(f"{name!r} failed integrity checks") from None
            self._last_used = self._clock()
            return SecretValue(name, value.decode("utf-8"))

    def pending(self) -> list[str]:
        with self._lock:
            return self._pending_names(self._read())

    def approve(self, names: list[str]) -> list[str]:
        """Endorse pending entries (requires unlock). Returns names approved."""
        with self._lock:
            if not self.is_unlocked():
                raise VaultLocked("vault is locked")
            data = self._read()
            done = []
            for n in names:
                e = data["entries"].get(n)
                if e is None or self._entry_state(data, n, e) != "pending":
                    continue
                try:
                    crypto.unseal(bytes(self._priv), e["box"], self._entry_aad(data, n, e["fp"]))
                except InvalidTag:
                    continue
                e["tag"] = crypto.mac(bytes(self._endorse), self._endorse_bytes(data, n, e))
                done.append(n)
            self._write(data)
            return done

    def delete(self, name: str) -> bool:
        with self._lock:
            data = self._read()
            if data["entries"].pop(name, None) is None:
                return False
            self._write(data)
            return True

    def status(self) -> dict:
        with self._lock:
            if not self.path.exists():
                return {"initialized": False, "unlocked": False, "path": str(self.path)}
            data = self._read()
            states = [self._entry_state(data, n, e) for n, e in data["entries"].items()]
            return {
                "initialized": True,
                "unlocked": self.is_unlocked(),
                "path": str(self.path),
                "secrets": len(states),
                "pending": states.count("pending"),
                "tampered": states.count("tampered"),
                "failed_attempts": int(data.get("failed_attempts", 0)),
            }


def _check_pin(pin: str) -> None:
    if not isinstance(pin, str) or len(pin) < 6:
        raise ValueError("PIN/password must be at least 6 characters")


@atexit.register
def _lock_all() -> None:
    for v in list(_OPEN_VAULTS):
        try:
            v.lock()
        except Exception:
            pass
