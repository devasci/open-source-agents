"""Exception hierarchy. Messages never contain secret values or PINs."""


class KeyguardError(Exception):
    """Base error for d3v-keyguard."""


class VaultNotFound(KeyguardError):
    pass


class VaultExists(KeyguardError):
    pass


class VaultLocked(KeyguardError):
    pass


class WrongPin(KeyguardError):
    pass


class LockedOut(KeyguardError):
    pass


class TamperDetected(KeyguardError):
    pass


class SecretNotFound(KeyguardError):
    pass


class SecretPending(KeyguardError):
    pass


class PolicyDenied(KeyguardError):
    pass


class InsecureBackend(KeyguardError):
    pass


class PromptCancelled(KeyguardError):
    pass
