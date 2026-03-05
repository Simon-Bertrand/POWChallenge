"""
POW Captcha Server — Public API

All domain errors are available at the top level of this package so that
users can import them without knowing the internal module structure:

    from powchallenge_server import POWCaptchaServer, ChallengeNotFoundOrExpired
"""

from powchallenge_server.core import (
    POWCaptchaServer,
    POWCaptchaError,
    ChallengeNotFoundOrExpired,
    DifficultyMismatch,
    InvalidProofOfWork,
    ChallengeAlreadyActive,
    ServerBusy,
)
from powchallenge_server.interfaces import (
    CaptchaResponse,
    CaptchaValidatedPOW,
    IPAddress,
    Difficulty,
    ChallengeB64,
    NonceB64,
)
from powchallenge_server.storage import (
    StorageBackend,
    MemoryStorage,
    RedisStorage,
    ChallengeState,
)

__all__ = [
    # Server
    "POWCaptchaServer",
    # Errors
    "POWCaptchaError",
    "ChallengeNotFoundOrExpired",
    "DifficultyMismatch",
    "InvalidProofOfWork",
    "ChallengeAlreadyActive",
    "ServerBusy",
    # Wire-format models
    "CaptchaResponse",
    "CaptchaValidatedPOW",
    # Type aliases
    "IPAddress",
    "Difficulty",
    "ChallengeB64",
    "NonceB64",
    # Storage
    "StorageBackend",
    "MemoryStorage",
    "RedisStorage",
    "ChallengeState",
]
