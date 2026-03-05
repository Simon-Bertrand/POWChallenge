from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Union
from uuid import UUID

from pydantic import UUID7, BaseModel, Field

# ──────────────────────────────────────────────────────────────────────────────
# Shared type aliases
# ──────────────────────────────────────────────────────────────────────────────

IPAddress = Union[IPv4Address, IPv6Address]

# Difficulty is always an integer in [1, 256].
# 1 leading zero bit → easy; 256 → 256 bits of leading zeros (impossible in practice).
Difficulty = Annotated[int, Field(ge=1, le=256)]

# Base64-encoded challenge: 32 bytes → base64 is exactly 44 chars.
ChallengeB64 = Annotated[str, Field(min_length=44, max_length=44)]

# Base64-encoded nonce: client uses 32 bytes → 44 chars; we cap at 64 bytes (88 chars)
# as a DoS guard against arbitrarily large Argon2 inputs.
NonceB64 = Annotated[str, Field(min_length=1, max_length=88)]


# ──────────────────────────────────────────────────────────────────────────────
# Wire-format models
# ──────────────────────────────────────────────────────────────────────────────

class CaptchaResponse(BaseModel):
    """Response returned by GET /challenge."""
    challenge: ChallengeB64
    difficulty: Difficulty
    req_id: UUID7


class CaptchaValidatedPOW(BaseModel):
    """Request body sent to POST /verify."""
    req_id: UUID7
    challenge: ChallengeB64
    # ISO-8601 timestamp sent by the client; kept as a string so we
    # accept any timezone-aware representation without parsing overhead.
    timestamp: str = Field(min_length=1, max_length=64)
    difficulty: Difficulty
    nonce: NonceB64