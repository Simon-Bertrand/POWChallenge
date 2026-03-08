

from pydantic import UUID7
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from pydantic import BaseModel, Field

class CaptchaResponse(BaseModel):
    challenge: str
    difficulty: int = Field(ge=1, le=256)
    req_id : UUID7

class CaptchaRequestState(BaseModel):
    challenge: bytes
    ip: IPv4Address | IPv6Address
    timestamp : datetime
    difficulty: int = Field(ge=1, le=256)
    req_id : UUID7


class CaptchaValidatedPOW(BaseModel):
    req_id: UUID7
    challenge: str = Field(min_length=20, max_length=100)
    timestamp : datetime
    difficulty: int = Field(ge=1, le=256)
    nonce: str = Field(min_length=1, max_length=200)