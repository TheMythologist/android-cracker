from dataclasses import dataclass
from typing import Optional


@dataclass
class PasswordProperty:
    upper: int
    lower: int
    number: int
    symbol: int


@dataclass
class DevicePolicy:
    length: int
    filter: Optional[PasswordProperty] = None
