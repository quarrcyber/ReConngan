from dataclasses import dataclass
from collections.abc import Callable


@dataclass
class HeaderRule:
    name: str
    severity: str
    weight: int
    attack: str
    validator: Callable[[str | None], tuple[str, str]]


@dataclass
class Finding:
    header: str
    status: str
    severity: str
    weight: int
    note: str
    attack: str
    evidence: str

@dataclass
class HttpMetadata:
    http_version: str
    response_time_ms: float
    content_type: str
    content_length: str
