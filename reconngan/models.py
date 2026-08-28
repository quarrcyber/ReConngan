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

@dataclass
class CookieInfo:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None
    path: str | None
    domain: str | None

@dataclass
class CookieFinding:
    cookie: str
    check: str
    status: str
    severity: str
    note: str
    evidence: str

@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str | None

#-------------------------Web Resources--------------------------
@dataclass
class WebResource:
    name: str
    url: str
    status_code: int | None
    content_type: str | None
    found: bool
    body: str | None
    error: str | None

@dataclass
class RobotsInfo:
    disallow: list[str]
    allow: list[str]
    sitemaps: list[str]

@dataclass
class SitemapInfo:
    urls: list[str]
    sitemaps: list[str]
    error: str | None

@dataclass
class SecurityTxtInfo:
    contacts: list[str]
    canonical: list[str]
    policy: list[str]
    acknowledgments: list[str]
    expires: str | None
    preferred_languages: list[str]

@dataclass
class URLCandidate:
    url: str
    source: str
    same_host: bool


@dataclass
class WebResourceAnalysis:
    robots: RobotsInfo | None
    sitemap: SitemapInfo | None
    security_txt: SecurityTxtInfo | None
    candidates: list[URLCandidate]
#Content Discovery
@dataclass
class ContentProbe:
    url: str
    source: str
    status_code: int | None
    classification: str

    content_type: str | None
    content_length: int | None
    redirect_to: str | None

    soft_404: bool
    error: str | None
# ---------------- TLS Intelligence ----------------
@dataclass
class HostnameCandidate:
    hostname: str
    source: str
    certificate_fingerprint: str
@dataclass
class DNSResolution:
    hostname: str
    source: str

    canonical_name: str | None

    ipv4_addresses: list[str]
    ipv6_addresses: list[str]

    resolved: bool
    errors: list[str]

@dataclass
class TLSResult:
    host: str
    port: int

    version: str | None
    cipher: str | None
    cipher_bits: int | None
    alpn: str | None

    subject: str
    issuer: str
    serial_number: str
    sha256_fingerprint: str

    valid_from: str
    valid_until: str
    days_remaining: int

    dns_names: list[str]
    ip_addresses: list[str]

    hostname_match: bool
    warnings: list[str]
