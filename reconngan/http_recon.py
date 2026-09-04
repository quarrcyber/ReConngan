import httpx
import re

from http.cookies import (
    SimpleCookie,
    CookieError,
)

from .models import (
    HttpMetadata,
    CookieInfo,
    RedirectHop,
    CookieFinding,
    HTTPFinding,
    HTTPIndicator,
    HTTPIntelligence,
)

def collect_http_metadata(
    response: httpx.Response
) -> HttpMetadata:

    content_type = response.headers.get(
        "Content-Type",
        "Not provided",
    )

    content_length = response.headers.get(
        "Content-Length",
        "Not provided",
    )

    response_time_ms = (
        response.elapsed.total_seconds()
        * 1000
    )

    return HttpMetadata(
        http_version=response.http_version,
        response_time_ms=response_time_ms,
        content_type=content_type,
        content_length=content_length,
    )
#-----------------http_cookies---------------
def collect_http_cookies(
    response: httpx.Response
) -> list[CookieInfo]:

    results: list[CookieInfo] = []

    raw_cookies = response.headers.get_list(
        "set-cookie"
    )

    for raw_cookie in raw_cookies:

        parsed = SimpleCookie()

        try:
            parsed.load(raw_cookie)

        except CookieError:
            continue

        for morsel in parsed.values():

            samesite = (
                morsel["samesite"].strip()
                or None
            )

            path = (
                morsel["path"].strip()
                or None
            )

            domain = (
                morsel["domain"].strip()
                or None
            )

            results.append(
                CookieInfo(
                    name=morsel.key,
                    secure=bool(
                        morsel["secure"]
                    ),
                    httponly=bool(
                        morsel["httponly"]
                    ),
                    samesite=samesite,
                    path=path,
                    domain=domain,
                )
            )

    return results
def looks_sensitive_cookie(
    name: str,
) -> bool:

    normalized = name.lower()

    hints = (
        "session",
        "sess",
        "auth",
        "token",
        "jwt",
        "sid",
        "login",
        "logged_in",
    )

    return any(
        hint in normalized
        for hint in hints
    )
def analyze_cookie_security(
    cookies: list[CookieInfo],
) -> list[CookieFinding]:

    findings: list[CookieFinding] = []

    for cookie in cookies:

        # --------------------------------
        # __Secure- prefix
        # --------------------------------

        if (
            cookie.name.startswith("__Secure-")
            and not cookie.secure
        ):

            findings.append(
                CookieFinding(
                    cookie=cookie.name,
                    check="__Secure- prefix",
                    status="INVALID",
                    severity="MEDIUM",
                    note=(
                        "__Secure- cookies "
                        "must use the Secure attribute"
                    ),
                    evidence=(
                        f"Cookie={cookie.name}; "
                        f"Secure={cookie.secure}"
                    ),
                )
            )

        # --------------------------------
        # __Host- prefix
        # --------------------------------

        if cookie.name.startswith("__Host-"):

            problems = []

            if not cookie.secure:
                problems.append(
                    "Secure missing"
                )

            if cookie.path != "/":
                problems.append(
                    "Path must be /"
                )

            if cookie.domain is not None:
                problems.append(
                    "Domain must not be set"
                )

            if problems:

                findings.append(
                    CookieFinding(
                        cookie=cookie.name,
                        check="__Host- prefix",
                        status="INVALID",
                        severity="MEDIUM",
                        note=", ".join(problems),
                        evidence=(
                            f"Secure={cookie.secure}; "
                            f"Path={cookie.path}; "
                            f"Domain={cookie.domain}"
                        ),
                    )
                )

        # --------------------------------
        # SameSite=None requires Secure
        # --------------------------------

        if (
            cookie.samesite is not None
            and
            cookie.samesite.lower() == "none"
            and
            not cookie.secure
        ):

            findings.append(
                CookieFinding(
                    cookie=cookie.name,
                    check="SameSite",
                    status="INVALID",
                    severity="MEDIUM",
                    note=(
                        "SameSite=None should be "
                        "combined with Secure"
                    ),
                    evidence=(
                        f"SameSite={cookie.samesite}; "
                        f"Secure={cookie.secure}"
                    ),
                )
            )

        # --------------------------------
        # likely session/auth cookie
        # --------------------------------

        if looks_sensitive_cookie(
            cookie.name
        ):

            if not cookie.secure:

                findings.append(
                    CookieFinding(
                        cookie=cookie.name,
                        check="Secure",
                        status="WEAK",
                        severity="MEDIUM",
                        note=(
                            "Potential session/auth "
                            "cookie lacks Secure"
                        ),
                        evidence=(
                            f"Cookie={cookie.name}; "
                            "Secure=False"
                        ),
                    )
                )

            if not cookie.httponly:

                findings.append(
                    CookieFinding(
                        cookie=cookie.name,
                        check="HttpOnly",
                        status="WEAK",
                        severity="MEDIUM",
                        note=(
                            "Potential session/auth "
                            "cookie lacks HttpOnly"
                        ),
                        evidence=(
                            f"Cookie={cookie.name}; "
                            "HttpOnly=False"
                        ),
                    )
                )

    return findings

def collect_redirect_chain(
    response: httpx.Response
) -> list[RedirectHop]:

    chain: list[RedirectHop] = []

    for hop in response.history:

        chain.append(
            RedirectHop(
                url=str(hop.url),
                status_code=hop.status_code,
                location=hop.headers.get(
                    "Location"
                ),
            )
        )

    chain.append(
        RedirectHop(
            url=str(response.url),
            status_code=response.status_code,
            location=response.headers.get(
                "Location"
            ),
        )
    )

    return chain

def _header_value(
    response: httpx.Response,
    name: str,
) -> str | None:
    value = response.headers.get(
        name
    )

    if value is None:
        return None

    value = value.strip()

    return value or None


def _body_sample(
    response: httpx.Response,
    max_chars: int = 20_000,
) -> str:
    try:
        text = response.text
    except UnicodeDecodeError:
        return ""

    return text[:max_chars]


def _add_indicator(
    indicators: list[HTTPIndicator],
    *,
    category: str,
    name: str,
    confidence: str,
    evidence: str,
) -> None:
    normalized_evidence = (
        evidence.strip()
    )

    if not normalized_evidence:
        return

    existing = {
        (
            item.category,
            item.name,
            item.evidence,
        )
        for item in indicators
    }

    key = (
        category,
        name,
        normalized_evidence,
    )

    if key in existing:
        return

    indicators.append(
        HTTPIndicator(
            category=category,
            name=name,
            confidence=confidence,
            evidence=normalized_evidence,
        )
    )
#version leakage
SERVER_PRODUCT_VERSION_RE = re.compile(
    r"(?P<product>[A-Za-z][A-Za-z0-9_.+-]*)"
    r"/"
    r"(?P<version>[0-9][A-Za-z0-9_.:+~-]*)"
)

VERSION_LIKE_RE = re.compile(
    r"\b[0-9]+(?:\.[0-9A-Za-z_-]+)+\b"
)

PARENTHESIZED_DETAIL_RE = re.compile(
    r"\((?P<detail>[^)]{2,200})\)"
)

SENSITIVE_STACK_MARKERS = (
    "ubuntu",
    "debian",
    "centos",
    "red hat",
    "rhel",
    "alpine",
    "freebsd",
    "openssl",
    "php",
    "python",
    "perl",
    "mod_",
    "passenger",
    "phusion",
    "gunicorn",
    "uvicorn",
    "werkzeug",
    "tomcat",
    "jetty",
    "wildfly",
    "jboss",
    "iis",
    "asp.net",
    "express",
    "node",
)


def _extract_product_versions(
    value: str,
) -> list[str]:
    """Extract product/version tokens from a header value."""

    matches: list[str] = []

    for match in SERVER_PRODUCT_VERSION_RE.finditer(
        value
    ):
        product = match.group(
            "product"
        )

        version = match.group(
            "version"
        )

        matches.append(
            f"{product}/{version}"
        )

    return matches


def _extract_parenthesized_details(
    value: str,
) -> list[str]:
    """Extract parenthesized platform/module details."""

    details: list[str] = []

    for match in PARENTHESIZED_DETAIL_RE.finditer(
        value
    ):
        detail = match.group(
            "detail"
        ).strip()

        if detail:
            details.append(
                detail
            )

    return details


def _contains_stack_detail(
    value: str,
) -> bool:
    lowered = value.lower()

    return any(
        marker in lowered
        for marker in SENSITIVE_STACK_MARKERS
    )


def _has_version_like_value(
    value: str,
) -> bool:
    return bool(
        VERSION_LIKE_RE.search(
            value
        )
    )


def _server_header_has_version_leakage(
    value: str,
) -> bool:
    if _extract_product_versions(
        value
    ):
        return True

    if _contains_stack_detail(
        value
    ) and _has_version_like_value(
        value
    ):
        return True

    return False


def _server_header_has_stack_detail(
    value: str,
) -> bool:
    if _extract_parenthesized_details(
        value
    ):
        return True

    return _contains_stack_detail(
        value
    )


def _server_version_severity(
    value: str,
) -> str:
    if _server_header_has_stack_detail(
        value
    ):
        return "HIGH"

    return "MEDIUM"


def _server_version_evidence(
    value: str,
) -> str:
    product_versions = _extract_product_versions(
        value
    )

    details = _extract_parenthesized_details(
        value
    )

    evidence_parts: list[str] = []

    if product_versions:
        evidence_parts.append(
            "products="
            + ", ".join(product_versions)
        )

    if details:
        evidence_parts.append(
            "details="
            + " | ".join(details)
        )

    if not evidence_parts:
        evidence_parts.append(
            value
        )

    return "; ".join(
        evidence_parts
    )


def _collect_header_technology_hints(
    response: httpx.Response,
) -> list[HTTPIndicator]:
    indicators: list[HTTPIndicator] = []

    server = _header_value(
        response,
        "Server",
    )

    if server:
        _add_indicator(
            indicators,
            category="server",
            name="Server header",
            confidence="HIGH",
            evidence=server,
        )

        product_versions = _extract_product_versions(
            server
        )

        for product_version in product_versions:
            _add_indicator(
                indicators,
                category="server",
                name="Server product/version",
                confidence="HIGH",
                evidence=product_version,
            )

        details = _extract_parenthesized_details(
            server
        )

        for detail in details:
            _add_indicator(
                indicators,
                category="server",
                name="Server platform/module detail",
                confidence="MEDIUM",
                evidence=detail,
            )

    powered_by = _header_value(
        response,
        "X-Powered-By",
    )

    if powered_by:
        _add_indicator(
            indicators,
            category="technology",
            name="X-Powered-By",
            confidence="HIGH",
            evidence=powered_by,
        )

    via = _header_value(
        response,
        "Via",
    )

    version_leak_headers = {
        "X-AspNet-Version": "ASP.NET version",
        "X-AspNetMvc-Version": "ASP.NET MVC version",
        "X-Generator": "Generator version",
        "X-Drupal-Cache": "Drupal indicator",
        "X-Runtime": "Runtime indicator",
        "X-Rack-Cache": "Rack cache indicator",
    }

    for header_name, name in version_leak_headers.items():
        value = _header_value(
            response,
            header_name,
        )

        if value:
            confidence = (
                "HIGH"
                if _has_version_like_value(
                    value
                )
                else "MEDIUM"
            )

            _add_indicator(
                indicators,
                category="technology",
                name=name,
                confidence=confidence,
                evidence=(
                    f"{header_name}: {value}"
                ),
            )

    if via:
        _add_indicator(
            indicators,
            category="proxy",
            name="Via header",
            confidence="MEDIUM",
            evidence=via,
        )

    cdn_headers = {
        "CF-Ray": "Cloudflare",
        "CF-Cache-Status": "Cloudflare",
        "X-Served-By": "Fastly/Varnish",
        "X-Cache": "Cache layer",
        "X-Amz-Cf-Id": "Amazon CloudFront",
        "X-Azure-Ref": "Azure Front Door",
        "X-Vercel-Id": "Vercel",
        "X-GitHub-Request-Id": "GitHub edge/app",
    }

    for header_name, technology in cdn_headers.items():
        value = _header_value(
            response,
            header_name,
        )

        if value:
            _add_indicator(
                indicators,
                category="edge",
                name=technology,
                confidence="MEDIUM",
                evidence=(
                    f"{header_name}: {value}"
                ),
            )

    return indicators

def _collect_framework_indicators(
    response: httpx.Response,
    body: str,
) -> list[HTTPIndicator]:
    indicators: list[HTTPIndicator] = []

    header_patterns = {
        "X-Django-Request-Id": "Django",
        "X-Rails-Version": "Ruby on Rails",
        "X-Runtime": "Ruby on Rails / Rack",
        "X-Drupal-Cache": "Drupal",
        "X-Generator": "CMS/framework generator",
        "X-Nextjs-Cache": "Next.js",
        "X-Remix-Response": "Remix",
    }

    for header_name, framework in header_patterns.items():
        value = _header_value(
            response,
            header_name,
        )

        if value:
            _add_indicator(
                indicators,
                category="framework",
                name=framework,
                confidence="MEDIUM",
                evidence=(
                    f"{header_name}: {value}"
                ),
            )

    body_patterns = {
        "__NEXT_DATA__": "Next.js",
        "data-reactroot": "React",
        "ng-version": "Angular",
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "drupal-settings-json": "Drupal",
        "content=\"Joomla": "Joomla",
        "csrf-token": "CSRF-protected application",
        "swagger-ui": "Swagger UI",
        "redoc": "ReDoc",
    }

    lower_body = body.lower()

    for marker, framework in body_patterns.items():
        if marker.lower() in lower_body:
            _add_indicator(
                indicators,
                category="framework",
                name=framework,
                confidence="LOW",
                evidence=marker,
            )

    return indicators

def _collect_api_indicators(
    response: httpx.Response,
    body: str,
) -> list[HTTPIndicator]:
    indicators: list[HTTPIndicator] = []

    content_type = (
        _header_value(
            response,
            "Content-Type",
        )
        or ""
    )

    lowered_content_type = (
        content_type.lower()
    )

    if "application/json" in lowered_content_type:
        _add_indicator(
            indicators,
            category="api",
            name="JSON response",
            confidence="HIGH",
            evidence=content_type,
        )

    if "application/graphql" in lowered_content_type:
        _add_indicator(
            indicators,
            category="api",
            name="GraphQL response",
            confidence="HIGH",
            evidence=content_type,
        )

    api_headers = {
        "GraphQL": "GraphQL",
        "X-GraphQL-Event-Stream": "GraphQL event stream",
        "X-RateLimit-Limit": "Rate limited API",
        "X-RateLimit-Remaining": "Rate limited API",
        "Retry-After": "Rate limiting / backoff",
        "Allow": "HTTP method surface",
        "Access-Control-Allow-Origin": "CORS surface",
        "Access-Control-Allow-Credentials": "CORS credentials surface",
    }

    for header_name, name in api_headers.items():
        value = _header_value(
            response,
            header_name,
        )

        if value:
            _add_indicator(
                indicators,
                category="api",
                name=name,
                confidence="MEDIUM",
                evidence=(
                    f"{header_name}: {value}"
                ),
            )

    lowered_body = body.lower()

    body_markers = {
        "\"graphql\"": "GraphQL marker",
        "\"openapi\"": "OpenAPI marker",
        "\"swagger\"": "Swagger marker",
        "\"api_version\"": "API version marker",
        "\"error\"": "Structured API error",
        "\"errors\"": "Structured API errors",
        "\"message\"": "Structured API message",
    }

    for marker, name in body_markers.items():
        if marker in lowered_body:
            _add_indicator(
                indicators,
                category="api",
                name=name,
                confidence="LOW",
                evidence=marker,
            )

    return indicators

def _collect_auth_surface(
    response: httpx.Response,
    body: str,
) -> list[HTTPIndicator]:
    indicators: list[HTTPIndicator] = []

    www_authenticate = _header_value(
        response,
        "WWW-Authenticate",
    )

    if www_authenticate:
        _add_indicator(
            indicators,
            category="auth",
            name="WWW-Authenticate",
            confidence="HIGH",
            evidence=www_authenticate,
        )

    auth_headers = {
        "Set-Cookie": "Cookie-based session surface",
        "Authorization": "Authorization header surface",
        "Proxy-Authenticate": "Proxy authentication surface",
    }

    for header_name, name in auth_headers.items():
        values = response.headers.get_list(
            header_name
        )

        for value in values:
            if value:
                _add_indicator(
                    indicators,
                    category="auth",
                    name=name,
                    confidence="MEDIUM",
                    evidence=(
                        f"{header_name}: "
                        f"{value[:160]}"
                    ),
                )

    lowered_body = body.lower()

    auth_markers = {
        "login": "Login surface",
        "sign in": "Login surface",
        "signin": "Login surface",
        "logout": "Logout surface",
        "csrf": "CSRF token surface",
        "password": "Password form surface",
        "oauth": "OAuth surface",
        "saml": "SAML surface",
        "webauthn": "WebAuthn surface",
    }

    for marker, name in auth_markers.items():
        if marker in lowered_body:
            _add_indicator(
                indicators,
                category="auth",
                name=name,
                confidence="LOW",
                evidence=marker,
            )

    return indicators

def _collect_interesting_metadata(
    response: httpx.Response,
    body: str,
) -> list[HTTPIndicator]:
    indicators: list[HTTPIndicator] = []

    metadata_headers = {
        "ETag": "Entity tag",
        "Last-Modified": "Last modified",
        "Content-Language": "Content language",
        "Link": "Link metadata",
        "Report-To": "Reporting endpoint",
        "NEL": "Network error logging",
        "Server-Timing": "Server timing",
        "Timing-Allow-Origin": "Timing exposure",
        "Alt-Svc": "Alternative service",
    }

    for header_name, name in metadata_headers.items():
        value = _header_value(
            response,
            header_name,
        )

        if value:
            _add_indicator(
                indicators,
                category="metadata",
                name=name,
                confidence="MEDIUM",
                evidence=(
                    f"{header_name}: {value}"
                ),
            )

    lowered_body = body.lower()

    html_markers = {
        "<meta name=\"generator\"": "HTML generator metadata",
        "sourceMappingURL=".lower(): "Source map reference",
        ".map\"": "Possible source map reference",
        "debug": "Debug marker",
        "staging": "Staging marker",
        "localhost": "Localhost marker",
        "127.0.0.1": "Loopback marker",
    }

    for marker, name in html_markers.items():
        if marker in lowered_body:
            _add_indicator(
                indicators,
                category="metadata",
                name=name,
                confidence="LOW",
                evidence=marker,
            )

    return indicators

def _build_http_intelligence_findings(
    response: httpx.Response,
    *,
    technology_hints: list[HTTPIndicator],
    framework_indicators: list[HTTPIndicator],
    api_indicators: list[HTTPIndicator],
    auth_surface: list[HTTPIndicator],
    metadata: list[HTTPIndicator],
) -> list[HTTPFinding]:
    findings: list[HTTPFinding] = []

    server = _header_value(
        response,
        "Server",
    )

    if server:
        findings.append(
            HTTPFinding(
                check="server-header",
                status="INFO",
                severity="LOW",
                note="Server header is exposed.",
                evidence=server,
            )
        )

        if _server_header_has_version_leakage(
            server
        ):
            findings.append(
                HTTPFinding(
                    check="server-version-leakage",
                    status="WEAK",
                    severity=_server_version_severity(
                        server
                    ),
                    note=(
                        "Server header exposes product, "
                        "version, platform, or module details."
                    ),
                    evidence=_server_version_evidence(
                        server
                    ),
                )
            )

        elif _server_header_has_stack_detail(
            server
        ):
            findings.append(
                HTTPFinding(
                    check="server-stack-detail",
                    status="INFO",
                    severity="LOW",
                    note=(
                        "Server header exposes stack or "
                        "platform detail without a clear version."
                    ),
                    evidence=server,
                )
            )

##
    powered_by = _header_value(
        response,
        "X-Powered-By",
    )

    if powered_by:
        severity = (
            "HIGH"
            if _has_version_like_value(
                powered_by
            )
            else "MEDIUM"
        )

        check = (
            "powered-by-version-leakage"
            if _has_version_like_value(
                powered_by
            )
            else "powered-by-header"
        )

        findings.append(
            HTTPFinding(
                check=check,
                status="WEAK",
                severity=severity,
                note=(
                    "X-Powered-By exposes backend "
                    "technology information."
                ),
                evidence=powered_by,
            )
        )
    version_leak_headers = {
        "X-AspNet-Version": "ASP.NET runtime version is exposed.",
        "X-AspNetMvc-Version": "ASP.NET MVC version is exposed.",
        "X-Generator": "Application generator metadata is exposed.",
    }

    for header_name, note in version_leak_headers.items():
        value = _header_value(
            response,
            header_name,
        )

        if not value:
            continue

        severity = (
            "HIGH"
            if _has_version_like_value(
                value
            )
            else "MEDIUM"
        )

        findings.append(
            HTTPFinding(
                check="framework-version-leakage",
                status="WEAK",
                severity=severity,
                note=note,
                evidence=(
                    f"{header_name}: {value}"
                ),
            )
        )


##
    cors_origin = _header_value(
        response,
        "Access-Control-Allow-Origin",
    )

    cors_credentials = _header_value(
        response,
        "Access-Control-Allow-Credentials",
    )

    if cors_origin == "*":
        findings.append(
            HTTPFinding(
                check="cors-origin",
                status="INFO",
                severity="LOW",
                note="CORS allows any origin. This may be acceptable for public APIs.",
                evidence="Access-Control-Allow-Origin: *",
            )
        )

    if (
        cors_credentials is not None
        and cors_credentials.lower() == "true"
    ):
        findings.append(
            HTTPFinding(
                check="cors-credentials",
                status="INFO",
                severity="LOW",
                note="CORS credential support is advertised.",
                evidence=(
                    "Access-Control-Allow-Credentials: "
                    f"{cors_credentials}"
                ),
            )
        )

    debug_headers = (
        "X-Debug",
        "X-Debug-Token",
        "X-Debug-Token-Link",
        "X-Trace",
        "X-Request-Id",
        "X-Correlation-Id",
    )

    for header_name in debug_headers:
        value = _header_value(
            response,
            header_name,
        )

        if value:
            severity = (
                "MEDIUM"
                if header_name.startswith("X-Debug")
                else "LOW"
            )

            findings.append(
                HTTPFinding(
                    check="debug-or-trace-header",
                    status="INFO",
                    severity=severity,
                    note="Debug, trace, or request correlation header is exposed.",
                    evidence=(
                        f"{header_name}: {value}"
                    ),
                )
            )

    if response.status_code in {
        401,
        403,
    } and auth_surface:
        findings.append(
            HTTPFinding(
                check="auth-surface",
                status="INFO",
                severity="LOW",
                note="Authentication or authorization surface is visible.",
                evidence=(
                    f"status={response.status_code}; "
                    f"signals={len(auth_surface)}"
                ),
            )
        )

    source_map_indicators = [
        item
        for item in metadata
        if "source map" in item.name.lower()
    ]

    for item in source_map_indicators:
        findings.append(
            HTTPFinding(
                check="source-map-reference",
                status="INFO",
                severity="LOW",
                note="Response appears to reference source maps.",
                evidence=item.evidence,
            )
        )

    if api_indicators:
        findings.append(
            HTTPFinding(
                check="api-surface",
                status="INFO",
                severity="LOW",
                note="Response exposes API-related indicators.",
                evidence=(
                    f"{len(api_indicators)} API indicator(s)"
                ),
            )
        )

    if framework_indicators:
        findings.append(
            HTTPFinding(
                check="framework-fingerprint",
                status="INFO",
                severity="LOW",
                note="Framework or application stack indicators were detected.",
                evidence=(
                    f"{len(framework_indicators)} framework indicator(s)"
                ),
            )
        )

    return findings

def collect_http_intelligence(
    response: httpx.Response,
) -> HTTPIntelligence:
    body = _body_sample(
        response
    )

    technology_hints = (
        _collect_header_technology_hints(
            response
        )
    )

    framework_indicators = (
        _collect_framework_indicators(
            response,
            body,
        )
    )

    api_indicators = (
        _collect_api_indicators(
            response,
            body,
        )
    )

    auth_surface = (
        _collect_auth_surface(
            response,
            body,
        )
    )

    metadata = (
        _collect_interesting_metadata(
            response,
            body,
        )
    )

    findings = (
        _build_http_intelligence_findings(
            response,
            technology_hints=technology_hints,
            framework_indicators=framework_indicators,
            api_indicators=api_indicators,
            auth_surface=auth_surface,
            metadata=metadata,
        )
    )

    return HTTPIntelligence(
        url=str(response.request.url),
        final_url=str(response.url),
        status_code=response.status_code,
        server=_header_value(
            response,
            "Server",
        ),
        powered_by=_header_value(
            response,
            "X-Powered-By",
        ),
        via=_header_value(
            response,
            "Via",
        ),
        cache_status=(
            _header_value(
                response,
                "CF-Cache-Status",
            )
            or _header_value(
                response,
                "X-Cache",
            )
        ),
        content_type=_header_value(
            response,
            "Content-Type",
        ),
        technology_hints=technology_hints,
        framework_indicators=framework_indicators,
        api_indicators=api_indicators,
        auth_surface=auth_surface,
        metadata=metadata,
        findings=findings,
    )
