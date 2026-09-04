import httpx

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

        if any(
            character.isdigit()
            for character in server
        ):
            findings.append(
                HTTPFinding(
                    check="server-version-leakage",
                    status="WEAK",
                    severity="MEDIUM",
                    note="Server header appears to expose version information.",
                    evidence=server,
                )
            )

    powered_by = _header_value(
        response,
        "X-Powered-By",
    )

    if powered_by:
        findings.append(
            HTTPFinding(
                check="powered-by-header",
                status="WEAK",
                severity="MEDIUM",
                note="X-Powered-By exposes backend technology information.",
                evidence=powered_by,
            )
        )

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
