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
