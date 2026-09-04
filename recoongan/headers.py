from .models import HeaderRule, Finding

#--------------------parse hsts----------------------
def parse_hsts(
    value: str,
) -> dict[str, str | bool]:

    directives: dict[str, str | bool] = {}

    for raw_part in value.split(";"):

        part = raw_part.strip()

        if not part:
            continue

        if "=" in part:

            name, raw_value = part.split(
                "=",
                1,
            )

            directives[
                name.strip().lower()
            ] = raw_value.strip()

        else:

            directives[
                part.lower()
            ] = True

    return directives
#--------------------config validator hsts--------------------------------
def validate_hsts(
    value: str | None
) -> tuple[str, str]:

    if value is None:
        return (
            "MISSING",
            "Header is not set"
        )

    policy = value.strip()

    if not policy:
        return (
            "WEAK",
            "Header is empty"
        )

    directives = parse_hsts(policy)

    max_age_raw = directives.get(
        "max-age"
    )

    if max_age_raw is None:
        return (
            "WEAK",
            "max-age directive is missing"
        )

    if not isinstance(
        max_age_raw,
        str,
    ):
        return (
            "WEAK",
            "max-age value is invalid"
        )

    try:
        seconds = int(max_age_raw)

    except ValueError:

        return (
            "WEAK",
            "max-age value is not an integer"
        )

    if seconds <= 0:

        return (
            "WEAK",
            "max-age=0 disables HSTS"
        )

    protections = [
        f"max-age={seconds}"
    ]

    if (
        directives.get(
            "includesubdomains"
        )
        is True
    ):
        protections.append(
            "includeSubDomains"
        )

    if (
        directives.get("preload")
        is True
    ):
        protections.append(
            "preload"
        )

    return (
        "OK",
        "HSTS enabled: "
        + ", ".join(protections)
    )
#---------------------------validate-x-content-type-options(xcto)------------------
def validate_x_content_type_options(
    value: str | None
) -> tuple[str, str]:

    if value is None:
        return "MISSING", "Header is not set"

    if value.strip().lower() == "nosniff":
        return "OK", "MIME sniffing protection enabled"

    return (
        "INVALID",
        f"Expected nosniff, got: {value}"
    )
#----------------------x-frame-options------------------------
def validate_x_frame_options(
    value: str | None
) -> tuple[str, str]:

    if value is None:
        return "MISSING", "Header is not set"

    normalized = value.strip().upper()

    if normalized == "DENY":
        return "OK", "Framing is completely blocked"

    if normalized == "SAMEORIGIN":
        return "OK", "Framing allowed only from same origin"

    if normalized.startswith("ALLOW-FROM"):
        return (
        "INVALID",
        f"Unrecognized value: {value}"
        )
    return "WEAK", f"Unexpected value: {value}"
#------------------referrer policy-----------------------
def validate_referrer_policy(
    value: str | None
) -> tuple[str, str]:

    if value is None:
        return "MISSING", "Header is not set"

    strong_policies = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }

    weak_policies = {
        "origin",
        "origin-when-cross-origin",
        "no-referrer-when-downgrade",
        "unsafe-url",
    }

    policies = [
        item.strip().lower()
        for item in value.split(",")
        if item.strip()
    ]

    if not policies:
        return "WEAK", "Header is empty"

    for policy in reversed(policies):
        if policy in strong_policies:
            return "OK", f"Recognized policy: {policy}"

        if policy in weak_policies:
            return "WEAK", f"Potentially permissive policy: {policy}"

    return "WEAK", f"Unrecognized policy: {value}"
#---------------------Permissions-Policy------------------------
def validate_permissions_policy(
    value: str | None
) -> tuple[str, str]:

    if value is None:
        return "MISSING", "Header is not set"

    policy = value.strip()

    if not policy:
        return "WEAK", "Header is empty"

    if "=" not in policy:
        return "WEAK", "Header does not contain any policy directives"

    return "OK", "Permissions-Policy is present"
#----------------------parse csp---------------------------
def parse_csp(
    value: str,
) -> dict[str, list[str]]:

    directives: dict[str, list[str]] = {}

    for raw_directive in value.split(";"):

        parts = raw_directive.strip().split()

        if not parts:
            continue

        name = parts[0].lower()
        values = parts[1:]

        directives[name] = values

    return directives
#----------------------validator CSP---------------------------
def validate_csp(
    value: str | None
) -> tuple[str, str]:

    if value is None:
        return "MISSING", "Header is not set"

    policy = value.strip()

    if not policy:
        return "WEAK", "Header is empty"

    directives = parse_csp(policy)

    if not directives:
        return "WEAK", "No valid CSP directives found"

    problems = []

    script_policy = directives.get(
        "script-src"
    )

    if script_policy is None:
        script_policy = directives.get(
            "default-src"
        )

    if script_policy is None:
        problems.append(
            "script-src and default-src are missing"
        )

    else:

        normalized_sources = {
            source.lower()
            for source in script_policy
        }

        if "'unsafe-eval'" in normalized_sources:
            problems.append(
                "unsafe-eval in script policy"
            )

        if "'unsafe-inline'" in normalized_sources:
            problems.append(
                "unsafe-inline in script policy"
            )

        if "*" in normalized_sources:
            problems.append(
                "wildcard source in script policy"
            )

    if problems:
        return (
            "WEAK",
            "Potentially weak CSP: "
            + ", ".join(problems)
        )

    return (
        "OK",
        "CSP contains a restrictive script policy"
    )  
#---------------RULES--------------------
SECURITY_RULES = [
    HeaderRule(
        name="Strict-Transport-Security",
        severity="HIGH",
        weight=20,
        attack="HTTPS downgrade / SSL stripping",
        validator=validate_hsts,
    ),

    HeaderRule(
        name="X-Content-Type-Options",
        severity="MEDIUM",
        weight=15,
        attack="MIME sniffing",
        validator=validate_x_content_type_options,
    ),

    HeaderRule(
        name="X-Frame-Options",
        severity="MEDIUM",
        weight=15,
        attack="Clickjacking",
        validator=validate_x_frame_options,
    ),

    HeaderRule(
    name="Referrer-Policy",
    severity="LOW",
    weight=15,
    attack="Referrer information leakage",
    validator=validate_referrer_policy,
),
    HeaderRule(
    name="Permissions-Policy",
    severity="LOW",
    weight=10,
    attack="Browser feature abuse / overly permissive browser capabilities",
    validator=validate_permissions_policy,
),
    HeaderRule(
    name="Content-Security-Policy",
    severity="HIGH",
    weight=25,
    attack="XSS / content injection",
    validator=validate_csp,
),
]
def analyze_headers(
    headers
) -> list[Finding]:

    normalized_headers = {
        name.lower(): value
        for name, value in headers.items()
    }

    findings = []

    for rule in SECURITY_RULES:

        value = normalized_headers.get(
            rule.name.lower()
        )

        status, note = rule.validator(value)

        if value is None:
            evidence = "Header not present"
        else:
            evidence = f"{rule.name}: {value}"

        finding = Finding(
            header=rule.name,
            status=status,
            severity=rule.severity,
            weight=rule.weight,
            note=note,
            attack=rule.attack,
            evidence=evidence,
        )

        findings.append(finding)

    return findings
