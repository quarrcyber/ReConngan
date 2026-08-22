from .models import HeaderRule, Finding

#--------------------config validator hsts--------------------------------
def validate_hsts(value: str | None) -> tuple[str, str]:

    if value is None:
        return "MISSING", "Header is not set"

    directives = [
        part.strip()
        for part in value.split(";")
    ]

    max_age = None

    for directive in directives:
        if directive.lower().startswith("max-age="):
            max_age = directive
            break

    if max_age is None:
        return "WEAK", "max-age directive is missing"

    try:
        seconds = int(
            max_age.split("=", 1)[1].strip()
        )

    except ValueError:
        return "WEAK", "max-age value is invalid"

    if seconds <= 0:
        return "WEAK", "max-age=0 disables HSTS"

    return "OK", f"HSTS enabled with max-age={seconds}"

#---------------------------validate-x-content-type-options------------------
def validate_x_content_type_options(
    value: str | None
) -> tuple[str, str]:

    if value is None:
        return "MISSING", "Header is not set"

    if value.strip().lower() == "nosniff":
        return "OK", "MIME sniffing protection enabled"

    return (
        "WEAK",
        f"Unexpected value: {value}"
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
        return "WEAK", "ALLOW-FROM is obsolete and not widely supported"

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
#----------------------validator CSP---------------------------
def validate_csp(
    value: str | None
) -> tuple[str, str]:

    if value is None:
        return "MISSING", "Header is not set"

    policy = value.strip()

    if not policy:
        return "WEAK", "Header is empty"

    normalized = policy.lower()

    problems = []

    if "'unsafe-inline'" in normalized:
        problems.append("unsafe-inline")

    if "'unsafe-eval'" in normalized:
        problems.append("unsafe-eval")

    if "script-src *" in normalized:
        problems.append("wildcard script-src")

    if problems:
        return (
            "WEAK",
            "Potentially weak directives: "
            + ", ".join(problems)
        )

    return "OK", "CSP is present with no basic weak patterns detected"
  
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
