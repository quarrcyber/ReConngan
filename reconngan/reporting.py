import json

from dataclasses import asdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

from .models import (
    Finding,
    HttpMetadata,
    CookieInfo,
    RedirectHop,
    CookieFinding,
    WebResource,
    SitemapInfo,
    SecurityTxtInfo,
    URLCandidate,
    WebResourceAnalysis,
    TLSResult,
)
from .models import (
    ContentProbe,
    HostnameCandidate,
    TLSResult,
)
console = Console()

def status_style(status: str) -> str:

    if status == "OK":
        return "green"

    if status == "WEAK":
        return "yellow"

    if status == "MISSING":
        return "red"
    if status == "INVALID":
        return "red"
    return "white"

def severity_style(severity: str) -> str:

    if severity == "HIGH":
        return "red"

    if severity == "MEDIUM":
        return "yellow"

    if severity == "LOW":
        return "cyan"

    return "white"

def grade_style(grade: str) -> str:

    if grade == "A":
        return "green"

    if grade == "B":
        return "green"

    if grade == "C":
        return "yellow"

    if grade == "D":
        return "dark_orange"

    return "red"

def http_status_style(
    status_code: int
) -> str:

    if 200 <= status_code < 300:
        return "green"

    if 300 <= status_code < 400:
        return "cyan"

    if 400 <= status_code < 500:
        return "yellow"

    if status_code >= 500:
        return "red"

    return "white"

def truncate_text(
    text: str,
    max_length: int = 250
) -> str:

    if len(text) <= max_length:
        return text

    return text[:max_length] + "..."

def print_target_info(
    url: str,
    status_code: int,
    final_url: str
) -> None:

    status_color = http_status_style(
        status_code
    )

    console.print()

    console.print(
        f"[bold]Target:[/bold]    "
        f"{escape(url)}"
    )

    console.print(
        f"[bold]Status:[/bold]    "
        f"[{status_color}]"
        f"{status_code}"
        f"[/{status_color}]"
    )

    console.print(
        f"[bold]Final URL:[/bold] "
        f"{escape(final_url)}"
    )

def print_report(
    findings: list[Finding],
    score: float,
    grade: str
) -> None:

    table = Table(
        title="Security Headers",
        show_header=True,
        header_style="bold"
    )

    table.add_column(
        "Header",
        no_wrap=True
    )

    table.add_column(
        "Status",
        no_wrap=True
    )

    table.add_column(
        "Severity",
        no_wrap=True
    )

    table.add_column(
        "Note",
        overflow="fold"
    )

    for finding in findings:

        status_color = status_style(
            finding.status
        )

        severity_color = severity_style(
            finding.severity
        )

        table.add_row(
            finding.header,
            (
                f"[{status_color}]"
                f"{finding.status}"
                f"[/{status_color}]"
            ),
            (
                f"[{severity_color}]"
                f"{finding.severity}"
                f"[/{severity_color}]"
            ),
            finding.note,
        )

    console.print(table)

    grade_color = grade_style(
        grade
    )

    result_text = (
        f"Score: {score:.1f} / 100\n"
        f"Grade: "
        f"[{grade_color}]"
        f"{grade}"
        f"[/{grade_color}]"
    )

    console.print(
        Panel(
            result_text,
            title="Result",
            expand=False,
        )
    )

    problem_findings = [
        finding
        for finding in findings
        if finding.status != "OK"
    ]

    if problem_findings:

        console.print(
            "\n[bold]Findings[/bold]"
        )

        for finding in problem_findings:

            status_color = status_style(
                finding.status
            )

            severity_color = severity_style(
                finding.severity
            )

            evidence_preview = escape(
                truncate_text(
                    finding.evidence
                )
            )

            reason_text = escape(
                finding.note
            )

            attack_text = escape(
                finding.attack
            )

            console.print()

            console.print(
                f"[bold]"
                f"[{severity_color}]"
                f"[{finding.severity}]"
                f"[/{severity_color}] "
                f"{finding.header}"
                f"[/bold]"
            )

            console.print(
                f"[bold]Status:[/bold] "
                f"[{status_color}]"
                f"{finding.status}"
                f"[/{status_color}]"
            )

            console.print(
                f"[bold]Attack:[/bold] "
                f"{attack_text}"
            )

            console.print(
                f"[bold]Reason:[/bold] "
                f"{reason_text}"
            )

            console.print(
                f"[bold]Evidence:[/bold] "
                f"{evidence_preview}"
            )
#------------buid_report_data()-----------------------------
def build_report_data(
    target: str,
    final_url: str,
    status_code: int,
    metadata: HttpMetadata,
    redirect_chain: list[RedirectHop],
    findings: list[Finding],
    cookies: list[CookieInfo],
    cookie_findings: list[CookieFinding],
    web_resources: list[WebResource], 
    web_analysis: WebResourceAnalysis,    
    security_txt: SecurityTxtInfo | None,    
    content_results: list[ContentProbe],    
    tls_result: TLSResult | None,
    score: float,
    grade: str,
) -> dict:

    return {
        "target": target,
        "final_url": final_url,
        "status_code": status_code,
        "http": asdict(metadata),
        "tls": (
            asdict(tls_result)
            if tls_result is not None
            else None
        ),
        "score": score,
        "grade": grade,
        "findings": [
            asdict(finding)
            for finding in findings
        ],
        "cookies": [
            asdict(cookie)
            for cookie in cookies
        ],

        "cookie_findings": [
            asdict(finding)
            for finding in cookie_findings
        ],
        "web_resources": [
           {
               "name": resource.name,
               "url": resource.url,
               "status_code": resource.status_code,
               "content_type": resource.content_type,
               "found": resource.found,
               "error": resource.error,
           }
           for resource in web_resources
        ],
        "web_discovery": {
            "robots": (
                asdict(web_analysis.robots)
                if web_analysis.robots
                else None
            ),

            "sitemap": (
                asdict(web_analysis.sitemap)
                if web_analysis.sitemap
                else None
            ),

            "security_txt": (
                asdict(web_analysis.security_txt)
                if web_analysis.security_txt
                else None
            ),

            "candidates": [
                asdict(candidate)
                for candidate
                in web_analysis.candidates
            ],
        },
        "content_discovery": [
            asdict(result)
            for result in content_results
        ],






    }

def write_json_report(
    data: dict,
    file_path: str,
) -> None:

    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False,
        )

def print_http_metadata(
    metadata: HttpMetadata
) -> None:

    table = Table(
        title="HTTP Information",
        show_header=False,
    )

    table.add_column(
        "Field",
        style="bold",
        no_wrap=True,
    )

    table.add_column(
        "Value",
    )

    table.add_row(
        "HTTP Version",
        metadata.http_version,
    )

    table.add_row(
        "Response Time",
        f"{metadata.response_time_ms:.1f} ms",
    )

    table.add_row(
        "Content-Type",
        metadata.content_type,
    )

    table.add_row(
        "Content-Length",
        metadata.content_length,
    )

    console.print(table)
def print_tls_info(
    result: TLSResult,
    hostname_candidates: list[HostnameCandidate],
    san_limit: int = 20,
) -> None:
    table = Table(
        title="TLS Intelligence",
        show_header=False,
    )

    table.add_column(
        "Field",
        style="bold",
        no_wrap=True,
    )

    table.add_column(
        "Value",
    )

    table.add_row(
        "Endpoint",
        f"{result.host}:{result.port}",
    )

    table.add_row(
        "TLS Version",
        result.version or "-",
    )

    table.add_row(
        "Cipher",
        result.cipher or "-",
    )

    table.add_row(
        "Cipher Bits",
        (
            str(result.cipher_bits)
            if result.cipher_bits is not None
            else "-"
        ),
    )

    table.add_row(
        "ALPN",
        result.alpn or "-",
    )

    table.add_row(
        "Subject",
        escape(result.subject),
    )

    table.add_row(
        "Issuer",
        escape(result.issuer),
    )

    table.add_row(
        "Valid From",
        result.valid_from,
    )
    table.add_row(
        "Serial Number",
        result.serial_number or "-",
    )
    table.add_row(
        "Valid Until",
        result.valid_until,
    )

    table.add_row(
        "Days Remaining",
        str(result.days_remaining),
    )

    table.add_row(
        "Hostname Match",
        (
            "[green]YES[/green]"
            if result.hostname_match
            else "[red]NO[/red]"
        ),
    )

    table.add_row(
        "DNS SANs",
        str(len(result.dns_names)),
    )

    table.add_row(
        "IP SANs",
        str(len(result.ip_addresses)),
    )

    console.print(table)
    if result.dns_names:
        console.print(
            "\n[bold]Subject Alternative Names[/bold]"
        )

        for name in result.dns_names[:san_limit]:
            console.print(
                f"  {escape(name)}"
            )

        remaining = (
            len(result.dns_names)
            - san_limit
        )

        if remaining > 0:
            console.print(
                f"[dim]  ... {remaining} more[/dim]"
            )
            console.print(
                "\n[bold]SHA-256 Fingerprint[/bold]"
            )

            console.print(
                f"  {result.sha256_fingerprint}"
            )
    if result.warnings:
        console.print(
            "\n[bold yellow]TLS Findings[/bold yellow]"
        )

        for warning in result.warnings:
            console.print(
                f"  [yellow]![/yellow] "
                f"{escape(warning)}"
            )
    if result.ip_addresses:
        console.print(
            "\n[bold]IP Subject Alternative Names[/bold]"
        )

        for address in result.ip_addresses[:san_limit]:
            console.print(
                f"  {escape(address)}"
            )

        remaining = (
            len(result.ip_addresses)
            - san_limit
        )

        if remaining > 0:
            console.print(
                f"[dim]  ... {remaining} more[/dim]"
            )
    if hostname_candidates:
        console.print(
            "\n[bold]Discovered Hostname Candidates[/bold]"
        )

        for candidate in hostname_candidates[:san_limit]:
            console.print(
                f"  {escape(candidate.hostname)}"
            )

        remaining = (
            len(hostname_candidates)
            - san_limit
        )

        if remaining > 0:
            console.print(
                f"[dim]  ... {remaining} more[/dim]"
            )







def print_http_cookies(
    cookies: list[CookieInfo]
) -> None:

    if not cookies:
        return

    table = Table(
        title="HTTP Cookies",
        show_header=True,
        header_style="bold",
    )

    table.add_column("Cookie")
    table.add_column("Secure")
    table.add_column("HttpOnly")
    table.add_column("SameSite")
    table.add_column("Path")

    for cookie in cookies:

        secure = (
            "[green]YES[/green]"
            if cookie.secure
            else "[yellow]NO[/yellow]"
        )

        httponly = (
            "[green]YES[/green]"
            if cookie.httponly
            else "[yellow]NO[/yellow]"
        )

        table.add_row(
            cookie.name,
            secure,
            httponly,
            cookie.samesite or "Not set",
            cookie.path or "Not set",
        )

    console.print(table)
def print_redirect_chain(
    chain: list[RedirectHop]
) -> None:

    if len(chain) <= 1:
        return

    table = Table(
        title="Redirect Chain",
        show_header=True,
        header_style="bold",
    )

    table.add_column(
        "Step",
        justify="right",
    )

    table.add_column(
        "Status",
    )

    table.add_column(
        "URL",
        overflow="fold",
    )

    table.add_column(
        "Location",
        overflow="fold",
    )

    for index, hop in enumerate(
        chain,
        start=1,
    ):

        status_color = http_status_style(
            hop.status_code
        )

        table.add_row(
            str(index),

            (
                f"[{status_color}]"
                f"{hop.status_code}"
                f"[/{status_color}]"
            ),

            escape(hop.url),

            (
                escape(hop.location)
                if hop.location
                else "-"
            ),
        )

    console.print(table)

def print_cookie_findings(
    findings: list[CookieFinding]
) -> None:

    if not findings:
        return

    table = Table(
        title="Cookie Security Findings",
        show_header=True,
        header_style="bold",
    )

    table.add_column(
        "Cookie",
        no_wrap=True,
    )

    table.add_column(
        "Check",
        no_wrap=True,
    )

    table.add_column(
        "Status",
        no_wrap=True,
    )

    table.add_column(
        "Severity",
        no_wrap=True,
    )

    table.add_column(
        "Note",
        overflow="fold",
    )

    for finding in findings:

        status_color = status_style(
            finding.status
        )

        severity_color = severity_style(
            finding.severity
        )

        table.add_row(
            finding.cookie,
            finding.check,

            (
                f"[{status_color}]"
                f"{finding.status}"
                f"[/{status_color}]"
            ),

            (
                f"[{severity_color}]"
                f"{finding.severity}"
                f"[/{severity_color}]"
            ),

            finding.note,
        )

    console.print(table)
#------------------web resource----------------
def print_web_resources(
    resources: list[WebResource]
) -> None:

    table = Table(
        title="Known Web Resources",
        show_header=True,
        header_style="bold",
    )

    table.add_column(
        "Resource"
    )

    table.add_column(
        "Status"
    )

    table.add_column(
        "Found"
    )

    table.add_column(
        "URL",
        overflow="fold",
    )

    for resource in resources:

        status = (
            str(resource.status_code)
            if resource.status_code is not None
            else "ERROR"
        )

        found_text = (
            "[green]YES[/green]"
            if resource.found
            else "[yellow]NO[/yellow]"
        )

        table.add_row(
            resource.name,
            status,
            found_text,
            escape(resource.url),
        )

    console.print(table)
#----------------------sitemap--------------------
def print_sitemap_info(
    sitemap: SitemapInfo | None
) -> None:

    if sitemap is None:
        return

    if sitemap.error:

        console.print(
            "[yellow]"
            "Sitemap parsing failed: "
            f"{escape(sitemap.error)}"
            "[/yellow]"
        )

        return

    if not sitemap.urls and not sitemap.sitemaps:
        return

    table = Table(
        title="Sitemap Discovery",
        show_header=True,
        header_style="bold",
    )

    table.add_column("Type")
    table.add_column(
        "URL",
        overflow="fold",
    )

    for url in sitemap.urls:

        table.add_row(
            "URL",
            escape(url),
        )

    for url in sitemap.sitemaps:

        table.add_row(
            "Sitemap",
            escape(url),
        )

    console.print(table)
#security.xml
def print_security_txt_info(
    info: SecurityTxtInfo | None
) -> None:

    if info is None:
        return

    table = Table(
        title="security.txt",
        show_header=True,
        header_style="bold",
    )

    table.add_column(
        "Field",
        no_wrap=True,
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    for contact in info.contacts:
        table.add_row(
            "Contact",
            escape(contact),
        )

    for canonical in info.canonical:
        table.add_row(
            "Canonical",
            escape(canonical),
        )

    for policy in info.policy:
        table.add_row(
            "Policy",
            escape(policy),
        )

    for acknowledgment in info.acknowledgments:
        table.add_row(
            "Acknowledgments",
            escape(acknowledgment),
        )

    if info.expires:

        table.add_row(
            "Expires",
            escape(info.expires),
        )

    if info.preferred_languages:

        table.add_row(
            "Languages",
            ", ".join(
                info.preferred_languages
            ),
        )

    console.print(table)
#URL candidate
def print_url_candidates(
    candidates: list[URLCandidate],
    limit: int = 30,
) -> None:

    if not candidates:
        return

    table = Table(
        title="Discovered URL Candidates",
        show_header=True,
        header_style="bold",
    )

    table.add_column(
        "Source",
        no_wrap=True,
    )

    table.add_column(
        "Scope",
        no_wrap=True,
    )

    table.add_column(
        "URL",
        overflow="fold",
    )

    for candidate in candidates[:limit]:

        scope = (
            "[green]SAME-HOST[/green]"
            if candidate.same_host
            else "[yellow]EXTERNAL[/yellow]"
        )

        table.add_row(
            candidate.source,
            scope,
            escape(candidate.url),
        )

    console.print(table)

    remaining = (
        len(candidates)
        - limit
    )

    if remaining > 0:

        console.print(
            f"[dim]"
            f"... {remaining} more candidates "
            f"not displayed"
            f"[/dim]"
        )
def print_content_results(
    results: list[ContentProbe]
) -> None:

    if not results:
        return

    table = Table(
        title="Content Discovery",
        show_header=True,
        header_style="bold",
    )

    table.add_column(
        "Status",
        no_wrap=True,
    )

    table.add_column(
        "Class",
        no_wrap=True,
    )

    table.add_column(
        "Source",
        no_wrap=True,
    )

    table.add_column(
        "Length",
        justify="right",
    )

    table.add_column(
        "URL",
        overflow="fold",
    )

    for result in results:

        status = (
            str(result.status_code)
            if result.status_code
            is not None
            else "-"
        )

        length = (
            str(result.content_length)
            if result.content_length
            is not None
            else "-"
        )

        table.add_row(
            status,
            result.classification,
            result.source,
            length,
            escape(result.url),
        )

    console.print(table)
