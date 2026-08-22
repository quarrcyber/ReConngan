import json
import httpx

from rich.console import Console
from rich.markup import escape
#sub files
from .models import HeaderRule, Finding
from .headers import analyze_headers
from .scoring import (
    calculate_score,
    calculate_grade,
    grade_meets_threshold,
)
from .reporting import (
    console,
    print_target_info,
    print_http_metadata,
    print_report,
    build_report_data,
    write_json_report,
)
from .network import (
    normalize_url,
    fetch_url,
)
from .cli import parse_args
from .http_recon import collect_http_metadata
#console
console = Console()

#-----------------------main---------------------------------
def main() -> int:

    args = parse_args()

    target = args.target

    url = normalize_url(target)

    try:
        response = fetch_url(
            url,
            timeout=args.timeout,
            follow_redirects=not args.no_redirect,    
        )
    except httpx.TimeoutException:
        console.print(
            "[red][!] Request timed out.[/red]"
        )
        return 3

    except httpx.RequestError as exc:
        console.print(
            f"[red][!] Request failed: "
            f"{escape(str(exc))}[/red]"
        )
        return 3

    print_target_info(
        url,
        response.status_code,
        str(response.url)
    )

    http_metadata = collect_http_metadata(
        response
    )

    print_http_metadata(
        http_metadata
    )

    findings = analyze_headers(
        response.headers
    )
#score
    score = calculate_score(findings)
    grade = calculate_grade(score)

    print_report(
        findings,
        score,
        grade
    )
    if args.json:

        report_data = build_report_data(
            target=url,
            final_url=str(response.url),
            status_code=response.status_code,
            metadata=http_metadata,
            findings=findings,
            score=score,
            grade=grade,
        )

        write_json_report(
            report_data,
            args.json,
        )

        console.print(
            f"\n[green][+] JSON report saved to "
            f"{escape(args.json)}[/green]"
        )
    if args.fail_under:

        if not grade_meets_threshold(
            grade,
            args.fail_under,
        ):

            console.print(
                f"\n[red][!] Grade {grade} "
                f"is below required grade "
                f"{args.fail_under}.[/red]"
            )

            return 1
    return 0

#===========================================
#test offline part
def test_http_metadata_offline():

    print(
        "\n[OFFLINE TEST] HTTP metadata"
    )
    print("-" * 55)

    response = httpx.Response(
        200,
        headers={
            "Content-Type":
                "text/html; charset=utf-8",

            "Content-Length":
                "12345",
        },
    )

    response.extensions[
        "http_version"
    ] = b"HTTP/2"

    response._elapsed = (
        __import__("datetime")
        .timedelta(milliseconds=150)
    )

    metadata = collect_http_metadata(
        response
    )

    checks = [
        (
            "HTTP version",
            metadata.http_version == "HTTP/2",
        ),
        (
            "Response time",
            metadata.response_time_ms == 150.0,
        ),
        (
            "Content-Type",
            metadata.content_type
            == "text/html; charset=utf-8",
        ),
        (
            "Content-Length",
            metadata.content_length
            == "12345",
        ),
    ]

    for name, passed in checks:

        print(
            f"{name:<20}"
            f"{'[PASS]' if passed else '[FAIL]'}"
        )
