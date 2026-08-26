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
    print_http_cookies,
    print_cookie_findings,
    print_redirect_chain,
    print_report,
    build_report_data,
    write_json_report,
    print_web_resources,
    print_sitemap_info,
    print_security_txt_info,
    print_url_candidates,
    print_content_results,
)
from .network import (
    normalize_url,
    fetch_url,
)
from .cli import parse_args
from .http_recon import (
    collect_http_metadata,
    collect_http_cookies,
    collect_redirect_chain,
    analyze_cookie_security,
)
from .web_resources import (
    collect_web_resources,
    analyze_web_resources,
    parse_sitemap_xml,
    parse_security_txt,
)
from .content_discovery import (
    discover_content,
)



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
# =========================================================
# 1. FETCH MAIN TARGET
# =========================================================
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


# =========================================================
# 2. TARGET INFORMATION
# =========================================================

    print_target_info(
        url,
        response.status_code,
        str(response.url),
    )


# =========================================================
# 3. REDIRECT RECONNAISSANCE
# =========================================================

    redirect_chain = collect_redirect_chain(
        response
    )

    print_redirect_chain(
        redirect_chain
    )


# =========================================================
# 4. HTTP METADATA
# =========================================================

    http_metadata = collect_http_metadata(
        response
    )

    print_http_metadata(
        http_metadata
    )


# =========================================================
# 5. COOKIE RECONNAISSANCE
# =========================================================

    cookies = collect_http_cookies(
        response
    )

    print_http_cookies(
        cookies
    )

    cookie_findings = analyze_cookie_security(
        cookies
    )

    print_cookie_findings(
        cookie_findings
    )


# =========================================================
# 6. SECURITY HEADER ANALYSIS
# =========================================================

    findings = analyze_headers(
        response.headers
    )

    score = calculate_score(
        findings
    )

    grade = calculate_grade(
        score
    )

    print_report(
        findings,
        score,
        grade,
    )


# =========================================================
# 7. KNOWN WEB RESOURCE DISCOVERY
# =========================================================

    web_resources = collect_web_resources(
        base_url=str(response.url),
        timeout=args.timeout,
    )

    print_web_resources(
        web_resources
    )


# =========================================================
# 8. ANALYZE DISCOVERED WEB RESOURCES
# =========================================================

    web_analysis = analyze_web_resources(
        base_url=str(response.url),
        resources=web_resources,
        redirect_chain=redirect_chain,
    )


# =========================================================
# 9. PARSED RESOURCE INFORMATION
# =========================================================

    print_sitemap_info(
        web_analysis.sitemap
    )

    print_security_txt_info(
        web_analysis.security_txt
    )


# =========================================================
# 10. DISCOVERED URL CANDIDATES
# =========================================================

    print_url_candidates(
        web_analysis.candidates
    )


# =========================================================
# 11. VERIFY DISCOVERED CONTENT
# =========================================================

    content_results = discover_content(
        base_url=str(response.url),
        candidates=web_analysis.candidates,
        timeout=args.timeout,
    )

    print_content_results(
        content_results
    )
# =========================================================
# JSON REPORT
# =========================================================
    if args.json:

        report_data = build_report_data(
            target=url,
            final_url=str(response.url),
            status_code=response.status_code,
            metadata=http_metadata,
            redirect_chain=redirect_chain,
            security_txt=security_txt_info,
            cookies=cookies,
            cookie_findings=cookie_findings,
            web_resources=web_resources,
            web_analysis=web_analysis,            
            content_results=content_results,
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
def test_content_discovery_offline():

    print(
        "\n[OFFLINE TEST] Content discovery"
    )
    print("-" * 55)

    from .content_discovery import (
        classify_status,
        response_similarity,
        looks_like_soft404,
    )

    baseline = (
        "<html>"
        "<h1>Page not found</h1>"
        "</html>"
    )

    candidate = (
        "<html>"
        "<h1>Page not found</h1>"
        "</html>"
    )

    checks = [
        (
            "200 FOUND",
            classify_status(200)
            == "FOUND",
        ),

        (
            "302 REDIRECT",
            classify_status(302)
            == "REDIRECT",
        ),

        (
            "403 PROTECTED",
            classify_status(403)
            == "PROTECTED",
        ),

        (
            "404 NOT_FOUND",
            classify_status(404)
            == "NOT_FOUND",
        ),

        (
            "similarity exact",
            response_similarity(
                baseline,
                candidate,
            ) == 1.0,
        ),

        (
            "soft404 detected",
            looks_like_soft404(
                status_code=200,
                body=candidate,
                baseline_status=200,
                baseline_body=baseline,
            ),
        ),
    ]

    for name, passed in checks:

        print(
            f"{name:<28}"
            f"{'[PASS]' if passed else '[FAIL]'}"
        )
