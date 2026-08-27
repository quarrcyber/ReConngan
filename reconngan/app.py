import json
import httpx
import time

from rich.console import Console
from rich.markup import escape
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    MofNCompleteColumn,
    TimeElapsedColumn,
)
from rich.table import Table

#sub files
from .models import (
    HeaderRule,
    Finding,
    WebResourceAnalysis,
)
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
    print_tls_info,
)
from .network import (
    normalize_url,
    fetch_url,
    parse_tls_endpoint,
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
    ContentDiscoveryInterrupted,
)
from .tls_recon import (
    TLSProbeError,
    probe_tls,
)

#console
console = Console()

#-----------------------main---------------------------------
def main() -> int:
    scan_started = time.perf_counter()
    args = parse_args()

    target = args.target
    url = normalize_url(target)

    # =========================================================
    # 1. FETCH MAIN TARGET
    # =========================================================

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

    # =========================================================
    # 2. TARGET INFORMATION
    # =========================================================

    print_target_info(
        url,
        response.status_code,
        str(response.url),
    )

    # =========================================================
    # 3. CORE: HTTP INFORMATION
    # =========================================================

    http_metadata = collect_http_metadata(
        response
    )

    print_http_metadata(
        http_metadata
    )

    # =========================================================
    # 4. CORE: SECURITY HEADERS
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
    # OPTIONAL MODULE STATE
    #
    # These defaults are important for JSON output.
    # If a module was not executed, its result stays empty.
    # =========================================================

    redirect_chain = []

    cookies = []
    cookie_findings = []

    web_resources = []

    web_analysis = WebResourceAnalysis(
        robots=None,
        sitemap=None,
        security_txt=None,
        candidates=[],
    )

    security_txt_info = None

    content_results = []
    tls_result = None
    scan_interrupted = False

    # =========================================================
    # OPTIONAL: TLS INTELLIGENCE
    # =========================================================

    if args.tls or args.all_modules:
        try:
            tls_host, tls_port = parse_tls_endpoint(
                target
            )

            tls_result = probe_tls(
                host=tls_host,
                port=tls_port,
                timeout=args.timeout,
            )

        except (
            ValueError,
            TLSProbeError,
        ) as exc:
            console.print(
                f"\n[red][!] TLS probe failed: "
                f"{escape(str(exc))}[/red]"
            )

        else:
            print_tls_info(
                tls_result
            )
    # =========================================================
    # OPTIONAL: REDIRECT RECONNAISSANCE
    # =========================================================

    needs_redirect_data = (
        args.redirects
        or args.candidates
        or args.content is not None
        or args.all_modules
    )

    if needs_redirect_data:
        redirect_chain = collect_redirect_chain(
            response
        )

    if args.redirects or args.all_modules:
        print_redirect_chain(
            redirect_chain
        )

    # =========================================================
    # 6. OPTIONAL: COOKIE SECURITY
    # =========================================================

    if args.cookies or args.all_modules:

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
    # 7. PLAN WEB RESOURCE REQUESTS
    # =========================================================

    resource_names: set[str] = set()

    # --resources, --candidates and --content require the
    # complete known-resource discovery set.
    if (
        args.resources
        or args.candidates
        or args.content
        or args.all_modules
    ):
        resource_names.update(
            {
                "robots.txt",
                "sitemap.xml",
                "security.txt",
            }
        )

    else:
        # Individual resource flags should only request
        # the resource explicitly requested by the user.

        if args.sitemap:
            resource_names.add(
                "sitemap.xml"
            )

        if args.security_txt:
            resource_names.add(
                "security.txt"
            )

    # =========================================================
    # 8. OPTIONAL: WEB RESOURCE DISCOVERY
    # =========================================================

    if resource_names:

        web_resources = collect_web_resources(
            base_url=str(response.url),
            timeout=args.timeout,
            names=resource_names,
        )

        web_analysis = analyze_web_resources(
            base_url=str(response.url),
            resources=web_resources,
            redirect_chain=redirect_chain,
        )

        security_txt_info = (
            web_analysis.security_txt
        )

    # =========================================================
    # 9. OPTIONAL OUTPUT: KNOWN WEB RESOURCES
    # =========================================================

    if args.resources or args.all_modules:
        print_web_resources(
            web_resources
        )

    # =========================================================
    # 10. OPTIONAL OUTPUT: SITEMAP
    # =========================================================

    if args.sitemap or args.all_modules:
        print_sitemap_info(
            web_analysis.sitemap
        )

    # =========================================================
    # 11. OPTIONAL OUTPUT: SECURITY.TXT
    # =========================================================

    if args.security_txt or args.all_modules:
        print_security_txt_info(
            web_analysis.security_txt
        )

    # =========================================================
    # 12. OPTIONAL OUTPUT: URL CANDIDATES
    # =========================================================

    if args.candidates or args.all_modules:
        print_url_candidates(
            web_analysis.candidates
        )

    # =========================================================
    # 13. OPTIONAL: ACTIVE CONTENT DISCOVERY
    # =========================================================

    if args.content is not None or args.all_modules:

        content_started = time.perf_counter()
        content_limit = (
            args.content
            if args.content is not None
            else 50
        )
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn(
                    "[cyan]{task.description}[/cyan]"
                ),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:

                task_id = progress.add_task(
                    "Content discovery",
                    total=None,
                )

                def update_content_progress(
                    completed: int,
                    total: int,
                    current: str,
                ) -> None:
                    progress.update(
                        task_id,
                        completed=completed,
                        total=total,
                    )
                content_results = discover_content(
                    base_url=str(response.url),
                    candidates=web_analysis.candidates,
                    timeout=args.timeout,
                    max_candidates=content_limit,
                    progress_callback=(
                        update_content_progress
                    ),
                )

        except ContentDiscoveryInterrupted as exc:
            content_results = exc.results
            scan_interrupted = True

        content_elapsed = (
            time.perf_counter()
            - content_started
        )

        if content_results:
            print_content_results(
                content_results
            )

        if scan_interrupted:
            console.print(
                "\n[yellow][!] Content discovery "
                "cancelled by user.[/yellow]"
            )

            console.print(
                "[yellow]"
                f"[+] Preserved "
                f"{len(content_results)} completed probes"
                f" after {content_elapsed:.2f}s."
                "[/yellow]"
            )

        else:
            console.print(
                "\n[green][+] Content discovery "
                "completed.[/green] "
                f"[dim]"
                f"{len(content_results)} probes "
                f"in {content_elapsed:.2f}s"
                f"[/dim]"
            )


    # =========================================================
    # 14. JSON REPORT
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
            tls_result=tls_result,
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

    # =========================================================
    # 15. FAIL-UNDER POLICY
    # =========================================================

        if scan_interrupted:
            scan_elapsed = (
                time.perf_counter()
                - scan_started
            )

            console.print(
                f"\n[yellow][!] Scan stopped by user "
                f"after {scan_elapsed:.2f}s.[/yellow]"
            )

            return 130


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
    scan_elapsed = (
        time.perf_counter()
        - scan_started
    )

    console.print(
        f"\n[green][+] Scan completed[/green] "
        f"[dim]in {scan_elapsed:.2f}s[/dim]"
    )

    return 0
#===========================================
#test offline part
