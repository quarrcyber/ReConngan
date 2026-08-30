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
    print_dns_resolutions,
    print_service_probes,

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
from .wordlist_discovery import (
    WordlistLoadError,
    build_wordlist_candidates,
    filter_interesting_wordlist_results,
    load_wordlist,
    merge_url_candidates,
)


from .tls_recon import (
    TLSProbeError,
    collect_tls_hostname_candidates,
    probe_tls,
)
from .dns_recon import (
    resolve_hostname_candidates,
)
from .service_recon import (
    probe_resolved_host_services,
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
    wordlist_candidates = []
    wordlist_results = []

    tls_result = None
    hostname_candidates = []
    dns_resolutions = []
    service_probes = []


    scan_interrupted = False

    # =========================================================
    # OPTIONAL: TLS INTELLIGENCE
    # =========================================================

    needs_tls_data = (
        args.tls
        or args.resolve_hosts is not None
        or args.services is not None
        or args.all_modules
    )

    if needs_tls_data:
        try:
            tls_host, tls_port = parse_tls_endpoint(
                target
            )

            tls_result = probe_tls(
                host=tls_host,
                port=tls_port,
                timeout=args.timeout,
            )

            hostname_candidates = (
                collect_tls_hostname_candidates(
                    tls_result
                )
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
            if args.tls or args.all_modules:
                print_tls_info(
                    tls_result,
                    hostname_candidates,
                )

    # =========================================================
    # OPTIONAL: DNS HOST VALIDATION
    # =========================================================

    needs_dns_data = (
        args.resolve_hosts is not None
        or args.services is not None
        or args.all_modules
    )

    if needs_dns_data:

        dns_limits: list[int] = []

        if args.resolve_hosts is not None:
            dns_limits.append(
                args.resolve_hosts
            )

        if args.services is not None:
            dns_limits.append(
                args.services
            )

        if args.all_modules:
            dns_limits.append(50)

        dns_limit = max(
            dns_limits,
            default=50,
        )

        dns_started = time.perf_counter()

        with Progress(
            SpinnerColumn(),
            TextColumn(
                "[cyan]"
                "{task.description}"
                "[/cyan]"
            ),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:

            total_hosts = min(
                len(hostname_candidates),
                dns_limit,
            )

            task_id = progress.add_task(
                "DNS validation",
                total=total_hosts,
            )

            def update_dns_progress(
                completed: int,
                total: int,
                current: str,
            ) -> None:

                progress.update(
                    task_id,
                    completed=completed,
                    total=total,
                    description=(
                        f"DNS {current}"
                    ),
                )

            dns_resolutions = (
                resolve_hostname_candidates(
                    candidates=hostname_candidates,
                    timeout=args.timeout,
                    max_candidates=dns_limit,
                    progress_callback=(
                        update_dns_progress
                    ),
                )
            )

        dns_elapsed = (
            time.perf_counter()
            - dns_started
        )

        if (
            args.resolve_hosts is not None
            or args.all_modules
        ):
            print_dns_resolutions(
                dns_resolutions
            )

            console.print(
                "\n[green][+] DNS validation "
                "completed.[/green] "
                f"[dim]"
                f"{len(dns_resolutions)} hosts "
                f"in {dns_elapsed:.2f}s"
                f"[/dim]"
            )

    # =========================================================
    # OPTIONAL: SERVICE VALIDATION
    # =========================================================

    if (
        args.services is not None
        or args.all_modules
    ):
        service_limit = (
            args.services
            if args.services is not None
            else 25
        )

        service_started = (
            time.perf_counter()
        )

        resolved_hosts = sum(
            1
            for result in dns_resolutions
            if result.resolved
        )

        total_endpoints = (
            min(
                resolved_hosts,
                service_limit,
            )
            * 2
        )

        with Progress(
            SpinnerColumn(),
            TextColumn(
                "[cyan]"
                "{task.description}"
                "[/cyan]"
            ),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:

            task_id = progress.add_task(
                "Service validation",
                total=total_endpoints,
            )

            def update_service_progress(
                completed: int,
                total: int,
                current: str,
            ) -> None:

                progress.update(
                    task_id,
                    completed=completed,
                    total=total,
                    description=(
                        f"Service {current}"
                    ),
                )

            service_probes = (
                probe_resolved_host_services(
                    resolutions=dns_resolutions,
                    timeout=args.timeout,
                    max_hosts=service_limit,
                    follow_redirects=(
                        not args.no_redirect
                    ),
                    progress_callback=(
                        update_service_progress
                    ),
                )
            )

        service_elapsed = (
            time.perf_counter()
            - service_started
        )

        print_service_probes(
            service_probes
        )

        console.print(
            "\n[green][+] Service validation "
            "completed.[/green] "
            f"[dim]"
            f"{len(service_probes)} endpoints "
            f"in {service_elapsed:.2f}s"
            f"[/dim]"
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
    # WORDLIST CANDIDATE GENERATION
    # =========================================================

    wordlist_requested = (
        args.wordlist is not None
        or args.all_modules
    )

    if wordlist_requested:

        # "" means:
        # --wordlist was provided without a file.
        #
        # None here therefore means use built-in entries.
        wordlist_file = (
            args.wordlist
            if args.wordlist
            else None
        )

        try:
            (
                wordlist_entries,
                wordlist_source,
            ) = load_wordlist(
                file_path=wordlist_file,
                limit=args.wordlist_limit,
            )

        except WordlistLoadError as exc:
            console.print(
                "\n[red][!] Wordlist error: "
                f"{escape(str(exc))}[/red]"
            )
            return 2

        try:
            wordlist_candidates = (
                build_wordlist_candidates(
                    base_url=str(
                        response.url
                    ),
                    entries=wordlist_entries,
                    source=wordlist_source,
                )
            )

        except ValueError as exc:
            console.print(
                "\n[red][!] Unable to build "
                "wordlist candidates: "
                f"{escape(str(exc))}[/red]"
            )
            return 2

        console.print(
            "\n[dim]"
            f"Wordlist: "
            f"{len(wordlist_candidates)} "
            f"candidate(s) loaded from "
            f"{escape(wordlist_source)}"
            f"[/dim]"
        )
    # =========================================================
    # OPTIONAL OUTPUT: URL CANDIDATES
    # =========================================================

    if args.candidates or args.all_modules:
        all_url_candidates = (
        merge_url_candidates(
                web_analysis.candidates,
                wordlist_candidates,
            )
        )
        print_url_candidates(
            all_url_candidates
        )

    # =========================================================
    # OPTIONAL: ACTIVE CONTENT / WORDLIST DISCOVERY
    # =========================================================

    active_discovery_requested = (
        args.content is not None
        or args.wordlist is not None
        or args.all_modules
    )

    if active_discovery_requested:

        passive_candidates = []

        if (
            args.content is not None
            or args.all_modules
        ):
            passive_limit = (
                args.content
                if args.content is not None
                else 50
            )

            passive_candidates = (
                web_analysis.candidates[:20]
            )

        active_wordlist_candidates = []

        if wordlist_requested:
            active_wordlist_candidates = (
                wordlist_candidates
            )

        active_candidates = (
        merge_url_candidates(
                passive_candidates,
                active_wordlist_candidates,
            )
        )

        content_started = (
            time.perf_counter()
        )
#Progress
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
                    max_candidates=len(
                        active_candidates
                    ),
                    progress_callback=(
                        update_content_progress
                    ),
                )

        except ContentDiscoveryInterrupted as exc:
            content_results = exc.results
            scan_interrupted = True
        # -------------------------------------------------
        # Separate results that belong to wordlist paths
        # -------------------------------------------------

        wordlist_urls = {
            candidate.url
            for candidate in wordlist_candidates
        }

        wordlist_results = [
            result
            for result in content_results
            if result.url in wordlist_urls
        ]
#--
        content_elapsed = (
            time.perf_counter()
            - content_started
        )

        wordlist_only = (
            args.wordlist is not None
            and args.content is None
            and not args.all_modules
        )

        if wordlist_only:

            interesting_results = (
                filter_interesting_wordlist_results(
                    wordlist_results
                )
            )

            if interesting_results:
                print_content_results(
                    interesting_results,
                    title="Wordlist Discovery",
                )

            else:
                console.print(
                    "\n[dim]"
                    "No interesting wordlist "
                    "responses discovered."
                    "[/dim]"
                )

        else:

            if content_results:
                print_content_results(
                    content_results
                )
        if scan_interrupted:
            console.print(
                "\n[yellow][!] Active discovery "
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
                "\n[green][+] Active discovery "
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

            wordlist_candidates=wordlist_candidates,
            wordlist_results=wordlist_results,

            tls_result=tls_result,
            hostname_candidates=hostname_candidates,
            dns_resolutions=dns_resolutions,
            service_probes=service_probes,
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
