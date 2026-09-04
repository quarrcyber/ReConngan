import json
import httpx
import time
from urllib.parse import urlsplit, urljoin
from pathlib import Path


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
    print_http_intelligence,
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
    print_path_discovery_results,

    print_tls_info,
    print_dns_resolutions,
    print_dns_intelligence,
    print_service_probes,
    print_dns_records,
    print_correlation,
)
from .network import (
    normalize_url,
    fetch_url,
    parse_tls_endpoint,
)
from .cli import parse_args
from .http_recon import (
    collect_http_metadata,
    collect_http_intelligence,
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
    PathDiscoveryInterrupted,
    WordlistLoadError,
    build_wordlist_candidates,
    filter_interesting_wordlist_results,
    discover_wordlist_paths,
    expand_wordlist_entries,
    load_wordlist,
    merge_url_candidates,
)


from .tls_recon import (
    TLSProbeError,
    collect_tls_hostname_candidates,
    probe_tls,
)
from .service_recon import (
    probe_resolved_host_services,
)
from .dns_recon import (
    DEFAULT_DNS_RECORD_TYPES,
    DNS_INTELLIGENCE_QUERY_COUNT,
    build_target_hostname_candidate,
    collect_dns_intelligence,
    merge_hostname_candidates,
    query_dns_records,
    resolve_hostname_candidates,
)
from .correlation import (
    correlate_recon_evidence,
)

#console
console = Console()

#-----------------------main---------------------------------
def main() -> int:
    scan_started = time.perf_counter()
    args = parse_args()

    correlation_requested = (
        args.correlate
        or args.all_modules
    )

    http_intel_requested = (
        args.http_intel
        or args.all_modules
        or correlation_requested
    )

    tls_requested = (
        args.tls
        or args.all_modules
        or correlation_requested
    )

    dns_records_requested = (
        args.dns_records
        or args.all_modules
        or correlation_requested
    )

    dns_validation_requested = (
        args.resolve_hosts is not None
        or args.all_modules
        or correlation_requested
    )

    service_validation_requested = (
        args.services is not None
        or args.all_modules
        or correlation_requested
    )

    redirects_requested = (
        args.redirects
        or args.all_modules
        or correlation_requested
    )

    def option_limit(
        value: object,
        default: int,
    ) -> int:
        if isinstance(
            value,
            bool,
        ):
            return default

        if value is None:
            return default

        return int(
            value
        )

    target = args.target
    url = normalize_url(
        target
    )

    target_hostname = urlsplit(
        url
    ).hostname

    http_intelligence = None

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


    if http_intel_requested:
        http_intelligence = collect_http_intelligence(
            response
        )

        print_http_intelligence(
            http_intelligence
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

    target_candidate = build_target_hostname_candidate(
        target_hostname
    )

    hostname_candidates = (
        [target_candidate]
        if target_candidate is not None
        else []
    )

    dns_records = []
    dns_resolutions = []
    dns_intelligence = None
    service_probes = []
    correlation = None



    scan_interrupted = False

    # =========================================================
    # OPTIONAL: TLS INTELLIGENCE
    # =========================================================

    needs_tls_data = (
        tls_requested
        or dns_validation_requested
        or service_validation_requested
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

            tls_hostname_candidates = (
                collect_tls_hostname_candidates(
                    tls_result
                )
            )

            hostname_candidates = (
                merge_hostname_candidates(
                    hostname_candidates,
                    tls_hostname_candidates,
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
            if tls_requested:
                print_tls_info(
                    tls_result,
                    hostname_candidates,
                )


    # =========================================================
    # OPTIONAL: DNS HOST VALIDATION
    # =========================================================

    needs_dns_data = (
        dns_validation_requested
        or service_validation_requested
    )

    if needs_dns_data:

        dns_limits: list[int] = []

        if args.resolve_hosts is not None:
            dns_limits.append(
                option_limit(
                    args.resolve_hosts,
                    50,
                )
            )

        if args.services is not None:
            dns_limits.append(
                option_limit(
                    args.services,
                    25,
                )
            )

        if correlation_requested or args.all_modules:
            dns_limits.append(
                50
            )


        if correlation_requested or args.all_modules:
            dns_limits.append(
                50
            )

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

        if dns_validation_requested:

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
    # OPTIONAL: DNS RECORD ENUMERATION
    # =========================================================

    if dns_records_requested:

        if not target_hostname:
            console.print(
                "\n[red][!] Unable to determine target "
                "hostname for DNS records.[/red]"
            )
            return 2

        dns_records_started = (
            time.perf_counter()
        )

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
                "DNS records",
                total=DNS_INTELLIGENCE_QUERY_COUNT,
            )

            def update_dns_records_progress(
                completed: int,
                total: int,
                current: str,
            ) -> None:
                progress.update(
                    task_id,
                    completed=completed,
                    total=total,
                    description=(
                        f"DNS record {current}"
                    ),
                )

            dns_intelligence = collect_dns_intelligence(
                hostname=target_hostname,
                timeout=args.timeout,
                progress_callback=(
                    update_dns_records_progress
                ),
            )

            dns_records = dns_intelligence.records

        dns_records_elapsed = (
            time.perf_counter()
            - dns_records_started
        )

        print_dns_records(
            dns_records
        )

        print_dns_intelligence(
            dns_intelligence
        )

        console.print(
            "\n[green][+] DNS records "
            "completed.[/green] "
            f"[dim]"
           f"{DNS_INTELLIGENCE_QUERY_COUNT} query step(s) "
            f"in {dns_records_elapsed:.2f}s"
            f"[/dim]"
        )
    # =========================================================
    # OPTIONAL: SERVICE VALIDATION
    # =========================================================


    if service_validation_requested:
        service_limit = option_limit(
            args.services,
            25,
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
        redirects_requested
        or args.candidates
        or args.content is not None
    )

    if needs_redirect_data:
        redirect_chain = collect_redirect_chain(
            response
        )

    if redirects_requested:
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
    )

    if wordlist_requested:

        # "" means:
        # --wordlist was provided without a file.
        #
        # None here therefore means use built-in entries.
        wordlist_file = args.wordlist
        #wordlist included file
        try:
            (
                wordlist_entries,
                wordlist_source,
            ) = load_wordlist(
                file_path=wordlist_file,
                limit=args.wordlist_limit,
            )
            base_wordlist_count = len(
                wordlist_entries
            )

            wordlist_entries = expand_wordlist_entries(
                entries=wordlist_entries,
                extensions=args.extensions,
            )

            expanded_wordlist_count = len(
                wordlist_entries
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

        if args.extensions:
            extension_text = ",".join(
                args.extensions
            )

            console.print(
                "\n[dim]"
                f"Wordlist: "
                f"{base_wordlist_count} base path(s), "
                f"{expanded_wordlist_count} expanded path(s), "
                f"{len(wordlist_candidates)} URL candidate(s), "
                f"extensions={escape(extension_text)}, "
                f"source={escape(wordlist_source)}"
                f"[/dim]"
            )
        else:
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
    # OPTIONAL: PASSIVE CONTENT DISCOVERY
    # =========================================================

    content_discovery_requested = (
        args.content is not None
        or args.all_modules
    )

    if content_discovery_requested:
        passive_limit = (
            args.content
            if args.content is not None
            else 50
        )

        content_started = (
            time.perf_counter()
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
                    "Passive content discovery",
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
                        description=(
                            "Content "
                            f"{current}"
                        ),
                    )

                content_results = discover_content(
                    base_url=str(response.url),
                    candidates=web_analysis.candidates,
                    timeout=args.timeout,
                    max_candidates=passive_limit,
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
                "\n[yellow][!] Passive content discovery "
                "cancelled by user.[/yellow]"
            )
        else:
            console.print(
                "\n[green][+] Passive content discovery "
                "completed.[/green] "
                f"[dim]"
                f"{len(content_results)} result(s) "
                f"in {content_elapsed:.2f}s"
                f"[/dim]"
            )


    # =========================================================
    # OPTIONAL: ACTIVE SUBDIRECTORY / PATH DISCOVERY
    # =========================================================

    if wordlist_requested:
        path_started = (
            time.perf_counter()
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
                    "Subdirectory/path discovery",
                    total=len(wordlist_candidates),
                )

                def update_path_progress(
                    completed: int,
                    total: int,
                    current: str,
                ) -> None:
                    progress.update(
                        task_id,
                        completed=completed,
                        total=total,
                        description=(
                            "Path "
                            f"{current}"
                        ),
                    )

                wordlist_results = discover_wordlist_paths(
                    base_url=str(response.url),
                    candidates=wordlist_candidates,
                    timeout=args.timeout,
                    concurrency=args.concurrency,
                    rate_limit=args.rate,
                    max_response_bytes=(
                        args.max_response_bytes
                    ),
                    min_response_size=(
                        args.min_response_size
                    ),
                    max_response_size=(
                        args.max_response_size
                    ),
                    depth_limit=args.depth,
                    progress_callback=(
                        update_path_progress
                    ),
                )



        except PathDiscoveryInterrupted as exc:
            wordlist_results = exc.results
            scan_interrupted = True

        path_elapsed = (
            time.perf_counter()
            - path_started
        )

        if wordlist_results:
            print_path_discovery_results(
                wordlist_results
            )
        else:
            console.print(
                "\n[dim]"
                "No existing subdirectories or paths "
                "discovered."
                "[/dim]"
            )


        if scan_interrupted:
            console.print(
                "\n[yellow][!] Subdirectory/path discovery "
                "cancelled by user.[/yellow]"
            )
        else:
            rate_text = (
                "unlimited"
                if args.rate is None
                else f"{args.rate:g} req/s"
            )
            size_filter_parts: list[str] = []

            if args.min_response_size is not None:
                size_filter_parts.append(
                    f"min {args.min_response_size}"
                )

            if args.max_response_size is not None:
                size_filter_parts.append(
                    f"max {args.max_response_size}"
                )

            size_filter_text = (
                ", ".join(size_filter_parts)
                if size_filter_parts
                else "none"
            )
            console.print(
                "\n[green][+] Subdirectory/path discovery "
                "completed.[/green] "
                f"[dim]"
                f"{len(wordlist_candidates)} tested, "
                f"{len(wordlist_results)} found, "
                f"concurrency {args.concurrency}, "
                f"depth {args.depth}, "
                f"rate {rate_text}, "
                f"size filter {size_filter_text} "
                f"in {path_elapsed:.2f}s"
                f"[/dim]"
            )

    # =========================================================
    # OPTIONAL: RECON CORRELATION
    # =========================================================

    if correlation_requested:
        correlation = correlate_recon_evidence(
            target=target_hostname or url,
            tls_result=tls_result,
            dns_intelligence=dns_intelligence,
            dns_resolutions=dns_resolutions,
            hostname_candidates=hostname_candidates,
            service_probes=service_probes,
            redirect_chain=redirect_chain,
            http_intelligence=http_intelligence,
        )

        print_correlation(
            correlation
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
            http_intelligence=http_intelligence,
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

            dns_records=dns_records,
            dns_intelligence=dns_intelligence,
            dns_resolutions=dns_resolutions,
            service_probes=service_probes,

            correlation=correlation,
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
