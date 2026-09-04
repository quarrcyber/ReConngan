import argparse
import os
import sys
from pathlib import Path
#color
YELLOW = "\033[33m"
RESET = "\033[0m"


def color_help_enabled() -> bool:
    """Return whether ANSI colors should be used in CLI help output."""
    return (
        sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
    )


def yellow_text(
    value: str,
) -> str:
    """Color text yellow when help colors are enabled."""
    if not color_help_enabled():
        return value

    return (
        f"{YELLOW}"
        f"{value}"
        f"{RESET}"
    )


class ReconnganHelpFormatter(
    argparse.RawDescriptionHelpFormatter
):
    """Argparse formatter with yellow section headings."""

    COLORED_SECTIONS = {
        "Positional arguments",
        "Options",
        "Network options",
        "Reconnaissance modules",
        "Output and policy",
    }

    def start_section(
        self,
        heading: str | None,
    ) -> None:
        if heading in self.COLORED_SECTIONS:
            heading = yellow_text(
                heading
            )

        super().start_section(
            heading
        )

    def _format_usage(
        self,
        usage: str | None,
        actions: list[argparse.Action],
        groups: list[argparse._MutuallyExclusiveGroup],
        prefix: str | None,
    ) -> str:
        if prefix is None:
            prefix = yellow_text(
                "Usage:"
            ) + " "

        return super()._format_usage(
            usage,
            actions,
            groups,
            prefix,
        )
#main
def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be an integer"
        ) from exc

    if number < 1:
        raise argparse.ArgumentTypeError(
            "must be greater than 0"
        )

    return number

def positive_float(
    value: str,
) -> float:
    try:
        number = float(
            value
        )
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be a number"
        ) from exc

    if number <= 0:
        raise argparse.ArgumentTypeError(
            "must be greater than 0"
        )

    return number

def non_negative_int(
    value: str,
) -> int:
    try:
        number = int(
            value
        )
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be an integer"
        ) from exc

    if number < 0:
        raise argparse.ArgumentTypeError(
            "must be greater than or equal to 0"
        )

    return number

def wordlist_limit_int(
    value: str,
) -> int:
    number = positive_int(
        value
    )

    if number > 50_000:
        raise argparse.ArgumentTypeError(
            "wordlist limit must not "
            "exceed 50.000"
        )

    return number

def depth_int(
    value: str,
) -> int:
    try:
        number = int(
            value
        )
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be an integer"
        ) from exc

    if number < 0:
        raise argparse.ArgumentTypeError(
            "must be greater than or equal to 0"
        )

    if number > 3:
        raise argparse.ArgumentTypeError(
            "depth must not exceed 3"
        )

    return number

def extension_list(
    value: str,
) -> tuple[str, ...]:
    extensions: list[str] = []
    seen: set[str] = set()

    for raw_extension in value.split(","):
        extension = (
            raw_extension
            .strip()
            .lower()
            .lstrip(".")
        )

        if not extension:
            continue

        if any(
            character in extension
            for character in (
                "/",
                "\\",
                "?",
                "#",
                ":",
                "*",
                " ",
            )
        ):
            raise argparse.ArgumentTypeError(
                f"invalid extension: {raw_extension!r}"
            )

        if extension in seen:
            continue

        seen.add(
            extension
        )

        extensions.append(
            extension
        )

    if not extensions:
        raise argparse.ArgumentTypeError(
            "at least one extension is required"
        )

    if len(extensions) > 20:
        raise argparse.ArgumentTypeError(
            "extensions must not exceed 20 values"
        )

    return tuple(
        extensions
    )

def parse_args():
    parser = argparse.ArgumentParser(
        prog="reconngan",
        description=(
            "Evidence-driven HTTP security "
            "reconnaissance scanner"
        ),
        epilog=(
            "Examples:\n"
            "  reconngan example.com\n"
            "  reconngan example.com --dns\n"
            "  reconngan example.com --target-ip\n"
            "  reconngan example.com --check-tls\n"
            "  reconngan example.com --check-cookies\n"
            "  reconngan example.com --known-files\n"
            "  reconngan example.com --show-redirects\n"
            "  reconngan example.com --show-sitemap\n"
            "  reconngan example.com --show-security-txt\n"
            "  reconngan example.com --discover-content\n"
            "  reconngan example.com --discover-paths paths.txt\n"
            "  reconngan example.com --save-report report.json\n"
            "  reconngan example.com --all"
        ),
        formatter_class=ReconnganHelpFormatter,
    )

    # =========================================================
    # TARGET
    # =========================================================

    parser.add_argument(
        "target",
        help="Target URL or domain to scan",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="ReConngan 0.2.1",
    )

    # =========================================================
    # NETWORK OPTIONS
    # =========================================================

    network_group = parser.add_argument_group(
        "Network options"
    )

    network_group.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Request timeout in seconds (default: 10)",
    )

    network_group.add_argument(
        "--concurrency",
        type=positive_int,
        default=40,
        metavar="N",
        help=(
            "Concurrent requests for active path discovery "
            "(default: 40)"
        ),
    )

    network_group.add_argument(
        "--rate",
        type=positive_float,
        default=None,
        metavar="RPS",
        help=(
            "Maximum active path discovery request rate "
            "in requests per second "
            "(default: unlimited)"
        ),
    )

    network_group.add_argument(
        "--max-response-bytes",
        type=positive_int,
        default=16_384,
        metavar="N",
        help=(
            "Maximum response bytes sampled per discovered path "
            "(default: 16384)"
        ),
    )
    network_group.add_argument(
        "--min-response-size",
        type=non_negative_int,
        default=None,
        metavar="N",
        help=(
            "Only keep active path discovery results "
            "with response size greater than or equal to N bytes."
        ),
    )

    network_group.add_argument(
        "--max-response-size",
        type=non_negative_int,
        default=None,
        metavar="N",
        help=(
            "Only keep active path discovery results "
            "with response size less than or equal to N bytes."
        ),
    )

    network_group.add_argument(
        "--no-redirect",
        dest="no_redirect",
        action="store_true",
        help=(
            "Do not follow HTTP redirects when fetching "
            "the main target."
        ),
    )

    # =========================================================
    # RECONNAISSANCE MODULES
    # =========================================================
    recon_group = parser.add_argument_group(
        "Reconnaissance modules"
    )

    recon_group.add_argument(
        "--check-cookies",
        dest="cookies",
        action="store_true",
        help=(
            "Analyze Set-Cookie security attributes "
            "(Secure, HttpOnly, SameSite)."
        ),
    )

    recon_group.add_argument(
        "--show-redirects",
        dest="redirects",
        action="store_true",
        help=(
            "Show the HTTP redirect chain from the "
            "original target to the final URL."
        ),
    )

    recon_group.add_argument(
        "--http-intel",
        dest="http_intel",
        action="store_true",
        help=(
            "Inspect HTTP technology hints, API indicators, "
            "authentication surface, and interesting metadata."
        ),
    )

    recon_group.add_argument(
        "--check-tls",
        dest="tls",
        action="store_true",
        help=(
            "Inspect TLS protocol, certificate issuer, "
            "expiry, SAN names, and certificate-derived hosts."
        ),
    )

    recon_group.add_argument(
        "--dns",
        "--target-ip",
        dest="resolve_hosts",
        nargs="?",
        const=50,
        default=None,
        type=positive_int,
        metavar="N",
        help=(
            "Resolve the target and discovered hostnames "
            "to IP addresses using DNS. Optionally limit to "
            "N hostnames (default: 50)."
        ),
    )
    recon_group.add_argument(
        "--dns-records",
        action="store_true",
        help=(
            "Query DNS records for the target domain "
            "(A, AAAA, CNAME, MX, NS, TXT)"
        ),
    )
    recon_group.add_argument(
        "--check-services",
        dest="services",
        nargs="?",
        const=25,
        default=None,
        type=positive_int,
        metavar="N",
        help=(
            "Check HTTP/80 and HTTPS/443 services on "
            "DNS-resolved hosts. Optionally limit to "
            "N hosts (default: 25)."
        ),
    )

    recon_group.add_argument(
        "--known-files",
        dest="resources",
        action="store_true",
        help=(
            "Probe common well-known files such as "
            "robots.txt, sitemap.xml, and security.txt."
        ),
    )

    recon_group.add_argument(
        "--show-sitemap",
        dest="sitemap",
        action="store_true",
        help=(
            "Fetch, parse, and display sitemap.xml "
            "entries."
        ),
    )

    recon_group.add_argument(
        "--show-security-txt",
        dest="security_txt",
        action="store_true",
        help=(
            "Fetch, parse, and display security.txt "
            "contact and policy information."
        ),
    )

    recon_group.add_argument(
        "--show-URL.candidates",
        dest="candidates",
        action="store_true",
        help=(
            "Show discovered URL candidates from redirects, "
            "known files, sitemap, security.txt, and wordlist "
            "input."
        ),
    )

    recon_group.add_argument(
        "--discover-content",
        dest="content",
        nargs="?",
        const=50,
        default=None,
        type=positive_int,
        metavar="N",
        help=(
            "Run passive content discovery from known "
            "resources and discovered URL candidates. "
            "Optionally probe at most N candidates "
            "(default: 50)."
        ),
    )

    recon_group.add_argument(
        "--discover-paths",
        dest="wordlist",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "Run active subdirectory/path discovery using "
            "a wordlist file. Only existing paths are shown."
        ),
    )

    recon_group.add_argument(
        "-x",
        "--extensions",
        type=extension_list,
        default=(),
        metavar="EXTS",
        help=(
            "Expand extensionless wordlist paths with "
            "comma-separated extensions, for example "
            "php,html,json,txt. Requires --discover-paths."
        ),
    )

    recon_group.add_argument(
        "--depth",
        type=depth_int,
        default=0,
        metavar="N",
        help=(
            "Recursively scan discovered directories "
            "up to N levels. 0 disables recursion. "
            "Requires --discover-paths."
        ),
    )

    recon_group.add_argument(
        "--wordlist-limit",
        dest="wordlist_limit",
        type=wordlist_limit_int,
        default=50_000,
        metavar="N",
        help=(
            "Maximum wordlist paths to probe "
            "(default: 50000, maximum: 50000)."
        ),
    )

    recon_group.add_argument(
        "--all",
        dest="all_modules",
        action="store_true",
        help=(
            "Enable all safe reconnaissance modules. "
            "Active wordlist path discovery still requires "
            "--discover-paths FILE."
        ),
    )


    # =========================================================
    # OUTPUT / POLICY
    # =========================================================

    output_group = parser.add_argument_group(
        "Output and policy"
    )

    output_group.add_argument(
        "--save-report",
        dest="json",
        metavar="FILE",
        help=(
            "Save the full scan report to a JSON file."
        ),
    )


    output_group.add_argument(
        "--minimum-grade",
        dest="fail_under",
        type=str.upper,
        choices=[
            "A",
            "B",
            "C",
            "D",
            "F",
        ],
        metavar="GRADE",
        help=(
            "Exit with code 1 if the scan grade "
            "is below this grade"
        ),
    )

    args = parser.parse_args()

    if args.extensions and args.wordlist is None:
        parser.error(
            "--extensions requires --discover-paths FILE"
        )

    if args.depth > 0 and args.wordlist is None:
        parser.error(
            "--depth requires --discover-paths FILE"
        )

    size_filter_requested = (
        args.min_response_size is not None
        or args.max_response_size is not None
    )

    if size_filter_requested and args.wordlist is None:
        parser.error(
            "--min-response-size/--max-response-size "
            "require --discover-paths FILE"
        )

    if (
        args.min_response_size is not None
        and args.max_response_size is not None
        and args.min_response_size > args.max_response_size
    ):
        parser.error(
            "--min-response-size must be less than "
            "or equal to --max-response-size"
        )

    return args
