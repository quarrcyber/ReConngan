import argparse
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
def wordlist_limit_int(
    value: str,
) -> int:
    number = positive_int(
        value
    )

    if number > 500:
        raise argparse.ArgumentTypeError(
            "wordlist limit must not "
            "exceed 500"
        )

    return number

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
            "  reconngan example.com --cookies\n"
            "  reconngan example.com --sitemap\n"
            "  reconngan example.com --tls\n"
            "  reconngan example.com --resolve-hosts\n"
            "  reconngan example.com --services\n"        
            "  reconngan example.com --content\n"
            "  reconngan example.com --wordlist\n"
            "  reconngan example.com --wordlist paths.txt\n"
            "  reconngan example.com --all"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # =========================================================
    # TARGET
    # =========================================================

    parser.add_argument(
        "target",
        help="Target URL or domain to scan",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ReConngan 0.1.6",
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
        "--no-redirect",
        action="store_true",
        help="Do not follow HTTP redirects",
    )

    # =========================================================
    # RECONNAISSANCE MODULES
    # =========================================================

    recon_group = parser.add_argument_group(
        "Reconnaissance modules"
    )

    recon_group.add_argument(
        "--cookies",
        action="store_true",
        help="Analyze HTTP cookie security",
    )

    recon_group.add_argument(
        "--redirects",
        action="store_true",
        help="Show HTTP redirect chain",
    )

    recon_group.add_argument(
        "--tls",
        action="store_true",
        help="Inspect TLS protocol and X.509 certificate",
    )
    recon_group.add_argument(
        "--resolve-hosts",
        nargs="?",
        const=50,
        default=None,
        type=positive_int,
        metavar="N",
        help=(
            "Resolve discovered hostname candidates "
            "via DNS, optionally at most N hosts "
            "(default: 50)"
        ),
    )
    recon_group.add_argument(
        "--services",
        nargs="?",
        const=25,
        default=None,
        type=positive_int,
        metavar="N",
        help=(
            "Probe HTTPS/443 and HTTP/80 "
            "on DNS-resolved hostname candidates, "
            "optionally at most N hosts "
            "(default: 25)"
        ),
    )

    recon_group.add_argument(
        "--resources",
        action="store_true",
        help="Probe known web resources",
    )

    recon_group.add_argument(
        "--sitemap",
        action="store_true",
        help="Discover and parse sitemap.xml",
    )

    recon_group.add_argument(
        "--security-txt",
        action="store_true",
        help="Discover and parse security.txt",
    )

    recon_group.add_argument(
        "--candidates",
        action="store_true",
        help="Show discovered URL candidates",
    )

    recon_group.add_argument(
        "--content",
        nargs="?",
        const=50,
        default=None,
        type=positive_int,
        metavar="N",
        help=(
            "Perform active content discovery, "
            "optionally probing at most N candidates "
            "(default: 50)"
        ),
    )

    recon_group.add_argument(
        "--wordlist",
        nargs="?",
        const="",
        default=None,
        metavar="FILE",
        help=(
            "Perform active wordlist discovery. "
            "Optionally load paths from FILE; "
            "without FILE use the built-in wordlist"
        ),
    )

    recon_group.add_argument(
        "--wordlist-limit",
        type=wordlist_limit_int,
        default=100,
        metavar="N",
        help=(
            "Maximum wordlist candidates to probe "
            "(default: 100, maximum: 500)"
        ),
    )
    
    recon_group.add_argument(
        "--all",
        dest="all_modules",
        action="store_true",

       help="Enable all reconnaissance modules",
    )

    # =========================================================
    # OUTPUT / POLICY
    # =========================================================

    output_group = parser.add_argument_group(
        "Output and policy"
    )

    output_group.add_argument(
        "--json",
        metavar="FILE",
        help="Write scan results to a JSON file",
    )

    output_group.add_argument(
        "--fail-under",
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

    return parser.parse_args()

