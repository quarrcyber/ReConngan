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
            "  reconngan example.com --content\n"
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
        version="ReConngan 0.1.2",
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

