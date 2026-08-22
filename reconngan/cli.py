import argparse

def parse_args():

    parser = argparse.ArgumentParser(
        prog="reconngan",
        description=(
            "ReConngan - HTTP security headers "
            "reconnaissance scanner"
        ),
    )

    parser.add_argument(
        "target",
        help="Target URL or domain to scan",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="ReConngan 0.1.0",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help=(
            "Request timeout in seconds "
            "(default: 10)"
        ),
    )

    parser.add_argument(
        "--no-redirect",
        action="store_true",
        help="Do not follow HTTP redirects",
    )

    parser.add_argument(
        "--json",
        metavar="FILE",
        help=(
            "Write scan results "
            "to a JSON file"
        ),
    )

    parser.add_argument(
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
            "Exit with code 1 if "
            "the scan grade is below "
            "this grade"
        ),
    )

    return parser.parse_args()
