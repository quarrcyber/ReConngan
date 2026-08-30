from __future__ import annotations

from pathlib import Path
from urllib.parse import (
    urljoin,
    urlsplit,
    urlunsplit,
)

from .models import (
    ContentProbe,
    URLCandidate,
)


MAX_WORDLIST_ENTRIES = 500


DEFAULT_WORDLIST: tuple[str, ...] = (
    "admin",
    "administrator",
    "login",
    "signin",
    "dashboard",
    "api",
    "api/v1*",
    "docs",
    "swagger",
    "swagger-ui",
    "openapi.json",
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    ".git/",
    ".env",
    "config",
    "config.json",
    "backup",
    "backups",
    "uploads",
    "static",
    "assets",
    "health",
    "healthz",
    "status",
    "server-status",
)


class WordlistLoadError(ValueError):
    """Raised when a wordlist cannot be loaded."""


def _normalize_wordlist_entry(
    raw_entry: str,
) -> str | None:
    """Normalize one wordlist entry into a relative web path."""

    entry = raw_entry.strip()

    if not entry:
        return None

    if entry.startswith("#"):
        return None

    # Normalize Windows-style separators found in some lists.
    entry = entry.replace(
        "\\",
        "/",
    )

    parsed = urlsplit(
        entry
    )

    # Wordlists must describe paths, never another origin.
    #
    # Reject:
    #   https://other.example/path
    #   //other.example/path
    if parsed.scheme or parsed.netloc:
        return None

    path = parsed.path.strip()

    if not path:
        return None

    path = (
        "/"
        + path.lstrip("/")
    )

    if path == "/":
        return None

    # Fragment never reaches an HTTP server, so drop it.
    return urlunsplit(
        (
            "",
            "",
            path,
            parsed.query,
            "",
        )
    )


def load_wordlist(
    file_path: str | None,
    limit: int,
) -> tuple[list[str], str]:
    """Load and normalize wordlist entries.

    Args:
        file_path:
            User-supplied file. None means use the
            conservative built-in wordlist.
        limit:
            Maximum number of accepted entries.

    Returns:
        A tuple containing normalized entries and
        their evidence source label.

    Raises:
        WordlistLoadError:
            If the supplied file cannot be read.
    """

    effective_limit = min(
        limit,
        MAX_WORDLIST_ENTRIES,
    )

    if file_path is None:
        raw_entries = list(
            DEFAULT_WORDLIST
        )

        source = (
            "wordlist:builtin"
        )

    else:
        path = Path(
            file_path
        ).expanduser()

        try:
            text = path.read_text(
                encoding="utf-8-sig",
            )

        except OSError as exc:
            raise WordlistLoadError(
                f"Unable to read wordlist "
                f"{path}: {exc}"
            ) from exc

        except UnicodeDecodeError as exc:
            raise WordlistLoadError(
                f"Wordlist is not valid UTF-8: "
                f"{path}"
            ) from exc

        raw_entries = (
            text.splitlines()
        )

        source = (
            f"wordlist:{path.name}"
        )

    entries: list[str] = []

    seen: set[str] = set()

    for raw_entry in raw_entries:

        normalized = (
            _normalize_wordlist_entry(
                raw_entry
            )
        )

        if normalized is None:
            continue

        if normalized in seen:
            continue

        seen.add(
            normalized
        )

        entries.append(
            normalized
        )

        if len(entries) >= effective_limit:
            break

    return (
        entries,
        source,
    )


def build_wordlist_candidates(
    base_url: str,
    entries: list[str],
    source: str,
) -> list[URLCandidate]:
    """Convert normalized wordlist paths to same-host candidates."""

    parsed_base = urlsplit(
        base_url
    )

    if (
        parsed_base.scheme
        not in {"http", "https"}
        or not parsed_base.netloc
    ):
        raise ValueError(
            f"Unsupported base URL: "
            f"{base_url}"
        )

    # Wordlist discovery always begins at the web origin.
    #
    # https://example.com/app/page
    #
    # becomes:
    #
    # https://example.com/
    origin = urlunsplit(
        (
            parsed_base.scheme,
            parsed_base.netloc,
            "/",
            "",
            "",
        )
    )

    candidates: list[
        URLCandidate
    ] = []

    seen_urls: set[str] = set()

    for entry in entries:

        candidate_url = urljoin(
            origin,
            entry,
        )

        parsed_candidate = urlsplit(
            candidate_url
        )

        # Defense in depth.
        #
        # Candidate generation must never escape
        # the original network authority.
        if (
            parsed_candidate.scheme
            != parsed_base.scheme
        ):
            continue

        if (
            parsed_candidate.netloc.lower()
            != parsed_base.netloc.lower()
        ):
            continue

        if candidate_url in seen_urls:
            continue

        seen_urls.add(
            candidate_url
        )

        candidates.append(
            URLCandidate(
                url=candidate_url,
                source=source,
                same_host=True,
            )
        )

    return candidates


def merge_url_candidates(
    *groups: list[URLCandidate],
) -> list[URLCandidate]:
    """Merge candidate sources while preserving first provenance."""

    merged: list[
        URLCandidate
    ] = []

    seen_urls: set[str] = set()

    for group in groups:

        for candidate in group:

            if candidate.url in seen_urls:
                continue

            seen_urls.add(
                candidate.url
            )

            merged.append(
                candidate
            )

    return merged


def filter_interesting_wordlist_results(
    results: list[ContentProbe],
) -> list[ContentProbe]:
    """Suppress ordinary misses from wordlist terminal output."""

    return [
        result
        for result in results
        if (
            result.error is None
            and not result.soft_404
            and result.classification
            != "NOT_FOUND"
        )
    ]
