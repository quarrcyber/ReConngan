from __future__ import annotations

import asyncio
import hashlib
import secrets

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import (
    urljoin,
    urlsplit,
    urlunsplit,
)

import httpx

from .content_discovery import (
    classify_status,
    normalize_body,
    response_similarity,
)
from .models import (
    ContentProbe,
    URLCandidate,
)


MAX_WORDLIST_ENTRIES = 50_000

FOUND_STATUS_CODES = frozenset(
    {
        200,
        204,
        301,
        302,
        307,
        308,
        401,
        403,
    }
)

REDIRECT_STATUS_CODES = frozenset(
    {
        301,
        302,
        307,
        308,
    }
)

MIN_RESPONSE_BYTES = 1_024

DEFAULT_WORDLIST: tuple[str, ...] = (
    "admin",
    "administrator",
    "login",
    "signin",
    "dashboard",
    "api",
    "api/v1",
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

ProgressCallback = Callable[
    [int, int, str],
    None,
]


class WordlistLoadError(ValueError):
    """Raised when a wordlist cannot be loaded."""


class PathDiscoveryInterrupted(KeyboardInterrupt):
    """Raised when path discovery is interrupted."""

    def __init__(
        self,
        results: list[ContentProbe],
    ) -> None:
        super().__init__(
            "Path discovery interrupted by user"
        )
        self.results = list(results)


@dataclass(frozen=True)
class PathDiscoveryConfig:
    timeout: float = 10.0
    concurrency: int = 40
    max_response_bytes: int = 16_384
    baseline_samples: int = 3
    found_statuses: frozenset[int] = FOUND_STATUS_CODES


@dataclass(frozen=True)
class SampledHTTPResponse:
    status_code: int
    content_type: str | None
    content_length: int | None
    redirect_to: str | None
    body_text: str
    body_hash: str


@dataclass(frozen=True)
class Soft404Baseline:
    status_code: int
    content_length: int | None
    redirect_to: str | None
    normalized_body: str
    body_hash: str


def _normalize_wordlist_entry(
    raw_entry: str,
) -> str | None:
    """Normalize one wordlist entry into a relative web path."""

    entry = raw_entry.strip()

    if not entry:
        return None

    if entry.startswith("#"):
        return None

    entry = entry.replace(
        "\\",
        "/",
    )

    parsed = urlsplit(
        entry
    )

    if parsed.scheme or parsed.netloc:
        return None

    path = parsed.path.strip()

    if not path:
        return None

    path = (
        "/"
        + path.lstrip("/")
    )

    if path in {
        "/",
        "/.",
        "/..",
    }:
        return None

    return urlunsplit(
        (
            "",
            "",
            path,
            parsed.query,
            "",
        )
    )


def _iter_raw_wordlist_entries(
    file_path: str | Path | None,
) -> Iterable[str]:
    if file_path is None:
        yield from DEFAULT_WORDLIST
        return

    path = Path(
        file_path
    ).expanduser()

    if not path.is_file():
        raise WordlistLoadError(
            f"Wordlist file does not exist: {path}"
        )

    try:
        with path.open(
            "r",
            encoding="utf-8-sig",
            errors="ignore",
        ) as file:
            for raw_entry in file:
                yield raw_entry

    except OSError as exc:
        raise WordlistLoadError(
            f"Unable to read wordlist {path}: {exc}"
        ) from exc


def load_wordlist(
    file_path: str | Path | None,
    limit: int,
) -> tuple[list[str], str]:
    """Load, normalize, deduplicate, and cap wordlist entries."""

    effective_limit = min(
        limit,
        MAX_WORDLIST_ENTRIES,
    )

    entries: list[str] = []
    seen: set[str] = set()

    for raw_entry in _iter_raw_wordlist_entries(
        file_path
    ):
        normalized = _normalize_wordlist_entry(
            raw_entry
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

    if file_path is None:
        source = "wordlist:builtin"
    else:
        source = (
            "wordlist:"
            f"{Path(file_path).expanduser()}"
        )

    return (
        entries,
        source,
    )


def _origin_url(
    base_url: str,
) -> str:
    parsed_base = urlsplit(
        base_url
    )

    if (
        parsed_base.scheme
        not in {
            "http",
            "https",
        }
        or not parsed_base.netloc
    ):
        raise ValueError(
            f"Unsupported base URL: {base_url}"
        )

    return urlunsplit(
        (
            parsed_base.scheme,
            parsed_base.netloc,
            "/",
            "",
            "",
        )
    )


def build_wordlist_candidates(
    base_url: str,
    entries: list[str],
    source: str,
) -> list[URLCandidate]:
    """Convert normalized wordlist paths to same-origin candidates."""

    origin = _origin_url(
        base_url
    )
    parsed_origin = urlsplit(
        origin
    )

    candidates: list[URLCandidate] = []
    seen_urls: set[str] = set()

    for entry in entries:
        candidate_url = urljoin(
            origin,
            entry,
        )

        parsed_candidate = urlsplit(
            candidate_url
        )

        if (
            parsed_candidate.scheme
            != parsed_origin.scheme
        ):
            continue

        if (
            parsed_candidate.netloc.lower()
            != parsed_origin.netloc.lower()
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

    merged: list[URLCandidate] = []
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


def _parse_content_length(
    value: str | None,
) -> int | None:
    if value is None:
        return None

    try:
        return int(
            value
        )
    except ValueError:
        return None


def _hash_bytes(
    data: bytes,
) -> str:
    return hashlib.blake2b(
        data,
        digest_size=16,
    ).hexdigest()


async def _request_sample(
    client: httpx.AsyncClient,
    url: str,
    max_response_bytes: int,
) -> SampledHTTPResponse:
    chunks: list[bytes] = []
    bytes_read = 0

    async with client.stream(
        "GET",
        url,
    ) as response:
        async for chunk in response.aiter_bytes():
            if bytes_read >= max_response_bytes:
                break

            remaining = (
                max_response_bytes
                - bytes_read
            )
            part = chunk[
                :remaining
            ]

            chunks.append(
                part
            )
            bytes_read += len(
                part
            )

            if bytes_read >= max_response_bytes:
                break

        body_bytes = b"".join(
            chunks
        )

        content_length = _parse_content_length(
            response.headers.get(
                "Content-Length"
            )
        )

        if content_length is None:
            content_length = len(
                body_bytes
            )

        encoding = (
            response.encoding
            or "utf-8"
        )

        body_text = body_bytes.decode(
            encoding,
            errors="replace",
        )

        return SampledHTTPResponse(
            status_code=response.status_code,
            content_type=response.headers.get(
                "Content-Type"
            ),
            content_length=content_length,
            redirect_to=response.headers.get(
                "Location"
            ),
            body_text=body_text,
            body_hash=_hash_bytes(
                body_bytes
            ),
        )


async def _build_soft404_baselines(
    client: httpx.AsyncClient,
    base_url: str,
    config: PathDiscoveryConfig,
) -> list[Soft404Baseline]:
    origin = _origin_url(
        base_url
    )

    baselines: list[Soft404Baseline] = []

    for _ in range(
        config.baseline_samples
    ):
        token = secrets.token_hex(
            12
        )

        random_path = (
            f"/__reconngan_404_{token}"
        )

        url = urljoin(
            origin,
            random_path,
        )

        sample = await _request_sample(
            client=client,
            url=url,
            max_response_bytes=(
                config.max_response_bytes
            ),
        )

        baselines.append(
            Soft404Baseline(
                status_code=sample.status_code,
                content_length=sample.content_length,
                redirect_to=sample.redirect_to,
                normalized_body=normalize_body(
                    sample.body_text,
                    token=token,
                ),
                body_hash=sample.body_hash,
            )
        )

    return baselines


def _looks_like_soft404(
    sample: SampledHTTPResponse,
    baselines: list[Soft404Baseline],
    threshold: float = 0.95,
) -> bool:
    normalized_body = normalize_body(
        sample.body_text
    )

    for baseline in baselines:
        if (
            sample.status_code
            != baseline.status_code
        ):
            continue

        if (
            sample.status_code
            in REDIRECT_STATUS_CODES
            and sample.redirect_to
            and sample.redirect_to
            == baseline.redirect_to
        ):
            return True

        if (
            sample.body_hash
            == baseline.body_hash
        ):
            return True

        if (
            not normalized_body
            and not baseline.normalized_body
        ):
            return True

        similarity = response_similarity(
            normalized_body,
            baseline.normalized_body,
        )

        if similarity >= threshold:
            return True

    return False


async def _probe_path(
    client: httpx.AsyncClient,
    candidate: URLCandidate,
    baselines: list[Soft404Baseline],
    config: PathDiscoveryConfig,
) -> ContentProbe | None:
    try:
        sample = await _request_sample(
            client=client,
            url=candidate.url,
            max_response_bytes=(
                config.max_response_bytes
            ),
        )

    except httpx.RequestError:
        return None

    if (
        sample.status_code
        not in config.found_statuses
    ):
        return None

    if _looks_like_soft404(
        sample,
        baselines,
    ):
        return None

    return ContentProbe(
        url=candidate.url,
        source=candidate.source,
        status_code=sample.status_code,
        classification=classify_status(
            sample.status_code
        ),
        content_type=sample.content_type,
        content_length=sample.content_length,
        redirect_to=sample.redirect_to,
        soft_404=False,
        error=None,
    )


async def discover_wordlist_paths_async(
    base_url: str,
    candidates: list[URLCandidate],
    timeout: float = 10.0,
    concurrency: int = 40,
    max_response_bytes: int = 16_384,
    progress_callback: ProgressCallback | None = None,
) -> list[ContentProbe]:
    """Probe wordlist candidates concurrently and return only real paths."""

    same_host_candidates = [
        candidate
        for candidate in candidates
        if candidate.same_host
    ]

    total_candidates = len(
        same_host_candidates
    )

    if not same_host_candidates:
        return []

    config = PathDiscoveryConfig(
        timeout=timeout,
        concurrency=max(
            1,
            concurrency,
        ),
        max_response_bytes=max(
            MIN_RESPONSE_BYTES,
            max_response_bytes,
        ),
    )

    results: list[ContentProbe] = []
    completed = 0

    limits = httpx.Limits(
        max_connections=config.concurrency,
        max_keepalive_connections=(
            config.concurrency
        ),
    )

    timeout_config = httpx.Timeout(
        config.timeout
    )

    async with httpx.AsyncClient(
        timeout=timeout_config,
        follow_redirects=False,
        limits=limits,
    ) as client:
        if progress_callback:
            progress_callback(
                0,
                total_candidates,
                "Building soft-404 baseline",
            )

        try:
            baselines = (
                await _build_soft404_baselines(
                    client=client,
                    base_url=base_url,
                    config=config,
                )
            )

        except httpx.RequestError:
            return []

        queue: asyncio.Queue[
            URLCandidate | None
        ] = asyncio.Queue(
            maxsize=config.concurrency * 4
        )

        async def worker() -> None:
            nonlocal completed

            while True:
                candidate = await queue.get()

                try:
                    if candidate is None:
                        return

                    result = await _probe_path(
                        client=client,
                        candidate=candidate,
                        baselines=baselines,
                        config=config,
                    )

                    if result is not None:
                        results.append(
                            result
                        )

                    completed += 1

                    if progress_callback:
                        progress_callback(
                            completed,
                            total_candidates,
                            candidate.url,
                        )

                finally:
                    queue.task_done()

        worker_count = min(
            config.concurrency,
            total_candidates,
        )

        workers = [
            asyncio.create_task(
                worker()
            )
            for _ in range(
                worker_count
            )
        ]

        for candidate in same_host_candidates:
            await queue.put(
                candidate
            )

        for _ in workers:
            await queue.put(
                None
            )

        await queue.join()
        await asyncio.gather(
            *workers
        )

    return sorted(
        results,
        key=lambda result: result.url,
    )


def discover_wordlist_paths(
    base_url: str,
    candidates: list[URLCandidate],
    timeout: float = 10.0,
    concurrency: int = 40,
    max_response_bytes: int = 16_384,
    progress_callback: ProgressCallback | None = None,
) -> list[ContentProbe]:
    """Synchronous wrapper for the CLI application."""

    try:
        return asyncio.run(
            discover_wordlist_paths_async(
                base_url=base_url,
                candidates=candidates,
                timeout=timeout,
                concurrency=concurrency,
                max_response_bytes=max_response_bytes,
                progress_callback=progress_callback,
            )
        )

    except KeyboardInterrupt as exc:
        raise PathDiscoveryInterrupted(
            []
        ) from exc


def filter_interesting_wordlist_results(
    results: list[ContentProbe],
) -> list[ContentProbe]:
    """Backward-compatible helper for older call sites."""

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
