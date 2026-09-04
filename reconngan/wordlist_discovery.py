from __future__ import annotations

import asyncio
import hashlib
import secrets

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

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
EMPTY_SUCCESS_MAX_BYTES = 0

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

        self.results = list(
            results
        )



@dataclass(frozen=True)
class PathDiscoveryConfig:
    timeout: float = 10.0
    concurrency: int = 40
    rate_limit: float | None = None
    max_response_bytes: int = 16_384
    min_response_size: int | None = None
    max_response_size: int | None = None
    depth_limit: int = 0
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

@dataclass
class AsyncRateLimiter:
    """Coordinate request pacing across concurrent workers."""

    requests_per_second: float | None
    _lock: asyncio.Lock = field(
        init=False,
        repr=False,
    )
    _next_allowed_at: float = field(
        default=0.0,
        init=False,
        repr=False,
    )

    def __post_init__(
        self,
    ) -> None:
        self._lock = asyncio.Lock()

        if (
            self.requests_per_second is not None
            and self.requests_per_second <= 0
        ):
            raise ValueError(
                "requests_per_second must be greater than 0"
            )

    async def wait(
        self,
    ) -> None:
        if self.requests_per_second is None:
            return

        interval = (
            1.0
            / self.requests_per_second
        )

        loop = asyncio.get_running_loop()

        async with self._lock:
            now = loop.time()

            allowed_at = max(
                now,
                self._next_allowed_at,
            )

            self._next_allowed_at = (
                allowed_at
                + interval
            )

            delay = (
                allowed_at
                - now
            )

        if delay > 0:
            await asyncio.sleep(
                min(
                    delay,
                    5.0,
                )
            )

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

def _path_has_extension(
    path: str,
) -> bool:
    parsed = urlsplit(
        path
    )

    final_segment = (
        parsed.path
        .rstrip("/")
        .rsplit(
            "/",
            maxsplit=1,
        )[-1]
    )

    if not final_segment:
        return False

    if final_segment.startswith(
        "."
    ):
        return True

    return "." in final_segment

def _path_is_extension_candidate(
    path: str,
) -> bool:
    parsed = urlsplit(
        path
    )

    if parsed.query:
        return False

    if parsed.path.endswith(
        "/"
    ):
        return False

    if _path_has_extension(
        path
    ):
        return False

    final_segment = (
        parsed.path
        .rsplit(
            "/",
            maxsplit=1,
        )[-1]
    )

    if not final_segment:
        return False

    return True

def expand_wordlist_entries(
    entries: list[str],
    extensions: tuple[str, ...],
) -> list[str]:
    """Expand extensionless wordlist paths with file extensions."""

    if not extensions:
        return entries

    expanded_entries: list[str] = []
    seen: set[str] = set()

    for entry in entries:
        if entry not in seen:
            seen.add(
                entry
            )

            expanded_entries.append(
                entry
            )

        if not _path_is_extension_candidate(
            entry
        ):
            continue

        parsed = urlsplit(
            entry
        )

        for extension in extensions:
            expanded_path = (
                f"{parsed.path}.{extension}"
            )

            expanded_entry = urlunsplit(
                (
                    "",
                    "",
                    expanded_path,
                    "",
                    "",
                )
            )

            if expanded_entry in seen:
                continue

            seen.add(
                expanded_entry
            )

            expanded_entries.append(
                expanded_entry
            )

    return expanded_entries

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

def _candidate_path_suffixes(
    base_url: str,
    candidates: list[URLCandidate],
) -> list[str]:
    """Extract relative path suffixes from root wordlist candidates."""

    origin = _origin_url(
        base_url
    )

    parsed_origin = urlsplit(
        origin
    )

    suffixes: list[str] = []
    seen: set[str] = set()

    for candidate in candidates:
        parsed_candidate = urlsplit(
            candidate.url
        )

        if (
            parsed_candidate.scheme
            != parsed_origin.scheme
            or parsed_candidate.netloc.lower()
            != parsed_origin.netloc.lower()
        ):
            continue

        suffix = parsed_candidate.path.lstrip(
            "/"
        )

        if not suffix:
            continue

        if parsed_candidate.query:
            suffix = (
                f"{suffix}?{parsed_candidate.query}"
            )

        if suffix in seen:
            continue

        seen.add(
            suffix
        )

        suffixes.append(
            suffix
        )

    return suffixes

def _result_directory_url(
    result: ContentProbe,
    origin: str,
) -> str | None:
    """Return a same-origin directory URL suitable for recursion."""

    parsed_origin = urlsplit(
        origin
    )

    parsed_result = urlsplit(
        result.url
    )

    if (
        parsed_result.scheme
        != parsed_origin.scheme
        or parsed_result.netloc.lower()
        != parsed_origin.netloc.lower()
    ):
        return None

    if parsed_result.path.endswith(
        "/"
    ):
        return urlunsplit(
            (
                parsed_result.scheme,
                parsed_result.netloc,
                parsed_result.path,
                "",
                "",
            )
        )

    if (
        result.status_code in REDIRECT_STATUS_CODES
        and result.redirect_to
    ):
        redirect_url = urljoin(
            result.url,
            result.redirect_to,
        )

        parsed_redirect = urlsplit(
            redirect_url
        )

        if (
            parsed_redirect.scheme
            == parsed_origin.scheme
            and parsed_redirect.netloc.lower()
            == parsed_origin.netloc.lower()
            and parsed_redirect.path.endswith("/")
        ):
            return urlunsplit(
                (
                    parsed_redirect.scheme,
                    parsed_redirect.netloc,
                    parsed_redirect.path,
                    "",
                    "",
                )
            )

    return None

def _build_recursive_candidates(
    directory_urls: list[str],
    path_suffixes: list[str],
    source: str,
    depth: int,
    seen_urls: set[str],
) -> list[URLCandidate]:
    """Build next-level candidates under discovered directories."""

    candidates: list[URLCandidate] = []

    for directory_url in directory_urls:
        parsed_directory = urlsplit(
            directory_url
        )

        for suffix in path_suffixes:
            child_url = urljoin(
                directory_url,
                suffix,
            )

            parsed_child = urlsplit(
                child_url
            )

            if (
                parsed_child.scheme
                != parsed_directory.scheme
                or parsed_child.netloc.lower()
                != parsed_directory.netloc.lower()
            ):
                continue

            if child_url in seen_urls:
                continue

            seen_urls.add(
                child_url
            )

            candidates.append(
                URLCandidate(
                    url=child_url,
                    source=(
                        f"{source}:depth-{depth}"
                    ),
                    same_host=True,
                )
            )

    return candidates

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

def _effective_response_size(
    sample: SampledHTTPResponse,
) -> int:
    """Return the best available response size for filtering."""

    if sample.content_length is not None:
        return sample.content_length

    return len(
        sample.body_text.encode(
            "utf-8",
            errors="ignore",
        )
    )

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

async def _request_sample_with_deadline(
    client: httpx.AsyncClient,
    url: str,
    config: PathDiscoveryConfig,
) -> SampledHTTPResponse:
    """Request a sampled response with a hard asyncio deadline."""

    return await asyncio.wait_for(
        _request_sample(
            client=client,
            url=url,
            max_response_bytes=(
                config.max_response_bytes
            ),
        ),
        timeout=(
            config.timeout
            + 1.0
        ),
    )

async def _build_soft404_baselines(
    client: httpx.AsyncClient,
    base_url: str,
    config: PathDiscoveryConfig,
    rate_limiter: AsyncRateLimiter | None = None,
) -> list[Soft404Baseline]:
    """Build soft-404 baselines without blocking path discovery."""

    _ = rate_limiter

    origin = _origin_url(
        base_url
    )

    baselines: list[Soft404Baseline] = []

    for _index in range(
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

        try:
            sample = await _request_sample_with_deadline(
                client=client,
                url=url,
                config=config,
            )

        except (
            httpx.HTTPError,
            asyncio.TimeoutError,
        ):
            continue

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

def _response_size_allowed(
    sample: SampledHTTPResponse,
    config: PathDiscoveryConfig,
) -> bool:
    """Return whether response size passes configured filters."""

    size = sample.content_length

    if size is None:
        return True

    if (
        config.min_response_size is not None
        and size < config.min_response_size
    ):
        return False

    if (
        config.max_response_size is not None
        and size > config.max_response_size
    ):
        return False

    return True

def _is_empty_success_noise(
    sample: SampledHTTPResponse,
) -> bool:
    """Return whether a successful response is likely empty noise."""

    if sample.status_code != 200:
        return False

    if sample.redirect_to:
        return False

    size = _effective_response_size(
        sample
    )

    if size > EMPTY_SUCCESS_MAX_BYTES:
        return False

    normalized_body = normalize_body(
        sample.body_text
    )

    return not normalized_body


async def _probe_path(
    client: httpx.AsyncClient,
    candidate: URLCandidate,
    baselines: list[Soft404Baseline],
    config: PathDiscoveryConfig,
    rate_limiter: AsyncRateLimiter,
) -> ContentProbe | None:
    try:
        await rate_limiter.wait()

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

    if _is_empty_success_noise(
        sample
    ):
        return None

    if not _response_size_allowed(
        sample,
        config,
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


async def _probe_candidate_batch(
    client: httpx.AsyncClient,
    candidates: list[URLCandidate],
    baselines: list[Soft404Baseline],
    config: PathDiscoveryConfig,
    rate_limiter: AsyncRateLimiter,
    progress_callback: ProgressCallback | None,
    completed_count: int,
    total_count: int,
) -> tuple[list[ContentProbe], int]:
    """Probe one batch of candidates with the configured workers."""

    if not candidates:
        return (
            [],
            completed_count,
        )

    results: list[ContentProbe] = []
    completed = completed_count

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

                result: ContentProbe | None = None

                try:
                    result = await _probe_path(
                        client=client,
                        candidate=candidate,
                        baselines=baselines,
                        config=config,
                        rate_limiter=rate_limiter,
                    )
                except asyncio.TimeoutError:
                    result = None

                if result is not None:
                    results.append(
                        result
                    )

                completed += 1

                if progress_callback:
                    progress_callback(
                        completed,
                        total_count,
                        candidate.url,
                    )

            finally:
                queue.task_done()

    worker_count = min(
        config.concurrency,
        len(candidates),
    )

    workers = [
        asyncio.create_task(
            worker()
        )
        for _ in range(
            worker_count
        )
    ]

    for candidate in candidates:
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

    return (
        results,
        completed,
    )

async def discover_wordlist_paths_async(
    base_url: str,
    candidates: list[URLCandidate],
    timeout: float = 10.0,
    concurrency: int = 40,
    rate_limit: float | None = None,
    max_response_bytes: int = 16_384,
    min_response_size: int | None = None,
    max_response_size: int | None = None,
    depth_limit: int = 0,
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
        rate_limit=rate_limit,
        max_response_bytes=max(
            MIN_RESPONSE_BYTES,
            max_response_bytes,
        ),
        min_response_size=min_response_size,
        max_response_size=max_response_size,
        depth_limit=max(
            0,
            depth_limit,
        ),

    )
    rate_limiter = AsyncRateLimiter(
        config.rate_limit
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
            baselines = await asyncio.wait_for(
                _build_soft404_baselines(
                    client=client,
                    base_url=base_url,
                    config=config,
                    rate_limiter=rate_limiter,
                ),
                timeout=(
                    config.timeout
                    + 2.0
                ),
            )

        except (
            httpx.HTTPError,
            asyncio.TimeoutError,
        ):
            baselines = []

#
        path_suffixes = _candidate_path_suffixes(
            base_url,
            same_host_candidates,
        )

        if not path_suffixes:
            return []

        origin = _origin_url(
            base_url
        )

        source = (
            same_host_candidates[0].source
            if same_host_candidates
            else "wordlist"
        )

        seen_candidate_urls = {
            candidate.url
            for candidate in same_host_candidates
        }

        seen_result_urls: set[str] = set()

        all_results: list[ContentProbe] = []
        completed = 0
        planned_total = len(
            same_host_candidates
        )

        current_candidates = same_host_candidates

        for current_depth in range(
            config.depth_limit + 1
        ):
            if not current_candidates:
                break

            level_results, completed = (
                await _probe_candidate_batch(
                    client=client,
                    candidates=current_candidates,
                    baselines=baselines,
                    config=config,
                    rate_limiter=rate_limiter,
                    progress_callback=progress_callback,
                    completed_count=completed,
                    total_count=planned_total,
                )
            )

            for result in level_results:
                if result.url in seen_result_urls:
                    continue

                seen_result_urls.add(
                    result.url
                )

                all_results.append(
                    result
                )

            if current_depth >= config.depth_limit:
                break

            directory_urls: list[str] = []
            seen_directory_urls: set[str] = set()

            for result in level_results:
                directory_url = _result_directory_url(
                    result,
                    origin,
                )

                if directory_url is None:
                    continue

                if directory_url in seen_directory_urls:
                    continue

                seen_directory_urls.add(
                    directory_url
                )

                directory_urls.append(
                    directory_url
                )

            if not directory_urls:
                break

            next_depth = (
                current_depth
                + 1
            )

            current_candidates = (
                _build_recursive_candidates(
                    directory_urls=directory_urls,
                    path_suffixes=path_suffixes,
                    source=source,
                    depth=next_depth,
                    seen_urls=seen_candidate_urls,
                )
            )

            planned_total += len(
                current_candidates
            )


#
    return sorted(
        all_results,
        key=lambda result: result.url,
    )

def discover_wordlist_paths(
    base_url: str,
    candidates: list[URLCandidate],
    timeout: float = 10.0,
    concurrency: int = 40,
    rate_limit: float | None = None,
    max_response_bytes: int = 16_384,
    min_response_size: int | None = None,
    max_response_size: int | None = None,    
    depth_limit: int = 0,

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
                rate_limit=rate_limit,
                max_response_bytes=max_response_bytes,
                min_response_size=min_response_size,
                max_response_size=max_response_size,
                depth_limit=depth_limit,
                progress_callback=progress_callback,
            )
        )

    except KeyboardInterrupt as exc:
        raise PathDiscoveryInterrupted(
            [],
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
