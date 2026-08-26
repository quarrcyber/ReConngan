import re
import secrets

from collections.abc import Callable
from difflib import SequenceMatcher
from urllib.parse import urljoin

import httpx

from .models import (
    URLCandidate,
    ContentProbe,
)

# ============================================================
# CONTENT DISCOVERY LIMITS
# ============================================================

# Do not feed huge HTML documents directly into difflib.
# Large dynamic pages can make SequenceMatcher extremely slow.
MAX_NORMALIZED_CHARS = 50_000

# Similarity is calculated on words instead of raw characters.
# This keeps the comparison bounded and predictable.
MAX_SIMILARITY_TOKENS = 4_000


ProgressCallback = Callable[
    [int, int, str],
    None,
]


class ContentDiscoveryInterrupted(KeyboardInterrupt):
    """
    Raised when the user interrupts content discovery.

    Completed probe results are preserved so the caller can
    still display or export partial results.
    """

    def __init__(
        self,
        results: list[ContentProbe],
    ) -> None:
        super().__init__(
            "Content discovery interrupted by user"
        )

        self.results = list(results)

def normalize_body(
    body: str,
    token: str | None = None,
) -> str:
    text = body[
        :MAX_NORMALIZED_CHARS
    ]

    if token:
        text = text.replace(
            token,
            "<RANDOM>",
        )

    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    return text.strip().lower()

def response_similarity(
    first: str,
    second: str,
) -> float:
    if not first or not second:
        return 0.0

    if first == second:
        return 1.0

    # Compare words instead of individual characters.
    first_tokens = first.split()[
        :MAX_SIMILARITY_TOKENS
    ]

    second_tokens = second.split()[
        :MAX_SIMILARITY_TOKENS
    ]

    if not first_tokens or not second_tokens:
        return 0.0

    # If page sizes differ substantially, they are very
    # unlikely to represent the same soft-404 template.
    shorter = min(
        len(first_tokens),
        len(second_tokens),
    )

    longer = max(
        len(first_tokens),
        len(second_tokens),
    )

    length_ratio = (
        shorter / longer
    )

    if length_ratio < 0.60:
        return 0.0

    matcher = SequenceMatcher(
        None,
        first_tokens,
        second_tokens,
        autojunk=True,
    )

    # quick_ratio() is an inexpensive upper bound.
    # If it is already low, avoid the more expensive
    # full matching algorithm.
    quick_similarity = (
        matcher.quick_ratio()
    )

    if quick_similarity < 0.90:
        return quick_similarity

    return matcher.ratio()


def classify_status(
    status_code: int,
) -> str:

    if 200 <= status_code < 300:
        return "FOUND"

    if 300 <= status_code < 400:
        return "REDIRECT"

    if status_code in {
        401,
        403,
    }:
        return "PROTECTED"

    if status_code in {
        404,
        410,
    }:
        return "NOT_FOUND"

    return "OTHER"

def build_soft404_baseline(
    client: httpx.Client,
    base_url: str,
) -> tuple[int, str]:

    token = secrets.token_hex(12)

    random_path = (
        f"/reconngan-not-found-{token}"
    )

    url = urljoin(
        base_url,
        random_path,
    )

    response = client.get(
        url
    )

    normalized_body = normalize_body(
        response.text,
        token=token,
    )

    return (
        response.status_code,
        normalized_body,
    )
def looks_like_soft404(
    status_code: int,
    body: str,
    baseline_status: int,
    baseline_body: str,
    threshold: float = 0.95,
) -> bool:

    if status_code != baseline_status:
        return False

    similarity = response_similarity(
        normalize_body(body),
        baseline_body,
    )

    return similarity >= threshold
def probe_candidate(
    client: httpx.Client,
    candidate: URLCandidate,
    baseline_status: int,
    baseline_body: str,
) -> ContentProbe:

    try:
        response = client.get(
            candidate.url
        )

    except httpx.RequestError as exc:

        return ContentProbe(
            url=candidate.url,
            source=candidate.source,
            status_code=None,
            classification="ERROR",
            content_type=None,
            content_length=None,
            redirect_to=None,
            soft_404=False,
            error=str(exc),
        )

    soft_404 = looks_like_soft404(
        status_code=response.status_code,
        body=response.text,
        baseline_status=baseline_status,
        baseline_body=baseline_body,
    )

    if soft_404:
        classification = "SOFT_404"

    else:
        classification = classify_status(
            response.status_code
        )

    content_length = len(
        response.content
    )

    return ContentProbe(
        url=candidate.url,
        source=candidate.source,
        status_code=response.status_code,
        classification=classification,

        content_type=response.headers.get(
            "Content-Type"
        ),

        content_length=content_length,

        redirect_to=response.headers.get(
            "Location"
        ),

        soft_404=soft_404,
        error=None,
    )


def discover_content(
    base_url: str,
    candidates: list[URLCandidate],
    timeout: float = 10.0,
    max_candidates: int = 30,
    progress_callback: ProgressCallback | None = None,
) -> list[ContentProbe]:
    same_host_candidates = [
        candidate
        for candidate in candidates
        if candidate.same_host
    ]

    same_host_candidates = (
        same_host_candidates[
            :max_candidates
        ]
    )

    total_candidates = len(
        same_host_candidates
    )

    if not same_host_candidates:
        return []

    results: list[ContentProbe] = []

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
        ) as client:

            # ---------------------------------------------
            # Build soft-404 baseline
            # ---------------------------------------------

            if progress_callback:
                progress_callback(
                    0,
                    total_candidates,
                    "Building soft-404 baseline",
                )

            try:
                (
                    baseline_status,
                    baseline_body,
                ) = build_soft404_baseline(
                    client,
                    base_url,
                )

            except httpx.RequestError:
                return []

            # ---------------------------------------------
            # Probe discovered candidates
            # ---------------------------------------------

            for index, candidate in enumerate(
                same_host_candidates,
                start=1,
            ):
                if progress_callback:
                    progress_callback(
                        index - 1,
                        total_candidates,
                        candidate.url,
                    )

                result = probe_candidate(
                    client=client,
                    candidate=candidate,
                    baseline_status=baseline_status,
                    baseline_body=baseline_body,
                )

                results.append(
                    result
                )

                if progress_callback:
                    progress_callback(
                        index,
                        total_candidates,
                        candidate.url,
                    )

    except KeyboardInterrupt as exc:
        raise ContentDiscoveryInterrupted(
            results
        ) from exc

    return results
