from __future__ import annotations

from collections.abc import Callable

import dns.exception
import dns.resolver

from .models import (
    DNSRecord,
    DNSResolution,
    HostnameCandidate,
)
DEFAULT_DNS_RECORD_TYPES: tuple[str, ...] = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
)
def _resolve_record_type(
    resolver: dns.resolver.Resolver,
    hostname: str,
    record_type: str,
    timeout: float,
) -> tuple[
    list[str],
    str | None,
    str | None,
]:
    try:
        answer = resolver.resolve(
            hostname,
            record_type,
            lifetime=timeout,
            search=False,
        )

    except dns.resolver.NXDOMAIN:
        return (
            [],
            None,
            "NXDOMAIN",
        )

    except dns.resolver.NoAnswer:
        return (
            [],
            None,
            None,
        )

    except dns.resolver.LifetimeTimeout:
        return (
            [],
            None,
            f"{record_type} lookup timed out",
        )

    except dns.resolver.NoNameservers:
        return (
            [],
            None,
            f"{record_type} lookup failed: "
            "no nameservers available",
        )

    except dns.exception.DNSException as exc:
        return (
            [],
            None,
            f"{record_type} lookup failed: {exc}",
        )

    records = sorted(
        {
            rdata.to_text()
            for rdata in answer
        }
    )

    canonical_name = (
        str(answer.canonical_name)
        .rstrip(".")
    )

    normalized_hostname = (
        hostname
        .rstrip(".")
        .lower()
    )

    if (
        canonical_name.lower()
        == normalized_hostname
    ):
        canonical_name = None

    return (
        records,
        canonical_name,
        None,
    )
#candidate
def resolve_hostname_candidate(
    resolver: dns.resolver.Resolver,
    candidate: HostnameCandidate,
    timeout: float,
) -> DNSResolution:

    ipv4_addresses: list[str] = []
    ipv6_addresses: list[str] = []

    canonical_name: str | None = None
    errors: list[str] = []

    (
        ipv4_addresses,
        ipv4_canonical,
        ipv4_error,
    ) = _resolve_record_type(
        resolver=resolver,
        hostname=candidate.hostname,
        record_type="A",
        timeout=timeout,
    )

    if ipv4_error == "NXDOMAIN":
        return DNSResolution(
            hostname=candidate.hostname,
            source=candidate.source,
            canonical_name=None,
            ipv4_addresses=[],
            ipv6_addresses=[],
            resolved=False,
            errors=["NXDOMAIN"],
        )

    (
        ipv6_addresses,
        ipv6_canonical,
        ipv6_error,
    ) = _resolve_record_type(
        resolver=resolver,
        hostname=candidate.hostname,
        record_type="AAAA",
        timeout=timeout,
    )
    canonical_name = (
        ipv4_canonical
        or ipv6_canonical
    )
    for error in (
        ipv4_error,
        ipv6_error,
    ):
        if (
            error
            and error not in errors
        ):
            errors.append(error)
    resolved = bool(
        ipv4_addresses
        or ipv6_addresses
    )
    return DNSResolution(
        hostname=candidate.hostname,
        source=candidate.source,
        canonical_name=canonical_name,
        ipv4_addresses=ipv4_addresses,
        ipv6_addresses=ipv6_addresses,
        resolved=resolved,
        errors=errors,
    )
#candidates
def resolve_hostname_candidates(
    candidates: list[HostnameCandidate],
    timeout: float = 5.0,
    max_candidates: int = 50,
    progress_callback: (
        Callable[[int, int, str], None]
        | None
    ) = None,
) -> list[DNSResolution]:
    selected = candidates[
        :max_candidates
    ]

    total = len(
        selected
    )

    resolver = dns.resolver.Resolver(
        configure=True
    )

    results: list[DNSResolution] = []

    for index, candidate in enumerate(
        selected,
        start=1,
    ):
        result = resolve_hostname_candidate(
            resolver=resolver,
            candidate=candidate,
            timeout=timeout,
        )

        results.append(
            result
        )

        if progress_callback:
            progress_callback(
                index,
                total,
                candidate.hostname,
            )

    return results



def query_dns_records(
    hostname: str,
    timeout: float = 5.0,
    progress_callback: (
        Callable[[int, int, str], None]
        | None
    ) = None,
) -> list[DNSRecord]:
    normalized_hostname = (
        hostname
        .rstrip(".")
        .lower()
    )

    resolver = dns.resolver.Resolver(
        configure=True
    )

    results: list[DNSRecord] = []
    total = len(
        DEFAULT_DNS_RECORD_TYPES
    )

    for index, record_type in enumerate(
        DEFAULT_DNS_RECORD_TYPES,
        start=1,
    ):
        (
            values,
            _canonical_name,
            error,
        ) = _resolve_record_type(
            resolver=resolver,
            hostname=normalized_hostname,
            record_type=record_type,
            timeout=timeout,
        )

        if not values and error is None:
            error = "NOANSWER"

        results.append(
            DNSRecord(
                hostname=normalized_hostname,
                record_type=record_type,
                values=values,
                error=error,
            )
        )

        if progress_callback:
            progress_callback(
                index,
                total,
                record_type,
            )

    return results
















