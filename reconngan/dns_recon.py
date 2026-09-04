from __future__ import annotations
from collections.abc import Callable

import ipaddress
import dns.exception
import dns.resolver

from .models import (
    DNSFinding,
    DNSIntelligence,
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
DMARC_PREFIX = "_dmarc"

DNS_INTELLIGENCE_QUERY_COUNT = (
    len(DEFAULT_DNS_RECORD_TYPES)
    + 1
)

def build_target_hostname_candidate(
    hostname: str | None,
) -> HostnameCandidate | None:
    """Build a hostname candidate from the original scan target."""

    if hostname is None:
        return None

    normalized_hostname = (
        hostname
        .strip()
        .rstrip(".")
        .lower()
    )

    if not normalized_hostname:
        return None

    try:
        ipaddress.ip_address(
            normalized_hostname
        )
    except ValueError:
        pass
    else:
        return None

    return HostnameCandidate(
        hostname=normalized_hostname,
        source="target",
        certificate_fingerprint="",
    )
def merge_hostname_candidates(
    *groups: list[HostnameCandidate],
) -> list[HostnameCandidate]:
    """Merge hostname candidates while preserving first source."""

    merged: list[HostnameCandidate] = []
    seen: set[str] = set()

    for group in groups:
        for candidate in group:
            hostname = (
                candidate.hostname
                .rstrip(".")
                .lower()
            )

            if hostname in seen:
                continue

            seen.add(
                hostname
            )

            merged.append(
                HostnameCandidate(
                    hostname=hostname,
                    source=candidate.source,
                    certificate_fingerprint=(
                        candidate.certificate_fingerprint
                    ),
                )
            )

    return merged
#records
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
#tls v2
def _clean_txt_value(
    value: str,
) -> str:
    return (
        value
        .replace('" "', "")
        .strip()
        .strip('"')
    )


def _values_for_record_type(
    records: list[DNSRecord],
    record_type: str,
) -> list[str]:
    values: list[str] = []

    for record in records:
        if record.record_type != record_type:
            continue

        values.extend(
            record.values
        )

    return values


def _is_spf_record(
    value: str,
) -> bool:
    return value.lower().startswith(
        "v=spf1"
    )


def _is_dmarc_record(
    value: str,
) -> bool:
    return value.lower().startswith(
        "v=dmarc1"
    )


def _extract_dns_tag(
    value: str,
    tag: str,
) -> str | None:
    wanted = tag.lower()

    for part in value.split(";"):
        key, separator, raw_value = (
            part.strip().partition("=")
        )

        if not separator:
            continue

        if key.lower() == wanted:
            return raw_value.strip().lower()

    return None


def trace_cname_chain(
    hostname: str,
    timeout: float = 5.0,
    max_hops: int = 8,
) -> list[str]:
    normalized_hostname = (
        hostname
        .rstrip(".")
        .lower()
    )

    resolver = dns.resolver.Resolver(
        configure=True
    )

    chain = [
        normalized_hostname
    ]

    seen = {
        normalized_hostname
    }

    current = normalized_hostname

    for _ in range(max_hops):
        values, _canonical, error = (
            _resolve_record_type(
                resolver=resolver,
                hostname=current,
                record_type="CNAME",
                timeout=timeout,
            )
        )

        if error or not values:
            break

        next_hostname = (
            values[0]
            .rstrip(".")
            .lower()
        )

        if next_hostname in seen:
            break

        chain.append(
            next_hostname
        )

        seen.add(
            next_hostname
        )

        current = next_hostname

    return chain

def _build_dns_findings(
    *,
    cname_chain: list[str],
    nameservers: list[str],
    mail_exchangers: list[str],
    spf_records: list[str],
    dmarc_records: list[str],
) -> list[DNSFinding]:
    findings: list[DNSFinding] = []

    if len(cname_chain) > 1:
        findings.append(
            DNSFinding(
                check="cname-chain",
                status="INFO",
                severity="LOW",
                note="Hostname resolves through a CNAME chain.",
                evidence=" -> ".join(cname_chain),
            )
        )

    if not nameservers:
        findings.append(
            DNSFinding(
                check="nameserver-records",
                status="MISSING",
                severity="MEDIUM",
                note="No NS records were found for the target hostname.",
                evidence="NS lookup returned no values",
            )
        )

    if not mail_exchangers:
        findings.append(
            DNSFinding(
                check="mail-exchange",
                status="INFO",
                severity="LOW",
                note="No MX records were found. This may be normal for web-only domains.",
                evidence="MX lookup returned no values",
            )
        )

    if len(spf_records) > 1:
        findings.append(
            DNSFinding(
                check="spf-record",
                status="INVALID",
                severity="HIGH",
                note="Multiple SPF records were found. Receivers may treat SPF as invalid.",
                evidence=" | ".join(spf_records),
            )
        )

    elif not spf_records:
        severity = (
            "MEDIUM"
            if mail_exchangers
            else "LOW"
        )

        findings.append(
            DNSFinding(
                check="spf-record",
                status="MISSING",
                severity=severity,
                note="No SPF TXT record was found for the target hostname.",
                evidence="TXT records do not contain v=spf1",
            )
        )

    else:
        findings.append(
            DNSFinding(
                check="spf-record",
                status="OK",
                severity="LOW",
                note="SPF record found.",
                evidence=spf_records[0],
            )
        )

    if not dmarc_records:
        severity = (
            "MEDIUM"
            if mail_exchangers
            else "LOW"
        )

        findings.append(
            DNSFinding(
                check="dmarc-record",
                status="MISSING",
                severity=severity,
                note="No DMARC TXT record was found.",
                evidence="No v=DMARC1 record under _dmarc hostname",
            )
        )

    else:
        dmarc_policy = _extract_dns_tag(
            dmarc_records[0],
            "p",
        )

        if dmarc_policy in {
            "reject",
            "quarantine",
        }:
            findings.append(
                DNSFinding(
                    check="dmarc-policy",
                    status="OK",
                    severity="LOW",
                    note="DMARC policy is enforcement-oriented.",
                    evidence=dmarc_records[0],
                )
            )

        elif dmarc_policy == "none":
            findings.append(
                DNSFinding(
                    check="dmarc-policy",
                    status="WEAK",
                    severity="MEDIUM",
                    note="DMARC policy is monitoring-only.",
                    evidence=dmarc_records[0],
                )
            )

        else:
            findings.append(
                DNSFinding(
                    check="dmarc-policy",
                    status="INVALID",
                    severity="MEDIUM",
                    note="DMARC record does not expose a recognized p= policy.",
                    evidence=dmarc_records[0],
                )
            )

    return findings
#collector tls v2
def collect_dns_intelligence(
    hostname: str,
    timeout: float = 5.0,
    progress_callback: (
        Callable[[int, int, str], None]
        | None
    ) = None,
) -> DNSIntelligence:
    normalized_hostname = (
        hostname
        .rstrip(".")
        .lower()
    )

    def update_base_progress(
        completed: int,
        _total: int,
        current: str,
    ) -> None:
        if progress_callback:
            progress_callback(
                completed,
                DNS_INTELLIGENCE_QUERY_COUNT,
                current,
            )

    records = query_dns_records(
        hostname=normalized_hostname,
        timeout=timeout,
        progress_callback=update_base_progress,
    )

    resolver = dns.resolver.Resolver(
        configure=True
    )

    dmarc_hostname = (
        f"{DMARC_PREFIX}.{normalized_hostname}"
    )

    (
        dmarc_values,
        _dmarc_canonical,
        dmarc_error,
    ) = _resolve_record_type(
        resolver=resolver,
        hostname=dmarc_hostname,
        record_type="TXT",
        timeout=timeout,
    )

    dmarc_values = [
        _clean_txt_value(value)
        for value in dmarc_values
    ]

    if not dmarc_values and dmarc_error is None:
        dmarc_error = "NOANSWER"

    records.append(
        DNSRecord(
            hostname=dmarc_hostname,
            record_type="DMARC",
            values=dmarc_values,
            error=dmarc_error,
        )
    )

    if progress_callback:
        progress_callback(
            DNS_INTELLIGENCE_QUERY_COUNT,
            DNS_INTELLIGENCE_QUERY_COUNT,
            "DMARC",
        )

    txt_records = [
        _clean_txt_value(value)
        for value in _values_for_record_type(
            records,
            "TXT",
        )
    ]

    spf_records = [
        value
        for value in txt_records
        if _is_spf_record(value)
    ]

    dmarc_records = [
        value
        for value in dmarc_values
        if _is_dmarc_record(value)
    ]

    cname_chain = trace_cname_chain(
        hostname=normalized_hostname,
        timeout=timeout,
    )

    nameservers = _values_for_record_type(
        records,
        "NS",
    )

    mail_exchangers = _values_for_record_type(
        records,
        "MX",
    )

    findings = _build_dns_findings(
        cname_chain=cname_chain,
        nameservers=nameservers,
        mail_exchangers=mail_exchangers,
        spf_records=spf_records,
        dmarc_records=dmarc_records,
    )

    return DNSIntelligence(
        hostname=normalized_hostname,
        records=records,
        cname_chain=cname_chain,
        nameservers=nameservers,
        mail_exchangers=mail_exchangers,
        txt_records=txt_records,
        spf_records=spf_records,
        dmarc_records=dmarc_records,
        findings=findings,
    )










