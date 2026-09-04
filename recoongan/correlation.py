from __future__ import annotations

from urllib.parse import urlparse

from .models import (
    DNSIntelligence,
    DNSResolution,
    HostServiceProbe,
    HostnameCandidate,
    HTTPIntelligence,
    ReconCorrelation,
    ReconRelationship,
    RedirectHop,
    TLSResult,
)


def _add_relationship(
    relationships: list[ReconRelationship],
    *,
    source: str,
    target: str,
    relationship_type: str,
    confidence: str,
    evidence: str,
) -> None:
    key = (
        source,
        target,
        relationship_type,
        evidence,
    )

    existing = {
        (
            item.source,
            item.target,
            item.relationship_type,
            item.evidence,
        )
        for item in relationships
    }

    if key in existing:
        return

    relationships.append(
        ReconRelationship(
            source=source,
            target=target,
            relationship_type=relationship_type,
            confidence=confidence,
            evidence=evidence,
        )
    )


def _hostname_from_url(
    url: str | None,
) -> str | None:
    if not url:
        return None

    parsed = urlparse(
        url
    )

    if parsed.hostname is None:
        return None

    return parsed.hostname.lower()

def _normalize_dns_name(
    value: str,
) -> str:
    return (
        value
        .strip()
        .rstrip(".")
        .lower()
    )


def _split_mx_value(
    value: str,
) -> tuple[str, str | None]:
    parts = value.strip().split()

    if (
        len(parts) >= 2
        and parts[0].isdigit()
    ):
        return (
            _normalize_dns_name(
                parts[-1]
            ),
            parts[0],
        )

    return (
        _normalize_dns_name(
            value
        ),
        None,
    )

def _safe_getattr(
    item: object,
    names: tuple[str, ...],
) -> object | None:
    for name in names:
        if hasattr(
            item,
            name,
        ):
            return getattr(
                item,
                name,
            )

    return None


def _string_or_none(
    value: object | None,
) -> str | None:
    if value is None:
        return None

    text = str(
        value
    ).strip()

    return text or None


def _correlate_tls_sans(
    *,
    target: str,
    tls_result: TLSResult | None,
    hostname_candidates: list[HostnameCandidate],
    relationships: list[ReconRelationship],
) -> None:
    if tls_result is None:
        return

    for san in tls_result.dns_names:
        _add_relationship(
            relationships,
            source=target,
            target=san,
            relationship_type="tls-san",
            confidence="HIGH",
            evidence=(
                "Hostname appears in certificate "
                "Subject Alternative Name"
            ),
        )

    candidate_hostnames = {
        candidate.hostname
        for candidate in hostname_candidates
    }

    for hostname in sorted(
        candidate_hostnames
    ):
        if hostname in tls_result.dns_names:
            _add_relationship(
                relationships,
                source=target,
                target=hostname,
                relationship_type="candidate-confirmed-by-tls",
                confidence="HIGH",
                evidence=(
                    f"{hostname} appears in TLS SAN"
                ),
            )

    if tls_result.sha256_fingerprint:
        _add_relationship(
            relationships,
            source=target,
            target=tls_result.sha256_fingerprint,
            relationship_type="certificate-fingerprint",
            confidence="HIGH",
            evidence="Leaf certificate SHA-256 fingerprint",
        )

    if tls_result.issuer:
        _add_relationship(
            relationships,
            source=target,
            target=tls_result.issuer,
            relationship_type="certificate-issuer",
            confidence="MEDIUM",
            evidence="TLS certificate issuer",
        )


def _list_of_strings(
    value: object | None,
) -> list[str]:
    if value is None:
        return []

    if isinstance(
        value,
        str,
    ):
        text = value.strip()
        return [text] if text else []

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        values: list[str] = []

        for item in value:
            text = str(
                item
            ).strip()

            if text:
                values.append(
                    text
                )

        return values

    text = str(
        value
    ).strip()

    return [text] if text else []


def _resolution_ip_addresses(
    resolution: DNSResolution,
) -> list[str]:
    ips: list[str] = []

    direct_fields = (
        "ip_addresses",
        "addresses",
        "ips",
        "ipv4_addresses",
        "ipv6_addresses",
        "a_records",
        "aaaa_records",
    )

    for field_name in direct_fields:
        values = _list_of_strings(
            _safe_getattr(
                resolution,
                (
                    field_name,
                ),
            )
        )

        ips.extend(
            values
        )

    records = _safe_getattr(
        resolution,
        (
            "records",
            "dns_records",
        ),
    )

    if isinstance(
        records,
        list,
    ):
        for record in records:
            record_type = _string_or_none(
                _safe_getattr(
                    record,
                    (
                        "record_type",
                        "type",
                    ),
                )
            )

            if record_type not in {
                "A",
                "AAAA",
            }:
                continue

            values = _list_of_strings(
                _safe_getattr(
                    record,
                    (
                        "values",
                        "answers",
                    ),
                )
            )

            ips.extend(
                values
            )

    return sorted(
        set(ips)
    )


def _correlate_dns_resolution(
    *,
    relationships: list[ReconRelationship],
    resolutions: list[DNSResolution],
) -> None:
    ip_to_hosts: dict[str, list[str]] = {}

    for resolution in resolutions:
        hostname = _string_or_none(
            _safe_getattr(
                resolution,
                (
                    "hostname",
                    "host",
                    "name",
                ),
            )
        )

        if hostname is None:
            continue

        ips = _resolution_ip_addresses(
            resolution
        )

        for ip_address in ips:
            ip_to_hosts.setdefault(
                ip_address,
                [],
            ).append(
                hostname
            )

            _add_relationship(
                relationships,
                source=hostname,
                target=ip_address,
                relationship_type="resolves-to-ip",
                confidence="HIGH",
                evidence="DNS validation result",
            )

    for ip_address, hosts in ip_to_hosts.items():
        unique_hosts = sorted(
            set(hosts)
        )

        if len(unique_hosts) < 2:
            continue

        for host in unique_hosts:
            peers = [
                peer
                for peer in unique_hosts
                if peer != host
            ]

            _add_relationship(
                relationships,
                source=host,
                target=", ".join(peers),
                relationship_type="shared-ip",
                confidence="MEDIUM",
                evidence=(
                    f"Shared resolved IP: {ip_address}"
                ),
            )

def _correlate_dns_intelligence(
    *,
    target: str,
    dns_intelligence: DNSIntelligence | None,
    relationships: list[ReconRelationship],
) -> None:
    if dns_intelligence is None:
        return

    cname_chain = dns_intelligence.cname_chain

    if len(cname_chain) > 1:
        for index in range(
            len(cname_chain) - 1
        ):
            _add_relationship(
                relationships,
                source=cname_chain[index],
                target=cname_chain[index + 1],
                relationship_type="cname-chain",
                confidence="HIGH",
                evidence="CNAME chain hop",
            )

    for nameserver in dns_intelligence.nameservers:
        _add_relationship(
            relationships,
            source=target,
            target=_normalize_dns_name(
                nameserver
            ),
            relationship_type="dns-nameserver",
            confidence="MEDIUM",
            evidence="NS record",
        )


    for exchanger in dns_intelligence.mail_exchangers:
        mx_host, priority = _split_mx_value(
            exchanger
        )

        evidence = (
            f"MX record priority={priority}"
            if priority is not None
            else "MX record"
        )

        _add_relationship(
            relationships,
            source=target,
            target=mx_host,
            relationship_type="mail-exchanger",
            confidence="MEDIUM",
            evidence=evidence,
        )


def _correlate_redirects(
    *,
    redirect_chain: list[RedirectHop],
    relationships: list[ReconRelationship],
) -> None:
    for hop in redirect_chain:
        source_url = _string_or_none(
            _safe_getattr(
                hop,
                (
                    "source_url",
                    "from_url",
                    "url",
                ),
            )
        )

        destination_url = _string_or_none(
            _safe_getattr(
                hop,
                (
                    "destination_url",
                    "to_url",
                    "location",
                    "redirect_to",
                ),
            )
        )

        status_code = _string_or_none(
            _safe_getattr(
                hop,
                (
                    "status_code",
                    "status",
                ),
            )
        )

        source_host = _hostname_from_url(
            source_url
        )

        target_host = _hostname_from_url(
            destination_url
        )

        if (
            source_host is None
            or target_host is None
        ):
            continue

        confidence = (
            "HIGH"
            if source_host == target_host
            else "MEDIUM"
        )

        _add_relationship(
            relationships,
            source=source_host,
            target=target_host,
            relationship_type="redirects-to",
            confidence=confidence,
            evidence=(
                f"HTTP {status_code or '-'}: "
                f"{source_url} -> {destination_url}"
            ),
        )


def _correlate_services(
    *,
    relationships: list[ReconRelationship],
    service_probes: list[HostServiceProbe],
) -> None:
    for probe in service_probes:
        reachable = bool(
            _safe_getattr(
                probe,
                (
                    "reachable",
                    "is_reachable",
                ),
            )
        )

        if not reachable:
            continue

        hostname = _string_or_none(
            _safe_getattr(
                probe,
                (
                    "hostname",
                    "host",
                ),
            )
        )

        final_url = _string_or_none(
            _safe_getattr(
                probe,
                (
                    "final_url",
                    "url",
                ),
            )
        )

        raw_url = _string_or_none(
            _safe_getattr(
                probe,
                (
                    "url",
                    "target_url",
                ),
            )
        )

        scheme = _string_or_none(
            _safe_getattr(
                probe,
                (
                    "scheme",
                    "protocol",
                ),
            )
        )

        status_code = _string_or_none(
            _safe_getattr(
                probe,
                (
                    "status_code",
                    "status",
                ),
            )
        )

        if hostname is None:
            continue

        target = (
            final_url
            or raw_url
            or hostname
        )

        _add_relationship(
            relationships,
            source=hostname,
            target=target,
            relationship_type="reachable-web-service",
            confidence="HIGH",
            evidence=(
                f"{(scheme or 'http').upper()} "
                f"status={status_code or '-'}"
            ),
        )


def _correlate_http_intelligence(
    *,
    target: str,
    http_intelligence: HTTPIntelligence | None,
    relationships: list[ReconRelationship],
) -> None:
    if http_intelligence is None:
        return

    for indicator in http_intelligence.technology_hints:
        _add_relationship(
            relationships,
            source=target,
            target=indicator.name,
            relationship_type="http-technology-hint",
            confidence=indicator.confidence,
            evidence=indicator.evidence,
        )

    for indicator in http_intelligence.framework_indicators:
        _add_relationship(
            relationships,
            source=target,
            target=indicator.name,
            relationship_type="http-framework-hint",
            confidence=indicator.confidence,
            evidence=indicator.evidence,
        )

    for indicator in http_intelligence.api_indicators:
        _add_relationship(
            relationships,
            source=target,
            target=indicator.name,
            relationship_type="http-api-surface",
            confidence=indicator.confidence,
            evidence=indicator.evidence,
        )

    for indicator in http_intelligence.auth_surface:
        _add_relationship(
            relationships,
            source=target,
            target=indicator.name,
            relationship_type="http-auth-surface",
            confidence=indicator.confidence,
            evidence=indicator.evidence,
        )


def _build_summary(
    relationships: list[ReconRelationship],
) -> list[str]:
    if not relationships:
        return [
            "No cross-module relationships were identified."
        ]

    by_type: dict[str, int] = {}

    by_confidence: dict[str, int] = {}

    for relationship in relationships:
        by_type[relationship.relationship_type] = (
            by_type.get(
                relationship.relationship_type,
                0,
            )
            + 1
        )

        by_confidence[relationship.confidence] = (
            by_confidence.get(
                relationship.confidence,
                0,
            )
            + 1
        )

    summary: list[str] = []

    for confidence in (
        "HIGH",
        "MEDIUM",
        "LOW",
    ):
        count = by_confidence.get(
            confidence,
            0,
        )

        if count:
            summary.append(
                f"{confidence} confidence relationship(s): {count}"
            )

    for relationship_type, count in sorted(
        by_type.items()
    ):
        summary.append(
            f"{relationship_type}: {count}"
        )

    return summary


def correlate_recon_evidence(
    *,
    target: str,
    tls_result: TLSResult | None,
    dns_intelligence: DNSIntelligence | None,
    dns_resolutions: list[DNSResolution],
    hostname_candidates: list[HostnameCandidate],
    service_probes: list[HostServiceProbe],
    redirect_chain: list[RedirectHop],
    http_intelligence: HTTPIntelligence | None,
) -> ReconCorrelation:
    relationships: list[ReconRelationship] = []

    _correlate_tls_sans(
        target=target,
        tls_result=tls_result,
        hostname_candidates=hostname_candidates,
        relationships=relationships,
    )

    _correlate_dns_resolution(
        relationships=relationships,
        resolutions=dns_resolutions,
    )

    _correlate_dns_intelligence(
        target=target,
        dns_intelligence=dns_intelligence,
        relationships=relationships,
    )

    _correlate_redirects(
        redirect_chain=redirect_chain,
        relationships=relationships,
    )

    _correlate_services(
        relationships=relationships,
        service_probes=service_probes,
    )

    _correlate_http_intelligence(
        target=target,
        http_intelligence=http_intelligence,
        relationships=relationships,
    )

    return ReconCorrelation(
        target=target,
        relationships=relationships,
        summary=_build_summary(
            relationships
        ),
    )
