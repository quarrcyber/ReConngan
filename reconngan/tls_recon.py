from __future__ import annotations

import ipaddress
import socket
import ssl

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .models import (
    HostnameCandidate,
    TLSCertificateSummary,
    TLSSecurityFinding,
    TLSResult,
)

class TLSProbeError(Exception):
    """Raised when a TLS probe cannot be completed."""

def _dns_name_matches(host: str, pattern: str) -> bool:
    host = host.rstrip(".").lower()
    pattern = pattern.rstrip(".").lower()

    if "*" not in pattern:
        return host == pattern

    if not pattern.startswith("*."):
        return False

    if pattern.count("*") != 1:
        return False

    suffix = pattern[2:]

    host_labels = host.split(".")
    suffix_labels = suffix.split(".")

    return (
        len(host_labels) == len(suffix_labels) + 1
        and host_labels[1:] == suffix_labels
    )


def _hostname_is_covered(
    host: str,
    dns_names: list[str],
    ip_addresses: list[str],
) -> bool:
    try:
        target_ip = ipaddress.ip_address(host)
    except ValueError:
        target_ip = None

    if target_ip is not None:
        for value in ip_addresses:
            try:
                if target_ip == ipaddress.ip_address(value):
                    return True
            except ValueError:
                continue

        return False

    return any(
        _dns_name_matches(host, pattern)
        for pattern in dns_names
    )

def _certificate_summary(
    cert: x509.Certificate,
) -> TLSCertificateSummary:
    fingerprint_bytes = cert.fingerprint(
        hashes.SHA256()
    )

    sha256_fingerprint = ":".join(
        f"{byte:02X}"
        for byte in fingerprint_bytes
    )

    try:
        basic_constraints = (
            cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        )
        is_ca = basic_constraints.ca
    except x509.ExtensionNotFound:
        is_ca = None

    return TLSCertificateSummary(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=format(
            cert.serial_number,
            "X",
        ),
        sha256_fingerprint=sha256_fingerprint,
        valid_from=cert.not_valid_before_utc.isoformat(),
        valid_until=cert.not_valid_after_utc.isoformat(),
        is_ca=is_ca,
    )

def _validate_trust(
    host: str,
    port: int,
    timeout: float,
) -> tuple[bool, str | None]:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as tcp_socket:
            with context.wrap_socket(
                tcp_socket,
                server_hostname=host,
            ):
                return (
                    True,
                    None,
                )

    except ssl.SSLCertVerificationError as exc:
        return (
            False,
            str(exc),
        )

    except (
        socket.timeout,
        socket.gaierror,
        ConnectionError,
        OSError,
        ssl.SSLError,
    ) as exc:
        return (
            False,
            str(exc),
        )

TLS_VERSION_PROBES: tuple[
    tuple[str, ssl.TLSVersion],
    ...
] = (
    (
        "TLSv1.0",
        ssl.TLSVersion.TLSv1,
    ),
    (
        "TLSv1.1",
        ssl.TLSVersion.TLSv1_1,
    ),
    (
        "TLSv1.2",
        ssl.TLSVersion.TLSv1_2,
    ),
    (
        "TLSv1.3",
        ssl.TLSVersion.TLSv1_3,
    ),
)


def _supports_tls_version(
    host: str,
    port: int,
    timeout: float,
    version: ssl.TLSVersion,
) -> bool:
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_CLIENT
    )
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = version
    context.maximum_version = version

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as tcp_socket:
            with context.wrap_socket(
                tcp_socket,
                server_hostname=host,
            ):
                return True

    except (
        socket.timeout,
        socket.gaierror,
        ConnectionError,
        OSError,
        ssl.SSLError,
    ):
        return False


def _enumerate_supported_tls_versions(
    host: str,
    port: int,
    timeout: float,
) -> list[str]:
    supported: list[str] = []

    for label, version in TLS_VERSION_PROBES:
        if _supports_tls_version(
            host,
            port,
            timeout,
            version,
        ):
            supported.append(
                label
            )

    return supported

def _build_tls_findings(
    *,
    trust_valid: bool,
    trust_error: str | None,
    hostname_match: bool,
    days_remaining: int,
    supported_versions: list[str],
    cipher: str | None,
    cipher_bits: int | None,
) -> list[TLSSecurityFinding]:
    findings: list[TLSSecurityFinding] = []

    weak_protocols = [
        version
        for version in supported_versions
        if version in {
            "TLSv1.0",
            "TLSv1.1",
        }
    ]

    if weak_protocols:
        findings.append(
            TLSSecurityFinding(
                check="tls-weak-protocol",
                status="WARN",
                severity="HIGH",
                note="Server supports deprecated TLS protocol versions.",
                evidence=", ".join(
                    weak_protocols
                ),
            )
        )

    if not trust_valid:
        findings.append(
            TLSSecurityFinding(
                check="certificate-trust",
                status="FAIL",
                severity="HIGH",
                note="Certificate chain could not be validated by the local trust store.",
                evidence=trust_error or "trust validation failed",
            )
        )

    if not hostname_match:
        findings.append(
            TLSSecurityFinding(
                check="certificate-hostname",
                status="FAIL",
                severity="HIGH",
                note="Target hostname is not covered by certificate SAN.",
                evidence="hostname_match=false",
            )
        )

    if days_remaining < 0:
        findings.append(
            TLSSecurityFinding(
                check="certificate-expiry",
                status="FAIL",
                severity="HIGH",
                note="Certificate is expired.",
                evidence=f"{abs(days_remaining)} day(s) expired",
            )
        )

    elif days_remaining <= 30:
        findings.append(
            TLSSecurityFinding(
                check="certificate-expiry",
                status="WARN",
                severity="MEDIUM",
                note="Certificate expires soon.",
                evidence=f"{days_remaining} day(s) remaining",
            )
        )

    if cipher_bits is not None and cipher_bits < 128:
        findings.append(
            TLSSecurityFinding(
                check="cipher-strength",
                status="WARN",
                severity="MEDIUM",
                note="Negotiated cipher has low effective key strength.",
                evidence=f"{cipher or '-'} / {cipher_bits} bits",
            )
        )

    return findings


def collect_tls_hostname_candidates(
    result: TLSResult,
) -> list[HostnameCandidate]:
    candidates: list[HostnameCandidate] = []
    seen: set[str] = set()

    target_host = (
        result.host
        .rstrip(".")
        .lower()
    )

    for raw_name in result.dns_names:
        hostname = (
            raw_name
            .strip()
            .rstrip(".")
            .lower()
        )

        if not hostname:
            continue

        # Wildcard SAN is evidence of a namespace,
        # but it is not a concrete resolvable hostname.
        if "*" in hostname:
            continue

        # The original target is already known.
        if hostname == target_host:
            continue

        if hostname in seen:
            continue

        seen.add(hostname)

        candidates.append(
            HostnameCandidate(
                hostname=hostname,
                source="tls:san",
                certificate_fingerprint=(
                    result.sha256_fingerprint
                ),
            )
        )

    return candidates


def probe_tls(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
) -> TLSResult:
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_CLIENT
    )

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    context.set_alpn_protocols([
        "h2",
        "http/1.1",
    ])

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as tcp_socket:

            with context.wrap_socket(
                tcp_socket,
                server_hostname=host,
            ) as tls_socket:

                version = tls_socket.version()

                cipher_info = tls_socket.cipher()

                if cipher_info:
                    cipher_name = cipher_info[0]
                    cipher_bits = cipher_info[2]
                else:
                    cipher_name = None
                    cipher_bits = None

                alpn = tls_socket.selected_alpn_protocol()

                der_certificate = tls_socket.getpeercert(
                    binary_form=True
                )

    except (
        socket.timeout,
        socket.gaierror,
        ConnectionError,
        OSError,
        ssl.SSLError,
    ) as exc:
        raise TLSProbeError(
            f"{host}:{port}: {exc}"
        ) from exc

    if not der_certificate:
        raise TLSProbeError(
            "Server did not provide a certificate"
        )

    try:
        cert = x509.load_der_x509_certificate(
            der_certificate
        )
    except ValueError as exc:
        raise TLSProbeError(
            "Unable to parse X.509 certificate"
        ) from exc

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    serial_number = format(
        cert.serial_number,
        "X",
    )

    fingerprint_bytes = cert.fingerprint(
        hashes.SHA256()
    )

    sha256_fingerprint = ":".join(
        f"{byte:02X}"
        for byte in fingerprint_bytes
    )

    valid_from = cert.not_valid_before_utc
    valid_until = cert.not_valid_after_utc

    now = datetime.now(timezone.utc)

    days_remaining = (
        valid_until - now
    ).days

    dns_names: list[str] = []
    ip_addresses: list[str] = []

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value

        dns_names = list(
            san.get_values_for_type(
                x509.DNSName
            )
        )

        ip_addresses = [
            str(value)
            for value in san.get_values_for_type(
                x509.IPAddress
            )
        ]

    except x509.ExtensionNotFound:
        pass

    hostname_match = _hostname_is_covered(
        host,
        dns_names,
        ip_addresses,
    )

    warnings: list[str] = []

    if valid_until <= now:
        warnings.append(
            "Certificate has expired"
        )

    elif days_remaining <= 30:
        warnings.append(
            f"Certificate expires in {days_remaining} days"
        )

    if valid_from > now:
        warnings.append(
            "Certificate is not valid yet"
        )

    if not dns_names and not ip_addresses:
        warnings.append(
            "Certificate has no Subject Alternative Name"
        )

    if not hostname_match:
        warnings.append(
            "Target hostname is not covered by certificate SAN"
        )

    if subject == issuer:
        warnings.append(
            "Certificate appears to be self-issued"
        )

    certificate_chain = [
        _certificate_summary(
            cert
        )
    ]

    trust_valid, trust_error = _validate_trust(
        host=host,
        port=port,
        timeout=timeout,
    )

    supported_versions = (
        _enumerate_supported_tls_versions(
            host=host,
            port=port,
            timeout=timeout,
        )
    )

    weak_protocols = [
        version
        for version in supported_versions
        if version in {
            "TLSv1.0",
            "TLSv1.1",
        }
    ]

    security_findings = _build_tls_findings(
        trust_valid=trust_valid,
        trust_error=trust_error,
        hostname_match=hostname_match,
        days_remaining=days_remaining,
        supported_versions=supported_versions,
        cipher=cipher_name,
        cipher_bits=cipher_bits,
    )

    return TLSResult(
        host=host,
        port=port,

        version=version,
        cipher=cipher_name,
        cipher_bits=cipher_bits,
        alpn=alpn,

        subject=subject,
        issuer=issuer,
        serial_number=serial_number,
        sha256_fingerprint=sha256_fingerprint,

        valid_from=valid_from.isoformat(),
        valid_until=valid_until.isoformat(),
        days_remaining=days_remaining,

        dns_names=dns_names,
        ip_addresses=ip_addresses,

        hostname_match=hostname_match,

        warnings=warnings,

        trust_valid=trust_valid,
        trust_error=trust_error,
        supported_versions=supported_versions,
        weak_protocols=weak_protocols,
        certificate_chain=certificate_chain,
        security_findings=security_findings,

    )
