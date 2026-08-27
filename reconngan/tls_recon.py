from __future__ import annotations

import ipaddress
import socket
import ssl

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .models import TLSResult

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

        valid_from=valid_from,
        valid_until=valid_until,
        days_remaining=days_remaining,

        dns_names=dns_names,
        ip_addresses=ip_addresses,

        hostname_match=hostname_match,

        warnings=warnings,
    )
