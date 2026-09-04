from __future__ import annotations

from collections.abc import Callable

import httpx

from .models import (
    DNSResolution,
    HostServiceProbe,
)


SERVICE_ENDPOINTS: tuple[
    tuple[str, int],
    ...
] = (
    ("https", 443),
    ("http", 80),
)


def _probe_service_endpoint(
    client: httpx.Client,
    resolution: DNSResolution,
    scheme: str,
    port: int,
) -> HostServiceProbe:
    """Probe one HTTP service without downloading its body."""

    url = (
        f"{scheme}://"
        f"{resolution.hostname}:"
        f"{port}/"
    )

    try:
        with client.stream(
            "GET",
            url,
        ) as response:
            return HostServiceProbe(
                hostname=resolution.hostname,
                source=resolution.source,
                scheme=scheme,
                port=port,
                url=url,
                reachable=True,
                status_code=response.status_code,
                final_url=str(response.url),
                redirected=bool(
                    response.history
                ),
                error=None,
            )

    except httpx.TimeoutException:
        return HostServiceProbe(
            hostname=resolution.hostname,
            source=resolution.source,
            scheme=scheme,
            port=port,
            url=url,
            reachable=False,
            status_code=None,
            final_url=None,
            redirected=False,
            error="Request timed out",
        )

    except httpx.RequestError as exc:
        return HostServiceProbe(
            hostname=resolution.hostname,
            source=resolution.source,
            scheme=scheme,
            port=port,
            url=url,
            reachable=False,
            status_code=None,
            final_url=None,
            redirected=False,
            error=str(exc),
        )


def probe_resolved_host_services(
    resolutions: list[DNSResolution],
    timeout: float = 5.0,
    max_hosts: int = 25,
    follow_redirects: bool = True,
    progress_callback: (
        Callable[[int, int, str], None]
        | None
    ) = None,
) -> list[HostServiceProbe]:
    """Probe HTTPS/443 and HTTP/80 on resolved hostnames."""

    selected = [
        resolution
        for resolution in resolutions
        if resolution.resolved
    ][:max_hosts]

    total = (
        len(selected)
        * len(SERVICE_ENDPOINTS)
    )

    completed = 0

    results: list[
        HostServiceProbe
    ] = []

    with httpx.Client(
        timeout=timeout,
        follow_redirects=follow_redirects,

        # This module tests service reachability,
        # not certificate trust.
        verify=False,
    ) as client:

        for resolution in selected:

            for scheme, port in SERVICE_ENDPOINTS:

                result = (
                    _probe_service_endpoint(
                        client=client,
                        resolution=resolution,
                        scheme=scheme,
                        port=port,
                    )
                )

                results.append(
                    result
                )

                completed += 1

                if progress_callback:
                    progress_callback(
                        completed,
                        total,
                        result.url,
                    )

    return results
