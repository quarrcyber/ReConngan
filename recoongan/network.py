import httpx
from urllib.parse import urlsplit




def normalize_url(target: str) -> str:
    target = target.strip()

    if not target.startswith(
        ("http://", "https://")
    ):
        target = "https://" + target

    return target

def fetch_url(
    url: str,
    timeout: float = 10.0,
    follow_redirects: bool = True,
) -> httpx.Response:

    return httpx.get(
        url,
        follow_redirects=follow_redirects,
        timeout=timeout,
    )
def parse_tls_endpoint(
    target: str,
) -> tuple[str, int]:
    value = target.strip()

    if "://" not in value:
        value = f"https://{value}"

    parsed = urlsplit(value)

    if not parsed.hostname:
        raise ValueError(
            f"Invalid TLS target: {target}"
        )

    try:
        port = (
            parsed.port
            if parsed.port is not None
            else 443
        )
    except ValueError as exc:
        raise ValueError(
            f"Invalid port in target: {target}"
        ) from exc

    return parsed.hostname, port
