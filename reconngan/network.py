import httpx

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
