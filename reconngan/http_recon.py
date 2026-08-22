import httpx

from .models import HttpMetadata

def collect_http_metadata(
    response: httpx.Response
) -> HttpMetadata:

    content_type = response.headers.get(
        "Content-Type",
        "Not provided",
    )

    content_length = response.headers.get(
        "Content-Length",
        "Not provided",
    )

    response_time_ms = (
        response.elapsed.total_seconds()
        * 1000
    )

    return HttpMetadata(
        http_version=response.http_version,
        response_time_ms=response_time_ms,
        content_type=content_type,
        content_length=content_length,
    )
