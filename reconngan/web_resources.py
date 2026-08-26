import httpx
import xml.etree.ElementTree as ET
from urllib.parse import (
    urljoin,
    urlparse,
)

from .models import (
    WebResource,
    RobotsInfo,
    SitemapInfo,
    SecurityTxtInfo,
    RedirectHop,
    URLCandidate,
    WebResourceAnalysis,
)
KNOWN_RESOURCES = {
    "robots.txt": "/robots.txt",
    "sitemap.xml": "/sitemap.xml",
    "security.txt": "/.well-known/security.txt",
}

def fetch_web_resource(
    base_url: str,
    name: str,
    path: str,
    timeout: float = 10.0,
) -> WebResource:

    url = urljoin(
        base_url,
        path,
    )

    try:
        response = httpx.get(
            url,
            timeout=timeout,
            follow_redirects=True,
        )

    except httpx.RequestError as exc:

        return WebResource(
            name=name,
            url=url,
            status_code=None,
            content_type=None,
            found=False,
            body=None,
            error=str(exc),
        )

    found = (
        200 <= response.status_code < 300
    )

    return WebResource(
        name=name,
        url=str(response.url),
        status_code=response.status_code,
        content_type=response.headers.get(
            "Content-Type"
        ),
        found=found,
        body=(
            response.text
            if found
            else None
        ),
        error=None,
    )

def collect_web_resources(
    base_url: str,
    timeout: float = 10.0,
) -> list[WebResource]:

    resources: list[WebResource] = []

    for name, path in KNOWN_RESOURCES.items():

        resource = fetch_web_resource(
            base_url=base_url,
            name=name,
            path=path,
            timeout=timeout,
        )

        resources.append(
            resource
        )

    return resources
#robots.txt parse
def parse_robots_txt(
    body: str,
) -> RobotsInfo:

    disallow: list[str] = []
    allow: list[str] = []
    sitemaps: list[str] = []

    for raw_line in body.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if ":" not in line:
            continue

        name, value = line.split(
            ":",
            1,
        )

        name = name.strip().lower()
        value = value.strip()

        if not value:
            continue

        if name == "disallow":
            disallow.append(
                value
            )

        elif name == "allow":
            allow.append(
                value
            )

        elif name == "sitemap":
            sitemaps.append(
                value
            )

    return RobotsInfo(
        disallow=disallow,
        allow=allow,
        sitemaps=sitemaps,
    )
#xml parse
def parse_sitemap_xml(
    body: str,
) -> SitemapInfo:

    urls: list[str] = []
    sitemaps: list[str] = []

    try:
        root = ET.fromstring(body)

    except ET.ParseError as exc:
        return SitemapInfo(
            urls=[],
            sitemaps=[],
            error=str(exc),
        )

    for element in root.iter():

        tag = element.tag

        if "}" in tag:
            tag = tag.split("}", 1)[1]

        tag = tag.lower()

        if tag != "loc":
            continue

        if element.text is None:
            continue

        location = element.text.strip()

        if not location:
            continue

        parent_type = None

        # ElementTree không có getparent(),
        # nên phân loại bằng root type phía dưới.

        root_tag = root.tag

        if "}" in root_tag:
            root_tag = root_tag.split(
                "}",
                1,
            )[1]

        root_tag = root_tag.lower()

        if root_tag == "urlset":
            urls.append(location)

        elif root_tag == "sitemapindex":
            sitemaps.append(location)

    return SitemapInfo(
        urls=urls,
        sitemaps=sitemaps,
        error=None,
    )
#security.txt parse
def parse_security_txt(
    body: str,
) -> SecurityTxtInfo:

    contacts: list[str] = []
    canonical: list[str] = []
    policy: list[str] = []
    acknowledgments: list[str] = []
    preferred_languages: list[str] = []

    expires = None

    for raw_line in body.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if ":" not in line:
            continue

        name, value = line.split(
            ":",
            1,
        )

        name = name.strip().lower()
        value = value.strip()

        if not value:
            continue

        if name == "contact":
            contacts.append(value)

        elif name == "canonical":
            canonical.append(value)

        elif name == "policy":
            policy.append(value)

        elif name == "acknowledgments":
            acknowledgments.append(value)

        elif name == "expires":
            expires = value

        elif name == "preferred-languages":

            preferred_languages.extend(
                language.strip()
                for language in value.split(",")
                if language.strip()
            )

    return SecurityTxtInfo(
        contacts=contacts,
        canonical=canonical,
        policy=policy,
        acknowledgments=acknowledgments,
        expires=expires,
        preferred_languages=preferred_languages,
    )

def analyze_web_resources(
    base_url: str,
    resources: list[WebResource],
    redirect_chain: list[RedirectHop],
) -> WebResourceAnalysis:

    robots = None
    sitemap = None
    security_txt = None

    # -----------------------------
    # Parse known resources
    # -----------------------------

    for resource in resources:

        if not resource.found:
            continue

        if not resource.body:
            continue

        if resource.name == "robots.txt":

            robots = parse_robots_txt(
                resource.body
            )

        elif resource.name == "sitemap.xml":

            sitemap = parse_sitemap_xml(
                resource.body
            )

        elif resource.name == "security.txt":

            security_txt = parse_security_txt(
                resource.body
            )

    # -----------------------------
    # Build candidates
    # -----------------------------

    candidates: list[URLCandidate] = []

    seen: set[str] = set()

    base_host = urlparse(
        base_url
    ).hostname

    def add_candidate(
        value: str,
        source: str,
    ) -> None:

        if not value:
            return

        absolute = urljoin(
            base_url,
            value,
        )

        parsed = urlparse(
            absolute
        )

        # Ignore mailto:, tel:, etc.
        if parsed.scheme not in {
            "http",
            "https",
        }:
            return

        # Fragment does not identify
        # a different HTTP resource.
        normalized = parsed._replace(
            fragment=""
        ).geturl()

        if normalized in seen:
            return

        seen.add(
            normalized
        )

        candidates.append(
            URLCandidate(
                url=normalized,
                source=source,
                same_host=(
                    parsed.hostname
                    == base_host
                ),
            )
        )

    # -----------------------------
    # Redirect evidence
    # -----------------------------

    for hop in redirect_chain:

        add_candidate(
            hop.url,
            "redirect",
        )

        if hop.location:

            add_candidate(
                hop.location,
                "redirect-location",
            )

    # -----------------------------
    # robots.txt
    # -----------------------------

    if robots is not None:

        for path in robots.disallow:

            add_candidate(
                path,
                "robots:disallow",
            )

        for path in robots.allow:

            add_candidate(
                path,
                "robots:allow",
            )

        for url in robots.sitemaps:

            add_candidate(
                url,
                "robots:sitemap",
            )

    # -----------------------------
    # sitemap.xml
    # -----------------------------

    if sitemap is not None:

        for url in sitemap.urls:

            add_candidate(
                url,
                "sitemap:url",
            )

        for url in sitemap.sitemaps:

            add_candidate(
                url,
                "sitemap:index",
            )

    # -----------------------------
    # security.txt
    # -----------------------------

    if security_txt is not None:

        for url in security_txt.canonical:

            add_candidate(
                url,
                "security:canonical",
            )

        for url in security_txt.policy:

            add_candidate(
                url,
                "security:policy",
            )

        for url in security_txt.acknowledgments:

            add_candidate(
                url,
                "security:acknowledgments",
            )

    return WebResourceAnalysis(
        robots=robots,
        sitemap=sitemap,
        security_txt=security_txt,
        candidates=candidates,
    )
