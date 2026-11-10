from urllib.parse import urlparse, urljoin, urldefrag, urlsplit, urlunsplit, parse_qsl, urlencode

def clean_url(url: str) -> str:
    """Clean and normalize a URL."""
    if not url:
        return None
    url = url.strip()
    if url.startswith(("mailto:", "javascript:", "tel:")):
        return None
    u, _ = urldefrag(url)
    return u

def absolutize(base_url: str, href: str) -> str:
    """Convert relative URL to absolute URL."""
    href = clean_url(href)
    if not href:
        return None
    try:
        return urljoin(base_url, href)
    except ValueError:
        return None

def same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs have the same domain."""
    try:
        d1 = urlparse(url1).netloc.lower()
        d2 = urlparse(url2).netloc.lower()
        return d1 == d2
    except ValueError:
        return False


# Query parameters that identify a visit, not a document. Removing them stops the
# same page from being queued once per campaign link or session.
TRACKING_PARAMS = frozenset({
    "gclid", "fbclid", "msclkid", "yclid", "dclid", "igshid", "mc_cid", "mc_eid",
    "_ga", "_gl", "ref_src", "phpsessid", "jsessionid", "sessionid",
})
DEFAULT_PORTS = {"http": 80, "https": 443}


def canonical_url(url: str) -> str:
    """Return the deduplication form of an absolute HTTP(S) URL.

    Lowercases scheme and host, drops fragments, default ports, tracking/session
    parameters and empty queries, and sorts the remaining query parameters.
    URLs this function cannot safely rewrite (other schemes, embedded credentials,
    malformed authority) are returned cleaned but otherwise untouched so the
    caller's scope policy still sees and rejects them.
    """
    url = clean_url(url)
    if not url:
        return None
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return url
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS or not host or parts.username or parts.password:
        return url
    host = host.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    query = parts.query
    if query:
        try:
            pairs = parse_qsl(query, keep_blank_values=True)
        except ValueError:
            pairs = None
        if pairs is not None:
            kept = sorted(
                (key, value) for key, value in pairs
                if key.lower() not in TRACKING_PARAMS and not key.lower().startswith("utm_")
            )
            query = urlencode(kept)
    return urlunsplit((scheme, netloc, parts.path or "/", query, ""))
