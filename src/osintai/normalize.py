import re
from urllib.parse import urlparse, urljoin, urldefrag

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
    except:
        return None

def same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs have the same domain."""
    try:
        d1 = urlparse(url1).netloc.lower()
        d2 = urlparse(url2).netloc.lower()
        return d1 == d2
    except:
        return False
