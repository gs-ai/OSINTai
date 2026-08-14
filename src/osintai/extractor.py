import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from .normalize import absolutize


def _validated_http_url(value: str) -> tuple[str, str] | None:
    """Return a cleaned URL and hostname, or None for malformed regex matches."""
    candidate = value.rstrip(".,;:!?)}")
    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
    except ValueError:
        # urllib raises for malformed bracketed IPv6-like strings.
        return None
    if parsed.scheme not in {"http", "https"} or not hostname:
        return None
    return candidate, hostname.lower()


class Extractor:
    EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    PHONE_RE = re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")
    URL_RE = re.compile(r"https?://[^\s<>\"']+")
    DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
    IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
    BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
    ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    SOCIAL_RE = re.compile(r"(?<![\w@])@[a-zA-Z0-9_]{3,30}\b")

    def html_to_text(self, html: str) -> tuple[str, str]:
        """Extract title and clean text from HTML."""
        soup = BeautifulSoup(html, "html.parser")

        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.extract()

        # Get title
        title = ""
        if soup.title:
            title = soup.title.get_text().strip()

        # Get text content
        text = soup.get_text()
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return title, "\n".join(lines)

    def extract_links(self, base_url: str, html: str) -> list[str]:
        """Extract all links from HTML."""
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            full = absolutize(base_url, a.get("href"))
            if full:
                links.append(full)
        return links

    def extract_indicators(self, url: str, text: str, html: str) -> dict:
        """Extract various indicators from content."""
        combined = "\n".join([text or "", html or ""])
        emails = sorted(set(self.EMAIL_RE.findall(combined)))[:200]
        phones = sorted(set(self.PHONE_RE.findall(combined)))[:100]
        parsed_urls = {
            parsed
            for match in self.URL_RE.findall(combined)
            if (parsed := _validated_http_url(match)) is not None
        }
        urls = sorted(url for url, _ in parsed_urls)[:100]
        btc_addresses = sorted(set(self.BTC_RE.findall(combined)))[:100]
        eth_addresses = sorted({addr.lower() for addr in self.ETH_RE.findall(combined)})[:100]
        social_handles = sorted(set(self.SOCIAL_RE.findall(combined)))[:100]
        ip_addresses = sorted(set(self.IP_RE.findall(combined)))[:100]

        source = _validated_http_url(url)
        domain = source[1] if source else ""
        domains = {domain} if domain else set()
        domains.update(self.DOMAIN_RE.findall(combined))
        domains.update(hostname for _, hostname in parsed_urls)

        # Drop email-only host fragments that appear solely because of address parsing noise.
        email_domains = {email.rsplit("@", 1)[-1].lower() for email in emails if "@" in email}
        domains = sorted({d.lower().strip(".") for d in domains if d and d.lower() not in email_domains})[:200]

        return {
            "url": url,
            "domain": domain,
            "domains": domains,
            "emails": emails,
            "phones": phones,
            "urls": urls,
            "ip_addresses": ip_addresses,
            "btc_addresses": btc_addresses,
            "eth_addresses": eth_addresses,
            "social_handles": social_handles,
            "email_count": len(emails),
            "phone_count": len(phones),
            "url_count": len(urls),
            "domain_count": len(domains),
            "ip_count": len(ip_addresses),
            "btc_count": len(btc_addresses),
            "eth_count": len(eth_addresses),
            "social_count": len(social_handles)
        }
