import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from .normalize import absolutize

class Extractor:
    EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    PHONE_RE = re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")
    URL_RE = re.compile(r"https?://[^\s<>\"']+")

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
        emails = sorted(set(self.EMAIL_RE.findall(text)))[:200]
        phones = sorted(set(self.PHONE_RE.findall(text)))[:100]
        urls = sorted(set(self.URL_RE.findall(text)))[:100]

        domain = urlparse(url).netloc

        return {
            "url": url,
            "domain": domain,
            "emails": emails,
            "phones": phones,
            "urls": urls,
            "email_count": len(emails),
            "phone_count": len(phones),
            "url_count": len(urls)
        }
