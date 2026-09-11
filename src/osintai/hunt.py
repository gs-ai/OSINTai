import re
from bisect import bisect_left
from typing import List, Dict, Any

URL_RE = re.compile(r"https?://[^\s\"\'<>]+", re.IGNORECASE)

def hunt_leads(text: str, hunt_terms: List[str], max_leads: int = 50) -> Dict[str, Any]:
    """Find hunt terms in text and extract lead URLs."""
    if not hunt_terms:
        return {"hits": [], "lead_urls": []}

    hits = []
    lead_urls = set()
    lowered = text.lower()
    offsets = (range(len(text)) if len(lowered) == len(text) else
               [i for i, char in enumerate(text) for _ in char.lower()])
    url_matches = list(URL_RE.finditer(text))
    url_starts = [match.start() for match in url_matches]

    # Search for each hunt term
    for term in hunt_terms:
        if not term or len(hits) >= 500:
            continue
        term_lower = term.lower()
        pos = 0
        while pos < len(lowered):
            idx = lowered.find(term_lower, pos)
            if idx == -1:
                break

            # Extract snippet around the hit
            original_start = offsets[idx]
            original_end = offsets[idx + len(term_lower) - 1] + 1
            start = max(0, original_start - 100)
            end = min(len(text), original_end + 100)
            snippet = text[start:end]

            hits.append({
                "term": term,
                "position": original_start,
                "end_position": original_end,
                "snippet": snippet.replace('\n', ' ').strip()
            })

            # Match complete URLs in the original text; a snippet edge is not a URL end.
            left = bisect_left(url_starts, start)
            right = bisect_left(url_starts, end)
            for match in url_matches[left:right]:
                if match.end() <= end:
                    lead_urls.add(match.group().rstrip(".,;:!?)}"))

            pos = idx + len(term_lower)
            if len(hits) >= 500:
                break

    return {
        "hits": hits[:500],
        "lead_urls": sorted(lead_urls)[:max(0, max_leads)],
        "url_provenance": {url: "page_prose" for url in sorted(lead_urls)[:max(0, max_leads)]}
    }
