import re
from typing import List, Dict, Any

URL_RE = re.compile(r"https?://[^\s\"\'<>]+", re.IGNORECASE)

def hunt_leads(text: str, hunt_terms: List[str], max_leads: int = 50) -> Dict[str, Any]:
    """Find hunt terms in text and extract lead URLs."""
    if not hunt_terms:
        return {"hits": [], "lead_urls": []}

    hits = []
    lead_urls = set()

    # Search for each hunt term
    for term in hunt_terms:
        term_lower = term.lower()
        pos = 0
        while pos < len(text):
            idx = text.lower().find(term_lower, pos)
            if idx == -1:
                break

            # Extract snippet around the hit
            start = max(0, idx - 100)
            end = min(len(text), idx + len(term) + 100)
            snippet = text[start:end]

            hits.append({
                "term": term,
                "position": idx,
                "snippet": snippet.replace('\n', ' ').strip()
            })

            # Extract URLs from snippet
            for match in URL_RE.findall(snippet):
                lead_urls.add(match.strip())

            pos = idx + len(term)
            if len(hits) >= 500:
                break

    return {
        "hits": hits[:500],
        "lead_urls": list(lead_urls)[:max_leads]
    }
