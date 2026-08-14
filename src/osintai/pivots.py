"""Lead generation: turn an observed identifier into the next place to look.

This module emits real lookup URLs without inventing results. Whether a lookup resolves to
the subject is something the investigator establishes by opening it. A generated pivot is a
candidate, never a hit, and this module itself makes no network requests.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote_plus

from .entities import (
    CRYPTO_BTC,
    CRYPTO_ETH,
    DOMAIN,
    EMAIL,
    Entity,
    EntityIndex,
    IP,
    NAME,
    PHONE,
    USERNAME,
    normalize_phone,
    phone_variants,
)
from .provenance import Lead

# How many entities of each kind get expanded. A crawl can produce thousands of identifiers
# and a lead list nobody can work through is not a lead list.
DEFAULT_PER_KIND = 10


def _q(value: str) -> str:
    return quote_plus(value)


def whois_url(domain: str) -> str:
    return f"https://www.whois.com/whois/{_q(domain)}"


def crtsh_url(domain: str) -> str:
    return f"https://crt.sh/?q={_q(domain)}"


def shodan_domain_url(domain: str) -> str:
    return f"https://www.shodan.io/search?query={_q(domain)}"


def shodan_host_url(ip: str) -> str:
    return f"https://www.shodan.io/host/{_q(ip)}"


def _search_engines(query: str) -> List[Dict[str, str]]:
    quoted = f'"{query}"'
    return [
        {"label": "Google", "target": f"https://www.google.com/search?q={_q(quoted)}"},
        {"label": "Bing", "target": f"https://www.bing.com/search?q={_q(quoted)}"},
        {"label": "DuckDuckGo", "target": f"https://duckduckgo.com/?q={_q(quoted)}"},
    ]


def pivots_for_username(handle: str) -> List[Dict[str, str]]:
    u = handle.lstrip("@")
    q = _q(u)
    return [
        {"label": "GitHub profile", "target": f"https://github.com/{q}",
         "rationale": "A 404 establishes the account does not exist."},
        {"label": "Reddit profile", "target": f"https://www.reddit.com/user/{q}",
         "rationale": "A 404 establishes the account does not exist."},
        {"label": "X / Twitter", "target": f"https://x.com/{q}"},
        {"label": "Instagram", "target": f"https://www.instagram.com/{q}/"},
        {"label": "Telegram", "target": f"https://t.me/{q}"},
        {"label": "Keybase", "target": f"https://keybase.io/{q}"},
        {"label": "WhatsMyName enumeration", "target": f"https://whatsmyname.app/?q={q}",
         "rationale": "Checks the handle across several hundred sites in one pass."},
        *_search_engines(u),
    ]


def pivots_for_email(email: str) -> List[Dict[str, str]]:
    q = _q(email)
    local = email.split("@")[0] if "@" in email else ""
    domain = email.split("@")[-1] if "@" in email else ""
    pivots = [
        {"label": "Have I Been Pwned", "target": f"https://haveibeenpwned.com/account/{q}",
         "rationale": "Breach exposure history for the address."},
        {"label": "IntelligenceX", "target": f"https://intelx.io/?s={q}"},
        {"label": "Gravatar", "target": f"https://gravatar.com/{q}",
         "rationale": "A Gravatar often carries a real name and photograph."},
        *_search_engines(email),
    ]
    if local and len(local) >= 4:
        pivots.append({
            "label": f"Pivot local part {local!r} as a handle",
            "target": f"https://whatsmyname.app/?q={_q(local)}",
            "rationale": "Local parts are frequently reused as usernames elsewhere.",
        })
    if domain:
        pivots.append({"label": "Sending domain WHOIS", "target": whois_url(domain)})
    return pivots


def pivots_for_phone(phone: str) -> List[Dict[str, str]]:
    digits = normalize_phone(phone)["digits"]
    if not digits:
        return []
    variants = phone_variants(phone)
    or_query = " OR ".join(f'"{v}"' for v in variants[:6])
    return [
        {"label": "TrueCaller", "target": f"https://www.truecaller.com/search/us/{_q(digits)}"},
        {"label": "TruePeopleSearch", "target":
            f"https://www.truepeoplesearch.com/resultphone?phoneno={_q(digits)}"},
        {"label": "ThatsThem", "target": f"https://thatsthem.com/phone/{_q(digits)}"},
        {"label": "WhatsApp presence", "target": f"https://wa.me/{_q(digits)}",
         "rationale": "Establishes whether the number is registered to the service."},
        {"label": "Search all written forms",
         "target": f"https://www.google.com/search?q={_q(or_query)}",
         "rationale": "Covers the formats the number is likely to be written in."},
    ]


def pivots_for_name(name: str) -> List[Dict[str, str]]:
    q = _q(name)
    parts = name.split()
    slug = _q("-".join(parts)) if len(parts) >= 2 else q
    return [
        {"label": "TruePeopleSearch", "target": f"https://www.truepeoplesearch.com/results?name={q}"},
        {"label": "FastPeopleSearch", "target": f"https://www.fastpeoplesearch.com/name/{slug}"},
        {"label": "ThatsThem", "target": f"https://thatsthem.com/name/{slug}"},
        {"label": "LinkedIn people search",
         "target": f"https://www.linkedin.com/search/results/people/?keywords={q}"},
        *_search_engines(name),
    ]


def pivots_for_domain(domain: str) -> List[Dict[str, str]]:
    return [
        {"label": "WHOIS registration", "target": whois_url(domain),
         "rationale": "Registrant, registrar, and creation date."},
        {"label": "Certificate transparency", "target": crtsh_url(domain),
         "rationale": "Historic and sibling hostnames issued under the domain."},
        {"label": "Shodan", "target": shodan_domain_url(domain),
         "rationale": "Hosting infrastructure and exposed services."},
        {"label": "Wayback history", "target": f"https://web.archive.org/web/*/{domain}",
         "rationale": "What the site said before it said what it says now."},
    ]


def pivots_for_ip(ip: str) -> List[Dict[str, str]]:
    return [
        {"label": "Shodan host", "target": shodan_host_url(ip)},
        {"label": "Reverse DNS and hosting", "target": f"https://viewdns.info/reverseip/?host={_q(ip)}"},
    ]


def pivots_for_crypto(address: str, chain: str) -> List[Dict[str, str]]:
    if chain == CRYPTO_ETH:
        return [{"label": "Etherscan", "target": f"https://etherscan.io/address/{_q(address)}",
                 "rationale": "Transaction history and counterparties."}]
    return [{"label": "Blockchain explorer",
             "target": f"https://www.blockchain.com/explorer/addresses/btc/{_q(address)}",
             "rationale": "Transaction history and counterparties."}]


# False-positive risk notes, because a pivot without one invites over-reading a hit.
FALSE_POSITIVE_RISK = {
    USERNAME: "High. Handles collide constantly; identical handles on two sites are often different people.",
    EMAIL: "Low for the address itself, high for anything pivoted from its local part.",
    PHONE: "Medium. Numbers are reassigned, and business numbers are shared by many people.",
    NAME: "Very high. Name matching alone establishes nothing without a second corroborating identifier.",
    DOMAIN: "Low for registration data, medium for shared-hosting inferences.",
    IP: "High. Shared hosting and CDNs put unrelated parties behind one address.",
    CRYPTO_BTC: "Low for the address, high for attributing an address to a person.",
    CRYPTO_ETH: "Low for the address, high for attributing an address to a person.",
}

_BUILDERS = {
    USERNAME: lambda v: pivots_for_username(v),
    EMAIL: lambda v: pivots_for_email(v),
    PHONE: lambda v: pivots_for_phone(v),
    NAME: lambda v: pivots_for_name(v),
    DOMAIN: lambda v: pivots_for_domain(v),
    IP: lambda v: pivots_for_ip(v),
    CRYPTO_BTC: lambda v: pivots_for_crypto(v, CRYPTO_BTC),
    CRYPTO_ETH: lambda v: pivots_for_crypto(v, CRYPTO_ETH),
}


def pivots_for(kind: str, value: str) -> List[Dict[str, str]]:
    builder = _BUILDERS.get(kind)
    return builder(value) if builder else []


def generate_leads(index: EntityIndex, per_kind: int = DEFAULT_PER_KIND) -> List[Lead]:
    """Expand the best-corroborated entities of each kind into actionable pivots.

    Entities seen on more pages come first, on the reasoning that an identifier the crawl
    kept running into is the one most worth chasing.
    """
    leads: List[Lead] = []
    for kind in _BUILDERS:
        entities = sorted(
            index.of_kind(kind),
            key=lambda e: (-len(e.sources), -e.count, e.canonical_value),
        )[:per_kind]
        for entity in entities:
            for pivot in pivots_for(kind, entity.value):
                leads.append(Lead(
                    label=pivot["label"],
                    target=pivot["target"],
                    rationale=pivot.get("rationale", ""),
                    seed=entity.value,
                    seed_type=kind,
                    sources=list(entity.sources)[:10],
                    false_positive_risk=FALSE_POSITIVE_RISK.get(kind, ""),
                ))
    return leads
