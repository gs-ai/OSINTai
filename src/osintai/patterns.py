"""Deterministic pattern and anomaly checks over crawled material.

Everything here is pure code. No model is consulted, nothing is inferred, and every finding
can be reproduced from the saved run artifacts. That is the point: OSINTai's only analysis
before this was whatever the model chose to say, and a finding an operator cannot reproduce
is a finding they cannot testify to.

The checks cover homoglyph and zero-width characters, sensitive domains, internal IPs,
secret-shaped material, JWT structure, credential-shaped text, and generated-text markers.

Matched secret values are never written into findings. The finding records that
credential-shaped material exists, where, and how much.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import unicodedata
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

from .provenance import (
    DERIVED,
    HIGH,
    LOW,
    MEDIUM,
    OBSERVED,
    CheckResult,
    Finding,
    deterministic_confidence,
    source_support,
)

ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "­": "SOFT HYPHEN",
}

# Practical investigative mapping of characters that render as ASCII but are not.
HOMOGLYPH_MAP: Dict[str, str] = {
    "а": "a", "Α": "A", "А": "A", "ɑ": "a", "à": "a", "á": "a", "ä": "a",
    "е": "e", "Ε": "E", "Е": "E", "è": "e", "é": "e", "ë": "e",
    "і": "i", "Ι": "I", "І": "I", "í": "i", "ï": "i", "ı": "i",
    "ο": "o", "О": "O", "Ο": "O", "о": "o", "ò": "o", "ó": "o", "ö": "o",
    "р": "p", "Ρ": "P", "Р": "P",
    "с": "c", "С": "C", "Ϲ": "C",
    "х": "x", "Χ": "X", "Х": "X",
    "у": "y", "Υ": "Y", "Ү": "Y",
    "ѕ": "s", "Ѕ": "S",
    "ԁ": "d", "Ԁ": "D",
    "Ь": "b", "Ꮟ": "b",
    "ӏ": "l", "ⅼ": "l", "Ⅰ": "I",
    "ｍ": "m", "ｎ": "n", "ａ": "a", "ｂ": "b", "ｃ": "c", "ｅ": "e", "ｉ": "i",
    "ｏ": "o", "ｐ": "p", "ｓ": "s", "ｔ": "t", "ｕ": "u", "ｘ": "x", "ｙ": "y",
}

SENSITIVE_TLDS = (".gov", ".mil")

# Phrases that leak through when generated text is published without editing. Cheap,
# deterministic, and a real source-validation signal on a modern crawl.
AI_TEXT_MARKERS = (
    "as an ai language model",
    "as an ai assistant",
    "i'm sorry, but i cannot",
    "i cannot fulfill that request",
    "my training data",
    "i do not have personal opinions",
    "knowledge cutoff",
    "as a large language model",
    "i'm unable to provide",
    "regenerate response",
)


def _codepoints(text: str) -> str:
    return " ".join(f"U+{ord(ch):04X}" for ch in text)


def _char_name(ch: str) -> str:
    if ch in ZERO_WIDTH:
        return ZERO_WIDTH[ch]
    return unicodedata.name(ch, "UNKNOWN")


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    if a == 10:
        return True
    if a == 192 and b == 168:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 127:
        return True
    if a == 169 and b == 254:
        return True
    return False


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """Decode a JWT's claim set. Structure only; no signature is verified."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload + padding)
        decoded = json.loads(raw.decode("utf-8", errors="ignore"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def check_homoglyphs(index) -> CheckResult:
    """Non-ASCII lookalikes in crawled domains and handles.

    A domain that reads as a familiar brand but carries a Cyrillic character is one of the
    higher-value things a crawl can surface, and OSINTai could not see it before.
    """
    from .entities import DOMAIN, USERNAME

    result = CheckResult(check_name="Unicode / Homoglyph Analysis")
    candidates = index.of_kind(DOMAIN) + index.of_kind(USERNAME)
    if not candidates:
        result.notes.append("No domains or handles collected. Homoglyph analysis skipped.")
        return result

    for entity in candidates:
        value = entity.value
        flagged: List[str] = []
        mapped: List[str] = []
        has_zero_width = False
        for ch in value:
            cp = ord(ch)
            if 0x20 <= cp <= 0x7E:
                continue
            if ch in ZERO_WIDTH:
                has_zero_width = True
            flagged.append(f"{ch} U+{cp:04X} {_char_name(ch)}")
            replacement = HOMOGLYPH_MAP.get(ch)
            mapped.append(
                f"U+{cp:04X} -> {replacement}" if replacement else f"U+{cp:04X} -> no ASCII mapping"
            )

        if not flagged:
            continue

        ascii_form = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in value)
        priority = HIGH if has_zero_width else MEDIUM
        reason = (
            "Contains zero-width control characters, which are invisible when rendered."
            if has_zero_width
            else "Contains non-ASCII characters that render similarly to ASCII."
        )
        result.rows.append({
            "value": value,
            "kind": entity.kind,
            "codepoints": _codepoints(value),
            "flagged_characters": "; ".join(flagged),
            "ascii_normalization": ascii_form,
            "sources": len(entity.sources),
        })
        result.findings.append(Finding(
            check="Unicode / Homoglyph",
            item=value,
            reason=reason,
            next_step=(
                "Compare against the canonical ASCII spelling "
                f"({ascii_form!r}), check registration and certificate history for both forms, "
                "and confirm which one the subject actually controls."
            ),
            origin=DERIVED,
            priority=priority,
            sources=list(entity.sources),
            evidence={
                "codepoints": _codepoints(value),
                "flagged_characters": flagged,
                "homoglyph_mapping": mapped,
                "ascii_normalization": ascii_form,
            },
            method="unicode_codepoint_scan",
            confidence=[
                deterministic_confidence(1.0, "codepoint inspection is exact"),
                source_support(list(entity.sources)),
            ],
        ))

    result.notes.append(
        f"Inspected {len(candidates)} domain(s)/handle(s). "
        f"Flagged {result.finding_count} containing non-ASCII characters."
    )
    return result


def check_sensitive_infrastructure(index) -> CheckResult:
    """Government/military identifiers and non-routable addresses in crawled content."""
    from .entities import DOMAIN, EMAIL, IP

    result = CheckResult(check_name="Sensitive Infrastructure Indicators")

    for entity in index.of_kind(EMAIL):
        domain_part = entity.canonical_value.rsplit("@", 1)[-1]
        if domain_part.endswith(SENSITIVE_TLDS):
            result.findings.append(Finding(
                check="Sensitive Email Domain",
                item=entity.value,
                reason=f"Email address on a restricted-use domain ({domain_part}).",
                next_step=(
                    "Confirm the address is genuinely published rather than scraped or spoofed, "
                    "and handle under the rules applying to government contact data."
                ),
                origin=OBSERVED,
                priority=HIGH,
                sources=list(entity.sources),
                evidence={"domain": domain_part},
                method="tld_rule",
                confidence=[deterministic_confidence(1.0, "suffix match"),
                            source_support(list(entity.sources))],
            ))

    for entity in index.of_kind(DOMAIN):
        if entity.canonical_value.endswith(SENSITIVE_TLDS):
            result.findings.append(Finding(
                check="Sensitive Domain",
                item=entity.value,
                reason="Domain on a restricted-use top-level domain.",
                next_step="Record the referencing page and confirm whether the reference is authentic.",
                origin=OBSERVED,
                priority=MEDIUM,
                sources=list(entity.sources),
                evidence={"domain": entity.canonical_value},
                method="tld_rule",
                confidence=[deterministic_confidence(1.0, "suffix match"),
                            source_support(list(entity.sources))],
            ))

    for entity in index.of_kind(IP):
        if _is_private_ip(entity.value):
            result.findings.append(Finding(
                check="Internal IP Exposure",
                item=entity.value,
                reason="Non-routable (internal) IP address published on a public page.",
                next_step=(
                    "Check whether the page leaks internal network topology, error output, or "
                    "configuration; capture the surrounding context before it changes."
                ),
                origin=OBSERVED,
                priority=MEDIUM,
                sources=list(entity.sources),
                evidence={"ip": entity.value},
                method="rfc1918_rule",
                confidence=[deterministic_confidence(1.0, "address range check"),
                            source_support(list(entity.sources))],
            ))

    result.rows = [
        {"item": f.item, "check": f.check, "sources": len(f.sources)} for f in result.findings
    ]
    result.notes.append(f"Flagged {result.finding_count} sensitive infrastructure indicator(s).")
    return result


def check_secret_exposure(page_extras: Dict[str, Dict[str, List[str]]]) -> CheckResult:
    """Credential-shaped and secret-shaped material on crawled pages.

    Deliberately reports presence and location only. The matched value is not copied into
    the finding, the evidence dict, or the report.
    """
    result = CheckResult(check_name="Credential and Secret Exposure")

    for url, extras in (page_extras or {}).items():
        tokens = extras.get("api_tokens") or []
        jwts = extras.get("jwts") or []
        pairs = extras.get("credential_pairs") or []

        if tokens:
            high_entropy = [t for t in tokens if _shannon_entropy(t) >= 3.5]
            result.findings.append(Finding(
                check="Potential Secret Exposure",
                item=url,
                reason=(
                    f"{len(tokens)} key/token-shaped value(s) found in page content, "
                    f"{len(high_entropy)} of them high-entropy."
                ),
                next_step=(
                    "Open the page and confirm whether these are live credentials, example "
                    "placeholders, or public identifiers. If live, treat as an exposure and "
                    "notify the owner rather than using them."
                ),
                origin=DERIVED,
                priority=HIGH if high_entropy else MEDIUM,
                sources=[url],
                evidence={
                    "token_count": len(tokens),
                    "high_entropy_count": len(high_entropy),
                    "value_recorded": False,
                },
                method="token_pattern_entropy",
                confidence=[deterministic_confidence(
                    0.6, "pattern match; placeholders and examples also match")],
            ))

        for token in jwts:
            claims = decode_jwt_payload(token)
            claim_keys = sorted(claims.keys()) if claims else []
            result.findings.append(Finding(
                check="JWT Present",
                item=url,
                reason=(
                    "JSON Web Token found in page content"
                    + (f" carrying claims: {', '.join(claim_keys[:12])}." if claim_keys else ".")
                ),
                next_step=(
                    "Review the decoded claim set for issuer, subject, audience and expiry to "
                    "identify the issuing system. Do not replay the token."
                ),
                origin=DERIVED,
                priority=HIGH if claims else MEDIUM,
                sources=[url],
                evidence={
                    "claim_keys": claim_keys,
                    "issuer": str(claims.get("iss", "")) if claims else "",
                    "audience": str(claims.get("aud", "")) if claims else "",
                    "expiry": str(claims.get("exp", "")) if claims else "",
                    "recorded_value": False,
                },
                method="jwt_structural_decode",
                confidence=[deterministic_confidence(
                    0.95 if claims else 0.5,
                    "three-segment structure decoded" if claims else "structure matched, payload unreadable")],
            ))

        if pairs:
            result.findings.append(Finding(
                check="Credential-Shaped Content",
                item=url,
                reason=f"{len(pairs)} line(s) matching an identifier:secret layout.",
                next_step=(
                    "Determine whether the page is a leak, a configuration sample, or unrelated "
                    "colon-delimited data. Preserve the page capture before it is removed."
                ),
                origin=DERIVED,
                priority=HIGH,
                sources=[url],
                evidence={"pair_count": len(pairs), "values_recorded": False},
                method="credential_pattern",
                confidence=[deterministic_confidence(
                    0.5, "layout match only; colon-delimited data is common")],
            ))

    result.rows = [
        {"url": f.item, "check": f.check, "priority": f.priority} for f in result.findings
    ]
    result.notes.append(
        f"Flagged {result.finding_count} secret/credential exposure indicator(s). "
        "Matched values are intentionally not recorded."
    )
    return result


def check_generated_text(pages: Iterable[Dict[str, Any]], text_loader) -> CheckResult:
    """Pages carrying unedited language-model output.

    Source validation: content that was generated rather than written changes what a page is
    worth as evidence, and it is worth knowing before the page is cited.
    """
    result = CheckResult(check_name="Generated-Content Fingerprint")
    checked = 0

    for page in pages or []:
        url = page.get("url")
        if not url:
            continue
        text = text_loader(url)
        if not text:
            continue
        checked += 1
        lowered = text.lower()
        hits = [marker for marker in AI_TEXT_MARKERS if marker in lowered]
        if not hits:
            continue
        result.rows.append({"url": url, "markers": "; ".join(hits), "marker_count": len(hits)})
        result.findings.append(Finding(
            check="Generated-Content Fingerprint",
            item=url,
            reason=(
                f"Page contains {len(hits)} phrase(s) characteristic of unedited language-model "
                "output."
            ),
            next_step=(
                "Weigh this page lower as a primary source. Check whether the site publishes "
                "generated content at scale before relying on any claim it makes."
            ),
            origin=DERIVED,
            priority=MEDIUM if len(hits) == 1 else HIGH,
            sources=[url],
            evidence={"markers": hits},
            method="phrase_fingerprint",
            confidence=[deterministic_confidence(
                min(0.9, 0.45 + 0.15 * len(hits)),
                f"{len(hits)} marker phrase(s) matched")],
        ))

    result.notes.append(
        f"Scanned {checked} page text(s). Flagged {result.finding_count} with generated-content markers."
    )
    return result


def check_recurring_and_outliers(index, page_scores: List[Dict[str, Any]]) -> CheckResult:
    """Recurring cross-page signals and statistical outliers in page scores.

    Both are stated as what they are: a distribution observation, not a conclusion. A page
    two standard deviations above the mean is unusual for this run and nothing more.
    """
    result = CheckResult(check_name="Recurring Signals and Outliers")

    recurring = index.multi_source(minimum=3)[:40]
    for entity in recurring:
        result.rows.append({
            "kind": entity.kind,
            "value": entity.value,
            "source_count": len(entity.sources),
        })
        result.findings.append(Finding(
            check="Recurring Signal",
            item=entity.value,
            reason=f"Appears on {len(entity.sources)} independently crawled pages.",
            next_step=(
                "Treat as a spine for the investigation: establish who controls this identifier "
                "and why it links these pages."
            ),
            origin=DERIVED,
            priority=MEDIUM,
            sources=list(entity.sources)[:25],
            evidence={"kind": entity.kind, "source_count": len(entity.sources)},
            method="cross_page_frequency",
            confidence=[source_support(list(entity.sources))],
        ))

    scores = [float(p.get("score") or 0.0) for p in page_scores or []]
    if len(scores) >= 5:
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        stdev = math.sqrt(variance)
        result.stats = {
            "page_count": len(scores),
            "score_mean": round(mean, 3),
            "score_stdev": round(stdev, 3),
            "score_max": round(max(scores), 3),
        }
        if stdev > 0:
            threshold = mean + 2 * stdev
            for page in page_scores:
                score = float(page.get("score") or 0.0)
                if score < threshold:
                    continue
                result.findings.append(Finding(
                    check="Score Outlier",
                    item=page.get("url", ""),
                    reason=(
                        f"Page signal score {score:.2f} is more than two standard deviations "
                        f"above this run's mean of {mean:.2f}."
                    ),
                    next_step="Review this page first; it carries the densest indicator set in the run.",
                    origin=DERIVED,
                    priority=MEDIUM,
                    sources=[page.get("url", "")],
                    evidence={"score": score, "mean": round(mean, 3), "stdev": round(stdev, 3)},
                    method="two_sigma_outlier",
                    confidence=[deterministic_confidence(
                        0.7, "distribution statistic over this run only")],
                ))
    else:
        result.notes.append("Fewer than 5 scored pages; outlier statistics not computed.")

    result.notes.append(
        f"Identified {len(recurring)} recurring signal(s) and "
        f"{sum(1 for f in result.findings if f.check == 'Score Outlier')} score outlier(s)."
    )
    return result
