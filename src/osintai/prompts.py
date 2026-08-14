"""Prompt registry for OSINTai.

The `standard` page prompt is the exact text the crawler has always sent, moved here
unchanged so that `osint-tuned-v3` sees byte-identical input and its behavior does not
shift. A regression test asserts that equality; do not edit the standard profile.

Additional profiles are opt-in lenses over the same page. The `threat` profile asks a
different question of the same content without silently changing the default. Run-level
prompts keep confidence, evidence, and proposed pivots distinct.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

STANDARD = "standard"
THREAT = "threat"

PAGE_SNIPPET_CHARS = 12000

# Stated at the top of every run-level prompt. Kept out of the standard page prompt so that
# prompt stays byte-identical to the baseline.
ANALYST_PREAMBLE = """You are a professional OSINT analyst.

Your output must:
- Separate confirmed facts from unverified leads
- Use precise confidence language: documented, indicated, appears, possible, unverified, requires confirmation
- Never overstate the strength of a lead
- Reference the source URL for every finding
- Flag false-positive risk on identifier-based pivots

Do not speculate. Do not present leads as facts. Output valid JSON only."""


def standard_page_prompt(url: str, title: str, text: str) -> str:
    """The baseline per-page extraction prompt. Text is frozen; do not modify."""
    snippet = (text or "")[:PAGE_SNIPPET_CHARS]
    return f"""
You are an OSINT analyst. Produce a structured intelligence extraction from this webpage.

Rules:
- No filler. No moralizing.
- Only use evidence from the content.
- Output valid JSON only.

Return schema:
{{
  "url": "...",
  "title": "...",
  "summary": "2-4 sentences",
  "key_entities": ["..."],
  "key_locations": ["..."],
  "key_dates": ["..."],
  "keywords": ["..."],
  "risk_flags": ["..."],
  "actionable_leads": ["..."]
}}

URL: {url}
TITLE: {title}

CONTENT:
{snippet}
""".strip()


def threat_page_prompt(url: str, title: str, text: str) -> str:
    """Cyber-threat lens. Same JSON schema so every downstream consumer keeps working."""
    snippet = (text or "")[:PAGE_SNIPPET_CHARS]
    return f"""
You are a cyber threat analyst. Assess this webpage for behavioral and cyber threat indicators.

Rules:
- No filler. No moralizing.
- Only use evidence from the content.
- Output valid JSON only.

Return schema:
{{
  "url": "...",
  "title": "...",
  "summary": "2-4 sentences covering threats and suspicious behavior",
  "key_entities": ["actors, organizations, infrastructure named in the content"],
  "key_locations": ["..."],
  "key_dates": ["..."],
  "keywords": ["..."],
  "risk_flags": ["indicators of compromise, suspicious behavior, exposure"],
  "actionable_leads": ["recommended further investigation"]
}}

URL: {url}
TITLE: {title}

CONTENT:
{snippet}
""".strip()


PAGE_PROFILES: Dict[str, Callable[[str, str, str], str]] = {
    STANDARD: standard_page_prompt,
    THREAT: threat_page_prompt,
}


def page_prompt(url: str, title: str, text: str, profile: str = STANDARD) -> str:
    builder = PAGE_PROFILES.get(profile, standard_page_prompt)
    return builder(url, title, text)


def deep_analysis_prompt(context: Dict[str, Any]) -> str:
    """Run-level analysis over the whole crawl.

    The context payload assembles several independent sources into one structured block and
    asks the model to reason across them — the cross-source fusion pattern from AvantGarde,
    applied to crawled material rather than third-party APIs.
    """
    import json

    return f"""{ANALYST_PREAMBLE}

You are reviewing an entire OSINT collection run. Deterministic analysis has already been
performed and is given to you below. Do not repeat it. Identify what it does not already say.

Return schema:
{{
  "assessment": "3-6 sentences on what this collection appears to show",
  "cross_source_observations": ["patterns visible only across multiple sources"],
  "hypotheses": [
    {{
      "statement": "...",
      "supporting": ["..."],
      "contradicting": ["..."],
      "would_confirm": "...",
      "would_refute": "...",
      "follow_up": "...",
      "confidence": 0.0
    }}
  ],
  "recommended_follow_up": ["..."],
  "gaps": ["what this collection does not cover"]
}}

RUN CONTEXT:
{json.dumps(context, ensure_ascii=False, indent=2, default=str)[:24000]}
""".strip()


def cross_check_prompt(claim: str, context: str) -> str:
    """Ask a second model to judge one claim independently.

    Deliberately narrow: a single claim and its context, so two models' answers are
    comparable rather than two different essays.
    """
    return f"""{ANALYST_PREAMBLE}

Assess the single claim below against the supplied context only.

Return schema:
{{
  "verdict": "supported" | "unsupported" | "contradicted" | "insufficient_evidence",
  "reason": "1-2 sentences",
  "confidence": 0.0
}}

CLAIM:
{claim}

CONTEXT:
{context[:8000]}
""".strip()
