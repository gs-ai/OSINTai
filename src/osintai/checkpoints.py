"""Content-addressed extraction checkpoints containing secret metadata only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .entities import extract_extended, API_TOKEN_RE
from .scanners import credentials
from .patterns import _shannon_entropy, decode_jwt_payload
from .storage import read_json, write_json

# Include implementation hashes so edits cannot silently reuse stale extraction results.
EXTRACTOR_VERSION = hashlib.sha256(
    b"".join(
        Path(__file__).with_name(name).read_bytes()
        for name in ("entities.py", "scanners.py", "patterns.py", "checkpoints.py")
    )
).hexdigest()


def extract_checkpoint(text):
    extras = extract_extended(text)
    coverage = extras.pop("extraction_coverage")
    tokens = extras.pop("api_tokens")
    jwts = extras.pop("jwts")
    pairs = extras.pop("credential_pairs")
    # Redaction must scan all matches, including those beyond the findings cap.
    secrets = set(API_TOKEN_RE.findall(text)) | set(jwts) | {secret for _, secret in credentials(text)}
    # A token can also resemble another indicator. Do not cache that copy either.
    extras = {
        key: [value for value in values if not any(secret in value for secret in secrets)]
        for key, values in extras.items()
    }
    extras["extraction_coverage"] = coverage
    extras["secret_summary"] = {
        "token_count": len(tokens),
        "high_entropy_count": sum(_shannon_entropy(token) >= 3.5 for token in tokens),
        "pair_count": len(pairs),
        # Arbitrary JWT claims can themselves contain secrets; retain only validity.
        "jwt_decodable": [decode_jwt_payload(token) is not None for token in jwts],
    }
    return extras


def _valid_extras(extras):
    list_fields = {"dates", "name_candidates", "addresses", "unicode_domains", "unicode_handles"}
    if not isinstance(extras, dict) or set(extras) != list_fields | {"secret_summary", "extraction_coverage"}:
        return False
    if any(
        not isinstance(extras[key], list) or any(not isinstance(v, str) for v in extras[key]) for key in list_fields
    ):
        return False
    summary, coverage = extras["secret_summary"], extras["extraction_coverage"]
    if not isinstance(summary, dict) or not isinstance(coverage, dict):
        return False
    if any(
        type(summary.get(key)) is not int or summary[key] < 0
        for key in ("token_count", "high_entropy_count", "pair_count")
    ):
        return False
    if not isinstance(summary.get("jwt_decodable"), list) or any(type(v) is not bool for v in summary["jwt_decodable"]):
        return False
    return all(
        isinstance(counts, dict)
        and all(type(counts.get(key)) is int and counts[key] >= 0 for key in ("observed", "retained", "omitted"))
        for counts in coverage.values()
    )


class ExtractionCache:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.hits = self.misses = self.invalid = 0

    def key(self, text, limit, truncated):
        metadata = {
            "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "extractor_version": EXTRACTOR_VERSION,
            "max_text_chars": limit,
            "truncated": truncated,
        }
        key = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()
        return key, metadata

    def get(self, key, metadata):
        path = self.directory / f"{key}.json"
        payload = read_json(str(path))
        if isinstance(payload, dict) and payload.get("metadata") == metadata:
            extras = payload.get("extras")
            if _valid_extras(extras):
                checksum = hashlib.sha256(json.dumps(extras, sort_keys=True).encode()).hexdigest()
                if checksum == payload.get("checksum"):
                    self.hits += 1
                    return extras
        self.invalid += int(path.exists())
        self.misses += 1
        return None

    def put(self, key, metadata, extras):
        write_json(
            str(self.directory / f"{key}.json"),
            {
                "metadata": metadata,
                "extras": extras,
                "checksum": hashlib.sha256(json.dumps(extras, sort_keys=True).encode()).hexdigest(),
            },
        )
