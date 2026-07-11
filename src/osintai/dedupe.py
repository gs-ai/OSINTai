import hashlib
import re

def sha1_bytes(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()

def sha1_text(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def simhash_64(text: str) -> int:
    """
    Compute a 64-bit weighted Simhash for near-duplicate detection.

    Runtime is O(t * 64), where t is the capped token count. Space is O(1)
    aside from the token iterator and fixed-width bit accumulator.
    """
    tokens = re.findall(r"[a-z0-9]{3,}", (text or "").lower())[:1000]
    if not tokens:
        return 0

    bit_weights = [0] * 64
    for token in tokens:
        h = int(hashlib.blake2b(token.encode("utf-8"), digest_size=8).hexdigest(), 16)
        for bit in range(64):
            bit_weights[bit] += 1 if h & (1 << bit) else -1

    simhash = 0
    for bit, weight in enumerate(bit_weights):
        if weight >= 0:
            simhash |= 1 << bit
    return simhash

def hamming64(a: int, b: int) -> int:
    """Calculate hamming distance between two 64-bit integers."""
    return (a ^ b).bit_count()
