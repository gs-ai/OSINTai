"""Model result classification without retaining invalid response bodies."""

from collections import Counter, defaultdict

LIST_FIELDS = ("key_entities", "key_locations", "key_dates", "keywords", "risk_flags", "actionable_leads")
STATUSES = ("ok", "empty", "invalid", "missing", "timed_out", "error", "skipped")


def page_status(payload):
    if payload is None or payload == {}:
        return "empty"
    if not isinstance(payload, dict):
        return "invalid"
    status = payload.get("_model_status")
    if status in STATUSES and status != "ok":
        return status
    if payload.get("error"):
        return "error"
    if not isinstance(payload.get("summary"), str) or not payload["summary"].strip():
        return "invalid"
    if any(not isinstance(payload.get(key), list) for key in LIST_FIELDS):
        return "invalid"
    if any(not isinstance(item, str) for key in LIST_FIELDS[:-1] for item in payload[key]):
        return "invalid"
    if any(not isinstance(item, (str, dict)) for item in payload["actionable_leads"]):
        return "invalid"
    return "ok"


def summarize(rows):
    by_model = defaultdict(Counter)
    counts = Counter()
    for row in rows:
        status = row["_model_status"]
        counts[status] += 1
        by_model[row.get("_model") or "unknown"][status] += 1
    return {
        "counts": {status: counts[status] for status in STATUSES},
        "models": {model: dict(count) for model, count in sorted(by_model.items())},
        "pages": len(rows),
    }
