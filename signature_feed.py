"""Strict parser/validator for ShieldCore local JSON signature-feed format v1."""
import json
import re

ALLOWED_SEVERITIES = {"high", "medium", "low", "test"}
MAX_RECORDS = 100_000

def load_feed(feed_path):
    """Return (feed_name, [(name, sha256, severity), ...]); reject malformed feeds entirely."""
    with open(feed_path, "r", encoding="utf-8") as f:
        feed = json.load(f)
    if not isinstance(feed, dict) or feed.get("format_version") != 1:
        raise ValueError("unsupported feed format_version; expected 1")
    feed_name = feed.get("feed_name")
    records = feed.get("signatures")
    if not isinstance(feed_name, str) or not feed_name.strip() or len(feed_name) > 120:
        raise ValueError("feed_name must be a non-empty string up to 120 chars")
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError(f"signatures must be a list of at most {MAX_RECORDS} records")
    prepared = []
    for n, item in enumerate(records, 1):
        if not isinstance(item, dict): raise ValueError(f"record {n}: expected object")
        name, value = item.get("name"), item.get("sha256")
        severity = item.get("severity", "high")
        if not isinstance(name, str) or not name.strip() or len(name) > 200:
            raise ValueError(f"record {n}: invalid name")
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError(f"record {n}: sha256 must be 64 hexadecimal characters")
        if not isinstance(severity, str) or severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"record {n}: invalid severity")
        prepared.append((name.strip(), value.lower(), severity))
    return feed_name.strip(), prepared
