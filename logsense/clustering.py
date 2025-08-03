"""
Error pattern clustering using token-based similarity.

Variable parts of messages (IPs, URLs, file paths, hex IDs, numbers) are
replaced with typed placeholders to form a canonical "template".  Entries
that share the same template are grouped together.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import Optional

from logsense.constants import ERROR_LEVELS


# ---------------------------------------------------------------------------
# Normalisation regexes — applied in order
# ---------------------------------------------------------------------------

_SUBSTITUTIONS: list[tuple[re.Pattern, str]] = [
    # IPv6 addresses
    (re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'), "<IPv6>"),
    # IPv4 addresses (including with port)
    (re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b'), "<IP>"),
    # UUIDs
    (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', re.IGNORECASE), "<UUID>"),
    # Long hex strings (commit hashes, tokens, etc.)
    (re.compile(r'\b[0-9a-fA-F]{8,}\b'), "<HEX>"),
    # URLs
    (re.compile(r'https?://[^\s"\'<>]+'), "<URL>"),
    # File/URL paths  (absolute unix paths or url paths)
    (re.compile(r'(?<!\w)/(?:[^\s/]+/)*[^\s/]+'), "<PATH>"),
    # Windows paths
    (re.compile(r'[A-Za-z]:\\(?:[^\s\\]+\\)*[^\s\\]+'), "<PATH>"),
    # Quoted strings
    (re.compile(r'"[^"]{4,}"'), "<STR>"),
    (re.compile(r"'[^']{4,}'"), "<STR>"),
    # Linux/Unix block device identifiers (sda, sdb, nvme0n1, vda, xvdb, etc.)
    (re.compile(r'\b(?:sd|hd|vd|xvd)[a-z][0-9]?\b|nvme\d+n\d+(?:p\d+)?\b', re.IGNORECASE), "<DEVICE>"),
    # Numbers with units (e.g. 512ms, 1.5s, 404)
    (re.compile(r'\b\d+(?:\.\d+)?(?:ms|s|kb|mb|gb|b)?\b', re.IGNORECASE), "<NUM>"),
    # Collapse repeated whitespace
    (re.compile(r'\s{2,}'), " "),
]


def _make_template(message: str) -> str:
    """Return a normalised template string for *message*."""
    tmpl = message.lower()
    for pattern, replacement in _SUBSTITUTIONS:
        tmpl = pattern.sub(replacement, tmpl)
    return tmpl.strip()


# ---------------------------------------------------------------------------
# Similarity helpers
# ---------------------------------------------------------------------------

def _token_similarity(a: str, b: str) -> float:
    """Jaccard similarity between token sets of two strings."""
    ta = set(re.split(r'\W+', a))
    tb = set(re.split(r'\W+', b))
    if not ta and not tb:
        return 1.0
    intersection = ta & tb
    union = ta | tb
    return len(intersection) / len(union)


def _merge_similar_templates(
    groups: dict[str, list[dict]],
    similarity_threshold: float = 0.72,
) -> dict[str, list[dict]]:
    """
    Merge template buckets that are very similar into a single representative
    template.  Uses a greedy single-pass approach — O(n²) on the number of
    unique templates, which is fine given the small number of patterns
    typically produced per log file.
    """
    keys = list(groups.keys())
    parent: dict[str, str] = {k: k for k in keys}

    def find(k: str) -> str:
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            ki, kj = find(keys[i]), find(keys[j])
            if ki == kj:
                continue
            if _token_similarity(ki, kj) >= similarity_threshold:
                # Merge the smaller group into the larger one
                if len(groups[ki]) >= len(groups[kj]):
                    parent[kj] = ki
                else:
                    parent[ki] = kj

    merged: dict[str, list[dict]] = defaultdict(list)
    for key, entries in groups.items():
        merged[find(key)].extend(entries)

    return dict(merged)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_ERROR_LEVELS = ERROR_LEVELS


def cluster_errors(
    log_entries: list[dict],
    *,
    include_warnings: bool = True,
    max_examples: int = 3,
    similarity_threshold: float = 0.72,
) -> list[dict]:
    """
    Group error/warning log entries by message template.

    Parameters
    ----------
    log_entries:
        List of entry dicts as returned by ``parser.parse_file``.
    include_warnings:
        If False, only ERROR/CRITICAL entries are clustered.
    max_examples:
        Number of raw example lines to keep per cluster.
    similarity_threshold:
        Jaccard similarity above which two templates are merged (0–1).

    Returns
    -------
    List of cluster dicts, sorted by count descending:
      {
        "pattern":    str,          # canonical template
        "count":      int,
        "examples":   list[str],    # sample raw lines
        "first_seen": datetime | None,
        "last_seen":  datetime | None,
        "levels":     dict[str, int],  # {"ERROR": 5, "WARNING": 2}
      }
    """
    target_levels = _ERROR_LEVELS if include_warnings else {"ERROR", "CRITICAL", "FATAL"}

    # Step 1: exact template grouping
    groups: dict[str, list[dict]] = defaultdict(list)
    for entry in log_entries:
        if entry.get("level", "").upper() not in target_levels:
            continue
        tmpl = _make_template(entry.get("message", entry.get("raw", "")))
        if tmpl:
            groups[tmpl].append(entry)

    if not groups:
        return []

    # Step 2: merge very-similar templates
    merged = _merge_similar_templates(dict(groups), similarity_threshold)

    # Step 3: build result objects
    results: list[dict] = []
    for pattern, entries in merged.items():
        timestamps: list[datetime] = [
            e["timestamp"] for e in entries if isinstance(e.get("timestamp"), datetime)
        ]
        level_counts: dict[str, int] = defaultdict(int)
        for e in entries:
            level_counts[e.get("level", "UNKNOWN")] += 1

        results.append(
            {
                "pattern": pattern,
                "count": len(entries),
                "examples": [e["raw"] for e in entries[:max_examples]],
                "first_seen": min(timestamps) if timestamps else None,
                "last_seen": max(timestamps) if timestamps else None,
                "levels": dict(level_counts),
            }
        )

    results.sort(key=lambda c: c["count"], reverse=True)
    return results


MAX_3 = 115
