"""
Log file parser supporting nginx combined, Apache common, JSON, and generic formats.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# nginx combined log format:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://referer" "Mozilla/5.0"
_NGINX_PATTERN = re.compile(
    r'(?P<remote_addr>\S+)'           # client IP
    r'\s+-\s+'                        # ident (always -)
    r'(?P<remote_user>\S+)'           # auth user
    r'\s+\[(?P<time_local>[^\]]+)\]'  # [timestamp]
    r'\s+"(?P<request>[^"]*)"'        # "METHOD /path HTTP/x.x"
    r'\s+(?P<status>\d{3})'          # status code
    r'\s+(?P<body_bytes_sent>\S+)'    # bytes sent
    r'(?:\s+"(?P<http_referer>[^"]*)"'  # optional referer
    r'\s+"(?P<http_user_agent>[^"]*)")?'  # optional user agent
)

# Apache common log format:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
_APACHE_PATTERN = re.compile(
    r'(?P<remote_addr>\S+)'
    r'\s+\S+'                          # ident
    r'\s+(?P<remote_user>\S+)'
    r'\s+\[(?P<time_local>[^\]]+)\]'
    r'\s+"(?P<request>[^"]*)"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<body_bytes_sent>\S+)'
    r'\s*$'
)

# Generic log: timestamp level message
# 2024-01-15 10:23:45 ERROR Something went wrong
# 2024-01-15T10:23:45.123Z [ERROR] Something went wrong
_GENERIC_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
    r'\s+(?:\[)?(?P<level>DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|CRITICAL|FATAL|TRACE)(?:\])?'
    r'\s+(?P<message>.+)',
    re.IGNORECASE,
)

_NGINX_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

_HTTP_STATUS_TO_LEVEL = {
    range(100, 200): "INFO",
    range(200, 300): "INFO",
    range(300, 400): "INFO",
    range(400, 500): "WARNING",
    range(500, 600): "ERROR",
}


def _http_status_level(status: int) -> str:
    for rng, level in _HTTP_STATUS_TO_LEVEL.items():
        if status in rng:
            return level
    return "INFO"


def _parse_nginx_timestamp(raw: str) -> Optional[datetime]:
    try:
        return datetime.strptime(raw, _NGINX_TIME_FORMAT)
    except ValueError:
        return None


def _parse_iso_timestamp(raw: str) -> Optional[datetime]:
    """Parse ISO-8601 and common variant timestamps."""
    raw = raw.replace(",", ".").rstrip("Z")
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_line(line: str) -> Optional[dict]:
    """
    Parse a single log line into a dict with keys:
      timestamp (datetime | None), level (str), message (str), raw (str)

    Returns None if the line is blank or a comment.
    """
    line = line.rstrip("\n\r")
    if not line or line.startswith("#"):
        return None

    # --- JSON ---
    stripped = line.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            ts = None
            for ts_key in ("timestamp", "time", "ts", "@timestamp", "date"):
                if ts_key in data:
                    ts = _parse_iso_timestamp(str(data[ts_key]))
                    break
            level = "INFO"
            for lvl_key in ("level", "severity", "log_level", "loglevel"):
                if lvl_key in data:
                    level = str(data[lvl_key]).upper()
                    break
            message = ""
            for msg_key in ("message", "msg", "text", "body"):
                if msg_key in data:
                    message = str(data[msg_key])
                    break
            if not message:
                message = stripped
            return {"timestamp": ts, "level": level, "message": message, "raw": line}
        except json.JSONDecodeError:
            pass

    # --- nginx combined ---
    m = _NGINX_PATTERN.match(line)
    if m:
        status = int(m.group("status"))
        level = _http_status_level(status)
        ts = _parse_nginx_timestamp(m.group("time_local"))
        request = m.group("request")
        message = (
            f'{m.group("remote_addr")} "{request}" {status} {m.group("body_bytes_sent")}B'
        )
        return {"timestamp": ts, "level": level, "message": message, "raw": line}

    # --- Apache common (no referer/agent) ---
    m = _APACHE_PATTERN.match(line)
    if m:
        status = int(m.group("status"))
        level = _http_status_level(status)
        ts = _parse_nginx_timestamp(m.group("time_local"))
        message = (
            f'{m.group("remote_addr")} "{m.group("request")}" {status} {m.group("body_bytes_sent")}B'
        )
        return {"timestamp": ts, "level": level, "message": message, "raw": line}

    # --- Generic timestamped log ---
    m = _GENERIC_PATTERN.match(line)
    if m:
        ts = _parse_iso_timestamp(m.group("timestamp"))
        level = m.group("level").upper()
        # Normalise WARN -> WARNING, FATAL -> CRITICAL
        level = {"WARN": "WARNING", "FATAL": "CRITICAL"}.get(level, level)
        return {"timestamp": ts, "level": level, "message": m.group("message").strip(), "raw": line}

    # --- Fallback: unparseable but non-empty ---
    return {"timestamp": None, "level": "UNKNOWN", "message": line, "raw": line}


def detect_format(sample_lines: list[str]) -> str:
    """
    Inspect up to 20 non-blank lines and return the most likely format:
    'nginx', 'apache', 'json', or 'generic'.
    """
    candidates: list[str] = []
    for line in sample_lines:
        line = line.rstrip()
        if line and not line.startswith("#"):
            candidates.append(line)
        if len(candidates) >= 20:
            break

    scores = {"nginx": 0, "apache": 0, "json": 0, "generic": 0}

    for line in candidates:
        stripped = line.lstrip()
        if stripped.startswith("{"):
            try:
                json.loads(stripped)
                scores["json"] += 1
                continue
            except json.JSONDecodeError:
                pass

        # nginx has referer + user-agent fields (7+ space-separated tokens after status)
        if _NGINX_PATTERN.match(line):
            m = _NGINX_PATTERN.match(line)
            if m and m.group("http_user_agent"):
                scores["nginx"] += 2
            else:
                scores["apache"] += 1
            continue

        if _APACHE_PATTERN.match(line):
            scores["apache"] += 1
            continue

        if _GENERIC_PATTERN.match(line):
            scores["generic"] += 1

    best = max(scores, key=lambda k: scores[k])
    # If nothing scored, default to generic
    return best if scores[best] > 0 else "generic"


def parse_file(path: str | Path) -> list[dict]:
    """
    Parse every line in the file at *path* and return a list of entry dicts.
    Unparseable blank/comment lines are skipped; everything else is included
    (worst case with level='UNKNOWN').
    """
    path = Path(path)
    entries: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    for line in lines:
        entry = parse_line(line)
        if entry is not None:
            entries.append(entry)

    return entries
