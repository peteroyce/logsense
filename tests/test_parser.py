"""
Tests for logsense.parser — parse_line and detect_format.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from logsense.parser import parse_line, detect_format, parse_file


# ---------------------------------------------------------------------------
# Fixtures / sample log lines
# ---------------------------------------------------------------------------

NGINX_LINE = (
    '192.168.1.10 - frank [10/Oct/2023:13:55:36 -0700] '
    '"GET /index.html HTTP/1.1" 200 2326 '
    '"http://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"'
)

NGINX_500_LINE = (
    '10.0.0.1 - - [15/Jan/2024:08:00:01 +0000] '
    '"POST /api/crash HTTP/1.1" 500 0 "-" "curl/7.88.1"'
)

APACHE_LINE = (
    '127.0.0.1 - bob [10/Oct/2023:13:55:36 +0000] '
    '"GET /apache_pb.gif HTTP/1.0" 200 2326'
)

APACHE_404_LINE = (
    '203.0.113.5 - - [16/Jan/2024:12:34:56 +0000] '
    '"GET /missing.html HTTP/1.1" 404 512'
)

GENERIC_ERROR_LINE = "2024-01-15 10:23:45 ERROR Database connection refused at 127.0.0.1:5432"
GENERIC_WARN_LINE  = "2024-01-15T10:24:00.123Z [WARNING] Disk usage above 80%"
GENERIC_INFO_LINE  = "2024-01-15 10:25:00 INFO Server started on port 8080"
GENERIC_FATAL_LINE = "2024-01-15 10:26:00 FATAL Out of memory — aborting"

JSON_LINE = (
    '{"timestamp": "2024-01-15T10:23:45.000Z", "level": "error", '
    '"message": "Failed to connect to Redis", "host": "app-server-1"}'
)

JSON_LINE_ALT_KEYS = (
    '{"ts": "2024-01-15T11:00:00", "severity": "WARNING", "msg": "Retry attempt 3"}'
)

BLANK_LINE       = "   "
COMMENT_LINE     = "# this is a comment"
UNPARSEABLE_LINE = "some random text without structure at all"


# ---------------------------------------------------------------------------
# parse_line — nginx
# ---------------------------------------------------------------------------

class TestParseLineNginx:

    def test_nginx_status_200_is_info(self):
        entry = parse_line(NGINX_LINE)
        assert entry is not None
        assert entry["level"] == "INFO"

    def test_nginx_status_500_is_error(self):
        entry = parse_line(NGINX_500_LINE)
        assert entry is not None
        assert entry["level"] == "ERROR"

    def test_nginx_has_timestamp(self):
        entry = parse_line(NGINX_LINE)
        assert isinstance(entry["timestamp"], datetime)
        assert entry["timestamp"].year == 2023
        assert entry["timestamp"].month == 10

    def test_nginx_message_contains_ip_and_status(self):
        entry = parse_line(NGINX_LINE)
        assert "192.168.1.10" in entry["message"]
        assert "200" in entry["message"]

    def test_nginx_raw_preserved(self):
        entry = parse_line(NGINX_LINE)
        assert entry["raw"] == NGINX_LINE


# ---------------------------------------------------------------------------
# parse_line — apache
# ---------------------------------------------------------------------------

class TestParseLineApache:

    def test_apache_200_is_info(self):
        entry = parse_line(APACHE_LINE)
        assert entry is not None
        assert entry["level"] == "INFO"

    def test_apache_404_is_warning(self):
        entry = parse_line(APACHE_404_LINE)
        assert entry is not None
        assert entry["level"] == "WARNING"

    def test_apache_has_timestamp(self):
        entry = parse_line(APACHE_LINE)
        assert isinstance(entry["timestamp"], datetime)

    def test_apache_message_contains_ip(self):
        entry = parse_line(APACHE_LINE)
        assert "127.0.0.1" in entry["message"]


# ---------------------------------------------------------------------------
# parse_line — JSON
# ---------------------------------------------------------------------------

class TestParseLineJSON:

    def test_json_level_parsed(self):
        entry = parse_line(JSON_LINE)
        assert entry is not None
        assert entry["level"] == "ERROR"

    def test_json_message_extracted(self):
        entry = parse_line(JSON_LINE)
        assert "Redis" in entry["message"]

    def test_json_timestamp_parsed(self):
        entry = parse_line(JSON_LINE)
        assert isinstance(entry["timestamp"], datetime)

    def test_json_alt_keys(self):
        entry = parse_line(JSON_LINE_ALT_KEYS)
        assert entry is not None
        assert entry["level"] == "WARNING"
        assert "Retry attempt 3" in entry["message"]


# ---------------------------------------------------------------------------
# parse_line — generic
# ---------------------------------------------------------------------------

class TestParseLineGeneric:

    def test_generic_error(self):
        entry = parse_line(GENERIC_ERROR_LINE)
        assert entry is not None
        assert entry["level"] == "ERROR"
        assert "Database" in entry["message"]

    def test_generic_warning_bracketed(self):
        entry = parse_line(GENERIC_WARN_LINE)
        assert entry is not None
        assert entry["level"] == "WARNING"

    def test_generic_info(self):
        entry = parse_line(GENERIC_INFO_LINE)
        assert entry is not None
        assert entry["level"] == "INFO"

    def test_generic_fatal_normalised_to_critical(self):
        entry = parse_line(GENERIC_FATAL_LINE)
        assert entry is not None
        assert entry["level"] == "CRITICAL"

    def test_generic_timestamp_parsed(self):
        entry = parse_line(GENERIC_ERROR_LINE)
        assert isinstance(entry["timestamp"], datetime)
        assert entry["timestamp"].year == 2024

    def test_generic_message_content(self):
        entry = parse_line(GENERIC_ERROR_LINE)
        assert "Database connection refused" in entry["message"]


# ---------------------------------------------------------------------------
# parse_line — edge cases
# ---------------------------------------------------------------------------

class TestParseLineEdgeCases:

    def test_blank_line_returns_none(self):
        assert parse_line(BLANK_LINE) is None

    def test_comment_line_returns_none(self):
        assert parse_line(COMMENT_LINE) is None

    def test_unparseable_returns_unknown(self):
        entry = parse_line(UNPARSEABLE_LINE)
        assert entry is not None
        assert entry["level"] == "UNKNOWN"
        assert entry["timestamp"] is None

    def test_empty_string_returns_none(self):
        assert parse_line("") is None


# ---------------------------------------------------------------------------
# detect_format
# ---------------------------------------------------------------------------

class TestDetectFormat:

    def test_detects_nginx(self):
        lines = [NGINX_LINE, NGINX_500_LINE]
        fmt = detect_format(lines)
        assert fmt == "nginx"

    def test_detects_apache(self):
        lines = [APACHE_LINE, APACHE_404_LINE]
        fmt = detect_format(lines)
        assert fmt in ("apache", "nginx")  # apache common is a subset of nginx combined

    def test_detects_json(self):
        lines = [JSON_LINE, JSON_LINE_ALT_KEYS]
        fmt = detect_format(lines)
        assert fmt == "json"

    def test_detects_generic(self):
        lines = [GENERIC_ERROR_LINE, GENERIC_INFO_LINE, GENERIC_WARN_LINE]
        fmt = detect_format(lines)
        assert fmt == "generic"

    def test_empty_sample_returns_generic(self):
        fmt = detect_format([])
        assert fmt == "generic"

    def test_only_blank_lines_returns_generic(self):
        fmt = detect_format(["", "   ", "\t"])
        assert fmt == "generic"


# ---------------------------------------------------------------------------
# parse_file (integration — uses tmp_path fixture)
# ---------------------------------------------------------------------------

class TestParseFile:

    def test_parse_file_returns_list(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text(
            "\n".join([GENERIC_ERROR_LINE, GENERIC_INFO_LINE, NGINX_LINE]) + "\n",
            encoding="utf-8",
        )
        entries = parse_file(log)
        assert isinstance(entries, list)
        assert len(entries) == 3

    def test_parse_file_skips_blanks(self, tmp_path):
        log = tmp_path / "sparse.log"
        log.write_text(
            f"{GENERIC_ERROR_LINE}\n\n\n{GENERIC_INFO_LINE}\n",
            encoding="utf-8",
        )
        entries = parse_file(log)
        assert len(entries) == 2

    def test_parse_file_all_have_raw_key(self, tmp_path):
        log = tmp_path / "raw.log"
        log.write_text(NGINX_LINE + "\n" + APACHE_LINE + "\n", encoding="utf-8")
        entries = parse_file(log)
        for e in entries:
            assert "raw" in e
            assert e["raw"]
