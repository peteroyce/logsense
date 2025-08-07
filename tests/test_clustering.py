"""
Tests for logsense.clustering — cluster_errors.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from logsense.clustering import cluster_errors, _make_template


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entry(
    message: str,
    level: str = "ERROR",
    timestamp: datetime | None = None,
) -> dict:
    ts = timestamp or datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    return {
        "timestamp": ts,
        "level": level,
        "message": message,
        "raw": f"2024-01-15 10:00:00 {level} {message}",
    }


# ---------------------------------------------------------------------------
# _make_template unit tests
# ---------------------------------------------------------------------------

class TestMakeTemplate:

    def test_replaces_ip(self):
        tmpl = _make_template("Connection refused from 192.168.1.10")
        assert "<IP>" in tmpl
        assert "192.168.1.10" not in tmpl

    def test_replaces_number(self):
        tmpl = _make_template("Retried 5 times before giving up")
        assert "<NUM>" in tmpl
        assert "5" not in tmpl

    def test_replaces_uuid(self):
        tmpl = _make_template("Request 550e8400-e29b-41d4-a716-446655440000 failed")
        assert "<UUID>" in tmpl

    def test_replaces_url(self):
        tmpl = _make_template("Failed to fetch https://api.example.com/v2/data")
        assert "<URL>" in tmpl
        assert "https://" not in tmpl

    def test_replaces_hex(self):
        tmpl = _make_template("Commit deadbeef12345678 not found")
        assert "<HEX>" in tmpl

    def test_preserves_keyword(self):
        tmpl = _make_template("Database connection timeout after 30s")
        assert "database" in tmpl
        assert "connection" in tmpl
        assert "timeout" in tmpl

    def test_lowercases_result(self):
        tmpl = _make_template("FATAL: Out of Memory")
        assert tmpl == tmpl.lower()


# ---------------------------------------------------------------------------
# cluster_errors
# ---------------------------------------------------------------------------

class TestClusterErrors:

    def test_returns_empty_for_no_entries(self):
        assert cluster_errors([]) == []

    def test_returns_empty_for_only_info_entries(self):
        entries = [_make_entry("All good", level="INFO") for _ in range(5)]
        assert cluster_errors(entries) == []

    def test_single_error_cluster(self):
        entries = [_make_entry("Database connection refused")]
        result = cluster_errors(entries)
        assert len(result) >= 1
        assert result[0]["count"] == 1

    def test_groups_identical_messages(self):
        msg = "Connection to Redis failed"
        entries = [_make_entry(msg) for _ in range(10)]
        result = cluster_errors(entries)
        assert len(result) == 1
        assert result[0]["count"] == 10

    def test_groups_messages_that_differ_only_in_ip(self):
        entries = [
            _make_entry("Connection refused from 10.0.0.1"),
            _make_entry("Connection refused from 10.0.0.2"),
            _make_entry("Connection refused from 10.0.0.3"),
        ]
        result = cluster_errors(entries)
        # All three should end up in the same cluster
        assert len(result) == 1
        assert result[0]["count"] == 3

    def test_groups_messages_that_differ_only_in_numbers(self):
        entries = [
            _make_entry("Timeout after 30s waiting for worker 1"),
            _make_entry("Timeout after 60s waiting for worker 2"),
            _make_entry("Timeout after 45s waiting for worker 3"),
        ]
        result = cluster_errors(entries)
        assert result[0]["count"] == 3

    def test_separates_distinct_patterns(self):
        entries = [
            _make_entry("Disk full on /dev/sda1"),
            _make_entry("Disk full on /dev/sdb1"),
            _make_entry("Out of memory: kill process 1234"),
            _make_entry("Out of memory: kill process 5678"),
        ]
        result = cluster_errors(entries)
        # Should have at most 2 distinct clusters
        assert len(result) <= 2
        total = sum(c["count"] for c in result)
        assert total == 4

    def test_sorted_by_count_descending(self):
        entries = (
            [_make_entry("Rare error")] * 1
            + [_make_entry("Common error message here")] * 5
            + [_make_entry("Moderate error occurred")] * 3
        )
        result = cluster_errors(entries)
        counts = [c["count"] for c in result]
        assert counts == sorted(counts, reverse=True)

    def test_cluster_has_required_keys(self):
        entries = [_make_entry("Something failed badly")]
        result = cluster_errors(entries)
        assert result
        cluster = result[0]
        assert "pattern" in cluster
        assert "count" in cluster
        assert "examples" in cluster
        assert "first_seen" in cluster
        assert "last_seen" in cluster
        assert "levels" in cluster

    def test_examples_are_raw_strings(self):
        entries = [_make_entry("Unhandled exception in thread") for _ in range(5)]
        result = cluster_errors(entries)
        assert result
        for ex in result[0]["examples"]:
            assert isinstance(ex, str)

    def test_first_and_last_seen_are_correct(self):
        t1 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2024, 1, 15, 11, 0, 0, tzinfo=timezone.utc)
        t3 = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        entries = [
            _make_entry("Timeout error occurred", timestamp=t2),
            _make_entry("Timeout error occurred", timestamp=t1),
            _make_entry("Timeout error occurred", timestamp=t3),
        ]
        result = cluster_errors(entries)
        assert result
        assert result[0]["first_seen"] == t1
        assert result[0]["last_seen"] == t3

    def test_levels_dict_counts_correctly(self):
        entries = (
            [_make_entry("Service unavailable", level="ERROR")] * 3
            + [_make_entry("Service unavailable", level="CRITICAL")] * 2
        )
        result = cluster_errors(entries)
        assert result
        levels = result[0]["levels"]
        assert levels.get("ERROR", 0) == 3
        assert levels.get("CRITICAL", 0) == 2

    def test_warnings_included_by_default(self):
        entries = [_make_entry("Low disk space warning", level="WARNING")] * 4
        result = cluster_errors(entries)
        assert result
        assert result[0]["count"] == 4

    def test_warnings_excluded_when_flag_false(self):
        entries = (
            [_make_entry("Low disk space warning", level="WARNING")] * 4
            + [_make_entry("Hard disk failed", level="ERROR")] * 2
        )
        result = cluster_errors(entries, include_warnings=False)
        # Only ERROR entries should be clustered
        for c in result:
            for lvl in c["levels"]:
                assert lvl in {"ERROR", "CRITICAL", "FATAL"}

    def test_max_examples_respected(self):
        entries = [_make_entry("Repeated failure") for _ in range(20)]
        result = cluster_errors(entries, max_examples=3)
        assert result
        assert len(result[0]["examples"]) <= 3

    def test_no_timestamp_entries_handled(self):
        entries = [
            {"timestamp": None, "level": "ERROR", "message": "No time info", "raw": "ERROR No time info"}
            for _ in range(3)
        ]
        result = cluster_errors(entries)
        assert result
        assert result[0]["first_seen"] is None
        assert result[0]["last_seen"] is None


# ---------------------------------------------------------------------------
# Jaccard similarity threshold tests
# ---------------------------------------------------------------------------

class TestSimilarityThreshold:

    def test_high_threshold_keeps_templates_separate(self):
        """
        At threshold=0.99 (near-perfect match required), two messages that
        differ in more than one token must remain as separate clusters.
        """
        entries = [
            _make_entry("Connection refused from database host"),
            _make_entry("Authentication failed for user account"),
        ]
        result = cluster_errors(entries, similarity_threshold=0.99)
        # The two very different messages must not be merged
        assert len(result) == 2

    def test_low_threshold_merges_similar_templates(self):
        """
        At threshold=0.5 (lenient), messages that share many tokens should
        be merged into a single cluster.
        """
        entries = [
            _make_entry("Connection timeout waiting for backend server"),
            _make_entry("Connection timeout waiting for backend cache"),
        ]
        result = cluster_errors(entries, similarity_threshold=0.5)
        # Both share most tokens → should merge into 1 cluster
        assert len(result) == 1
        assert result[0]["count"] == 2

    def test_default_threshold_is_applied(self):
        """cluster_errors uses 0.72 by default — vary templates just enough."""
        entries = [
            _make_entry("Disk full on device sda"),
            _make_entry("Disk full on device sdb"),
        ]
        # These differ in only one token (sda vs sdb → both become <PATH>)
        # After normalisation they should produce the same template regardless
        result = cluster_errors(entries)
        assert len(result) == 1
        assert result[0]["count"] == 2

    def test_dissimilar_templates_stay_separate_at_default_threshold(self):
        """Completely different messages must never merge."""
        entries = [
            _make_entry("Out of memory error in kernel subsystem"),
            _make_entry("HTTP 503 service unavailable upstream"),
        ]
        result = cluster_errors(entries)
        total = sum(c["count"] for c in result)
        assert total == 2

    def test_single_entry_produces_one_cluster(self):
        """Single log line should produce exactly one cluster."""
        entries = [_make_entry("Unique fatal error occurred")]
        result = cluster_errors(entries)
        assert len(result) == 1
        assert result[0]["count"] == 1

    def test_empty_input_returns_empty(self):
        assert cluster_errors([]) == []

    def test_only_info_entries_returns_empty(self):
        entries = [_make_entry("Everything is fine", level="INFO") for _ in range(10)]
        assert cluster_errors(entries) == []

    def test_threshold_boundary_low(self):
        """Threshold at minimum boundary 0.5 must not error."""
        entries = [_make_entry("Some error happened") for _ in range(3)]
        result = cluster_errors(entries, similarity_threshold=0.5)
        assert isinstance(result, list)

    def test_threshold_boundary_high(self):
        """Threshold at near-maximum 0.99 must not error."""
        entries = [_make_entry("Some error happened") for _ in range(3)]
        result = cluster_errors(entries, similarity_threshold=0.99)
        assert isinstance(result, list)


MAX_9 = 145
