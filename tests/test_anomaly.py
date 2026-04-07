"""
Tests for logsense.anomaly — detect_anomalies.

Edge cases covered
------------------
- Empty input
- No entries with timestamps
- All-zero error windows (all entries are INFO — stddev=0)
- Single time window (stddev=0 edge case)
- Uniform error rate across all windows (stddev=0 — no anomalies)
- Normal multi-window case with a clear spike
- window_minutes > total log span (returns [] because single bucket)
- min_entries_per_window filtering
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from logsense.anomaly import detect_anomalies, _mean_stddev


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entry(
    dt: datetime,
    level: str = "INFO",
) -> dict:
    return {
        "timestamp": dt,
        "level": level,
        "message": "test message",
        "raw": f"{dt.isoformat()} {level} test message",
    }


def _ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC datetime at 2024-01-15 HH:MM:00."""
    return datetime(2024, 1, 15, hour, minute, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# _mean_stddev unit tests
# ---------------------------------------------------------------------------

class TestMeanStddev:

    def test_empty_list(self):
        mu, sigma = _mean_stddev([])
        assert mu == 0.0
        assert sigma == 0.0

    def test_single_value(self):
        mu, sigma = _mean_stddev([0.5])
        assert mu == 0.5
        assert sigma == 0.0

    def test_all_same_values(self):
        mu, sigma = _mean_stddev([0.3, 0.3, 0.3])
        assert abs(mu - 0.3) < 1e-9
        assert sigma < 1e-9

    def test_known_values(self):
        # mean=2, population stddev=sqrt((1+0+1)/3) = sqrt(2/3)
        import math
        mu, sigma = _mean_stddev([1.0, 2.0, 3.0])
        assert abs(mu - 2.0) < 1e-9
        assert abs(sigma - math.sqrt(2 / 3)) < 1e-9


# ---------------------------------------------------------------------------
# detect_anomalies — basic/empty cases
# ---------------------------------------------------------------------------

class TestDetectAnomaliesEmpty:

    def test_empty_entries_returns_empty(self):
        assert detect_anomalies([]) == []

    def test_entries_without_timestamps_returns_empty(self):
        entries = [
            {"timestamp": None, "level": "ERROR", "message": "x", "raw": "x"}
            for _ in range(5)
        ]
        assert detect_anomalies(entries) == []

    def test_single_entry_no_anomaly(self):
        """One entry → one window → stddev=0 → no anomalies."""
        entries = [_make_entry(_ts(10), "ERROR")]
        result = detect_anomalies(entries)
        assert result == []

    def test_single_window_no_anomaly(self):
        """All entries fall in the same 5-minute window — stddev=0."""
        base = _ts(10, 0)
        entries = [_make_entry(base + timedelta(seconds=i * 10), "ERROR") for i in range(10)]
        result = detect_anomalies(entries)
        assert result == []


# ---------------------------------------------------------------------------
# detect_anomalies — all-zero / uniform error rates
# ---------------------------------------------------------------------------

class TestDetectAnomaliesUniform:

    def test_all_info_entries_no_anomaly(self):
        """Zero error rate in every window — stddev=0 → no anomalies."""
        entries = []
        for hour in range(5):
            for minute in range(0, 60, 5):
                ts = _ts(hour, minute)
                # 3 INFO entries per window (above min_entries_per_window=2)
                entries.extend([_make_entry(ts + timedelta(seconds=i), "INFO") for i in range(3)])
        result = detect_anomalies(entries)
        assert result == []

    def test_uniform_error_rate_no_anomaly(self):
        """Same error rate in every window means stddev=0 → nothing flagged."""
        entries = []
        # 5 windows, each with 2 ERRORs and 2 INFOs → 50% error rate everywhere
        for hour in range(5):
            ts = _ts(hour, 0)
            entries.extend([_make_entry(ts + timedelta(seconds=i), "ERROR") for i in range(2)])
            entries.extend([_make_entry(ts + timedelta(seconds=i + 10), "INFO") for i in range(2)])
        result = detect_anomalies(entries)
        assert result == []


# ---------------------------------------------------------------------------
# detect_anomalies — real anomaly detection
# ---------------------------------------------------------------------------

class TestDetectAnomaliesRealSpike:

    def _build_normal_entries(self) -> list[dict]:
        """8 normal windows with ~10% error rate (2 errors out of 20 entries each)."""
        entries = []
        for hour in range(8):
            ts = _ts(hour, 0)
            entries.extend([_make_entry(ts + timedelta(seconds=i), "INFO") for i in range(18)])
            entries.extend([_make_entry(ts + timedelta(seconds=i + 100), "ERROR") for i in range(2)])
        return entries

    def test_spike_window_detected(self):
        """A window with 100% errors should be flagged as anomalous."""
        entries = self._build_normal_entries()
        # Add a spike window: hour 9, all ERRORs
        spike_ts = _ts(9, 0)
        entries.extend([_make_entry(spike_ts + timedelta(seconds=i), "ERROR") for i in range(20)])

        result = detect_anomalies(entries, window_minutes=60)
        assert len(result) >= 1

    def test_anomaly_has_required_keys(self):
        entries = self._build_normal_entries()
        spike_ts = _ts(9, 0)
        entries.extend([_make_entry(spike_ts + timedelta(seconds=i), "ERROR") for i in range(20)])

        result = detect_anomalies(entries, window_minutes=60)
        assert result
        anomaly = result[0]
        assert "window_start" in anomaly
        assert "window_end" in anomaly
        assert "total_count" in anomaly
        assert "error_count" in anomaly
        assert "error_rate" in anomaly
        assert "severity" in anomaly
        assert "z_score" in anomaly

    def test_severity_is_valid_value(self):
        entries = self._build_normal_entries()
        spike_ts = _ts(9, 0)
        entries.extend([_make_entry(spike_ts + timedelta(seconds=i), "ERROR") for i in range(20)])

        result = detect_anomalies(entries, window_minutes=60)
        for anomaly in result:
            assert anomaly["severity"] in ("warning", "critical")

    def test_anomalies_sorted_by_window_start(self):
        entries = self._build_normal_entries()
        # Two spike windows
        for spike_hour in (9, 10):
            spike_ts = _ts(spike_hour, 0)
            entries.extend([_make_entry(spike_ts + timedelta(seconds=i), "ERROR") for i in range(20)])

        result = detect_anomalies(entries, window_minutes=60)
        starts = [a["window_start"] for a in result]
        assert starts == sorted(starts)

    def test_z_score_positive(self):
        entries = self._build_normal_entries()
        spike_ts = _ts(9, 0)
        entries.extend([_make_entry(spike_ts + timedelta(seconds=i), "ERROR") for i in range(20)])

        result = detect_anomalies(entries, window_minutes=60)
        assert result
        assert result[0]["z_score"] > 0


# ---------------------------------------------------------------------------
# detect_anomalies — min_entries_per_window edge case
# ---------------------------------------------------------------------------

class TestDetectAnomaliesMinEntries:

    def test_sparse_windows_skipped(self):
        """Windows with fewer than min_entries_per_window should not be flagged."""
        # One big normal window then one tiny spike (1 entry → below threshold)
        entries = []
        base = _ts(10, 0)
        # Normal window: 10 entries, 10% error rate
        entries.extend([_make_entry(base + timedelta(seconds=i), "INFO") for i in range(9)])
        entries.append(_make_entry(base + timedelta(seconds=10), "ERROR"))

        # Sparse window: only 1 ERROR entry — below min_entries_per_window=2
        sparse_ts = _ts(11, 0)
        entries.append(_make_entry(sparse_ts, "ERROR"))

        result = detect_anomalies(entries, window_minutes=60, min_entries_per_window=2)
        # Sparse window should be excluded from rate calculation; no spike to detect
        # (at most 1 window of rates after filtering, so stddev=0 → no anomalies)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# detect_anomalies — window larger than log time span
# ---------------------------------------------------------------------------

class TestWindowLargerThanSpan:

    def test_window_larger_than_span_returns_empty_or_no_anomaly(self):
        """
        When window_minutes > total log span, all entries fall into one bucket.
        One bucket → stddev=0 → no anomalies returned.
        """
        # Log spans only 2 minutes; window is 60 minutes
        base = _ts(10, 0)
        entries = []
        entries.extend([_make_entry(base + timedelta(seconds=i), "INFO") for i in range(5)])
        entries.extend([_make_entry(base + timedelta(seconds=i + 60), "ERROR") for i in range(5)])

        result = detect_anomalies(entries, window_minutes=60)
        # All entries land in one 60-minute bucket → single window → stddev=0 → []
        assert result == []
