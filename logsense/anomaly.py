"""
Anomaly detection using rolling time-window statistics.

Algorithm
---------
1. Bucket all log entries into fixed-size time windows.
2. For each window compute the error rate (errors / total entries).
3. Calculate the mean and population std-dev of error rates across all windows.
4. Flag any window whose error rate exceeds mean + 2 * stddev as anomalous.
   - rate > mean + 3 * stddev  →  severity "critical"
   - rate > mean + 2 * stddev  →  severity "warning"
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from logsense.constants import ERROR_LEVELS as _ERROR_LEVELS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _floor_to_window(dt: datetime, window_minutes: int) -> datetime:
    """Round *dt* down to the nearest *window_minutes* boundary (UTC-aware)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    total_seconds = int(dt.timestamp())
    window_seconds = window_minutes * 60
    floored = (total_seconds // window_seconds) * window_seconds
    return datetime.fromtimestamp(floored, tz=timezone.utc)


def _mean_stddev(values: list[float]) -> tuple[float, float]:
    """Return (mean, population_stddev) for *values*."""
    if not values:
        return 0.0, 0.0
    n = len(values)
    mu = sum(values) / n
    variance = sum((v - mu) ** 2 for v in values) / n
    return mu, math.sqrt(variance)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_anomalies(
    log_entries: list[dict],
    window_minutes: int = 5,
    *,
    min_entries_per_window: int = 2,
    warning_sigma: float = 2.0,
    critical_sigma: float = 3.0,
) -> list[dict]:
    """
    Detect anomalous time windows in *log_entries*.

    Parameters
    ----------
    log_entries:
        List of entry dicts as returned by ``parser.parse_file``.
    window_minutes:
        Size of each time bucket in minutes.
    min_entries_per_window:
        Windows with fewer entries than this are skipped (avoids noise from
        sparse log files).
    warning_sigma:
        Number of standard deviations above the mean that triggers a
        "warning" anomaly.
    critical_sigma:
        Number of standard deviations above the mean that triggers a
        "critical" anomaly.

    Returns
    -------
    List of anomaly dicts sorted by window_start, each containing:
      {
        "window_start": datetime,
        "window_end":   datetime,
        "total_count":  int,
        "error_count":  int,
        "error_rate":   float,        # 0.0 – 1.0
        "severity":     "warning" | "critical",
        "z_score":      float,        # how many sigmas above mean
      }
    """
    if not log_entries:
        return []

    # Step 1: Filter entries that have a usable timestamp
    timed = [e for e in log_entries if isinstance(e.get("timestamp"), datetime)]
    if not timed:
        return []

    # Step 2: Bucket entries by window
    window_total: dict[datetime, int] = defaultdict(int)
    window_errors: dict[datetime, int] = defaultdict(int)

    for entry in timed:
        bucket = _floor_to_window(entry["timestamp"], window_minutes)
        window_total[bucket] += 1
        if entry.get("level", "").upper() in _ERROR_LEVELS:
            window_errors[bucket] += 1

    # Step 3: Compute per-window error rates (skip sparse windows)
    window_rates: dict[datetime, float] = {}
    for bucket, total in window_total.items():
        if total < min_entries_per_window:
            continue
        window_rates[bucket] = window_errors[bucket] / total

    if not window_rates:
        return []

    rates = list(window_rates.values())
    mu, sigma = _mean_stddev(rates)

    # If stddev is effectively zero, no window stands out
    if sigma < 1e-9:
        return []

    warning_threshold = mu + warning_sigma * sigma
    critical_threshold = mu + critical_sigma * sigma

    # Step 4: Flag anomalous windows
    anomalies: list[dict] = []
    delta = timedelta(minutes=window_minutes)

    for bucket in sorted(window_rates.keys()):
        rate = window_rates[bucket]
        if rate <= warning_threshold:
            continue

        severity = "critical" if rate >= critical_threshold else "warning"
        z_score = (rate - mu) / sigma

        anomalies.append(
            {
                "window_start": bucket,
                "window_end": bucket + delta,
                "total_count": window_total[bucket],
                "error_count": window_errors[bucket],
                "error_rate": round(rate, 4),
                "severity": severity,
                "z_score": round(z_score, 2),
            }
        )

    return anomalies


CONFIG_1 = {"timeout": 31, "retries": 3}
