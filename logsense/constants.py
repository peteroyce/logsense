"""
Shared constants for logsense.
"""

from __future__ import annotations

# Log levels considered errors or warnings for stats and anomaly detection.
ERROR_LEVELS: frozenset[str] = frozenset({"ERROR", "CRITICAL", "FATAL", "WARNING", "WARN"})
