"""
Tests for logsense.alerts — send_slack_alert.

Strategy
--------
- httpx.post is mocked in every test; the real network is never hit.
- We test three distinct return values:
    NO_WEBHOOK  — no webhook URL provided (silent skip)
    True        — webhook present AND HTTP 200 "ok" received
    False       — webhook present BUT request failed / bad status
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from logsense.alerts import send_slack_alert, NO_WEBHOOK


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_anomaly(severity: str = "warning") -> dict:
    now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    return {
        "window_start": now,
        "window_end": now,
        "total_count": 10,
        "error_count": 8,
        "error_rate": 0.8,
        "severity": severity,
        "z_score": 3.5,
    }


SUMMARY = {
    "file_path": "/var/log/app.log",
    "total_lines": 1000,
    "error_count": 42,
    "error_rate": 0.042,
    "format": "generic",
    "top_pattern": "database connection refused",
}

WEBHOOK = "https://hooks.slack.com/services/T000/B000/xxxx"


# ---------------------------------------------------------------------------
# No webhook configured — must return NO_WEBHOOK sentinel, never call httpx
# ---------------------------------------------------------------------------

class TestNoWebhook:

    def test_empty_string_returns_no_webhook_sentinel(self):
        with patch("httpx.post") as mock_post:
            result = send_slack_alert("", [_make_anomaly()], SUMMARY)
        assert result is NO_WEBHOOK
        mock_post.assert_not_called()

    def test_none_treated_as_empty_returns_no_webhook(self):
        # None is falsy, so it should behave identically to ""
        with patch("httpx.post") as mock_post:
            result = send_slack_alert(None, [_make_anomaly()], SUMMARY)  # type: ignore[arg-type]
        assert result is NO_WEBHOOK
        mock_post.assert_not_called()

    def test_no_webhook_is_not_false(self):
        """NO_WEBHOOK must not be equal to False so callers can distinguish them."""
        assert NO_WEBHOOK is not False
        assert NO_WEBHOOK is not True


# ---------------------------------------------------------------------------
# Success path — webhook configured, HTTP 200 "ok"
# ---------------------------------------------------------------------------

class TestSuccessPath:

    def _mock_ok_response(self) -> MagicMock:
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        return resp

    def test_returns_true_on_200_ok(self):
        with patch("httpx.post", return_value=self._mock_ok_response()):
            result = send_slack_alert(WEBHOOK, [_make_anomaly()], SUMMARY)
        assert result is True

    def test_post_called_once(self):
        with patch("httpx.post", return_value=self._mock_ok_response()) as mock_post:
            send_slack_alert(WEBHOOK, [_make_anomaly()], SUMMARY)
        mock_post.assert_called_once()

    def test_post_called_with_correct_url(self):
        with patch("httpx.post", return_value=self._mock_ok_response()) as mock_post:
            send_slack_alert(WEBHOOK, [_make_anomaly()], SUMMARY)
        args, kwargs = mock_post.call_args
        assert args[0] == WEBHOOK

    def test_post_sends_json_content_type(self):
        with patch("httpx.post", return_value=self._mock_ok_response()) as mock_post:
            send_slack_alert(WEBHOOK, [_make_anomaly()], SUMMARY)
        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Content-Type"] == "application/json"

    def test_empty_anomalies_returns_true_without_posting(self):
        """No anomalies → skip the HTTP request but still return True."""
        with patch("httpx.post") as mock_post:
            result = send_slack_alert(WEBHOOK, [], SUMMARY)
        assert result is True
        mock_post.assert_not_called()

    def test_multiple_anomalies_sent_in_one_call(self):
        anomalies = [_make_anomaly("warning"), _make_anomaly("critical")]
        with patch("httpx.post", return_value=self._mock_ok_response()) as mock_post:
            result = send_slack_alert(WEBHOOK, anomalies, SUMMARY)
        assert result is True
        mock_post.assert_called_once()


# ---------------------------------------------------------------------------
# Failure path — webhook configured but request failed / non-200
# ---------------------------------------------------------------------------

class TestFailurePath:

    def test_non_200_status_returns_false(self):
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "Internal Server Error"
        with patch("httpx.post", return_value=resp):
            result = send_slack_alert(WEBHOOK, [_make_anomaly()], SUMMARY)
        assert result is False

    def test_200_but_wrong_body_returns_false(self):
        """Slack returns 200 but body is not 'ok' (misconfigured webhook)."""
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "no_service"
        with patch("httpx.post", return_value=resp):
            result = send_slack_alert(WEBHOOK, [_make_anomaly()], SUMMARY)
        assert result is False

    def test_timeout_exception_returns_false(self):
        import httpx as _httpx
        with patch("httpx.post", side_effect=_httpx.TimeoutException("timed out")):
            result = send_slack_alert(WEBHOOK, [_make_anomaly()], SUMMARY)
        assert result is False

    def test_request_error_returns_false(self):
        import httpx as _httpx
        with patch("httpx.post", side_effect=_httpx.RequestError("connection refused")):
            result = send_slack_alert(WEBHOOK, [_make_anomaly()], SUMMARY)
        assert result is False

    def test_404_status_returns_false(self):
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "Not Found"
        with patch("httpx.post", return_value=resp):
            result = send_slack_alert(WEBHOOK, [_make_anomaly()], SUMMARY)
        assert result is False

    def test_failure_is_not_no_webhook(self):
        """False (failure) must be distinguishable from NO_WEBHOOK (unconfigured)."""
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "error"
        with patch("httpx.post", return_value=resp):
            result = send_slack_alert(WEBHOOK, [_make_anomaly()], SUMMARY)
        assert result is not NO_WEBHOOK
        assert result is False
