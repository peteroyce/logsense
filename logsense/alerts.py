"""
Slack webhook alerting via httpx.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# Sentinel object returned by send_slack_alert when no webhook URL is configured.
# Callers can distinguish "not configured" (NO_WEBHOOK) from "configured but
# failed" (False) and "succeeded" (True).
NO_WEBHOOK = object()

_SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "warning": ":large_yellow_circle:",
}

_SEVERITY_COLOR = {
    "critical": "#E53E3E",
    "warning": "#D69E2E",
}


def _format_dt(dt: Optional[datetime]) -> str:
    if dt is None:
        return "unknown"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _build_payload(anomalies: list[dict], summary: dict) -> dict:
    """
    Build the Slack Block Kit / attachment payload.

    *summary* is expected to have keys:
      file_path, total_lines, error_count, error_rate, format, top_pattern
    """
    file_path = summary.get("file_path", "unknown file")
    total_lines = summary.get("total_lines", 0)
    error_count = summary.get("error_count", 0)
    error_rate = summary.get("error_rate", 0.0)
    top_pattern = summary.get("top_pattern", "")

    # Determine overall severity
    severities = [a["severity"] for a in anomalies]
    overall_severity = "critical" if "critical" in severities else "warning"
    emoji = _SEVERITY_EMOJI[overall_severity]
    color = _SEVERITY_COLOR[overall_severity]

    header_text = f"{emoji} *LogSense Anomaly Alert* — `{file_path}`"

    meta_fields = [
        {"type": "mrkdwn", "text": f"*Total lines analysed*\n{total_lines:,}"},
        {"type": "mrkdwn", "text": f"*Errors found*\n{error_count:,} ({error_rate:.1%})"},
        {"type": "mrkdwn", "text": f"*Anomalous windows*\n{len(anomalies)}"},
        {"type": "mrkdwn", "text": f"*Overall severity*\n{overall_severity.upper()}"},
    ]

    blocks: list[dict] = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": header_text},
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": meta_fields,
        },
    ]

    if top_pattern:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Top error pattern:*\n```{top_pattern[:200]}```",
                },
            }
        )

    blocks.append({"type": "divider"})
    blocks.append(
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Anomalous time windows:*"},
        }
    )

    for idx, anomaly in enumerate(anomalies[:10], start=1):
        sev = anomaly["severity"]
        sev_emoji = _SEVERITY_EMOJI[sev]
        window_text = (
            f"{sev_emoji} *Window {idx}* — {sev.upper()}\n"
            f"  • Start: `{_format_dt(anomaly['window_start'])}`\n"
            f"  • End:   `{_format_dt(anomaly['window_end'])}`\n"
            f"  • Errors: {anomaly['error_count']} / {anomaly['total_count']} "
            f"({anomaly['error_rate']:.1%} — z={anomaly['z_score']:.1f}σ)"
        )
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": window_text},
            }
        )

    if len(anomalies) > 10:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"_... and {len(anomalies) - 10} more anomalous windows._",
                    }
                ],
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "_Sent by LogSense — terminal-native log intelligence_",
                }
            ],
        }
    )

    return {
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
                "fallback": (
                    f"LogSense alert: {len(anomalies)} anomalous window(s) detected "
                    f"in {file_path}. Overall severity: {overall_severity}."
                ),
            }
        ]
    }


def send_slack_alert(
    webhook_url: str,
    anomalies: list[dict],
    summary: dict,
    *,
    timeout: float = 10.0,
) -> object:
    """
    Send a formatted Slack alert for *anomalies*.

    Parameters
    ----------
    webhook_url:
        Slack Incoming Webhook URL.
    anomalies:
        List of anomaly dicts as returned by ``anomaly.detect_anomalies``.
    summary:
        Dict with aggregate statistics (see ``_build_payload`` for expected keys).
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    NO_WEBHOOK
        The module-level sentinel when *webhook_url* is empty/None — the caller
        should silently skip (no warning needed; the webhook was never set up).
    True
        Message delivered successfully (HTTP 200 "ok").
    False
        Webhook is configured but the request failed (network error, bad status,
        timeout) — the caller should warn the user.
    """
    if not webhook_url:
        logger.debug("send_slack_alert called with empty webhook_url — skipping silently")
        return NO_WEBHOOK

    if not anomalies:
        logger.debug("No anomalies to report — skipping Slack alert")
        return True

    payload = _build_payload(anomalies, summary)

    try:
        response = httpx.post(
            webhook_url,
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        if response.status_code == 200 and response.text == "ok":
            logger.info("Slack alert sent successfully")
            return True
        else:
            logger.error(
                "Slack webhook returned unexpected response: %s — %s",
                response.status_code,
                response.text[:200],
            )
            return False
    except httpx.TimeoutException:
        logger.error("Slack webhook request timed out after %.1fs", timeout)
        return False
    except httpx.RequestError as exc:
        logger.error("Slack webhook request failed: %s", exc)
        return False


def validate_0(data):
    """Validate: add data validation"""
    return data is not None


def validate_12(data):
    """Validate: add schema validation"""
    return data is not None
