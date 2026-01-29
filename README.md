# LogSense

> Terminal-native log intelligence — parses any log format, clusters error patterns, detects anomalies, and fires Slack alerts. All from one command.

LogSense is a Python CLI that turns raw log files into actionable insight with zero configuration. Point it at a log file and get a Rich terminal dashboard: a breakdown of log levels, deduplicated error pattern clusters, time-window anomaly detection, and optional Slack notifications — all in one pass.

---

## Features

- **Auto-detects** nginx combined, Apache common, JSON, and generic `TIMESTAMP LEVEL MESSAGE` log formats
- **Clusters** similar error messages by replacing variable tokens (IPs, numbers, UUIDs, paths, hex IDs) with typed placeholders, then grouping by Jaccard similarity
- **Detects anomalies** using rolling time windows: flags windows where the error rate exceeds mean + 2σ as warning, mean + 3σ as critical
- **Slack alerts** via Incoming Webhooks — rich Block Kit messages with anomaly details
- **Rich terminal UI** — panels, colour-coded tables, live progress spinners

---

## Installation

Requires Python 3.11+.

```bash
# Clone and install in editable mode
git clone https://github.com/you/logsense.git
cd logsense
pip install -e .

# Or install with dev dependencies for running tests
pip install -e ".[dev]"
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your Slack webhook URL:

```bash
cp .env.example .env
```

```dotenv
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

The `SLACK_WEBHOOK_URL` environment variable is also read directly from the shell environment, so you can set it inline or via CI secrets without a `.env` file.

---

## Usage

### Full analysis

```bash
logsense analyse /var/log/nginx/access.log
```

```bash
# Force a specific format
logsense analyse app.log --format json

# Custom anomaly detection window (default: 5 minutes)
logsense analyse app.log --window-minutes 15

# Pass Slack webhook inline
logsense analyse app.log --slack-webhook https://hooks.slack.com/services/…

# All options together
logsense analyse /var/log/app.log \
  --format generic \
  --window-minutes 10 \
  --slack-webhook "$SLACK_WEBHOOK_URL"
```

The `analyse` command outputs:

1. **Summary panel** — file path, detected format, total entries, error count/rate, time range, anomaly count
2. **Log level breakdown table** — count and share per level (DEBUG/INFO/WARNING/ERROR/CRITICAL)
3. **Top error patterns table** — up to 15 deduplicated templates with occurrence count and time range
4. **Anomalies table** — each flagged time window with total entries, error count, error rate, z-score, and severity
5. **Slack alert** (if a webhook URL is configured and anomalies were found)

### Quick stats

```bash
logsense stats /var/log/nginx/error.log
```

Outputs four stat panels — total lines, error/warning count, error rate, detected format — plus the time range, in under a second.

---

## Supported log formats

| Format        | Example line |
|---------------|--------------|
| **nginx combined** | `10.0.0.1 - - [15/Jan/2024:08:00:01 +0000] "GET / HTTP/1.1" 200 1024 "-" "curl/7.88"` |
| **Apache common**  | `127.0.0.1 - bob [10/Oct/2023:13:55:36 +0000] "GET /index HTTP/1.0" 200 2326` |
| **JSON**           | `{"timestamp":"2024-01-15T10:23:45Z","level":"error","message":"DB timeout"}` |
| **Generic**        | `2024-01-15 10:23:45 ERROR Database connection refused at 127.0.0.1:5432` |
|                    | `2024-01-15T10:24:00.123Z [WARNING] Disk usage above 80%` |

Format auto-detection samples the first 40 lines and scores them against each pattern. Pass `--format` to override.

---

## How anomaly detection works

1. All timestamped entries are bucketed into fixed-size windows (default 5 minutes).
2. For each window, the **error rate** = (error + warning entries) / (total entries) is computed.
3. The mean (μ) and population standard deviation (σ) of error rates across all windows are calculated.
4. Windows with `rate > μ + 2σ` are flagged as **warning**; `rate > μ + 3σ` as **critical**.

Windows with fewer than 2 entries are ignored to avoid noise from sparse logs.

---

## How error clustering works

Each error message is normalised into a **template** by:
- Replacing IPv4/IPv6 addresses with `<IP>`
- Replacing UUIDs with `<UUID>`
- Replacing long hex strings with `<HEX>`
- Replacing URLs with `<URL>`
- Replacing file/URL paths with `<PATH>`
- Replacing quoted strings with `<STR>`
- Replacing numbers (with optional units) with `<NUM>`

Templates that share ≥ 72% Jaccard token similarity are then merged into a single cluster. The result is a ranked list of error patterns with occurrence count, first/last seen timestamps, and representative raw lines.

---

## Running tests

```bash
pytest
# With coverage
pytest --cov=logsense --cov-report=term-missing
```

---

## Tech stack

| Library | Purpose |
|---------|---------|
| [Click](https://click.palletsprojects.com/) | CLI framework |
| [Rich](https://rich.readthedocs.io/) | Terminal UI (tables, panels, spinners) |
| [httpx](https://www.python-httpx.org/) | Async-capable HTTP client for Slack webhooks |
| [python-dotenv](https://saurabh-kumar.com/python-dotenv/) | `.env` file loading |
| [pytest](https://pytest.org/) | Test runner |

---

## Project layout

```
logsense/
├── logsense/
│   ├── __init__.py      # version
│   ├── parser.py        # log format parsing
│   ├── clustering.py    # error pattern clustering
│   ├── anomaly.py       # rolling-window anomaly detection
│   ├── alerts.py        # Slack webhook alerting
│   └── cli.py           # Click CLI + Rich dashboard
├── tests/
│   ├── test_parser.py
│   └── test_clustering.py
├── .env.example
├── .gitignore
├── pyproject.toml
└── README.md
```

---

## License

MIT
