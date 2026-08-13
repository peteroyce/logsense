# LogSense

> Terminal-native log intelligence — parses any log format, clusters error patterns, detects anomalies, and fires Slack alerts. All from one command.

LogSense is a Python CLI that turns raw log files into actionable insight with zero configuration.
Point it at a log file and get a Rich terminal dashboard: a breakdown of log levels, deduplicated
error pattern clusters, time-window anomaly detection, and optional Slack notifications — all in one pass.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- Parses nginx combined, Apache common, JSON, and generic `TIMESTAMP LEVEL MESSAGE` lines, deciding
  per line rather than per file, so mixed-format and interleaved logs still parse
- Never drops a line: anything that matches no pattern is kept with `level="UNKNOWN"` and its raw text,
  so counts stay honest instead of silently shrinking
- Maps HTTP status codes to levels for access logs (4xx becomes `WARNING`, 5xx becomes `ERROR`), which
  is what makes anomaly detection meaningful on logs that have no level field at all
- Clusters error messages by rewriting variable tokens (IPs, UUIDs, hex IDs, URLs, paths, quoted
  strings, block devices, numbers) into typed placeholders, then union-merging templates above a
  Jaccard similarity threshold
- Detects anomalous time windows from the error-rate distribution: `μ + 2σ` is a warning, `μ + 3σ`
  is critical, with sparse windows excluded
- Sends Slack Block Kit alerts through an Incoming Webhook, distinguishing "no webhook configured"
  from "webhook configured but delivery failed"
- Rich dashboard output — summary panel, level breakdown, ranked error patterns, anomaly table

## Architecture

```
  log file
     │
     ▼
  parser.parse_file          per-line format detection; entries are
     │                       {timestamp, level, message, raw}
     ├──────────────┐
     ▼              ▼
  clustering     anomaly
  .cluster_      .detect_
   errors()       anomalies()
     │              │
     │              ├─ bucket by window → error rate per window
     │              └─ flag windows above μ + 2σ / μ + 3σ
     ▼              ▼
        cli.analyse  ── Rich dashboard
             │
             └─ alerts.send_slack_alert()   (only when anomalies exist)
```

| Module | Responsibility |
|---|---|
| `logsense/parser.py` | Format regexes, per-line parsing, `detect_format` scoring |
| `logsense/clustering.py` | Template normalisation, Jaccard similarity, union-find merge |
| `logsense/anomaly.py` | Time-window bucketing, mean/σ, severity classification |
| `logsense/alerts.py` | Slack Block Kit payload construction and delivery |
| `logsense/cli.py` | Click commands and Rich rendering |
| `logsense/constants.py` | `ERROR_LEVELS` — the single definition of what counts as an error |

`ERROR_LEVELS` is shared by the CLI, the clusterer and the anomaly detector so that the error rate
in the summary panel, the entries that get clustered, and the entries that drive anomaly detection
can never disagree.

## Quickstart

Requires Python 3.11+.

```bash
git clone https://github.com/peteroyce/logsense.git
cd logsense
pip install -e .

# with dev dependencies for running the tests
pip install -e ".[dev]"
```

### Configuration

Slack alerting is optional. Copy `.env.example` to `.env` and fill in a webhook URL:

```bash
cp .env.example .env
```

```dotenv
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

`SLACK_WEBHOOK_URL` is also read straight from the shell environment, so CI secrets work without a
`.env` file. It can equally be passed inline with `--slack-webhook`.

## Usage

```bash
logsense analyse /var/log/nginx/access.log
logsense stats   /var/log/nginx/error.log
```

### `analyse`

| Option | Default | Effect |
|---|---|---|
| `--format` | `auto` | One of `nginx`, `apache`, `json`, `auto`. Sets the format reported in the summary; parsing itself is per line and always tries every pattern |
| `--window-minutes` | `5` | Anomaly window size in minutes (1–1440) |
| `--threshold` | `0.72` | Jaccard similarity above which two error templates merge (0.5–0.99) |
| `--level` | none | Restrict the whole analysis to one severity, e.g. `--level ERROR` |
| `--limit` | `20` | Maximum error-pattern clusters shown |
| `--slack-webhook` | `$SLACK_WEBHOOK_URL` | Incoming Webhook URL |

```bash
logsense analyse app.log --window-minutes 15
logsense analyse app.log --threshold 0.85 --limit 10
logsense analyse app.log --level ERROR
logsense analyse /var/log/app.log \
  --window-minutes 10 \
  --slack-webhook "$SLACK_WEBHOOK_URL"
```

The dashboard prints, in order: a summary panel (path, format, total entries, error count and rate,
time range, anomaly count); a log level breakdown with counts and shares; a ranked table of error
patterns with counts and first/last seen; and, if any windows were flagged, an anomaly table with
z-scores and severities. A Slack alert is sent only when anomalies were found and a webhook is
available; if none is configured the run prints a hint rather than an error.

If `--window-minutes` exceeds the total time span of the file, LogSense warns rather than silently
returning no anomalies — the most common cause of a confusingly empty result.

### `stats`

Takes only a file path. Prints four panels — total lines, error/warning count, error rate, detected
format — plus the earliest and latest timestamps.

## Supported log formats

| Format | Example line |
|---|---|
| nginx combined | `10.0.0.1 - - [15/Jan/2024:08:00:01 +0000] "GET / HTTP/1.1" 200 1024 "-" "curl/7.88"` |
| Apache common | `127.0.0.1 - bob [10/Oct/2023:13:55:36 +0000] "GET /index HTTP/1.0" 200 2326` |
| JSON | `{"timestamp":"2024-01-15T10:23:45Z","level":"error","message":"DB timeout"}` |
| Generic | `2024-01-15 10:23:45 ERROR Database connection refused at 127.0.0.1:5432` |
| Generic | `2024-01-15T10:24:00.123Z [WARNING] Disk usage above 80%` |

JSON entries are searched for a timestamp under `timestamp`, `time`, `ts`, `@timestamp` or `date`,
a level under `level`, `severity`, `log_level` or `loglevel`, and a message under `message`, `msg`,
`text` or `body` — enough to cover the common structured-logging libraries without configuration.

`detect_format` scores up to 20 non-blank lines from the sample it is given (the CLI passes the first
40 parsed entries) and returns the highest-scoring pattern, defaulting to `generic` if nothing matches.
An nginx match only counts as nginx when the referer and user-agent fields are present; otherwise it
scores as Apache.

## How anomaly detection works

1. Entries with a parsed timestamp are floored into fixed-size UTC windows (default 5 minutes).
2. Each window's error rate is `entries at an error level / total entries`, where error levels are
   `ERROR`, `CRITICAL`, `FATAL`, `WARNING` and `WARN`.
3. The mean and population standard deviation of those rates are computed across all windows.
4. Windows above `μ + 2σ` are flagged `warning`, those at or above `μ + 3σ` are `critical`.

Windows with fewer than two entries are skipped, and if σ is effectively zero no anomalies are
reported at all — with a flat error rate, nothing stands out by definition, and reporting anything
would be noise.

## How error clustering works

Each error message is lowercased and normalised into a template by substitution, in order: IPv6 and
IPv4 addresses (`<IPv6>`, `<IP>`), UUIDs (`<UUID>`), long hex strings (`<HEX>`), URLs (`<URL>`), Unix
and Windows paths (`<PATH>`), quoted strings (`<STR>`), block devices such as `sda1` or `nvme0n1`
(`<DEVICE>`), and numbers with optional units (`<NUM>`).

Identical templates are grouped, then a union-find pass merges any two groups whose token sets share
at least `--threshold` Jaccard similarity, keeping the larger group's template as the representative.
Exact grouping first keeps the O(n²) merge pass over *unique templates* rather than over every line,
which is what makes it cheap enough on real log volumes. Clusters are returned ranked by count with
occurrence totals, per-level breakdowns, first/last seen timestamps and up to three raw examples.

## Tech stack

Python 3.11+ · Click · Rich · httpx · python-dotenv · pytest

## Testing

```bash
pip install -e ".[dev]"
pytest
pytest --cov=logsense --cov-report=term-missing
```

Tests cover the parser, clusterer, anomaly detector and Slack alerting
(`tests/test_parser.py`, `test_clustering.py`, `test_anomaly.py`, `test_alerts.py`). GitHub Actions
runs `pytest tests/ -v` on Python 3.11 for pushes and pull requests to `main` and `master`
(`.github/workflows/ci.yml`).

## License

MIT
