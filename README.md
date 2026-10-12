# Kotri

Local LLM-assisted vulnerability triage.

Kotri reads [Semgrep](https://semgrep.dev) (SAST) and [OWASP ZAP](https://www.zaproxy.org) (DAST) JSON reports, normalizes the findings into one model, asks a **locally hosted** LLM to triage each one, and writes a ranked Markdown report. It was built around scans of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/).

For every finding the model returns:

- a **verdict**: `likely_true_positive`, `likely_false_positive` or `needs_review`
- an **adjusted severity**: `critical`, `high`, `medium`, `low` or `info`
- a short **exploitability rationale** and an optional **suggested fix**

## Findings never leave your machine

Kotri only talks to a local inference runtime ([Ollama](https://ollama.com)'s OpenAI-compatible endpoint). The client refuses any base URL whose host is not `127.0.0.1`, `localhost` or `::1`, and the config is checked for the same thing before any scan is read. There are no hosted LLM APIs, telemetry or remote logging.

## Quick start

You need Python 3.11+ and [Ollama](https://ollama.com) running locally.

```bash
# 1. Install
pip install -e ".[dev]"

# 2. Pull a model
ollama pull llama3.1:8b

# 3. Create your config (config.yaml is gitignored)
cp config.example.yaml config.yaml        # Windows: copy config.example.yaml config.yaml

# 4. Triage the bundled sample scans
python -m kotri --semgrep data/semgrep.sample.json --zap data/zap.sample.json
```

The report is written to `reports/kotri-report.md`. The `kotri` command works too once the package is installed.

## Usage

```
kotri [--semgrep FILE] [--zap FILE] [--config FILE] [--model NAME] [--output FILE]
```

| Option | Description |
| --- | --- |
| `--semgrep FILE` | Semgrep JSON report |
| `--zap FILE` | OWASP ZAP JSON report (the `traditional-json` template) |
| `--config FILE` | Config file. Default: `config.yaml` |
| `--model NAME` | Model to use. Default: the first entry in `llm.models` |
| `--output FILE` | Where to write the report. Default: `reports/kotri-report.md` |

Give at least one of `--semgrep` or `--zap`; you can pass both. Findings repeated within or across scans are deduplicated so each is triaged once.

Examples:

```bash
# Both scanners, default model
python -m kotri --semgrep scans/semgrep.json --zap scans/zap-baseline.json

# Only ZAP, a specific model, custom output path
python -m kotri --zap scans/zap-baseline.json --model qwen2.5:7b --output reports/zap-qwen.md
```

Triage is sequential and can take a while on a laptop; progress is logged per finding.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Report written, every finding got an outcome |
| `1` | Report written, but some findings were not triaged (runtime error, or the run aborted after repeated runtime failures) |
| `2` | Bad config, unreadable or invalid scan file, or the report could not be written |

## Configuration

Copy `config.example.yaml` to `config.yaml` and edit it:

```yaml
llm:
  base_url: http://127.0.0.1:11434/v1   # must be a loopback host
  timeout_seconds: 120                  # per request
  max_retries: 2                        # connection/timeout/5xx retries (not parse retries)
  max_tokens: 1024                      # cap on generated tokens per reply
  models:
    - llama3.1:8b
    - qwen2.5:7b
```

`models` is required and must list models your runtime has pulled. The other keys are optional and fall back to the client's defaults.

## Producing scan input

Scan files are not committed (`scans/` is gitignored); trimmed samples live in `data/` so you can try the tool straight away. To scan Juice Shop yourself:

```bash
# Semgrep, from the Juice Shop source directory. Keep metrics off; never use `semgrep ci`.
semgrep scan --config auto --metrics=off --json --output /path/to/Kotri/scans/semgrep.json

# ZAP baseline against a running Juice Shop (JSON output)
docker run --rm -v "$PWD/scans:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:3000 -J zap-baseline.json
```

## Reading the report

The report starts with the model used, finding counts, parse retries/failures and total triage time, followed by a summary table of adjusted severities. Findings are then ranked:

1. By the model's **adjusted severity**, highest first.
2. Within a severity, confirmed issues before `needs_review`.
3. **Likely false positives come after everything else**, so a dismissed high cannot outrank a real medium.

Findings that got no usable result (parse failure, runtime error, aborted run) are listed last under "Not triaged" with the scanner's own severity. Text that originates from scanners or the model is escaped so it cannot inject links, images or headings into the report.

## How it works

```
Semgrep JSON ─┐
              ├─> normalize ─> dedupe ─> triage (local LLM) ─> ranked Markdown report
ZAP JSON ─────┘
```

LLM output is treated as untrusted: it is parsed and validated against a Pydantic schema, retried once on failure, and recorded as a parse failure (and counted) rather than crashing the run. Triage uses temperature 0 so runs are repeatable.

```
src/kotri/
  ingest/      Semgrep and ZAP parsers -> the shared Finding model
  llm/         localhost-only client, prompts, output schema
  config.py    config.yaml loading and validation
  pipeline.py  normalize -> dedupe -> triage -> collect
  report.py    ranked Markdown report
  cli.py       command line entry point
data/          trimmed sample scans
tests/         pytest suite
```

## Development

```bash
python -m pytest
```

Tests never call a real LLM or need network access; the client is mocked.
