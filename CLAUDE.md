# Kotri

Local LLM-assisted vulnerability triage. Kotri reads Semgrep (SAST) and OWASP ZAP (DAST) JSON output from scans of OWASP Juice Shop, normalizes the findings into one model, asks a locally hosted LLM to triage each one (true/false positive, severity, rationale), and produces a ranked Markdown report. An eval harness measures how well each model agrees with hand-labeled findings.

## Hard rule: findings never leave this machine

- The only network destination allowed is the local inference runtime (Ollama's OpenAI-compatible endpoint, default `http://127.0.0.1:11434/v1`).
- `src/kotri/llm/client.py` must refuse any base URL whose host is not `127.0.0.1`, `localhost` or `::1`. Do not weaken or bypass this check.
- No hosted LLM APIs, telemetry, analytics, crash reporting, or remote logging. Do not add dependencies that phone home.
- Scanner runs use `--metrics=off` (Semgrep). Never use `semgrep ci` or `semgrep login`.
- Never commit real scan output. `scans/`, `config.yaml` and generated reports are gitignored. Only the trimmed Juice Shop samples in `data/` are committed.
- If a task seems to require sending data off the machine, stop and ask instead.

## Structure

```
src/
  kotri/
    __init__.py
    ingest/
      __init__.py
      models.py    # Finding model (Pydantic) - the single normalized shape every parser returns
      semgrep.py   # Semgrep JSON -> list[Finding]
      zap.py       # ZAP JSON -> list[Finding]
    llm/
      __init__.py
      client.py    # OpenAI-compatible client: localhost-only, timeouts, retries
      prompts.py   # triage prompt templates
      schema.py    # Pydantic schema the LLM's JSON output must validate against
    pipeline.py    # normalize -> dedupe -> triage -> collect results
    report.py      # ranked Markdown report
eval/
  labels.csv       # hand-labeled findings (ground truth; do not edit without asking)
  run_eval.py      # agreement, parse-failure rate, latency per model
data/              # trimmed sample scan JSON so others can reproduce results
tests/             # pytest tests and small fixture files
config.example.yaml  # runtime base URL and model names (copy to config.yaml locally)
```

All application code lives in the `kotri` package under `src/kotri/` (src layout). Import with absolute package paths, e.g. `from kotri.ingest.models import Finding` - never `from src...` or bare `from ingest...`. `eval/` and `tests/` import from `kotri` the same way, which works once the package is installed with `pip install -e .`.

Put new code in the module that owns that responsibility. Parsers only parse; the LLM layer only talks to the model; the pipeline wires them together.

## Conventions

- Python 3.11+. Small, single-purpose modules and functions.
- Type hints on every function signature and return value. Pydantic v2 models for data crossing module boundaries.
- Every module gets pytest tests in `tests/`. Use small fixture files in `tests/fixtures/`; tests must never call a real LLM or need network access. Mock the client.
- LLM output is untrusted: parse it, validate it against `schema.py`, retry once on failure, then record a parse failure rather than crashing. Parse failures are an eval metric, so count them.
- Use temperature 0 for triage so eval runs are repeatable.
- Configuration comes from `config.yaml` (never hard-code model names or ports outside the localhost check).
- Don't add a new dependency without saying why. Prefer the standard library.

## Commands

```
pip install -e ".[dev]"     # install with dev dependencies
python -m pytest            # run tests
```

## Working style

- Make small, focused changes and run the tests before calling a task done.
- When changing a parser, add or update a fixture that covers the new case.
- Ask before changing `eval/labels.csv`, the Finding model's fields, or the output schema, since the eval depends on them.
