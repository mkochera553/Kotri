"""Command line entry point: scan reports in, ranked Markdown report out."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from kotri.config import ConfigError, load_config
from kotri.llm.client import LLMClient
from kotri.pipeline import run_pipeline
from kotri.report import render_report

DEFAULT_CONFIG = Path("config.yaml")
DEFAULT_OUTPUT = Path("reports/kotri-report.md")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kotri",
        description="Triage Semgrep/ZAP findings with a local LLM and write a ranked report.",
    )
    parser.add_argument("--semgrep", type=Path, help="Semgrep JSON report")
    parser.add_argument("--zap", type=Path, help="OWASP ZAP JSON report")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="default: config.yaml")
    parser.add_argument("--model", help="model to use (default: first in config llm.models)")
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_OUTPUT, help=f"default: {DEFAULT_OUTPUT}"
    )
    return parser


def _prepare_output(output: Path) -> None:
    """Create the report's parent directory; raise OSError if it can't be a file path."""
    if output.is_dir():
        raise IsADirectoryError(f"--output {output} is a directory, not a file")
    output.parent.mkdir(parents=True, exist_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.semgrep is None and args.zap is None:
        parser.error("give at least one of --semgrep or --zap")

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        llm_config = load_config(args.config)
        client = LLMClient.from_config(llm_config, args.model or llm_config["models"][0])
        _prepare_output(args.output)  # fail before the slow triage run, not after
        result = run_pipeline(client, semgrep=args.semgrep, zap=args.zap)
    except (ConfigError, OSError, ValueError) as exc:
        print(f"kotri: {exc}", file=sys.stderr)
        return 2
    client.log_parse_stats()

    try:
        args.output.write_text(render_report(result), encoding="utf-8")
    except OSError as exc:
        print(f"kotri: cannot write report {args.output}: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote {args.output} ({len(result.items)} findings)")
    return 1 if result.incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
