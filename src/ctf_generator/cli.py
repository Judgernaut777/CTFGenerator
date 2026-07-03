from __future__ import annotations

import argparse
import json
from pathlib import Path

from .generator import create_challenge
from .runtime_validator import validate_runtime
from .score import score_challenge
from .sibling_validator import validate_siblings
from .validator import validate_challenge


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctfgen",
        description="Generate and validate AI-resistant CTF challenge environments.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="Generate a challenge environment")
    create.add_argument("--output", "-o", required=True, type=Path)
    create.add_argument("--seed", default="demo-001")
    create.add_argument("--title", default="Invoice Drift")
    create.add_argument("--difficulty", default="medium", choices=["easy", "medium", "hard"])
    create.add_argument(
        "--family",
        default="web_business_logic_tenant_export",
        choices=["web_business_logic_tenant_export"],
    )
    create.add_argument("--force", action="store_true", help="Overwrite an existing output directory")

    validate = subparsers.add_parser("validate", help="Validate generated challenge files")
    validate.add_argument("challenge_path", type=Path)

    validate_runtime_parser = subparsers.add_parser(
        "validate-runtime",
        help="Build, launch, health-check, solve, and tear down a generated challenge",
    )
    validate_runtime_parser.add_argument("challenge_path", type=Path)
    validate_runtime_parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    validate_runtime_parser.add_argument("--timeout", default=90, type=int)
    validate_runtime_parser.add_argument(
        "--keep-running",
        action="store_true",
        help="Leave containers running after validation",
    )

    siblings = subparsers.add_parser(
        "validate-siblings",
        help="Generate sibling variants and verify they differ meaningfully",
    )
    siblings.add_argument("--output", "-o", required=True, type=Path)
    siblings.add_argument("--seed", default="demo-001")
    siblings.add_argument("--title", default="Invoice Drift")
    siblings.add_argument("--difficulty", default="medium", choices=["easy", "medium", "hard"])
    siblings.add_argument(
        "--family",
        default="web_business_logic_tenant_export",
        choices=["web_business_logic_tenant_export"],
    )
    siblings.add_argument("--force", action="store_true")
    siblings.add_argument(
        "--runtime",
        action="store_true",
        help="Also run Docker runtime validation for each sibling sequentially",
    )
    siblings.add_argument("--timeout", default=90, type=int)

    score = subparsers.add_parser(
        "score",
        help="Score a generated challenge on AI-resistance dimensions",
    )
    score.add_argument("challenge_path", type=Path)
    score.add_argument("--json", action="store_true", help="Emit the score report as JSON")
    score.add_argument(
        "--min-score",
        type=float,
        default=None,
        help="Exit non-zero if the total score is below this threshold",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "create":
        result = create_challenge(
            output_dir=args.output,
            seed=args.seed,
            title=args.title,
            difficulty=args.difficulty,
            family=args.family,
            force=args.force,
        )
        print(f"Generated challenge at {result}")
        return 0

    if args.command == "validate":
        report = validate_challenge(args.challenge_path)
        if report.errors:
            print("Validation failed:")
            for error in report.errors:
                print(f"- {error}")
            return 1
        print("Validation passed")
        for warning in report.warnings:
            print(f"warning: {warning}")
        return 0

    if args.command == "validate-runtime":
        report = validate_runtime(
            challenge_path=args.challenge_path,
            base_url=args.base_url,
            timeout_seconds=args.timeout,
            keep_running=args.keep_running,
        )
        for log in report.logs:
            print(log.rstrip())
        if report.errors:
            print("Runtime validation failed:")
            for error in report.errors:
                print(f"- {error}")
            return 1
        print("Runtime validation passed")
        return 0

    if args.command == "validate-siblings":
        report = validate_siblings(
            output_dir=args.output,
            seed=args.seed,
            title=args.title,
            difficulty=args.difficulty,
            family=args.family,
            force=args.force,
            runtime=args.runtime,
            timeout_seconds=args.timeout,
        )
        for log in report.logs:
            print(log.rstrip())
        if report.errors:
            print("Sibling validation failed:")
            for error in report.errors:
                print(f"- {error}")
            return 1
        print(f"Sibling A: {report.sibling_a}")
        print(f"Sibling B: {report.sibling_b}")
        print("Changed fields:")
        for field in report.changed_tokens:
            print(f"- {field}")
        for warning in report.warnings:
            print(f"warning: {warning}")
        print("Sibling validation passed")
        return 0

    if args.command == "score":
        report = score_challenge(args.challenge_path)
        if report.errors:
            print("Scoring failed:")
            for error in report.errors:
                print(f"- {error}")
            return 1
        if args.json:
            print(json.dumps(report.to_mapping(), indent=2, sort_keys=True))
        else:
            print(f"AI-resistance score: {report.total:.1f}/100 ({report.band})")
            for dimension in report.dimensions:
                print(f"- {dimension.name} [w={dimension.weight}]: {dimension.score:.1f}")
                for note in dimension.notes:
                    print(f"    {note}")
            for warning in report.warnings:
                print(f"warning: {warning}")
        if args.min_score is not None and report.total < args.min_score:
            print(f"score {report.total:.1f} is below threshold {args.min_score:.1f}")
            return 1
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2
