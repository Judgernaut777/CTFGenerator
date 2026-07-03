from __future__ import annotations

import argparse
from pathlib import Path

from .generator import create_challenge
from .runtime_validator import validate_runtime
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

    parser.error(f"unknown command: {args.command}")
    return 2
