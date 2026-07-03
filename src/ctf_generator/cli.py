from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, report_index, report_writer, spec_generator
from .generator import create_challenge
from .replay_validator import cross_replay
from .runtime_validator import validate_runtime
from .score import score_challenge
from .sibling_validator import validate_siblings
from .validator import validate_challenge

# Challenge families the generator can produce. Single source of truth for the
# argparse choices below and the `list-families` discovery command.
FAMILIES = ["web_business_logic_tenant_export"]


def _write_cli_report(
    args: argparse.Namespace,
    command: str,
    subject: dict,
    status: str,
    result: dict,
) -> None:
    """Best-effort report artifact write. No-ops when --report-dir is unset.

    Any failure is warned to stderr and never alters the exit code or stdout.
    """
    report_dir = getattr(args, "report_dir", None)
    if report_dir is None:
        return
    try:
        report = report_writer.build_report(
            command=command,
            subject=subject,
            result=result,
            status=status,
        )
        report_writer.write_report(report_dir, report)
    except Exception as exc:  # noqa: BLE001 - report writing must never be fatal
        print(f"warning: failed to write report: {exc}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctfgen",
        description="Generate and validate AI-resistant CTF challenge environments.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=False)

    create = subparsers.add_parser("create", help="Generate a challenge environment")
    create.add_argument("--output", "-o", required=True, type=Path)
    create.add_argument("--seed", default="demo-001")
    create.add_argument("--title", default="Invoice Drift")
    create.add_argument("--difficulty", default="medium", choices=["easy", "medium", "hard"])
    create.add_argument(
        "--family",
        default=FAMILIES[0],
        choices=FAMILIES,
    )
    create.add_argument("--force", action="store_true", help="Overwrite an existing output directory")
    create.add_argument(
        "--from-spec",
        type=Path,
        default=None,
        help="Render from a challenge spec JSON file (produced by `ctfgen spec`)",
    )

    spec = subparsers.add_parser(
        "spec",
        help="Generate a structured challenge spec before rendering any code",
    )
    spec.add_argument("--output", "-o", required=True, type=Path, help="Spec JSON output path")
    spec.add_argument("--seed", default="demo-001")
    spec.add_argument("--title", default="Invoice Drift")
    spec.add_argument("--difficulty", default="medium", choices=["easy", "medium", "hard"])
    spec.add_argument("--family", default=FAMILIES[0], choices=FAMILIES)
    spec.add_argument(
        "--backend",
        default="deterministic",
        choices=["deterministic", "llm"],
        help="deterministic (offline default) or llm (Claude-backed, needs ctf-generator[llm])",
    )
    spec.add_argument(
        "--model",
        default=spec_generator.DEFAULT_MODEL,
        help="Model id for the llm backend",
    )

    validate = subparsers.add_parser("validate", help="Validate generated challenge files")
    validate.add_argument("challenge_path", type=Path)
    validate.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Write a structured JSON report artifact to this directory",
    )

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
    validate_runtime_parser.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Write a structured JSON report artifact to this directory",
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
        default=FAMILIES[0],
        choices=FAMILIES,
    )
    siblings.add_argument("--force", action="store_true")
    siblings.add_argument(
        "--runtime",
        action="store_true",
        help="Also run Docker runtime validation for each sibling sequentially",
    )
    siblings.add_argument(
        "--cross-replay",
        action="store_true",
        help=(
            "With --runtime, additionally replay each sibling's solver against the "
            "other sibling's live instance (cross-sibling exploit replay)"
        ),
    )
    siblings.add_argument("--timeout", default=90, type=int)
    siblings.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Write a structured JSON report artifact to this directory",
    )

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
    score.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Write a structured JSON report artifact to this directory",
    )

    replay = subparsers.add_parser(
        "replay",
        help="Replay one challenge's solver against another challenge's live instance",
    )
    replay.add_argument("solver_dir", type=Path, help="Challenge whose solver is run")
    replay.add_argument("target_dir", type=Path, help="Challenge whose instance is launched as the target")
    replay.add_argument("--base-url", default="http://127.0.0.1:8080")
    replay.add_argument("--timeout", default=90, type=int)
    replay.add_argument(
        "--keep-running",
        action="store_true",
        help="Leave the target containers running after replay",
    )
    replay.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Write a structured JSON report artifact to this directory",
    )

    subparsers.add_parser(
        "list-families",
        help="List the challenge families the generator can produce",
    )

    report_index_parser = subparsers.add_parser(
        "report-index",
        help="Summarize JSON report artifacts in a directory as a table (and optional HTML)",
    )
    report_index_parser.add_argument("report_dir", type=Path)
    report_index_parser.add_argument(
        "--html",
        type=Path,
        default=None,
        help="Write a self-contained static HTML dashboard to this file",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return 2

    if args.command == "list-families":
        for family in FAMILIES:
            print(family)
        return 0

    if args.command == "create":
        spec = None
        if args.from_spec is not None:
            try:
                spec = spec_generator.load_spec(args.from_spec)
            except (OSError, json.JSONDecodeError) as exc:
                print(f"Could not read spec {args.from_spec}: {exc}", file=sys.stderr)
                return 1
            errors = spec_generator.validate_spec(spec)
            if errors:
                print("Spec validation failed:")
                for error in errors:
                    print(f"- {error}")
                return 1
        try:
            result = create_challenge(
                output_dir=args.output,
                seed=args.seed,
                title=args.title,
                difficulty=args.difficulty,
                family=args.family,
                force=args.force,
                spec=spec,
            )
        except FileExistsError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"Generated challenge at {result}")
        return 0

    if args.command == "spec":
        backend = spec_generator.get_backend(args.backend, model=args.model)
        try:
            generated = backend.generate(
                family=args.family,
                difficulty=args.difficulty,
                seed=args.seed,
                title=args.title,
            )
        except Exception as exc:  # noqa: BLE001 - surface backend/LLM errors cleanly
            print(f"Spec generation failed: {exc}", file=sys.stderr)
            return 1
        errors = spec_generator.validate_spec(generated)
        if errors:
            print("Spec validation failed:")
            for error in errors:
                print(f"- {error}")
            return 1
        spec_generator.write_spec(args.output, generated)
        print(f"Wrote {args.backend} spec to {args.output}")
        return 0

    if args.command == "validate":
        report = validate_challenge(args.challenge_path)
        subject = {"type": "challenge", "identifier": args.challenge_path.name}
        result = report_writer.serialize_validation(report)
        status = report_writer.status_of(report.errors)
        _write_cli_report(args, "validate", subject, status, result)
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
        subject = {"type": "challenge", "identifier": args.challenge_path.name}
        result = report_writer.serialize_runtime(report)
        status = report_writer.status_of(report.errors)
        _write_cli_report(args, "validate-runtime", subject, status, result)
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
        if args.cross_replay and not args.runtime:
            parser.error("--cross-replay requires --runtime")
        report = validate_siblings(
            output_dir=args.output,
            seed=args.seed,
            title=args.title,
            difficulty=args.difficulty,
            family=args.family,
            force=args.force,
            runtime=args.runtime,
            cross_replay=args.cross_replay,
            timeout_seconds=args.timeout,
        )
        subject = {"type": "sibling-set", "identifier": args.seed}
        result = report_writer.serialize_siblings(report)
        status = report_writer.status_of(report.errors)
        _write_cli_report(args, "validate-siblings", subject, status, result)
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

    if args.command == "replay":
        report = cross_replay(
            solver_dir=args.solver_dir,
            target_dir=args.target_dir,
            base_url=args.base_url,
            timeout_seconds=args.timeout,
            keep_running=args.keep_running,
        )
        subject = {
            "type": "replay",
            "identifier": f"{args.solver_dir.name}-vs-{args.target_dir.name}",
        }
        result = report_writer.serialize_replay(report)
        status = report_writer.status_of(report.errors)
        _write_cli_report(args, "replay", subject, status, result)
        for log in report.logs:
            print(log.rstrip())
        if report.errors:
            print("Replay failed:")
            for error in report.errors:
                print(f"- {error}")
            return 1
        print(
            f"Replay passed: {args.solver_dir.name}'s solver extracted the flag "
            f"from {args.target_dir.name}"
        )
        return 0

    if args.command == "score":
        report = score_challenge(args.challenge_path)
        subject = {"type": "challenge", "identifier": args.challenge_path.name}
        result = report.to_mapping()
        if report.errors:
            _write_cli_report(args, "score", subject, "failed", result)
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
        below_min = args.min_score is not None and report.total < args.min_score
        status = "failed" if below_min else "passed"
        _write_cli_report(args, "score", subject, status, result)
        if below_min:
            print(f"score {report.total:.1f} is below threshold {args.min_score:.1f}")
            return 1
        return 0

    if args.command == "report-index":
        index = report_index.load_index(args.report_dir)
        print(report_index.render_table(index))
        if args.html is not None:
            try:
                args.html.parent.mkdir(parents=True, exist_ok=True)
                args.html.write_text(report_index.render_html(index), encoding="utf-8")
            except OSError as exc:
                print(f"warning: failed to write HTML dashboard: {exc}", file=sys.stderr)
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2
