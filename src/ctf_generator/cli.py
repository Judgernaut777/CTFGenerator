from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, families, report_index, report_writer, spec_generator
from .generator import create_challenge
from .replay_validator import cross_replay
from .runtime_validator import validate_runtime
from .score import score_challenge
from .sdk.plugins import bootstrap_family_plugins
from .sibling_validator import validate_siblings
from .validator import validate_challenge

# Challenge families the generator can produce. Sourced from the live family
# registry (`families.family_names()`) so newly-registered families show up
# here automatically; kept as a module-level alias so existing importers
# (e.g. `from ctf_generator.cli import FAMILIES`) keep working unchanged.
FAMILIES = families.family_names()

# The historical default family for `create`/`spec`/`validate-siblings` when
# --family is omitted. Kept as an explicit constant (rather than
# ``FAMILIES[0]``) so widening `FAMILIES` to the full registry never changes
# default CLI behavior for existing callers/tests.
_DEFAULT_FAMILY = "web_business_logic_tenant_export"


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
        default=_DEFAULT_FAMILY,
        choices=FAMILIES,
    )
    create.add_argument("--force", action="store_true", help="Overwrite an existing output directory")
    create.add_argument(
        "--from-spec",
        type=Path,
        default=None,
        help="Render from a challenge spec JSON file (produced by `ctfgen spec`)",
    )
    create.add_argument(
        "--mode",
        default="red",
        help="Challenge mode (default: red)",
    )
    create.add_argument(
        "--cve-ref",
        dest="cve_refs",
        action="append",
        default=[],
        help="CVE id (e.g. CVE-2021-44228) this challenge is grounded in (repeatable)",
    )

    spec = subparsers.add_parser(
        "spec",
        help="Generate a structured challenge spec before rendering any code",
    )
    spec.add_argument("--output", "-o", required=True, type=Path, help="Spec JSON output path")
    spec.add_argument("--seed", default="demo-001")
    spec.add_argument("--title", default="Invoice Drift")
    spec.add_argument("--difficulty", default="medium", choices=["easy", "medium", "hard"])
    spec.add_argument("--family", default=_DEFAULT_FAMILY, choices=FAMILIES)
    spec.add_argument(
        "--mode",
        default="red",
        help="Challenge mode (default: red)",
    )
    spec.add_argument(
        "--cve-ref",
        dest="cve_refs",
        action="append",
        default=[],
        help="CVE id (e.g. CVE-2021-44228) this challenge is grounded in (repeatable)",
    )
    spec.add_argument(
        "--backend",
        default="deterministic",
        choices=["deterministic", "anthropic", "openai"],
        help=(
            "deterministic (offline default), anthropic (Claude-backed, needs "
            "ctf-generator[anthropic]), or openai (needs ctf-generator[openai])"
        ),
    )
    spec.add_argument(
        "--model",
        default=None,
        help="Model id for the anthropic/openai backend (defaults per provider)",
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
    validate_runtime_parser.add_argument(
        "--sandbox",
        action="store_true",
        help=(
            "Run the bundle's healthcheck.py/solver.py inside an ephemeral "
            "read-only container instead of on the host. Use this for challenge "
            "bundles you did NOT generate yourself -- they contain code that "
            "otherwise executes with your privileges."
        ),
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
        default=_DEFAULT_FAMILY,
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

    # --- CVE / scenario / scoreboard platform commands (Phase 4) ------------

    cve_search_parser = subparsers.add_parser(
        "cve-search",
        help="Search CVE records to ground a challenge in",
    )
    cve_search_parser.add_argument("--category", default=None, choices=list(_cve_categories()))
    cve_search_parser.add_argument("--min-cvss", type=float, default=0.0)
    cve_search_parser.add_argument("--keyword", default=None)
    cve_search_parser.add_argument("--limit", type=int, default=20)
    cve_search_parser.add_argument(
        "--source", default="snapshot", choices=["snapshot", "nvd"]
    )
    cve_search_parser.add_argument("--cache-dir", type=Path, default=None)

    cve_show_parser = subparsers.add_parser(
        "cve-show",
        help="Show a single CVE record",
    )
    cve_show_parser.add_argument("cve_id")
    cve_show_parser.add_argument(
        "--source", default="snapshot", choices=["snapshot", "nvd"]
    )
    cve_show_parser.add_argument("--cache-dir", type=Path, default=None)

    subparsers.add_parser(
        "cve-categories",
        help="List the CVE category taxonomy",
    )

    create_from_cve_parser = subparsers.add_parser(
        "create-from-cve",
        help="Generate a challenge environment grounded in a real CVE",
    )
    create_from_cve_parser.add_argument("--output", "-o", required=True, type=Path)
    create_from_cve_parser.add_argument(
        "cve_id", nargs="?", default=None, help="CVE id (or use --cve-id)"
    )
    create_from_cve_parser.add_argument("--cve-id", dest="cve_id_flag", default=None)
    create_from_cve_parser.add_argument("--seed", default="demo-001", help="Base seed")
    create_from_cve_parser.add_argument(
        "--difficulty", default=None, choices=["easy", "medium", "hard"]
    )
    create_from_cve_parser.add_argument("--family", default=None, choices=FAMILIES)
    create_from_cve_parser.add_argument("--title", default=None)
    create_from_cve_parser.add_argument("--force", action="store_true")
    create_from_cve_parser.add_argument(
        "--source", default="snapshot", choices=["snapshot", "nvd"]
    )
    create_from_cve_parser.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Write a structured JSON report artifact to this directory",
    )

    run_scenario_parser = subparsers.add_parser(
        "run-scenario",
        help="Run a challenge's scripted scenario timeline offline (deterministic)",
    )
    run_scenario_parser.add_argument("challenge_dir", type=Path)
    run_scenario_parser.add_argument(
        "--max-ticks",
        type=int,
        default=None,
        help="Number of ticks to run (default: scenario engine's own default)",
    )
    run_scenario_parser.add_argument(
        "--json", action="store_true", help="Emit the scenario report as JSON"
    )
    run_scenario_parser.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Write a structured JSON report artifact to this directory",
    )
    run_scenario_parser.add_argument(
        "--runtime",
        action="store_true",
        help=(
            "Run against a live Docker instance via scenario_runtime.run_live_scenario "
            "instead of the pure, offline scenario engine"
        ),
    )
    run_scenario_parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8080",
        help="Base URL of the live challenge instance (only used with --runtime)",
    )

    subparsers.add_parser(
        "list-scoring-engines",
        help="List registered competition scoring engines",
    )

    scoreboard_parser = subparsers.add_parser(
        "scoreboard",
        help="Compute a competition scoreboard from JSON fixtures",
    )
    scoreboard_parser.add_argument(
        "--events", required=True, type=Path, help="JSON array of SolveEvent records"
    )
    scoreboard_parser.add_argument(
        "--challenges",
        required=True,
        type=Path,
        help="JSON array of ChallengeScoringConfig records",
    )
    scoreboard_parser.add_argument(
        "--config", required=True, type=Path, help="JSON CompetitionConfig object"
    )
    scoreboard_parser.add_argument(
        "--engine",
        default=None,
        help="Scoring engine name (default: time_decay)",
    )
    scoreboard_parser.add_argument(
        "--as-of",
        default=None,
        help="ISO-8601 timestamp; compute a frozen snapshot as of this moment",
    )
    scoreboard_parser.add_argument(
        "--json", action="store_true", help="Emit the scoreboard as JSON"
    )
    scoreboard_parser.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Write a structured JSON report artifact to this directory",
    )

    # --- Agent-eval / live dashboard platform commands (Phase 5) ------------

    eval_agent_parser = subparsers.add_parser(
        "eval-agent",
        help="Run an AI-agent evaluation against a live (Docker) challenge instance",
    )
    eval_agent_parser.add_argument("challenge_dir", type=Path)
    eval_agent_parser.add_argument(
        "--profile",
        required=True,
        help="Eval profile name (see agent_eval.list_eval_profiles())",
    )
    eval_agent_parser.add_argument(
        "--adversarial",
        action="store_true",
        help=(
            "Also compute the live-adversarial delta (agent_eval.run_adversarial_delta): "
            "the same eval run twice, scenario engine off then on"
        ),
    )
    eval_agent_parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    eval_agent_parser.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Write a structured JSON report artifact to this directory",
    )

    serve_parser = subparsers.add_parser(
        "serve",
        help="Serve the live competition admin dashboard + public scoreboard (stdlib HTTP)",
    )
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--admin-user", required=True)
    serve_parser.add_argument("--admin-password", required=True)
    serve_parser.add_argument(
        "--events-file",
        type=Path,
        default=None,
        help="Persist the event log to this JSONL file (default: in-memory only)",
    )
    serve_parser.add_argument(
        "--challenges",
        type=Path,
        default=None,
        help="JSON array of ChallengeScoringConfig records (default: empty catalog)",
    )
    serve_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="JSON CompetitionConfig object (default: a permissive built-in placeholder)",
    )
    serve_parser.add_argument(
        "--public-token",
        default=None,
        help="Fixed public scoreboard token (default: randomly generated, printed once)",
    )
    serve_parser.add_argument(
        "--challenges-dir",
        type=Path,
        default=None,
        help=(
            "Directory of generated challenge folders (each with a challenge.yaml) "
            "to scan into a catalog in-process -- an alternative to --challenges FILE"
        ),
    )
    serve_parser.add_argument(
        "--secure-cookie",
        action="store_true",
        help=(
            "Add the Secure attribute to session cookies. Enable only when "
            "terminating TLS at a proxy -- the built-in server is plain HTTP, "
            "where browsers drop Secure cookies (breaking login)."
        ),
    )

    # --- Onboarding commands (catalog / quickstart) --------------------------

    catalog_parser = subparsers.add_parser(
        "catalog",
        help=(
            "Scan a directory of generated challenges into a ChallengeScoringConfig "
            "JSON catalog usable by `serve --challenges`"
        ),
    )
    catalog_parser.add_argument(
        "--challenges-dir",
        required=True,
        type=Path,
        help="Directory containing generated challenge folders (each with a challenge.yaml)",
    )
    catalog_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Write the catalog JSON to this file (default: print to stdout)",
    )

    quickstart_parser = subparsers.add_parser(
        "quickstart",
        help=(
            "Generate a small set of sample challenges (web + crypto + a CVE-driven "
            "one) and print the next commands to catalog + serve them"
        ),
    )
    quickstart_parser.add_argument("--output", "-o", required=True, type=Path)
    quickstart_parser.add_argument("--seed", default="quickstart-001")

    return parser


def main(argv: list[str] | None = None) -> int:
    # EXPLICIT external-family bootstrap. This is the ONE place entry-point
    # plugins are loaded (fail-safe, at most once per process). It lives on the
    # generator-CLI bootstrap path deliberately -- NEVER at ``families`` import
    # time and NEVER reachable from ``mcp_server`` (which must only ever expose
    # the built-in families to a model host). See sdk/plugins.py.
    bootstrap_family_plugins()

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
        # --mode/--cve-ref only take effect when no --from-spec was given
        # (a loaded spec is already the full source of truth) and only build
        # a spec at all when either is actually used, so a bare `create`
        # keeps today's exact behavior (spec stays None, create_challenge
        # builds its own default spec internally).
        if spec is None and (args.mode != "red" or args.cve_refs):
            import dataclasses

            spec = dataclasses.replace(
                spec_generator.default_spec(
                    seed=args.seed,
                    title=args.title,
                    difficulty=args.difficulty,
                    family=args.family,
                ),
                mode=args.mode,
                cve_refs=list(args.cve_refs),
            )
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
        # --mode/--cve-ref only override when actually used, so a bare `spec`
        # keeps today's exact output (mode="red", cve_refs=[]).
        if args.mode != "red" or args.cve_refs:
            import dataclasses

            generated = dataclasses.replace(
                generated, mode=args.mode, cve_refs=list(args.cve_refs)
            )
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
        if not args.sandbox:
            print(
                "WARNING: validate-runtime executes this bundle's "
                "tests/healthcheck.py and private/solver.py on the host with "
                "your privileges. Only run it on challenges you trust; for an "
                "untrusted bundle, re-run with --sandbox.",
                file=sys.stderr,
            )
        report = validate_runtime(
            challenge_path=args.challenge_path,
            base_url=args.base_url,
            timeout_seconds=args.timeout,
            keep_running=args.keep_running,
            sandbox=args.sandbox,
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

    if args.command == "cve-search":
        source = _build_cve_source(args.source, args.cache_dir)
        records = source.fetch(
            category=args.category,
            min_cvss=args.min_cvss,
            keyword=args.keyword,
            limit=args.limit,
        )
        for record in records:
            print(f"{record.cve_id}  [{record.cvss_severity} {record.cvss_score}]  {record.category}")
            print(f"    {record.description}")
        if not records:
            print("No matching CVEs found")
        return 0

    if args.command == "cve-show":
        source = _build_cve_source(args.source, args.cache_dir)
        record = source.get(args.cve_id)
        if record is None:
            print(f"unknown CVE id: {args.cve_id}", file=sys.stderr)
            return 1
        for key, value in record.to_mapping().items():
            print(f"{key}: {value}")
        return 0

    if args.command == "cve-categories":
        for category in _cve_categories():
            print(category)
        return 0

    if args.command == "create-from-cve":
        cve_id = args.cve_id_flag or args.cve_id
        if not cve_id:
            parser.error("create-from-cve requires a CVE id (positional or --cve-id)")
        from .generator import create_challenge_from_cve

        source = _build_cve_source(args.source, cache_dir=None)
        try:
            result = create_challenge_from_cve(
                output_dir=args.output,
                cve_id=cve_id,
                base_seed=args.seed,
                difficulty=args.difficulty,
                family=args.family,
                title=args.title,
                force=args.force,
                source=source,
            )
        except (FileExistsError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        subject = {"type": "challenge", "identifier": cve_id}
        result_payload = {"output": str(result), "cve_id": cve_id}
        _write_cli_report(args, "create-from-cve", subject, "passed", result_payload)
        print(f"Generated challenge from {cve_id} at {result}")
        return 0

    # Sibling branch (not an edit of the existing run-scenario branch below):
    # when --runtime is set, dispatch to the live/Docker-backed scenario
    # engine instead. Placed first so it short-circuits before the existing
    # branch's body ever runs; the existing branch itself is untouched.
    if args.command == "run-scenario" and getattr(args, "runtime", False):
        from . import scenario_runtime
        from .models import ScenarioSpec

        # Load the recorded timeline so the live defender/attacker are derived
        # from it (same as the offline branch). Without this the live run has
        # no triggers to fire and does nothing.
        timeline_path = Path(args.challenge_dir) / "private" / "scenario_timeline.json"
        if timeline_path.exists():
            scenario_spec = _scenario_spec_from_mapping(
                json.loads(timeline_path.read_text(encoding="utf-8"))
            )
        else:
            scenario_spec = ScenarioSpec()

        report = scenario_runtime.run_live_scenario(
            args.challenge_dir,
            base_url=args.base_url,
            spec=scenario_spec,
            max_ticks=args.max_ticks,
        )
        subject = {"type": "challenge", "identifier": args.challenge_dir.name}
        result = _serialize_scenario_report(report)
        _write_cli_report(args, "run-scenario", subject, "passed", result)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"Ran live scenario for {args.challenge_dir} ({report.ticks_run} ticks)")
            for event in report.timeline:
                print(
                    f"- tick {event.tick} [{event.source}] {event.kind} "
                    f"-> {event.target or '(none)'} {event.payload}"
                )
            print(f"Triggers fired: {report.triggers_fired}")
            print(f"Attacker moves blocked: {report.attacker_blocked}")
        return 0

    if args.command == "run-scenario":
        report = _run_scenario_command(args.challenge_dir, max_ticks=args.max_ticks)
        subject = {"type": "challenge", "identifier": args.challenge_dir.name}
        result = _serialize_scenario_report(report)
        _write_cli_report(args, "run-scenario", subject, "passed", result)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"Ran scenario for {args.challenge_dir} ({report.ticks_run} ticks)")
            for event in report.timeline:
                print(
                    f"- tick {event.tick} [{event.source}] {event.kind} "
                    f"-> {event.target or '(none)'} {event.payload}"
                )
            print(f"Triggers fired: {report.triggers_fired}")
            print(f"Attacker moves blocked: {report.attacker_blocked}")
        return 0

    if args.command == "list-scoring-engines":
        from .scoring_engine import list_scoring_engines

        default_engine = "time_decay"
        for name in list_scoring_engines():
            marker = " (default)" if name == default_engine else ""
            print(f"{name}{marker}")
        return 0

    if args.command == "scoreboard":
        import datetime as _datetime

        from . import scoreboard as scoreboard_module
        from .scoring_engine import get_scoring_engine

        try:
            events = scoreboard_module.load_events(args.events)
            challenges = scoreboard_module.load_challenges(args.challenges)
            config = scoreboard_module.load_competition_config(args.config)
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
            print(f"Could not load scoreboard inputs: {exc}", file=sys.stderr)
            return 1

        engine_name = args.engine or "time_decay"
        try:
            engine = get_scoring_engine(engine_name)
        except KeyError as exc:
            print(str(exc), file=sys.stderr)
            return 1

        as_of = _datetime.datetime.fromisoformat(args.as_of) if args.as_of else None
        snapshot = scoreboard_module.compute_scoreboard(
            events, challenges, config, engine=engine, as_of=as_of
        )
        result = report_writer.serialize_scoreboard(snapshot)
        subject = {"type": "scoreboard", "identifier": config.competition_id}
        _write_cli_report(args, "scoreboard", subject, "passed", result)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"Scoreboard for {config.competition_id} (frozen={snapshot.frozen})")
            for entry in snapshot.entries:
                print(
                    f"{entry.rank}. {entry.team_id} - {entry.score} pts "
                    f"({entry.solve_count} solves)"
                )
        return 0

    if args.command == "eval-agent":
        from . import agent_eval

        subject = {"type": "challenge", "identifier": args.challenge_dir.name}
        if args.adversarial:
            delta_report = agent_eval.run_adversarial_delta(
                args.challenge_dir,
                args.profile,
                base_url=args.base_url,
            )
            result = report_writer.serialize_adversarial_delta(delta_report)
            _write_cli_report(args, "eval-agent", subject, "passed", result)
            print(
                f"Adversarial delta for {args.challenge_dir} [{args.profile}]"
            )
            print(
                f"  baseline:    solved={delta_report.baseline.solved} "
                f"steps={delta_report.baseline.steps}"
            )
            print(
                f"  adversarial: solved={delta_report.adversarial.solved} "
                f"steps={delta_report.adversarial.steps}"
            )
            print(
                f"  success_dropped={delta_report.success_dropped} "
                f"step_delta={delta_report.step_delta}"
            )
        else:
            eval_report = agent_eval.run_agent_eval(
                args.challenge_dir,
                args.profile,
                base_url=args.base_url,
            )
            result = report_writer.serialize_agent_eval(eval_report)
            _write_cli_report(args, "eval-agent", subject, "passed", result)
            print(
                f"Agent eval for {args.challenge_dir} [{args.profile}]: "
                f"solved={eval_report.solved} steps={eval_report.steps}"
            )
            for note in eval_report.notes:
                print(f"  {note}")
        return 0

    if args.command == "serve":
        from . import dashboard_server
        from .competition_service import CompetitionService

        service = _build_serve_service(args)
        auth = _build_serve_auth(args)
        if args.public_token is None:
            print(f"public scoreboard token: {auth.public_token}")
        server = dashboard_server.serve(
            args.host,
            args.port,
            service=service,
            auth=auth,
            secure_cookies=getattr(args, "secure_cookie", False),
        )
        print(f"Serving CTFGenerator dashboard on http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0

    if args.command == "catalog":
        entries = _build_challenge_catalog_entries(args.challenges_dir)
        payload = json.dumps(entries, indent=2, sort_keys=True)
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(payload + "\n", encoding="utf-8")
            print(f"Wrote catalog with {len(entries)} challenge(s) to {args.output}")
        else:
            print(payload)
        return 0

    if args.command == "quickstart":
        return _run_quickstart(args.output, args.seed)

    parser.error(f"unknown command: {args.command}")
    return 2


# --- CVE / scenario helpers (Phase 4 platform commands) -----------------------
#
# Appended, standalone helpers used only by the cve-*/create-from-cve/
# run-scenario dispatch branches above. Kept as plain functions (not methods)
# to match this module's existing style.


def _cve_categories() -> tuple[str, ...]:
    """Lazy import of ``cve_source.CATEGORIES`` (avoids a module-load-time
    dependency on cve_source for callers that never touch CVE commands)."""
    from . import cve_source

    return cve_source.CATEGORIES


def _build_cve_source(source_name: str, cache_dir: Path | None):
    """Build a ``CveSource`` for ``source_name``, optionally TTL-cached to disk."""
    from . import cve_source

    source = cve_source.get_source(source_name)
    if cache_dir is not None:
        source = cve_source.CachingCveSource(source, cache_dir)
    return source


def _scenario_spec_from_mapping(data: dict):
    """Parse a ``private/scenario_timeline.json``-shaped mapping into a
    ``models.ScenarioSpec``.

    Mirrors the inline scenario-parsing block in
    ``spec_generator.spec_from_dict`` (which parses a ``ChallengeSpec``'s
    nested ``"scenario"`` key), but operates directly on the flat mapping
    written by ``generator.create_challenge`` at
    ``private/scenario_timeline.json`` (i.e. ``ScenarioSpec.to_mapping()``
    itself, not a full spec). Duplicated rather than imported/refactored per
    this project's strict per-file ownership rules.
    """
    from .models import ResponseSpec, ScenarioSpec, TriggerSpec

    return ScenarioSpec(
        enabled=bool(data.get("enabled", False)),
        triggers=[
            TriggerSpec(
                trigger_id=str(t.get("trigger_id", "")),
                description=str(t.get("description", "")),
                condition=str(t.get("condition", "")),
            )
            for t in data.get("triggers", [])
            if isinstance(t, dict)
        ],
        responses=[
            ResponseSpec(
                response_id=str(r.get("response_id", "")),
                description=str(r.get("description", "")),
                action=str(r.get("action", "")),
                payload={str(k): str(v) for k, v in (r.get("payload") or {}).items()},
            )
            for r in data.get("responses", [])
            if isinstance(r, dict)
        ],
    )


def _run_scenario_command(challenge_dir: Path, max_ticks: int | None):
    """Run the pure, offline scenario engine for ``challenge_dir``.

    Reads ``private/scenario_timeline.json`` when present (the flat
    ``ScenarioSpec.to_mapping()`` written by ``generator.create_challenge``).
    Falls back to an empty/default ``ScenarioSpec`` (no triggers, disabled)
    when the file is absent -- there is no stdlib YAML reader in this project
    to round-trip ``challenge.yaml`` back into a full spec (see
    ``scenario.py``'s module docstring), so a challenge with no recorded
    timeline simply runs an inert scenario rather than erroring.

    Always offline and deterministic: ``NullEnvironmentController`` (records
    intent, touches nothing real) plus an empty ``ReplayEventSource`` (no
    exogenous events -- ``ScenarioSpec`` carries no separate event script).
    The defender is left to ``scenario.run_scenario``'s own
    ``_default_defender_from_spec`` derivation from the (possibly empty)
    scenario spec, per this command's brief.
    """
    from . import scenario as scenario_module
    from .models import ScenarioSpec

    timeline_path = Path(challenge_dir) / "private" / "scenario_timeline.json"
    if timeline_path.exists():
        data = json.loads(timeline_path.read_text(encoding="utf-8"))
        scenario_spec = _scenario_spec_from_mapping(data)
    else:
        scenario_spec = ScenarioSpec()

    environment = scenario_module.NullEnvironmentController()
    event_source = scenario_module.ReplayEventSource({})
    return scenario_module.run_scenario(
        challenge_path=challenge_dir,
        environment=environment,
        events=event_source,
        spec=scenario_spec,
        max_ticks=max_ticks,
    )


def _serialize_scenario_report(report) -> dict:
    """JSON-safe mapping for a ``scenario.ScenarioRunReport``."""
    final_state = report.final_state
    return {
        "challenge_path": report.challenge_path,
        "ticks_run": report.ticks_run,
        "timeline": [event.to_mapping() for event in report.timeline],
        "triggers_fired": list(report.triggers_fired),
        "responses_applied": [
            {
                "tick": record.tick,
                "role": record.role,
                "response_id": record.response_id,
                "action": record.action,
                "target": record.target,
            }
            for record in report.responses_applied
        ],
        "attacker_blocked": list(report.attacker_blocked),
        "final_state": (
            {
                "tick": final_state.tick,
                "checkpoints": sorted(final_state.checkpoints),
                "flags": dict(final_state.flags),
                "fired_triggers": sorted(final_state.fired_triggers),
                "noise_count": final_state.noise_count,
            }
            if final_state is not None
            else None
        ),
    }


# --- eval-agent / serve helpers (Phase 5 platform commands) ------------------
#
# Appended, standalone helpers used only by the eval-agent/serve dispatch
# branches above. The service/auth builders are split out of the `serve`
# dispatch branch specifically so they're unit-testable without opening a
# real socket (constructing a CompetitionService/AuthConfig touches only
# JSON files / in-memory defaults, never Docker/network/sockets).


def _default_serve_config():
    """A permissive placeholder ``CompetitionConfig`` for ``serve`` when
    ``--config`` is omitted: a single wide-open, always-scoring window
    starting now and running for a year."""
    import datetime as _datetime

    from .models import CompetitionConfig

    now = _datetime.datetime.now(_datetime.timezone.utc)
    return CompetitionConfig(
        competition_id="ctfgen-live",
        name="CTFGenerator Live",
        start_time=now,
        end_time=now + _datetime.timedelta(days=365),
    )


def _build_serve_service(args: argparse.Namespace):
    """Build the ``CompetitionService`` for ``serve`` from CLI args.

    Store: ``JsonlEventStore`` (persisted) when ``--events-file`` is given,
    else a volatile ``InMemoryEventStore``. Catalog: parsed from
    ``--challenges`` (reusing ``scoreboard.load_challenges`` for the
    ``ChallengeScoringConfig`` shape, wrapped in bare ``ChallengeMeta``s -- no
    separate title/category/mode JSON shape is introduced) when given, else
    an empty catalog. Config: parsed from ``--config`` (reusing
    ``scoreboard.load_competition_config``) when given, else
    :func:`_default_serve_config`.
    """
    from . import events
    from .competition_service import ChallengeCatalog, ChallengeMeta, CompetitionService
    from .scoreboard import load_challenges, load_competition_config

    events_file = getattr(args, "events_file", None)
    store = (
        events.JsonlEventStore(events_file)
        if events_file is not None
        else events.InMemoryEventStore()
    )

    # --challenges-dir guarded pre-step (additive alternative to
    # --challenges FILE): when given, build the catalog in-process from the
    # directory and return immediately, leaving the existing
    # --challenges/empty-catalog logic below completely untouched.
    challenges_dir = getattr(args, "challenges_dir", None)
    if challenges_dir is not None:
        catalog = _build_challenge_catalog_from_dir(challenges_dir)
        config_path = getattr(args, "config", None)
        config = (
            load_competition_config(config_path)
            if config_path is not None
            else _default_serve_config()
        )
        return CompetitionService(store=store, catalog=catalog, config=config)

    challenges_path = getattr(args, "challenges", None)
    if challenges_path is not None:
        scoring_configs = load_challenges(challenges_path)
        catalog = ChallengeCatalog.from_entries(
            {
                challenge_id: ChallengeMeta(scoring=scoring)
                for challenge_id, scoring in scoring_configs.items()
            }
        )
    else:
        catalog = ChallengeCatalog()

    config_path = getattr(args, "config", None)
    config = load_competition_config(config_path) if config_path is not None else _default_serve_config()

    return CompetitionService(store=store, catalog=catalog, config=config)


def _build_serve_auth(args: argparse.Namespace):
    """Build the dashboard ``AuthConfig`` for ``serve`` from CLI args."""
    from .dashboard_server import AuthConfig

    return AuthConfig.create(
        admin_username=args.admin_user,
        password=args.admin_password,
        public_token=getattr(args, "public_token", None),
    )


# --- catalog / quickstart onboarding helpers ----------------------------------
#
# Appended, standalone helpers used only by the catalog/quickstart dispatch
# branches above and by the `serve --challenges-dir` pre-step in
# _build_serve_service. Everything here is pure filesystem scanning + stdlib
# json/string parsing -- no network, Docker, or clock use, so it is fully
# exercisable offline in tests.


def _iter_challenge_dirs(challenges_dir: Path) -> list[Path]:
    """Find generated-challenge folders under ``challenges_dir``.

    A "generated challenge folder" is any directory directly containing a
    ``challenge.yaml`` (the file ``generator.create_challenge`` always
    writes). Looks at immediate subdirectories of ``challenges_dir`` first
    (the normal case: a directory of several challenges, as produced by
    ``quickstart``); if none qualify, falls back to treating
    ``challenges_dir`` itself as a single challenge when *it* directly
    contains a ``challenge.yaml``. Returns an empty list for a missing/empty
    directory rather than raising, since ``catalog``/``serve
    --challenges-dir`` should degrade to an empty catalog, not crash.
    """
    challenges_dir = Path(challenges_dir)
    if not challenges_dir.is_dir():
        return []
    subdirs = sorted(
        (p for p in challenges_dir.iterdir() if p.is_dir() and (p / "challenge.yaml").is_file()),
        key=lambda p: p.name,
    )
    if subdirs:
        return subdirs
    if (challenges_dir / "challenge.yaml").is_file():
        return [challenges_dir]
    return []


def _parse_yaml_scalar_field(text: str, key: str) -> str:
    """Best-effort extraction of a single top-level, double-quoted scalar
    field (e.g. ``title``/``category``) from a ``challenge.yaml`` file
    written by ``yaml_writer.dump_yaml``.

    This project has no stdlib YAML reader (see
    ``_run_scenario_command``'s docstring for the same constraint elsewhere
    in this module) and only ever needs to recover a couple of known-scalar,
    unindented top-level keys here -- not round-trip a full spec. Returns
    "" when the key is absent or not a plain quoted scalar.
    """
    prefix = f'{key}: "'
    for line in text.splitlines():
        if line.startswith(prefix) and line.endswith('"'):
            raw = line[len(prefix) : -1]
            return raw.replace('\\"', '"').replace("\\\\", "\\")
    return ""


def _build_challenge_catalog_entries(challenges_dir: Path) -> list[dict]:
    """Scan ``challenges_dir`` and build one ChallengeScoringConfig-shaped
    dict per generated challenge found (default scoring values,
    ``challenge_id`` = the challenge's folder name), with ``title`` and
    ``category`` display fields appended.

    The extra ``title``/``category`` keys are silently ignored by
    ``scoreboard.load_challenges`` (``_parse_challenge_scoring`` only reads
    its known ``ChallengeScoringConfig`` fields), so the returned list is
    still a valid ``serve --challenges``/``scoreboard --challenges`` JSON
    input as-is, while also carrying enough display metadata for a human
    skimming the catalog file.
    """
    from .models import ChallengeScoringConfig

    entries: list[dict] = []
    for challenge_path in _iter_challenge_dirs(Path(challenges_dir)):
        text = (challenge_path / "challenge.yaml").read_text(encoding="utf-8")
        mapping = ChallengeScoringConfig(challenge_id=challenge_path.name).to_mapping()
        mapping["title"] = _parse_yaml_scalar_field(text, "title")
        mapping["category"] = _parse_yaml_scalar_field(text, "category")
        entries.append(mapping)
    return entries


def _build_challenge_catalog_from_dir(challenges_dir: Path):
    """Build a ``competition_service.ChallengeCatalog`` directly from a
    directory of generated challenge folders -- the in-process equivalent of
    writing ``_build_challenge_catalog_entries``'s output to a file and
    re-reading it via ``scoreboard.load_challenges``, except it keeps the
    ``title``/``category`` metadata that a JSON round-trip through
    ``load_challenges`` would drop.
    """
    from .competition_service import ChallengeCatalog, ChallengeMeta
    from .models import ChallengeScoringConfig

    entries: dict[str, ChallengeMeta] = {}
    for mapping in _build_challenge_catalog_entries(challenges_dir):
        challenge_id = str(mapping["challenge_id"])
        entries[challenge_id] = ChallengeMeta(
            scoring=ChallengeScoringConfig(challenge_id=challenge_id),
            title=str(mapping.get("title", "")),
            category=str(mapping.get("category", "")),
        )
    return ChallengeCatalog.from_entries(entries)


def _run_quickstart(output_dir: Path, seed: str) -> int:
    """Generate a small, deterministic sample catalog spanning a few domains
    (web, crypto, a real CVE) into ``output_dir``, then print the exact next
    commands to build a catalog and serve the dashboard.

    Deliberately offline/no-Docker: three plain ``create_challenge``/
    ``create_challenge_from_cve`` calls (same functions ``create``/
    ``create-from-cve`` use), each ``force=True`` so re-running quickstart
    with the same ``--output`` is idempotent rather than erroring.
    """
    from .generator import create_challenge_from_cve

    output_dir = Path(output_dir)
    samples = (
        ("web", output_dir / "web-sample", "web_business_logic_tenant_export"),
        ("crypto", output_dir / "crypto-sample", "crypto_token_forgery"),
    )
    created: list[tuple[str, Path]] = []
    for domain, sample_dir, family in samples:
        create_challenge(
            output_dir=sample_dir,
            seed=f"{seed}-{domain}",
            title=f"Quickstart {domain.title()} Sample",
            difficulty="easy",
            family=family,
            force=True,
        )
        created.append((domain, sample_dir))

    cve_dir = output_dir / "cve-log4shell-sample"
    cve_source = _build_cve_source("snapshot", cache_dir=None)
    create_challenge_from_cve(
        output_dir=cve_dir,
        cve_id="CVE-2021-44228",
        base_seed=f"{seed}-cve",
        difficulty="easy",
        title="Quickstart Log4Shell Sample",
        force=True,
        source=cve_source,
    )
    created.append(("cve", cve_dir))

    print(f"Generated {len(created)} sample challenge(s) under {output_dir}:")
    for domain, path in created:
        print(f"  [{domain}] {path}")

    catalog_path = output_dir / "catalog.json"
    print()
    print("Next steps:")
    print(f"  ctfgen catalog --challenges-dir {output_dir} -o {catalog_path}")
    print(
        "  ctfgen serve --admin-user admin --admin-password <password> "
        f"--challenges {catalog_path}"
    )
    print(
        "  (or skip the catalog file entirely: ctfgen serve --admin-user admin "
        f"--admin-password <password> --challenges-dir {output_dir})"
    )
    print(
        "Then open http://127.0.0.1:8000/ for the admin dashboard and "
        "http://127.0.0.1:8000/public/scoreboard (or /public/feed) for the "
        "public scoreboard -- no external CDN/scripts, everything is served "
        "inline by the stdlib http.server."
    )
    return 0
