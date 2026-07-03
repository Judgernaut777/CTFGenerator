"""MCP server exposing CTFGenerator's safe, deterministic tools.

Running CTFGenerator as an MCP *server* lets an MCP host (Claude Desktop/Code,
or any other client) drive challenge generation with the model the user already
pays for -- the host's model drafts the pedagogical metadata and calls these
tools; the LLM never lives in CTFGenerator and no API key is needed.

Security boundary: only pure, side-effect-bounded tools are exposed here.
Everything that shells out to Docker (`validate-runtime`, `replay`,
`validate-siblings --runtime`) stays CLI-only, so connecting a model host to
this server never hands it container builds or host execution. The tools below
either compute in-process or write plain files under a caller-named directory.

The tool bodies are plain functions so they are unit-testable without the
optional `mcp` dependency; ``build_server`` wires them into a FastMCP instance
lazily, and ``main`` runs it over stdio.
"""

from __future__ import annotations

from pathlib import Path

from . import report_index, spec_generator
from .generator import create_challenge as _create_challenge
from .score import score_challenge as _score_challenge
from .validator import validate_challenge as _validate_challenge

# The design guidance handed to a host model before it calls build_spec. It is
# exposed as an MCP prompt so an interactive client can prime the model with the
# safety boundary this server enforces.
DESIGN_PROMPT = (
    "You are drafting a capture-the-flag challenge spec through the CTFGenerator "
    "MCP server. You supply ONLY human-facing pedagogical metadata: a title, "
    "learning objectives, and ordered solve-path checkpoints. You never write "
    "code, exploits, flags, routes, or the security-relevant AI-resistance "
    "knobs -- those are generated deterministically by the server. Call "
    "list_families and spec_schema first, then build_spec with your drafted "
    "metadata, then create_from_spec to render the challenge."
)


# --- Pure tool implementations ------------------------------------------------


def list_families() -> dict:
    """List the challenge families and difficulty levels the generator supports."""
    return {
        "families": list(spec_generator.FAMILIES),
        "difficulties": list(spec_generator.DIFFICULTIES),
    }


def spec_schema() -> dict:
    """Return the JSON schema for the metadata a host model drafts for a spec."""
    return {
        "metadata_schema": spec_generator._LLM_SCHEMA,
        "families": list(spec_generator.FAMILIES),
        "difficulties": list(spec_generator.DIFFICULTIES),
        "note": (
            "Provide only title, learning_objectives, and checkpoints. Security "
            "knobs (ai_resistance, dynamic_variation) are fixed by the server."
        ),
    }


def build_spec(
    family: str,
    difficulty: str,
    seed: str,
    title: str = "",
    learning_objectives: list[str] | None = None,
    checkpoints: list[str] | None = None,
) -> dict:
    """Assemble and validate a challenge spec from host-supplied metadata.

    The host model provides the pedagogical fields; this merges them with the
    fixed, safety-relevant defaults and validates the result. If no metadata is
    supplied, the deterministic built-in spec for the family is used.
    """
    if family not in spec_generator.FAMILIES:
        return {"ok": False, "errors": [f"unknown family: {family}"]}
    if difficulty not in spec_generator.DIFFICULTIES:
        return {"ok": False, "errors": [f"unknown difficulty: {difficulty}"]}

    if learning_objectives or checkpoints or title:
        spec = spec_generator.spec_from_llm_output(
            {
                "title": title,
                "learning_objectives": learning_objectives or [],
                "checkpoints": checkpoints or [],
            },
            family=family,
            difficulty=difficulty,
            seed=seed,
            fallback_title=title or "Untitled Challenge",
        )
    else:
        spec = spec_generator.default_spec(
            seed=seed, title=title or "Invoice Drift", difficulty=difficulty, family=family
        )

    errors = spec_generator.validate_spec(spec)
    return {
        "ok": not errors,
        "errors": errors,
        "spec": spec_generator.spec_to_dict(spec),
    }


def validate_spec(spec: dict) -> dict:
    """Structurally validate a spec dict before it is rendered."""
    errors = spec_generator.validate_spec(spec_generator.spec_from_dict(spec))
    return {"ok": not errors, "errors": errors}


def create_from_spec(spec: dict, output_dir: str, force: bool = False) -> dict:
    """Render a challenge folder from a spec dict. Filesystem-only, no Docker."""
    parsed = spec_generator.spec_from_dict(spec)
    errors = spec_generator.validate_spec(parsed)
    if errors:
        return {"ok": False, "errors": errors}
    try:
        path = _create_challenge(
            output_dir=Path(output_dir),
            seed=parsed.seed,
            title=parsed.title,
            difficulty=parsed.difficulty,
            family=parsed.family,
            force=force,
            spec=parsed,
        )
    except FileExistsError as exc:
        return {"ok": False, "errors": [str(exc)]}
    return {"ok": True, "output_dir": str(path)}


def create_challenge(
    output_dir: str,
    seed: str,
    title: str = "Invoice Drift",
    difficulty: str = "medium",
    family: str = spec_generator.FAMILIES[0],
    force: bool = False,
) -> dict:
    """Render a challenge folder deterministically from a seed. No Docker."""
    if family not in spec_generator.FAMILIES:
        return {"ok": False, "errors": [f"unknown family: {family}"]}
    if difficulty not in spec_generator.DIFFICULTIES:
        return {"ok": False, "errors": [f"unknown difficulty: {difficulty}"]}
    try:
        path = _create_challenge(
            output_dir=Path(output_dir),
            seed=seed,
            title=title,
            difficulty=difficulty,
            family=family,
            force=force,
        )
    except FileExistsError as exc:
        return {"ok": False, "errors": [str(exc)]}
    return {"ok": True, "output_dir": str(path)}


def validate_challenge(challenge_dir: str) -> dict:
    """Run static artifact validation on a generated challenge folder."""
    report = _validate_challenge(Path(challenge_dir))
    return {
        "ok": not report.errors,
        "errors": report.errors,
        "warnings": report.warnings,
    }


def score_challenge(challenge_dir: str) -> dict:
    """Score a generated challenge on the AI-resistance dimensions."""
    return _score_challenge(Path(challenge_dir)).to_mapping()


def report_index_table(report_dir: str) -> dict:
    """Summarize persisted JSON report artifacts in a directory as a table."""
    index = report_index.load_index(Path(report_dir))
    return {"table": report_index.render_table(index)}


# Ordered so build_server and the docs share one source of truth.
TOOLS = [
    list_families,
    spec_schema,
    build_spec,
    validate_spec,
    create_from_spec,
    create_challenge,
    validate_challenge,
    score_challenge,
    report_index_table,
]


def build_server(name: str = "ctfgenerator"):  # pragma: no cover - needs mcp
    """Construct a FastMCP server with every safe tool and the design prompt.

    Imported lazily so the pure tool functions above stay usable (and testable)
    without the optional ``mcp`` dependency installed.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        raise RuntimeError(
            "the MCP server requires the 'mcp' package; install it with "
            "'pip install ctf-generator[mcp]'"
        ) from None

    server = FastMCP(name)
    for tool in TOOLS:
        server.add_tool(tool)

    @server.prompt()
    def design_challenge() -> str:
        """Guidance for drafting a challenge spec within the safety boundary."""
        return DESIGN_PROMPT

    return server


def main() -> None:  # pragma: no cover - process entry point
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
