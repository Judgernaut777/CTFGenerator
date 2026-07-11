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

import dataclasses
import json
import os
from pathlib import Path

from . import families, report_index, schema, spec_generator
from .generator import create_challenge as _create_challenge
from .score import score_challenge as _score_challenge
from .validator import validate_challenge as _validate_challenge

# --- Filesystem sandbox -------------------------------------------------------
#
# The write tools (create_challenge / create_from_spec) render files to a
# caller-named directory and, with force=True, ``shutil.rmtree`` it first. A
# model host is only semi-trusted (prompt injection, a manipulated turn), so an
# unconstrained ``output_dir`` would be an arbitrary host write + recursive
# delete primitive. All caller paths are therefore resolved against a workspace
# root and rejected if they escape it (absolute paths outside the root or ``..``
# traversal). The root defaults to the process CWD and is overridable via the
# ``CTFGEN_MCP_WORKSPACE`` env var (or ``set_workspace_root`` in tests).


class WorkspaceError(ValueError):
    """Raised when a caller path escapes the configured MCP workspace root."""


_workspace_root: Path = Path(os.environ.get("CTFGEN_MCP_WORKSPACE") or Path.cwd()).resolve()


def set_workspace_root(path: str | Path) -> None:
    """Set the sandbox root that all MCP tool paths must resolve inside."""
    global _workspace_root
    _workspace_root = Path(path).resolve()


def get_workspace_root() -> Path:
    return _workspace_root


def _resolve_in_workspace(user_path: str) -> Path:
    root = _workspace_root
    candidate = Path(user_path)
    combined = candidate if candidate.is_absolute() else root / candidate
    resolved = combined.resolve()
    if resolved != root and root not in resolved.parents:
        raise WorkspaceError(
            f"path {user_path!r} escapes the MCP workspace root {root}. MCP "
            "tools may only write inside the workspace; set CTFGEN_MCP_WORKSPACE "
            "to relocate it."
        )
    return resolved

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
    mode: str = "red",
    cve_refs: list[str] | None = None,
) -> dict:
    """Assemble and validate a challenge spec from host-supplied metadata.

    The host model provides the pedagogical fields; this merges them with the
    fixed, safety-relevant defaults and validates the result. If no metadata is
    supplied, the deterministic built-in spec for the family is used.

    ``mode`` and ``cve_refs`` are optional and default to today's plain
    behavior ("red" mode, no CVE grounding) so existing callers are
    unaffected. When supplied, they are validated by
    ``spec_generator.validate_spec`` -- ``mode`` must be one of the family's
    declared modes and each ``cve_refs`` entry must match ``CVE-YYYY-NNNN+``.
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

    if mode != "red" or cve_refs:
        spec = dataclasses.replace(spec, mode=mode, cve_refs=list(cve_refs or []))

    errors = spec_generator.validate_spec(spec)
    return {
        "ok": not errors,
        "errors": errors,
        "spec": spec_generator.spec_to_dict(spec),
    }


def validate_spec(spec: dict) -> dict:
    """Structurally validate a spec dict before it is rendered."""
    try:
        parsed = spec_generator.spec_from_dict(spec)
    except schema.SchemaError as exc:
        # An incompatible/malformed schema stamp is a validation failure, not a
        # crash: fold it into the structured error list like any other.
        return {"ok": False, "errors": [str(exc)]}
    errors = spec_generator.validate_spec(parsed)
    return {"ok": not errors, "errors": errors}


def create_from_spec(
    spec: dict,
    output_dir: str,
    force: bool = False,
    mode: str | None = None,
    cve_refs: list[str] | None = None,
) -> dict:
    """Render a challenge folder from a spec dict. Filesystem-only, no Docker.

    ``mode``/``cve_refs`` are optional overrides applied on top of whatever
    the ``spec`` dict already carries (it may already have its own "mode"/
    "cve_refs" keys, e.g. from ``build_spec``). Left as ``None`` (the
    default), the spec dict is used exactly as given -- existing callers are
    unaffected. Either way the result is validated by
    ``spec_generator.validate_spec`` before anything is rendered.
    """
    try:
        parsed = spec_generator.spec_from_dict(spec)
    except schema.SchemaError as exc:
        return {"ok": False, "errors": [str(exc)]}
    if mode is not None or cve_refs is not None:
        parsed = dataclasses.replace(
            parsed,
            mode=mode if mode is not None else parsed.mode,
            cve_refs=list(cve_refs) if cve_refs is not None else parsed.cve_refs,
        )
    errors = spec_generator.validate_spec(parsed)
    if errors:
        return {"ok": False, "errors": errors}
    try:
        safe_output_dir = _resolve_in_workspace(output_dir)
    except WorkspaceError as exc:
        return {"ok": False, "errors": [str(exc)]}
    try:
        path = _create_challenge(
            output_dir=safe_output_dir,
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
    mode: str = "red",
    cve_refs: list[str] | None = None,
) -> dict:
    """Render a challenge folder deterministically from a seed. No Docker.

    ``mode``/``cve_refs`` default to today's plain behavior, so calls that
    omit them render byte-identically to before these params existed: the
    server falls back to the exact same code path (``spec=None``) that
    ``generator.create_challenge`` already used internally. Only when a
    non-default ``mode`` or a non-empty ``cve_refs`` is supplied is a spec
    built up front (and validated) to carry them through.
    """
    if family not in spec_generator.FAMILIES:
        return {"ok": False, "errors": [f"unknown family: {family}"]}
    if difficulty not in spec_generator.DIFFICULTIES:
        return {"ok": False, "errors": [f"unknown difficulty: {difficulty}"]}

    spec = None
    if mode != "red" or cve_refs:
        spec = dataclasses.replace(
            spec_generator.default_spec(
                seed=seed, title=title, difficulty=difficulty, family=family
            ),
            mode=mode,
            cve_refs=list(cve_refs or []),
        )
        errors = spec_generator.validate_spec(spec)
        if errors:
            return {"ok": False, "errors": errors}

    try:
        safe_output_dir = _resolve_in_workspace(output_dir)
    except WorkspaceError as exc:
        return {"ok": False, "errors": [str(exc)]}
    try:
        path = _create_challenge(
            output_dir=safe_output_dir,
            seed=seed,
            title=title,
            difficulty=difficulty,
            family=family,
            force=force,
            spec=spec,
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


def family_info(name: str) -> dict:
    """Return read-only registry metadata for a single challenge family.

    Pure lookup against the in-process family registry -- no rendering, no
    filesystem access.
    """
    if not families.is_registered(name):
        return {"ok": False, "errors": [f"unknown family: {name}"]}
    fam = families.get(name)
    return {
        "ok": True,
        "name": fam.name,
        "category": fam.category,
        "modes": list(fam.modes),
        "difficulties": list(fam.difficulties),
        "cve_driven": fam.cve_driven,
        "llm_brief": fam.llm_brief,
        "required_files": list(fam.required_files),
    }


def list_cves(category: str | None = None, keyword: str | None = None, limit: int = 10) -> dict:
    """List curated CVE records from the bundled offline snapshot only.

    Always uses ``cve_source.get_source("snapshot")`` -- the deterministic,
    offline fixture backend. There is deliberately no way to select an
    ``nvd`` (network-fetching) or other source over MCP: this tool stays
    read-only and side-effect-free regardless of caller input.
    """
    from .cve_source import get_source

    source = get_source("snapshot")
    records = source.fetch(category=category, keyword=keyword, limit=limit)
    return {"cves": [record.to_mapping() for record in records]}


def scenario_timeline_summary(challenge_dir: str) -> dict:
    """Summarize a generated challenge's private/scenario_timeline.json.

    Read-only: parses the JSON file already written by ``create_challenge``/
    ``create_from_spec`` for scenario-enabled specs. Returns a compact
    summary (trigger/response counts, enabled flag) with no code execution.
    Returns ``present: False`` when the file does not exist (e.g. a non-
    scenario challenge).
    """
    path = Path(challenge_dir) / "private" / "scenario_timeline.json"
    if not path.exists():
        return {"ok": True, "present": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"ok": False, "errors": [str(exc)]}
    triggers = data.get("triggers") or []
    responses = data.get("responses") or []
    return {
        "ok": True,
        "present": True,
        "enabled": bool(data.get("enabled", False)),
        "trigger_count": len(triggers),
        "response_count": len(responses),
    }


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
    family_info,
    list_cves,
    scenario_timeline_summary,
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
