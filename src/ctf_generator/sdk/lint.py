"""Structural linter for challenge families and renderer modules.

The generator core is only as trustworthy as the families feeding it. A family
author (built-in or third-party) needs a fast, deterministic, offline check that
their family upholds the same invariants the release gates enforce on the
built-ins -- WITHOUT launching Docker or writing to disk. ``lint_family`` renders
a family for a representative default spec and asserts:

* (a) the rendered bundle contains every path the family declares in
  ``required_files`` (``MISSING_REQUIRED_FILE``);
* (b) every emitted relative path passes :func:`build.validate_relative_path`
  (no absolute/traversal/control/bidi/reserved path -- ``UNSAFE_PATH``) and lives
  under an allowed root (``public/`` ``private/`` ``services/`` ``tests/`` or the
  top-level ``challenge.yaml`` / ``docker-compose.yml`` -- ``PATH_OUTSIDE_ROOT``);
* (c) no private content leaks into ``public/`` -- the exact invariant
  ``tests/test_baseline_fixtures.py::test_no_private_content_leaks_into_public``
  enforces (identical private/public file bytes) PLUS a flag-token scan so a
  family that prints the flag into a player-facing file is caught
  (``PRIVATE_CONTENT_IN_PUBLIC``);
* (d) the capability metadata is well-formed: a valid semver ``version``
  (``BAD_VERSION``), a known ``maintenance_status`` (``BAD_MAINTENANCE_STATUS``)
  and ``isolation_level`` (``BAD_ISOLATION_LEVEL``), a non-empty ``modes`` subset
  of the known modes (``BAD_MODES``), and a non-empty ``category``
  (``EMPTY_CATEGORY``).

``lint_renderer_module`` adds (e): an AST check that a renderer *module* does not
import ``ctf_generator.families`` -- the circular-import contract that keeps a
template importable by ``families.py`` (``MODULE_IMPORTS_FAMILIES``).

Everything here is pure: stdlib ``ast``/``hashlib``/``re`` plus the existing
``build``/``schema`` validators. It renders in-memory and never writes a build.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import random
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .. import build, schema
from ..families import Family
from ..models import ChallengeSpec, ScenarioSpec

if TYPE_CHECKING:  # pragma: no cover
    from ..families import Family as _Family  # noqa: F401

# Recognized challenge modes (the union of every built-in family's declared
# modes: red/blue/purple). A family's ``modes`` must be a non-empty subset.
KNOWN_MODES = frozenset({"red", "blue", "purple"})
# Allowed maintenance tiers (docs/MATURITY.md) and isolation levels (the
# ``Family.isolation_level`` contract).
KNOWN_MAINTENANCE_STATUS = frozenset({"stable", "beta", "experimental"})
KNOWN_ISOLATION_LEVELS = frozenset({"container", "raw_tcp", "artifact"})

# Top-level roots a renderer may write under, plus the allowed top-level files.
# This is the legitimate bundle layout the built-in families establish:
# player-facing ``public/``, answer material ``private/``, buildable ``services/``,
# harness ``tests/``, and blue-team ``detection/`` rules. ``challenge.yaml`` is
# injected by ``generator.create_challenge`` (renderers do not emit it), so it is
# allowed as an effective-bundle member; ``docker-compose.yml`` orchestrates the
# services and ``.env.example`` documents its environment.
_ALLOWED_ROOTS = frozenset({"public", "private", "services", "tests", "detection"})
_ALLOWED_TOPLEVEL_FILES = frozenset(
    {"challenge.yaml", "docker-compose.yml", ".env.example"}
)

# A concrete flag token (``ctf{...}`` with an alphanumeric/underscore/hyphen
# body). Deliberately excludes the ``ctf{...}`` *format placeholder* (dots), so a
# public "the flag looks like ctf{...}" hint is not mistaken for a real secret.
_FLAG_RE = re.compile(r"ctf\{[0-9A-Za-z_\-]+\}")

_DEFAULT_SAMPLE_SEED = "ctfgen-sdk-lint-0001"


@dataclass(frozen=True)
class LintIssue:
    """One structural finding. ``severity`` is ``"error"`` or ``"warning"``."""

    code: str
    message: str
    severity: str = "error"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"[{self.severity}:{self.code}] {self.message}"


class FamilyLintError(Exception):
    """Raised by :func:`assert_family_ok` when a family has error-severity issues."""

    def __init__(self, issues: list[LintIssue]) -> None:
        self.issues = list(issues)
        joined = "; ".join(str(i) for i in self.issues)
        super().__init__(f"family failed structural lint: {joined}")


def _seed_int(seed: str) -> int:
    # Matches generator._seed_int so lint renders through the same seeding a real
    # build would use.
    return int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16], 16)


def _sample_spec(family: Family, seed: str) -> ChallengeSpec:
    """A representative :class:`ChallengeSpec` for ``family``, built directly from
    the family's own declared metadata (so linting does not require the family to
    already be registered -- the loader lints BEFORE it registers)."""
    return ChallengeSpec(
        title="SDK Lint Sample",
        category=family.category or "web",
        difficulty=(family.difficulties[0] if family.difficulties else "medium"),
        family=family.name,
        seed=seed,
        learning_objectives=list(family.learning_objectives),
        checkpoints=list(family.checkpoints),
        scenario=(family.default_scenario or ScenarioSpec()),
        mode=(family.modes[0] if family.modes else "red"),
    )


def _effective_paths(rendered: dict[str, str], spec: ChallengeSpec) -> set[str]:
    """The full on-disk path set a build would publish: the renderer output plus
    the files ``generator.create_challenge`` injects (``challenge.yaml`` always;
    ``private/scenario_timeline.json`` when the scenario is enabled)."""
    paths = set(rendered)
    paths.add("challenge.yaml")
    if spec.scenario.enabled:
        paths.add("private/scenario_timeline.json")
    return paths


def _check_metadata(family: Family) -> list[LintIssue]:
    issues: list[LintIssue] = []
    try:
        schema.parse_semver(family.version)
    except schema.SchemaError as exc:
        issues.append(LintIssue("BAD_VERSION", f"invalid family version: {exc}"))
    if family.maintenance_status not in KNOWN_MAINTENANCE_STATUS:
        issues.append(
            LintIssue(
                "BAD_MAINTENANCE_STATUS",
                f"maintenance_status {family.maintenance_status!r} not in "
                f"{sorted(KNOWN_MAINTENANCE_STATUS)}",
            )
        )
    if family.isolation_level not in KNOWN_ISOLATION_LEVELS:
        issues.append(
            LintIssue(
                "BAD_ISOLATION_LEVEL",
                f"isolation_level {family.isolation_level!r} not in "
                f"{sorted(KNOWN_ISOLATION_LEVELS)}",
            )
        )
    if not family.modes:
        issues.append(LintIssue("BAD_MODES", "modes is empty"))
    else:
        unknown = [m for m in family.modes if m not in KNOWN_MODES]
        if unknown:
            issues.append(
                LintIssue(
                    "BAD_MODES",
                    f"modes {unknown} are not among the known modes {sorted(KNOWN_MODES)}",
                )
            )
    if not (family.category or "").strip():
        issues.append(LintIssue("EMPTY_CATEGORY", "category is empty"))
    return issues


def _check_paths(rendered: dict[str, str]) -> list[LintIssue]:
    issues: list[LintIssue] = []
    for rel in rendered:
        try:
            norm = build.validate_relative_path(rel)
        except build.PathValidationError as exc:
            issues.append(LintIssue("UNSAFE_PATH", f"unsafe rendered path {rel!r}: {exc}"))
            continue
        top = norm.split("/", 1)[0]
        if norm in _ALLOWED_TOPLEVEL_FILES:
            continue
        if "/" not in norm or top not in _ALLOWED_ROOTS:
            issues.append(
                LintIssue(
                    "PATH_OUTSIDE_ROOT",
                    f"rendered path {norm!r} is not under an allowed root "
                    f"({sorted(_ALLOWED_ROOTS)}) or a top-level "
                    f"{sorted(_ALLOWED_TOPLEVEL_FILES)}",
                )
            )
    return issues


def _extract_variant_flags(rendered: dict[str, str]) -> set[str]:
    """Pull declared flag value(s) out of a ``private/variant.json`` if present."""
    flags: set[str] = set()
    raw = rendered.get("private/variant.json")
    if not raw:
        return flags

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "flag" and isinstance(value, str):
                    flags.add(value)
                _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    try:
        _walk(json.loads(raw))
    except (ValueError, TypeError):
        pass
    return flags


def _check_private_leak(rendered: dict[str, str]) -> list[LintIssue]:
    issues: list[LintIssue] = []
    private = {p: c for p, c in rendered.items() if p.startswith("private/")}
    public = {p: c for p, c in rendered.items() if p.startswith("public/")}

    # (c1) exact-content leak: identical bytes under private/ and public/ -- the
    # invariant test_no_private_content_leaks_into_public enforces on the golden
    # baseline, applied here to a freshly rendered bundle.
    def _digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    private_hashes = {_digest(c): p for p, c in private.items()}
    for pub_path, pub_content in public.items():
        priv_path = private_hashes.get(_digest(pub_content))
        if priv_path is not None:
            issues.append(
                LintIssue(
                    "PRIVATE_CONTENT_IN_PUBLIC",
                    f"public file {pub_path!r} is byte-identical to private file "
                    f"{priv_path!r}",
                )
            )

    # (c2) flag-token leak: any concrete flag token that appears in a private
    # file must not appear verbatim in any public file (a description leaking the
    # answer). Secrets are the variant.json flag(s) plus flag tokens scanned from
    # private files.
    secrets: set[str] = _extract_variant_flags(rendered)
    for content in private.values():
        secrets.update(_FLAG_RE.findall(content))
    for secret in sorted(secrets):
        for pub_path, pub_content in public.items():
            if secret and secret in pub_content:
                issues.append(
                    LintIssue(
                        "PRIVATE_CONTENT_IN_PUBLIC",
                        f"public file {pub_path!r} leaks the private flag token "
                        f"{secret!r}",
                    )
                )
    return issues


def lint_family(family: Family, *, sample_seed: str = _DEFAULT_SAMPLE_SEED) -> list[LintIssue]:
    """Structurally lint ``family`` by rendering it for a default sample spec.

    Returns a list of :class:`LintIssue` (empty when the family is clean). Never
    raises for a *family-level* defect -- a render that crashes is reported as an
    error-severity ``RENDER_FAILED`` issue so a broken family is a finding, not an
    exception (the loader depends on this to fail-safe).
    """
    issues: list[LintIssue] = []
    issues.extend(_check_metadata(family))

    spec = _sample_spec(family, sample_seed)
    rng = random.Random(_seed_int(sample_seed))  # noqa: S311 - deterministic render seeding, not crypto
    try:
        rendered = dict(family.render(spec, rng, None))
    except Exception as exc:  # noqa: BLE001 - a broken renderer is a finding
        issues.append(
            LintIssue("RENDER_FAILED", f"render() raised {type(exc).__name__}: {exc}")
        )
        return issues

    issues.extend(_check_paths(rendered))
    issues.extend(_check_private_leak(rendered))

    effective = _effective_paths(rendered, spec)
    for rel in family.required_files:
        if rel not in effective:
            issues.append(
                LintIssue(
                    "MISSING_REQUIRED_FILE",
                    f"required file {rel!r} is not produced by render() (nor injected "
                    f"by the generator)",
                )
            )
    return issues


def _families_imported_by_source(source: str) -> list[str]:
    """AST-scan ``source`` for any import of ``ctf_generator.families``.

    Catches ``import ctf_generator.families``, ``from ctf_generator.families
    import ...``, ``from ctf_generator import families``, and the relative
    ``from . import families`` / ``from .families import ...`` forms.
    """
    hits: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "ctf_generator.families":
                    hits.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level and module in ("", "families"):
                # ``from . import families`` or ``from .families import ...``
                if module == "families":
                    hits.append("ctf_generator.families")
                elif any(a.name == "families" for a in node.names):
                    hits.append("ctf_generator.families")
            elif module == "ctf_generator.families":
                hits.append("ctf_generator.families")
            elif module == "ctf_generator" and any(a.name == "families" for a in node.names):
                hits.append("ctf_generator.families")
    return hits


def lint_renderer_module(module: Any, *, sample_seed: str = _DEFAULT_SAMPLE_SEED) -> list[LintIssue]:
    """Lint a renderer *module*: the family it adapts to (a-d) plus the
    circular-import contract (e). A module that cannot be adapted is reported as
    a ``MODULE_INTERFACE`` error rather than raising."""
    from .adapter import ModuleInterfaceError, family_from_module

    issues: list[LintIssue] = []

    # (e) circular-import contract: a renderer module must not import families.
    try:
        source = inspect.getsource(module)
    except (OSError, TypeError):
        source = None
    if source is not None:
        for hit in _families_imported_by_source(source):
            issues.append(
                LintIssue(
                    "MODULE_IMPORTS_FAMILIES",
                    f"renderer module imports {hit!r}; a renderer template must NOT "
                    "import ctf_generator.families (families.py imports the template)",
                )
            )
    else:
        # Source unavailable (compiled/.pyc-only, dynamically constructed, zip
        # loader): the import contract could NOT be verified -- surface it as a
        # warning rather than a silent pass, so a source-less plugin isn't
        # mistaken for having passed check (e).
        issues.append(
            LintIssue(
                "MODULE_SOURCE_UNAVAILABLE",
                "renderer module source is unavailable; the no-import-families "
                "contract could not be statically verified",
                severity="warning",
            )
        )

    try:
        family = family_from_module(module)
    except ModuleInterfaceError as exc:
        issues.append(LintIssue("MODULE_INTERFACE", str(exc)))
        return issues

    issues.extend(lint_family(family, sample_seed=sample_seed))
    return issues


def assert_family_ok(family: Family, *, sample_seed: str = _DEFAULT_SAMPLE_SEED) -> None:
    """Raise :class:`FamilyLintError` if ``family`` has any error-severity issue.

    For author tests (``assert_family_ok(MY_FAMILY)`` in a family's own test
    suite) and for the entry-point loader, which refuses to register a family
    that does not lint clean.
    """
    issues = lint_family(family, sample_seed=sample_seed)
    errors = [i for i in issues if i.severity == "error"]
    if errors:
        raise FamilyLintError(errors)
