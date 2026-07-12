"""The SUPPORTED author-testing surface for challenge families.

This package is a small, stable set of reusable assertions a family author (a
built-in maintainer or a third-party plugin author) can call in their OWN test
suite to prove a family upholds the same invariants the release gates enforce on
the built-ins -- **without reaching into the ``tests/`` suite** and without
re-implementing any check.

It is strictly a **facade**: every helper delegates to the real implementation
already used in production --

* :func:`assert_family_ok` is exactly ``sdk.assert_family_ok`` (the structural
  linter, ``sdk.lint``);
* :func:`assert_no_private_leak` runs ``sdk.lint_family`` and surfaces its
  ``PRIVATE_CONTENT_IN_PUBLIC`` findings -- the identical invariant
  ``tests/test_baseline_fixtures.py::test_no_private_content_leaks_into_public``
  enforces on the golden baseline;
* :func:`assert_deterministic` renders through the *same* RNG derivation the
  real generator uses (``random.Random(generator.seed_to_int(spec.seed))`` on a
  ``spec_generator.default_spec``), so a pass here means a byte-identical real
  build;
* :func:`build_family_in` and :func:`assert_rebuild_is_byte_identical` render to
  disk through the REAL, hardened ``generator.create_challenge`` /
  ``build.write_build`` path, so the built tree is exactly what ``ctfgen
  validate`` / ``validator.validate_challenge`` would see.

Authoring-side only: this module imports the pure generator core (no DB/API/HTTP
framework), so it stays importable without the ``[db]``/``[api]`` extras. It is
NOT reachable from ``mcp_server`` (the MCP surface only ever exposes the built-in
families).
"""

from __future__ import annotations

import hashlib
import random
import tempfile
from pathlib import Path

from .. import families, generator, sdk
from ..sdk import FamilyLintError

__all__ = [
    "assert_family_ok",
    "assert_deterministic",
    "assert_no_private_leak",
    "build_family_in",
    "assert_rebuild_is_byte_identical",
    "FamilyLintError",
    "DeterminismError",
    "PrivateLeakError",
    "RebuildMismatchError",
]

# Default rendering knobs for the assertions. Deterministic (no wall-clock / no
# random ids) so an author test is reproducible.
_PROBE_SEED = "probe-seed"
_PROBE_DIFFICULTY = "medium"
_PROBE_TITLE = "Probe"


class DeterminismError(AssertionError):
    """A family rendered non-identical output for the same seed/spec."""


class PrivateLeakError(AssertionError):
    """A family leaked private content (a flag token or a byte-identical file)
    into a ``public/`` file."""


class RebuildMismatchError(AssertionError):
    """Two on-disk builds of the same family/seed were not byte-identical."""


def assert_family_ok(family: sdk.Family, *, sample_seed: str = _PROBE_SEED) -> None:
    """Structurally lint ``family``; raise :class:`FamilyLintError` on any
    error-severity issue.

    A thin re-export of :func:`sdk.assert_family_ok` (``sdk.lint``) so an author
    test can assert its family passes exactly the linter the entry-point loader
    and release gates run -- no duplicated logic.
    """
    sdk.assert_family_ok(family, sample_seed=sample_seed)


def _probe_spec(
    family: sdk.Family, seed: str, title: str, difficulty: str
):
    """The spec the real generator renders for this family/seed, built DIRECTLY
    from the family's declared metadata (scenario, category, objectives) -- the
    same construction ``sdk.lint._sample_spec`` uses.

    This deliberately does NOT go through the registry-sensitive
    ``spec_generator.default_spec``: on an UNregistered family (the scaffolded
    author path -- ``sdk.family_from_module(module)`` without ``register``) that
    builder falls back to generic defaults with the family's default scenario
    DISABLED, which would skip a scenario-enabled render branch and give a false
    determinism PASS. Building from the family object matches what
    ``create_challenge`` renders for the registered family AND requires no global
    registry mutation.
    """
    return sdk.ChallengeSpec(
        title=title,
        category=family.category or "web",
        difficulty=difficulty,
        family=family.name,
        seed=seed,
        learning_objectives=list(family.learning_objectives),
        checkpoints=list(family.checkpoints),
        scenario=(family.default_scenario or sdk.ScenarioSpec()),
        mode=(family.modes[0] if family.modes else "red"),
    )


def _render_once(family: sdk.Family, spec) -> dict[str, str]:
    """Render ``family`` once with the SAME RNG derivation the generator uses.

    ``generator.create_challenge`` seeds the family RNG with
    ``random.Random(generator.seed_to_int(spec.seed))``; mirroring that here
    means a determinism pass corresponds to a byte-identical real build.
    """
    rng = random.Random(generator.seed_to_int(spec.seed))  # noqa: S311 - deterministic render seeding, not crypto
    return dict(family.render(spec, rng, None))


def assert_deterministic(
    family: sdk.Family,
    *,
    seed: str = _PROBE_SEED,
    difficulty: str = _PROBE_DIFFICULTY,
    title: str = _PROBE_TITLE,
) -> dict[str, str]:
    """Render ``family`` TWICE for the same seed/spec and assert byte-identical
    output.

    Renders in-memory (calls ``family.render`` directly -- nothing is written to
    disk) through the generator's own RNG derivation. Raises
    :class:`DeterminismError` naming the first differing path(s) when the two
    renders disagree. Returns the (agreeing) rendered mapping on success.
    """
    # No registry mutation: _probe_spec builds the family's real (scenario-enabled)
    # spec directly from the family object, so this in-memory determinism check
    # neither requires nor performs registration.
    spec = _probe_spec(family, seed, title, difficulty)
    first = _render_once(family, spec)
    second = _render_once(family, spec)
    if first != second:
        diffs: list[str] = []
        for path in sorted(set(first) | set(second)):
            if first.get(path) != second.get(path):
                diffs.append(path)
        raise DeterminismError(
            f"family {family.name!r} is non-deterministic for seed {seed!r}: "
            f"render output differs at {diffs}"
        )
    return first


def assert_no_private_leak(
    family: sdk.Family, *, seed: str = _PROBE_SEED
) -> None:
    """Assert no private content leaks into ``public/``.

    Runs the real linter (:func:`sdk.lint_family`) and raises
    :class:`PrivateLeakError` if it reports any ``PRIVATE_CONTENT_IN_PUBLIC``
    finding -- the exact invariant (byte-identical private/public files OR a
    private flag token appearing in a public file) that ``sdk.lint`` and
    ``tests/test_baseline_fixtures.py::test_no_private_content_leaks_into_public``
    enforce. No re-implementation: the check lives in ``sdk.lint`` and is called
    here.
    """
    leaks = [
        issue
        for issue in sdk.lint_family(family, sample_seed=seed)
        if issue.code == "PRIVATE_CONTENT_IN_PUBLIC"
    ]
    if leaks:
        raise PrivateLeakError(
            f"family {family.name!r} leaks private content into public/: "
            + "; ".join(str(i) for i in leaks)
        )


def _ensure_registered(family: sdk.Family) -> None:
    """Register ``family`` so ``generator.create_challenge`` (which resolves the
    family by name from the registry) can build it.

    Only registers when the name is not already present, so a built-in is never
    clobbered by an author's test helper (the incumbent always wins, matching the
    plugin loader's no-override rule).
    """
    if not families.is_registered(family.name):
        families.register(family)


def build_family_in(
    family: sdk.Family,
    dest: Path | str,
    *,
    seed: str = _PROBE_SEED,
    difficulty: str = _PROBE_DIFFICULTY,
    title: str = _PROBE_TITLE,
    force: bool = False,
) -> Path:
    """Render ``family`` to an on-disk bundle via the REAL generator and return
    the build path.

    Delegates to ``generator.create_challenge`` (which publishes through the
    hardened, path-safe ``build.write_build``), so the resulting tree is exactly
    what ``ctfgen validate`` / ``validator.validate_challenge`` inspects -- an
    author can build then validate their family with the same code the platform
    runs. The family is registered first (never overriding a built-in) so the
    generator can resolve it by name.
    """
    _ensure_registered(family)
    return generator.create_challenge(
        output_dir=Path(dest),
        seed=seed,
        title=title,
        difficulty=difficulty,
        family=family.name,
        force=force,
    )


def _tree_hashes(root: Path) -> dict[str, str]:
    """Map every file under ``root`` to its SHA-256 (relative POSIX path keys)."""
    hashes: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            hashes[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def assert_rebuild_is_byte_identical(
    family: sdk.Family,
    *,
    seed: str = _PROBE_SEED,
    difficulty: str = _PROBE_DIFFICULTY,
    title: str = _PROBE_TITLE,
) -> None:
    """Build ``family`` twice (two temp dirs) for the same seed and assert every
    file is byte-identical across the two trees (per-file SHA-256).

    The on-disk analogue of :func:`assert_deterministic`: it exercises the full
    ``generator.create_challenge`` publish path (renderer output PLUS the
    generator-injected ``challenge.yaml`` and the cryptographic manifests) and
    proves the golden-manifest determinism guarantee end to end. Raises
    :class:`RebuildMismatchError` naming the divergent files.
    """
    _ensure_registered(family)
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        p1 = generator.create_challenge(
            output_dir=Path(d1) / "chal",
            seed=seed,
            title=title,
            difficulty=difficulty,
            family=family.name,
            force=True,
        )
        p2 = generator.create_challenge(
            output_dir=Path(d2) / "chal",
            seed=seed,
            title=title,
            difficulty=difficulty,
            family=family.name,
            force=True,
        )
        h1 = _tree_hashes(p1)
        h2 = _tree_hashes(p2)
    if h1 != h2:
        divergent = sorted(
            path
            for path in set(h1) | set(h2)
            if h1.get(path) != h2.get(path)
        )
        raise RebuildMismatchError(
            f"family {family.name!r} did not rebuild byte-identically for seed "
            f"{seed!r}: divergent files {divergent}"
        )
