"""Scaffold a new challenge family (the ``ctfgen new-family`` command).

Writes a minimal but **lint-clean and immediately generatable** starting point
for a new family into a destination directory:

* ``<name>.py`` -- a renderer module exposing the fixed module-interface
  constants + a ``render`` that emits exactly the files it declares in
  ``REQUIRED_FILES``. It does NOT import ``ctf_generator.families`` (the
  circular-import contract).
* ``test_<name>.py`` -- a runnable author test using the supported
  ``ctf_generator.testing`` facade (lints clean + deterministic).
* ``ENTRY_POINT.md`` -- the ``[project.entry-points."ctf_generator.families"]``
  snippet to register the family for distribution.

Safety: the family ``name`` and ``category`` must be safe Python identifiers (no
path separators, traversal, or non-identifier characters); every written path is
validated with :func:`build.validate_relative_path`; existing files are never
overwritten unless ``force`` is set (all targets are checked BEFORE any is
written, so a partial clobber cannot happen); and the output is deterministic for
a given name (no timestamps or random ids).

Pure filesystem + string templating -- no network, Docker, or clock use.
"""

from __future__ import annotations

import keyword
import os
import re
from pathlib import Path

from .. import build
from .lint import KNOWN_MODES

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ScaffoldError(Exception):
    """A ``new-family`` request was invalid (bad name/category/modes or a
    would-be clobber). Carries a clean, user-facing message; the CLI turns it
    into a nonzero exit with no traceback."""


def _validate_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ScaffoldError(f"{label} must be a non-empty string")
    # ``isidentifier()`` already rejects path separators, ``..``, dots, spaces,
    # and leading digits; the regex pins it to the ASCII snake-case shape family
    # names/categories use, and the keyword check keeps the module importable.
    if not value.isidentifier() or not _IDENT_RE.match(value):
        raise ScaffoldError(
            f"invalid {label} {value!r}: must be a Python identifier "
            f"([A-Za-z_][A-Za-z0-9_]*), with no path separators or traversal"
        )
    if keyword.iskeyword(value):
        raise ScaffoldError(f"invalid {label} {value!r}: is a Python keyword")


def _parse_modes(modes: str) -> tuple[str, ...]:
    parsed = tuple(m.strip() for m in modes.split(",") if m.strip())
    if not parsed:
        raise ScaffoldError("at least one mode is required")
    unknown = [m for m in parsed if m not in KNOWN_MODES]
    if unknown:
        raise ScaffoldError(
            f"unknown mode(s) {unknown}: valid modes are {sorted(KNOWN_MODES)}"
        )
    return parsed


def _modes_literal(modes: tuple[str, ...]) -> str:
    inner = ", ".join(f'"{m}"' for m in modes)
    # Force a trailing comma so a single-element tuple stays a tuple literal.
    return f"({inner},)" if len(modes) == 1 else f"({inner})"


# --- File templates -----------------------------------------------------------
#
# Templates use ``__NAME__`` / ``__CATEGORY__`` / ``__MODES__`` / ``__BRIEF__``
# placeholders (replaced verbatim) instead of str.format, so the Python braces in
# the emitted f-strings/dicts don't need escaping.

_MODULE_TEMPLATE = '''\
"""Renderer for the ``__NAME__`` challenge family.

Scaffolded by ``ctfgen new-family``. This is a MINIMAL, lint-clean starting
point: edit ``render`` (and ``REQUIRED_FILES``) to build your real challenge.

Per the module-interface contract this file MUST NOT import
``ctf_generator.families`` (that module imports this one).
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctf_generator.cve_source import CveRecord
    from ctf_generator.models import ChallengeSpec

# --- Module interface contract ------------------------------------------------

FAMILY_NAME = "__NAME__"
CATEGORY = "__CATEGORY__"
MODES: tuple[str, ...] = __MODES__
DIFFICULTIES: tuple[str, ...] = ("easy", "medium", "hard")
CVE_DRIVEN = False
LLM_BRIEF = "__BRIEF__"
COMPOSE_MARKERS: tuple[str, ...] = ()
SCORING_HINTS: dict[str, object] = {}
REQUIRED_FILES: tuple[str, ...] = (
    "challenge.yaml",
    "public/description.md",
    "private/solution.md",
    "private/solver.py",
    "tests/healthcheck.py",
)


def render(
    spec: "ChallengeSpec",
    rng: random.Random,
    cve_record: "CveRecord | None" = None,
) -> dict[str, str]:
    """Return a mapping of ``{relative_path: text}``.

    Deterministic in ``(spec, rng)`` -- derive every per-instance value from
    ``rng`` (seeded by the generator), never from the clock or global state.
    ``challenge.yaml`` is injected by the generator, so ``render`` emits every
    OTHER file listed in ``REQUIRED_FILES``.
    """
    # A seed-derived flag: unique per instance, deterministic per seed. NEVER
    # emit this token into any ``public/`` file.
    flag = f"ctf{{__NAME___{rng.getrandbits(32):08x}}}"
    return {
        "public/description.md": _description(spec),
        "private/solution.md": _solution(flag),
        "private/solver.py": _solver(),
        "tests/healthcheck.py": _healthcheck(),
    }


def _description(spec: "ChallengeSpec") -> str:
    return (
        f"# {spec.title}\\n\\n"
        "TODO: describe the player-facing challenge here. Do NOT include the\\n"
        "flag value in any public file. The flag format is `ctf{...}`.\\n"
    )


def _solution(flag: str) -> str:
    return (
        "# Private Solution\\n\\n"
        "TODO: document the intended solve path step by step.\\n\\n"
        f"The flag for this instance is `{flag}`.\\n"
    )


def _solver() -> str:
    return (
        "from __future__ import annotations\\n\\n"
        "import argparse\\n"
        "import sys\\n\\n\\n"
        "def main() -> int:\\n"
        "    parser = argparse.ArgumentParser()\\n"
        '    parser.add_argument("--base-url", default="http://127.0.0.1:8080")\\n'
        "    parser.parse_args()\\n"
        "    # TODO: implement the reference solver that extracts the flag.\\n"
        "    return 0\\n\\n\\n"
        'if __name__ == "__main__":\\n'
        "    sys.exit(main())\\n"
    )


def _healthcheck() -> str:
    return (
        "from __future__ import annotations\\n\\n"
        "import sys\\n\\n\\n"
        "def main() -> int:\\n"
        "    # TODO: verify the running challenge instance is healthy.\\n"
        "    return 0\\n\\n\\n"
        'if __name__ == "__main__":\\n'
        "    sys.exit(main())\\n"
    )
'''

_TEST_TEMPLATE = '''\
"""Author test for the ``__NAME__`` family.

Run it from this directory with either runner::

    python -m pytest test___NAME__.py
    python -m unittest test___NAME__

Uses the SUPPORTED author-testing facade ``ctf_generator.testing`` -- the same
structural-lint and determinism checks the release gates run on the built-ins.
"""

from __future__ import annotations

import unittest

import __NAME__ as family_module

from ctf_generator import sdk, testing


def _family():
    # Adapt the renderer module's interface constants into a Family, exactly as
    # the built-in loader and the entry-point plugin loader do.
    return sdk.family_from_module(family_module)


class __NAME__Tests(unittest.TestCase):
    def test_family_lints_clean(self) -> None:
        testing.assert_family_ok(_family())

    def test_family_is_deterministic(self) -> None:
        testing.assert_deterministic(_family())

    def test_family_has_no_private_leak(self) -> None:
        testing.assert_no_private_leak(_family())


if __name__ == "__main__":
    unittest.main()
'''

_ENTRY_POINT_TEMPLATE = '''\
# Registering the `__NAME__` family

To distribute this family as an installable plugin, declare a
`ctf_generator.families` entry point in your package's `pyproject.toml`:

```toml
[project.entry-points."ctf_generator.families"]
__NAME__ = "__NAME__"
```

The entry point may resolve to any of:

- this renderer module (`__NAME__`), adapted exactly like the built-in template
  modules;
- a `ctf_generator.sdk.Family` instance; or
- a zero-argument callable returning a `Family`.

Once your package is installed in the same environment, the family is
discovered, **linted**, and registered automatically by `ctfgen` at CLI startup
(via `sdk.plugins.bootstrap_family_plugins`). Only lint-clean families are
registered; a plugin that fails the linter is skipped with a warning and never
crashes the app. See `docs/CHALLENGE_SDK.md` for the full contract.
'''


def render_family_module(name: str, category: str, modes: tuple[str, ...], brief: str) -> str:
    return (
        _MODULE_TEMPLATE.replace("__NAME__", name)
        .replace("__CATEGORY__", category)
        .replace("__MODES__", _modes_literal(modes))
        .replace("__BRIEF__", brief)
    )


def render_test_module(name: str) -> str:
    return _TEST_TEMPLATE.replace("__NAME__", name)


def render_entry_point_doc(name: str) -> str:
    return _ENTRY_POINT_TEMPLATE.replace("__NAME__", name)


def scaffold_family(
    name: str,
    category: str,
    dest: Path,
    *,
    modes: str = "red",
    force: bool = False,
) -> list[Path]:
    """Write the three scaffold files into ``dest`` and return their paths.

    Validates ``name``/``category``/``modes`` first (raising :class:`ScaffoldError`
    before touching the filesystem), routes every written filename through
    :func:`build.validate_relative_path`, and refuses to overwrite any existing
    target unless ``force`` -- checking ALL targets before writing ANY, so a
    rejected run writes nothing.
    """
    _validate_identifier(name, "name")
    _validate_identifier(category, "category")
    parsed_modes = _parse_modes(modes)
    brief = f"A {category} security challenge (scaffolded; edit LLM_BRIEF)."

    dest = Path(dest)
    files = {
        f"{name}.py": render_family_module(name, category, parsed_modes, brief),
        f"test_{name}.py": render_test_module(name),
        "ENTRY_POINT.md": render_entry_point_doc(name),
    }

    # Path-safety: each filename must be a safe single-component relative path
    # (no absolute/traversal/reserved). ``name`` is a validated identifier, so
    # these always pass -- the check is defense in depth against future edits.
    for rel in files:
        build.validate_relative_path(rel)

    # A dest that exists but is NOT a directory (a regular file, a symlink) must
    # be a clean error, not a raw FileExistsError traceback from mkdir.
    if dest.exists() and not dest.is_dir():
        raise ScaffoldError(f"--dest is not a directory: {dest}")
    if dest.is_symlink():
        raise ScaffoldError(f"--dest is a symlink; refusing to follow it: {dest}")
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ScaffoldError(f"cannot create --dest {dest}: {exc}") from exc

    # No-clobber: check every target up front so a rejected run leaves the tree
    # untouched (no partial write). A SYMLINK target (dangling OR live) is refused
    # unconditionally -- writing through it would escape dest (path.exists() is
    # False for a dangling link, so it must be caught by is_symlink, not exists).
    targets = {rel: dest / rel for rel in files}
    symlinks = sorted(str(p) for p in targets.values() if p.is_symlink())
    if symlinks:
        raise ScaffoldError(
            f"refusing to write through symlink(s) in --dest: {symlinks}"
        )
    if not force:
        existing = sorted(str(path) for path in targets.values() if path.exists())
        if existing:
            raise ScaffoldError(
                "refusing to overwrite existing file(s) (pass --force to "
                f"overwrite): {existing}"
            )

    written: list[Path] = []
    for rel, content in files.items():
        target = targets[rel]
        # O_NOFOLLOW closes the TOCTOU window: if a symlink is swapped in AFTER the
        # check above, the open refuses rather than following it out of dest.
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
        flags |= os.O_TRUNC if force else os.O_EXCL
        try:
            fd = os.open(target, flags, 0o644)
        except OSError as exc:
            raise ScaffoldError(f"cannot write {target}: {exc}") from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
        except OSError as exc:  # pragma: no cover - write failure after open
            raise ScaffoldError(f"cannot write {target}: {exc}") from exc
        written.append(target)
    return written
