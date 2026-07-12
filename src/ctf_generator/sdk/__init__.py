"""The CTFGenerator challenge-authoring SDK: the SUPPORTED authoring surface.

This package is the **stable, semver-governed contract** a challenge-family
author writes against. Author a family with::

    from ctf_generator.sdk import Family, ScoringHints, register

    def render(spec, rng, cve_record=None):
        ...  # return {relative_path: text}

    register(Family(name="my_family", category="web", modes=("red",),
                    render=render, required_files=(...)))

and, for third-party distribution, expose it through a ``ctf_generator.families``
entry point (see :func:`load_entry_point_families`).

Stability contract:
    The names re-exported here are the authoring API. Internal modules
    (``ctf_generator.families``, ``ctf_generator.models``,
    ``ctf_generator.build``, ...) MAY change between releases; this ``sdk`` facade
    is the surface we keep stable. The facade **re-exports the real
    implementations** -- ``sdk.Family is ctf_generator.families.Family`` -- so
    authoring against the facade is authoring against the real types, with no
    shim/adapter drift.

What lives where:
    * value/registry types come from ``ctf_generator.families`` and
      ``ctf_generator.models``;
    * :func:`lint_family` / :func:`assert_family_ok` / :class:`LintIssue` are the
      structural linter (``sdk.lint``);
    * :func:`load_entry_point_families` / :func:`bootstrap_family_plugins` are the
      external-plugin loader (``sdk.plugins``);
    * :func:`family_from_module` adapts a renderer module into a ``Family``.
"""

from __future__ import annotations

# --- Registry + family record (canonical home: ctf_generator.families) --------
from ..build import validate_relative_path

# --- CVE record type (canonical home: cve_source) -----------------------------
# A cve_driven family's render() receives a CveRecord; export it so an author can
# type/access that parameter against the stable surface (7 of 8 built-ins are
# CVE-driven -- the dominant authoring shape).
from ..cve_source import CveRecord
from ..families import (
    DefaultSpecBuilder,
    Family,
    FamilyRenderer,
    ScoringHints,
    families_for_category,
    families_for_mode,
    family_names,
    get,
    is_registered,
    register,
)

# --- Spec value types authors compose (canonical home: ctf_generator.models) --
from ..models import (
    AIResistance,
    ChallengeSpec,
    DynamicVariation,
    ResponseSpec,
    ScenarioSpec,
    TriggerSpec,
)
from ..schema import SchemaError, parse_semver

# --- Spec construction / validation (canonical home: spec_generator) ----------
from ..spec_generator import (
    DIFFICULTIES,
    default_spec,
    spec_from_dict,
    spec_to_dict,
    validate_spec,
)
from .adapter import ModuleInterfaceError, family_from_module, is_renderer_module

# --- Linter -------------------------------------------------------------------
from .lint import (
    FamilyLintError,
    LintIssue,
    assert_family_ok,
    lint_family,
    lint_renderer_module,
)

# --- External-plugin loader ---------------------------------------------------
from .plugins import (
    ENTRY_POINT_GROUP,
    bootstrap_family_plugins,
    load_entry_point_families,
)

__all__ = [
    # registry + family record
    "Family",
    "FamilyRenderer",
    "ScoringHints",
    "DefaultSpecBuilder",
    "register",
    "get",
    "is_registered",
    "family_names",
    "families_for_mode",
    "families_for_category",
    # spec value types
    "ChallengeSpec",
    "ScenarioSpec",
    "TriggerSpec",
    "ResponseSpec",
    "AIResistance",
    "DynamicVariation",
    "CveRecord",
    # spec construction / validation
    "default_spec",
    "validate_spec",
    "spec_to_dict",
    "spec_from_dict",
    "DIFFICULTIES",
    # build/schema helpers authors need
    "validate_relative_path",
    "parse_semver",
    "SchemaError",
    # module adapter
    "family_from_module",
    "is_renderer_module",
    "ModuleInterfaceError",
    # linter
    "lint_family",
    "lint_renderer_module",
    "assert_family_ok",
    "LintIssue",
    "FamilyLintError",
    # external-plugin loader
    "load_entry_point_families",
    "bootstrap_family_plugins",
    "ENTRY_POINT_GROUP",
]
