from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Protocol

from .models import ChallengeSpec
from .spec_generator import _FAMILY_BRIEF
from .templates.tenant_export import render_tenant_export
from .validator import REQUIRED_FILES

if TYPE_CHECKING:
    from .cve_source import CveRecord

# --- Scoring hints ------------------------------------------------------------


@dataclass(frozen=True)
class ScoringHints:
    """Hints ``score.py`` reads to compute dimension scores for a family.

    Defaults reproduce the current, hard-coded ``tenant_export`` scoring
    signals (see ``score._statefulness`` / ``score._live_interaction``): a
    background worker + queue backend, live discover-and-poll interaction,
    and medium decoy density.
    """

    has_worker: bool = True
    has_queue: bool = True
    live_interaction: bool = True
    decoy_density: str = "medium"


# --- Renderer protocol ---------------------------------------------------------


class FamilyRenderer(Protocol):
    def __call__(
        self,
        spec: ChallengeSpec,
        rng: random.Random,
        cve_record: "CveRecord | None" = None,
    ) -> dict[str, str]: ...


DefaultSpecBuilder = Callable[..., ChallengeSpec]


# --- Family record ---------------------------------------------------------------


@dataclass(frozen=True)
class Family:
    name: str
    category: str
    modes: tuple[str, ...]
    render: FamilyRenderer
    required_files: tuple[str, ...]
    compose_service_markers: tuple[str, ...] = ()
    difficulties: tuple[str, ...] = ("easy", "medium", "hard")
    cve_driven: bool = False
    llm_brief: str = "A security challenge."
    default_spec_builder: DefaultSpecBuilder | None = None
    scoring_hints: ScoringHints = field(default_factory=ScoringHints)


# --- Registry --------------------------------------------------------------------

_REGISTRY: dict[str, Family] = {}


def register(family: Family) -> None:
    """Register (or replace) a family in the process-wide registry."""
    _REGISTRY[family.name] = family


def get(name: str) -> Family:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown family: {name}") from None


def is_registered(name: str) -> bool:
    return name in _REGISTRY


def family_names() -> list[str]:
    return sorted(_REGISTRY)


def families_for_mode(mode: str) -> list[Family]:
    return [f for f in sorted(_REGISTRY.values(), key=lambda fam: fam.name) if mode in f.modes]


def families_for_category(category: str) -> list[Family]:
    return [
        f
        for f in sorted(_REGISTRY.values(), key=lambda fam: fam.name)
        if f.category == category
    ]


# A top-level ``family: "..."`` (or ``family: value``) line in a rendered
# challenge.yaml. Anchored to zero leading whitespace so it only matches the
# top-level key, not the nested ``meta.family`` line emitted alongside it.
_FAMILY_LINE = re.compile(r'^family:\s*"?([^"\r\n]*?)"?\s*$')


def family_of(challenge_yaml_text: str) -> str | None:
    """Parse the top-level ``family`` field out of rendered challenge.yaml text.

    Returns ``None`` if no top-level ``family:`` line is present.
    """
    for line in challenge_yaml_text.splitlines():
        if line.startswith(" "):
            continue
        match = _FAMILY_LINE.match(line)
        if match:
            value = match.group(1).strip()
            return value or None
    return None


# --- Bootstrap: existing tenant_export family -------------------------------------


def _render_web_business_logic_tenant_export(
    spec: ChallengeSpec,
    rng: random.Random,
    cve_record: "CveRecord | None" = None,
) -> dict[str, str]:
    """Adapter wrapping ``render_tenant_export`` unchanged for the registry.

    ``cve_record`` is accepted (per the ``FamilyRenderer`` protocol) and
    ignored: this family predates CVE-driven generation and is not
    ``cve_driven``.
    """
    return render_tenant_export(spec, rng)


register(
    Family(
        name="web_business_logic_tenant_export",
        category="web",
        modes=("red",),
        render=_render_web_business_logic_tenant_export,
        required_files=tuple(REQUIRED_FILES),
        compose_service_markers=("worker:", "redis"),
        difficulties=("easy", "medium", "hard"),
        cve_driven=False,
        llm_brief=_FAMILY_BRIEF.get(
            "web_business_logic_tenant_export", "A security challenge."
        ),
        scoring_hints=ScoringHints(
            has_worker=True,
            has_queue=True,
            live_interaction=True,
            decoy_density="medium",
        ),
    )
)
