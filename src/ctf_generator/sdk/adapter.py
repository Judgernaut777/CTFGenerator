"""Adapt a renderer *module* into a :class:`~ctf_generator.families.Family`.

A renderer module exposes the fixed module-interface constants
(``FAMILY_NAME``/``CATEGORY``/``MODES``/``DIFFICULTIES``/``CVE_DRIVEN``/
``LLM_BRIEF``/``COMPOSE_MARKERS``/``SCORING_HINTS``/``REQUIRED_FILES``) plus a
``render`` callable. ``families.py`` wires each *built-in* template module into
the registry with exactly this mapping in its bootstrap loop; this function
factors the same mapping out so an *external* plugin module can be adapted
identically -- WITHOUT touching ``families.py`` (whose built-in registration,
and therefore the deterministic rendered bytes of the built-in families, must
stay untouched).

Only the module-interface fields are read here. The per-family pedagogical
defaults and capability-metadata overrides that ``families.py`` layers on top of
its built-ins (``_FAMILY_SPEC_DEFAULTS`` / ``_FAMILY_META`` / ``_FAMILY_
SCENARIOS``) are built-in-specific look-up tables and are intentionally NOT
consulted for external modules -- an external module gets the ``Family``
dataclass defaults for anything it does not declare.
"""

from __future__ import annotations

from typing import Any

from ..families import Family, ScoringHints


class ModuleInterfaceError(TypeError):
    """A renderer module is missing a required module-interface attribute."""


_REQUIRED_ATTRS = ("FAMILY_NAME", "CATEGORY", "MODES", "REQUIRED_FILES", "render")


def is_renderer_module(obj: Any) -> bool:
    """True if ``obj`` looks like a renderer module (has the core interface)."""
    return all(hasattr(obj, attr) for attr in _REQUIRED_ATTRS)


def family_from_module(module: Any) -> Family:
    """Build a :class:`Family` from a renderer module's interface constants.

    Mirrors the built-in bootstrap loop in ``families.py`` for the fields a
    renderer module owns. Raises :class:`ModuleInterfaceError` if a required
    attribute is absent, so a malformed plugin fails cleanly (the loader turns
    that into a skip, never a crash).
    """
    missing = [attr for attr in _REQUIRED_ATTRS if not hasattr(module, attr)]
    if missing:
        raise ModuleInterfaceError(
            f"renderer module {getattr(module, '__name__', module)!r} is missing "
            f"required interface attribute(s): {', '.join(missing)}"
        )

    scoring = getattr(module, "SCORING_HINTS", None)
    scoring_hints = ScoringHints(**scoring) if isinstance(scoring, dict) else ScoringHints()

    return Family(
        name=module.FAMILY_NAME,
        category=module.CATEGORY,
        modes=tuple(module.MODES),
        render=module.render,
        required_files=tuple(module.REQUIRED_FILES),
        compose_service_markers=tuple(getattr(module, "COMPOSE_MARKERS", ())),
        difficulties=tuple(getattr(module, "DIFFICULTIES", ("easy", "medium", "hard"))),
        cve_driven=bool(getattr(module, "CVE_DRIVEN", False)),
        llm_brief=getattr(module, "LLM_BRIEF", "A security challenge."),
        scoring_hints=scoring_hints,
    )
