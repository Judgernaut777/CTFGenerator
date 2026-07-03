from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Protocol

from .models import (
    AIResistance,
    ChallengeSpec,
    DynamicVariation,
    ResponseSpec,
    ScenarioSpec,
    TriggerSpec,
)

# Challenge families the generator can render. NOTE: ``families`` (the
# registry module) imports ``_FAMILY_BRIEF`` from this module, so this module
# must not import ``families`` at module scope (it would be circular) --
# functions below that need the registry import it lazily instead.
#
# ``FAMILIES`` is kept as a module-level name (aliased to the registry's
# family list at call time via a lazy property-like function below) for any
# importer that still expects a plain list; validate_spec itself now checks
# against the live registry so newly-registered families are recognized
# without editing this module.
DIFFICULTIES = ["easy", "medium", "hard"]

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _families_module():
    """Lazy import of the families registry (avoids a circular import)."""
    from . import families

    return families


class _FamilyNames:
    """Mirrors ``families.family_names()`` on every access.

    Kept as the module-level ``FAMILIES`` name for backward compatibility
    with importers that used the old static list, while staying in sync
    with the live registry (looked up lazily to avoid a circular import).
    """

    def __iter__(self):
        return iter(_families_module().family_names())

    def __contains__(self, item):
        return item in _families_module().family_names()

    def __len__(self):
        return len(_families_module().family_names())

    def __getitem__(self, index):
        return _families_module().family_names()[index]

    def __repr__(self):
        return repr(_families_module().family_names())


FAMILIES = _FamilyNames()


class SpecBackend(Protocol):
    """Produces a structured ``ChallengeSpec`` before any code is rendered."""

    def generate(
        self, family: str, difficulty: str, seed: str, title: str
    ) -> ChallengeSpec: ...


# --- Deterministic backend (default, offline, no dependencies) ----------------

_DEFAULT_OBJECTIVES = [
    "Trace an authorization boundary across API and worker services",
    "Identify a legacy trust mismatch in a stateful export workflow",
    "Write a robust exploit that adapts to generated route and data variants",
]

_DEFAULT_CHECKPOINTS = [
    "discovers profile and notice endpoints",
    "identifies the export workflow",
    "finds cross-tenant invoice metadata",
    "queues a legacy export job with attacker-controlled tenant reference",
    "retrieves the generated export and extracts the flag",
]


def default_spec(seed: str, title: str, difficulty: str, family: str) -> ChallengeSpec:
    """The built-in, fully deterministic spec used when no backend is chosen."""
    return ChallengeSpec(
        title=title,
        category="web",
        difficulty=difficulty,
        family=family,
        seed=seed,
        learning_objectives=list(_DEFAULT_OBJECTIVES),
        checkpoints=list(_DEFAULT_CHECKPOINTS),
    )


def default_spec_for_family(seed: str, title: str, difficulty: str, family: str) -> ChallengeSpec:
    """Like ``default_spec`` but routes through a family's own builder if set.

    Falls back to ``default_spec`` when the family is unregistered or has no
    ``default_spec_builder`` configured, so unfamiliar/legacy families keep
    today's behavior unchanged.
    """
    families = _families_module()
    if families.is_registered(family):
        builder = families.get(family).default_spec_builder
        if builder is not None:
            return builder(seed=seed, title=title, difficulty=difficulty, family=family)
    return default_spec(seed=seed, title=title, difficulty=difficulty, family=family)


class DeterministicSpecBackend:
    def generate(
        self, family: str, difficulty: str, seed: str, title: str
    ) -> ChallengeSpec:
        return default_spec(seed=seed, title=title, difficulty=difficulty, family=family)


# --- Anthropic (LLM) backend --------------------------------------------------

# The LLM produces ONLY human-facing pedagogical metadata (title, learning
# objectives, checkpoints). It never emits code, flags, or the security-relevant
# AI-resistance knobs -- those stay under deterministic control so a generated
# challenge is always safe and structurally valid.
_LLM_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "title": {"type": "string"},
        "learning_objectives": {"type": "array", "items": {"type": "string"}},
        "checkpoints": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["title", "learning_objectives", "checkpoints"],
}

_FAMILY_BRIEF = {
    "web_business_logic_tenant_export": (
        "A multi-tenant SaaS 'export' web challenge. A legacy background worker "
        "trusts a tenant reference supplied at job-queue time, enabling a "
        "cross-tenant IDOR: the attacker queues an export for a victim tenant's "
        "invoice and reads back a flag. The player must discover routes at "
        "runtime, chain a stateful async job, and adapt to per-instance route "
        "and field names."
    ),
}

ANTHROPIC_DEFAULT_MODEL = "claude-opus-4-8"
OPENAI_DEFAULT_MODEL = "gpt-5.1"


def build_prompt(family: str, difficulty: str) -> tuple[str, str]:
    """Return (system, user) prompts. Pure, so the wording is unit-testable."""
    families = _families_module()
    if families.is_registered(family):
        brief = families.get(family).llm_brief
    else:
        brief = _FAMILY_BRIEF.get(family, "A web security challenge.")
    system = (
        "You design capture-the-flag challenge specifications. You output only "
        "structured pedagogical metadata for an already-defined challenge family: "
        "a title, learning objectives, and solve-path checkpoints. You never write "
        "code, exploits, flags, routes, or infrastructure details -- those are "
        "generated deterministically by a separate renderer. Keep objectives and "
        "checkpoints concise (one short phrase each)."
    )
    user = (
        f"Challenge family: {family}\n"
        f"Difficulty: {difficulty}\n"
        f"Family brief: {brief}\n\n"
        "Produce a short evocative title, 3-5 learning objectives, and 5-7 "
        "checkpoints that trace the intended solve path in order (from initial "
        "recon to flag extraction). Return them via the required schema."
    )
    return system, user


def spec_from_llm_output(
    data: dict, family: str, difficulty: str, seed: str, fallback_title: str
) -> ChallengeSpec:
    """Merge LLM-produced metadata with our fixed, safety-relevant defaults."""
    title = str(data.get("title") or fallback_title).strip() or fallback_title
    objectives = [str(o).strip() for o in data.get("learning_objectives", []) if str(o).strip()]
    checkpoints = [str(c).strip() for c in data.get("checkpoints", []) if str(c).strip()]
    return ChallengeSpec(
        title=title,
        category="web",
        difficulty=difficulty,
        family=family,
        seed=seed,
        learning_objectives=objectives,
        checkpoints=checkpoints,
        ai_resistance=AIResistance(),
        dynamic_variation=DynamicVariation(),
    )


def _extract_json_anthropic(response: object) -> dict:
    """Pull the JSON object out of an Anthropic structured-output response."""
    for block in getattr(response, "content", []) or []:
        if getattr(block, "type", None) == "text":
            return json.loads(block.text)
    raise RuntimeError("Anthropic response contained no text block to parse")


def _extract_json_openai(response: object) -> dict:
    """Pull the JSON object out of an OpenAI chat-completion response."""
    choices = getattr(response, "choices", None) or []
    if not choices:
        raise RuntimeError("OpenAI response contained no choices to parse")
    return json.loads(choices[0].message.content)


def _make_anthropic_client():  # pragma: no cover - needs real credentials
    try:
        import anthropic
    except ImportError:
        raise RuntimeError(
            "the anthropic backend requires the 'anthropic' package; install it "
            "with 'pip install ctf-generator[anthropic]'"
        ) from None
    return anthropic.Anthropic()


def _make_openai_client():  # pragma: no cover - needs real credentials
    try:
        import openai
    except ImportError:
        raise RuntimeError(
            "the openai backend requires the 'openai' package; install it with "
            "'pip install ctf-generator[openai]'"
        ) from None
    return openai.OpenAI()


class AnthropicSpecBackend:
    """Generate a spec with Claude, then validate before it is trusted.

    The Anthropic client is injectable so the prompt-building and response-parsing
    logic can be unit-tested without network access or credentials.
    """

    def __init__(
        self, model: str = ANTHROPIC_DEFAULT_MODEL, client: object | None = None
    ) -> None:
        self._model = model
        self._client = client

    def generate(
        self, family: str, difficulty: str, seed: str, title: str
    ) -> ChallengeSpec:
        client = self._client or _make_anthropic_client()
        system, user = build_prompt(family, difficulty)
        response = client.messages.create(
            model=self._model,
            max_tokens=4096,
            thinking={"type": "adaptive"},
            output_config={"format": {"type": "json_schema", "schema": _LLM_SCHEMA}},
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        data = _extract_json_anthropic(response)
        return spec_from_llm_output(
            data, family=family, difficulty=difficulty, seed=seed, fallback_title=title
        )


class OpenAISpecBackend:
    """Generate a spec with OpenAI, then validate before it is trusted.

    Uses Chat Completions structured outputs (json_schema, strict). The client is
    injectable so the prompt/parse logic is unit-tested without network access.
    """

    def __init__(
        self, model: str = OPENAI_DEFAULT_MODEL, client: object | None = None
    ) -> None:
        self._model = model
        self._client = client

    def generate(
        self, family: str, difficulty: str, seed: str, title: str
    ) -> ChallengeSpec:
        client = self._client or _make_openai_client()
        system, user = build_prompt(family, difficulty)
        response = client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "challenge_spec",
                    "schema": _LLM_SCHEMA,
                    "strict": True,
                },
            },
        )
        data = _extract_json_openai(response)
        return spec_from_llm_output(
            data, family=family, difficulty=difficulty, seed=seed, fallback_title=title
        )


def get_backend(name: str, model: str | None = None) -> SpecBackend:
    if name == "deterministic":
        return DeterministicSpecBackend()
    if name == "anthropic":
        return AnthropicSpecBackend(model=model or ANTHROPIC_DEFAULT_MODEL)
    if name == "openai":
        return OpenAISpecBackend(model=model or OPENAI_DEFAULT_MODEL)
    raise ValueError(f"unknown spec backend: {name}")


# --- Validation & serialization -----------------------------------------------


def validate_spec(spec: ChallengeSpec) -> list[str]:
    """Structural checks a spec must pass before it is rendered into code."""
    errors: list[str] = []
    families = _families_module()
    if not spec.title.strip():
        errors.append("title is empty")
    family_known = spec.family in families.family_names()
    if not family_known:
        errors.append(f"unknown family: {spec.family}")
    if spec.difficulty not in DIFFICULTIES:
        errors.append(f"unknown difficulty: {spec.difficulty}")
    if not spec.seed.strip():
        errors.append("seed is empty")
    if len(spec.learning_objectives) < 1:
        errors.append("at least one learning objective is required")
    min_steps = spec.ai_resistance.min_solver_steps
    if len(spec.checkpoints) < min_steps:
        errors.append(
            f"spec declares {len(spec.checkpoints)} checkpoints but "
            f"ai_resistance.min_solver_steps requires at least {min_steps}"
        )
    for cve_ref in spec.cve_refs:
        if not _CVE_ID_RE.match(cve_ref):
            errors.append(f"invalid cve_ref: {cve_ref}")
    # Only check mode-against-family once the family itself is known; an
    # unknown family is already flagged above and has no ``modes`` to check.
    if family_known and spec.mode not in families.get(spec.family).modes:
        errors.append(
            f"mode {spec.mode!r} is not valid for family {spec.family!r}"
        )
    return errors


def spec_to_dict(spec: ChallengeSpec) -> dict:
    data: dict = {
        "title": spec.title,
        "category": spec.category,
        "difficulty": spec.difficulty,
        "family": spec.family,
        "seed": spec.seed,
        "learning_objectives": list(spec.learning_objectives),
        "checkpoints": list(spec.checkpoints),
        "ai_resistance": vars(spec.ai_resistance),
        "dynamic_variation": vars(spec.dynamic_variation),
    }
    # Conditionally-emitted keys (new spec fields): only appear when set to a
    # non-default value, so a spec without them round-trips to byte-identical
    # dict/JSON as before these fields existed.
    if spec.cve_refs:
        data["cve_refs"] = list(spec.cve_refs)
    if spec.cve_content_hash is not None:
        data["cve_content_hash"] = spec.cve_content_hash
    if spec.mode != "red":
        data["mode"] = spec.mode
    if not spec.scenario.is_default():
        data["scenario"] = spec.scenario.to_mapping()
    return data


def spec_from_dict(data: dict) -> ChallengeSpec:
    ai = data.get("ai_resistance") or {}
    variation = data.get("dynamic_variation") or {}
    scenario_data = data.get("scenario")
    if isinstance(scenario_data, dict):
        scenario = ScenarioSpec(
            enabled=bool(scenario_data.get("enabled", False)),
            triggers=[
                TriggerSpec(
                    trigger_id=str(t.get("trigger_id", "")),
                    description=str(t.get("description", "")),
                    condition=str(t.get("condition", "")),
                )
                for t in scenario_data.get("triggers", [])
                if isinstance(t, dict)
            ],
            responses=[
                ResponseSpec(
                    response_id=str(r.get("response_id", "")),
                    description=str(r.get("description", "")),
                    action=str(r.get("action", "")),
                    payload={str(k): str(v) for k, v in (r.get("payload") or {}).items()},
                )
                for r in scenario_data.get("responses", [])
                if isinstance(r, dict)
            ],
        )
    else:
        scenario = ScenarioSpec()
    return ChallengeSpec(
        title=str(data.get("title", "")),
        category=str(data.get("category", "web")),
        difficulty=str(data.get("difficulty", "medium")),
        family=str(data.get("family", FAMILIES[0])),
        seed=str(data.get("seed", "")),
        learning_objectives=[str(o) for o in data.get("learning_objectives", [])],
        checkpoints=[str(c) for c in data.get("checkpoints", [])],
        ai_resistance=AIResistance(**ai) if isinstance(ai, dict) else AIResistance(),
        dynamic_variation=(
            DynamicVariation(**variation) if isinstance(variation, dict) else DynamicVariation()
        ),
        cve_refs=[str(c) for c in data.get("cve_refs", [])],
        cve_content_hash=(
            str(data["cve_content_hash"]) if data.get("cve_content_hash") is not None else None
        ),
        mode=str(data.get("mode", "red")),
        scenario=scenario,
    )


def write_spec(path: Path, spec: ChallengeSpec) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(spec_to_dict(spec), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_spec(path: Path) -> ChallengeSpec:
    return spec_from_dict(json.loads(path.read_text(encoding="utf-8")))
