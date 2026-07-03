from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from .models import AIResistance, ChallengeSpec, DynamicVariation

# Challenge families the generator can render. Kept here (not imported from cli)
# so the spec layer has no dependency on the CLI.
FAMILIES = ["web_business_logic_tenant_export"]
DIFFICULTIES = ["easy", "medium", "hard"]


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
    if not spec.title.strip():
        errors.append("title is empty")
    if spec.family not in FAMILIES:
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
    return errors


def spec_to_dict(spec: ChallengeSpec) -> dict:
    return {
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


def spec_from_dict(data: dict) -> ChallengeSpec:
    ai = data.get("ai_resistance") or {}
    variation = data.get("dynamic_variation") or {}
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
    )


def write_spec(path: Path, spec: ChallengeSpec) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(spec_to_dict(spec), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_spec(path: Path) -> ChallengeSpec:
    return spec_from_dict(json.loads(path.read_text(encoding="utf-8")))
