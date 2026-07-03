from __future__ import annotations

from dataclasses import dataclass, field

from . import __version__

# Version of the stamped challenge metadata schema. Bump when the shape of the
# ``meta`` block (or any generated layout it describes) changes incompatibly.
SPEC_VERSION = "1.0"


@dataclass(frozen=True)
class AIResistance:
    novelty_target: str = "high"
    min_solver_steps: int = 5
    require_live_interaction: bool = True
    decoy_density: str = "medium"
    generic_scanner_usefulness: str = "low"
    hidden_sibling_validation: bool = True


@dataclass(frozen=True)
class DynamicVariation:
    per_user_schema: bool = True
    per_user_routes: bool = True
    per_user_seed_data: bool = True
    per_user_auth_flow: bool = False
    per_user_flag_path: bool = True


@dataclass(frozen=True)
class ChallengeSpec:
    title: str
    category: str
    difficulty: str
    family: str
    seed: str
    learning_objectives: list[str]
    checkpoints: list[str]
    ai_resistance: AIResistance = field(default_factory=AIResistance)
    dynamic_variation: DynamicVariation = field(default_factory=DynamicVariation)

    def meta_mapping(self) -> dict[str, object]:
        """Provenance stamp for a generated instance.

        Deterministic given the seed: version/spec/family/seed only, with no
        wall-clock time or randomness, so a fixed seed yields a byte-identical
        meta block.
        """
        return {
            "generator_version": __version__,
            "spec_version": SPEC_VERSION,
            "family": self.family,
            "seed": self.seed,
        }

    def to_mapping(self) -> dict[str, object]:
        return {
            "meta": self.meta_mapping(),
            "title": self.title,
            "category": self.category,
            "difficulty": self.difficulty,
            "family": self.family,
            "seed": self.seed,
            "learning_objectives": self.learning_objectives,
            "ai_resistance": vars(self.ai_resistance),
            "dynamic_variation": vars(self.dynamic_variation),
            "checkpoints": [{"name": item} for item in self.checkpoints],
            "validation": {
                "private_solver_required": True,
                "ai_agent_eval_required": False,
                "variant_static_validation_required": True,
            },
        }

