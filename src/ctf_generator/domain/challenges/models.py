from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ... import __version__

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
    # Phase-5 knob: whether a live adversarial (red-team) engine actively
    # probes/mutates the challenge at runtime. Unused until that phase wires
    # it up; defaulting to False keeps today's behavior unchanged.
    live_adversarial_engine: bool = False


@dataclass(frozen=True)
class DynamicVariation:
    per_user_schema: bool = True
    per_user_routes: bool = True
    per_user_seed_data: bool = True
    per_user_auth_flow: bool = False
    per_user_flag_path: bool = True


@dataclass(frozen=True)
class TriggerSpec:
    """A single condition in a scenario timeline that can fire a response."""

    trigger_id: str
    description: str = ""
    # Small DSL-ish string describing what fires this trigger, e.g.
    # "checkpoint:queues_export_job" or "time:+120s". Interpreted by the
    # (future) scenario engine, not by models.py.
    condition: str = ""

    def to_mapping(self) -> dict[str, object]:
        return {
            "trigger_id": self.trigger_id,
            "description": self.description,
            "condition": self.condition,
        }


@dataclass(frozen=True)
class ResponseSpec:
    """A single scripted reaction to a trigger firing."""

    response_id: str
    description: str = ""
    # What kind of reaction this is, e.g. "reveal_hint", "spawn_decoy",
    # "notify". Interpreted by the (future) scenario engine.
    action: str = ""
    payload: dict[str, str] = field(default_factory=dict)

    def to_mapping(self) -> dict[str, object]:
        return {
            "response_id": self.response_id,
            "description": self.description,
            "action": self.action,
            "payload": dict(self.payload),
        }


@dataclass(frozen=True)
class ScenarioSpec:
    """Minimal, serializable description of a challenge's live timeline.

    Disabled by default so existing (non-scenario) challenges are unaffected.
    """

    enabled: bool = False
    triggers: list[TriggerSpec] = field(default_factory=list)
    responses: list[ResponseSpec] = field(default_factory=list)

    def is_default(self) -> bool:
        return not self.enabled and not self.triggers and not self.responses

    def to_mapping(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "triggers": [t.to_mapping() for t in self.triggers],
            "responses": [r.to_mapping() for r in self.responses],
        }


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
    # CVE ids (e.g. "CVE-2023-12345") that a cve-driven family grounded this
    # instance in. Empty for non-CVE challenges (today's default).
    cve_refs: list[str] = field(default_factory=list)
    # Content hash locking the exact CVE record content used at generation
    # time, so re-generating from the same seed stays byte-identical even if
    # the upstream CVE source is later updated. None when unused.
    cve_content_hash: str | None = None
    # "red" (today's only mode) vs. e.g. "scenario" for a live, timed
    # storyline challenge. Defaults to "red" to match existing challenges.
    mode: str = "red"
    scenario: ScenarioSpec = field(default_factory=ScenarioSpec)

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
        mapping: dict[str, object] = {
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
        # Conditionally-emitted keys: only appear when set to a non-default
        # value, so a default ChallengeSpec (red, no cve, scenario disabled)
        # keeps serializing byte-identically to before these fields existed.
        if self.cve_refs:
            mapping["cve_refs"] = list(self.cve_refs)
        if self.cve_content_hash is not None:
            mapping["cve_content_hash"] = self.cve_content_hash
        if self.mode != "red":
            mapping["mode"] = self.mode
        if not self.scenario.is_default():
            mapping["scenario"] = self.scenario.to_mapping()
        return mapping


@dataclass(frozen=True)
class Submission:
    """A single team's answer attempt for a challenge."""

    submission_id: str
    team_id: str
    challenge_id: str
    submitted_at: datetime
    correct: bool
    instance_seed: str | None = None

    def to_mapping(self) -> dict[str, object]:
        return {
            "submission_id": self.submission_id,
            "team_id": self.team_id,
            "challenge_id": self.challenge_id,
            "submitted_at": self.submitted_at.isoformat(),
            "correct": self.correct,
            "instance_seed": self.instance_seed,
        }


@dataclass(frozen=True)
class SolveEvent:
    """Records the moment a team's submission was accepted as correct."""

    team_id: str
    challenge_id: str
    solved_at: datetime
    submission_id: str
    instance_seed: str | None = None

    def to_mapping(self) -> dict[str, object]:
        return {
            "team_id": self.team_id,
            "challenge_id": self.challenge_id,
            "solved_at": self.solved_at.isoformat(),
            "submission_id": self.submission_id,
            "instance_seed": self.instance_seed,
        }


def solve_event_from_submission(submission: Submission) -> SolveEvent:
    """Build a ``SolveEvent`` from a correct ``Submission``.

    Raises ``ValueError`` if the submission was not marked correct, since a
    solve event should only ever be derived from an accepted answer.
    """
    if not submission.correct:
        raise ValueError("cannot build a SolveEvent from an incorrect submission")
    return SolveEvent(
        team_id=submission.team_id,
        challenge_id=submission.challenge_id,
        solved_at=submission.submitted_at,
        submission_id=submission.submission_id,
        instance_seed=submission.instance_seed,
    )


@dataclass(frozen=True)
class FirstBloodBonusConfig:
    """Extra points awarded to the first team to solve a challenge."""

    enabled: bool = True
    bonus_points: int = 0
    bonus_percent: float = 0.0

    def to_mapping(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "bonus_points": self.bonus_points,
            "bonus_percent": self.bonus_percent,
        }


@dataclass(frozen=True)
class ChallengeScoringConfig:
    """Per-challenge point-value behavior during a live competition."""

    challenge_id: str
    initial_value: int = 500
    minimum_value: int = 100
    # "static", "linear", or "logarithmic" decay of value as solve_count grows.
    decay_function: str = "static"
    decay: int = 0
    first_blood_bonus: FirstBloodBonusConfig = field(default_factory=FirstBloodBonusConfig)

    def to_mapping(self) -> dict[str, object]:
        return {
            "challenge_id": self.challenge_id,
            "initial_value": self.initial_value,
            "minimum_value": self.minimum_value,
            "decay_function": self.decay_function,
            "decay": self.decay,
            "first_blood_bonus": self.first_blood_bonus.to_mapping(),
        }


@dataclass(frozen=True)
class CompetitionConfig:
    """Top-level timing/scoring configuration for a competition run."""

    competition_id: str
    name: str
    start_time: datetime
    end_time: datetime
    scoring_start_time: datetime | None = None
    freeze_time: datetime | None = None
    default_scoring: ChallengeScoringConfig | None = None

    def to_mapping(self) -> dict[str, object]:
        return {
            "competition_id": self.competition_id,
            "name": self.name,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "scoring_start_time": (
                self.scoring_start_time.isoformat() if self.scoring_start_time else None
            ),
            "freeze_time": self.freeze_time.isoformat() if self.freeze_time else None,
            "default_scoring": (
                self.default_scoring.to_mapping() if self.default_scoring else None
            ),
        }


@dataclass(frozen=True)
class ScoreboardEntry:
    """A single team's standing at a point in time."""

    team_id: str
    score: int
    solve_count: int
    last_solve_at: datetime | None = None
    rank: int = 0

    def to_mapping(self) -> dict[str, object]:
        return {
            "team_id": self.team_id,
            "score": self.score,
            "solve_count": self.solve_count,
            "last_solve_at": self.last_solve_at.isoformat() if self.last_solve_at else None,
            "rank": self.rank,
        }


@dataclass(frozen=True)
class ScoreboardSnapshot:
    """An immutable snapshot of standings, e.g. for a frozen scoreboard."""

    competition_id: str
    generated_at: datetime
    entries: list[ScoreboardEntry] = field(default_factory=list)
    frozen: bool = False

    def to_mapping(self) -> dict[str, object]:
        return {
            "competition_id": self.competition_id,
            "generated_at": self.generated_at.isoformat(),
            "entries": [entry.to_mapping() for entry in self.entries],
            "frozen": self.frozen,
        }


@dataclass(frozen=True)
class ChallengeValueSnapshot:
    """A challenge's computed point value at a point in time (dynamic scoring)."""

    challenge_id: str
    value: int
    solve_count: int
    computed_at: datetime

    def to_mapping(self) -> dict[str, object]:
        return {
            "challenge_id": self.challenge_id,
            "value": self.value,
            "solve_count": self.solve_count,
            "computed_at": self.computed_at.isoformat(),
        }

