"""Authoring value types: ``ChallengeDefinition``, ``ChallengeVersion``,
``ChallengeBuild``, ``ChallengePublication``.

Pure domain aggregates -- frozen dataclasses over stdlib only. Each is keyed by
business identity, never a surrogate uuid:

* ``ChallengeDefinition`` -- keyed by ``slug`` (stable author-facing id).
* ``ChallengeVersion`` -- keyed by ``(definition_slug, version_no)``. Carries the
  authoritative content hash ``spec_sha256`` plus the canonical spec payload as
  a mapping. Once ``state == 'published'`` its content is frozen and it may only
  move to ``archived`` (the store enforces this with a trigger).
* ``ChallengeBuild`` -- keyed by its own content address ``build_sha256`` (the
  built bundle's hash). Insert-only: a new build is a new hash, never an edit.
* ``ChallengePublication`` -- a published version attached to a competition,
  keyed by ``(competition_id, definition_slug, version_no)``, carrying the
  per-competition scoring config (the normalized ``ChallengeScoringConfig``).

The ``spec``/``manifest`` mappings are treated as read-only content documents;
``spec_sha256`` (not the mapping) is the authoritative identity, because the
store keeps the mapping in ``jsonb`` which round-trips at the dict level, not
byte-for-byte.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

# A challenge version's lifecycle. Only two forward transitions are legal:
# draft -> published and published -> archived (enforced by a DB trigger too).
VALID_VERSION_STATES = frozenset({"draft", "published", "archived"})

# Scoring decay functions permitted on a publication (mirrors the DB CHECK and
# the ChallengeScoringConfig domain).
VALID_DECAY_FUNCTIONS = frozenset({"static", "linear", "logarithmic"})


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


@dataclass(frozen=True)
class ChallengeDefinition:
    """The stable identity of a challenge across edits. Keyed by ``slug``.

    ``family`` names one of the registered generator families (validated against
    the process registry at the application layer, stored as text). ``title`` is
    mutable display metadata; ``family`` and ``slug`` are identity.
    """

    family: str
    slug: str
    title: str

    def __post_init__(self) -> None:
        _require_nonempty(self.family, "family")
        _require_nonempty(self.slug, "slug")
        _require_nonempty(self.title, "title")


@dataclass(frozen=True)
class ChallengeVersion:
    """One concrete, scorable revision of a definition.

    Keyed by ``(definition_slug, version_no)``. ``spec_sha256`` is the
    authoritative content hash; ``spec`` is the canonical ``ChallengeSpec``
    mapping (a queryable copy). ``published_at`` is stamped when the version
    leaves ``draft`` and is retained through ``archived`` (so a version has a
    publish timestamp iff it is *not* a draft) -- this preserves publish
    provenance and lets ``published -> archived`` proceed without violating the
    state/timestamp invariant.
    """

    definition_slug: str
    version_no: int
    state: str
    family_version: str
    seed: str
    spec_sha256: str
    # spec_sha256 is the authoritative content identity, and the store keeps the
    # mapping in jsonb (round-trips at the dict level, not byte-for-byte, and
    # coerces tuples->lists / non-str keys->str). So the mapping is excluded from
    # equality/hash -- otherwise a persisted-then-reread version would compare
    # unequal to its in-memory original despite an identical hash. Excluding it
    # also restores hashability (a dict field would otherwise make it unhashable).
    spec: Mapping[str, object] = field(compare=False)
    spec_version: str
    mode: str = "red"
    cve_refs: tuple[str, ...] = ()
    cve_content_hash: str | None = None
    published_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.definition_slug, "definition_slug")
        if not isinstance(self.version_no, int) or self.version_no < 1:
            raise ValueError(f"version_no must be an int >= 1, got {self.version_no!r}")
        if self.state not in VALID_VERSION_STATES:
            raise ValueError(
                f"state must be one of {sorted(VALID_VERSION_STATES)}, "
                f"got {self.state!r}"
            )
        _require_nonempty(self.family_version, "family_version")
        _require_nonempty(self.seed, "seed")
        _require_nonempty(self.spec_sha256, "spec_sha256")
        _require_nonempty(self.spec_version, "spec_version")
        _require_nonempty(self.mode, "mode")
        if not isinstance(self.spec, Mapping):
            raise ValueError("spec must be a mapping (the canonical spec payload)")
        # published_at is set once the version leaves draft and kept thereafter:
        # a draft has no timestamp; published/archived both do. The DB CHECK
        # encodes the same rule.
        if (self.state == "draft") != (self.published_at is None):
            raise ValueError(
                "published_at must be None iff state is 'draft' "
                f"(state={self.state!r}, published_at={self.published_at!r})"
            )


@dataclass(frozen=True)
class ChallengeBuild:
    """The content-addressed, insert-only artifact of a version.

    Keyed by ``build_sha256`` (the built bundle's content address). References
    the version it materializes by ``(definition_slug, version_no)``.
    ``spec_sha256`` must equal that version's. ``manifest`` is the file
    manifest / provenance marker.
    """

    build_sha256: str
    definition_slug: str
    version_no: int
    family: str
    seed: str
    spec_sha256: str
    generator_version: str
    # Excluded from equality/hash for the same reason as ChallengeVersion.spec:
    # the manifest is a jsonb-stored document, identified content-wise by
    # build_sha256; comparing the mapping would break round-trip equality.
    manifest: Mapping[str, object] = field(compare=False)
    family_version: str | None = None
    storage_uri: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.build_sha256, "build_sha256")
        _require_nonempty(self.definition_slug, "definition_slug")
        if not isinstance(self.version_no, int) or self.version_no < 1:
            raise ValueError(f"version_no must be an int >= 1, got {self.version_no!r}")
        _require_nonempty(self.family, "family")
        _require_nonempty(self.seed, "seed")
        _require_nonempty(self.spec_sha256, "spec_sha256")
        _require_nonempty(self.generator_version, "generator_version")
        if not isinstance(self.manifest, Mapping):
            raise ValueError("manifest must be a mapping")


@dataclass(frozen=True)
class ChallengePublication:
    """A published version attached to a competition with its scoring config.

    Keyed by ``(competition_id, definition_slug, version_no)``. Only a published
    version may be attached (checked by the application; the version must exist).
    The scoring fields are the normalized ``ChallengeScoringConfig`` /
    ``FirstBloodBonusConfig``.
    """

    competition_id: str
    definition_slug: str
    version_no: int
    initial_value: int = 500
    minimum_value: int = 100
    decay_function: str = "static"
    decay: int = 0
    first_blood_enabled: bool = True
    first_blood_bonus_points: int = 0
    first_blood_bonus_percent: float = 0.0

    def __post_init__(self) -> None:
        _require_nonempty(self.competition_id, "competition_id")
        _require_nonempty(self.definition_slug, "definition_slug")
        if not isinstance(self.version_no, int) or self.version_no < 1:
            raise ValueError(f"version_no must be an int >= 1, got {self.version_no!r}")
        if self.decay_function not in VALID_DECAY_FUNCTIONS:
            raise ValueError(
                f"decay_function must be one of {sorted(VALID_DECAY_FUNCTIONS)}, "
                f"got {self.decay_function!r}"
            )
        if self.initial_value < 0:
            raise ValueError("initial_value must be >= 0")
        if self.minimum_value > self.initial_value:
            raise ValueError("minimum_value must be <= initial_value")
        if self.decay < 0:
            raise ValueError("decay must be >= 0")
        if self.first_blood_bonus_points < 0:
            raise ValueError("first_blood_bonus_points must be >= 0")
        if self.first_blood_bonus_percent < 0:
            raise ValueError("first_blood_bonus_percent must be >= 0")
