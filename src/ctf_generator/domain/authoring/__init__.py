"""Authoring domain: the challenge-authoring aggregates that sit between the
deterministic generator and the competition control plane.

* ``ChallengeDefinition`` -- the stable identity of a challenge across edits.
* ``ChallengeVersion`` -- one concrete, individually-scorable revision; once
  ``published`` its content is frozen (draft → published → archived only).
* ``ChallengeBuild`` -- the content-addressed, insert-only materialized artifact
  of a version (byte-identical for identical generator/spec/family/seed).
* ``ChallengePublication`` -- a published version attached to a competition with
  its per-competition scoring config (the normalized ``ChallengeScoringConfig``).

Pure, frozen value types keyed by business identity; surrogate uuids, ``jsonb``
projections and lifecycle columns live only in ``ctf_generator.infrastructure``.
See ``models`` for the canonical home and each type's invariants.
"""

from .models import (
    VALID_DECAY_FUNCTIONS,
    VALID_VERSION_STATES,
    ChallengeBuild,
    ChallengeDefinition,
    ChallengePublication,
    ChallengeVersion,
)

__all__ = [
    "VALID_DECAY_FUNCTIONS",
    "VALID_VERSION_STATES",
    "ChallengeBuild",
    "ChallengeDefinition",
    "ChallengePublication",
    "ChallengeVersion",
]
