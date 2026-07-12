"""Bidirectional mapping between domain aggregates and ORM rows.

Infrastructure-only. The domain never sees ORM objects; repositories call these
functions at the boundary. Mappers are pure (no session/IO) so they are trivial
to reason about and test.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from ctf_generator.domain.authoring.models import (
    ChallengeBuild,
    ChallengeDefinition,
    ChallengePublication,
    ChallengeVersion,
)
from ctf_generator.domain.challenges.models import CompetitionConfig
from ctf_generator.domain.identity.models import Membership, Team, User
from ctf_generator.domain.ledger.models import LedgerSubmission, ScoreEvent, Solve

from .models import ChallengeBuild as ChallengeBuildRow
from .models import ChallengeDefinition as ChallengeDefinitionRow
from .models import ChallengeVersion as ChallengeVersionRow
from .models import Competition
from .models import CompetitionChallenge as CompetitionChallengeRow
from .models import Membership as MembershipRow
from .models import ScoreEvent as ScoreEventRow
from .models import Solve as SolveRow
from .models import Submission as SubmissionRow
from .models import Team as TeamRow
from .models import User as UserRow


def _as_uuid(value: str) -> uuid.UUID:
    """Coerce a business id string to a uuid (ledger PKs/refs are uuids)."""
    return value if isinstance(value, uuid.UUID) else uuid.UUID(value)


def to_utc(value: datetime | None) -> datetime | None:
    """Coerce a datetime to an unambiguous UTC instant for persistence.

    A tz-aware value keeps its instant (converted to UTC). A naive value is
    assumed to already be UTC and is stamped with ``timezone.utc`` -- so the
    round-trip preserves the *instant* (as UTC), never the original named
    offset. ``None`` passes through.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def competition_to_orm(
    config: CompetitionConfig, existing: Competition | None = None
) -> Competition:
    """Map a domain ``CompetitionConfig`` onto an ORM ``Competition``.

    With ``existing is None`` a fresh row is built (new surrogate uuid via the
    column default, ``slug`` from ``competition_id``, ``status`` defaulting to
    'draft'). With ``existing`` given, only the mutable business fields are
    updated -- ``id``, ``slug``, ``created_at`` and ``status`` are left
    untouched, which is what the repository's ``update()`` relies on.

    ``default_scoring`` is not stored by this table; rather than silently drop
    it, a non-None value raises ``NotImplementedError`` until it lands with the
    ``competition_challenges`` normalization.
    """
    if config.default_scoring is not None:
        raise NotImplementedError(
            "default_scoring persistence lands with competition_challenges"
        )

    if existing is None:
        return Competition(
            slug=config.competition_id,
            name=config.name,
            start_time=to_utc(config.start_time),
            end_time=to_utc(config.end_time),
            scoring_start_at=to_utc(config.scoring_start_time),
            freeze_time=to_utc(config.freeze_time),
        )

    existing.name = config.name
    existing.start_time = to_utc(config.start_time)
    existing.end_time = to_utc(config.end_time)
    existing.scoring_start_at = to_utc(config.scoring_start_time)
    existing.freeze_time = to_utc(config.freeze_time)
    return existing


def competition_from_orm(row: Competition) -> CompetitionConfig:
    """Map an ORM ``Competition`` row back to a domain ``CompetitionConfig``.

    ``slug`` becomes ``competition_id``; ``scoring_start_at`` becomes
    ``scoring_start_time``. ORM-managed columns (``id``, ``status``,
    ``archived_at``, ``created_at``) have no domain counterpart and are dropped.
    ``default_scoring`` is always ``None`` -- it is not stored on this table.
    """
    return CompetitionConfig(
        competition_id=row.slug,
        name=row.name,
        start_time=row.start_time,
        end_time=row.end_time,
        scoring_start_time=row.scoring_start_at,
        freeze_time=row.freeze_time,
        default_scoring=None,
    )


# --- Identity aggregates -------------------------------------------------
#
# Users map purely. Teams and memberships reference other aggregates by
# surrogate uuid, which the domain never sees -- so their ``*_to_orm`` takes the
# already-resolved parent uuids (the repository looks them up by business key
# and fails loudly if absent) and their ``*_from_orm`` takes the parent business
# keys the repository read alongside the row. Mappers stay pure (no session/IO).


def user_to_orm(user: User, existing: UserRow | None = None) -> UserRow:
    """Map a domain ``User`` onto an ORM ``User`` row.

    Fresh row when ``existing is None`` (new surrogate uuid via the column
    default). With ``existing`` given, only the mutable ``display_name`` is
    updated -- ``id``, ``email`` and ``created_at`` are left untouched, which is
    what the repository's ``update()`` (keyed on the immutable email) relies on.
    """
    if existing is None:
        return UserRow(email=user.email, display_name=user.display_name)
    existing.display_name = user.display_name
    return existing


def user_from_orm(row: UserRow) -> User:
    """Map an ORM ``User`` row back to a domain ``User``. ORM-managed columns
    (``id``, ``archived_at``, ``created_at``) have no domain counterpart."""
    return User(email=row.email, display_name=row.display_name)


def team_to_orm(
    team: Team, competition_uuid: uuid.UUID, existing: TeamRow | None = None
) -> TeamRow:
    """Map a domain ``Team`` onto an ORM ``Team`` row.

    ``competition_uuid`` is the surrogate id of the owning competition, resolved
    by the repository from ``team.competition_id`` (the business slug). Teams are
    immutable in M6 (identity is ``(competition_id, name)`` and there are no
    other business fields), so ``existing`` is accepted only for symmetry and
    the mapper never mutates a passed row's identity.
    """
    if existing is not None:
        # Nothing mutable to update -- name/competition are the identity.
        return existing
    return TeamRow(competition_id=competition_uuid, name=team.name)


def team_from_orm(row: TeamRow, competition_slug: str) -> Team:
    """Map an ORM ``Team`` row back to a domain ``Team``.

    ``competition_slug`` is the owning competition's business id, read by the
    repository (the row itself only carries the surrogate ``competition_id``).
    """
    return Team(competition_id=competition_slug, name=row.name)


def membership_to_orm(
    membership: Membership,
    user_uuid: uuid.UUID,
    competition_uuid: uuid.UUID,
    team_uuid: uuid.UUID | None,
    existing: MembershipRow | None = None,
) -> MembershipRow:
    """Map a domain ``Membership`` onto an ORM ``Membership`` row.

    The three surrogate uuids are resolved by the repository from the
    membership's business identities (user email, competition slug, optional
    team name). ``team_uuid`` is ``None`` iff ``membership.team_name`` is ``None``
    -- the repository guarantees this pairing. With ``existing`` given, only the
    mutable ``role`` and ``team_id`` are updated (identity ``user_id`` /
    ``competition_id`` untouched), which ``update()`` relies on.
    """
    if existing is None:
        return MembershipRow(
            user_id=user_uuid,
            competition_id=competition_uuid,
            team_id=team_uuid,
            role=membership.role,
        )
    existing.role = membership.role
    existing.team_id = team_uuid
    return existing


def membership_from_orm(
    row: MembershipRow, user_email: str, competition_slug: str, team_name: str | None
) -> Membership:
    """Map an ORM ``Membership`` row back to a domain ``Membership``.

    The parent business identities (``user_email``, ``competition_slug``,
    optional ``team_name``) are read by the repository alongside the row; the
    row itself carries only surrogate uuids. ``team_name`` is ``None`` iff
    ``row.team_id`` is ``None`` -- asserted defensively below so a broken join
    contract fails loud here rather than yielding a silently wrong aggregate.
    """
    if (row.team_id is None) != (team_name is None):
        raise ValueError(
            "team_id/team_name inconsistency: resolved team name "
            f"{team_name!r} does not match row.team_id {row.team_id!r}"
        )
    return Membership(
        user_email=user_email,
        competition_id=competition_slug,
        role=row.role,
        team_name=team_name,
    )


# --- Authoring aggregates ------------------------------------------------
#
# Definitions map purely (slug is the business key, like Competition). Versions,
# builds and publications reference parents by surrogate uuid, which the domain
# never sees -- so their ``*_to_orm`` take already-resolved parent uuids (the
# repository looks them up by business key and fails loud if absent) and their
# ``*_from_orm`` take the parent business keys the repository read alongside the
# row. Version transitions (publish/archive) are applied by the repository
# directly on the row, so ``*_version_to_orm`` is create-only.


def challenge_definition_to_orm(
    definition: ChallengeDefinition, existing: ChallengeDefinitionRow | None = None
) -> ChallengeDefinitionRow:
    """Map a domain ``ChallengeDefinition`` onto its ORM row.

    Fresh row when ``existing is None``. With ``existing`` given, only the
    mutable ``title`` is updated; ``id``/``family``/``slug``/``created_at`` are
    left untouched (the repository's ``update`` relies on this)."""
    if existing is None:
        return ChallengeDefinitionRow(
            family=definition.family, slug=definition.slug, title=definition.title
        )
    existing.title = definition.title
    return existing


def challenge_definition_from_orm(
    row: ChallengeDefinitionRow,
) -> ChallengeDefinition:
    return ChallengeDefinition(family=row.family, slug=row.slug, title=row.title)


def challenge_version_to_orm(
    version: ChallengeVersion, definition_uuid: uuid.UUID
) -> ChallengeVersionRow:
    """Map a domain ``ChallengeVersion`` onto a fresh ORM row (create-only).

    ``definition_uuid`` is the owning definition's surrogate id, resolved by the
    repository from ``version.definition_slug``. ``spec`` (a mapping) is stored
    as ``jsonb``; ``cve_refs`` stores ``NULL`` when empty (design: non-CVE)."""
    return ChallengeVersionRow(
        definition_id=definition_uuid,
        version_no=version.version_no,
        state=version.state,
        family_version=version.family_version,
        seed=version.seed,
        mode=version.mode,
        spec_sha256=version.spec_sha256,
        spec_json=dict(version.spec),
        cve_refs=list(version.cve_refs) if version.cve_refs else None,
        cve_content_hash=version.cve_content_hash,
        spec_version=version.spec_version,
        published_at=to_utc(version.published_at),
    )


def challenge_version_from_orm(
    row: ChallengeVersionRow, definition_slug: str
) -> ChallengeVersion:
    """Map an ORM ``ChallengeVersion`` row back to a domain object.

    ``definition_slug`` is the owning definition's business id (read by the
    repository). ``spec_json`` (``jsonb``) comes back as a dict -- round-tripped
    at the dict level, not byte-for-byte; ``spec_sha256`` is the authoritative
    identity. NULL ``cve_refs`` becomes an empty tuple."""
    return ChallengeVersion(
        definition_slug=definition_slug,
        version_no=row.version_no,
        state=row.state,
        family_version=row.family_version,
        seed=row.seed,
        spec_sha256=row.spec_sha256,
        spec=dict(row.spec_json),
        spec_version=row.spec_version,
        mode=row.mode,
        cve_refs=tuple(row.cve_refs) if row.cve_refs else (),
        cve_content_hash=row.cve_content_hash,
        published_at=row.published_at,
    )


def challenge_build_to_orm(
    build: ChallengeBuild, version_uuid: uuid.UUID
) -> ChallengeBuildRow:
    """Map a domain ``ChallengeBuild`` onto a fresh ORM row (insert-only).

    ``version_uuid`` is the materialized version's surrogate id, resolved by the
    repository from ``(definition_slug, version_no)``."""
    return ChallengeBuildRow(
        build_sha256=build.build_sha256,
        challenge_version_id=version_uuid,
        family=build.family,
        seed=build.seed,
        family_version=build.family_version,
        spec_sha256=build.spec_sha256,
        generator_version=build.generator_version,
        manifest_json=dict(build.manifest),
        storage_uri=build.storage_uri,
    )


def challenge_build_from_orm(
    row: ChallengeBuildRow, definition_slug: str, version_no: int
) -> ChallengeBuild:
    """Map an ORM ``ChallengeBuild`` row back to a domain object. The parent
    ``(definition_slug, version_no)`` are read by the repository via a join."""
    return ChallengeBuild(
        build_sha256=row.build_sha256,
        definition_slug=definition_slug,
        version_no=version_no,
        family=row.family,
        seed=row.seed,
        spec_sha256=row.spec_sha256,
        generator_version=row.generator_version,
        manifest=dict(row.manifest_json),
        family_version=row.family_version,
        storage_uri=row.storage_uri,
    )


def challenge_publication_to_orm(
    publication: ChallengePublication,
    competition_uuid: uuid.UUID,
    version_uuid: uuid.UUID,
    existing: CompetitionChallengeRow | None = None,
) -> CompetitionChallengeRow:
    """Map a domain ``ChallengePublication`` onto a ``competition_challenges``
    row. The two surrogate uuids are resolved by the repository. With
    ``existing`` given, only the mutable scoring fields are updated; the
    identity (``competition_id``/``challenge_version_id``) and ``created_at`` are
    left untouched."""
    if existing is None:
        return CompetitionChallengeRow(
            competition_id=competition_uuid,
            challenge_version_id=version_uuid,
            initial_value=publication.initial_value,
            minimum_value=publication.minimum_value,
            decay_function=publication.decay_function,
            decay=publication.decay,
            first_blood_enabled=publication.first_blood_enabled,
            first_blood_bonus_points=publication.first_blood_bonus_points,
            first_blood_bonus_percent=publication.first_blood_bonus_percent,
        )
    existing.initial_value = publication.initial_value
    existing.minimum_value = publication.minimum_value
    existing.decay_function = publication.decay_function
    existing.decay = publication.decay
    existing.first_blood_enabled = publication.first_blood_enabled
    existing.first_blood_bonus_points = publication.first_blood_bonus_points
    existing.first_blood_bonus_percent = publication.first_blood_bonus_percent
    return existing


def challenge_publication_from_orm(
    row: CompetitionChallengeRow,
    competition_slug: str,
    definition_slug: str,
    version_no: int,
) -> ChallengePublication:
    """Map a ``competition_challenges`` row back to a domain
    ``ChallengePublication``. The parent business keys are read by the
    repository via joins."""
    return ChallengePublication(
        competition_id=competition_slug,
        definition_slug=definition_slug,
        version_no=version_no,
        initial_value=row.initial_value,
        minimum_value=row.minimum_value,
        decay_function=row.decay_function,
        decay=row.decay,
        first_blood_enabled=row.first_blood_enabled,
        first_blood_bonus_points=row.first_blood_bonus_points,
        first_blood_bonus_percent=row.first_blood_bonus_percent,
    )


# --- Ledger aggregates ---------------------------------------------------
#
# Submissions/solves/score_events reference competition, team and challenge
# version by surrogate uuid (resolved by the repository via _resolve). Their
# business ids (submission_id, solve_id) are uuid strings that map directly to
# the row PKs. ``*_from_orm`` take the parent business keys read alongside the
# row. Append-only: there is no existing-row (update) branch.


def submission_to_orm(
    submission: LedgerSubmission,
    competition_uuid: uuid.UUID,
    team_uuid: uuid.UUID,
    version_uuid: uuid.UUID,
    user_uuid: uuid.UUID | None,
) -> SubmissionRow:
    return SubmissionRow(
        id=_as_uuid(submission.submission_id),
        competition_id=competition_uuid,
        team_id=team_uuid,
        challenge_version_id=version_uuid,
        user_id=user_uuid,
        submitted_at=to_utc(submission.submitted_at),
        correct=submission.correct,
        instance_seed=submission.instance_seed,
    )


def submission_from_orm(
    row: SubmissionRow,
    competition_slug: str,
    team_name: str,
    definition_slug: str,
    version_no: int,
    submitter_email: str | None,
) -> LedgerSubmission:
    return LedgerSubmission(
        submission_id=str(row.id),
        competition_id=competition_slug,
        team_name=team_name,
        definition_slug=definition_slug,
        version_no=version_no,
        submitted_at=row.submitted_at,
        correct=row.correct,
        submitter_email=submitter_email,
        instance_seed=row.instance_seed,
    )


def solve_to_orm(
    solve: Solve,
    competition_uuid: uuid.UUID,
    team_uuid: uuid.UUID,
    version_uuid: uuid.UUID,
) -> SolveRow:
    return SolveRow(
        id=_as_uuid(solve.solve_id),
        competition_id=competition_uuid,
        team_id=team_uuid,
        challenge_version_id=version_uuid,
        submission_id=_as_uuid(solve.submission_id),
        solved_at=to_utc(solve.solved_at),
        instance_seed=solve.instance_seed,
    )


def solve_from_orm(
    row: SolveRow,
    competition_slug: str,
    team_name: str,
    definition_slug: str,
    version_no: int,
) -> Solve:
    return Solve(
        solve_id=str(row.id),
        competition_id=competition_slug,
        team_name=team_name,
        definition_slug=definition_slug,
        version_no=version_no,
        submission_id=str(row.submission_id),
        solved_at=row.solved_at,
        instance_seed=row.instance_seed,
    )


def score_event_to_orm(
    event: ScoreEvent,
    competition_uuid: uuid.UUID,
    team_uuid: uuid.UUID,
    version_uuid: uuid.UUID,
) -> ScoreEventRow:
    return ScoreEventRow(
        competition_id=competition_uuid,
        team_id=team_uuid,
        challenge_version_id=version_uuid,
        type=event.type,
        ts=event.ts,
        payload=dict(event.payload),
        submission_id=(
            _as_uuid(event.submission_id) if event.submission_id is not None else None
        ),
        solve_id=_as_uuid(event.solve_id) if event.solve_id is not None else None,
    )


def score_event_from_orm(
    row: ScoreEventRow,
    competition_slug: str,
    team_name: str,
    definition_slug: str,
    version_no: int,
) -> ScoreEvent:
    return ScoreEvent(
        competition_id=competition_slug,
        team_name=team_name,
        definition_slug=definition_slug,
        version_no=version_no,
        type=row.type,
        ts=row.ts,
        payload=dict(row.payload),
        submission_id=str(row.submission_id) if row.submission_id is not None else None,
        solve_id=str(row.solve_id) if row.solve_id is not None else None,
        seq=row.seq,
    )
