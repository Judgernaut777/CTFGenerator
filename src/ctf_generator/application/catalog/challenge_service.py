"""Challenge authoring catalog services -- unit-of-work-owning facades over the
challenge-definition and challenge-version repositories.

* :class:`ChallengeDefinitionService` -- create / read / list / update the stable
  logical challenge identity (keyed by ``slug``).
* :class:`ChallengeVersionService` -- create an immutable *draft* version under a
  definition (server-allocated ``version_no`` monotonic from 1, server-computed
  ``spec_sha256`` content hash), read / list, and ``publish`` a draft
  (``draft -> published``, forward-only, trigger-backstopped).

NOTE (slice-a scope): the endpoints draft describes ``POST /challenge-versions``
as triggering *deterministic generation* from ``{challenge_id, seed}``. Wiring the
generator pipeline into the API is deferred to a later slice; slice a persists a
draft from a client-supplied canonical spec payload and exercises the
create -> publish lifecycle. The content hash is authoritative and computed here,
so determinism/dedup (the ``(definition, spec_sha256)`` UNIQUE) still holds.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import datetime

from ctf_generator.domain.authoring.models import (
    ChallengeDefinition,
    ChallengeVersion,
)
from ctf_generator.infrastructure.database.challenge_definition_repository import (
    SqlAlchemyChallengeDefinitionRepository,
)
from ctf_generator.infrastructure.database.challenge_version_repository import (
    SqlAlchemyChallengeVersionRepository,
)
from ctf_generator.infrastructure.database.session import Database

DefinitionGuard = Callable[[ChallengeDefinition], None]
VersionGuard = Callable[[ChallengeVersion], None]


def spec_content_hash(spec: Mapping[str, object]) -> str:
    """Deterministic sha256 over the canonical JSON of a spec mapping. This is
    the authoritative content identity for a version (the store's
    ``(definition, spec_sha256)`` UNIQUE dedups byte-equivalent regenerations)."""
    canonical = json.dumps(
        spec, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ChallengeDefinitionService:
    """Create / read / list / update challenge definitions, owning the UoW."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def create(self, definition: ChallengeDefinition) -> ChallengeDefinition:
        with self._database.session_scope() as session:
            repo = SqlAlchemyChallengeDefinitionRepository(session)
            repo.add(definition)
            stored = repo.get(definition.slug)
        assert stored is not None  # noqa: S101 - just inserted in this UoW
        return stored

    def get(self, slug: str) -> ChallengeDefinition | None:
        with self._database.session_scope() as session:
            return SqlAlchemyChallengeDefinitionRepository(session).get(slug)

    def list(self) -> list[ChallengeDefinition]:
        with self._database.session_scope() as session:
            return SqlAlchemyChallengeDefinitionRepository(session).list()

    def update(
        self, definition: ChallengeDefinition, *, guard: DefinitionGuard | None = None
    ) -> ChallengeDefinition:
        """Update the mutable metadata (``title``) of an existing definition.
        ``guard`` is the optimistic-concurrency seam (see module docstring).
        Raises :class:`LookupError` if the definition does not exist."""
        with self._database.session_scope() as session:
            repo = SqlAlchemyChallengeDefinitionRepository(session)
            current = repo.get(definition.slug)
            if current is None:
                raise LookupError(
                    f"challenge definition not found: {definition.slug!r}"
                )
            if guard is not None:
                guard(current)
            repo.update(definition)
            updated = repo.get(definition.slug)
        assert updated is not None  # noqa: S101 - updated in this UoW
        return updated


class ChallengeVersionService:
    """Create draft / read / list / publish challenge versions, owning the UoW."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def create_draft(
        self,
        *,
        definition_slug: str,
        seed: str,
        family_version: str,
        spec: Mapping[str, object],
        spec_version: str,
        mode: str = "red",
        cve_refs: tuple[str, ...] = (),
        cve_content_hash: str | None = None,
    ) -> ChallengeVersion:
        """Insert a new ``draft`` version under an existing definition.

        ``version_no`` is allocated as ``max(existing) + 1`` within the same
        transaction and ``spec_sha256`` is computed from ``spec``. A missing
        definition raises :class:`LookupError`; a concurrent duplicate
        ``version_no`` / an identical ``spec_sha256`` surfaces the underlying
        :class:`~sqlalchemy.exc.IntegrityError` (the caller maps it to a 409).
        """
        with self._database.session_scope() as session:
            repo = SqlAlchemyChallengeVersionRepository(session)
            existing = repo.list_for_definition(definition_slug)
            next_no = (max((v.version_no for v in existing), default=0)) + 1
            version = ChallengeVersion(
                definition_slug=definition_slug,
                version_no=next_no,
                state="draft",
                family_version=family_version,
                seed=seed,
                spec_sha256=spec_content_hash(spec),
                spec=dict(spec),
                spec_version=spec_version,
                mode=mode,
                cve_refs=tuple(cve_refs),
                cve_content_hash=cve_content_hash,
                published_at=None,
            )
            repo.add(version)
            stored = repo.get(definition_slug, next_no)
        assert stored is not None  # noqa: S101 - just inserted in this UoW
        return stored

    def get(self, definition_slug: str, version_no: int) -> ChallengeVersion | None:
        with self._database.session_scope() as session:
            return SqlAlchemyChallengeVersionRepository(session).get(
                definition_slug, version_no
            )

    def list_for_definition(self, definition_slug: str) -> list[ChallengeVersion]:
        with self._database.session_scope() as session:
            return SqlAlchemyChallengeVersionRepository(
                session
            ).list_for_definition(definition_slug)

    def publish(
        self,
        definition_slug: str,
        version_no: int,
        now: datetime,
        *,
        guard: VersionGuard | None = None,
    ) -> ChallengeVersion:
        """Transition a ``draft`` version to ``published`` (stamping
        ``published_at=now``). ``guard`` is the optimistic-concurrency seam.
        Raises :class:`LookupError` if the version is missing, :class:`ValueError`
        if it is not a draft."""
        with self._database.session_scope() as session:
            repo = SqlAlchemyChallengeVersionRepository(session)
            current = repo.get(definition_slug, version_no)
            if current is None:
                raise LookupError(
                    f"challenge version not found: {definition_slug!r} v{version_no}"
                )
            if guard is not None:
                guard(current)
            repo.publish(definition_slug, version_no, now)
            updated = repo.get(definition_slug, version_no)
        assert updated is not None  # noqa: S101 - updated in this UoW
        return updated
