"""Concrete SQLAlchemy repository for the EvalRun aggregate (M15).

Implements the domain
:class:`ctf_generator.domain.repositories.EvalRunRepository` over the
``eval_runs`` platform-record table. An eval run references the version it
evaluates by the business ``(definition_slug, version_no)``; the repository
resolves it to the surrogate uuid and fails loudly (:class:`LookupError`) if
the version is missing. The dedupe key ``(challenge_version_id, profile,
adversarial)`` is UNIQUE, so a duplicate request surfaces as an
``IntegrityError`` the application layer collapses. ``update`` is the guarded
status move; a terminal row is frozen by the ``eval_run_transition_guard`` DB
trigger (the backstop -- the app service is the primary guard). ORM rows never
escape: every method returns domain objects.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.evaluation.models import EvalRun

from .mappers import eval_run_apply_update, eval_run_from_orm, eval_run_to_orm
from .models import ChallengeDefinition as ChallengeDefinitionRow
from .models import ChallengeVersion as ChallengeVersionRow
from .models import EvalRun as EvalRunRow


class SqlAlchemyEvalRunRepository:
    """Persist and retrieve eval-run records, keyed by ``eval_run_id``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _version_uuid(self, definition_slug: str, version_no: int) -> uuid.UUID:
        result = self._session.scalars(
            select(ChallengeVersionRow.id)
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
            )
        ).one_or_none()
        if result is None:
            raise LookupError(
                f"challenge version not found: {definition_slug!r} v{version_no}"
            )
        return result

    def add(self, eval_run: EvalRun) -> None:
        """Insert a fresh eval run. Raises :class:`LookupError` if the version is
        missing and ``IntegrityError`` on a duplicate ``eval_run_id`` or a
        duplicate ``(challenge_version_id, profile, adversarial)`` at flush."""
        version_uuid = self._version_uuid(
            eval_run.definition_slug, eval_run.version_no
        )
        row = eval_run_to_orm(eval_run, version_uuid)
        self._session.add(row)
        self._session.flush()

    def get(self, eval_run_id: str) -> EvalRun | None:
        row = self._session.execute(
            select(
                EvalRunRow,
                ChallengeDefinitionRow.slug,
                ChallengeVersionRow.version_no,
            )
            .join(
                ChallengeVersionRow,
                EvalRunRow.challenge_version_id == ChallengeVersionRow.id,
            )
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(EvalRunRow.id == uuid.UUID(eval_run_id))
        ).one_or_none()
        if row is None:
            return None
        eval_row, definition_slug, version_no = row
        return eval_run_from_orm(eval_row, definition_slug, version_no)

    def get_for_version(
        self, definition_slug: str, version_no: int, profile: str, adversarial: bool
    ) -> EvalRun | None:
        row = self._session.execute(
            select(EvalRunRow)
            .join(
                ChallengeVersionRow,
                EvalRunRow.challenge_version_id == ChallengeVersionRow.id,
            )
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
                EvalRunRow.profile == profile,
                EvalRunRow.adversarial == adversarial,
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        return eval_run_from_orm(row, definition_slug, version_no)

    def list_for_version(
        self, definition_slug: str, version_no: int
    ) -> list[EvalRun]:
        rows = self._session.scalars(
            select(EvalRunRow)
            .join(
                ChallengeVersionRow,
                EvalRunRow.challenge_version_id == ChallengeVersionRow.id,
            )
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
            )
            .order_by(EvalRunRow.requested_at, EvalRunRow.id)
        )
        return [
            eval_run_from_orm(row, definition_slug, version_no) for row in rows
        ]

    def update(self, eval_run: EvalRun) -> None:
        """Guarded status move + advisory-result/error update, keyed by
        ``eval_run_id``. Raises :class:`LookupError` if the run does not exist;
        the DB trigger rejects leaving a terminal state."""
        row = self._session.get(EvalRunRow, uuid.UUID(eval_run.eval_run_id))
        if row is None:
            raise LookupError(f"eval run not found: {eval_run.eval_run_id!r}")
        eval_run_apply_update(row, eval_run)
        self._session.flush()
