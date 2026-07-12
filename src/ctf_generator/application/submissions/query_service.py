"""Read-only submission query service (unit-of-work-owning).

The *write* path (attempt -> verify -> first-correct-solve -> commit once) is
:class:`~ctf_generator.application.submissions.service.SubmissionProcessingService`.
This service exposes the append-only ledger for reads only: list a team's or a
whole competition's attempts, and fetch one attempt with its derived solve (if
any). The candidate flag is never persisted, so it can never appear in any read
-- :class:`~ctf_generator.domain.ledger.models.LedgerSubmission` carries only the
``correct`` boolean, never the answer.

Tenancy (which team a caller may read) is an authorization concern decided in the
interface layer from the :class:`~ctf_generator.interfaces.api.deps.Principal`;
this service just serves the requested scope.
"""

from __future__ import annotations

from ctf_generator.domain.ledger.models import LedgerSubmission, Solve
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.solve_repository import (
    SqlAlchemySolveRepository,
)
from ctf_generator.infrastructure.database.submission_repository import (
    SqlAlchemyLedgerSubmissionRepository,
)


class SubmissionQueryService:
    """List / fetch submissions read-only, owning the transaction."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def list_for_team(
        self, competition_id: str, team_name: str
    ) -> list[LedgerSubmission]:
        with self._database.session_scope() as session:
            return SqlAlchemyLedgerSubmissionRepository(session).list_for_team(
                competition_id, team_name
            )

    def list_for_competition(self, competition_id: str) -> list[LedgerSubmission]:
        with self._database.session_scope() as session:
            return SqlAlchemyLedgerSubmissionRepository(
                session
            ).list_for_competition(competition_id)

    def get_detail(
        self, submission_id: str
    ) -> tuple[LedgerSubmission, Solve | None] | None:
        """Return one attempt and the solve it produced (``None`` if it was not a
        first-correct solve), or ``None`` if the submission is unknown."""
        with self._database.session_scope() as session:
            submission = SqlAlchemyLedgerSubmissionRepository(session).get(
                submission_id
            )
            if submission is None:
                return None
            solve = SqlAlchemySolveRepository(session).get_by_submission(
                submission_id
            )
            return submission, solve
