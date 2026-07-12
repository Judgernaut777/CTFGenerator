"""Competition catalog service -- the unit-of-work-owning facade over
:class:`~ctf_generator.infrastructure.database.competition_repository.SqlAlchemyCompetitionRepository`.
"""

from __future__ import annotations

from collections.abc import Callable

from ctf_generator.domain.challenges.models import CompetitionConfig
from ctf_generator.infrastructure.database.competition_repository import (
    SqlAlchemyCompetitionRepository,
)
from ctf_generator.infrastructure.database.session import Database

Guard = Callable[[CompetitionConfig], None]


class CompetitionWindowError(ValueError):
    """The competition timing-window invariant was violated (``end>start``;
    ``scoring_start``/``freeze`` within ``[start, end]``). A :class:`ValueError`
    subclass so plain callers still see a value error, but the API error layer
    maps it to ``422 validation_failed`` (not the generic 400) and surfaces the
    per-field ``problems``. Carrying the invariant here (not only in the HTTP DTO
    / router) protects every non-HTTP caller of the service."""

    def __init__(self, problems: list[dict[str, str]]) -> None:
        self.problems = problems
        super().__init__("; ".join(p["issue"] for p in problems))


def _validate_window(config: CompetitionConfig) -> None:
    """Raise :class:`CompetitionWindowError` if ``config``'s timing window is
    invalid. The authoritative check (the HTTP DTO mirrors it for a field-level
    422 on create; this one also guards service-only / PATCH callers)."""
    problems: list[dict[str, str]] = []
    if config.end_time <= config.start_time:
        problems.append({"field": "end_time", "issue": "must be after start_time"})
    if config.scoring_start_time is not None and not (
        config.start_time <= config.scoring_start_time <= config.end_time
    ):
        problems.append(
            {
                "field": "scoring_start_time",
                "issue": "must be within [start_time, end_time]",
            }
        )
    if config.freeze_time is not None and not (
        config.start_time <= config.freeze_time <= config.end_time
    ):
        problems.append(
            {
                "field": "freeze_time",
                "issue": "must be within [start_time, end_time]",
            }
        )
    if problems:
        raise CompetitionWindowError(problems)


class CompetitionService:
    """Create / read / list / update competitions, owning the transaction."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def create(self, config: CompetitionConfig) -> CompetitionConfig:
        """Persist a new competition and return the stored aggregate. A duplicate
        ``competition_id`` (slug) surfaces the underlying
        :class:`~sqlalchemy.exc.IntegrityError` at flush time (the caller maps it
        to a 409). Domain/DB validation failures surface as their native
        exceptions. Raises :class:`CompetitionWindowError` (mapped to 422) if the
        timing window is invalid."""
        _validate_window(config)
        with self._database.session_scope() as session:
            repo = SqlAlchemyCompetitionRepository(session)
            repo.add(config)
            stored = repo.get(config.competition_id)
        assert stored is not None  # noqa: S101 - just inserted in this UoW
        return stored

    def get(self, competition_id: str) -> CompetitionConfig | None:
        with self._database.session_scope() as session:
            return SqlAlchemyCompetitionRepository(session).get(competition_id)

    def list(self) -> list[CompetitionConfig]:
        with self._database.session_scope() as session:
            return SqlAlchemyCompetitionRepository(session).list()

    def update(
        self, config: CompetitionConfig, *, guard: Guard | None = None
    ) -> CompetitionConfig:
        """Update the mutable fields of an existing competition atomically.

        ``guard`` (if given) is invoked with the freshly-read *current* aggregate
        inside the transaction and may raise to abort -- this is the seam the
        interface layer uses for ``If-Match`` optimistic-concurrency checks
        without the service knowing about ETags. Raises :class:`LookupError` if
        the competition does not exist, or :class:`CompetitionWindowError`
        (mapped to 422) if the update would violate the timing window -- enforced
        here so a non-HTTP / PATCH caller cannot bypass the invariant.

        When a ``guard`` is supplied the current aggregate is read *with a row
        lock* so two concurrent guarded updates serialize: the second blocks
        until the first commits, then its guard sees the new ETag and aborts
        (412) instead of silently overwriting.
        """
        _validate_window(config)
        with self._database.session_scope() as session:
            repo = SqlAlchemyCompetitionRepository(session)
            current = (
                repo.get_for_update(config.competition_id)
                if guard is not None
                else repo.get(config.competition_id)
            )
            if current is None:
                raise LookupError(
                    f"competition not found: {config.competition_id!r}"
                )
            if guard is not None:
                guard(current)
            repo.update(config)
            updated = repo.get(config.competition_id)
        assert updated is not None  # noqa: S101 - updated in this UoW
        return updated
