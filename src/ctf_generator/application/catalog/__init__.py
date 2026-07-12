"""Catalog application services: thin, unit-of-work-owning use-case facades over
the M6 persistence repositories for the *authoring / configuration* aggregates
(competitions, teams, challenge definitions and versions).

These services are the write/read boundary the interface layer (CLI, the M9 HTTP
API, MCP) calls. They own the transaction -- every method opens a
:meth:`~ctf_generator.infrastructure.database.session.Database.session_scope`
(commit-on-success / rollback-on-error) and instantiates the concrete repository
on that session -- so no session or commit logic ever leaks into an interface
handler, mirroring the existing ``JobService`` / ``SubmissionProcessingService``
pattern. ORM rows never escape the repositories; these services speak only in the
frozen domain aggregates.

Optimistic-concurrency preconditions are expressed as a caller-supplied ``guard``
callback invoked with the freshly-read current aggregate *inside* the
transaction. This keeps the atomic read-check-write on the application side while
leaving the HTTP-specific ETag/``If-Match`` vocabulary entirely in the interface
layer (the service never imports it): the guard simply raises to abort, and the
unit of work rolls back.
"""

from __future__ import annotations

from .challenge_service import (
    ChallengeDefinitionService,
    ChallengeVersionService,
)
from .competition_service import CompetitionService
from .publication_service import PublicationService
from .team_service import TeamService

__all__ = [
    "CompetitionService",
    "TeamService",
    "ChallengeDefinitionService",
    "ChallengeVersionService",
    "PublicationService",
]
