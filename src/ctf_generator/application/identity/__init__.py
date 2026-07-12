"""Identity application services: unit-of-work-owning use-case facades over the
identity persistence repositories (users, memberships, teams).

Mirrors the catalog services' pattern -- every method opens a
:meth:`~ctf_generator.infrastructure.database.session.Database.session_scope`
(commit-on-success / rollback-on-error) and instantiates the concrete repository
on that session, so no session or commit logic leaks into an interface handler.
ORM rows never escape the repositories; these services speak only in the frozen
domain aggregates.
"""

from __future__ import annotations

from .service import IdentityService

__all__ = ["IdentityService"]
