"""Request-scoped collaborators for the web sub-app (M11 slice a).

Mirror of the API's ``interfaces.api.deps`` service getters, but reading from the
WEB sub-app's ``app.state`` (which the sub-app owns when mounted) and returning
the SAME application services -- so the web handlers are as thin as the API's:
resolve auth, call one service, render. No business logic, no session lifecycle.
"""

from __future__ import annotations

from fastapi import Request

from ctf_generator.application.auth import AuthService
from ctf_generator.application.catalog import (
    ChallengeDefinitionService,
    ChallengeVersionService,
    CompetitionService,
    TeamService,
)
from ctf_generator.application.catalog.publication_service import PublicationService
from ctf_generator.infrastructure.database.session import Database

from .settings import WebSettings


def get_web_settings(request: Request) -> WebSettings:
    settings = getattr(request.app.state, "web_settings", None)
    if settings is None:  # pragma: no cover - misconfiguration guard
        raise RuntimeError("no web settings configured on the web app")
    return settings


def get_web_database(request: Request) -> Database:
    database = getattr(request.app.state, "database", None)
    if database is None:  # pragma: no cover - misconfiguration guard
        raise RuntimeError("no database configured on the web app")
    return database


def get_web_auth_service(request: Request) -> AuthService:
    service = getattr(request.app.state, "auth_service", None)
    if service is None:  # pragma: no cover - misconfiguration guard
        raise RuntimeError("no auth service configured on the web app")
    return service


def get_web_competition_service(request: Request) -> CompetitionService:
    return CompetitionService(get_web_database(request))


def get_web_team_service(request: Request) -> TeamService:
    return TeamService(get_web_database(request))


def get_web_publication_service(request: Request) -> PublicationService:
    return PublicationService(get_web_database(request))


def get_web_challenge_definition_service(
    request: Request,
) -> ChallengeDefinitionService:
    return ChallengeDefinitionService(get_web_database(request))


def get_web_challenge_version_service(request: Request) -> ChallengeVersionService:
    return ChallengeVersionService(get_web_database(request))
