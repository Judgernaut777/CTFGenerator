"""Shared harness for the M11 organizer web-UI integration tests.

Needs the ``[api]`` + ``[web]`` + ``[db]`` extras and a running PostgreSQL
(``CTFGEN_TEST_DATABASE_URL``). Imported INSIDE each test module's guarded
try/except so the host suite (no extras) SKIPS cleanly rather than erroring.

Seeds real M10 auth data (users, password credentials, a system-admin grant,
per-competition memberships) and two competitions, then builds the JSON API app
with the M11 web UI mounted at ``/app``. Tests drive the browser flow over an
``https`` base_url so the ``Secure`` session cookie is stored + replayed by the
test client exactly as a real browser would.
"""

from __future__ import annotations

import os
import re
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from alembic import command
from alembic.config import Config as AlembicConfig
from fastapi.testclient import TestClient
from sqlalchemy.engine import make_url

from ctf_generator.application.auth import AuthService
from ctf_generator.application.auth.hashing import Pbkdf2Sha256Hasher
from ctf_generator.application.catalog import CompetitionService
from ctf_generator.domain.challenges.models import (
    ChallengeScoringConfig,
    CompetitionConfig,
)
from ctf_generator.domain.identity.models import Membership, User
from ctf_generator.infrastructure.database.config import DatabaseConfig
from ctf_generator.infrastructure.database.membership_repository import (
    SqlAlchemyMembershipRepository,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.user_repository import (
    SqlAlchemyUserRepository,
)
from ctf_generator.interfaces.api.app import create_app
from ctf_generator.interfaces.api.db_authenticator import DbAuthenticator
from ctf_generator.interfaces.api.settings import ApiSettings
from ctf_generator.interfaces.web import mount_web_app
from ctf_generator.interfaces.web.settings import WebSettings

TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Fixtures. Not real secrets.
PASSWORD = "correct-horse-battery"  # noqa: S105 - test fixture, not a real secret
ALICE = "alice@example.com"  # organizer of competition A only
CAROL = "carol@example.com"  # organizer of competition B only
DAVE = "dave@example.com"  # system admin (sees all)
NOBODY = "nobody@example.com"  # authenticated but authorized in no competition

COMP_A = "alpha-ctf-2026"
COMP_B = "bravo-ctf-2026"
NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


def _alembic_config(url: str) -> AlembicConfig:
    cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def competition_config(cid: str, name: str, *, with_scoring: bool = False) -> CompetitionConfig:
    # default_scoring persistence is not wired yet (it lands with
    # competition_challenges), so the fixture competitions carry none -- the web
    # detail view renders the timing window and simply omits the scoring card.
    scoring = (
        ChallengeScoringConfig(challenge_id="demo", initial_value=500, minimum_value=100)
        if with_scoring
        else None
    )
    return CompetitionConfig(
        competition_id=cid,
        name=name,
        start_time=NOW,
        end_time=NOW + timedelta(days=2),
        scoring_start_time=NOW,
        default_scoring=scoring,
    )


@contextmanager
def web_client(*, seed: bool = True):
    """Yield ``(client, db, service)`` with a fresh migrated database, the M11 web
    UI mounted at ``/app``, and (by default) the standard fixture data seeded."""
    base = make_url(TEST_URL)
    name = f"ctfgen_web_it_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        url = base.set(database=name).render_as_string(hide_password=False)
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            service = AuthService(db, hasher=Pbkdf2Sha256Hasher(iterations=1000))
            if seed:
                _seed(db, service)
            app = create_app(
                ApiSettings(),
                database=db,
                auth_service=service,
                authenticator=DbAuthenticator(service),
            )
            mount_web_app(
                app,
                database=db,
                auth_service=service,
                settings=WebSettings(mount_path="/app", cookie_secure=True),
            )
            client = TestClient(app, base_url="https://testserver")
            yield client, db, service
        finally:
            db.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _seed(db: Database, service: AuthService) -> None:
    competitions = CompetitionService(db)
    competitions.create(competition_config(COMP_A, "Alpha CTF"))
    competitions.create(competition_config(COMP_B, "Bravo CTF"))
    with db.session_scope() as s:
        users = SqlAlchemyUserRepository(s)
        for email, name in (
            (ALICE, "Alice"),
            (CAROL, "Carol"),
            (DAVE, "Dave"),
            (NOBODY, "Nobody"),
        ):
            users.add(User(email=email, display_name=name))
    for email in (ALICE, CAROL, DAVE, NOBODY):
        service.set_password(email, PASSWORD, NOW)
    service.grant_system_role(DAVE, "admin")
    with db.session_scope() as s:
        memberships = SqlAlchemyMembershipRepository(s)
        memberships.add(Membership(user_email=ALICE, competition_id=COMP_A, role="organizer"))
        memberships.add(Membership(user_email=CAROL, competition_id=COMP_B, role="organizer"))


def add_competition(db: Database, cid: str, name: str) -> None:
    """Add a competition with an arbitrary (possibly hostile) name, e.g. for XSS."""
    CompetitionService(db).create(competition_config(cid, name, with_scoring=False))


def grant_membership(db: Database, email: str, cid: str, role: str) -> None:
    with db.session_scope() as s:
        SqlAlchemyMembershipRepository(s).add(
            Membership(user_email=email, competition_id=cid, role=role)
        )


def login(client: TestClient, email: str, password: str = PASSWORD):
    """GET the login form to obtain the double-submit login-CSRF pair (cookie +
    hidden field), then POST the credentials with the matching token. Returns the
    (non-followed) POST response, exactly as a browser flow would produce it."""
    form = client.get("/app/login")
    token = extract_login_csrf(form.text)
    return client.post(
        "/app/login",
        data={"email": email, "password": password, "login_csrf_token": token},
        follow_redirects=False,
    )


def session_cookie(client: TestClient) -> str | None:
    return client.cookies.get("ctfgen_web_session")


_CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
_LOGIN_CSRF_RE = re.compile(r'name="login_csrf_token" value="([^"]+)"')


def extract_csrf(html: str) -> str | None:
    match = _CSRF_RE.search(html)
    return match.group(1) if match else None


def extract_login_csrf(html: str) -> str | None:
    match = _LOGIN_CSRF_RE.search(html)
    return match.group(1) if match else None
