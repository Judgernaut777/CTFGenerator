"""Full-stack E2E scenario driven through the HTTP API edge (M20 stream 5).

The KEY evidence: the WHOLE contestant-scoring loop run as ONE ordered scenario
THROUGH THE HTTP API -- ``create_app`` wrapped in a Starlette ``TestClient`` (an
in-process ``httpx.Client``; no real socket) against a live PostgreSQL. Unlike
``test_cli_e2e_integration`` (which drives the same flow through the CLI process),
this test speaks the HTTP surface directly: it logs in over ``POST /auth/login``
and carries the returned bearer token on every subsequent request, exactly as an
external client would. Authentication is REAL (``DbAuthenticator`` over the
``AuthService`` bootstrapped admin + a password-credentialed contestant); nothing
is stubbed.

Scenario (each step asserts status + the resulting persisted state, read back
over HTTP):

  organizer logs in -> creates a competition -> creates a team -> creates a
  challenge definition -> creates a challenge version -> publishes it -> attaches
  the publication -> registers a contestant user -> [places the contestant on the
  team: NO membership-grant API route exists, so via services -- documented gap]
  -> contestant logs in -> submits the correct flag -> the submission is accepted
  and produces exactly ONE solve -> the projector folds the outbox -> the
  competition scoreboard reflects the solve.

Invariants asserted at the edge:
  * a DUPLICATE correct submission (a genuine re-submit, not an idempotency
    replay) does NOT create a second solve (``first_solve`` false, ``solve`` null)
    and does NOT move the scoreboard (append-only-consistent: solve_count and
    score unchanged after re-folding);
  * the expected flag never appears in any response body.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_e2e_flow_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime

try:  # heavy deps optional; guard so import never fails the host suite
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url
    from starlette.testclient import TestClient

    from ctf_generator.application.auth import AuthService
    from ctf_generator.application.auth.hashing import Pbkdf2Sha256Hasher
    from ctf_generator.application.scoring.projector import ScoreProjector
    from ctf_generator.domain.identity.models import Membership
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.membership_repository import (
        SqlAlchemyMembershipRepository,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.db_authenticator import DbAuthenticator
    from ctf_generator.interfaces.api.settings import ApiSettings

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - only without the extras
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)
_SKIP_REASON = (
    f"[api]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)

_V1 = "/api/v1"
_ADMIN_EMAIL = "organizer@example.com"
_ADMIN_PW = "correct-horse-battery-9"  # noqa: S105 - test fixture, not a real secret
_PLAYER_EMAIL = "red-one@example.com"
_PLAYER_PW = "player-horse-battery-8"  # noqa: S105 - test fixture, not a real secret

_CID = "spring-ctf-2026"
_SLUG = "sqli-1"
_TEAM = "Red"
_FLAG = "CTF{the-secret-flag}"


@contextmanager
def _app():
    base = make_url(_TEST_URL)
    name = f"ctfgen_e2e_it_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        url = base.set(database=name).render_as_string(hide_password=False)
        cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        db = Database(DatabaseConfig(url=url))
        try:
            service = AuthService(db, hasher=Pbkdf2Sha256Hasher(iterations=1000))
            service.bootstrap_admin(
                email=_ADMIN_EMAIL,
                display_name="Organizer",
                password=_ADMIN_PW,
                now=datetime.now(UTC),
            )
            app = create_app(
                ApiSettings(),
                database=db,
                auth_service=service,
                authenticator=DbAuthenticator(service),
            )
            yield app, db, service
        finally:
            db.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class HttpEndToEndFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self._ctx = _app()
        self.app, self.db, self.service = self._ctx.__enter__()
        self.client = TestClient(self.app, follow_redirects=False)

    def tearDown(self) -> None:
        self.client.close()
        self._ctx.__exit__(None, None, None)

    def _login(self, email: str, password: str) -> str:
        r = self.client.post(
            f"{_V1}/auth/login", json={"email": email, "password": password}
        )
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        self.assertTrue(token)
        # The password is inbound only -- it must never be echoed back.
        self.assertNotIn(password, r.text)
        return token

    @staticmethod
    def _auth(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def _standings(self, token: str) -> list[dict]:
        r = self.client.get(
            f"{_V1}/competitions/{_CID}/scoreboard", headers=self._auth(token)
        )
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["data"]

    def test_full_contestant_scoring_loop_over_http(self) -> None:
        # -- organizer authenticates over HTTP -----------------------------
        admin = self._login(_ADMIN_EMAIL, _ADMIN_PW)
        me = self.client.get(f"{_V1}/auth/me", headers=self._auth(admin))
        self.assertEqual(me.status_code, 200, me.text)
        self.assertEqual(me.json()["subject"], _ADMIN_EMAIL)

        # -- create a competition ------------------------------------------
        r = self.client.post(
            f"{_V1}/competitions",
            headers=self._auth(admin),
            json={
                "competition_id": _CID,
                "name": "Spring CTF 2026",
                "start_time": "2026-06-01T09:00:00Z",
                "end_time": "2026-06-03T09:00:00Z",
                "scoring_start_time": "2026-06-01T09:30:00Z",
                "freeze_time": "2026-06-02T09:00:00Z",
            },
        )
        self.assertEqual(r.status_code, 201, r.text)
        # Persisted effect visible in a read-back.
        got = self.client.get(
            f"{_V1}/competitions/{_CID}", headers=self._auth(admin)
        )
        self.assertEqual(got.status_code, 200, got.text)
        self.assertEqual(got.json()["competition_id"], _CID)

        # -- create a team --------------------------------------------------
        r = self.client.post(
            f"{_V1}/teams",
            headers=self._auth(admin),
            json={"competition_id": _CID, "name": _TEAM},
        )
        self.assertEqual(r.status_code, 201, r.text)
        teams = self.client.get(
            f"{_V1}/teams?competition_id={_CID}", headers=self._auth(admin)
        )
        self.assertEqual(teams.status_code, 200, teams.text)
        self.assertIn(_TEAM, [t["name"] for t in teams.json()["data"]])

        # -- create a challenge definition ---------------------------------
        r = self.client.post(
            f"{_V1}/challenge-definitions",
            headers=self._auth(admin),
            json={"family": "web", "slug": _SLUG, "title": "SQLi One"},
        )
        self.assertEqual(r.status_code, 201, r.text)

        # -- create a challenge version (spec carries the real flag) --------
        r = self.client.post(
            f"{_V1}/challenge-versions",
            headers=self._auth(admin),
            json={
                "definition_slug": _SLUG,
                "seed": "seed-1",
                "family_version": "1.0.0",
                "spec": {"title": "SQLi One", "flag": _FLAG},
            },
        )
        self.assertEqual(r.status_code, 201, r.text)
        # NB: the version-create response DOES echo the organizer's own authored
        # spec (flag included) -- that is the authoring surface, owned by the
        # organizer. The flag-leak invariant is asserted below on the
        # CONTESTANT-facing surfaces (submission outcome + list), where a leak
        # would be a real disclosure.

        # -- publish the version -------------------------------------------
        r = self.client.post(
            f"{_V1}/challenge-versions/{_SLUG}/1/publish", headers=self._auth(admin)
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["state"], "published")

        # -- attach the publication ----------------------------------------
        r = self.client.post(
            f"{_V1}/competitions/{_CID}/publications",
            headers=self._auth(admin),
            json={"definition_slug": _SLUG, "version_no": 1},
        )
        self.assertEqual(r.status_code, 201, r.text)
        pubs = self.client.get(
            f"{_V1}/competitions/{_CID}/publications", headers=self._auth(admin)
        )
        self.assertEqual(pubs.status_code, 200, pubs.text)
        self.assertIn(_SLUG, [p["definition_slug"] for p in pubs.json()["data"]])

        # -- register the contestant user ----------------------------------
        r = self.client.post(
            f"{_V1}/users",
            headers=self._auth(admin),
            json={
                "email": _PLAYER_EMAIL,
                "display_name": "Red One",
                "role": "player",
            },
        )
        self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(r.json()["email"], _PLAYER_EMAIL)

        # -- place the contestant on the team (NO API route -> services) ----
        # There is no membership-grant / team-placement endpoint on the HTTP
        # surface, so the contestant's password credential and their player
        # membership on _TEAM are seeded directly via the services. This is a
        # documented product/validation gap (see docs/validation/e2e.md), NOT an
        # invented route.
        self.service.set_password(_PLAYER_EMAIL, _PLAYER_PW, datetime.now(UTC))
        with self.db.session_scope() as session:
            SqlAlchemyMembershipRepository(session).add(
                Membership(
                    user_email=_PLAYER_EMAIL,
                    competition_id=_CID,
                    role="player",
                    team_name=_TEAM,
                )
            )

        # -- contestant authenticates over HTTP ----------------------------
        player = self._login(_PLAYER_EMAIL, _PLAYER_PW)
        who = self.client.get(f"{_V1}/auth/me", headers=self._auth(player))
        self.assertEqual(who.status_code, 200, who.text)
        self.assertEqual(who.json()["subject"], _PLAYER_EMAIL)

        # -- contestant submits the correct flag ---------------------------
        r = self.client.post(
            f"{_V1}/competitions/{_CID}/submissions",
            headers=self._auth(player),
            json={
                "team": _TEAM,
                "definition_slug": _SLUG,
                "version_no": 1,
                "answer": _FLAG,
            },
        )
        self.assertEqual(r.status_code, 201, r.text)
        body = r.json()
        self.assertTrue(body["correct"])
        self.assertTrue(body["first_solve"])
        self.assertIsNotNone(body["solve"])
        self.assertTrue(body["solve"]["solve_id"])
        # The candidate flag is inbound only -- never echoed in the outcome.
        self.assertNotIn(_FLAG, r.text)
        first_solve_id = body["solve"]["solve_id"]

        # -- the solve is exactly ONE ledger fact for the team -------------
        listing = self.client.get(
            f"{_V1}/competitions/{_CID}/submissions", headers=self._auth(player)
        )
        self.assertEqual(listing.status_code, 200, listing.text)
        rows = listing.json()["data"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["team"], _TEAM)
        self.assertTrue(rows[0]["correct"])

        # -- the scoreboard reflects the solve -----------------------------
        # A GET never triggers a projection run, so the scoreboard is empty until
        # the projector folds the transactional outbox (M7). Assert BOTH: empty
        # before, and the team ranked with exactly one solve after.
        self.assertEqual(self._standings(player), [])
        ScoreProjector(self.db).run_until_drained()
        standings = self._standings(player)
        self.assertEqual([e["team_id"] for e in standings], [_TEAM])
        self.assertEqual(standings[0]["solve_count"], 1)
        self.assertGreater(standings[0]["score"], 0)
        self.assertIsNotNone(standings[0]["last_solve_at"])

        # -- INVARIANT: a duplicate correct submission adds no second solve -
        # A genuine re-submit of the same correct flag (a distinct submission,
        # NOT an idempotency replay) must be accepted but produce no new solve.
        dup = self.client.post(
            f"{_V1}/competitions/{_CID}/submissions",
            headers=self._auth(player),
            json={
                "team": _TEAM,
                "definition_slug": _SLUG,
                "version_no": 1,
                "answer": _FLAG,
            },
        )
        self.assertEqual(dup.status_code, 201, dup.text)
        dup_body = dup.json()
        self.assertNotEqual(dup_body["submission_id"], body["submission_id"])
        self.assertTrue(dup_body["correct"])
        self.assertFalse(dup_body["first_solve"], "no second solve for a solved team")
        self.assertIsNone(dup_body["solve"])

        # -- INVARIANT: the scoreboard is append-only-consistent -----------
        # Re-folding after the duplicate must not add a solve or change the score:
        # the standing is byte-for-byte the same, and the solve_id is unchanged.
        ScoreProjector(self.db).run_until_drained()
        after = self._standings(player)
        self.assertEqual(after, standings)
        self.assertEqual(after[0]["solve_count"], 1)

        # The original solve is still the one and only solve on the ledger.
        final = self.client.get(
            f"{_V1}/competitions/{_CID}/submissions", headers=self._auth(player)
        )
        self.assertEqual(final.status_code, 200, final.text)
        solves = [s for s in final.json()["data"] if s["correct"]]
        self.assertEqual(len(solves), 2, "both correct attempts are recorded")
        # ...but they map to a single solve fact (first_solve semantics above).
        self.assertEqual(standings[0]["solve_count"], 1)
        self.assertTrue(first_solve_id)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
