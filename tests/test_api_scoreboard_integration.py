"""PostgreSQL integration tests for the M9 slice-b scoreboard API ([api]+[db]).

empty scoreboard; after solves the correct ordering + a full pagination walk with
no gaps/dupes; the lag endpoint is organizer/ops-only (player -> 403). SKIPS
cleanly without the ``[api]``/``[db]`` extras or ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_scoreboard_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager

try:  # heavy deps optional; guard so import never fails the host suite
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from sqlalchemy.engine import make_url

    from ctf_generator.application.scoring.projector import ScoreProjector
    from ctf_generator.domain.authoring.models import ChallengePublication
    from ctf_generator.infrastructure.database.challenge_publication_repository import (
        SqlAlchemyChallengePublicationRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.deps import StubAuthenticator, principal_for
    from ctf_generator.interfaces.api.settings import ApiSettings

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - only without the extras
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"[api]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_ADMIN = "admintoken"  # noqa: S105 - test fixture token, not a real secret
_ORGANIZER = "orgtoken"  # noqa: S105 - test fixture token, not a real secret
_PLAYER = "playertoken"  # noqa: S105 - test fixture token, not a real secret

_CID = "spring-ctf-2026"
_FLAGS = {"sqli-1": "CTF{one}", "sqli-2": "CTF{two}"}


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_it_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _alembic_config(url) -> AlembicConfig:
    cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    cfg.set_main_option("sqlalchemy.url", str(url))
    return cfg


def _authenticator() -> StubAuthenticator:
    return StubAuthenticator(
        {
            _ADMIN: principal_for("admin-user", {"admin"}),
            _ORGANIZER: principal_for("org-user", {"organizer"}),
            _PLAYER: principal_for("player-user", {"player"}, team="Red"),
        }
    )


@contextmanager
def _client_and_db():
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            app = create_app(
                ApiSettings(), database=db, authenticator=_authenticator()
            )
            yield TestClient(app), db
        finally:
            db.dispose()


def _auth(token: str = _ADMIN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _competition_body() -> dict:
    return {
        "competition_id": _CID,
        "name": "Spring CTF 2026",
        "start_time": "2026-06-01T09:00:00Z",
        "end_time": "2026-06-03T09:00:00Z",
        "scoring_start_time": "2026-06-01T09:30:00Z",
        "freeze_time": "2026-06-02T09:00:00Z",
    }


def _seed(client: TestClient, db: Database) -> None:
    """Competition + Red/Blue teams + two published, attached challenges."""
    assert client.post(
        "/api/v1/competitions", headers=_auth(), json=_competition_body()
    ).status_code == 201
    for team in ("Red", "Blue"):
        assert client.post(
            "/api/v1/teams",
            headers=_auth(),
            json={"competition_id": _CID, "name": team},
        ).status_code == 201
    for slug, flag in _FLAGS.items():
        assert client.post(
            "/api/v1/challenge-definitions",
            headers=_auth(),
            json={"family": "web", "slug": slug, "title": slug},
        ).status_code == 201
        assert client.post(
            "/api/v1/challenge-versions",
            headers=_auth(),
            json={
                "definition_slug": slug,
                "seed": "s",
                "family_version": "1.0.0",
                "spec": {"title": slug, "flag": flag},
            },
        ).status_code == 201
        assert client.post(
            f"/api/v1/challenge-versions/{slug}/1/publish", headers=_auth()
        ).status_code == 200
        with db.session_scope() as session:
            SqlAlchemyChallengePublicationRepository(session).add(
                ChallengePublication(
                    competition_id=_CID, definition_slug=slug, version_no=1
                )
            )


def _solve(client: TestClient, team: str, slug: str) -> None:
    r = client.post(
        f"/api/v1/competitions/{_CID}/submissions",
        headers=_auth(),
        json={
            "team": team,
            "definition_slug": slug,
            "version_no": 1,
            "answer": _FLAGS[slug],
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["correct"], r.text


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ScoreboardApiIntegrationTests(unittest.TestCase):
    def test_empty_scoreboard(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client, db)
            r = client.get(
                f"/api/v1/competitions/{_CID}/scoreboard", headers=_auth(_PLAYER)
            )
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["schema"], "ctfgen.scoreboard")
            self.assertEqual(r.json()["data"], [])
            self.assertFalse(r.json()["page"]["has_more"])

    def test_ordering_and_pagination_walk(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client, db)
            # Red solves both challenges; Blue solves one -> Red outranks Blue.
            _solve(client, "Red", "sqli-1")
            _solve(client, "Red", "sqli-2")
            _solve(client, "Blue", "sqli-1")
            ScoreProjector(db).run_until_drained()

            full = client.get(
                f"/api/v1/competitions/{_CID}/scoreboard", headers=_auth(_PLAYER)
            )
            self.assertEqual(full.status_code, 200, full.text)
            rows = full.json()["data"]
            self.assertEqual([r["team_id"] for r in rows], ["Red", "Blue"])
            self.assertEqual(rows[0]["solve_count"], 2)
            self.assertEqual(rows[1]["solve_count"], 1)
            self.assertGreater(rows[0]["score"], rows[1]["score"])
            self.assertEqual(rows[0]["rank"], 1)

            # Walk the same ordering one page at a time: no gaps, no dupes.
            walked: list[str] = []
            cursor: str | None = None
            for _ in range(10):  # generous bound; the walk terminates well before
                url = f"/api/v1/competitions/{_CID}/scoreboard?limit=1"
                if cursor:
                    url += f"&cursor={cursor}"
                page = client.get(url, headers=_auth(_PLAYER))
                self.assertEqual(page.status_code, 200, page.text)
                walked.extend(e["team_id"] for e in page.json()["data"])
                cursor = page.json()["page"]["next_cursor"]
                if cursor is None:
                    break
            self.assertEqual(walked, ["Red", "Blue"])
            self.assertEqual(len(walked), len(set(walked)))

    def test_lag_endpoint_is_organizer_only(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client, db)
            player = client.get(
                f"/api/v1/competitions/{_CID}/scoreboard/lag", headers=_auth(_PLAYER)
            )
            self.assertEqual(player.status_code, 403, player.text)
            self.assertEqual(player.json()["error"]["code"], "forbidden")

            org = client.get(
                f"/api/v1/competitions/{_CID}/scoreboard/lag",
                headers=_auth(_ORGANIZER),
            )
            self.assertEqual(org.status_code, 200, org.text)
            self.assertEqual(org.json()["schema"], "ctfgen.scoreboard-lag")
            body = org.json()
            for key in (
                "pending_count",
                "latest_seq",
                "max_as_of_seq",
                "failed_count",
            ):
                self.assertIn(key, body)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
