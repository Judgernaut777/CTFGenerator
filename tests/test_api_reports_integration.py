"""PostgreSQL integration tests for the reports API ([api]+[db]).

A report is a read-only summary of already-persisted data. A POST FREEZES an
immutable snapshot; a GET reads the latest snapshot or a subject's history.
Authorization is ROLE-SCOPED PER REPORT: the version-scoped kinds carry their own
flat read permission (validation->``challenge:read``, build->``build:read``,
eval->``eval:read``); the competition-run report is competition-scoped on
``scoreboard:read``. SKIPS cleanly without the extras / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_reports_integration
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
_SLUG = "sqli"
_FLAG = "CTF{one}"


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_report_{uuid.uuid4().hex[:12]}"
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
            _ADMIN: principal_for("admin-user", {"admin"}, system_roles={"admin"}),
            _ORGANIZER: principal_for(
                "org-user", {"organizer"}, memberships={_CID: ("organizer", None)}
            ),
            # A contestant: no flat AUTHORING read permission (challenge/build/eval),
            # but a SCOREBOARD_READ-bearing membership in _CID.
            _PLAYER: principal_for(
                "player-user", {"player"}, team="Red",
                memberships={_CID: ("player", "Red")},
            ),
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


def _seed_version(client: TestClient) -> None:
    assert client.post(
        "/api/v1/challenge-definitions",
        headers=_auth(),
        json={"family": "web", "slug": _SLUG, "title": "SQLi"},
    ).status_code == 201
    assert client.post(
        "/api/v1/challenge-versions",
        headers=_auth(),
        json={
            "definition_slug": _SLUG,
            "seed": "s",
            "family_version": "1.0.0",
            "spec": {"title": "SQLi", "flag": _FLAG},
        },
    ).status_code == 201


def _seed_competition_with_solve(client: TestClient, db: Database) -> None:
    """Competition + Red team + one published, attached challenge with a solve."""
    assert client.post(
        "/api/v1/competitions", headers=_auth(), json=_competition_body()
    ).status_code == 201
    assert client.post(
        "/api/v1/teams",
        headers=_auth(),
        json={"competition_id": _CID, "name": "Red"},
    ).status_code == 201
    _seed_version(client)
    assert client.post(
        f"/api/v1/challenge-versions/{_SLUG}/1/publish", headers=_auth()
    ).status_code == 200
    with db.session_scope() as session:
        SqlAlchemyChallengePublicationRepository(session).add(
            ChallengePublication(
                competition_id=_CID, definition_slug=_SLUG, version_no=1
            )
        )
    r = client.post(
        f"/api/v1/competitions/{_CID}/submissions",
        headers=_auth(),
        json={
            "team": "Red",
            "definition_slug": _SLUG,
            "version_no": 1,
            "answer": _FLAG,
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["correct"], r.text
    ScoreProjector(db).run_until_drained()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class VersionReportsApiIntegrationTests(unittest.TestCase):
    def test_snapshot_and_read_validation_report(self) -> None:
        with _client_and_db() as (client, db):
            _seed_version(client)
            # No snapshot yet -> latest is 404.
            self.assertEqual(
                client.get(
                    f"/api/v1/reports/versions/{_SLUG}/1/validation/latest",
                    headers=_auth(_ORGANIZER),
                ).status_code,
                404,
            )
            # Freeze a snapshot.
            post = client.post(
                f"/api/v1/reports/versions/{_SLUG}/1/validation",
                headers=_auth(_ORGANIZER),
            )
            self.assertEqual(post.status_code, 201, post.text)
            body = post.json()
            self.assertEqual(body["schema"], "ctfgen.report-snapshot")
            self.assertEqual(body["report_type"], "validation")
            self.assertEqual(body["definition_slug"], _SLUG)
            self.assertEqual(body["version_no"], 1)
            # A report FAITHFULLY summarizes static validation of the spec as
            # stored: ``valid`` is a bool and ``error_count`` matches the error
            # list -- it does not assert the spec happens to be valid.
            payload = body["payload"]
            self.assertIsInstance(payload["valid"], bool)
            self.assertEqual(payload["error_count"], len(payload["errors"]))
            self.assertEqual(payload["valid"], payload["error_count"] == 0)
            report_id = body["report_id"]

            # Latest returns the same immutable snapshot.
            latest = client.get(
                f"/api/v1/reports/versions/{_SLUG}/1/validation/latest",
                headers=_auth(_ORGANIZER),
            )
            self.assertEqual(latest.status_code, 200, latest.text)
            self.assertEqual(latest.json()["report_id"], report_id)

            # History lists it.
            lst = client.get(
                f"/api/v1/reports/versions/{_SLUG}/1/validation",
                headers=_auth(_ORGANIZER),
            )
            self.assertEqual(lst.status_code, 200, lst.text)
            self.assertEqual(lst.json()["schema"], "ctfgen.report-snapshot-list")
            self.assertIn(
                report_id, [s["report_id"] for s in lst.json()["data"]]
            )

    def test_build_and_eval_reports_snapshot(self) -> None:
        with _client_and_db() as (client, db):
            _seed_version(client)
            for kind in ("build", "eval"):
                post = client.post(
                    f"/api/v1/reports/versions/{_SLUG}/1/{kind}",
                    headers=_auth(_ADMIN),
                )
                self.assertEqual(post.status_code, 201, post.text)
                self.assertEqual(post.json()["report_type"], kind)
            # A build report with no build image reports built=false, secret-free.
            build = client.get(
                f"/api/v1/reports/versions/{_SLUG}/1/build/latest",
                headers=_auth(_ADMIN),
            ).json()
            self.assertFalse(build["payload"]["built"])
            self.assertIsNone(build["payload"]["image_ref"])

    def test_unknown_version_is_404(self) -> None:
        with _client_and_db() as (client, db):
            _seed_version(client)
            r = client.post(
                f"/api/v1/reports/versions/{_SLUG}/99/validation",
                headers=_auth(_ORGANIZER),
            )
            self.assertEqual(r.status_code, 404, r.text)

    def test_contestant_forbidden_on_version_reports(self) -> None:
        with _client_and_db() as (client, db):
            _seed_version(client)
            # A player holds no flat challenge/build/eval read permission.
            probes = [
                client.post(
                    f"/api/v1/reports/versions/{_SLUG}/1/validation",
                    headers=_auth(_PLAYER),
                ),
                client.get(
                    f"/api/v1/reports/versions/{_SLUG}/1/build/latest",
                    headers=_auth(_PLAYER),
                ),
                client.get(
                    f"/api/v1/reports/versions/{_SLUG}/1/eval",
                    headers=_auth(_PLAYER),
                ),
            ]
            for r in probes:
                self.assertEqual(r.status_code, 403, r.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CompetitionRunReportApiIntegrationTests(unittest.TestCase):
    def test_snapshot_and_read_competition_run(self) -> None:
        with _client_and_db() as (client, db):
            _seed_competition_with_solve(client, db)
            post = client.post(
                f"/api/v1/reports/competitions/{_CID}/run",
                headers=_auth(_ORGANIZER),
            )
            self.assertEqual(post.status_code, 201, post.text)
            payload = post.json()["payload"]
            self.assertEqual(payload["competition_id"], _CID)
            self.assertEqual(payload["solve_count"], 1)
            self.assertEqual(len(payload["first_bloods"]), 1)
            self.assertEqual(payload["first_bloods"][0]["team"], "Red")

            latest = client.get(
                f"/api/v1/reports/competitions/{_CID}/run/latest",
                headers=_auth(_ORGANIZER),
            )
            self.assertEqual(latest.status_code, 200, latest.text)
            self.assertEqual(latest.json()["report_id"], post.json()["report_id"])

    def test_contestant_can_read_own_competition_run(self) -> None:
        with _client_and_db() as (client, db):
            _seed_competition_with_solve(client, db)
            # A player of _CID holds SCOREBOARD_READ there -> may read the run report.
            post = client.post(
                f"/api/v1/reports/competitions/{_CID}/run",
                headers=_auth(_PLAYER),
            )
            self.assertEqual(post.status_code, 201, post.text)
            lst = client.get(
                f"/api/v1/reports/competitions/{_CID}/run",
                headers=_auth(_PLAYER),
            )
            self.assertEqual(lst.status_code, 200, lst.text)
            self.assertGreaterEqual(len(lst.json()["data"]), 1)

    def test_outsider_forbidden_on_other_competition_run(self) -> None:
        with _client_and_db() as (client, db):
            _seed_competition_with_solve(client, db)
            # A player with no membership in some OTHER competition is denied there.
            r = client.get(
                "/api/v1/reports/competitions/other-ctf/run/latest",
                headers=_auth(_PLAYER),
            )
            self.assertEqual(r.status_code, 403, r.text)

    def test_no_snapshot_is_404(self) -> None:
        with _client_and_db() as (client, db):
            _seed_competition_with_solve(client, db)
            r = client.get(
                f"/api/v1/reports/competitions/{_CID}/run/latest",
                headers=_auth(_ORGANIZER),
            )
            self.assertEqual(r.status_code, 404, r.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
