"""PostgreSQL integration tests for the M15 evaluations API ([api]+[db]).

Request an agent-eval (202 + EvalRun envelope; a queued ``run_agent_evaluation``
job appears -- NOT an in-process eval), read it / list it, idempotent re-request
(200, same record). A contestant is 403. A missing version -> 404; a
non-published version -> 409 (never a 500). SKIPS cleanly without the extras /
``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_evaluations_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from sqlalchemy.engine import make_url

    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.deps import StubAuthenticator, principal_for
    from ctf_generator.interfaces.api.settings import ApiSettings

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"[api]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_ADMIN = "admintoken"  # noqa: S105
_AUTHOR = "authortoken"  # noqa: S105
_ORGANIZER = "orgtoken"  # noqa: S105
_PLAYER = "playertoken"  # noqa: S105

_SLUG = "sqli"


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_eval_{uuid.uuid4().hex[:12]}"
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
            # Evaluations are an AUTHORING surface (flat require_permission): an
            # author/organizer evaluates a version independent of any competition.
            _ADMIN: principal_for("admin-user", {"admin"}, system_roles={"admin"}),
            _AUTHOR: principal_for("author-user", {"author"}),
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


def _seed_published_version(client: TestClient) -> None:
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
            "spec": {"title": "SQLi"},
        },
    ).status_code == 201
    assert client.post(
        f"/api/v1/challenge-versions/{_SLUG}/1/publish", headers=_auth()
    ).status_code == 200


def _seed_second_draft(client: TestClient) -> None:
    # A second version (v2) left as DRAFT -- request against it must 409.
    assert client.post(
        "/api/v1/challenge-versions",
        headers=_auth(),
        json={
            "definition_slug": _SLUG,
            "seed": "s2",
            "family_version": "1.0.0",
            "spec": {"title": "SQLi", "rev": 2},
        },
    ).status_code == 201


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class EvaluationsApiIntegrationTests(unittest.TestCase):
    def test_request_read_list_and_job_enqueued(self) -> None:
        with _client_and_db() as (client, db):
            _seed_published_version(client)
            r = client.post(
                f"/api/v1/challenge-versions/{_SLUG}/1/evaluations"
                "?profile=writeup_replay",
                headers=_auth(_AUTHOR),
            )
            self.assertEqual(r.status_code, 202, r.text)
            body = r.json()
            self.assertEqual(body["schema"], "ctfgen.eval-run")
            self.assertEqual(body["status"], "pending")
            self.assertEqual(body["profile"], "writeup_replay")
            eval_run_id = body["eval_run_id"]
            # No secret/payload leaked into the response.
            self.assertNotIn("payload", body)
            self.assertIsNone(body["solved"])

            # A REAL queued eval job exists -- the control plane did NOT run it.
            with db.session_scope() as s:
                count = s.execute(
                    sa.text(
                        "SELECT count(*) FROM jobs "
                        "WHERE job_type='run_agent_evaluation' AND status='queued'"
                    )
                ).scalar_one()
            self.assertEqual(count, 1)

            # Read one.
            detail = client.get(
                f"/api/v1/evaluations/{eval_run_id}", headers=_auth(_ORGANIZER)
            )
            self.assertEqual(detail.status_code, 200, detail.text)
            self.assertEqual(detail.json()["eval_run_id"], eval_run_id)

            # List.
            listed = client.get(
                f"/api/v1/challenge-versions/{_SLUG}/1/evaluations",
                headers=_auth(_AUTHOR),
            )
            self.assertEqual(listed.status_code, 200, listed.text)
            self.assertEqual(listed.json()["schema"], "ctfgen.eval-run-list")
            self.assertIn(
                eval_run_id, [e["eval_run_id"] for e in listed.json()["data"]]
            )

    def test_re_request_is_idempotent(self) -> None:
        with _client_and_db() as (client, db):
            _seed_published_version(client)
            first = client.post(
                f"/api/v1/challenge-versions/{_SLUG}/1/evaluations"
                "?profile=writeup_replay",
                headers=_auth(_AUTHOR),
            )
            second = client.post(
                f"/api/v1/challenge-versions/{_SLUG}/1/evaluations"
                "?profile=writeup_replay",
                headers=_auth(_AUTHOR),
            )
            self.assertEqual(first.status_code, 202, first.text)
            self.assertEqual(second.status_code, 200, second.text)
            self.assertEqual(
                first.json()["eval_run_id"], second.json()["eval_run_id"]
            )
            with db.session_scope() as s:
                count = s.execute(
                    sa.text(
                        "SELECT count(*) FROM jobs "
                        "WHERE job_type='run_agent_evaluation'"
                    )
                ).scalar_one()
            self.assertEqual(count, 1)

    def test_missing_version_is_404(self) -> None:
        with _client_and_db() as (client, db):
            _seed_published_version(client)
            r = client.post(
                f"/api/v1/challenge-versions/{_SLUG}/99/evaluations"
                "?profile=writeup_replay",
                headers=_auth(_AUTHOR),
            )
            self.assertEqual(r.status_code, 404, r.text)

    def test_non_published_version_is_409_not_500(self) -> None:
        with _client_and_db() as (client, db):
            _seed_published_version(client)
            _seed_second_draft(client)
            r = client.post(
                f"/api/v1/challenge-versions/{_SLUG}/2/evaluations"
                "?profile=writeup_replay",
                headers=_auth(_AUTHOR),
            )
            self.assertEqual(r.status_code, 409, r.text)
            self.assertEqual(r.json()["error"]["code"], "conflict")

    def test_unknown_profile_is_400(self) -> None:
        with _client_and_db() as (client, db):
            _seed_published_version(client)
            r = client.post(
                f"/api/v1/challenge-versions/{_SLUG}/1/evaluations?profile=nope",
                headers=_auth(_AUTHOR),
            )
            self.assertEqual(r.status_code, 400, r.text)

    def test_contestant_is_forbidden(self) -> None:
        with _client_and_db() as (client, db):
            _seed_published_version(client)
            probes = [
                client.post(
                    f"/api/v1/challenge-versions/{_SLUG}/1/evaluations"
                    "?profile=writeup_replay",
                    headers=_auth(_PLAYER),
                ),
                client.get(
                    f"/api/v1/challenge-versions/{_SLUG}/1/evaluations",
                    headers=_auth(_PLAYER),
                ),
                client.get("/api/v1/evaluations/nope", headers=_auth(_PLAYER)),
            ]
            for r in probes:
                self.assertEqual(r.status_code, 403, r.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
