"""PostgreSQL integration tests for the M9 competitions API ([api]+[db], real PG).

Drives the FastAPI TestClient against a fresh, Alembic-migrated throwaway
database (same isolation approach as ``test_competition_repository_integration``):
the full create -> get -> list(paginated) -> patch(If-Match ok) ->
patch(stale If-Match -> 412) round trip, plus 404 / 409 / 422 / 401 / 403
envelopes and idempotent-create replay. SKIPS cleanly when the ``[api]``/``[db]``
extras or ``CTFGEN_TEST_DATABASE_URL`` are absent, so the host stdlib suite stays
green.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_competitions_integration
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

    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.deps import StubAuthenticator, principal_for
    from ctf_generator.interfaces.api.settings import ApiSettings
    from ctf_generator.schema import ERROR_SCHEMA

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
_PLAYER = "playertoken"  # noqa: S105 - test fixture token, not a real secret


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
            # Admin is a deployment-global SYSTEM role: authorized in every
            # competition (M10b scoped checks consult system_roles ∪ membership).
            _ADMIN: principal_for("admin-user", {"admin"}, system_roles={"admin"}),
            # Player has no membership: every scoped op it attempts here is a denial.
            _PLAYER: principal_for("player-user", {"player"}),
        }
    )


@contextmanager
def _client():
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            app = create_app(
                ApiSettings(), database=db, authenticator=_authenticator()
            )
            yield TestClient(app)
        finally:
            db.dispose()


def _auth(token: str = _ADMIN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _competition_body(cid: str = "spring-ctf-2026") -> dict:
    return {
        "competition_id": cid,
        "name": "Spring CTF 2026",
        "start_time": "2026-06-01T09:00:00Z",
        "end_time": "2026-06-03T09:00:00Z",
        "scoring_start_time": "2026-06-01T09:30:00Z",
        "freeze_time": "2026-06-02T09:00:00Z",
    }


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CompetitionsApiIntegrationTests(unittest.TestCase):
    def test_full_lifecycle_round_trip(self) -> None:
        with _client() as client:
            # CREATE -> 201 + ETag + stamped envelope
            r = client.post(
                "/api/v1/competitions", headers=_auth(), json=_competition_body()
            )
            self.assertEqual(r.status_code, 201, r.text)
            self.assertEqual(r.json()["schema"], "ctfgen.competition")
            self.assertEqual(r.json()["competition_id"], "spring-ctf-2026")
            etag = r.headers["ETag"]
            self.assertTrue(etag)

            # GET -> 200 + same ETag
            r = client.get("/api/v1/competitions/spring-ctf-2026", headers=_auth())
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers["ETag"], etag)
            self.assertEqual(r.json()["name"], "Spring CTF 2026")

            # LIST (paginated) -> the created competition appears
            r = client.get("/api/v1/competitions?limit=50", headers=_auth())
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertEqual(body["schema"], "ctfgen.competition-list")
            ids = [c["competition_id"] for c in body["data"]]
            self.assertIn("spring-ctf-2026", ids)
            self.assertIn("page", body)

            # PATCH with the correct If-Match -> 200, new ETag
            r = client.patch(
                "/api/v1/competitions/spring-ctf-2026",
                headers={**_auth(), "If-Match": etag},
                json={"name": "Spring CTF 2026 (rev)"},
            )
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["name"], "Spring CTF 2026 (rev)")
            new_etag = r.headers["ETag"]
            self.assertNotEqual(new_etag, etag)

            # PATCH with the STALE If-Match -> 412
            r = client.patch(
                "/api/v1/competitions/spring-ctf-2026",
                headers={**_auth(), "If-Match": etag},
                json={"name": "should not apply"},
            )
            self.assertEqual(r.status_code, 412, r.text)
            self.assertEqual(r.json()["error"]["code"], "precondition_failed")

    def test_patch_without_if_match_is_428(self) -> None:
        with _client() as client:
            client.post(
                "/api/v1/competitions", headers=_auth(), json=_competition_body()
            )
            r = client.patch(
                "/api/v1/competitions/spring-ctf-2026",
                headers=_auth(),
                json={"name": "x"},
            )
            self.assertEqual(r.status_code, 428)
            self.assertEqual(r.json()["error"]["code"], "precondition_failed")

    def test_missing_competition_is_404_envelope(self) -> None:
        with _client() as client:
            r = client.get("/api/v1/competitions/nope", headers=_auth())
            self.assertEqual(r.status_code, 404)
            self.assertEqual(r.json()["schema"], ERROR_SCHEMA)
            self.assertEqual(r.json()["error"]["code"], "not_found")
            self.assertIn("request_id", r.json()["error"])

    def test_duplicate_competition_is_409(self) -> None:
        with _client() as client:
            client.post(
                "/api/v1/competitions", headers=_auth(), json=_competition_body()
            )
            r = client.post(
                "/api/v1/competitions", headers=_auth(), json=_competition_body()
            )
            self.assertEqual(r.status_code, 409, r.text)
            self.assertEqual(r.json()["error"]["code"], "conflict")

    def test_malformed_body_is_422(self) -> None:
        with _client() as client:
            bad = _competition_body()
            bad["end_time"] = "2026-05-01T09:00:00Z"  # before start_time
            r = client.post("/api/v1/competitions", headers=_auth(), json=bad)
            self.assertEqual(r.status_code, 422, r.text)
            self.assertEqual(r.json()["error"]["code"], "validation_failed")
            self.assertTrue(r.json()["error"]["details"])

    def test_unauthenticated_is_401(self) -> None:
        with _client() as client:
            r = client.get("/api/v1/competitions/spring-ctf-2026")
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json()["error"]["code"], "unauthorized")

    def test_insufficient_principal_is_403(self) -> None:
        with _client() as client:
            r = client.post(
                "/api/v1/competitions",
                headers=_auth(_PLAYER),
                json=_competition_body(),
            )
            self.assertEqual(r.status_code, 403)
            self.assertEqual(r.json()["error"]["code"], "forbidden")

    def test_idempotency_key_replays_create(self) -> None:
        with _client() as client:
            headers = {**_auth(), "Idempotency-Key": "key-abc"}
            body = _competition_body()
            first = client.post("/api/v1/competitions", headers=headers, json=body)
            self.assertEqual(first.status_code, 201, first.text)
            replay = client.post("/api/v1/competitions", headers=headers, json=body)
            self.assertEqual(replay.status_code, 201, replay.text)
            self.assertEqual(
                replay.json()["competition_id"], first.json()["competition_id"]
            )
            # A reused key with a DIFFERENT body -> 409 idempotency_key_reused.
            other = _competition_body()
            other["name"] = "different"
            conflict = client.post(
                "/api/v1/competitions", headers=headers, json=other
            )
            self.assertEqual(conflict.status_code, 409)
            self.assertEqual(
                conflict.json()["error"]["code"], "idempotency_key_reused"
            )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class TeamsAndChallengesApiIntegrationTests(unittest.TestCase):
    """Proves the representative team + challenge-definition/version/publish
    routers (which copy the competitions pattern) work end to end against PG."""

    def test_team_create_get_list_scoped_to_competition(self) -> None:
        with _client() as client:
            client.post(
                "/api/v1/competitions", headers=_auth(), json=_competition_body()
            )
            r = client.post(
                "/api/v1/teams",
                headers=_auth(),
                json={"competition_id": "spring-ctf-2026", "name": "Red"},
            )
            self.assertEqual(r.status_code, 201, r.text)
            self.assertEqual(r.json()["schema"], "ctfgen.team")
            self.assertTrue(r.headers["ETag"])

            r = client.get(
                "/api/v1/teams/spring-ctf-2026/Red", headers=_auth()
            )
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["name"], "Red")

            r = client.get(
                "/api/v1/teams?competition_id=spring-ctf-2026", headers=_auth()
            )
            self.assertEqual(r.status_code, 200)
            self.assertEqual([t["name"] for t in r.json()["data"]], ["Red"])

            # A team under a missing competition -> 404 (fail-loud FK).
            r = client.post(
                "/api/v1/teams",
                headers=_auth(),
                json={"competition_id": "no-such", "name": "Blue"},
            )
            self.assertEqual(r.status_code, 404)

    def test_challenge_definition_version_publish_lifecycle(self) -> None:
        with _client() as client:
            r = client.post(
                "/api/v1/challenge-definitions",
                headers=_auth(),
                json={"family": "web", "slug": "sqli-1", "title": "SQLi One"},
            )
            self.assertEqual(r.status_code, 201, r.text)
            self.assertEqual(r.json()["schema"], "ctfgen.challenge-definition")
            def_etag = r.headers["ETag"]

            # PATCH title with If-Match.
            r = client.patch(
                "/api/v1/challenge-definitions/sqli-1",
                headers={**_auth(), "If-Match": def_etag},
                json={"title": "SQLi One (rev)"},
            )
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["title"], "SQLi One (rev)")

            # Create a DRAFT version (server allocates version_no, hashes spec).
            r = client.post(
                "/api/v1/challenge-versions",
                headers=_auth(),
                json={
                    "definition_slug": "sqli-1",
                    "seed": "seed-1",
                    "family_version": "1.0.0",
                    "spec": {"title": "SQLi One", "flagless": True},
                },
            )
            self.assertEqual(r.status_code, 201, r.text)
            body = r.json()
            self.assertEqual(body["state"], "draft")
            self.assertEqual(body["version_no"], 1)
            self.assertFalse(body["immutable"])
            self.assertTrue(body["spec_sha256"])

            # PUBLISH -> 200, state published, publish timestamp set.
            r = client.post(
                "/api/v1/challenge-versions/sqli-1/1/publish", headers=_auth()
            )
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["state"], "published")
            self.assertTrue(r.json()["immutable"])
            self.assertIsNotNone(r.json()["published_at"])

            # Re-publish -> 400 (no longer a draft; ValueError -> invalid_request).
            r = client.post(
                "/api/v1/challenge-versions/sqli-1/1/publish", headers=_auth()
            )
            self.assertEqual(r.status_code, 400, r.text)

            # GET single includes the spec; LIST does not.
            r = client.get("/api/v1/challenge-versions/sqli-1/1", headers=_auth())
            self.assertEqual(r.status_code, 200)
            self.assertIn("spec", r.json())
            r = client.get(
                "/api/v1/challenge-versions?definition_slug=sqli-1", headers=_auth()
            )
            self.assertEqual(r.status_code, 200)
            self.assertNotIn("spec", r.json()["data"][0])

    def test_version_create_requires_existing_definition(self) -> None:
        with _client() as client:
            r = client.post(
                "/api/v1/challenge-versions",
                headers=_auth(),
                json={
                    "definition_slug": "ghost",
                    "seed": "s",
                    "family_version": "1.0.0",
                    "spec": {"x": 1},
                },
            )
            self.assertEqual(r.status_code, 404, r.text)

    def test_player_cannot_publish(self) -> None:
        with _client() as client:
            client.post(
                "/api/v1/challenge-definitions",
                headers=_auth(),
                json={"family": "web", "slug": "d1", "title": "D1"},
            )
            client.post(
                "/api/v1/challenge-versions",
                headers=_auth(),
                json={
                    "definition_slug": "d1",
                    "seed": "s",
                    "family_version": "1.0.0",
                    "spec": {"x": 1},
                },
            )
            r = client.post(
                "/api/v1/challenge-versions/d1/1/publish", headers=_auth(_PLAYER)
            )
            self.assertEqual(r.status_code, 403)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
