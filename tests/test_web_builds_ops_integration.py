"""PostgreSQL integration tests for the M11c BUILD ops views.

List a version's content-addressed builds; a trigger ENQUEUES a durable
``build_challenge`` job (DB-verified job row -- the control plane never runs the
build in-process); authz mirrors the API's flat authoring permissions
(BUILD_READ / BUILD_CREATE); CSRF is enforced on the trigger. SKIPS cleanly
without the extras / test DB.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_builds_ops_integration
"""

from __future__ import annotations

import os
import unittest
import uuid

try:
    import sqlalchemy as sa
    import web_support as ws

    from ctf_generator.domain.authoring.models import ChallengeBuild
    from ctf_generator.infrastructure.database.challenge_build_repository import (
        SqlAlchemyChallengeBuildRepository,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_SKIP_REASON = (
    f"[api]/[web]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_SLUG = "sqli"


def _seed_version(db) -> None:
    ws.seed_published_version(db, _SLUG, "SQLi")


def _plant_build(db) -> str:
    with db.session_scope() as s:
        version_sha = s.execute(
            sa.text("SELECT spec_sha256 FROM challenge_versions LIMIT 1")
        ).scalar_one()
    build_sha = f"build-{uuid.uuid4().hex}"
    with db.session_scope() as s:
        SqlAlchemyChallengeBuildRepository(s).add(
            ChallengeBuild(
                build_sha256=build_sha,
                definition_slug=_SLUG,
                version_no=1,
                family="web",
                seed="s",
                spec_sha256=version_sha,
                generator_version="1.0.0",
                manifest={"files": ["a"]},
            )
        )
    return build_sha


def _build_job_count(db) -> int:
    with db.session_scope() as s:
        return s.execute(
            sa.text("SELECT count(*) FROM jobs WHERE job_type = 'build_challenge'")
        ).scalar_one()


def _csrf(client, path):
    r = client.get(path)
    return r, ws.extract_csrf(r.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class BuildOpsWebTests(unittest.TestCase):
    def test_build_list_renders(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)  # organizer: BUILD_READ
            _seed_version(db)
            build_sha = _plant_build(db)
            page = client.get(
                f"/app/challenge-definitions/{_SLUG}/builds", params={"version_no": 1}
            )
            self.assertEqual(page.status_code, 200, page.text)
            self.assertIn(build_sha, page.text)
            self.assertNotIn("style=", page.text)

    def test_trigger_enqueues_build_job_not_in_process(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)  # organizer: BUILD_CREATE
            _seed_version(db)
            self.assertEqual(_build_job_count(db), 0)
            _r, token = _csrf(
                client,
                f"/app/challenge-definitions/{_SLUG}/builds?version_no=1",
            )
            resp = client.post(
                f"/app/challenge-definitions/{_SLUG}/builds",
                data={"csrf_token": token, "version_no": "1"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertIn("enqueued", resp.text)
            # A durable job row exists -- the build was NOT run in-process.
            self.assertEqual(_build_job_count(db), 1)

    def test_contestant_cannot_read_or_trigger(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.EVE)  # player: no BUILD_READ/BUILD_CREATE
            _seed_version(db)
            self.assertEqual(
                client.get(
                    f"/app/challenge-definitions/{_SLUG}/builds",
                    params={"version_no": 1},
                ).status_code,
                403,
            )
            # With a valid session CSRF token so the denial is the AUTHZ path
            # (no BUILD_CREATE), not merely the CSRF guard.
            _r, token = _csrf(client, "/app/")
            resp = client.post(
                f"/app/challenge-definitions/{_SLUG}/builds",
                data={"csrf_token": token or "", "version_no": "1"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertEqual(_build_job_count(db), 0)

    def test_trigger_without_csrf_is_403_and_no_job(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            _seed_version(db)
            resp = client.post(
                f"/app/challenge-definitions/{_SLUG}/builds",
                data={"version_no": "1"},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertEqual(_build_job_count(db), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
