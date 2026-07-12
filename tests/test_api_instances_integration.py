"""PostgreSQL integration tests for the M9 slice-c instances API ([api]+[db]).

Covers the operator view + lifecycle actions and, critically, the SECRET
BOUNDARY: a planted instance credential (``secret_ref``), runtime-resource handle
(``external_ref``), and internal endpoint token must NEVER appear in any list or
detail body. A contestant (player) is 403 on every instance endpoint. SKIPS
cleanly without the ``[api]``/``[db]`` extras or ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_instances_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from sqlalchemy.engine import make_url

    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.instances.models import (
        Instance,
        InstanceCredential,
        InstanceEndpoint,
        RuntimeResource,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.instance_repository import (
        SqlAlchemyInstanceRepository,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.worker_repository import (
        SqlAlchemyWorkerRegistry,
    )
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
_ORGANIZER = "orgtoken"  # noqa: S105
_PLAYER = "playertoken"  # noqa: S105

_CID = "spring-ctf-2026"
_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)

# Planted secrets that MUST NOT leak into any response.
_CRED_SECRET = "vault://instance-cred-SECRET-TOKEN-zzz"  # noqa: S105
_RESOURCE_HANDLE = "container-runtime-SECRET-HANDLE-yyy"  # noqa: S105
_INTERNAL_TOKEN = "INTERNAL-ADMIN-SECRET-TOKEN-xxx"  # noqa: S105
_PUBLIC_URL = "https://ctf.example.com/c/public-abc"


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_inst_{uuid.uuid4().hex[:12]}"
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


def _seed_parents(client: TestClient) -> None:
    assert client.post(
        "/api/v1/competitions",
        headers=_auth(),
        json={
            "competition_id": _CID,
            "name": "Spring CTF",
            "start_time": "2026-06-01T09:00:00Z",
            "end_time": "2026-06-03T09:00:00Z",
        },
    ).status_code == 201
    assert client.post(
        "/api/v1/teams", headers=_auth(), json={"competition_id": _CID, "name": "Red"}
    ).status_code == 201
    assert client.post(
        "/api/v1/challenge-definitions",
        headers=_auth(),
        json={"family": "web", "slug": "sqli", "title": "SQLi"},
    ).status_code == 201
    assert client.post(
        "/api/v1/challenge-versions",
        headers=_auth(),
        json={
            "definition_slug": "sqli",
            "seed": "s",
            "family_version": "1.0.0",
            "spec": {"title": "SQLi", "flag": "CTF{x}"},
        },
    ).status_code == 201
    assert client.post(
        "/api/v1/challenge-versions/sqli/1/publish", headers=_auth()
    ).status_code == 200


def _seed_instance_with_secrets(db: Database) -> str:
    iid = str(uuid.uuid4())
    with db.session_scope() as s:
        reg = SqlAlchemyWorkerRegistry(s)
        reg.add(Worker("w1", "docker-rootless", ("x86_64",), ("launch_instance",), 4, "1"))
        reg.approve("w1")
        reg.heartbeat("w1", _NOW)
    with db.session_scope() as s:
        repo = SqlAlchemyInstanceRepository(s)
        repo.add(
            Instance(
                instance_id=iid,
                competition_id=_CID,
                team_name="Red",
                definition_slug="sqli",
                version_no=1,
                state="active",
                desired_state="active",
                assigned_worker="w1",
                image_ref="registry.example/sqli@sha256:abc",
                instance_seed="SEED-should-not-leak-123",
                expires_at=_NOW + timedelta(hours=1),
            ),
            _NOW,
        )
        # Plant the secrets that must never surface.
        repo.record_credential(
            InstanceCredential(
                instance_id=iid, name="ssh", secret_ref=_CRED_SECRET,
                scopes=("shell",),
            )
        )
        repo.record_runtime_resource(
            RuntimeResource(
                instance_id=iid, kind="container", external_ref=_RESOURCE_HANDLE,
                worker="w1",
            )
        )
        repo.record_endpoint(
            InstanceEndpoint(
                instance_id=iid, name="admin", host="10.0.0.5", port=9000,
                protocol="https", url=f"https://10.0.0.5:9000/?token={_INTERNAL_TOKEN}",
                internal=True,
            )
        )
        repo.record_endpoint(
            InstanceEndpoint(
                instance_id=iid, name="web", host="ctf.example.com", port=443,
                protocol="https", url=_PUBLIC_URL, internal=False,
            )
        )
    return iid


def _seed_plain_instance(db: Database) -> str:
    """Add a bare (worker-less, secret-less) instance under the seeded parents.
    Used to populate the list for pagination-walk assertions."""
    iid = str(uuid.uuid4())
    with db.session_scope() as s:
        SqlAlchemyInstanceRepository(s).add(
            Instance(
                instance_id=iid,
                competition_id=_CID,
                team_name="Red",
                definition_slug="sqli",
                version_no=1,
                state="active",
                desired_state="active",
                expires_at=_NOW + timedelta(hours=1),
            ),
            _NOW,
        )
    return iid


def _enable_placeable_worker(db: Database) -> None:
    """Register + approve + heartbeat a dispatch-eligible worker and open a
    platform ``active_instances`` pool so a launch can reserve + place."""
    from ctf_generator.domain.scheduling.models import (
        PLATFORM_SCOPE_KEY,
        ResourceQuota,
    )
    from ctf_generator.infrastructure.database.quota_repository import (
        SqlAlchemyQuotaPolicyRepository,
    )

    with db.session_scope() as s:
        reg = SqlAlchemyWorkerRegistry(s)
        reg.add(
            Worker("w1", "docker-rootless", ("x86_64",), ("launch_instance",), 4, "1")
        )
        reg.approve("w1")
    with db.session_scope() as s:
        SqlAlchemyWorkerRegistry(s).heartbeat("w1", datetime.now(UTC))
    with db.session_scope() as s:
        SqlAlchemyQuotaPolicyRepository(s).upsert_limit(
            ResourceQuota("platform", PLATFORM_SCOPE_KEY, "active_instances", 100)
        )


def _count_instances(db: Database, iid: str) -> int:
    with db.session_scope() as s:
        return s.execute(
            sa.text("SELECT count(*) FROM instances WHERE id = :iid"),
            {"iid": iid},
        ).scalar_one()


def _count_launch_jobs(db: Database) -> int:
    with db.session_scope() as s:
        return s.execute(
            sa.text("SELECT count(*) FROM jobs WHERE job_type = 'launch_instance'")
        ).scalar_one()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class InstancesApiIntegrationTests(unittest.TestCase):
    def test_list_and_detail(self) -> None:
        with _client_and_db() as (client, db):
            _seed_parents(client)
            iid = _seed_instance_with_secrets(db)

            lst = client.get("/api/v1/instances", headers=_auth(_ORGANIZER))
            self.assertEqual(lst.status_code, 200, lst.text)
            self.assertEqual(lst.json()["schema"], "ctfgen.instance-list")
            ids = [row["instance_id"] for row in lst.json()["data"]]
            self.assertIn(iid, ids)

            scoped = client.get(
                f"/api/v1/competitions/{_CID}/instances", headers=_auth(_ORGANIZER)
            )
            self.assertEqual(scoped.status_code, 200, scoped.text)
            self.assertIn(iid, [r["instance_id"] for r in scoped.json()["data"]])

            detail = client.get(f"/api/v1/instances/{iid}", headers=_auth(_ORGANIZER))
            self.assertEqual(detail.status_code, 200, detail.text)
            body = detail.json()
            self.assertEqual(body["state"], "active")
            self.assertEqual(body["assigned_worker"], "w1")
            # Public endpoint present; internal endpoint absent.
            urls = [e["url"] for e in body["endpoints"]]
            self.assertIn(_PUBLIC_URL, urls)
            self.assertEqual([e["name"] for e in body["endpoints"]], ["web"])

    def test_missing_instance_is_404(self) -> None:
        with _client_and_db() as (client, db):
            _seed_parents(client)
            r = client.get(
                f"/api/v1/instances/{uuid.uuid4()}", headers=_auth(_ORGANIZER)
            )
            self.assertEqual(r.status_code, 404, r.text)
            self.assertEqual(r.json()["error"]["code"], "not_found")

    def test_stop_action_drives_desired_state(self) -> None:
        with _client_and_db() as (client, db):
            _seed_parents(client)
            iid = _seed_instance_with_secrets(db)
            r = client.post(
                f"/api/v1/instances/{iid}/stop", headers=_auth(_ORGANIZER)
            )
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["desired_state"], "stopped")
            self.assertEqual(r.json()["instance_id"], iid)
            # Persisted.
            detail = client.get(f"/api/v1/instances/{iid}", headers=_auth(_ORGANIZER))
            self.assertEqual(detail.json()["desired_state"], "stopped")

    def test_no_credential_or_token_leaks(self) -> None:
        with _client_and_db() as (client, db):
            _seed_parents(client)
            iid = _seed_instance_with_secrets(db)
            lst = client.get("/api/v1/instances", headers=_auth(_ADMIN))
            detail = client.get(f"/api/v1/instances/{iid}", headers=_auth(_ADMIN))
            for resp in (lst, detail):
                text = resp.text
                for secret in (
                    _CRED_SECRET,
                    _RESOURCE_HANDLE,
                    _INTERNAL_TOKEN,
                    "SEED-should-not-leak-123",
                ):
                    self.assertNotIn(secret, text, f"secret leaked: {secret!r}")

    def test_contestant_is_forbidden_everywhere(self) -> None:
        with _client_and_db() as (client, db):
            _seed_parents(client)
            iid = _seed_instance_with_secrets(db)
            # List / path-competition / body-competition routes carry the tenancy
            # context in the caller's own request, so an unauthorized contestant is
            # a plain 403 (no new information disclosed).
            forbidden_probes = [
                ("get", "/api/v1/instances"),
                ("get", f"/api/v1/competitions/{_CID}/instances"),
            ]
            for method, path in forbidden_probes:
                r = getattr(client, method)(path, headers=_auth(_PLAYER))
                self.assertEqual(r.status_code, 403, f"{method} {path}: {r.text}")
                self.assertEqual(r.json()["error"]["code"], "forbidden")
            # Launch endpoint too (competition_id in the body).
            r = client.post(
                "/api/v1/instances",
                headers=_auth(_PLAYER),
                json={
                    "competition_id": _CID, "team": "Red",
                    "definition_slug": "sqli", "version_no": 1,
                },
            )
            self.assertEqual(r.status_code, 403, r.text)
            # The instance-by-id routes resolve tenancy from the LOADED row (no
            # {competition_id} in the path): an unauthorized caller must not learn the
            # instance exists, so a denial is a GENERIC 404 (identical to a
            # nonexistent id) -- NOT a 403 that names the resource. No existence leak.
            for method, path in (
                ("get", f"/api/v1/instances/{iid}"),
                ("post", f"/api/v1/instances/{iid}/stop"),
                ("post", f"/api/v1/instances/{iid}/reset"),
                ("post", f"/api/v1/instances/{iid}/delete"),
            ):
                r = getattr(client, method)(path, headers=_auth(_PLAYER))
                self.assertEqual(r.status_code, 404, f"{method} {path}: {r.text}")
                self.assertEqual(r.json()["error"]["code"], "not_found")

    def test_list_pagination_walks_every_instance(self) -> None:
        # FIX 1: with the 500-row cap removed, cursor pagination over a small page
        # size must reach every seeded instance exactly once and only null out
        # next_cursor after the last real row (no premature truncation).
        with _client_and_db() as (client, db):
            _seed_parents(client)
            seeded = {_seed_plain_instance(db) for _ in range(5)}

            collected: list[str] = []
            cursor: str | None = None
            pages = 0
            while True:
                pages += 1
                self.assertLessEqual(pages, 10, "pagination did not terminate")
                params = {"limit": 2}
                if cursor is not None:
                    params["cursor"] = cursor
                r = client.get(
                    "/api/v1/instances", headers=_auth(_ORGANIZER), params=params
                )
                self.assertEqual(r.status_code, 200, r.text)
                body = r.json()
                self.assertLessEqual(len(body["data"]), 2)
                collected.extend(row["instance_id"] for row in body["data"])
                cursor = body["page"]["next_cursor"]
                if cursor is None:
                    break

            # Every seeded id retrieved exactly once; no duplicates, none dropped.
            self.assertEqual(len(collected), len(set(collected)), collected)
            self.assertTrue(seeded <= set(collected), seeded - set(collected))

    def test_launch_resumes_after_no_worker_and_key_not_poisoned(self) -> None:
        # FIX 2 + FIX 3: a launch with NO eligible worker is a 409 (not an opaque
        # 500) and leaves exactly ONE 'requested' row; retrying with the SAME
        # Idempotency-Key after a worker becomes available RESUMES that row to
        # 'queued' (no orphan, no duplicate, key no longer poisoned).
        with _client_and_db() as (client, db):
            _seed_parents(client)
            headers = {**_auth(_ORGANIZER), "Idempotency-Key": "launch-key-abc"}
            payload = {
                "competition_id": _CID, "team": "Red",
                "definition_slug": "sqli", "version_no": 1, "ttl_seconds": 3600,
            }

            first = client.post("/api/v1/instances", headers=headers, json=payload)
            self.assertEqual(first.status_code, 409, first.text)
            self.assertEqual(first.json()["error"]["code"], "conflict")

            # The instance id is derived from the principal-scoped key, so the row
            # persists in 'requested'. Find it and assert exactly one.
            with db.session_scope() as s:
                rows = list(
                    s.execute(sa.text("SELECT id, state FROM instances")).all()
                )
            self.assertEqual(len(rows), 1, rows)
            iid = str(rows[0][0])
            self.assertEqual(rows[0][1], "requested")

            # A worker is enabled; the SAME key resumes placement of the same row.
            _enable_placeable_worker(db)
            second = client.post("/api/v1/instances", headers=headers, json=payload)
            self.assertEqual(second.status_code, 201, second.text)
            body = second.json()
            self.assertEqual(body["instance_id"], iid)
            self.assertEqual(body["state"], "queued")
            self.assertEqual(body["assigned_worker"], "w1")

            # Resumed, not duplicated: still exactly one row, and a launch job was
            # enqueued.
            self.assertEqual(_count_instances(db, iid), 1)
            self.assertEqual(_count_launch_jobs(db), 1)

    def test_launch_requests_instance(self) -> None:
        with _client_and_db() as (client, db):
            _seed_parents(client)
            # A dispatch-eligible worker + platform capacity for the reservation.
            with db.session_scope() as s:
                reg = SqlAlchemyWorkerRegistry(s)
                reg.add(
                    Worker(
                        "w1", "docker-rootless", ("x86_64",),
                        ("launch_instance",), 4, "1",
                    )
                )
                reg.approve("w1")
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).heartbeat("w1", datetime.now(UTC))
            from ctf_generator.domain.scheduling.models import (
                PLATFORM_SCOPE_KEY,
                ResourceQuota,
            )
            from ctf_generator.infrastructure.database.quota_repository import (
                SqlAlchemyQuotaPolicyRepository,
            )
            with db.session_scope() as s:
                SqlAlchemyQuotaPolicyRepository(s).upsert_limit(
                    ResourceQuota("platform", PLATFORM_SCOPE_KEY, "active_instances", 100)
                )
            r = client.post(
                "/api/v1/instances",
                headers=_auth(_ORGANIZER),
                json={
                    "competition_id": _CID, "team": "Red",
                    "definition_slug": "sqli", "version_no": 1,
                    "ttl_seconds": 3600,
                },
            )
            self.assertEqual(r.status_code, 201, r.text)
            body = r.json()
            self.assertEqual(body["state"], "queued")
            self.assertEqual(body["assigned_worker"], "w1")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
