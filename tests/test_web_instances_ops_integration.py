"""PostgreSQL integration tests for the M11c organizer INSTANCE ops views.

List + detail render the public operational facts ONLY -- a planted instance
credential (``secret_ref``), runtime-resource handle (``external_ref``), internal
endpoint token, and ``instance_seed`` must NEVER appear on any page. A lifecycle
action (stop) drives desired state (DB-verified) + 303. Authz mirrors the JSON API
sibling: an organizer of A cannot view/operate an instance of competition B
(existence-hiding 404, DB-verified no change); a contestant lacking instance:read
is denied; a POST without the session-bound CSRF token is 403 and nothing changes.
SKIPS cleanly without the extras / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_instances_ops_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from datetime import timedelta

try:
    import sqlalchemy as sa
    import web_support as ws

    from ctf_generator.application.catalog import TeamService
    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.identity.models import Team
    from ctf_generator.domain.instances.models import (
        Instance,
        InstanceCredential,
        InstanceEndpoint,
        RuntimeResource,
    )
    from ctf_generator.infrastructure.database.instance_repository import (
        SqlAlchemyInstanceRepository,
    )
    from ctf_generator.infrastructure.database.worker_repository import (
        SqlAlchemyWorkerRegistry,
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

# Planted secrets that MUST NOT leak into any page.
_CRED_SECRET = "vault://instance-cred-SECRET-TOKEN-zzz"  # noqa: S105
_RESOURCE_HANDLE = "container-runtime-SECRET-HANDLE-yyy"  # noqa: S105
_INTERNAL_TOKEN = "INTERNAL-ADMIN-SECRET-TOKEN-xxx"  # noqa: S105
_INSTANCE_SEED = "SEED-should-not-leak-123"  # noqa: S105
_PUBLIC_URL = "https://ctf.example.com/c/public-abc"

_SECRETS = (_CRED_SECRET, _RESOURCE_HANDLE, _INTERNAL_TOKEN, _INSTANCE_SEED)


def _seed_instance(
    db,
    competition_id: str,
    *,
    with_secrets: bool = False,
    state: str = "active",
    desired_state: str = "active",
) -> str:
    iid = str(uuid.uuid4())
    # The instance repo resolves ``team_name`` + the ``(slug, version_no)`` pair to
    # surrogates, so the team + a published challenge version must exist first.
    TeamService(db).create(Team(competition_id=competition_id, name="Red"))
    with db.session_scope() as s:
        exists = s.execute(
            sa.text(
                "SELECT 1 FROM challenge_versions v "
                "JOIN challenge_definitions d ON d.id = v.definition_id "
                "WHERE d.slug = 'sqli' AND v.version_no = 1"
            )
        ).first()
    if exists is None:
        ws.seed_published_version(db, "sqli", "SQLi")
    with db.session_scope() as s:
        reg = SqlAlchemyWorkerRegistry(s)
        reg.add(
            Worker("w1", "docker-rootless", ("x86_64",), ("launch_instance",), 4, "1")
        )
        reg.approve("w1")
        reg.heartbeat("w1", ws.NOW)
    with db.session_scope() as s:
        repo = SqlAlchemyInstanceRepository(s)
        repo.add(
            Instance(
                instance_id=iid,
                competition_id=competition_id,
                team_name="Red",
                definition_slug="sqli",
                version_no=1,
                state=state,
                desired_state=desired_state,
                assigned_worker="w1",
                image_ref="registry.example/sqli@sha256:abc",
                instance_seed=_INSTANCE_SEED,
                expires_at=ws.NOW + timedelta(hours=1),
            ),
            ws.NOW,
        )
        if with_secrets:
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
                    protocol="https",
                    url=f"https://10.0.0.5:9000/?token={_INTERNAL_TOKEN}",
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


def _desired_state(db, iid: str) -> str | None:
    with db.session_scope() as s:
        return s.execute(
            sa.text("SELECT desired_state FROM instances WHERE id = :iid"),
            {"iid": iid},
        ).scalar_one_or_none()


def _generation(db, iid: str) -> int | None:
    with db.session_scope() as s:
        return s.execute(
            sa.text("SELECT generation FROM instances WHERE id = :iid"),
            {"iid": iid},
        ).scalar_one_or_none()


def _csrf(client, path):
    r = client.get(path)
    return r, ws.extract_csrf(r.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class InstanceOpsWebTests(unittest.TestCase):
    def test_list_and_detail_render_without_secrets(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)  # organizer of COMP_A
            iid = _seed_instance(db, ws.COMP_A, with_secrets=True)

            lst = client.get(f"/app/competitions/{ws.COMP_A}/instances")
            self.assertEqual(lst.status_code, 200, lst.text)
            self.assertIn(iid, lst.text)
            self.assertIn("sqli", lst.text)

            detail = client.get(f"/app/instances/{iid}")
            self.assertEqual(detail.status_code, 200, detail.text)
            self.assertIn("active", detail.text)
            self.assertIn(_PUBLIC_URL, detail.text)  # public endpoint shown

            for page in (lst, detail):
                for secret in _SECRETS:
                    self.assertNotIn(secret, page.text, f"secret leaked: {secret!r}")
                self.assertNotIn("style=", page.text)

    def test_stop_drives_desired_state_and_redirects(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            iid = _seed_instance(db, ws.COMP_A)
            _r, token = _csrf(client, f"/app/instances/{iid}")
            resp = client.post(
                f"/app/instances/{iid}/stop",
                data={"csrf_token": token},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 303, resp.text)
            self.assertEqual(_desired_state(db, iid), "stopped")

    def test_reset_bumps_generation_and_redirects(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            iid = _seed_instance(db, ws.COMP_A)
            before = _generation(db, iid)
            _r, token = _csrf(client, f"/app/instances/{iid}")
            resp = client.post(
                f"/app/instances/{iid}/reset",
                data={"csrf_token": token},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 303, resp.text)
            # A reset bumps the fencing generation (stale observations ignored).
            self.assertEqual(_generation(db, iid), before + 1)

    def test_delete_drives_desired_state_and_redirects(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            iid = _seed_instance(db, ws.COMP_A)
            _r, token = _csrf(client, f"/app/instances/{iid}")
            resp = client.post(
                f"/app/instances/{iid}/delete",
                data={"csrf_token": token},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 303, resp.text)
            # delete redirects to the competition instance list, not the detail page.
            self.assertIn(
                f"/app/competitions/{ws.COMP_A}/instances",
                resp.headers["location"],
            )
            self.assertEqual(_desired_state(db, iid), "deleted")

    def test_stop_reset_on_archived_instance_is_no_op_not_500(self) -> None:
        # A terminal (archived) row is frozen by the 0010 transition guard; a
        # naive stop/reset UPDATE would trip it -> ProgrammingError -> 500. Both
        # actions must be a clean no-op redirect (the "never a 500" invariant),
        # leaving the frozen row untouched.
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            iid = _seed_instance(
                db, ws.COMP_A, state="archived", desired_state="deleted"
            )
            before = _generation(db, iid)
            for action in ("stop", "reset"):
                _r, token = _csrf(client, f"/app/instances/{iid}")
                resp = client.post(
                    f"/app/instances/{iid}/{action}",
                    data={"csrf_token": token},
                    follow_redirects=False,
                )
                self.assertEqual(resp.status_code, 303, f"{action}: {resp.text}")
            # Nothing was written to the frozen row.
            self.assertEqual(_desired_state(db, iid), "deleted")
            self.assertEqual(_generation(db, iid), before)

    def test_organizer_cannot_view_or_operate_other_competition_instance_404(
        self,
    ) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)  # organizer of A, NOT B
            iid = _seed_instance(db, ws.COMP_B)  # instance belongs to COMP_B

            # By-id detail resolves the competition from the loaded row -> generic
            # 404 (no cross-tenant existence oracle), identical to a nonexistent id.
            self.assertEqual(client.get(f"/app/instances/{iid}").status_code, 404)
            # The competition-scoped list for B is likewise existence-hiding.
            self.assertEqual(
                client.get(f"/app/competitions/{ws.COMP_B}/instances").status_code,
                404,
            )
            # Operate is denied AND nothing changes.
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}")
            resp = client.post(
                f"/app/instances/{iid}/stop",
                data={"csrf_token": token or ""},
                follow_redirects=False,
            )
            self.assertIn(resp.status_code, (403, 404))
            self.assertEqual(_desired_state(db, iid), "active")  # unchanged

    def test_contestant_is_denied(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.EVE)  # player in COMP_A: no instance:read/operate
            iid = _seed_instance(db, ws.COMP_A)
            self.assertIn(
                client.get(f"/app/competitions/{ws.COMP_A}/instances").status_code,
                (403, 404),
            )
            self.assertIn(client.get(f"/app/instances/{iid}").status_code, (403, 404))

    def test_stop_without_csrf_is_403_and_no_change(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)
            iid = _seed_instance(db, ws.COMP_A)
            resp = client.post(
                f"/app/instances/{iid}/stop", follow_redirects=False
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertEqual(_desired_state(db, iid), "active")  # nothing performed


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
