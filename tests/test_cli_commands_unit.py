"""Host-side unit tests for the ``ctfgen <area> <verb>`` command groups (M13 13b).

No database, no real socket: each command is driven end-to-end through
``platform.main`` over a scripted ``httpx.MockTransport`` that RECORDS the request
it received, so the test asserts the EXACT method + path + body + headers the
command sent and the rendered output. The whole module SKIPS cleanly when httpx
(the ``[cli]`` extra) is absent, like the other CLI unit suites.

    PYTHONPATH=src:tests python -m unittest test_cli_commands_unit
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import httpx

    from ctf_generator.interfaces.cli import commands, entry, platform
    from ctf_generator.interfaces.cli.commands import _common

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_SKIP = unittest.skipIf(_IMPORT_ERROR is not None, f"[cli] extra absent ({_IMPORT_ERROR})")

_TOKEN = "ci-token"  # noqa: S105 - test fixture, not a real secret
_BASE = "http://testserver"


def _resource(schema: str, body: dict) -> dict:
    return {"schema": schema, "schema_version": "1.0", **body}


def _list_env(schema: str, data: list[dict], next_cursor=None) -> dict:
    return {
        "schema": schema,
        "schema_version": "1.0",
        "data": data,
        "page": {"limit": len(data), "next_cursor": next_cursor, "has_more": False},
    }


class _Recorder:
    """A MockTransport handler that records every request and replies with a
    canned response chosen by ``(method, path)``. ``route`` registers a reply and
    the request is captured for later assertions."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self._routes: dict[tuple[str, str], tuple[int, dict | None]] = {}

    def route(self, method: str, path: str, status: int, body: dict | None) -> None:
        self._routes[(method, path)] = (status, body)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = (request.method, request.url.path)
        if key not in self._routes:  # pragma: no cover - a misrouted test request
            raise AssertionError(f"unexpected request: {request.method} {request.url.path}")
        status, body = self._routes[key]
        if body is None:
            return httpx.Response(status)
        return httpx.Response(status, json=body)

    def only(self) -> httpx.Request:
        writes = [r for r in self.requests if r.method != "GET"]
        return writes[0] if writes else self.requests[-1]

    def body_of(self, request: httpx.Request) -> dict:
        return json.loads(request.content)


@_SKIP
class CommandDispatchTests(unittest.TestCase):
    def _run(self, recorder: _Recorder, argv: list[str]) -> tuple[int, str]:
        transport = httpx.MockTransport(recorder)

        def _fake_build(api_url, **kwargs):
            return httpx.Client(transport=transport, base_url=api_url)

        env = {
            "CTFGEN_API_TOKEN": _TOKEN,
            "CTFGEN_API_URL": _BASE,
            "CTFGEN_CONFIG": str(self.config_path),
        }
        out = io.StringIO()
        with mock.patch.object(_common, "build_http_client", _fake_build), \
                mock.patch.dict(os.environ, env), \
                mock.patch("sys.stdout", out):
            code = platform.main(argv)
        return code, out.getvalue()

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.config_path = Path(self._dir.name) / "credentials.json"

    def tearDown(self) -> None:
        self._dir.cleanup()

    # -- competition ---------------------------------------------------------

    def test_competition_create_posts_exact_body(self) -> None:
        rec = _Recorder()
        rec.route(
            "POST", "/api/v1/competitions", 201,
            _resource("ctfgen.competition", {
                "competition_id": "c1", "name": "Winter",
                "start_time": "2026-01-01T00:00:00+00:00",
                "end_time": "2026-01-02T00:00:00+00:00",
                "scoring_start_time": None, "freeze_time": None,
                "default_scoring": None,
            }),
        )
        code, out = self._run(rec, [
            "competition", "create", "c1", "--name", "Winter",
            "--start-time", "2026-01-01T00:00:00+00:00",
            "--end-time", "2026-01-02T00:00:00+00:00",
        ])
        self.assertEqual(code, 0)
        req = rec.only()
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.url.path, "/api/v1/competitions")
        self.assertEqual(rec.body_of(req), {
            "competition_id": "c1", "name": "Winter",
            "start_time": "2026-01-01T00:00:00+00:00",
            "end_time": "2026-01-02T00:00:00+00:00",
        })
        # A write carries an Idempotency-Key and the bearer.
        self.assertTrue(req.headers.get("Idempotency-Key"))
        self.assertEqual(req.headers.get("Authorization"), f"Bearer {_TOKEN}")
        self.assertIn("Winter", out)

    def test_competition_list_renders_table(self) -> None:
        rec = _Recorder()
        rec.route(
            "GET", "/api/v1/competitions", 200,
            _list_env("ctfgen.competition-list", [
                {"competition_id": "c1", "name": "Winter",
                 "start_time": "s", "end_time": "e",
                 "scoring_start_time": None, "freeze_time": None},
            ]),
        )
        code, out = self._run(rec, ["competition", "list"])
        self.assertEqual(code, 0)
        self.assertEqual(rec.requests[0].url.path, "/api/v1/competitions")
        self.assertIn("competition_id", out)
        self.assertIn("c1", out)
        self.assertIn("Winter", out)

    def test_competition_update_reads_etag_then_sends_if_match(self) -> None:
        rec = _Recorder()
        rec.route(
            "GET", "/api/v1/competitions/c1", 200,
            _resource("ctfgen.competition", {"competition_id": "c1", "name": "Old"}),
        )
        rec.route(
            "PATCH", "/api/v1/competitions/c1", 200,
            _resource("ctfgen.competition", {"competition_id": "c1", "name": "New"}),
        )
        # The GET reply must carry an ETag for the command to echo as If-Match.
        real_call = rec.__call__

        def with_etag(request):
            resp = real_call(request)
            if request.method == "GET":
                resp.headers["ETag"] = '"v1"'
            return resp

        transport = httpx.MockTransport(with_etag)

        def _fake_build(api_url, **kwargs):
            return httpx.Client(transport=transport, base_url=api_url)

        env = {"CTFGEN_API_TOKEN": _TOKEN, "CTFGEN_API_URL": _BASE,
               "CTFGEN_CONFIG": str(self.config_path)}
        with mock.patch.object(_common, "build_http_client", _fake_build), \
                mock.patch.dict(os.environ, env), mock.patch("sys.stdout", io.StringIO()):
            code = platform.main(["competition", "update", "c1", "--name", "New"])
        self.assertEqual(code, 0)
        patch = [r for r in rec.requests if r.method == "PATCH"][0]
        self.assertEqual(patch.url.path, "/api/v1/competitions/c1")
        self.assertEqual(patch.headers.get("If-Match"), '"v1"')
        self.assertEqual(rec.body_of(patch), {"name": "New"})

    def test_competition_scoreboard_show(self) -> None:
        rec = _Recorder()
        rec.route(
            "GET", "/api/v1/competitions/c1/scoreboard", 200,
            _list_env("ctfgen.scoreboard", [
                {"rank": 1, "team_id": "Red", "score": 500,
                 "solve_count": 1, "last_solve_at": "t"},
            ]),
        )
        code, out = self._run(rec, ["competition", "scoreboard", "c1"])
        self.assertEqual(code, 0)
        self.assertEqual(rec.requests[0].url.path, "/api/v1/competitions/c1/scoreboard")
        self.assertIn("Red", out)
        self.assertIn("rank", out)

    # -- publication ---------------------------------------------------------

    def test_publication_attach_posts_to_competition(self) -> None:
        rec = _Recorder()
        rec.route(
            "POST", "/api/v1/competitions/c1/publications", 201,
            _resource("ctfgen.publication", {
                "competition_id": "c1", "definition_slug": "d1", "version_no": 1,
                "initial_value": 500, "minimum_value": 100, "decay_function": "static",
                "decay": 0, "first_blood_enabled": True,
                "first_blood_bonus_points": 0, "first_blood_bonus_percent": 0.0,
            }),
        )
        code, out = self._run(rec, [
            "publication", "attach", "--competition-id", "c1",
            "--definition-slug", "d1", "--version-no", "1",
        ])
        self.assertEqual(code, 0)
        req = rec.only()
        self.assertEqual(req.url.path, "/api/v1/competitions/c1/publications")
        self.assertEqual(rec.body_of(req), {"definition_slug": "d1", "version_no": 1})
        self.assertTrue(req.headers.get("Idempotency-Key"))
        self.assertIn("d1", out)

    def test_publication_detach_uses_http_delete(self) -> None:
        # The ONLY HTTP DELETE verb in the CLI: DELETE /competitions/{id}/
        # publications/{slug}/{version_no}. Pin the method AND the path ordering
        # (slug before version_no) against a POST/reversed-path regression.
        rec = _Recorder()
        rec.route("DELETE", "/api/v1/competitions/c1/publications/d1/1", 204, None)
        code, _ = self._run(rec, [
            "publication", "detach", "--competition-id", "c1",
            "--definition-slug", "d1", "--version-no", "1",
        ])
        self.assertEqual(code, 0)
        req = rec.requests[-1]
        self.assertEqual(req.method, "DELETE")
        self.assertEqual(req.url.path, "/api/v1/competitions/c1/publications/d1/1")

    # -- submission ----------------------------------------------------------

    def test_submission_submit_sends_key_and_body_shape(self) -> None:
        rec = _Recorder()
        rec.route(
            "POST", "/api/v1/competitions/c1/submissions", 201,
            _resource("ctfgen.submission", {
                "submission_id": "s1", "competition_id": "c1", "team": "Red",
                "definition_slug": "d1", "version_no": 1, "submitted_at": "t",
                "correct": True, "first_solve": True, "replay": False, "solve": None,
            }),
        )
        code, out = self._run(rec, [
            "submission", "submit", "--competition-id", "c1", "--team", "Red",
            "--definition-slug", "d1", "--version-no", "1", "--answer", "flag{x}",
            "--idempotency-key", "pinned-123",
        ])
        self.assertEqual(code, 0)
        req = rec.only()
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.url.path, "/api/v1/competitions/c1/submissions")
        self.assertEqual(req.headers.get("Idempotency-Key"), "pinned-123")
        self.assertEqual(rec.body_of(req), {
            "team": "Red", "definition_slug": "d1", "version_no": 1, "answer": "flag{x}",
        })
        self.assertIn("s1", out)

    def test_submission_submit_requires_answer(self) -> None:
        rec = _Recorder()
        # No route needed: it must fail BEFORE any HTTP call.
        code, _ = self._run(rec, [
            "submission", "submit", "--competition-id", "c1", "--team", "Red",
            "--definition-slug", "d1", "--version-no", "1",
        ])
        self.assertEqual(code, 1)
        self.assertEqual(rec.requests, [])

    # -- instance (secret redaction) ----------------------------------------

    def test_instance_list_never_renders_secret_columns(self) -> None:
        rec = _Recorder()
        # The canned payload deliberately CARRIES secret-ish keys; the table must
        # render only the public whitelist and never leak these values.
        rec.route(
            "GET", "/api/v1/instances", 200,
            _list_env("ctfgen.instance-list", [{
                "instance_id": "i1", "competition_id": "c1", "team": "Red",
                "definition_slug": "d1", "version_no": 1, "state": "running",
                "desired_state": "running", "assigned_worker": "w1",
                "expires_at": "t", "generation": 3,
                "instance_seed": "SEED-SECRET-XYZ",
                "secret_ref": "vault://SECRET-REF-XYZ",
                "external_ref": "docker://EXTERNAL-REF-XYZ",
            }]),
        )
        code, out = self._run(rec, ["instance", "list"])
        self.assertEqual(code, 0)
        self.assertEqual(rec.requests[0].url.path, "/api/v1/instances")
        self.assertIn("i1", out)
        self.assertIn("running", out)
        for secret in ("SEED-SECRET-XYZ", "SECRET-REF-XYZ", "EXTERNAL-REF-XYZ",
                       "instance_seed", "secret_ref", "external_ref"):
            self.assertNotIn(secret, out, f"secret {secret!r} leaked into output")

    def test_instance_request_posts_launch_body(self) -> None:
        # The most complex write body in the slice (InstanceLaunchRequest). Pin
        # POST /instances + the exact key NAMES against a drift (e.g. arch vs
        # architecture, capabilities vs required_capabilities, dropping worker_units).
        rec = _Recorder()
        rec.route(
            "POST", "/api/v1/instances", 201,
            _resource("ctfgen.instance", {"instance_id": "i9", "state": "requested"}),
        )
        code, _ = self._run(rec, [
            "instance", "request", "--competition-id", "c1", "--team", "Red",
            "--definition-slug", "d1", "--version-no", "1",
            "--worker-units", "2", "--capability", "gpu",
        ])
        self.assertEqual(code, 0)
        req = rec.only()
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.url.path, "/api/v1/instances")
        self.assertTrue(req.headers.get("Idempotency-Key"))
        body = rec.body_of(req)
        # Exact key names the InstanceLaunchRequest schema accepts.
        self.assertEqual(body["competition_id"], "c1")
        self.assertEqual(body["team"], "Red")
        self.assertEqual(body["definition_slug"], "d1")
        self.assertEqual(body["version_no"], 1)
        self.assertEqual(body["worker_units"], 2)
        self.assertEqual(body["required_capabilities"], ["gpu"])

    def test_instance_delete_uses_post_not_http_delete(self) -> None:
        rec = _Recorder()
        rec.route(
            "POST", "/api/v1/instances/i1/delete", 200,
            _resource("ctfgen.instance", {"instance_id": "i1", "state": "deleting"}),
        )
        code, _ = self._run(rec, ["instance", "delete", "i1"])
        self.assertEqual(code, 0)
        req = rec.only()
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.url.path, "/api/v1/instances/i1/delete")
        self.assertTrue(req.headers.get("Idempotency-Key"))

    # -- job -----------------------------------------------------------------

    def test_job_list_hits_dead_letter(self) -> None:
        rec = _Recorder()
        rec.route(
            "GET", "/api/v1/jobs/dead-letter", 200,
            _list_env("ctfgen.job-list", [{
                "job_id": "j1", "job_type": "build", "status": "dead_letter",
                "attempt_count": 3, "max_attempts": 3, "available_at": "t",
                "error_class": "TimeoutError",
            }]),
        )
        code, out = self._run(rec, ["job", "list"])
        self.assertEqual(code, 0)
        self.assertEqual(rec.requests[0].url.path, "/api/v1/jobs/dead-letter")
        self.assertIn("j1", out)
        self.assertIn("dead_letter", out)

    # -- build ---------------------------------------------------------------

    def test_build_trigger_posts_version(self) -> None:
        rec = _Recorder()
        rec.route(
            "POST", "/api/v1/challenge-definitions/d1/builds", 202,
            _resource("ctfgen.job", {"job_id": "j2", "status": "queued"}),
        )
        code, _ = self._run(rec, ["build", "trigger", "--slug", "d1", "--version-no", "2"])
        self.assertEqual(code, 0)
        req = rec.only()
        self.assertEqual(req.url.path, "/api/v1/challenge-definitions/d1/builds")
        self.assertEqual(rec.body_of(req), {"version_no": 2})
        self.assertTrue(req.headers.get("Idempotency-Key"))

    # -- system --------------------------------------------------------------

    def test_system_health_is_unauthenticated(self) -> None:
        rec = _Recorder()
        rec.route(
            "GET", "/api/v1/system/health", 200,
            _resource("ctfgen.system-health", {"status": "ok"}),
        )
        code, out = self._run(rec, ["system", "health"])
        self.assertEqual(code, 0)
        req = rec.requests[0]
        self.assertEqual(req.url.path, "/api/v1/system/health")
        self.assertIsNone(req.headers.get("Authorization"))
        self.assertIn("ok", out)


@_SKIP
class AreaRegistrationTests(unittest.TestCase):
    def test_platform_areas_in_sync_with_entry(self) -> None:
        # The two dispatch sets MUST agree (entry declares literals without
        # importing platform, so drift is only caught here).
        self.assertEqual(platform.PLATFORM_AREAS, entry._PLATFORM_AREAS)

    def test_every_area_registered_and_routes_through_dispatcher(self) -> None:
        parser = platform.build_parser()
        # Each area name resolves to a subparser with at least one verb.
        area_action = next(
            a for a in parser._actions if getattr(a, "dest", None) == "area"
        )
        registered = set(area_action.choices)
        self.assertIn("auth", registered)
        self.assertTrue(commands.AREA_NAMES <= registered)

        # entry.main routes every area's first token to platform.main.
        for area in sorted(commands.AREA_NAMES | {"auth"}):
            with mock.patch(
                "ctf_generator.interfaces.cli.platform.main", return_value=0
            ) as pmain:
                code = entry.main([area, "list"])
            self.assertEqual(code, 0)
            pmain.assert_called_once_with([area, "list"])

    def test_no_area_shadows_a_legacy_command(self) -> None:
        # Regression: an area name must NEVER collide with a legacy generator
        # command (e.g. the legacy ``scoreboard``), or entry would shadow it.
        from ctf_generator.cli import build_parser as legacy_build_parser

        legacy = legacy_build_parser()
        legacy_cmd = next(
            a for a in legacy._actions if getattr(a, "dest", None) == "command"
        )
        legacy_names = set(legacy_cmd.choices)
        self.assertEqual(entry._PLATFORM_AREAS & legacy_names, set())


if __name__ == "__main__":
    unittest.main()
