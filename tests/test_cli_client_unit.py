"""Host-side unit tests for the platform CLI (M13 slice 13a).

No database, no real socket: the :class:`ApiClient` is driven over a scripted
``httpx.MockTransport`` and the ``TokenStore`` / ``output`` helpers are pure. The
whole module SKIPS cleanly when httpx (the ``[cli]`` extra) is absent, so the
stdlib-only unit gate stays green -- exactly like the [api]/[db] suites.

    PYTHONPATH=src:tests python -m unittest test_cli_client_unit
"""

from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import httpx

    from ctf_generator.interfaces.cli import entry, output, platform
    from ctf_generator.interfaces.cli.client import ApiClient
    from ctf_generator.interfaces.cli.config import Session, TokenStore
    from ctf_generator.interfaces.cli.errors import (
        ApiError,
        ApiUnreachable,
        AuthRequired,
        CliError,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_SKIP = unittest.skipIf(_IMPORT_ERROR is not None, f"[cli] extra absent ({_IMPORT_ERROR})")

_FAKE_TOKEN = "tok-old"  # noqa: S105 - test fixture, not a real secret


def _client(handler, store: TokenStore, *, token_override=None) -> ApiClient:
    transport = httpx.MockTransport(handler)
    http = httpx.Client(transport=transport, base_url="http://testserver")
    return ApiClient(http, store, "http://testserver", token_override=token_override)


def _error_body(code: str, message: str, request_id: str) -> dict:
    return {
        "schema": "ctfgen.error",
        "schema_version": "1.0",
        "error": {"code": code, "message": message, "request_id": request_id},
    }


@_SKIP
class TokenStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.path = Path(self._dir.name) / "sub" / "credentials.json"
        self.store = TokenStore(self.path)

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_missing_file_loads_none(self) -> None:
        self.assertIsNone(self.store.load())

    def test_save_then_load_round_trips(self) -> None:
        self.store.save(
            Session(api_url="http://h", token="secret", expires_at="2030", subject="a")
        )
        loaded = self.store.load()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.token, "secret")
        self.assertEqual(loaded.api_url, "http://h")
        self.assertEqual(loaded.subject, "a")

    def test_save_enforces_0600_and_0700_dir(self) -> None:
        self.store.save(Session(api_url="http://h", token="secret"))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)

    def test_save_tightens_preexisting_loose_file(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text("{}", encoding="utf-8")
        os.chmod(self.path, 0o644)
        self.store.save(Session(api_url="http://h", token="secret"))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_load_refuses_group_world_readable_file(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text(
            json.dumps({"api_url": "http://h", "token": "secret"}), encoding="utf-8"
        )
        os.chmod(self.path, 0o644)
        stderr = io.StringIO()
        with mock.patch("sys.stderr", stderr):
            self.assertIsNone(self.store.load())
        self.assertIn("too permissive", stderr.getvalue())

    def test_clear_is_idempotent(self) -> None:
        self.store.clear()  # no file yet -> no error
        self.store.save(Session(api_url="http://h", token="secret"))
        self.store.clear()
        self.assertFalse(self.path.exists())
        self.store.clear()  # already gone -> no error


@_SKIP
class OutputTests(unittest.TestCase):
    def test_table_aligns_columns(self) -> None:
        rows = [{"id": "a", "role": "admin"}, {"id": "bb", "role": "player"}]
        rendered = output.render_table(rows, ["id", "role"])
        lines = rendered.splitlines()
        self.assertEqual(lines[0].split(), ["id", "role"])
        self.assertIn("admin", rendered)
        self.assertIn("player", rendered)

    def test_print_resource_json_mode(self) -> None:
        buf = io.StringIO()
        output.print_resource({"subject": "alice", "roles": ["admin"]}, as_json=True, stream=buf)
        self.assertEqual(json.loads(buf.getvalue()), {"subject": "alice", "roles": ["admin"]})

    def test_print_resource_text_mode(self) -> None:
        buf = io.StringIO()
        output.print_resource({"subject": "alice"}, as_json=False, stream=buf)
        self.assertIn("subject", buf.getvalue())
        self.assertIn("alice", buf.getvalue())


@_SKIP
class ApiClientErrorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.store = TokenStore(Path(self._dir.name) / "cred.json")

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_error_envelope_parsed_into_apierror(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json=_error_body("not_found", "no such thing", "req-9"))

        client = _client(handler, self.store)
        with self.assertRaises(ApiError) as cm:
            client.request("GET", "/competitions/x", authed=False)
        self.assertEqual(cm.exception.code, "not_found")
        self.assertEqual(cm.exception.status_code, 404)
        self.assertEqual(cm.exception.request_id, "req-9")
        # The rendered message surfaces code + request_id for support.
        self.assertIn("not_found", str(cm.exception))
        self.assertIn("req-9", str(cm.exception))

    def test_non_envelope_error_falls_back(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(502, text="bad gateway")

        client = _client(handler, self.store)
        with self.assertRaises(ApiError) as cm:
            client.request("GET", "/x", authed=False)
        self.assertEqual(cm.exception.status_code, 502)
        self.assertEqual(cm.exception.code, "http_502")

    def test_resource_envelope_unwrapped(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "schema": "ctfgen.competition",
                    "schema_version": "1.0",
                    "id": "c1",
                    "name": "Winter",
                },
            )

        body = _client(handler, self.store).request("GET", "/competitions/c1", authed=False)
        self.assertEqual(body, {"id": "c1", "name": "Winter"})

    def test_list_follows_cursor(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            cursor = request.url.params.get("cursor")
            if cursor is None:
                return httpx.Response(
                    200,
                    json={
                        "schema": "ctfgen.competition-list",
                        "schema_version": "1.0",
                        "data": [{"id": "1"}],
                        "page": {"limit": 1, "next_cursor": "c2", "has_more": True},
                    },
                )
            return httpx.Response(
                200,
                json={
                    "schema": "ctfgen.competition-list",
                    "schema_version": "1.0",
                    "data": [{"id": "2"}],
                    "page": {"limit": 1, "next_cursor": None, "has_more": False},
                },
            )

        items = _client(handler, self.store).list("/competitions")
        self.assertEqual(items, [{"id": "1"}, {"id": "2"}])

    def test_list_terminates_on_repeating_cursor(self) -> None:
        # A hostile/buggy server that keeps returning the SAME non-null cursor
        # (here with empty pages) must NOT spin the CLI forever. The seen-cursor
        # guard stops after re-seeing "loop".
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            self.assertLess(calls["n"], 10, "list() looped without terminating")
            return httpx.Response(
                200,
                json={
                    "schema": "ctfgen.competition-list",
                    "schema_version": "1.0",
                    "data": [],
                    "page": {"next_cursor": "loop", "has_more": True},
                },
            )

        items = _client(handler, self.store).list("/competitions")
        self.assertEqual(items, [])
        # First page (no cursor) + one follow of "loop", then "loop" is seen again.
        self.assertLessEqual(calls["n"], 2)

    def test_transport_error_raises_api_unreachable(self) -> None:
        # A read/pool timeout or a mid-response drop (NOT a ConnectError) must
        # still map to a friendly ApiUnreachable, never a raw traceback.
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("stalled", request=request)

        client = _client(handler, self.store)
        with self.assertRaises(ApiUnreachable):
            client.request("GET", "/x", authed=False)


@_SKIP
class ApiClientRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.store = TokenStore(Path(self._dir.name) / "cred.json")
        self.store.save(Session(api_url="http://testserver", token=_FAKE_TOKEN))

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_401_triggers_single_refresh_then_retry(self) -> None:
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            auth = request.headers.get("authorization", "")
            calls.append(f"{request.method} {path} auth={auth}")
            if path == "/api/v1/auth/me":
                if auth == "Bearer tok-new":
                    return httpx.Response(200, json={"subject": "alice", "system_roles": ["admin"]})
                return httpx.Response(401, json=_error_body("unauthorized", "expired", "r1"))
            if path == "/api/v1/auth/refresh":
                return httpx.Response(200, json={"token": "tok-new", "expires_at": "2031"})
            raise AssertionError(f"unexpected {path}")

        client = _client(handler, self.store)
        me = client.request("GET", "/auth/me")
        self.assertEqual(me["subject"], "alice")
        # The rotated token was persisted.
        self.assertEqual(self.store.load().token, "tok-new")
        # Exactly one refresh happened (me -> refresh -> me), no loop.
        self.assertEqual(sum(1 for c in calls if "auth/refresh" in c), 1)
        self.assertEqual(sum(1 for c in calls if "auth/me" in c), 2)

    def test_refresh_failure_raises_auth_required(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/v1/auth/refresh":
                return httpx.Response(401, json=_error_body("unauthorized", "gone", "r2"))
            return httpx.Response(401, json=_error_body("unauthorized", "expired", "r1"))

        client = _client(handler, self.store)
        with self.assertRaises(AuthRequired):
            client.request("GET", "/auth/me")

    def test_no_stored_token_authed_401_raises_auth_required(self) -> None:
        self.store.clear()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json=_error_body("unauthorized", "no token", "r3"))

        client = _client(handler, self.store)
        with self.assertRaises(AuthRequired):
            client.request("GET", "/auth/me")

    def test_refresh_succeeds_but_retry_still_401_raises_auth_required(self) -> None:
        # Refresh rotates the token (200), but the resource STILL 401s for the
        # rotated token -> a genuine authorization failure -> AuthRequired, and
        # NOT a second refresh (no loop).
        refreshes = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/v1/auth/refresh":
                refreshes["n"] += 1
                return httpx.Response(200, json={"token": "tok-new", "expires_at": "2031"})
            # /auth/me: 401 for both the old AND the rotated token.
            return httpx.Response(401, json=_error_body("unauthorized", "denied", "r4"))

        client = _client(handler, self.store)
        with self.assertRaises(AuthRequired):
            client.request("GET", "/auth/me")
        self.assertEqual(refreshes["n"], 1)  # exactly one refresh, no loop
        self.assertEqual(self.store.load().token, "tok-new")  # rotation persisted


@_SKIP
class EntryDispatchTests(unittest.TestCase):
    def test_auth_routes_to_platform(self) -> None:
        with mock.patch(
            "ctf_generator.interfaces.cli.platform.main", return_value=0
        ) as platform_main:
            code = entry.main(["auth", "whoami"])
        self.assertEqual(code, 0)
        platform_main.assert_called_once_with(["auth", "whoami"])

    def test_legacy_command_delegates_to_cli_main(self) -> None:
        with mock.patch("ctf_generator.cli.main", return_value=0) as legacy_main:
            code = entry.main(["list-families"])
        self.assertEqual(code, 0)
        legacy_main.assert_called_once_with(["list-families"])

    def test_create_delegates_to_cli_main(self) -> None:
        with mock.patch("ctf_generator.cli.main", return_value=7) as legacy_main:
            code = entry.main(["create", "-o", "out/x"])
        self.assertEqual(code, 7)
        legacy_main.assert_called_once_with(["create", "-o", "out/x"])

    def test_bare_invocation_delegates_to_legacy(self) -> None:
        with mock.patch("ctf_generator.cli.main", return_value=2) as legacy_main:
            code = entry.main([])
        self.assertEqual(code, 2)
        legacy_main.assert_called_once_with([])

    def test_cli_extra_absent_prints_install_hint(self) -> None:
        # Simulate httpx / the [cli] extra being absent: importing the platform
        # module raises ImportError -> a clean install hint + rc 1, no traceback.
        stderr = io.StringIO()
        with mock.patch.dict(
            "sys.modules", {"ctf_generator.interfaces.cli.platform": None}
        ), mock.patch("sys.stderr", stderr):
            code = entry.main(["auth", "whoami"])
        self.assertEqual(code, 1)
        self.assertIn("ctf-generator[cli]", stderr.getvalue())


@_SKIP
class LegacyIsolationTests(unittest.TestCase):
    def test_legacy_path_imports_no_httpx_or_platform(self) -> None:
        # The slice's core guarantee: a legacy generator command through the
        # ctfgen dispatcher must NOT import httpx or the platform module, so a
        # no-[cli] install still runs every generator command. Verified in a
        # FRESH interpreter (this test module already imported httpx itself).
        import subprocess
        import sys

        src = str(Path(__file__).resolve().parent.parent / "src")
        code = (
            "import sys\n"
            "from ctf_generator.interfaces.cli import entry\n"
            "rc = entry.main(['list-families'])\n"
            "leaked = [m for m in ('httpx', 'ctf_generator.interfaces.cli.platform')"
            " if m in sys.modules]\n"
            "sys.stderr.write('LEAKED=' + ','.join(leaked) + '\\n')\n"
            "sys.exit(rc)\n"
        )
        proc = subprocess.run(  # noqa: S603 - fixed snippet via sys.executable
            [sys.executable, "-c", code],
            env={**os.environ, "PYTHONPATH": src},
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("LEAKED=\n", proc.stderr, f"legacy path leaked imports: {proc.stderr}")


@_SKIP
class PlatformOriginGuardTests(unittest.TestCase):
    """The stored session bearer must never be sent to a --api-url other than the
    origin it was issued for (a credential-exfiltration guard)."""

    def _args(self, api_url):
        ns = mock.Mock()
        ns.api_url = api_url
        return ns

    def test_refuses_mismatched_api_url_for_stored_session(self) -> None:
        stored = Session(api_url="https://ctf.example", token="live")
        with self.assertRaises(CliError) as cm:
            platform._guard_stored_origin(
                self._args("https://attacker.example"),
                stored,
                None,  # no env override -> the stored token would be sent
                "https://attacker.example",
            )
        self.assertIn("refusing to send", str(cm.exception))

    def test_allows_matching_api_url(self) -> None:
        stored = Session(api_url="https://ctf.example", token="live")
        # Same origin -> no error.
        platform._guard_stored_origin(
            self._args("https://ctf.example"), stored, None, "https://ctf.example"
        )

    def test_env_override_bypasses_guard(self) -> None:
        stored = Session(api_url="https://ctf.example", token="live")
        # An explicit env token targets a host of the operator's choosing; the
        # stored token is not the one being sent, so no guard applies.
        platform._guard_stored_origin(
            self._args("https://other.example"),
            stored,
            "env-token",
            "https://other.example",
        )


if __name__ == "__main__":
    unittest.main()
