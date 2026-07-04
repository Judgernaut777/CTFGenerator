from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import ctf_generator.dashboard_server as ds

from ctf_generator.competition_service import ChallengeCatalog, ChallengeMeta, CompetitionService
from ctf_generator.dashboard_server import (
    CSRF_HEADER,
    PUBLIC_TOKEN_HEADER,
    SESSION_COOKIE,
    AuthConfig,
    DashboardRequest,
    InMemorySessionStore,
    dispatch,
)
from ctf_generator.events import InMemoryEventStore
from ctf_generator.models import ChallengeScoringConfig, CompetitionConfig
from ctf_generator.scoring_engine import StaticPointsEngine

START = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)


class ScriptedClock:
    """Fake ``dashboard_server.Clock``: returns scripted datetimes in
    sequence, repeating the final value once exhausted so callers that read
    "now" more times than scripted don't explode."""

    def __init__(self, moments: list[datetime]) -> None:
        self._moments = list(moments)
        self._index = 0

    def __call__(self) -> datetime:
        if self._index < len(self._moments):
            value = self._moments[self._index]
            self._index += 1
            return value
        return self._moments[-1]


class SequentialTokens:
    """Deterministic token factory: 'tok-1', 'tok-2', ... in call order."""

    def __init__(self, prefix: str = "tok") -> None:
        self._prefix = prefix
        self._n = 0

    def __call__(self) -> str:
        self._n += 1
        return f"{self._prefix}-{self._n}"


def make_config(**overrides) -> CompetitionConfig:
    kwargs = dict(competition_id="comp-1", name="Test Comp", start_time=START, end_time=END)
    kwargs.update(overrides)
    return CompetitionConfig(**kwargs)


def make_catalog() -> ChallengeCatalog:
    return ChallengeCatalog.from_entries(
        {
            "web-1": ChallengeMeta(
                scoring=ChallengeScoringConfig(challenge_id="web-1", initial_value=500, minimum_value=100),
                title="Web One",
                category="web",
            ),
        }
    )


def make_service() -> CompetitionService:
    store = InMemoryEventStore(clock=lambda: 1700000000.0)
    return CompetitionService(
        store=store,
        catalog=make_catalog(),
        config=make_config(),
        scoring_engine=StaticPointsEngine(),
        teams={"alpha": "Team Alpha"},
    )


def make_auth(**overrides) -> AuthConfig:
    kwargs = dict(
        admin_username="admin",
        password="hunter2",
        public_token="pub-token-fixed",
        session_ttl_seconds=300,
        pbkdf2_iterations=1000,  # keep tests fast; production default is higher
        salt=b"fixed-salt-16bb",
    )
    kwargs.update(overrides)
    return AuthConfig.create(**kwargs)


def login_request(username: str = "admin", password: str = "hunter2") -> DashboardRequest:
    return DashboardRequest(method="POST", path="/login", body=json.dumps({"username": username, "password": password}))


class Harness:
    """Bundles a service/sessions/auth/clock/token-factory quad and a
    convenience ``call`` that runs ``dispatch`` with them."""

    def __init__(self, ttl_seconds: int = 300, moments: list[datetime] | None = None) -> None:
        self.service = make_service()
        self.tokens = SequentialTokens()
        self.sessions = InMemorySessionStore(token_factory=self.tokens)
        self.auth = make_auth(session_ttl_seconds=ttl_seconds)
        self.clock = ScriptedClock(moments or [START + timedelta(seconds=i) for i in range(50)])

    def call(self, request: DashboardRequest):
        return dispatch(request, service=self.service, sessions=self.sessions, auth=self.auth, clock=self.clock)

    def login(self) -> tuple[str, str]:
        response = self.call(login_request())
        assert response.status == 200, response.body
        token = response.cookies[SESSION_COOKIE]
        csrf = json.loads(response.body)["csrf_token"]
        return token, csrf


class LoginTests(unittest.TestCase):
    def test_login_sets_session_cookie_and_csrf(self) -> None:
        h = Harness()
        response = h.call(login_request())

        self.assertEqual(response.status, 200)
        self.assertIn(SESSION_COOKIE, response.cookies)
        self.assertEqual(response.cookies[SESSION_COOKIE], "tok-1")
        payload = json.loads(response.body)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["csrf_token"], "tok-2")

    def test_login_rejects_bad_password(self) -> None:
        h = Harness()
        response = h.call(login_request(password="wrong"))

        self.assertEqual(response.status, 401)
        self.assertEqual(h.sessions.get("tok-1"), None)

    def test_login_rejects_bad_username(self) -> None:
        h = Harness()
        response = h.call(login_request(username="not-admin"))

        self.assertEqual(response.status, 401)

    def test_login_rejects_malformed_body(self) -> None:
        h = Harness()
        response = h.call(DashboardRequest(method="POST", path="/login", body="not json"))

        self.assertEqual(response.status, 400)

    def test_logout_deletes_session(self) -> None:
        h = Harness()
        token, _ = h.login()

        response = h.call(DashboardRequest(method="POST", path="/logout", cookies={SESSION_COOKIE: token}))

        self.assertEqual(response.status, 200)
        self.assertIsNone(h.sessions.get(token))


class AdminAuthTests(unittest.TestCase):
    def test_missing_session_rejected(self) -> None:
        h = Harness()
        response = h.call(DashboardRequest(method="GET", path="/api/progress"))

        self.assertEqual(response.status, 401)

    def test_unknown_session_token_rejected(self) -> None:
        h = Harness()
        response = h.call(
            DashboardRequest(method="GET", path="/api/progress", cookies={SESSION_COOKIE: "bogus-token"})
        )

        self.assertEqual(response.status, 401)

    def test_valid_session_grants_access(self) -> None:
        h = Harness()
        token, _ = h.login()

        response = h.call(DashboardRequest(method="GET", path="/api/progress", cookies={SESSION_COOKIE: token}))

        self.assertEqual(response.status, 200)
        payload = json.loads(response.body)
        self.assertIn("progress", payload)

    def test_token_rotates_on_each_authenticated_request(self) -> None:
        h = Harness()
        token, _ = h.login()

        first = h.call(DashboardRequest(method="GET", path="/api/progress", cookies={SESSION_COOKIE: token}))
        new_token = first.cookies[SESSION_COOKIE]

        self.assertNotEqual(new_token, token)
        # Old token is now dead.
        replay = h.call(DashboardRequest(method="GET", path="/api/progress", cookies={SESSION_COOKIE: token}))
        self.assertEqual(replay.status, 401)

        # New token works, and rotates again.
        second = h.call(DashboardRequest(method="GET", path="/api/progress", cookies={SESSION_COOKIE: new_token}))
        self.assertEqual(second.status, 200)
        self.assertNotEqual(second.cookies[SESSION_COOKIE], new_token)

    def test_rotated_away_token_rejected(self) -> None:
        h = Harness()
        token, _ = h.login()
        h.call(DashboardRequest(method="GET", path="/api/leaderboard", cookies={SESSION_COOKIE: token}))

        stale = h.call(DashboardRequest(method="GET", path="/api/leaderboard", cookies={SESSION_COOKIE: token}))

        self.assertEqual(stale.status, 401)

    def test_expired_session_rejected(self) -> None:
        # ttl=1s; clock jumps 10s between login and the next call.
        h = Harness(ttl_seconds=1, moments=[START, START + timedelta(seconds=10)])
        token, _ = h.login()

        response = h.call(DashboardRequest(method="GET", path="/api/progress", cookies={SESSION_COOKIE: token}))

        self.assertEqual(response.status, 401)

    def test_root_dashboard_route_returns_progress_and_leaderboard(self) -> None:
        h = Harness()
        h.service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})
        token, _ = h.login()

        response = h.call(DashboardRequest(method="GET", path="/", cookies={SESSION_COOKIE: token}))

        payload = json.loads(response.body)
        self.assertIn("progress", payload)
        self.assertIn("leaderboard", payload)
        self.assertEqual(payload["progress"]["alpha"]["solved"], ["web-1"])

    def test_leaderboard_route(self) -> None:
        h = Harness()
        h.service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})
        token, _ = h.login()

        response = h.call(DashboardRequest(method="GET", path="/api/leaderboard", cookies={SESSION_COOKIE: token}))

        payload = json.loads(response.body)
        self.assertEqual(payload["leaderboard"]["entries"][0]["team_id"], "alpha")

    def test_feed_route_since(self) -> None:
        h = Harness()
        h.service.record_event("attempt", "alpha", "web-1")
        h.service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})
        token, _ = h.login()

        response = h.call(
            DashboardRequest(method="GET", path="/api/feed", query={"since": "1"}, cookies={SESSION_COOKIE: token})
        )

        payload = json.loads(response.body)
        self.assertEqual([e["seq"] for e in payload["feed"]], [2])


class CsrfTests(unittest.TestCase):
    def test_post_without_csrf_header_rejected(self) -> None:
        h = Harness()
        token, _ = h.login()

        response = h.call(
            DashboardRequest(
                method="POST",
                path="/api/event",
                cookies={SESSION_COOKIE: token},
                body=json.dumps({"type": "solve", "team_id": "alpha", "challenge_id": "web-1"}),
            )
        )

        self.assertEqual(response.status, 403)

    def test_post_with_wrong_csrf_header_rejected(self) -> None:
        h = Harness()
        token, _ = h.login()

        response = h.call(
            DashboardRequest(
                method="POST",
                path="/api/event",
                cookies={SESSION_COOKIE: token},
                headers={CSRF_HEADER: "wrong-csrf"},
                body=json.dumps({"type": "solve", "team_id": "alpha", "challenge_id": "web-1"}),
            )
        )

        self.assertEqual(response.status, 403)

    def test_post_with_valid_csrf_records_event_and_rotates_session(self) -> None:
        h = Harness()
        token, csrf = h.login()

        response = h.call(
            DashboardRequest(
                method="POST",
                path="/api/event",
                cookies={SESSION_COOKIE: token},
                headers={CSRF_HEADER: csrf},
                body=json.dumps(
                    {"type": "solve", "team_id": "alpha", "challenge_id": "web-1", "payload": {"submission_id": "s1"}}
                ),
            )
        )

        self.assertEqual(response.status, 201)
        payload = json.loads(response.body)
        self.assertEqual(payload["event"]["type"], "solve")
        self.assertEqual(payload["event"]["team_id"], "alpha")
        self.assertNotEqual(response.cookies[SESSION_COOKIE], token)

        # Session survives a failed-CSRF request: old token wasn't rotated
        # away by the earlier rejected attempts in other tests, only by
        # successful authenticated requests.
        progress = h.service.progress()
        self.assertEqual(progress["alpha"].solved, ["web-1"])

    def test_failed_csrf_does_not_rotate_session(self) -> None:
        h = Harness()
        token, _ = h.login()

        h.call(
            DashboardRequest(
                method="POST",
                path="/api/event",
                cookies={SESSION_COOKIE: token},
                body=json.dumps({"type": "solve", "team_id": "alpha", "challenge_id": "web-1"}),
            )
        )

        # Original token still valid since the CSRF-rejected request never rotated it.
        response = h.call(DashboardRequest(method="GET", path="/api/progress", cookies={SESSION_COOKIE: token}))
        self.assertEqual(response.status, 200)


class PublicRouteTests(unittest.TestCase):
    def test_public_scoreboard_reachable_with_public_token(self) -> None:
        h = Harness()
        h.service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})

        response = h.call(
            DashboardRequest(
                method="GET", path="/public/scoreboard", headers={PUBLIC_TOKEN_HEADER: h.auth.public_token}
            )
        )

        self.assertEqual(response.status, 200)
        payload = json.loads(response.body)
        self.assertEqual(len(payload["scoreboard"]), 1)
        row = payload["scoreboard"][0]
        self.assertEqual(set(row), {"display_name", "rank", "score", "solve_count"})
        self.assertEqual(row["display_name"], "Team Alpha")

    def test_public_scoreboard_via_query_token(self) -> None:
        h = Harness()

        response = h.call(
            DashboardRequest(method="GET", path="/public/scoreboard", query={"token": h.auth.public_token})
        )

        self.assertEqual(response.status, 200)

    def test_public_scoreboard_rejects_missing_token(self) -> None:
        h = Harness()
        response = h.call(DashboardRequest(method="GET", path="/public/scoreboard"))

        self.assertEqual(response.status, 401)

    def test_public_scoreboard_rejects_wrong_token(self) -> None:
        h = Harness()
        response = h.call(
            DashboardRequest(method="GET", path="/public/scoreboard", headers={PUBLIC_TOKEN_HEADER: "nope"})
        )

        self.assertEqual(response.status, 401)

    def test_public_scoreboard_not_reachable_with_admin_session(self) -> None:
        h = Harness()
        token, _ = h.login()

        # Admin session cookie alone (no public token) must not grant access.
        response = h.call(
            DashboardRequest(method="GET", path="/public/scoreboard", cookies={SESSION_COOKIE: token})
        )

        self.assertEqual(response.status, 401)

    def test_admin_dashboard_not_reachable_with_public_token(self) -> None:
        h = Harness()

        # Public token used as if it were the session cookie value.
        response = h.call(
            DashboardRequest(method="GET", path="/api/progress", cookies={SESSION_COOKIE: h.auth.public_token})
        )
        self.assertEqual(response.status, 401)

        # Public token in the public-token header on an admin route also
        # doesn't help -- admin routes never look at that header.
        response = h.call(
            DashboardRequest(
                method="GET", path="/api/progress", headers={PUBLIC_TOKEN_HEADER: h.auth.public_token}
            )
        )
        self.assertEqual(response.status, 401)

    def test_public_feed_is_redacted(self) -> None:
        h = Harness()
        h.service.record_event("attempt", "alpha", "web-1")
        h.service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1", "flag": "CTF{x}"})

        response = h.call(
            DashboardRequest(method="GET", path="/public/feed", headers={PUBLIC_TOKEN_HEADER: h.auth.public_token})
        )

        payload = json.loads(response.body)
        self.assertEqual(len(payload["feed"]), 1)  # attempt filtered out
        row = payload["feed"][0]
        self.assertEqual(set(row), {"seq", "ts", "type", "display_name"})
        self.assertEqual(row["display_name"], "Team Alpha")
        self.assertNotIn("payload", row)
        self.assertNotIn("team_id", row)
        self.assertNotIn("challenge_id", row)


class NotFoundTests(unittest.TestCase):
    def test_unknown_path_is_404(self) -> None:
        h = Harness()
        response = h.call(DashboardRequest(method="GET", path="/nope"))

        self.assertEqual(response.status, 404)


def make_service_with_teams(teams: dict[str, str]) -> CompetitionService:
    store = InMemoryEventStore(clock=lambda: 1700000000.0)
    return CompetitionService(
        store=store,
        catalog=make_catalog(),
        config=make_config(),
        scoring_engine=StaticPointsEngine(),
        teams=teams,
    )


def html_get(path: str, **kwargs) -> DashboardRequest:
    headers = dict(kwargs.pop("headers", {}) or {})
    headers.setdefault("Accept", "text/html")
    return DashboardRequest(method="GET", path=path, headers=headers, **kwargs)


class HtmlRouteTests(unittest.TestCase):
    def test_login_page_is_html_with_password_field(self) -> None:
        h = Harness()
        response = h.call(html_get("/login"))

        self.assertEqual(response.status, 200)
        self.assertIn("text/html", response.headers["Content-Type"])
        self.assertIn('type="password"', response.body)

    def test_root_html_unauthenticated_redirects_to_login(self) -> None:
        h = Harness()
        response = h.call(html_get("/"))

        self.assertEqual(response.status, 302)
        self.assertEqual(response.headers.get("Location"), "/login")

    def test_root_html_authenticated_returns_dashboard(self) -> None:
        h = Harness()
        token, _ = h.login()

        response = h.call(html_get("/", cookies={SESSION_COOKIE: token}))

        self.assertEqual(response.status, 200)
        self.assertIn("text/html", response.headers["Content-Type"])
        self.assertIn("Admin Dashboard", response.body)

    def test_root_without_html_accept_still_returns_json(self) -> None:
        # Back-compat: an API client (no Accept: text/html) hits the JSON
        # dashboard handler unchanged.
        h = Harness()
        token, _ = h.login()

        response = h.call(DashboardRequest(method="GET", path="/", cookies={SESSION_COOKIE: token}))

        self.assertEqual(response.status, 200)
        self.assertIn("application/json", response.headers["Content-Type"])
        payload = json.loads(response.body)
        self.assertIn("progress", payload)

    def test_dashboard_html_escapes_malicious_team_name(self) -> None:
        service = make_service_with_teams({"alpha": "<script>alert('xss')</script>"})
        service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})
        sessions = InMemorySessionStore(token_factory=SequentialTokens())
        auth = make_auth()
        clock = ScriptedClock([START + timedelta(seconds=i) for i in range(10)])

        login = dispatch(login_request(), service=service, sessions=sessions, auth=auth, clock=clock)
        token = login.cookies[SESSION_COOKIE]

        response = dispatch(
            html_get("/", cookies={SESSION_COOKIE: token}),
            service=service,
            sessions=sessions,
            auth=auth,
            clock=clock,
        )

        self.assertEqual(response.status, 200)
        # The raw injected tag must never appear; it must be entity-encoded.
        self.assertNotIn("<script>alert('xss')</script>", response.body)
        self.assertIn("&lt;script&gt;", response.body)

    def test_public_html_reachable_with_token(self) -> None:
        h = Harness()
        response = h.call(html_get("/public", query={"token": h.auth.public_token}))

        self.assertEqual(response.status, 200)
        self.assertIn("text/html", response.headers["Content-Type"])

    def test_public_html_rejects_admin_session_without_token(self) -> None:
        h = Harness()
        token, _ = h.login()

        response = h.call(html_get("/public", cookies={SESSION_COOKIE: token}))

        self.assertEqual(response.status, 401)

    def test_admin_dashboard_not_reachable_with_public_token(self) -> None:
        h = Harness()
        # Public token stuffed into the session cookie must not unlock the
        # admin HTML page -- it redirects to login instead.
        response = h.call(html_get("/", cookies={SESSION_COOKIE: h.auth.public_token}))

        self.assertEqual(response.status, 302)
        self.assertEqual(response.headers.get("Location"), "/login")


class MultiAdminTests(unittest.TestCase):
    def make_multi_auth(self) -> AuthConfig:
        return AuthConfig.from_users(
            [("admin", "hunter2"), ("root", "toor")],
            public_token="pub-token-fixed",
            session_ttl_seconds=300,
            pbkdf2_iterations=1000,
            salt=b"fixed-salt-16bb",
        )

    def _login(self, auth: AuthConfig, username: str, password: str):
        sessions = InMemorySessionStore(token_factory=SequentialTokens())
        clock = ScriptedClock([START + timedelta(seconds=i) for i in range(5)])
        return dispatch(
            login_request(username=username, password=password),
            service=make_service(),
            sessions=sessions,
            auth=auth,
            clock=clock,
        )

    def test_both_admins_can_log_in(self) -> None:
        auth = self.make_multi_auth()

        first = self._login(auth, "admin", "hunter2")
        second = self._login(auth, "root", "toor")

        self.assertEqual(first.status, 200)
        self.assertIn(SESSION_COOKIE, first.cookies)
        self.assertEqual(second.status, 200)
        self.assertIn(SESSION_COOKIE, second.cookies)

    def test_wrong_password_rejected_for_multi_admin(self) -> None:
        auth = self.make_multi_auth()

        response = self._login(auth, "root", "wrong")

        self.assertEqual(response.status, 401)

    def test_unknown_user_rejected_for_multi_admin(self) -> None:
        auth = self.make_multi_auth()

        response = self._login(auth, "ghost", "toor")

        self.assertEqual(response.status, 401)

    def test_single_admin_create_still_logs_in(self) -> None:
        # Back-compat: a config built via create() (no admins roster) still
        # authenticates via the verify_any fallback.
        auth = make_auth()

        response = self._login(auth, "admin", "hunter2")

        self.assertEqual(response.status, 200)


class LoginTimingTests(unittest.TestCase):
    """Regression: login must not leak whether a username exists via response
    timing. We can't assert wall-clock timing deterministically/offline, so we
    assert the underlying invariant that produces it: the number of (expensive)
    PBKDF2 evaluations is identical for a valid vs. an unknown username."""

    def _count_pbkdf2(self, fn) -> int:
        real = ds.hashlib.pbkdf2_hmac
        calls = {"n": 0}

        def counting(*args, **kwargs):
            calls["n"] += 1
            return real(*args, **kwargs)

        with mock.patch.object(ds.hashlib, "pbkdf2_hmac", counting):
            fn()
        return calls["n"]

    def test_single_admin_hashes_regardless_of_username(self) -> None:
        auth = make_auth()  # single admin "admin"
        known = self._count_pbkdf2(lambda: auth.verify_any("admin", "nope"))
        unknown = self._count_pbkdf2(lambda: auth.verify_any("ghost", "nope"))
        self.assertGreaterEqual(known, 1)
        self.assertEqual(known, unknown)

    def test_verify_password_hashes_regardless_of_username(self) -> None:
        auth = make_auth()
        known = self._count_pbkdf2(lambda: auth.verify_password("admin", "nope"))
        unknown = self._count_pbkdf2(lambda: auth.verify_password("ghost", "nope"))
        self.assertGreaterEqual(known, 1)
        self.assertEqual(known, unknown)

    def test_multi_admin_hashes_regardless_of_username(self) -> None:
        auth = AuthConfig.from_users(
            [("admin", "hunter2"), ("root", "toor")],
            public_token="pub-token-fixed",
            pbkdf2_iterations=1000,
            salt=b"fixed-salt-16bb",
        )
        known = self._count_pbkdf2(lambda: auth.verify_any("root", "nope"))
        unknown = self._count_pbkdf2(lambda: auth.verify_any("ghost", "nope"))
        self.assertGreaterEqual(known, 1)
        self.assertEqual(known, unknown)

    def test_constant_time_fix_preserves_correctness(self) -> None:
        auth = make_auth()
        self.assertTrue(auth.verify_any("admin", "hunter2"))
        self.assertFalse(auth.verify_any("admin", "wrong"))
        self.assertFalse(auth.verify_any("ghost", "hunter2"))
        self.assertTrue(auth.verify_password("admin", "hunter2"))
        self.assertFalse(auth.verify_password("ghost", "hunter2"))

    def test_uses_constant_time_compare_digest(self) -> None:
        # The secret comparisons must go through hmac/secrets.compare_digest,
        # never ``==``. Assert compare_digest is actually invoked on a login.
        auth = make_auth()
        real = ds.secrets.compare_digest
        calls = {"n": 0}

        def counting(*args, **kwargs):
            calls["n"] += 1
            return real(*args, **kwargs)

        with mock.patch.object(ds.secrets, "compare_digest", counting):
            auth.verify_any("admin", "hunter2")
        self.assertGreater(calls["n"], 0)


class Pbkdf2StrengthTests(unittest.TestCase):
    def test_default_iterations_meet_owasp_2023_minimum(self) -> None:
        auth = AuthConfig.create("admin", "pw", public_token="x")
        self.assertGreaterEqual(auth.pbkdf2_iterations, 600_000)

    def test_from_users_default_iterations_meet_owasp_2023_minimum(self) -> None:
        auth = AuthConfig.from_users([("admin", "pw")], public_token="x")
        self.assertGreaterEqual(auth.pbkdf2_iterations, 600_000)


class LiveTimeDecayScoringTests(unittest.TestCase):
    """The live dashboard must pass its own clock to the leaderboard so the
    default time-decay engine reports the current value -- not the fully
    decayed floor. Uses the REAL default engine, not StaticPointsEngine, which
    is exactly the combination the other dashboard tests never exercise.
    """

    def _service(self) -> CompetitionService:
        # Solve recorded at START; default (time_decay) engine; 10h window.
        store = InMemoryEventStore(clock=lambda: START.timestamp())
        service = CompetitionService(
            store=store,
            catalog=make_catalog(),
            config=make_config(),  # start=START, end=END
            teams={"alpha": "Team Alpha"},
        )
        service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})
        return service

    def test_default_engine_bug_baseline(self) -> None:
        # Documents the defect: calling leaderboard() with no as_of resolves
        # "now" to end_time, so the challenge reads its fully-decayed minimum.
        service = self._service()
        floored = service.leaderboard().entries[0].score
        live = service.leaderboard(as_of=START + timedelta(seconds=5)).entries[0].score
        self.assertEqual(floored, 100)  # minimum_value
        self.assertEqual(live, 500)  # initial_value, essentially undecayed

    def test_dashboard_leaderboard_uses_live_clock_not_floor(self) -> None:
        service = self._service()
        tokens = SequentialTokens()
        sessions = InMemorySessionStore(token_factory=tokens)
        auth = make_auth()
        # Clock stays a few seconds past START for every read.
        clock = ScriptedClock([START + timedelta(seconds=i) for i in range(1, 20)])

        login = dispatch(login_request(), service=service, sessions=sessions, auth=auth, clock=clock)
        token = login.cookies[SESSION_COOKIE]

        response = dispatch(
            DashboardRequest(method="GET", path="/api/leaderboard", cookies={SESSION_COOKIE: token}),
            service=service,
            sessions=sessions,
            auth=auth,
            clock=clock,
        )
        self.assertEqual(response.status, 200)
        score = json.loads(response.body)["leaderboard"]["entries"][0]["score"]
        # Before the fix this was 100 (floored); now it reflects the live value.
        self.assertEqual(score, 500)

    def test_public_scoreboard_uses_live_clock_not_floor(self) -> None:
        service = self._service()
        sessions = InMemorySessionStore(token_factory=SequentialTokens())
        auth = make_auth()
        clock = ScriptedClock([START + timedelta(seconds=3)])

        response = dispatch(
            DashboardRequest(
                method="GET",
                path="/public/scoreboard",
                headers={PUBLIC_TOKEN_HEADER: auth.public_token},
            ),
            service=service,
            sessions=sessions,
            auth=auth,
            clock=clock,
        )
        self.assertEqual(response.status, 200)
        score = json.loads(response.body)["scoreboard"][0]["score"]
        self.assertEqual(score, 500)


if __name__ == "__main__":
    unittest.main()
