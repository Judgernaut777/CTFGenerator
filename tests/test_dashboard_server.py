from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

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


if __name__ == "__main__":
    unittest.main()
