"""PostgreSQL integration tests for the M11 web cookie-session auth bridge.

Unauthenticated UI page -> 302 to the login form (NOT a JSON 401); good creds set
an httpOnly+Secure+SameSite cookie and redirect to the dashboard; bad creds
re-render the form with a generic error, NO cookie, and no which-field
disclosure; logout revokes the session server-side AND clears the cookie. The raw
session token never appears in any response body or a Location URL (REQ-INV-011).
SKIPS cleanly without the [api]+[web]+[db] extras / CTFGEN_TEST_DATABASE_URL.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_auth_integration
"""

from __future__ import annotations

import os
import unittest

try:  # heavy deps optional; guard so import never fails the host suite
    import web_support as ws

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - only without the extras
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_SKIP_REASON = (
    f"[api]/[web]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WebAuthBridgeTests(unittest.TestCase):
    def test_unauthenticated_page_redirects_to_login(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            # No cookie: the dashboard redirects to the login form, not a JSON 401.
            r = client.get("/app/", follow_redirects=False)
            self.assertEqual(r.status_code, 302, r.text)
            self.assertTrue(r.headers["location"].endswith("/app/login"))
            # And it is HTML on arrival, not the ctfgen.error JSON envelope.
            final = client.get("/app/", follow_redirects=True)
            self.assertEqual(final.status_code, 200)
            self.assertIn("Sign in", final.text)
            self.assertNotIn('"error"', final.text)

    def test_login_success_sets_hardened_cookie_and_redirects(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            r = ws.login(client, ws.ALICE)
            self.assertEqual(r.status_code, 303, r.text)
            self.assertTrue(r.headers["location"].endswith("/app/"))
            set_cookie = r.headers.get("set-cookie", "")
            lowered = set_cookie.lower()
            self.assertIn("ctfgen_web_session=", set_cookie)
            self.assertIn("httponly", lowered)
            self.assertIn("secure", lowered)
            self.assertIn("samesite=lax", lowered)
            # The token is never placed in the redirect Location.
            token = ws.session_cookie(client)
            self.assertTrue(token)
            self.assertNotIn(token, r.headers["location"])
            # The cookie now authenticates the dashboard (stable, no rotation).
            dash = client.get("/app/")
            self.assertEqual(dash.status_code, 200, dash.text)
            self.assertIn("Dashboard", dash.text)
            # A second load keeps working with the SAME token (no self-DoS).
            self.assertEqual(client.get("/app/").status_code, 200)
            self.assertEqual(ws.session_cookie(client), token)

    def test_bad_credentials_generic_error_no_cookie_no_disclosure(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            wrong = ws.login(client, ws.ALICE, password="not-the-password")  # noqa: S106
            unknown = ws.login(client, "ghost@example.com")
            for r in (wrong, unknown):
                self.assertEqual(r.status_code, 401, r.text)
                self.assertNotIn("set-cookie", {k.lower() for k in r.headers})
                self.assertIsNone(ws.session_cookie(client))
                self.assertIn("Invalid email or password", r.text)
            # Same generic message for wrong-password and unknown-email: no oracle.
            self.assertIn("Invalid email or password", wrong.text)
            self.assertIn("Invalid email or password", unknown.text)
            # No disclosure of which field was wrong.
            for probe in ("password is", "no such", "not found", "unknown email"):
                self.assertNotIn(probe, wrong.text.lower())

    def test_logout_revokes_session_and_clears_cookie(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)
            token = ws.session_cookie(client)
            self.assertTrue(token)
            # Grab a CSRF token from a rendered page (logout is CSRF-protected).
            csrf = ws.extract_csrf(client.get("/app/").text)
            self.assertTrue(csrf)
            out = client.post(
                "/app/logout", data={"csrf_token": csrf}, follow_redirects=False
            )
            self.assertEqual(out.status_code, 303, out.text)
            self.assertTrue(out.headers["location"].endswith("/app/login"))
            # Cookie cleared, and the OLD token no longer resolves -> redirect to
            # login (session revoked server-side, not merely forgotten by the client).
            after = client.get("/app/", follow_redirects=False)
            self.assertEqual(after.status_code, 302)
            self.assertTrue(after.headers["location"].endswith("/app/login"))
            # Even replaying the exact revoked token cookie is rejected.
            replay = client.get(
                "/app/",
                cookies={"ctfgen_web_session": token},
                follow_redirects=False,
            )
            self.assertEqual(replay.status_code, 302)

    def test_token_never_appears_in_body_or_location(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            r = ws.login(client, ws.ALICE)
            token = ws.session_cookie(client)
            self.assertTrue(token)
            self.assertNotIn(token, r.headers.get("location", ""))
            for path in ("/app/", "/app/competitions", f"/app/competitions/{ws.COMP_A}"):
                page = client.get(path)
                self.assertEqual(page.status_code, 200, page.text)
                self.assertNotIn(token, page.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
