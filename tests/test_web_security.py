"""PostgreSQL integration tests for the M11 web security posture.

XSS: a competition name containing ``<script>`` renders ESCAPED (the raw tag is
absent). CSRF: a state-changing POST without / with a wrong token is 403; a
correct token succeeds. Headers: every HTML response carries the strict CSP plus
nosniff / frame-deny / referrer-policy. Cookie: the session cookie is
httpOnly + Secure + SameSite. SKIPS cleanly without the extras / test database.
"""

from __future__ import annotations

import os
import unittest

try:
    import web_support as ws

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

_XSS_CID = "xss-ctf-2026"
_XSS_NAME = "<script>alert(1)</script>"


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WebXssTests(unittest.TestCase):
    def test_hostile_competition_name_is_escaped(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.add_competition(db, _XSS_CID, _XSS_NAME)
            ws.grant_membership(db, ws.ALICE, _XSS_CID, "organizer")
            ws.login(client, ws.ALICE)
            for path in ("/app/competitions", f"/app/competitions/{_XSS_CID}"):
                page = client.get(path)
                self.assertEqual(page.status_code, 200, page.text)
                # The raw executable tag must NOT appear; its escaped form must.
                self.assertNotIn("<script>alert(1)</script>", page.text)
                self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WebCsrfTests(unittest.TestCase):
    def test_state_changing_post_requires_valid_csrf(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)
            # Missing token -> 403.
            missing = client.post("/app/logout", follow_redirects=False)
            self.assertEqual(missing.status_code, 403, missing.text)
            # Wrong token -> 403.
            wrong = client.post(
                "/app/logout", data={"csrf_token": "not-the-token"}, follow_redirects=False
            )
            self.assertEqual(wrong.status_code, 403, wrong.text)
            # The session survived both rejected attempts (still authenticated).
            self.assertEqual(client.get("/app/").status_code, 200)
            # Correct token (positive control) -> 303 redirect (logout succeeds).
            csrf = ws.extract_csrf(client.get("/app/").text)
            self.assertTrue(csrf)
            ok = client.post(
                "/app/logout", data={"csrf_token": csrf}, follow_redirects=False
            )
            self.assertEqual(ok.status_code, 303, ok.text)

    def test_csrf_error_page_leaks_nothing(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.ALICE)
            r = client.post("/app/logout", follow_redirects=False)
            self.assertEqual(r.status_code, 403)
            token = ws.session_cookie(client)
            self.assertNotIn(token or "impossible", r.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WebSecurityHeadersTests(unittest.TestCase):
    def _assert_headers(self, response) -> None:
        csp = response.headers.get("content-security-policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        # Scripts admitted ONLY via a per-response nonce -- never 'unsafe-inline'.
        self.assertIn("script-src 'nonce-", csp)
        self.assertNotIn("'unsafe-inline'", csp.split("script-src")[1].split(";")[0])
        self.assertEqual(response.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(response.headers.get("x-frame-options"), "DENY")
        self.assertIn("referrer-policy", {k.lower() for k in response.headers})

    def test_every_html_response_carries_the_hardening_headers(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            # Unauthenticated login page.
            self._assert_headers(client.get("/app/login"))
            ws.login(client, ws.ALICE)
            # Authenticated pages + a 404 error page all carry the headers.
            for path in (
                "/app/",
                "/app/competitions",
                f"/app/competitions/{ws.COMP_A}",
                f"/app/competitions/{ws.COMP_B}",  # 404 (unauthorized) page
                "/app/competitions/nope",  # 404 (missing) page
            ):
                self._assert_headers(client.get(path))

    def test_nonce_in_header_matches_the_rendered_style_nonce(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            page = client.get("/app/login")
            csp = page.headers["content-security-policy"]
            import re

            nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
            self.assertIn(f'<style nonce="{nonce}">', page.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WebLoginCsrfTests(unittest.TestCase):
    """POST /app/login is protected by a pre-session double-submit login-CSRF token
    (closing login-CSRF / session fixation), verified BEFORE authentication."""

    def _post(self, client, *, email, password, token):
        data = {"email": email, "password": password}
        if token is not None:
            data["login_csrf_token"] = token
        return client.post("/app/login", data=data, follow_redirects=False)

    def test_login_without_csrf_token_is_403_and_no_session(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            # Valid credentials but NO login-CSRF token -> 403, and crucially no
            # session cookie is issued (authentication never ran).
            r = self._post(client, email=ws.ALICE, password=ws.PASSWORD, token=None)
            self.assertEqual(r.status_code, 403, r.text)
            self.assertIsNone(ws.session_cookie(client))

    def test_login_with_wrong_csrf_token_is_403_and_no_session(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            # Prime the login-CSRF cookie via a GET, then submit a MISMATCHED field.
            client.get("/app/login")
            r = self._post(
                client,
                email=ws.ALICE,
                password=ws.PASSWORD,
                token="not-the-token",  # noqa: S106 - a forged CSRF token, not a password
            )
            self.assertEqual(r.status_code, 403, r.text)
            self.assertIsNone(ws.session_cookie(client))

    def test_login_with_matching_csrf_token_proceeds(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            # Matching cookie+field pair -> authentication proceeds: good creds set
            # the session cookie and redirect to the dashboard.
            ok = ws.login(client, ws.ALICE)
            self.assertEqual(ok.status_code, 303, ok.text)
            self.assertTrue(ok.headers["location"].endswith("/app/"))
            self.assertTrue(ws.session_cookie(client))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WebInlineStyleTests(unittest.TestCase):
    """The strict CSP admits no style ATTRIBUTES (only the nonce'd <style> ELEMENT),
    so no rendered page may carry a ``style="`` attribute; login/error use classes."""

    def test_no_rendered_page_carries_a_style_attribute(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            # Login + error pages BEFORE authenticating.
            login_page = client.get("/app/login")
            self.assertEqual(login_page.status_code, 200, login_page.text)
            self.assertNotIn('style="', login_page.text)
            # The login markup uses the classes defined in the nonce'd <style> block.
            self.assertIn('class="card card-narrow"', login_page.text)
            self.assertIn('class="field-full"', login_page.text)
            self.assertIn('class="btn"', login_page.text)

            ws.login(client, ws.ALICE)
            error_page = client.get("/app/competitions/does-not-exist")
            self.assertEqual(error_page.status_code, 404, error_page.text)
            self.assertNotIn('style="', error_page.text)
            self.assertIn('class="card card-centered"', error_page.text)

            for path in (
                "/app/",
                "/app/competitions",
                f"/app/competitions/{ws.COMP_A}",
            ):
                page = client.get(path)
                self.assertEqual(page.status_code, 200, page.text)
                self.assertNotIn('style="', page.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WebCacheControlTests(unittest.TestCase):
    """Authenticated HTML + the login page carry ``Cache-Control: no-store`` so
    per-user data / the CSRF token is not retained by a shared cache or the
    bfcache (readable after logout / via the back button)."""

    def test_web_html_carries_no_store(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            login_page = client.get("/app/login")
            self.assertEqual(
                login_page.headers.get("cache-control"), "no-store", login_page.text
            )
            ws.login(client, ws.ALICE)
            for path in ("/app/", "/app/competitions", f"/app/competitions/{ws.COMP_A}"):
                page = client.get(path)
                self.assertEqual(page.status_code, 200, page.text)
                self.assertEqual(page.headers.get("cache-control"), "no-store")


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WebCookieAttributeTests(unittest.TestCase):
    def test_session_cookie_is_httponly_secure_samesite(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            r = ws.login(client, ws.ALICE)
            set_cookie = r.headers.get("set-cookie", "")
            lowered = set_cookie.lower()
            self.assertIn("ctfgen_web_session=", set_cookie)
            self.assertIn("httponly", lowered)
            self.assertIn("secure", lowered)
            self.assertIn("samesite=lax", lowered)
            self.assertIn("path=/app", lowered)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
