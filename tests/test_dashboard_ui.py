from __future__ import annotations

import unittest

from ctf_generator.dashboard_ui import (
    admin_dashboard_page,
    escape,
    login_page,
    public_scoreboard_page,
)

ALL_PAGES = [login_page(), admin_dashboard_page(), public_scoreboard_page()]


class EscapeTests(unittest.TestCase):
    def test_escapes_script_tag(self) -> None:
        self.assertEqual(escape("<script>"), "&lt;script&gt;")

    def test_escapes_quotes_and_amp(self) -> None:
        result = escape("a & b \"c\" 'd'")
        self.assertNotIn('"', result)
        self.assertNotIn("'", result)
        self.assertIn("&amp;", result)

    def test_coerces_non_strings(self) -> None:
        self.assertEqual(escape(7), "7")
        self.assertEqual(escape(None), "")


class SelfContainedTests(unittest.TestCase):
    def test_pages_are_complete_html_documents(self) -> None:
        for page in ALL_PAGES:
            self.assertTrue(page.lstrip().lower().startswith("<!doctype html>"))
            self.assertIn("<style>", page)
            self.assertIn("<script>", page)

    def test_pages_reference_no_external_resources(self) -> None:
        # CSP-hostile environment: no external CDN/font/script/stylesheet.
        for page in ALL_PAGES:
            lowered = page.lower()
            self.assertNotIn("http://", lowered)
            self.assertNotIn("https://", lowered)
            self.assertNotIn("<link", lowered)
            self.assertNotIn('src="//', lowered)


class LoginPageTests(unittest.TestCase):
    def test_has_password_field_and_form(self) -> None:
        page = login_page()
        self.assertIn('type="password"', page)
        self.assertIn("<form", page)
        self.assertIn("/login", page)

    def test_optional_csrf_is_escaped(self) -> None:
        page = login_page(csrf="<x>&\"'")
        self.assertNotIn("<x>", page)
        self.assertIn("&lt;x&gt;", page)


class AdminPageTests(unittest.TestCase):
    def test_polls_api_routes(self) -> None:
        page = admin_dashboard_page()
        self.assertIn("/api/leaderboard", page)
        self.assertIn("/api/progress", page)
        self.assertIn("/api/feed", page)
        self.assertIn("/api/event", page)

    def test_uses_csrf_header_and_textcontent(self) -> None:
        page = admin_dashboard_page()
        self.assertIn("X-CSRF-Token", page)
        self.assertIn("textContent", page)
        # Server data must never be assigned via innerHTML.
        self.assertNotIn("innerHTML", page)

    def test_initial_rows_are_html_escaped(self) -> None:
        rows = [
            {
                "display_name": "<script>alert('xss')</script>",
                "rank": 1,
                "score": 500,
                "solve_count": 1,
            }
        ]
        page = admin_dashboard_page(rows)
        self.assertNotIn("<script>alert('xss')</script>", page)
        self.assertIn("&lt;script&gt;", page)


class PublicPageTests(unittest.TestCase):
    def test_polls_public_scoreboard_with_token(self) -> None:
        page = public_scoreboard_page()
        self.assertIn("/public/scoreboard", page)
        self.assertIn("token", page)
        self.assertIn("textContent", page)
        self.assertNotIn("innerHTML", page)

    def test_initial_rows_are_html_escaped(self) -> None:
        rows = [{"display_name": "<img src=x onerror=alert(1)>", "rank": 1, "score": 10, "solve_count": 1}]
        page = public_scoreboard_page(rows)
        self.assertNotIn("<img src=x onerror=alert(1)>", page)
        self.assertIn("&lt;img", page)


if __name__ == "__main__":
    unittest.main()
