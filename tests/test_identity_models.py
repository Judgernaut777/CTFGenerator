"""Pure unit tests for the Identity domain value types (host-runnable, stdlib).

These exercise the aggregates' invariants directly -- no database -- so the core
gate covers the domain rules even where the Docker-gated repository suite skips.
"""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from ctf_generator.domain.identity.models import (
    VALID_ROLES,
    Membership,
    Team,
    User,
)


class UserTests(unittest.TestCase):
    def test_valid_user(self) -> None:
        u = User(email="alice@example.io", display_name="Alice")
        self.assertEqual(u.email, "alice@example.io")
        self.assertEqual(u.display_name, "Alice")

    def test_frozen(self) -> None:
        u = User(email="a@x.io", display_name="A")
        with self.assertRaises(FrozenInstanceError):
            u.display_name = "B"  # type: ignore[misc]

    def test_rejects_empty_display_name(self) -> None:
        for bad in ("", "   "):
            with self.assertRaises(ValueError):
                User(email="a@x.io", display_name=bad)

    def test_rejects_malformed_email(self) -> None:
        for bad in ("", "   ", "no-at-sign", "@x.io", "a@nodot", "a@"):
            with self.assertRaises(ValueError):
                User(email=bad, display_name="A")


class TeamTests(unittest.TestCase):
    def test_valid_team(self) -> None:
        t = Team(competition_id="spring-2026", name="Red")
        self.assertEqual(t.competition_id, "spring-2026")
        self.assertEqual(t.name, "Red")

    def test_rejects_empty_fields(self) -> None:
        with self.assertRaises(ValueError):
            Team(competition_id="", name="Red")
        with self.assertRaises(ValueError):
            Team(competition_id="c", name="   ")


class MembershipTests(unittest.TestCase):
    def test_valid_teamed(self) -> None:
        m = Membership(
            user_email="a@x.io", competition_id="c", role="captain", team_name="Red"
        )
        self.assertEqual(m.role, "captain")
        self.assertEqual(m.team_name, "Red")

    def test_valid_unteamed_defaults_to_none(self) -> None:
        m = Membership(user_email="a@x.io", competition_id="c", role="organizer")
        self.assertIsNone(m.team_name)

    def test_all_valid_roles_accepted(self) -> None:
        for role in VALID_ROLES:
            m = Membership(user_email="a@x.io", competition_id="c", role=role)
            self.assertEqual(m.role, role)

    def test_rejects_unknown_role(self) -> None:
        with self.assertRaises(ValueError):
            Membership(user_email="a@x.io", competition_id="c", role="superuser")

    def test_rejects_empty_required_fields(self) -> None:
        with self.assertRaises(ValueError):
            Membership(user_email="", competition_id="c", role="player")
        with self.assertRaises(ValueError):
            Membership(user_email="a@x.io", competition_id="", role="player")

    def test_empty_team_name_is_rejected_not_treated_as_unteamed(self) -> None:
        # Unteamed is None, never "" -- an empty string is a programming error.
        with self.assertRaises(ValueError):
            Membership(
                user_email="a@x.io", competition_id="c", role="player", team_name=""
            )


if __name__ == "__main__":
    unittest.main()
