#!/usr/bin/env python3
"""Internal-alpha EXIT-scenario simulation (M21 stream A).

Executes the mechanizable half of the internal-alpha *exit* gate
(``docs/RELEASE_CRITERIA.md`` lines ~201-208) as a SIMULATED dry-run on this
single host: one challenge is **generated -> published (content-addressed,
immutable) -> submitted -> solved (exactly once) -> scored -> shown on a
scoreboard**, end to end through the real application services + HTTP API over a
live PostgreSQL.

It is deliberately the SAME spine as ``tests/test_e2e_flow_integration.py`` and
``tests/test_cli_e2e_integration.py`` (a fresh per-run migrated database, real
``DbAuthenticator`` over ``AuthService``, a Starlette ``TestClient`` speaking the
JSON API), refactored into a re-runnable script that prints a PASS / per-step
summary. ``tests/test_alpha_sim_integration.py`` calls :func:`run_simulation` and
asserts the invariants.

HONEST BOUNDARY (charter): this is a COMPOSITE, not one unbroken automated flow.
The exit criterion also says "launched on a worker" -- the *distributed worker
launching the published bundle as a contestant instance* is NOT wired here,
because the ``build_challenge`` pipeline is unbuilt (see
``docs/evaluation/eval-worker-limitations.md``). This sim scores the intended
solver's flag against the published, content-addressed version; the worker
container-launch + isolation half is proven separately by the executed Docker
test ``test_docker_backend_integration``. Neither half is faked; they are not
stitched into a single flow. See ``docs/validation/internal-alpha-report.md``.

Run:
    cd /home/mini/CTFGenerator && PYTHONPATH=src:tests \\
      CTFGEN_TEST_DATABASE_URL='postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres' \\
      .venv/bin/python3 scripts/alpha_sim.py

Exit code 0 => every step PASS and every invariant held. Without
``CTFGEN_TEST_DATABASE_URL`` (or the ``[api]``/``[db]`` extras) it prints a SKIP
and exits 0 -- it never silently claims success.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime

try:  # heavy deps optional; guard so a bare import never explodes the caller
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url
    from starlette.testclient import TestClient

    from ctf_generator.application.auth import AuthService
    from ctf_generator.application.auth.hashing import Pbkdf2Sha256Hasher
    from ctf_generator.application.scoring.projector import ScoreProjector
    from ctf_generator.domain.identity.models import Membership
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.membership_repository import (
        SqlAlchemyMembershipRepository,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.db_authenticator import DbAuthenticator
    from ctf_generator.interfaces.api.settings import ApiSettings

    IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - only without the extras
    IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_V1 = "/api/v1"
_ADMIN_EMAIL = "organizer@example.com"
_ADMIN_PW = "correct-horse-battery-9"  # noqa: S105 - sim fixture, not a real secret
_PLAYER_EMAIL = "red-one@example.com"
_PLAYER_PW = "player-horse-battery-8"  # noqa: S105 - sim fixture, not a real secret

_CID = "internal-alpha-2026"
_SLUG = "sqli-1"
_TEAM = "Red"
_FLAG = "CTF{internal-alpha-secret-flag}"

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


@dataclass
class Step:
    """One ordered scenario step and whether its assertion held."""

    name: str
    ok: bool
    detail: str


@dataclass
class SimResult:
    steps: list[Step] = field(default_factory=list)
    invariants: dict[str, bool] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)
    # The content identity captured from the published version.
    spec_sha256: str | None = None

    @property
    def passed(self) -> bool:
        return (
            bool(self.steps)
            and all(s.ok for s in self.steps)
            and bool(self.invariants)
            and all(self.invariants.values())
        )


@contextmanager
def _app(url_base: str):
    """A fresh per-run migrated database + real-auth app, torn down after."""
    base = make_url(url_base)
    name = f"ctfgen_alpha_sim_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        url = base.set(database=name).render_as_string(hide_password=False)
        cfg = AlembicConfig(os.path.join(repo_root, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(repo_root, "alembic"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        db = Database(DatabaseConfig(url=url))
        try:
            service = AuthService(db, hasher=Pbkdf2Sha256Hasher(iterations=1000))
            service.bootstrap_admin(
                email=_ADMIN_EMAIL,
                display_name="Organizer",
                password=_ADMIN_PW,
                now=datetime.now(UTC),
            )
            app = create_app(
                ApiSettings(),
                database=db,
                auth_service=service,
                authenticator=DbAuthenticator(service),
            )
            yield app, db, service
        finally:
            db.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def run_simulation(database_url: str) -> SimResult:
    """Run the internal-alpha exit scenario end to end; return a structured result.

    SECRET DISCIPLINE (S5): neither the intended flag nor any bearer token is ever
    appended to ``result.log``. ``test_alpha_sim_integration`` scans the log to
    prove absence, so the log must stay clean by construction.
    """
    if IMPORT_ERROR is not None:  # pragma: no cover - guarded by callers
        raise RuntimeError(f"alpha_sim dependencies unavailable: {IMPORT_ERROR}")

    res = SimResult()

    def record(name: str, ok: bool, detail: str) -> None:
        res.steps.append(Step(name, ok, detail))
        res.log.append(f"[{'PASS' if ok else 'FAIL':4}] {name}: {detail}")

    with _app(database_url) as (app, db, service):
        client = TestClient(app, follow_redirects=False)
        try:

            def _auth(tok: str) -> dict[str, str]:
                return {"Authorization": f"Bearer {tok}"}

            def _login(email: str, pw: str) -> str:
                r = client.post(
                    f"{_V1}/auth/login", json={"email": email, "password": pw}
                )
                if r.status_code != 200:
                    raise RuntimeError(r.text)
                if pw in r.text:
                    raise RuntimeError("password echoed by login")
                return r.json()["token"]

            # -- organizer authenticates -------------------------------------
            admin = _login(_ADMIN_EMAIL, _ADMIN_PW)
            me = client.get(f"{_V1}/auth/me", headers=_auth(admin))
            record(
                "operator-login",
                me.status_code == 200 and me.json()["subject"] == _ADMIN_EMAIL,
                "named internal operator authenticated over HTTP",
            )

            # -- generate: author the challenge version (spec carries the flag)
            client.post(
                f"{_V1}/competitions",
                headers=_auth(admin),
                json={
                    "competition_id": _CID,
                    "name": "Internal Alpha 2026",
                    "start_time": "2026-06-01T09:00:00Z",
                    "end_time": "2026-06-03T09:00:00Z",
                    "scoring_start_time": "2026-06-01T09:30:00Z",
                    "freeze_time": "2026-06-02T09:00:00Z",
                },
            )
            client.post(
                f"{_V1}/teams",
                headers=_auth(admin),
                json={"competition_id": _CID, "name": _TEAM},
            )
            client.post(
                f"{_V1}/challenge-definitions",
                headers=_auth(admin),
                json={"family": "web", "slug": _SLUG, "title": "SQLi One"},
            )
            cv = client.post(
                f"{_V1}/challenge-versions",
                headers=_auth(admin),
                json={
                    "definition_slug": _SLUG,
                    "seed": "seed-1",
                    "family_version": "1.0.0",
                    "spec": {"title": "SQLi One", "flag": _FLAG},
                },
            )
            draft_hash = cv.json().get("spec_sha256") if cv.status_code == 201 else None
            record(
                "generate",
                cv.status_code == 201 and bool(draft_hash),
                f"draft version created; server-computed spec_sha256={_short(draft_hash)}",
            )

            # -- publish: content-addressed + immutable ----------------------
            pub = client.post(
                f"{_V1}/challenge-versions/{_SLUG}/1/publish", headers=_auth(admin)
            )
            pub_body = pub.json() if pub.status_code == 200 else {}
            res.spec_sha256 = pub_body.get("spec_sha256")
            content_addressed = bool(
                res.spec_sha256
                and _HEX64.match(res.spec_sha256)
                and res.spec_sha256 == draft_hash  # hash stable => content identity
            )
            record(
                "publish",
                pub.status_code == 200
                and pub_body.get("state") == "published"
                and pub_body.get("immutable") is True
                and content_addressed,
                f"state=published immutable=True content-addressed "
                f"(spec_sha256 stable across create->publish={_short(res.spec_sha256)})",
            )

            # -- attach the publication to the competition -------------------
            att = client.post(
                f"{_V1}/competitions/{_CID}/publications",
                headers=_auth(admin),
                json={"definition_slug": _SLUG, "version_no": 1},
            )
            client.post(
                f"{_V1}/users",
                headers=_auth(admin),
                json={
                    "email": _PLAYER_EMAIL,
                    "display_name": "Red One",
                    "role": "player",
                },
            )
            record(
                "attach-publication",
                att.status_code == 201,
                "published version attached to the competition",
            )

            # -- place the contestant on the team (NO API route -> services) --
            # Documented product gap (same as the e2e tests): no membership-grant
            # endpoint exists, so the password credential + player membership are
            # seeded via the services. Everything downstream runs over HTTP.
            service.set_password(_PLAYER_EMAIL, _PLAYER_PW, datetime.now(UTC))
            with db.session_scope() as session:
                SqlAlchemyMembershipRepository(session).add(
                    Membership(
                        user_email=_PLAYER_EMAIL,
                        competition_id=_CID,
                        role="player",
                        team_name=_TEAM,
                    )
                )

            player = _login(_PLAYER_EMAIL, _PLAYER_PW)

            # -- submit: the intended solver's flag --------------------------
            sub = client.post(
                f"{_V1}/competitions/{_CID}/submissions",
                headers=_auth(player),
                json={
                    "team": _TEAM,
                    "definition_slug": _SLUG,
                    "version_no": 1,
                    "answer": _FLAG,
                },
            )
            sub_body = sub.json() if sub.status_code == 201 else {}
            first_solve_ok = (
                sub.status_code == 201
                and sub_body.get("correct") is True
                and sub_body.get("first_solve") is True
                and sub_body.get("solve") is not None
                and _FLAG not in sub.text  # S5: flag never echoed on the outcome
            )
            record(
                "submit-and-solve",
                first_solve_ok,
                "intended solver's flag accepted; first_solve=True; flag not echoed",
            )

            # -- exactly ONE solve -------------------------------------------
            dup = client.post(
                f"{_V1}/competitions/{_CID}/submissions",
                headers=_auth(player),
                json={
                    "team": _TEAM,
                    "definition_slug": _SLUG,
                    "version_no": 1,
                    "answer": _FLAG,
                },
            )
            dup_body = dup.json() if dup.status_code == 201 else {}
            single_solve = (
                dup.status_code == 201
                and dup_body.get("correct") is True
                and dup_body.get("first_solve") is False
                and dup_body.get("solve") is None
                and dup_body.get("submission_id") != sub_body.get("submission_id")
            )
            record(
                "exactly-one-solve",
                single_solve,
                "duplicate correct re-submit accepted but yields NO second solve",
            )

            # -- score + scoreboard ------------------------------------------
            def standings() -> list[dict]:
                r = client.get(
                    f"{_V1}/competitions/{_CID}/scoreboard", headers=_auth(player)
                )
                if r.status_code != 200:
                    raise RuntimeError(r.text)
                return r.json()["data"]

            empty_before = standings() == []  # a GET never triggers a projection
            ScoreProjector(db).run_until_drained()
            board = standings()
            on_board = (
                empty_before
                and [e["team_id"] for e in board] == [_TEAM]
                and board[0]["solve_count"] == 1
                and board[0]["score"] > 0
                and board[0]["last_solve_at"] is not None
            )
            record(
                "score-and-scoreboard",
                on_board,
                f"projector folded the outbox; {_TEAM} ranked with "
                f"solve_count=1 score={board[0]['score'] if board else 'n/a'}",
            )

            # -- INVARIANT: re-folding is append-only-consistent -------------
            ScoreProjector(db).run_until_drained()
            after = standings()
            res.invariants["single_solve"] = single_solve
            res.invariants["scoreboard_reflects_solve"] = on_board
            res.invariants["append_only_consistent"] = (
                after == board and after and after[0]["solve_count"] == 1
            )
            res.invariants["published_content_addressed_immutable"] = (
                pub_body.get("immutable") is True and content_addressed
            )
            res.invariants["flag_absent_from_contestant_surfaces"] = (
                _FLAG not in sub.text and _FLAG not in dup.text
            )
        finally:
            client.close()

    return res


def _short(h: str | None) -> str:
    return f"{h[:12]}..." if h else "<none>"


def _print_report(res: SimResult) -> None:
    print("Internal-alpha EXIT-scenario simulation")
    print("=" * 60)
    for s in res.steps:
        print(f"  [{'PASS' if s.ok else 'FAIL'}] {s.name:24} {s.detail}")
    print("-" * 60)
    print("  invariants:")
    for name, ok in res.invariants.items():
        print(f"    [{'PASS' if ok else 'FAIL'}] {name}")
    print("-" * 60)
    print(f"RESULT: {'PASS' if res.passed else 'FAIL'}")
    print(
        "NOTE: composite, not one unbroken flow -- the distributed-worker launch "
        "of the published bundle is proven separately by "
        "test_docker_backend_integration (build_challenge unbuilt)."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        default=os.environ.get("CTFGEN_TEST_DATABASE_URL"),
        help="PostgreSQL URL (defaults to $CTFGEN_TEST_DATABASE_URL)",
    )
    args = parser.parse_args(argv)

    if IMPORT_ERROR is not None:
        print(f"SKIP: [api]/[db] extras not importable ({IMPORT_ERROR})")
        return 0
    if not args.database_url:
        print("SKIP: CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)")
        return 0

    res = run_simulation(args.database_url)
    _print_report(res)
    return 0 if res.passed else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
