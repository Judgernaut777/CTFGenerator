#!/usr/bin/env python3
"""Closed-beta EXIT-criteria simulation (M21, stream B).

A SMOKE-scale, SIMULATED dry-run of the two *mechanizable* closed-beta exit
invariants, executed over a REAL PostgreSQL through the production HTTP edge
(``create_app`` + Starlette ``TestClient``) and the production scoring fold:

  1. AT-MOST-ONE-SOLVE UNDER CONCURRENCY (the key correctness item, exit
     criterion "at-most-one solve per (team, challenge, competition) held under
     real submissions"). ``--concurrency`` submitters POST the SAME correct flag
     for the SAME (competition, team, challenge) SIMULTANEOUSLY (released off a
     ``threading.Barrier``, each with its OWN ``TestClient`` so httpx is never
     shared). We assert: every POST is accepted (correct), EXACTLY ONE reports
     ``first_solve`` true, and the ledger holds EXACTLY ONE solve row + EXACTLY
     ONE ``solve`` score event for that pair -- no double-count.

  2. SCOREBOARD RECONSTRUCTED FROM PERSISTED SCORE EVENTS == LIVE STATE (exit
     criterion "scoreboard reconstructed from persisted score events and matched
     live state"). After a mixed set of solves is folded into the live
     projection cache by the real ``ScoreProjector`` (via the 0008 transactional
     outbox), we INDEPENDENTLY refold the append-only ``score_events`` for the
     competition through the same pure ``compute_scoreboard`` path and assert the
     reconstruction is byte-equal to the persisted live projection.

This is NOT the production-scale beta run. Per charter §5, 25-team / 20-challenge
production scale, >=99% launch success, sustained <3s/<500ms at scale, a real
TLS reverse proxy, and real external organizers/contestants are UNVERIFIED here;
see ``docs/validation/closed-beta-report.md``. This sim proves the CORRECTNESS
invariants at smoke scale on this single host, re-runnably.

Run (needs the ``[api]`` + ``[db]`` extras and a running PostgreSQL)::

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python scripts/beta_sim.py --teams 3 --challenges 2 \\
        --concurrency 6

It creates a throwaway database, migrates it to head, seeds a competition +
teams + published+attached challenges, runs the two checks, prints a PASS/FAIL
summary, and drops the database.
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field

import sqlalchemy as sa
from alembic import command
from alembic.config import Config as AlembicConfig
from fastapi.testclient import TestClient
from sqlalchemy.engine import make_url

from ctf_generator.application.scoring.projector import (
    ScoreProjector,
    _challenge_key,
    _solve_event,
)
from ctf_generator.domain.authoring.models import ChallengePublication
from ctf_generator.domain.challenges.models import (
    ChallengeScoringConfig,
    FirstBloodBonusConfig,
    SolveEvent,
)
from ctf_generator.domain.scoring.scoring_engine import get_scoring_engine
from ctf_generator.infrastructure.database.challenge_publication_repository import (
    SqlAlchemyChallengePublicationRepository,
)
from ctf_generator.infrastructure.database.competition_repository import (
    SqlAlchemyCompetitionRepository,
)
from ctf_generator.infrastructure.database.config import DatabaseConfig
from ctf_generator.infrastructure.database.score_ledger_repository import (
    SqlAlchemyScoreLedger,
)
from ctf_generator.infrastructure.database.score_projection_repository import (
    SqlAlchemyScoreboardProjectionRepository,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.solve_repository import (
    SqlAlchemySolveRepository,
)
from ctf_generator.infrastructure.database.submission_repository import (
    SqlAlchemyLedgerSubmissionRepository,
)
from ctf_generator.interfaces.api.app import create_app
from ctf_generator.interfaces.api.deps import StubAuthenticator, principal_for
from ctf_generator.interfaces.api.settings import ApiSettings
from ctf_generator.scoreboard import compute_scoreboard

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ADMIN = "admintoken"  # noqa: S105 - sim fixture token, not a real secret
_CID = "beta-sim-ctf"
# ScoreProjector's default engine -- the reconstruction MUST fold with the same
# engine as the live projection cache for parity to be meaningful.
_ENGINE = "dynamic_decay"


def _team_token(i: int) -> str:
    return f"team{i}token"


def _team_name(i: int) -> str:
    return f"Team{i}"


def _slug(i: int) -> str:
    return f"chal-{i}"


def _flag(slug: str) -> str:
    return f"CTF{{flag-{slug}}}"


@dataclass
class SingleSolveResult:
    """The MEASURED outcome of the concurrent single-solve check."""

    concurrency: int
    accepted: int = 0
    first_solves: int = 0
    http_errors: list[str] = field(default_factory=list)
    solves_in_db: int = -1
    solve_events_in_db: int = -1
    submissions_in_db: int = -1

    @property
    def ok(self) -> bool:
        return (
            not self.http_errors
            and self.accepted == self.concurrency
            and self.first_solves == 1
            and self.solves_in_db == 1
            and self.solve_events_in_db == 1
            and self.submissions_in_db == self.concurrency
        )


@dataclass
class ReconResult:
    """The MEASURED outcome of the scoreboard-reconstruction parity check."""

    live_rows: int = -1
    reconstructed_rows: int = -1
    live_as_of_seq: int = -1
    parity: bool = False
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.parity and self.live_rows >= 0


@dataclass
class BetaSimResult:
    single_solve: SingleSolveResult
    recon: ReconResult

    @property
    def ok(self) -> bool:
        return self.single_solve.ok and self.recon.ok


@contextmanager
def _isolated_database(base_url: str):
    """Create a throwaway database, yield its DSN, drop it on exit."""
    base = make_url(base_url)
    name = f"ctfgen_beta_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _alembic_config(url: str) -> AlembicConfig:
    cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    cfg.set_main_option("sqlalchemy.url", str(url))
    return cfg


def _expect(response, code: int, what: str) -> None:
    if response.status_code != code:
        raise RuntimeError(
            f"seed step {what!r} expected {code}, got {response.status_code}: "
            f"{response.text[:200]}"
        )


def _authenticator(teams: int) -> StubAuthenticator:
    tokens = {
        _ADMIN: principal_for("admin-user", {"admin"}, system_roles={"admin"}),
    }
    for i in range(teams):
        tokens[_team_token(i)] = principal_for(
            f"player-{i}",
            {"player"},
            team=_team_name(i),
            memberships={_CID: ("player", _team_name(i))},
        )
    return StubAuthenticator(tokens)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _seed(client: TestClient, db: Database, teams: int, challenges: int) -> None:
    """One competition + ``teams`` teams + ``challenges`` published+attached
    challenges (each with a distinct flag). Mirrors the loadtest / submissions
    integration seed."""
    _expect(
        client.post(
            "/api/v1/competitions",
            headers=_auth(_ADMIN),
            json={
                "competition_id": _CID,
                "name": "Beta Sim CTF",
                "start_time": "2026-06-01T09:00:00Z",
                "end_time": "2026-06-03T09:00:00Z",
                "scoring_start_time": "2026-06-01T09:30:00Z",
                "freeze_time": "2026-06-02T09:00:00Z",
            },
        ),
        201,
        "create competition",
    )
    for i in range(teams):
        _expect(
            client.post(
                "/api/v1/teams",
                headers=_auth(_ADMIN),
                json={"competition_id": _CID, "name": _team_name(i)},
            ),
            201,
            f"create team {i}",
        )
    for i in range(challenges):
        slug = _slug(i)
        _expect(
            client.post(
                "/api/v1/challenge-definitions",
                headers=_auth(_ADMIN),
                json={"family": "web", "slug": slug, "title": f"Challenge {i}"},
            ),
            201,
            f"create definition {slug}",
        )
        _expect(
            client.post(
                "/api/v1/challenge-versions",
                headers=_auth(_ADMIN),
                json={
                    "definition_slug": slug,
                    "seed": f"seed-{i}",
                    "family_version": "1.0.0",
                    "spec": {"title": f"Challenge {i}", "flag": _flag(slug)},
                },
            ),
            201,
            f"create version {slug}",
        )
        _expect(
            client.post(
                f"/api/v1/challenge-versions/{slug}/1/publish", headers=_auth(_ADMIN)
            ),
            200,
            f"publish {slug}",
        )
    # No publication API endpoint -- attach directly via the repo (mirrors the
    # existing submissions/loadtest integration path).
    with db.session_scope() as session:
        repo = SqlAlchemyChallengePublicationRepository(session)
        for i in range(challenges):
            repo.add(
                ChallengePublication(
                    competition_id=_CID, definition_slug=_slug(i), version_no=1
                )
            )


def _submit(app, token: str, team: str, slug: str) -> tuple[int, dict | str]:
    """One HTTP submission with its OWN TestClient. Returns (status, body)."""
    client = TestClient(app)
    r = client.post(
        f"/api/v1/competitions/{_CID}/submissions",
        headers=_auth(token),
        json={
            "team": team,
            "definition_slug": slug,
            "version_no": 1,
            "answer": _flag(slug),
        },
    )
    try:
        return r.status_code, r.json()
    except Exception:  # pragma: no cover - non-JSON error body
        return r.status_code, r.text[:200]


def _run_single_solve(app, db, *, team_index: int, slug: str, concurrency: int) -> SingleSolveResult:
    """Fire ``concurrency`` SIMULTANEOUS correct submissions of the same flag for
    ONE (competition, team, challenge) and assert at-most-one solve."""
    result = SingleSolveResult(concurrency=concurrency)
    token = _team_token(team_index)
    team = _team_name(team_index)
    barrier = threading.Barrier(concurrency)
    lock = threading.Lock()

    def worker() -> None:
        # Release all workers at the same instant for a genuine race.
        barrier.wait(timeout=30)
        status, body = _submit(app, token, team, slug)
        with lock:
            if status != 201 or not isinstance(body, dict):
                result.http_errors.append(f"{status}: {body}")
                return
            if body.get("correct"):
                result.accepted += 1
            if body.get("first_solve"):
                result.first_solves += 1

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(worker) for _ in range(concurrency)]
        for f in as_completed(futs):
            f.result()  # re-raise a worker crash (e.g. barrier timeout)

    # Ground truth from the ledger for exactly this (team, challenge) pair,
    # read back through the production repositories (not raw SQL).
    with db.session_scope() as session:
        solve = SqlAlchemySolveRepository(session).get_for_challenge(
            _CID, team, slug, 1
        )
        result.solves_in_db = 1 if solve is not None else 0
        events = SqlAlchemyScoreLedger(session).list_for_competition(_CID)
        result.solve_events_in_db = sum(
            1
            for e in events
            if e.type == "solve"
            and e.team_name == team
            and e.definition_slug == slug
        )
        subs = SqlAlchemyLedgerSubmissionRepository(session).list_for_team(
            _CID, team
        )
        result.submissions_in_db = sum(
            1 for s in subs if s.definition_slug == slug
        )
    return result


def _spread_solves(app, *, teams: int, challenges: int, skip: tuple[int, str]) -> None:
    """Give the scoreboard non-trivial, multi-team, multi-challenge shape so the
    reconstruction parity check is not vacuous. Sequential, one correct
    submission each; ``skip`` (the pair used by the concurrency check) is left
    alone (it is already solved)."""
    for ti in range(teams):
        for ci in range(challenges):
            slug = _slug(ci)
            if (ti, slug) == skip:
                continue
            # Deterministic sparsity: team ti solves challenge ci iff (ti+ci) is
            # even -> a mix of ranks and per-challenge solver counts.
            if (ti + ci) % 2 != 0:
                continue
            status, body = _submit(app, _team_token(ti), _team_name(ti), slug)
            if status != 201 or not (isinstance(body, dict) and body.get("correct")):
                raise RuntimeError(f"spread solve {ti},{slug} failed: {status} {body}")


def _reconstruct_from_events(db: Database) -> dict:
    """Independently refold the persisted, append-only ``score_events`` for the
    competition through the SAME pure ``compute_scoreboard`` path the projector
    uses, and return ``snapshot.to_mapping()``. This is the from-scratch
    reconstruction that the live projection cache must match."""
    with db.session_scope() as session:
        config = SqlAlchemyCompetitionRepository(session).get(_CID)
        events = SqlAlchemyScoreLedger(session).list_for_competition(_CID)
        publications = SqlAlchemyChallengePublicationRepository(
            session
        ).list_for_competition(_CID)

    solves: list[SolveEvent] = [
        _solve_event(e) for e in events if e.type == "solve"
    ]
    challenges: dict[str, ChallengeScoringConfig] = {}
    for pub in publications:
        key = _challenge_key(pub.definition_slug, pub.version_no)
        challenges[key] = ChallengeScoringConfig(
            challenge_id=key,
            initial_value=pub.initial_value,
            minimum_value=pub.minimum_value,
            decay_function=pub.decay_function,
            decay=pub.decay,
            first_blood_bonus=FirstBloodBonusConfig(
                enabled=pub.first_blood_enabled,
                bonus_points=pub.first_blood_bonus_points,
                bonus_percent=pub.first_blood_bonus_percent,
            ),
        )
    snapshot = compute_scoreboard(
        solves, challenges, config, engine=get_scoring_engine(_ENGINE)
    )
    return snapshot.to_mapping()


def _run_reconstruction(app, db, *, teams: int, challenges: int, skip: tuple[int, str]) -> ReconResult:
    result = ReconResult()
    _spread_solves(app, teams=teams, challenges=challenges, skip=skip)
    # Fold the append-only events into the live projection cache exactly as
    # production does (drains the 0008 transactional outbox).
    ScoreProjector(db, engine_name=_ENGINE).run_until_drained()

    with db.session_scope() as session:
        record = SqlAlchemyScoreboardProjectionRepository(session).get(_CID)
    if record is None:
        result.detail = "no live projection record found for the competition"
        return result
    live = record.entries
    result.live_as_of_seq = record.as_of_seq
    reconstructed = _reconstruct_from_events(db)

    live_rows = live.get("entries") if isinstance(live, dict) else None
    recon_rows = (
        reconstructed.get("entries") if isinstance(reconstructed, dict) else None
    )
    result.live_rows = len(live_rows) if isinstance(live_rows, list) else -1
    result.reconstructed_rows = len(recon_rows) if isinstance(recon_rows, list) else -1
    result.parity = live == reconstructed
    if not result.parity:
        result.detail = "live projection cache != from-scratch event refold"
    return result


def run_beta_sim(
    *,
    database_url: str,
    teams: int = 3,
    challenges: int = 2,
    concurrency: int = 6,
) -> BetaSimResult:
    if teams < 1 or challenges < 1:
        raise ValueError("teams and challenges must both be >= 1")
    if concurrency < 2:
        raise ValueError("concurrency must be >= 2 to exercise a race")
    # The concurrency check targets Team0 + chal-0.
    target = (0, _slug(0))
    with _isolated_database(database_url) as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            app = create_app(
                ApiSettings(), database=db, authenticator=_authenticator(teams)
            )
            _seed(TestClient(app), db, teams, challenges)
            single = _run_single_solve(
                app, db, team_index=0, slug=_slug(0), concurrency=concurrency
            )
            recon = _run_reconstruction(
                app, db, teams=teams, challenges=challenges, skip=target
            )
        finally:
            db.dispose()
    return BetaSimResult(single_solve=single, recon=recon)


def print_report(result: BetaSimResult) -> None:
    p = sys.stdout.write
    s = result.single_solve
    r = result.recon
    p("\n=== CTFGenerator closed-beta EXIT simulation (smoke scale, real PG) ===\n\n")

    p("[1] AT-MOST-ONE-SOLVE UNDER CONCURRENCY (exit: at-most-one solve/team/challenge)\n")
    p(
        f"    {s.concurrency} simultaneous correct submissions of the same flag\n"
        f"    accepted(correct)={s.accepted}/{s.concurrency}  "
        f"first_solve=true count={s.first_solves} (want 1)\n"
        f"    ledger: solves={s.solves_in_db} (want 1)  "
        f"solve-events={s.solve_events_in_db} (want 1)  "
        f"submissions={s.submissions_in_db} (want {s.concurrency})\n"
    )
    if s.http_errors:
        p(f"    HTTP errors: {s.http_errors[:5]}\n")
    p(f"    -> {'PASS' if s.ok else 'FAIL'}\n\n")

    p("[2] SCOREBOARD RECONSTRUCTED FROM PERSISTED SCORE EVENTS == LIVE STATE\n")
    p(
        f"    live projection rows={r.live_rows}  reconstructed rows={r.reconstructed_rows}  "
        f"as_of_seq={r.live_as_of_seq}\n"
        f"    byte-equal(live cache == from-scratch event refold)={r.parity}\n"
    )
    if r.detail:
        p(f"    detail: {r.detail}\n")
    p(f"    -> {'PASS' if r.ok else 'FAIL'}\n\n")

    p(f"OVERALL: {'PASS' if result.ok else 'FAIL'}\n")
    p(
        "SCOPE (charter §5): smoke scale on one host. Production 25-team/20-challenge\n"
        "scale, >=99% launch success, sustained <3s/<500ms at scale, a real TLS\n"
        "reverse proxy, and real external organizers/contestants are UNVERIFIED here\n"
        "(see docs/validation/closed-beta-report.md). This proves the CORRECTNESS\n"
        "invariants, not the deployment-scale sign-off (M21/M22).\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        default=os.environ.get("CTFGEN_TEST_DATABASE_URL"),
        help="PostgreSQL DSN (default: $CTFGEN_TEST_DATABASE_URL). A throwaway DB "
        "is created from it, migrated, seeded, exercised, then dropped.",
    )
    parser.add_argument("--teams", type=int, default=3)
    parser.add_argument("--challenges", type=int, default=2)
    parser.add_argument(
        "--concurrency",
        type=int,
        default=6,
        help="Simultaneous correct submitters of the SAME flag/team/challenge.",
    )
    args = parser.parse_args(argv)

    if not args.database_url:
        parser.error(
            "no database URL: set CTFGEN_TEST_DATABASE_URL or pass --database-url "
            "(needs a running PostgreSQL, e.g. the ctfgen_pg container)."
        )

    result = run_beta_sim(
        database_url=args.database_url,
        teams=args.teams,
        challenges=args.challenges,
        concurrency=args.concurrency,
    )
    print_report(result)
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
