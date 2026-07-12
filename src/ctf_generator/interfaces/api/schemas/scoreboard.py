"""Scoreboard DTOs + mappers.

Standings come from the read-only scoreboard projection: each entry is a public
team standing (team, score, solve count, last-solve time, rank). The lag DTO is an
operator metrics snapshot of the shared projection outbox. Nothing secret is ever
present in either.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ctf_generator.domain.ledger.models import ProjectionLag


class ScoreboardEntryResponse(BaseModel):
    team_id: str
    score: int
    solve_count: int
    rank: int
    last_solve_at: str | None = None


class ScoreboardLagResponse(BaseModel):
    pending_count: int
    latest_seq: int
    max_as_of_seq: int
    failed_count: int
    oldest_pending_created_at: str | None = None


def entry_to_response(entry: dict[str, Any]) -> dict[str, Any]:
    """Project a stored projection entry onto the public standings DTO, ignoring
    any unexpected extra keys."""
    return {
        "team_id": entry.get("team_id"),
        "score": entry.get("score"),
        "solve_count": entry.get("solve_count"),
        "rank": entry.get("rank"),
        "last_solve_at": entry.get("last_solve_at"),
    }


def entry_sort_key(entry: dict[str, Any]) -> list[Any]:
    """Stable page ordering: ascending rank, then team_id as the deterministic
    tiebreak (ranks can tie)."""
    return [entry.get("rank", 0), entry.get("team_id", "")]


def lag_to_response(lag: ProjectionLag) -> dict[str, Any]:
    return {
        "pending_count": lag.pending_count,
        "latest_seq": lag.latest_seq,
        "max_as_of_seq": lag.max_as_of_seq,
        "failed_count": lag.failed_count,
        "oldest_pending_created_at": (
            lag.oldest_pending_created_at.isoformat()
            if lag.oldest_pending_created_at
            else None
        ),
    }
