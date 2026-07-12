"""``ctfgen competition`` -- competitions + the per-competition scoreboard.

Routes (all under ``/api/v1``):

* ``create``     -> ``POST   /competitions``                    (Idempotency-Key)
* ``list``       -> ``GET    /competitions``
* ``get``        -> ``GET    /competitions/{id}``
* ``update``     -> ``PATCH  /competitions/{id}``  (If-Match from a prior GET)
* ``scoreboard`` -> ``GET    /competitions/{id}/scoreboard``

``scoreboard`` lives HERE as a verb (not its own area) because ``scoreboard`` is
an existing LEGACY generator command name -- a top-level ``scoreboard`` area would
shadow it in the entry dispatcher. It is inherently per-competition anyway.
"""

from __future__ import annotations

import argparse

from .. import output
from ._common import add_global_options, add_idempotency_option, idempotency_key, open_client

AREA = "competition"

_COLUMNS = [
    "competition_id",
    "name",
    "start_time",
    "end_time",
    "scoring_start_time",
    "freeze_time",
]
_SCOREBOARD_COLUMNS = ["rank", "team_id", "score", "solve_count", "last_solve_at"]


def _create(args: argparse.Namespace) -> int:
    body = {
        "competition_id": args.competition_id,
        "name": args.name,
        "start_time": args.start_time,
        "end_time": args.end_time,
    }
    if args.scoring_start_time is not None:
        body["scoring_start_time"] = args.scoring_start_time
    if args.freeze_time is not None:
        body["freeze_time"] = args.freeze_time
    with open_client(args) as client:
        created = client.request(
            "POST", "/competitions", json=body, idempotency_key=idempotency_key(args)
        )
    output.print_resource(created, as_json=args.json)
    return 0


def _list(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        rows = client.list("/competitions", limit=args.limit)
    output.print_rows(rows, _COLUMNS, as_json=args.json)
    return 0


def _get(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        body = client.request("GET", f"/competitions/{args.competition_id}")
    output.print_resource(body, as_json=args.json)
    return 0


def _update(args: argparse.Namespace) -> int:
    changes: dict[str, object] = {}
    for field in ("name", "start_time", "end_time", "scoring_start_time", "freeze_time"):
        value = getattr(args, field)
        if value is not None:
            changes[field] = value
    if not changes:
        from ..errors import CliError

        raise CliError("nothing to update: pass at least one field to change")
    with open_client(args) as client:
        # Optimistic concurrency: read the current ETag, then send it as If-Match
        # so the PATCH fails (412) rather than clobbering a concurrent edit.
        _body, etag = client.request(
            "GET", f"/competitions/{args.competition_id}", return_etag=True
        )
        updated = client.request(
            "PATCH",
            f"/competitions/{args.competition_id}",
            json=changes,
            headers={"If-Match": etag} if etag else None,
        )
    output.print_resource(updated, as_json=args.json)
    return 0


def _scoreboard(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        rows = client.list(
            f"/competitions/{args.competition_id}/scoreboard", limit=args.limit
        )
    output.print_rows(rows, _SCOREBOARD_COLUMNS, as_json=args.json)
    return 0


def add_parser(areas: argparse._SubParsersAction) -> None:
    area = areas.add_parser(AREA, help="Manage competitions and view scoreboards.")
    verbs = area.add_subparsers(dest="verb", required=True)

    create = verbs.add_parser("create", help="Create a competition.")
    create.add_argument("competition_id", help="Stable business slug")
    create.add_argument("--name", required=True)
    create.add_argument("--start-time", dest="start_time", required=True, help="ISO-8601")
    create.add_argument("--end-time", dest="end_time", required=True, help="ISO-8601")
    create.add_argument("--scoring-start-time", dest="scoring_start_time", default=None)
    create.add_argument("--freeze-time", dest="freeze_time", default=None)
    add_idempotency_option(create)
    add_global_options(create)
    create.set_defaults(func=_create)

    listp = verbs.add_parser("list", help="List competitions you can read.")
    listp.add_argument("--limit", type=int, default=None)
    add_global_options(listp)
    listp.set_defaults(func=_list)

    get = verbs.add_parser("get", help="Show one competition.")
    get.add_argument("competition_id")
    add_global_options(get)
    get.set_defaults(func=_get)

    update = verbs.add_parser("update", help="Update a competition (optimistic concurrency).")
    update.add_argument("competition_id")
    update.add_argument("--name", default=None)
    update.add_argument("--start-time", dest="start_time", default=None)
    update.add_argument("--end-time", dest="end_time", default=None)
    update.add_argument("--scoring-start-time", dest="scoring_start_time", default=None)
    update.add_argument("--freeze-time", dest="freeze_time", default=None)
    add_global_options(update)
    update.set_defaults(func=_update)

    board = verbs.add_parser("scoreboard", help="Show a competition scoreboard.")
    board.add_argument("competition_id")
    board.add_argument("--limit", type=int, default=None)
    add_global_options(board)
    board.set_defaults(func=_scoreboard)
