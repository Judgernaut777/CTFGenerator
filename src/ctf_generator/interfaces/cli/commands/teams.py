"""``ctfgen team`` -- competition teams.

* ``create`` -> ``POST /teams``                         (Idempotency-Key)
* ``list``   -> ``GET  /teams?competition_id=...``      (competition_id required)
* ``get``    -> ``GET  /teams/{competition_id}/{name}``

GAP -- team membership: there is NO API route to grant/list a user's team
membership (the ``users`` and ``teams`` routers expose no membership/grant
endpoint; a ``Membership`` is created out of band today). So ``member add`` /
``member list`` are intentionally NOT implemented -- inventing a route would be
wrong. See the M13 return notes.
"""

from __future__ import annotations

import argparse

from .. import output
from ._common import add_global_options, add_idempotency_option, idempotency_key, open_client

AREA = "team"

_COLUMNS = ["competition_id", "name"]


def _create(args: argparse.Namespace) -> int:
    body = {"competition_id": args.competition_id, "name": args.name}
    with open_client(args) as client:
        created = client.request(
            "POST", "/teams", json=body, idempotency_key=idempotency_key(args)
        )
    output.print_resource(created, as_json=args.json)
    return 0


def _list(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        rows = client.list(
            "/teams", params={"competition_id": args.competition_id}, limit=args.limit
        )
    output.print_rows(rows, _COLUMNS, as_json=args.json)
    return 0


def _get(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        body = client.request("GET", f"/teams/{args.competition_id}/{args.name}")
    output.print_resource(body, as_json=args.json)
    return 0


def add_parser(areas: argparse._SubParsersAction) -> None:
    area = areas.add_parser(AREA, help="Manage competition teams.")
    verbs = area.add_subparsers(dest="verb", required=True)

    create = verbs.add_parser("create", help="Create a team.")
    create.add_argument("--competition-id", dest="competition_id", required=True)
    create.add_argument("--name", required=True)
    add_idempotency_option(create)
    add_global_options(create)
    create.set_defaults(func=_create)

    listp = verbs.add_parser("list", help="List a competition's teams.")
    listp.add_argument("--competition-id", dest="competition_id", required=True)
    listp.add_argument("--limit", type=int, default=None)
    add_global_options(listp)
    listp.set_defaults(func=_list)

    get = verbs.add_parser("get", help="Show one team.")
    get.add_argument("--competition-id", dest="competition_id", required=True)
    get.add_argument("--name", required=True)
    add_global_options(get)
    get.set_defaults(func=_get)
