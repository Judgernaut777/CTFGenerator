"""``ctfgen user`` -- global user profiles (email + display name).

* ``create`` -> ``POST /users``           (Idempotency-Key)
* ``list``   -> ``GET  /users``
* ``get``    -> ``GET  /users/{email}``

The create ``role`` is validated at the API boundary but NOT persisted on the
global profile (competition role/team placement is a per-competition membership);
the response echoes only ``email`` + ``display_name``.
"""

from __future__ import annotations

import argparse

from .. import output
from ._common import add_global_options, add_idempotency_option, idempotency_key, open_client

AREA = "user"

_COLUMNS = ["email", "display_name"]


def _create(args: argparse.Namespace) -> int:
    body = {
        "email": args.email,
        "display_name": args.display_name,
        "role": args.role,
    }
    with open_client(args) as client:
        created = client.request(
            "POST", "/users", json=body, idempotency_key=idempotency_key(args)
        )
    output.print_resource(created, as_json=args.json)
    return 0


def _list(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        rows = client.list("/users", limit=args.limit)
    output.print_rows(rows, _COLUMNS, as_json=args.json)
    return 0


def _get(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        body = client.request("GET", f"/users/{args.email}")
    output.print_resource(body, as_json=args.json)
    return 0


def add_parser(areas: argparse._SubParsersAction) -> None:
    area = areas.add_parser(AREA, help="Manage user profiles.")
    verbs = area.add_subparsers(dest="verb", required=True)

    create = verbs.add_parser("create", help="Register a user.")
    create.add_argument("--email", required=True)
    create.add_argument("--display-name", dest="display_name", required=True)
    create.add_argument(
        "--role", required=True, help="Requested competition role (validated server-side)"
    )
    add_idempotency_option(create)
    add_global_options(create)
    create.set_defaults(func=_create)

    listp = verbs.add_parser("list", help="List users.")
    listp.add_argument("--limit", type=int, default=None)
    add_global_options(listp)
    listp.set_defaults(func=_list)

    get = verbs.add_parser("get", help="Show one user by email.")
    get.add_argument("email")
    add_global_options(get)
    get.set_defaults(func=_get)
