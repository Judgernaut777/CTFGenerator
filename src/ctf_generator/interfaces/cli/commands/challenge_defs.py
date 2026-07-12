"""``ctfgen challenge-def`` -- challenge definitions (stable authoring identity).

* ``create`` -> ``POST  /challenge-definitions``          (Idempotency-Key)
* ``list``   -> ``GET   /challenge-definitions``
* ``get``    -> ``GET   /challenge-definitions/{slug}``
* ``update`` -> ``PATCH /challenge-definitions/{slug}``   (If-Match; only title)
"""

from __future__ import annotations

import argparse

from .. import output
from ._common import add_global_options, add_idempotency_option, idempotency_key, open_client

AREA = "challenge-def"

_COLUMNS = ["family", "slug", "title"]


def _create(args: argparse.Namespace) -> int:
    body = {"family": args.family, "slug": args.slug, "title": args.title}
    with open_client(args) as client:
        created = client.request(
            "POST",
            "/challenge-definitions",
            json=body,
            idempotency_key=idempotency_key(args),
        )
    output.print_resource(created, as_json=args.json)
    return 0


def _list(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        rows = client.list("/challenge-definitions", limit=args.limit)
    output.print_rows(rows, _COLUMNS, as_json=args.json)
    return 0


def _get(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        body = client.request("GET", f"/challenge-definitions/{args.slug}")
    output.print_resource(body, as_json=args.json)
    return 0


def _update(args: argparse.Namespace) -> int:
    if args.title is None:
        from ..errors import CliError

        raise CliError("nothing to update: pass --title")
    with open_client(args) as client:
        _body, etag = client.request(
            "GET", f"/challenge-definitions/{args.slug}", return_etag=True
        )
        updated = client.request(
            "PATCH",
            f"/challenge-definitions/{args.slug}",
            json={"title": args.title},
            headers={"If-Match": etag} if etag else None,
        )
    output.print_resource(updated, as_json=args.json)
    return 0


def add_parser(areas: argparse._SubParsersAction) -> None:
    area = areas.add_parser(AREA, help="Manage challenge definitions.")
    verbs = area.add_subparsers(dest="verb", required=True)

    create = verbs.add_parser("create", help="Create a challenge definition.")
    create.add_argument("--family", required=True)
    create.add_argument("--slug", required=True)
    create.add_argument("--title", required=True)
    add_idempotency_option(create)
    add_global_options(create)
    create.set_defaults(func=_create)

    listp = verbs.add_parser("list", help="List challenge definitions.")
    listp.add_argument("--limit", type=int, default=None)
    add_global_options(listp)
    listp.set_defaults(func=_list)

    get = verbs.add_parser("get", help="Show one challenge definition.")
    get.add_argument("slug")
    add_global_options(get)
    get.set_defaults(func=_get)

    update = verbs.add_parser("update", help="Update a definition's title.")
    update.add_argument("slug")
    update.add_argument("--title", default=None)
    add_global_options(update)
    update.set_defaults(func=_update)
