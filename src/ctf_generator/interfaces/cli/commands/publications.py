"""``ctfgen publication`` -- attach/detach a published version to a competition.

* ``attach`` -> ``POST   /competitions/{id}/publications``                  (Idempotency-Key)
* ``list``   -> ``GET    /competitions/{id}/publications``
* ``detach`` -> ``DELETE /competitions/{id}/publications/{slug}/{version_no}``

``detach`` returns 204 (no body) and its route does not honour an Idempotency-Key,
so none is sent; a successful detach prints a short confirmation.
"""

from __future__ import annotations

import argparse

from .. import output
from ._common import add_global_options, add_idempotency_option, idempotency_key, open_client

AREA = "publication"

_COLUMNS = [
    "competition_id",
    "definition_slug",
    "version_no",
    "initial_value",
    "minimum_value",
    "decay_function",
    "decay",
    "first_blood_enabled",
]


def _attach(args: argparse.Namespace) -> int:
    body: dict[str, object] = {
        "definition_slug": args.definition_slug,
        "version_no": args.version_no,
    }
    for field in (
        "initial_value",
        "minimum_value",
        "decay_function",
        "decay",
        "first_blood_bonus_points",
        "first_blood_bonus_percent",
    ):
        value = getattr(args, field)
        if value is not None:
            body[field] = value
    if args.no_first_blood:
        body["first_blood_enabled"] = False
    with open_client(args) as client:
        created = client.request(
            "POST",
            f"/competitions/{args.competition_id}/publications",
            json=body,
            idempotency_key=idempotency_key(args),
        )
    output.print_resource(created, as_json=args.json)
    return 0


def _list(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        rows = client.list(
            f"/competitions/{args.competition_id}/publications", limit=args.limit
        )
    output.print_rows(rows, _COLUMNS, as_json=args.json)
    return 0


def _detach(args: argparse.Namespace) -> int:
    path = (
        f"/competitions/{args.competition_id}/publications/"
        f"{args.definition_slug}/{args.version_no}"
    )
    with open_client(args) as client:
        client.request("DELETE", path)
    result = {
        "detached": True,
        "competition_id": args.competition_id,
        "definition_slug": args.definition_slug,
        "version_no": args.version_no,
    }
    output.print_resource(result, as_json=args.json)
    return 0


def add_parser(areas: argparse._SubParsersAction) -> None:
    area = areas.add_parser(AREA, help="Attach/detach challenge versions to competitions.")
    verbs = area.add_subparsers(dest="verb", required=True)

    attach = verbs.add_parser("attach", help="Attach a version to a competition.")
    attach.add_argument("--competition-id", dest="competition_id", required=True)
    attach.add_argument("--definition-slug", dest="definition_slug", required=True)
    attach.add_argument("--version-no", dest="version_no", type=int, required=True)
    attach.add_argument("--initial-value", dest="initial_value", type=int, default=None)
    attach.add_argument("--minimum-value", dest="minimum_value", type=int, default=None)
    attach.add_argument("--decay-function", dest="decay_function", default=None)
    attach.add_argument("--decay", type=int, default=None)
    attach.add_argument("--no-first-blood", dest="no_first_blood", action="store_true")
    attach.add_argument(
        "--first-blood-bonus-points", dest="first_blood_bonus_points", type=int, default=None
    )
    attach.add_argument(
        "--first-blood-bonus-percent",
        dest="first_blood_bonus_percent",
        type=float,
        default=None,
    )
    add_idempotency_option(attach)
    add_global_options(attach)
    attach.set_defaults(func=_attach)

    listp = verbs.add_parser("list", help="List a competition's publications.")
    listp.add_argument("--competition-id", dest="competition_id", required=True)
    listp.add_argument("--limit", type=int, default=None)
    add_global_options(listp)
    listp.set_defaults(func=_list)

    detach = verbs.add_parser("detach", help="Detach a publication.")
    detach.add_argument("--competition-id", dest="competition_id", required=True)
    detach.add_argument("--definition-slug", dest="definition_slug", required=True)
    detach.add_argument("--version-no", dest="version_no", type=int, required=True)
    add_global_options(detach)
    detach.set_defaults(func=_detach)
