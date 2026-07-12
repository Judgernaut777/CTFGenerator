"""``ctfgen instance`` -- the operator view over the instance lifecycle.

* ``list``    -> ``GET  /instances``  (or ``/competitions/{id}/instances`` with ``--competition-id``)
* ``get``     -> ``GET  /instances/{instance_id}``
* ``request`` -> ``POST /instances``                    (Idempotency-Key)
* ``stop``    -> ``POST /instances/{instance_id}/stop``   (Idempotency-Key)
* ``reset``   -> ``POST /instances/{instance_id}/reset``  (Idempotency-Key)
* ``delete``  -> ``POST /instances/{instance_id}/delete`` (Idempotency-Key; note: POST, not HTTP DELETE)

SECRET BOUNDARY: an instance carries credentials / runtime handles / an
``instance_seed`` in the store, but the API DTO already omits ALL of them. The
table here renders an explicit whitelist of PUBLIC operational columns only --
never a seed, ``secret_ref``, ``external_ref``, or internal endpoint.
"""

from __future__ import annotations

import argparse

from .. import output
from ._common import add_global_options, add_idempotency_option, idempotency_key, open_client

AREA = "instance"

# PUBLIC operational columns ONLY (no instance_seed / secret_ref / external_ref).
_COLUMNS = [
    "instance_id",
    "competition_id",
    "team",
    "definition_slug",
    "version_no",
    "state",
    "desired_state",
    "assigned_worker",
    "expires_at",
]


def _list(args: argparse.Namespace) -> int:
    path = (
        f"/competitions/{args.competition_id}/instances"
        if args.competition_id
        else "/instances"
    )
    with open_client(args) as client:
        rows = client.list(path, limit=args.limit)
    output.print_rows(rows, _COLUMNS, as_json=args.json)
    return 0


def _get(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        body = client.request("GET", f"/instances/{args.instance_id}")
    output.print_resource(body, as_json=args.json)
    return 0


def _request(args: argparse.Namespace) -> int:
    body: dict[str, object] = {
        "competition_id": args.competition_id,
        "team": args.team,
        "definition_slug": args.definition_slug,
        "version_no": args.version_no,
        "architecture": args.architecture,
        "ttl_seconds": args.ttl_seconds,
        "worker_units": args.worker_units,
        "platform_capacity": args.platform_capacity,
    }
    if args.capability:
        body["required_capabilities"] = list(args.capability)
    with open_client(args) as client:
        created = client.request(
            "POST", "/instances", json=body, idempotency_key=idempotency_key(args)
        )
    output.print_resource(created, as_json=args.json)
    return 0


def _action(args: argparse.Namespace, action: str) -> int:
    body = {"ttl_seconds": args.ttl_seconds} if action == "reset" else None
    with open_client(args) as client:
        result = client.request(
            "POST",
            f"/instances/{args.instance_id}/{action}",
            json=body,
            idempotency_key=idempotency_key(args),
        )
    output.print_resource(result, as_json=args.json)
    return 0


def add_parser(areas: argparse._SubParsersAction) -> None:
    area = areas.add_parser(AREA, help="Operate challenge instances.")
    verbs = area.add_subparsers(dest="verb", required=True)

    listp = verbs.add_parser("list", help="List instances (optionally one competition).")
    listp.add_argument("--competition-id", dest="competition_id", default=None)
    listp.add_argument("--limit", type=int, default=None)
    add_global_options(listp)
    listp.set_defaults(func=_list)

    get = verbs.add_parser("get", help="Show one instance.")
    get.add_argument("instance_id")
    add_global_options(get)
    get.set_defaults(func=_get)

    request = verbs.add_parser("request", help="Request a new instance for a team.")
    request.add_argument("--competition-id", dest="competition_id", required=True)
    request.add_argument("--team", required=True)
    request.add_argument("--definition-slug", dest="definition_slug", required=True)
    request.add_argument("--version-no", dest="version_no", type=int, required=True)
    request.add_argument("--architecture", default="x86_64")
    request.add_argument("--capability", action="append", default=None, help="Repeatable")
    request.add_argument("--ttl-seconds", dest="ttl_seconds", type=int, default=3600)
    request.add_argument("--worker-units", dest="worker_units", type=int, default=1)
    request.add_argument(
        "--platform-capacity", dest="platform_capacity", type=int, default=1
    )
    add_idempotency_option(request)
    add_global_options(request)
    request.set_defaults(func=_request)

    stop = verbs.add_parser("stop", help="Request an instance stop.")
    stop.add_argument("instance_id")
    add_idempotency_option(stop)
    add_global_options(stop)
    stop.set_defaults(func=lambda a: _action(a, "stop"))

    reset = verbs.add_parser("reset", help="Request an instance reset.")
    reset.add_argument("instance_id")
    reset.add_argument("--ttl-seconds", dest="ttl_seconds", type=int, default=3600)
    add_idempotency_option(reset)
    add_global_options(reset)
    reset.set_defaults(func=lambda a: _action(a, "reset"))

    delete = verbs.add_parser("delete", help="Request an instance delete.")
    delete.add_argument("instance_id")
    add_idempotency_option(delete)
    add_global_options(delete)
    delete.set_defaults(func=lambda a: _action(a, "delete"))
