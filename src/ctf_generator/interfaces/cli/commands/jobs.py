"""``ctfgen job`` -- ops observability + control (admin / support scoped).

* ``list``   -> ``GET  /jobs/dead-letter``   (the only list route is the dead-letter queue)
* ``get``    -> ``GET  /jobs/{job_id}``
* ``cancel`` -> ``POST /jobs/{job_id}/cancel`` (Idempotency-Key)
* ``retry``  -> ``POST /jobs/{job_id}/retry``  (Idempotency-Key)

``list`` maps to the dead-letter queue because that is the only job-listing route
the API exposes; the job DTO never surfaces raw payload / result / error detail
(only type, status, attempt accounting, and a structured ``error_class``).
"""

from __future__ import annotations

import argparse

from .. import output
from ._common import add_global_options, add_idempotency_option, idempotency_key, open_client

AREA = "job"

_COLUMNS = [
    "job_id",
    "job_type",
    "status",
    "attempt_count",
    "max_attempts",
    "available_at",
    "error_class",
]


def _list(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        rows = client.list("/jobs/dead-letter", limit=args.limit)
    output.print_rows(rows, _COLUMNS, as_json=args.json)
    return 0


def _get(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        body = client.request("GET", f"/jobs/{args.job_id}")
    output.print_resource(body, as_json=args.json)
    return 0


def _action(args: argparse.Namespace, action: str) -> int:
    with open_client(args) as client:
        result = client.request(
            "POST",
            f"/jobs/{args.job_id}/{action}",
            idempotency_key=idempotency_key(args),
        )
    output.print_resource(result, as_json=args.json)
    return 0


def add_parser(areas: argparse._SubParsersAction) -> None:
    area = areas.add_parser(AREA, help="Inspect and control background jobs.")
    verbs = area.add_subparsers(dest="verb", required=True)

    listp = verbs.add_parser("list", help="List dead-letter jobs.")
    listp.add_argument("--limit", type=int, default=None)
    add_global_options(listp)
    listp.set_defaults(func=_list)

    get = verbs.add_parser("get", help="Show one job.")
    get.add_argument("job_id")
    add_global_options(get)
    get.set_defaults(func=_get)

    cancel = verbs.add_parser("cancel", help="Request cancellation of a job.")
    cancel.add_argument("job_id")
    add_idempotency_option(cancel)
    add_global_options(cancel)
    cancel.set_defaults(func=lambda a: _action(a, "cancel"))

    retry = verbs.add_parser("retry", help="Requeue a dead-letter job.")
    retry.add_argument("job_id")
    add_idempotency_option(retry)
    add_global_options(retry)
    retry.set_defaults(func=lambda a: _action(a, "retry"))
