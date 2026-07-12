"""``ctfgen build`` -- challenge build artifacts + build triggering.

* ``trigger`` -> ``POST /challenge-definitions/{slug}/builds``   (Idempotency-Key; returns a Job)
* ``list``    -> ``GET  /challenge-definitions/{slug}/builds?version_no=...``  (version_no required)
* ``get``     -> ``GET  /builds/{build_id}``

``trigger`` enqueues a build job and returns the JOB (202 Accepted), not the
build itself; the build appears in ``build list`` once the worker produces it.
"""

from __future__ import annotations

import argparse

from .. import output
from ._common import add_global_options, add_idempotency_option, idempotency_key, open_client

AREA = "build"

_COLUMNS = [
    "build_sha256",
    "definition_slug",
    "version_no",
    "family",
    "generator_version",
    "spec_sha256",
    "storage_uri",
]


def _trigger(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        job = client.request(
            "POST",
            f"/challenge-definitions/{args.slug}/builds",
            json={"version_no": args.version_no},
            idempotency_key=idempotency_key(args),
        )
    output.print_resource(job, as_json=args.json)
    return 0


def _list(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        rows = client.list(
            f"/challenge-definitions/{args.slug}/builds",
            params={"version_no": args.version_no},
            limit=args.limit,
        )
    output.print_rows(rows, _COLUMNS, as_json=args.json)
    return 0


def _get(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        body = client.request("GET", f"/builds/{args.build_id}")
    output.print_resource(body, as_json=args.json)
    return 0


def add_parser(areas: argparse._SubParsersAction) -> None:
    area = areas.add_parser(AREA, help="Trigger and inspect challenge builds.")
    verbs = area.add_subparsers(dest="verb", required=True)

    trigger = verbs.add_parser("trigger", help="Enqueue a build for a version.")
    trigger.add_argument("--slug", required=True)
    trigger.add_argument("--version-no", dest="version_no", type=int, required=True)
    add_idempotency_option(trigger)
    add_global_options(trigger)
    trigger.set_defaults(func=_trigger)

    listp = verbs.add_parser("list", help="List builds for a version.")
    listp.add_argument("--slug", required=True)
    listp.add_argument("--version-no", dest="version_no", type=int, required=True)
    listp.add_argument("--limit", type=int, default=None)
    add_global_options(listp)
    listp.set_defaults(func=_list)

    get = verbs.add_parser("get", help="Show one build.")
    get.add_argument("build_id")
    add_global_options(get)
    get.set_defaults(func=_get)
