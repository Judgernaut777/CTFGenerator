"""``ctfgen system`` -- platform health probe.

* ``health`` -> ``GET /system/health``  (unauthenticated liveness)

The health route is public liveness (no auth required); the CLI sends it
unauthenticated so a probe works even without a session.
"""

from __future__ import annotations

import argparse

from .. import output
from ._common import add_global_options, open_client

AREA = "system"


def _health(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        body = client.request("GET", "/system/health", authed=False)
    output.print_resource(body, as_json=args.json)
    return 0


def add_parser(areas: argparse._SubParsersAction) -> None:
    area = areas.add_parser(AREA, help="Platform health/status probes.")
    verbs = area.add_subparsers(dest="verb", required=True)

    health = verbs.add_parser("health", help="Show platform health.")
    add_global_options(health)
    health.set_defaults(func=_health)
