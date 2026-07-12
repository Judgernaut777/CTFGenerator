"""``ctfgen submission`` -- flag submission + the append-only submission ledger.

* ``submit`` -> ``POST /competitions/{id}/submissions``   (Idempotency-Key)
* ``list``   -> ``GET  /competitions/{id}/submissions``   (optional ``--team``)
* ``get``    -> ``GET  /submissions/{submission_id}``

The candidate answer/flag is inbound only: the API verifies it transiently and
NEVER stores/echoes it, and no response column carries it. The answer is taken
from ``--answer`` or ``$CTFGEN_ANSWER`` (env avoids leaving the guess in ``ps`` /
shell history). ``submit`` always sends an Idempotency-Key so a re-run with the
SAME pinned key replays the first attempt rather than recording a new one.
"""

from __future__ import annotations

import argparse
import os

from .. import output
from ..errors import CliError
from ._common import add_global_options, add_idempotency_option, idempotency_key, open_client

AREA = "submission"

_ANSWER_ENV = "CTFGEN_ANSWER"  # noqa: S105 - env var name, not a secret
_COLUMNS = [
    "submission_id",
    "team",
    "definition_slug",
    "version_no",
    "submitted_at",
    "correct",
]


def _submit(args: argparse.Namespace) -> int:
    answer = args.answer if args.answer is not None else os.environ.get(_ANSWER_ENV)
    if not answer:
        raise CliError(
            f"an answer is required: pass --answer or set {_ANSWER_ENV}"
        )
    body: dict[str, object] = {
        "team": args.team,
        "definition_slug": args.definition_slug,
        "version_no": args.version_no,
        "answer": answer,
    }
    if args.instance_seed is not None:
        body["instance_seed"] = args.instance_seed
    with open_client(args) as client:
        outcome = client.request(
            "POST",
            f"/competitions/{args.competition_id}/submissions",
            json=body,
            idempotency_key=idempotency_key(args),
        )
    output.print_resource(outcome, as_json=args.json)
    return 0


def _list(args: argparse.Namespace) -> int:
    params = {"team": args.team} if args.team is not None else None
    with open_client(args) as client:
        rows = client.list(
            f"/competitions/{args.competition_id}/submissions",
            params=params,
            limit=args.limit,
        )
    output.print_rows(rows, _COLUMNS, as_json=args.json)
    return 0


def _get(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        body = client.request("GET", f"/submissions/{args.submission_id}")
    output.print_resource(body, as_json=args.json)
    return 0


def add_parser(areas: argparse._SubParsersAction) -> None:
    area = areas.add_parser(AREA, help="Submit flags and read the submission ledger.")
    verbs = area.add_subparsers(dest="verb", required=True)

    submit = verbs.add_parser("submit", help="Submit a flag for a team.")
    submit.add_argument("--competition-id", dest="competition_id", required=True)
    submit.add_argument("--team", required=True)
    submit.add_argument("--definition-slug", dest="definition_slug", required=True)
    submit.add_argument("--version-no", dest="version_no", type=int, required=True)
    submit.add_argument(
        "--answer", default=None, help=f"Candidate flag (or set {_ANSWER_ENV})"
    )
    submit.add_argument("--instance-seed", dest="instance_seed", default=None)
    add_idempotency_option(submit)
    add_global_options(submit)
    submit.set_defaults(func=_submit)

    listp = verbs.add_parser("list", help="List a competition's submissions.")
    listp.add_argument("--competition-id", dest="competition_id", required=True)
    listp.add_argument("--team", default=None, help="Filter by team (organizer/admin)")
    listp.add_argument("--limit", type=int, default=None)
    add_global_options(listp)
    listp.set_defaults(func=_list)

    get = verbs.add_parser("get", help="Show one submission.")
    get.add_argument("submission_id")
    add_global_options(get)
    get.set_defaults(func=_get)
