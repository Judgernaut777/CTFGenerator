"""``ctfgen challenge-version`` -- immutable-once-published challenge revisions.

* ``create``  -> ``POST /challenge-versions``                       (Idempotency-Key)
* ``list``    -> ``GET  /challenge-versions?definition_slug=...``   (slug required)
* ``get``     -> ``GET  /challenge-versions/{slug}/{version_no}``
* ``publish`` -> ``POST /challenge-versions/{slug}/{version_no}/publish``

``publish`` takes no body and its route does NOT honour an Idempotency-Key (the
transition is idempotent server-side), so none is sent.
"""

from __future__ import annotations

import argparse
import json

from .. import output
from ..errors import CliError
from ._common import add_global_options, add_idempotency_option, idempotency_key, open_client

AREA = "challenge-version"

# List projection is metadata-only (the full ``spec`` is returned solely by GET).
_COLUMNS = [
    "definition_slug",
    "version_no",
    "state",
    "family_version",
    "spec_version",
    "mode",
    "published_at",
    "immutable",
]


def _load_spec(args: argparse.Namespace) -> dict:
    if args.spec_file:
        # Read INSIDE the guard: a mistyped path / directory / unreadable / binary
        # file must be a clean CliError (run() -> one-line stderr), never a raw
        # traceback (the CLI's never-a-traceback contract).
        try:
            with open(args.spec_file, encoding="utf-8") as handle:
                raw = handle.read()
        except OSError as exc:
            raise CliError(f"cannot read spec file {args.spec_file}: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise CliError(f"spec file {args.spec_file} is not UTF-8 text: {exc}") from exc
    else:
        raw = args.spec
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise CliError(f"--spec/--spec-file must be a JSON object: {exc}") from exc
    if not isinstance(parsed, dict):
        raise CliError("--spec/--spec-file must be a JSON object")
    return parsed


def _create(args: argparse.Namespace) -> int:
    body: dict[str, object] = {
        "definition_slug": args.definition_slug,
        "seed": args.seed,
        "family_version": args.family_version,
        "spec": _load_spec(args),
        "mode": args.mode,
        "cve_refs": list(args.cve_ref or []),
    }
    if args.spec_version is not None:
        body["spec_version"] = args.spec_version
    if args.cve_content_hash is not None:
        body["cve_content_hash"] = args.cve_content_hash
    with open_client(args) as client:
        created = client.request(
            "POST",
            "/challenge-versions",
            json=body,
            idempotency_key=idempotency_key(args),
        )
    output.print_resource(created, as_json=args.json)
    return 0


def _list(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        rows = client.list(
            "/challenge-versions",
            params={"definition_slug": args.definition_slug},
            limit=args.limit,
        )
    output.print_rows(rows, _COLUMNS, as_json=args.json)
    return 0


def _get(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        body = client.request(
            "GET",
            f"/challenge-versions/{args.definition_slug}/{args.version_no}",
        )
    output.print_resource(body, as_json=args.json)
    return 0


def _publish(args: argparse.Namespace) -> int:
    with open_client(args) as client:
        published = client.request(
            "POST",
            f"/challenge-versions/{args.definition_slug}/{args.version_no}/publish",
        )
    output.print_resource(published, as_json=args.json)
    return 0


def add_parser(areas: argparse._SubParsersAction) -> None:
    area = areas.add_parser(AREA, help="Manage challenge versions.")
    verbs = area.add_subparsers(dest="verb", required=True)

    create = verbs.add_parser("create", help="Create a draft version.")
    create.add_argument("--definition-slug", dest="definition_slug", required=True)
    create.add_argument("--seed", required=True)
    create.add_argument("--family-version", dest="family_version", required=True)
    spec = create.add_mutually_exclusive_group(required=True)
    spec.add_argument("--spec", default=None, help="Inline JSON object spec")
    spec.add_argument("--spec-file", dest="spec_file", default=None, help="Path to a JSON spec")
    create.add_argument("--spec-version", dest="spec_version", default=None)
    create.add_argument("--mode", default="red")
    create.add_argument("--cve-ref", dest="cve_ref", action="append", default=None)
    create.add_argument("--cve-content-hash", dest="cve_content_hash", default=None)
    add_idempotency_option(create)
    add_global_options(create)
    create.set_defaults(func=_create)

    listp = verbs.add_parser("list", help="List versions of a definition.")
    listp.add_argument("--definition-slug", dest="definition_slug", required=True)
    listp.add_argument("--limit", type=int, default=None)
    add_global_options(listp)
    listp.set_defaults(func=_list)

    get = verbs.add_parser("get", help="Show one version (with its spec).")
    get.add_argument("definition_slug")
    get.add_argument("version_no", type=int)
    add_global_options(get)
    get.set_defaults(func=_get)

    publish = verbs.add_parser("publish", help="Publish a draft version.")
    publish.add_argument("definition_slug")
    publish.add_argument("version_no", type=int)
    add_global_options(publish)
    publish.set_defaults(func=_publish)
