"""Terminal rendering for the platform CLI (M13 slice 13a).

Two output modes, pure stdlib (no new deps):

* default -- a human-readable aligned TABLE (or key/value block for a single
  resource);
* ``--json`` -- the raw JSON, pretty-printed, for scripting.

Rendering NEVER fetches or decides anything -- callers pass already-shaped data.
It also never emits a token: callers strip secrets before handing data here (the
API's ``/auth/me`` payload has none, and the token payload is never rendered).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from typing import Any


def _cell(value: Any) -> str:
    """Render one table cell. Lists/dicts collapse to compact JSON; ``None`` to
    an empty string."""
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


def render_table(rows: Sequence[Mapping[str, Any]], columns: Sequence[str]) -> str:
    """Render ``rows`` as an aligned text table over ``columns`` (in order).

    An empty ``rows`` yields just the header line. Column width is the max of the
    header and every cell in that column."""
    header = list(columns)
    body = [[_cell(row.get(col)) for col in header] for row in rows]
    widths = [len(col) for col in header]
    for line in body:
        for i, cell in enumerate(line):
            widths[i] = max(widths[i], len(cell))
    out = ["  ".join(col.ljust(widths[i]) for i, col in enumerate(header)).rstrip()]
    out.append("  ".join("-" * widths[i] for i in range(len(header))))
    for line in body:
        out.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(line)).rstrip())
    return "\n".join(out)


def render_resource(body: Mapping[str, Any]) -> str:
    """Render a single resource as an aligned ``key: value`` block."""
    if not body:
        return ""
    width = max(len(str(k)) for k in body)
    return "\n".join(f"{str(k).ljust(width)} : {_cell(v)}" for k, v in body.items())


def print_resource(body: Mapping[str, Any], *, as_json: bool, stream=None) -> None:
    stream = stream if stream is not None else sys.stdout
    if as_json:
        print(json.dumps(body, indent=2, sort_keys=True), file=stream)
    else:
        print(render_resource(body), file=stream)


def print_rows(
    rows: Sequence[Mapping[str, Any]],
    columns: Sequence[str],
    *,
    as_json: bool,
    stream=None,
) -> None:
    stream = stream if stream is not None else sys.stdout
    if as_json:
        print(json.dumps(list(rows), indent=2, sort_keys=True), file=stream)
    else:
        print(render_table(rows, columns), file=stream)
