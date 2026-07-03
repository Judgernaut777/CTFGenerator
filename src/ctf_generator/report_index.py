from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ReportRow:
    command: str
    status: str
    subject_type: str
    subject_identifier: str
    timestamp: str
    git_commit_short: str
    score_total: float | None
    source: str


@dataclass
class ReportIndex:
    rows: list[ReportRow] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def row_from_report(report: dict, source: str) -> ReportRow:
    """Project a report envelope into a ``ReportRow``.

    Pure and defensive: a malformed or partial envelope never raises. Every
    field is read with ``.get`` plus an ``isinstance`` guard so unexpected
    shapes degrade to placeholder values instead of crashing.
    """
    command = _as_str(report.get("command")) if isinstance(report, dict) else ""
    status = _as_str(report.get("status")) if isinstance(report, dict) else ""
    timestamp = _as_str(report.get("timestamp")) if isinstance(report, dict) else ""

    subject = report.get("subject") if isinstance(report, dict) else None
    if isinstance(subject, dict):
        subject_type = _as_str(subject.get("type"))
        subject_identifier = _as_str(subject.get("identifier"))
    else:
        subject_type = ""
        subject_identifier = ""

    git_commit = _as_str(report.get("git_commit")) if isinstance(report, dict) else ""
    git_commit_short = git_commit[:12] if git_commit else "-"

    result = report.get("result") if isinstance(report, dict) else None
    score_total: float | None = None
    if isinstance(result, dict):
        total = result.get("total")
        if isinstance(total, bool):
            # bool is a subclass of int/float but is not a real score.
            score_total = None
        elif isinstance(total, (int, float)):
            score_total = float(total)

    return ReportRow(
        command=command,
        status=status,
        subject_type=subject_type,
        subject_identifier=subject_identifier,
        timestamp=timestamp,
        git_commit_short=git_commit_short,
        score_total=score_total,
        source=source,
    )


def load_index(report_dir: Path) -> ReportIndex:
    """Load every ``*.json`` report envelope in ``report_dir`` (non-recursive).

    The only disk-touching function in this module. Missing directories yield
    an empty index. Files that cannot be read or parsed are recorded in
    ``skipped`` and never abort the scan.
    """
    index = ReportIndex()
    if not report_dir.is_dir():
        return index
    for path in sorted(report_dir.glob("*.json")):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            index.skipped.append(path.name)
            continue
        if not isinstance(report, dict):
            index.skipped.append(path.name)
            continue
        index.rows.append(row_from_report(report, path.name))
    index.rows.sort(key=lambda row: (row.timestamp, row.source))
    return index


def _as_str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _subject_cell(row: ReportRow) -> str:
    if row.subject_type and row.subject_identifier:
        return f"{row.subject_type}:{row.subject_identifier}"
    return row.subject_identifier or row.subject_type or "-"


def _score_cell(row: ReportRow) -> str:
    return f"{row.score_total:.1f}" if row.score_total is not None else ""


_COLUMNS = ("command", "status", "subject", "timestamp", "commit", "score")


def render_table(index: ReportIndex) -> str:
    """Render the index as a fixed-width plain-text table. Pure."""
    if not index.rows:
        lines = ["No reports found."]
        if index.skipped:
            lines.append(f"({len(index.skipped)} file(s) skipped: could not parse)")
        return "\n".join(lines)

    cells = [list(_COLUMNS)]
    for row in index.rows:
        cells.append(
            [
                row.command or "-",
                row.status or "-",
                _subject_cell(row),
                row.timestamp or "-",
                row.git_commit_short,
                _score_cell(row),
            ]
        )

    widths = [max(len(r[i]) for r in cells) for i in range(len(_COLUMNS))]
    lines = []
    for r, cell_row in enumerate(cells):
        lines.append("  ".join(value.ljust(widths[i]) for i, value in enumerate(cell_row)))
        if r == 0:
            lines.append("  ".join("-" * widths[i] for i in range(len(_COLUMNS))))
    if index.skipped:
        lines.append("")
        lines.append(f"({len(index.skipped)} file(s) skipped: could not parse)")
    return "\n".join(lines)


def render_html(index: ReportIndex) -> str:
    """Render the index as one self-contained static HTML document. Pure.

    Inline CSS only; no <script>, no external/network assets. Every dynamic
    value is passed through ``html.escape`` because subject identifiers can
    carry attacker-influenced challenge names.
    """
    style = (
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;"
        "margin:2rem;color:#1a1a1a;background:#fafafa}"
        "h1{font-size:1.4rem}"
        "table{border-collapse:collapse;width:100%;background:#fff;"
        "box-shadow:0 1px 3px rgba(0,0,0,0.1)}"
        "th,td{padding:0.5rem 0.75rem;text-align:left;border-bottom:1px solid #eee;"
        "font-size:0.9rem}"
        "th{background:#f0f0f0;font-weight:600}"
        "td.num{text-align:right;font-variant-numeric:tabular-nums}"
        ".status-passed{color:#0a7a2f;font-weight:600}"
        ".status-failed{color:#c0392b;font-weight:600}"
        ".card{background:#fff;border:1px solid #eee;border-radius:6px;"
        "padding:2rem;text-align:center;color:#666}"
        ".note{margin-top:1rem;color:#888;font-size:0.85rem}"
    )
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>CTF Report Index</title>",
        f"<style>{style}</style>",
        "</head>",
        "<body>",
        "<h1>CTF Report Index</h1>",
    ]

    if not index.rows:
        parts.append('<div class="card">No reports found.</div>')
    else:
        parts.append("<table>")
        parts.append(
            "<thead><tr>"
            "<th>Command</th><th>Status</th><th>Subject</th>"
            "<th>Timestamp</th><th>Commit</th><th>Score</th>"
            "</tr></thead>"
        )
        parts.append("<tbody>")
        for row in index.rows:
            status = row.status or "-"
            status_class = ""
            if status in ("passed", "failed"):
                status_class = f' class="status-{status}"'
            parts.append(
                "<tr>"
                f"<td>{html.escape(row.command or '-')}</td>"
                f"<td{status_class}>{html.escape(status)}</td>"
                f"<td>{html.escape(_subject_cell(row))}</td>"
                f"<td>{html.escape(row.timestamp or '-')}</td>"
                f"<td>{html.escape(row.git_commit_short)}</td>"
                f'<td class="num">{html.escape(_score_cell(row))}</td>'
                "</tr>"
            )
        parts.append("</tbody></table>")

    if index.skipped:
        parts.append(
            f'<p class="note">{len(index.skipped)} file(s) skipped: could not parse.</p>'
        )

    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts) + "\n"
