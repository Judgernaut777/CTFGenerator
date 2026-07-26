"""Reports router: validation / build / eval (version-scoped) + competition-run.

A report is a read-only summary of already-persisted data. A POST FREEZES a report
as an immutable snapshot (the archived "run report"); a GET reads the latest
snapshot or a subject's snapshot history -- reads never compute-and-persist.

Authorization is ROLE-SCOPED PER REPORT: the version-scoped kinds each carry their
own flat AUTHORING read permission (validation->``build:read``, build->``build:read``,
eval->``eval:read``) via :func:`require_version_report_permission` -- none held by
a contestant, so authoring internals never leak to players; the competition-run
report is competition-scoped on ``scoreboard:read`` (so a contestant can read their
own competition's final results). Every payload is secret-free by construction
(references / hashes / counts / booleans only).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ctf_generator.domain.reports.models import ReportSnapshot, report_subject

from ..deps import (
    Permission,
    Principal,
    VersionReportType,
    get_report_service,
    require_competition_permission,
    require_version_report_permission,
)
from ..envelopes import (
    REPORT_SNAPSHOT_LIST_SCHEMA,
    REPORT_SNAPSHOT_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..schemas.common import ERROR_RESPONSES
from ._support import record_audit, respond

router = APIRouter(tags=["reports"])

_READ_ERRORS = {k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)}


def _snapshot_to_response(snap: ReportSnapshot) -> dict:
    return {
        "report_id": snap.report_id,
        "report_type": snap.report_type,
        "subject": snap.subject,
        "definition_slug": snap.definition_slug,
        "version_no": snap.version_no,
        "competition_id": snap.competition_id,
        "created_by": snap.created_by,
        "created_at": snap.created_at.isoformat(),
        "payload": dict(snap.payload),
    }


# -- version-scoped reports (validation / build / eval) -----------------------


@router.post(
    "/reports/versions/{definition_slug}/{version_no}/{report_type}",
    response_model=None,
    status_code=201,
    responses={201: {"description": "Snapshot created"}, **_READ_ERRORS},
)
def snapshot_version_report(
    request: Request,
    definition_slug: str,
    version_no: int,
    report_type: VersionReportType,
    principal: Principal = Depends(require_version_report_permission),
    service=Depends(get_report_service),
):
    snap = service.snapshot(
        report_type.value,
        principal.subject,
        definition_slug=definition_slug,
        version_no=version_no,
    )
    record_audit(
        request, principal,
        action=f"report.{report_type.value}.snapshot",
        target=f"{definition_slug}:v{version_no}",
    )
    return respond(
        201, resource_envelope(REPORT_SNAPSHOT_SCHEMA, _snapshot_to_response(snap))
    )


@router.get(
    "/reports/versions/{definition_slug}/{version_no}/{report_type}/latest",
    response_model=None,
    responses={200: {"description": "OK"}, **_READ_ERRORS},
)
def latest_version_report(
    definition_slug: str,
    version_no: int,
    report_type: VersionReportType,
    principal: Principal = Depends(require_version_report_permission),
    service=Depends(get_report_service),
):
    subject = report_subject(
        report_type.value, definition_slug=definition_slug, version_no=version_no
    )
    snap = service.latest(report_type.value, subject)
    if snap is None:
        raise LookupError(
            f"no {report_type.value} report snapshot for {subject!r}"
        )
    return respond(
        200, resource_envelope(REPORT_SNAPSHOT_SCHEMA, _snapshot_to_response(snap))
    )


@router.get(
    "/reports/versions/{definition_slug}/{version_no}/{report_type}",
    response_model=None,
    responses={200: {"description": "OK"}, **_READ_ERRORS},
)
def list_version_reports(
    definition_slug: str,
    version_no: int,
    report_type: VersionReportType,
    principal: Principal = Depends(require_version_report_permission),
    service=Depends(get_report_service),
):
    subject = report_subject(
        report_type.value, definition_slug=definition_slug, version_no=version_no
    )
    snaps = service.list_snapshots(report_type.value, subject)
    items = [_snapshot_to_response(s) for s in snaps]
    return respond(
        200,
        list_envelope(
            REPORT_SNAPSHOT_LIST_SCHEMA, items, limit=len(items), next_cursor=None
        ),
    )


# -- competition-run report ---------------------------------------------------


@router.post(
    "/reports/competitions/{competition_id}/run",
    response_model=None,
    status_code=201,
    responses={201: {"description": "Snapshot created"}, **_READ_ERRORS},
)
def snapshot_competition_run(
    request: Request,
    competition_id: str,
    principal: Principal = Depends(
        require_competition_permission(Permission.SCOREBOARD_READ)
    ),
    service=Depends(get_report_service),
):
    snap = service.snapshot(
        "competition_run", principal.subject, competition_id=competition_id
    )
    record_audit(
        request, principal, action="report.competition_run.snapshot",
        target=competition_id,
    )
    return respond(
        201, resource_envelope(REPORT_SNAPSHOT_SCHEMA, _snapshot_to_response(snap))
    )


@router.get(
    "/reports/competitions/{competition_id}/run/latest",
    response_model=None,
    responses={200: {"description": "OK"}, **_READ_ERRORS},
)
def latest_competition_run(
    competition_id: str,
    principal: Principal = Depends(
        require_competition_permission(Permission.SCOREBOARD_READ)
    ),
    service=Depends(get_report_service),
):
    subject = report_subject("competition_run", competition_id=competition_id)
    snap = service.latest("competition_run", subject)
    if snap is None:
        raise LookupError(
            f"no competition_run report snapshot for {competition_id!r}"
        )
    return respond(
        200, resource_envelope(REPORT_SNAPSHOT_SCHEMA, _snapshot_to_response(snap))
    )


@router.get(
    "/reports/competitions/{competition_id}/run",
    response_model=None,
    responses={200: {"description": "OK"}, **_READ_ERRORS},
)
def list_competition_runs(
    competition_id: str,
    principal: Principal = Depends(
        require_competition_permission(Permission.SCOREBOARD_READ)
    ),
    service=Depends(get_report_service),
):
    subject = report_subject("competition_run", competition_id=competition_id)
    snaps = service.list_snapshots("competition_run", subject)
    items = [_snapshot_to_response(s) for s in snaps]
    return respond(
        200,
        list_envelope(
            REPORT_SNAPSHOT_LIST_SCHEMA, items, limit=len(items), next_cursor=None
        ),
    )
