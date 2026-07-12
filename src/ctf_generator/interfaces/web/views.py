"""Domain -> view-dict mapping (M11 slice a).

Handlers map the ORM-free application aggregates onto plain dicts BEFORE handing
them to a template, so an ORM object / lazy relationship never escapes into the
rendering layer, and the exact set of rendered fields is explicit and auditable.
A :class:`CompetitionConfig` carries NO secret (no flags, tokens, or credentials),
and this mapping renders only its timing/scoring configuration.
"""

from __future__ import annotations

from typing import Any

from ctf_generator.domain.authoring.models import (
    ChallengeBuild,
    ChallengePublication,
)
from ctf_generator.domain.challenges.models import CompetitionConfig
from ctf_generator.domain.identity.models import Team
from ctf_generator.domain.instances.models import (
    HealthObservation,
    Instance,
    InstanceEndpoint,
)
from ctf_generator.domain.work.models import Job
from ctf_generator.interfaces.api.schemas.builds import build_to_list_item
from ctf_generator.interfaces.api.schemas.instances import (
    instance_to_list_item,
    instance_to_response,
)
from ctf_generator.interfaces.api.schemas.jobs import job_to_response
from ctf_generator.interfaces.api.schemas.scoreboard import (
    entry_sort_key,
    entry_to_response,
)


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def _dt_local(value: Any) -> str:
    """Render a datetime for an ``<input type="datetime-local">`` value
    (``YYYY-MM-DDTHH:MM``), or ``""`` when absent. Used to PRE-FILL the edit form
    from the stored config -- never a secret, only timing configuration."""
    return value.strftime("%Y-%m-%dT%H:%M") if value is not None else ""


def team_row(team: Team) -> dict[str, Any]:
    """A compact list-row view of a team (name only -- a Team carries no secret)."""
    return {"name": team.name}


def publication_row(publication: ChallengePublication) -> dict[str, Any]:
    """The read view of one competition<->version attachment (public config only)."""
    return {
        "definition_slug": publication.definition_slug,
        "version_no": publication.version_no,
        "initial_value": publication.initial_value,
        "minimum_value": publication.minimum_value,
        "decay_function": publication.decay_function,
    }


def competition_form_values(config: CompetitionConfig) -> dict[str, str]:
    """Map a stored competition onto the string field values the edit FORM renders,
    so a re-render pre-fills exactly what would be submitted (no secret involved)."""
    return {
        "competition_id": config.competition_id,
        "name": config.name,
        "start_time": _dt_local(config.start_time),
        "end_time": _dt_local(config.end_time),
        "scoring_start_time": _dt_local(config.scoring_start_time),
        "freeze_time": _dt_local(config.freeze_time),
    }


def competition_row(config: CompetitionConfig) -> dict[str, Any]:
    """A compact list-row view (id + name + window bounds)."""
    return {
        "competition_id": config.competition_id,
        "name": config.name,
        "start_time": _iso(config.start_time),
        "end_time": _iso(config.end_time),
    }


# -- ops view mappers -------------------------------------------------------
#
# These DELEGATE to the API's DTO mappers so the secret-redaction boundary has a
# SINGLE source of truth: an instance's credential/runtime-token/``instance_seed``,
# a job's ``payload``/``result_json``/``error_detail``, and a build's ``seed`` are
# already stripped by the shared API mappers and can never reach a template. The
# web layer adds no field the API would not also surface.


def instance_row(instance: Instance) -> dict[str, Any]:
    """A list-row view of an instance (public operational facts only -- NEVER a
    credential, runtime token, or ``instance_seed``)."""
    return instance_to_list_item(instance)


def instance_detail(
    instance: Instance,
    endpoints: list[InstanceEndpoint],
    health: HealthObservation | None,
) -> dict[str, Any]:
    """The operator detail view: public facts + PUBLIC (non-internal) endpoints +
    latest health. ``endpoints`` is already filtered to non-internal by the service;
    no secret is read on this path."""
    return instance_to_response(instance, endpoints, health)


def job_row(job: Job) -> dict[str, Any]:
    """The ops view of a job: type / state / attempt accounting / timestamps /
    sanitized ``error_class`` summary ONLY -- never the payload, result, or
    error detail (where a flag/seed/credential would live)."""
    return job_to_response(job)


def build_row(build: ChallengeBuild) -> dict[str, Any]:
    """A build's content identity + provenance (never the generation ``seed``)."""
    return build_to_list_item(build)


def scoreboard_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """One public standings row (team / score / solves / last-solve / rank)."""
    return entry_to_response(entry)


def scoreboard_entry_key(entry: dict[str, Any]) -> list[Any]:
    """The API's stable standings ordering: ascending rank, then team id."""
    return entry_sort_key(entry)


def competition_detail(config: CompetitionConfig) -> dict[str, Any]:
    """The full read view of a competition's configuration (no secrets)."""
    scoring = config.default_scoring
    scoring_view: dict[str, Any] | None = None
    if scoring is not None:
        scoring_view = {
            "challenge_id": scoring.challenge_id,
            "initial_value": scoring.initial_value,
            "minimum_value": scoring.minimum_value,
            "decay_function": scoring.decay_function,
            "decay": scoring.decay,
            "first_blood_enabled": scoring.first_blood_bonus.enabled,
            "first_blood_bonus_points": scoring.first_blood_bonus.bonus_points,
            "first_blood_bonus_percent": scoring.first_blood_bonus.bonus_percent,
        }
    return {
        "competition_id": config.competition_id,
        "name": config.name,
        "start_time": _iso(config.start_time),
        "end_time": _iso(config.end_time),
        "scoring_start_time": _iso(config.scoring_start_time),
        "freeze_time": _iso(config.freeze_time),
        "scoring": scoring_view,
    }
