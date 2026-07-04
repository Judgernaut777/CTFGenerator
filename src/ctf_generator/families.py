from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Protocol

from .models import ChallengeSpec, ResponseSpec, ScenarioSpec, TriggerSpec
from .spec_generator import _DEFAULT_CHECKPOINTS, _DEFAULT_OBJECTIVES, _FAMILY_BRIEF
from .templates import binary, cloud, crypto, forensics, mobile, network, scada_ics
from .templates.tenant_export import render_tenant_export
from .validator import REQUIRED_FILES

if TYPE_CHECKING:
    from .cve_source import CveRecord

# --- Scoring hints ------------------------------------------------------------


@dataclass(frozen=True)
class ScoringHints:
    """Hints ``score.py`` reads to compute dimension scores for a family.

    Defaults reproduce the current, hard-coded ``tenant_export`` scoring
    signals (see ``score._statefulness`` / ``score._live_interaction``): a
    background worker + queue backend, live discover-and-poll interaction,
    and medium decoy density.
    """

    has_worker: bool = True
    has_queue: bool = True
    live_interaction: bool = True
    decoy_density: str = "medium"


# --- Renderer protocol ---------------------------------------------------------


class FamilyRenderer(Protocol):
    def __call__(
        self,
        spec: ChallengeSpec,
        rng: random.Random,
        cve_record: "CveRecord | None" = None,
    ) -> dict[str, str]: ...


DefaultSpecBuilder = Callable[..., ChallengeSpec]


# --- Family record ---------------------------------------------------------------


@dataclass(frozen=True)
class Family:
    name: str
    category: str
    modes: tuple[str, ...]
    render: FamilyRenderer
    required_files: tuple[str, ...]
    compose_service_markers: tuple[str, ...] = ()
    difficulties: tuple[str, ...] = ("easy", "medium", "hard")
    cve_driven: bool = False
    llm_brief: str = "A security challenge."
    default_spec_builder: DefaultSpecBuilder | None = None
    scoring_hints: ScoringHints = field(default_factory=ScoringHints)
    # Family-appropriate pedagogical defaults used by ``spec_generator.
    # default_spec`` so a generated challenge.yaml/checkpoints.yaml describes
    # THIS family rather than the historical tenant-export defaults. The
    # defaults below reproduce the tenant-export text so the tenant_export
    # family (which does not override them) is byte-for-byte unchanged.
    learning_objectives: tuple[str, ...] = tuple(_DEFAULT_OBJECTIVES)
    checkpoints: tuple[str, ...] = tuple(_DEFAULT_CHECKPOINTS)
    # A real, enabled live-adversarial scenario for this family (blue reacts
    # mid-solve). None means the family ships no default scenario. Targets are
    # STABLE substrings of the family's own attack surface (e.g. an admin path
    # prefix), so the defender genuinely disrupts the standard solve path on
    # any instance -- not a hand-matched test literal.
    default_scenario: ScenarioSpec | None = None


# --- Registry --------------------------------------------------------------------

_REGISTRY: dict[str, Family] = {}


def register(family: Family) -> None:
    """Register (or replace) a family in the process-wide registry."""
    _REGISTRY[family.name] = family


def get(name: str) -> Family:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown family: {name}") from None


def is_registered(name: str) -> bool:
    return name in _REGISTRY


def family_names() -> list[str]:
    return sorted(_REGISTRY)


def families_for_mode(mode: str) -> list[Family]:
    return [f for f in sorted(_REGISTRY.values(), key=lambda fam: fam.name) if mode in f.modes]


def families_for_category(category: str) -> list[Family]:
    return [
        f
        for f in sorted(_REGISTRY.values(), key=lambda fam: fam.name)
        if f.category == category
    ]


# A top-level ``family: "..."`` (or ``family: value``) line in a rendered
# challenge.yaml. Anchored to zero leading whitespace so it only matches the
# top-level key, not the nested ``meta.family`` line emitted alongside it.
_FAMILY_LINE = re.compile(r'^family:\s*"?([^"\r\n]*?)"?\s*$')


def family_of(challenge_yaml_text: str) -> str | None:
    """Parse the top-level ``family`` field out of rendered challenge.yaml text.

    Returns ``None`` if no top-level ``family:`` line is present.
    """
    for line in challenge_yaml_text.splitlines():
        if line.startswith(" "):
            continue
        match = _FAMILY_LINE.match(line)
        if match:
            value = match.group(1).strip()
            return value or None
    return None


# --- Bootstrap: existing tenant_export family -------------------------------------


def _render_web_business_logic_tenant_export(
    spec: ChallengeSpec,
    rng: random.Random,
    cve_record: "CveRecord | None" = None,
) -> dict[str, str]:
    """Adapter wrapping ``render_tenant_export`` unchanged for the registry.

    ``cve_record`` is accepted (per the ``FamilyRenderer`` protocol) and
    ignored: this family predates CVE-driven generation and is not
    ``cve_driven``.
    """
    return render_tenant_export(spec, rng)


register(
    Family(
        name="web_business_logic_tenant_export",
        category="web",
        modes=("red",),
        render=_render_web_business_logic_tenant_export,
        required_files=tuple(REQUIRED_FILES),
        compose_service_markers=("worker:", "redis"),
        difficulties=("easy", "medium", "hard"),
        cve_driven=False,
        llm_brief=_FAMILY_BRIEF.get(
            "web_business_logic_tenant_export", "A security challenge."
        ),
        scoring_hints=ScoringHints(
            has_worker=True,
            has_queue=True,
            live_interaction=True,
            decoy_density="medium",
        ),
    )
)


# --- Bootstrap: Phase 3 template-module families -----------------------------
#
# Each of these modules exports the fixed renderer-module interface
# (FAMILY_NAME/CATEGORY/MODES/DIFFICULTIES/CVE_DRIVEN/LLM_BRIEF/
# COMPOSE_MARKERS/SCORING_HINTS/REQUIRED_FILES/render) described in their own
# docstrings; this loop just wires each one into the registry uniformly.

# Per-family pedagogical defaults, keyed by FAMILY_NAME. Each pair is
# (learning_objectives, checkpoints) tracing that family's actual solve path,
# so the default (no-LLM) spec no longer stamps every family with the
# tenant-export objectives/checkpoints. Families absent here fall back to the
# tenant-export defaults on the ``Family`` record.
_FAMILY_SPEC_DEFAULTS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "binary_heap_exploit": (
        (
            "Reverse the service's line-oriented wire protocol from its responses",
            "Infer the heap struct layout from the fixed per-session buffer size",
            "Overflow the client-controlled note into the adjacent admin flag field",
        ),
        (
            "connects to the service and enumerates its command verbs",
            "identifies the client-declared length trusted during the note copy",
            "computes the offset from the note buffer to the admin flag",
            "sends an overlong note that overflows into the admin flag",
            "invokes the privileged command and reads the flag",
        ),
    ),
    "network_lateral_pivot": (
        (
            "Discover the default administrative credentials on the edge jump host",
            "Abuse the diagnostics/relay feature to reach an internal-only host",
            "Read a flag exposed only inside the internal network segment",
        ),
        (
            "logs into the edge service with default credentials",
            "enumerates the diagnostics and relay endpoints",
            "pivots through the relay to the internal host",
            "requests the internal-only resource holding the flag",
            "extracts the flag from the internal response",
        ),
    ),
    "crypto_token_forgery": (
        (
            "Analyze how the console issues and verifies HMAC-signed session tokens",
            "Identify the legacy 'alg: none' verification bypass (CWE-347)",
            "Forge an unsigned admin token to reach the protected endpoint",
        ),
        (
            "obtains a normal signed session token from the console",
            "decodes the token and identifies the signing scheme",
            "discovers the verifier still accepts alg:none tokens",
            "forges an unsigned token asserting admin privilege",
            "reaches the admin endpoint and reads the flag",
        ),
    ),
    "cloud_metadata_ssrf": (
        (
            "Coerce the asset-fetch service into a server-side request (SSRF, CWE-918)",
            "Retrieve temporary IAM credentials from the instance metadata endpoint",
            "Replay the stolen credentials against the internal storage service",
        ),
        (
            "identifies the URL parameter the fetch service will follow",
            "points the fetch at the 169.254.169.254 instance metadata endpoint",
            "recovers temporary IAM credentials from the metadata response",
            "authenticates to the internal storage service with those credentials",
            "reads the flag object from storage",
        ),
    ),
    "forensics_incident_triage": (
        (
            "Correlate access, auth, and payload-strings artifacts from a compromise",
            "Identify the exploited CVE from the attacker's activity",
            "Assemble the recovered indicators of compromise into the flag",
        ),
        (
            "reviews the access log for anomalous requests",
            "correlates the auth log to the attacker session",
            "extracts the payload strings tied to the exploit",
            "identifies the exploited CVE from the evidence",
            "assembles the indicators of compromise into the flag",
        ),
    ),
    "mobile_insecure_storage": (
        (
            "Locate the hardcoded cipher key in the decompiled sources (CWE-798)",
            "Recover the sensitive note from SharedPreferences and the device backup (CWE-312)",
            "Decrypt the note to obtain the flag",
        ),
        (
            "decompiles the app and reviews the storage code",
            "finds the hardcoded encryption key",
            "extracts the ciphertext from SharedPreferences or the backup",
            "decrypts the note with the recovered key",
            "reads the flag from the decrypted plaintext",
        ),
    ),
    "scada_ics_modbus_takeover": (
        (
            "Enumerate coils and holding registers on an unauthenticated Modbus/TCP PLC (CWE-306)",
            "Disable the safety-interlock coil guarding the control logic",
            "Push a setpoint register past its safe limit to bypass the interlock",
        ),
        (
            "connects to the PLC and enumerates coils and holding registers",
            "identifies the safety-interlock coil and the setpoint register",
            "clears the interlock coil",
            "writes an out-of-range setpoint to trigger the control-logic bypass",
            "reads the exposed flag",
        ),
    ),
}

def _http_defense_scenario(
    detect_id: str,
    detect_desc: str,
    patch_id: str,
    patch_desc: str,
    target: str,
) -> ScenarioSpec:
    """A two-stage blue-team reaction against an HTTP attack surface.

    Stage 1 (tick>=1): the SOC detects the intrusion. Stage 2 (tick>=2): the
    blue team hardens ``target`` -- a STABLE substring of the challenge's own
    attack surface -- so any request the attacker's plan sends to it after that
    point is refused (403) mid-solve. Triggers are time-based so the timeline
    fires deterministically offline (`run-scenario`) with no exogenous events,
    and the paired trigger/response lists let ``_default_defender_from_spec``
    build the defender automatically.
    """
    return ScenarioSpec(
        enabled=True,
        triggers=[
            TriggerSpec(trigger_id=detect_id, description=detect_desc, condition="time:>=1"),
            TriggerSpec(trigger_id=patch_id, description=patch_desc, condition="time:>=2"),
        ],
        responses=[
            ResponseSpec(
                response_id=f"{detect_id}-alert",
                description="Raise an incident alert (observability only).",
                action="notify",
                payload={"target": target},
            ),
            ResponseSpec(
                response_id=f"{patch_id}-block",
                description=patch_desc,
                action="patch_route",
                payload={"target": target},
            ),
        ],
    )


# Per-family default live-adversarial scenarios, keyed by FAMILY_NAME. Only
# families with a live HTTP attack surface ship one today; the target is a
# stable path/host substring every solver of that family must touch.
_FAMILY_SCENARIOS: dict[str, ScenarioSpec] = {
    "crypto_token_forgery": _http_defense_scenario(
        "ir-detect-forged-token",
        "SOC flags anomalous alg:none tokens hitting the admin console",
        "ir-lock-admin-route",
        "Blue team requires re-authentication on the admin route",
        target="/api/admin/",
    ),
    "cloud_metadata_ssrf": _http_defense_scenario(
        "ir-detect-ssrf-egress",
        "SOC detects SSRF egress toward the instance metadata endpoint",
        "ir-quarantine-internal-storage",
        "Blue team quarantines the internal object store after the SSRF",
        target="/internal/objects",
    ),
}


for _module in (scada_ics, network, crypto, cloud, forensics, binary, mobile):
    _objectives, _checkpoints = _FAMILY_SPEC_DEFAULTS.get(
        _module.FAMILY_NAME, (tuple(_DEFAULT_OBJECTIVES), tuple(_DEFAULT_CHECKPOINTS))
    )
    register(
        Family(
            name=_module.FAMILY_NAME,
            category=_module.CATEGORY,
            modes=_module.MODES,
            render=_module.render,
            required_files=tuple(_module.REQUIRED_FILES),
            compose_service_markers=tuple(_module.COMPOSE_MARKERS),
            difficulties=_module.DIFFICULTIES,
            cve_driven=_module.CVE_DRIVEN,
            llm_brief=_module.LLM_BRIEF,
            scoring_hints=ScoringHints(**_module.SCORING_HINTS),
            learning_objectives=_objectives,
            checkpoints=_checkpoints,
            default_scenario=_FAMILY_SCENARIOS.get(_module.FAMILY_NAME),
        )
    )

del _module
