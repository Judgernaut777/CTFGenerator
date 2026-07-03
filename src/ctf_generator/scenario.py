"""Scripted, deterministic live-adversarial scenario engine.

This is the offline "core" of the Phase-5 live-adversarial engine described by
``ChallengeSpec.ai_resistance.live_adversarial_engine`` and ``ChallengeSpec.scenario``
(see ``models.py``): a blue team (defender) reacting live to a red team
(attacker), or vice versa, so a static writeup goes stale mid-solve.

Everything here is pure, offline and deterministic:

* No Docker, no HTTP, no subprocess, no wall clock, no ``random`` module.
* Every external effect (environment mutation, the passage of "time", the
  stream of observed/attacker events) sits behind an injectable Protocol,
  mirroring ``runtime_validator.CommandRunner`` and the injectable clients in
  ``spec_generator.py``. Tests supply deterministic fakes; a future phase can
  supply real ones (talking to Docker, a real clock, etc.) without touching
  this module's logic.
* Same inputs (same scripted ``EventSource``, same agents, same
  ``max_ticks``) always produce a byte-identical ``ScenarioRunReport``
  timeline: there is no hidden randomness or nondeterministic ordering.

Two internal, single-run types anchor the engine: ``SimEvent`` and
``SimEventBus``. These are explicitly **not** ``events.Event`` /
``events.EventStore`` -- that pair is the persistent, cross-competition JSONL
log written by the running platform. ``SimEvent`` only exists for the
lifetime of one ``run_scenario`` call, in memory, and is never appended to
the competition event store.

Condition DSL
-------------

``TriggerSpec.condition`` (and the attacker-move preconditions used by
``ScriptedAttacker``) are small strings interpreted by ``evaluate_condition``.
Clauses are joined with ``&&`` (all must hold); supported clause forms:

* ``""``                       -- always true (no condition)
* ``time:+Ns`` / ``time:>=N`` / ``time:<=N`` / ``time:==N`` / ``time:<N`` /
  ``time:>N`` -- compares the current tick to N (trailing ``s`` optional)
* ``event:<kind>``              -- any event of this kind seen so far
* ``event:<source>:<kind>``     -- any event from this source with this kind
* ``checkpoint:<name>``         -- the named checkpoint has been reached
* ``state:<key>=<value>``       -- ``state.flags[key] == value``
* ``state:<key>!=<value>``      -- ``state.flags[key] != value``
* ``count:<kind><op><N>``       -- count of events of ``<kind>`` compares to
  N, where ``<op>`` is one of ``>= <= == != > <``

``ResponseSpec.payload`` stays a plain ``dict[str, str]`` (per ``models.py``),
so declarative state mutation uses a mini string format rather than nested
dicts: ``payload["sets"] = "cred:api-token=stolen,route:x=patched"``.

Note on ``challenge_path``: this module performs no filesystem access on it.
It is accepted (and echoed back on the report) purely so callers/tests can
identify which challenge a run belongs to; there is no full YAML round-trip
reader for ``ScenarioSpec`` yet (only ``models.ScenarioSpec.to_mapping()`` /
``yaml_writer.dump_yaml`` for the write side), so a ``spec`` should be passed
in explicitly by the caller.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .models import ResponseSpec, ScenarioSpec, TriggerSpec

DEFAULT_MAX_TICKS = 20


def seed_to_int(seed: str) -> int:
    """Deterministic seed -> int, same technique as ``generator._seed_int``.

    Duplicated here (not imported) per this project's file-ownership rules:
    ``scenario.py`` must not import from ``generator.py``.
    """
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return int(digest[:16], 16)


# --- Single-run event types (NOT events.Event) --------------------------------


@dataclass(frozen=True)
class SimEvent:
    """A single-run, in-memory scenario event.

    Explicitly not ``events.Event``: this type never touches the persistent
    competition event log and only lives for one ``run_scenario`` call.
    """

    tick: int
    source: str
    kind: str
    target: str = ""
    payload: dict[str, str] = field(default_factory=dict)

    def to_mapping(self) -> dict[str, object]:
        return {
            "tick": self.tick,
            "source": self.source,
            "kind": self.kind,
            "target": self.target,
            "payload": dict(self.payload),
        }


@dataclass
class SimEventBus:
    """Ordered, append-only record of ``SimEvent``s for one scenario run."""

    _events: list[SimEvent] = field(default_factory=list)

    def publish(self, event: SimEvent) -> None:
        self._events.append(event)

    def all(self) -> list[SimEvent]:
        return list(self._events)

    def at_tick(self, tick: int) -> list[SimEvent]:
        return [event for event in self._events if event.tick == tick]

    def since_tick(self, tick: int) -> list[SimEvent]:
        return [event for event in self._events if event.tick > tick]


@dataclass
class ScenarioState:
    """Mutable state accumulated across ticks of one scenario run.

    Convention: agents (``Agent.decide``) treat this as read-only and only
    *propose* ``ResponseSpec``s; ``run_scenario`` is the sole mutator, applying
    effects (flags, checkpoints, fired triggers) after collecting each tick's
    decisions. This keeps ``decide()`` implementations simple, pure functions
    of (tick, events-so-far, state-snapshot).
    """

    tick: int = 0
    checkpoints: set[str] = field(default_factory=set)
    flags: dict[str, str] = field(default_factory=dict)
    fired_triggers: set[str] = field(default_factory=set)
    noise_count: int = 0


# --- Injectable protocols -------------------------------------------------------


class EnvironmentController(Protocol):
    """Effects a scenario can have on the (real or simulated) environment."""

    def rotate_credential(self, target: str, params: dict) -> SimEvent: ...

    def patch_route(self, target: str, params: dict) -> SimEvent: ...

    def quarantine_host(self, target: str, params: dict) -> SimEvent: ...

    def inject_noise(self, target: str, params: dict) -> SimEvent: ...


class EventSource(Protocol):
    """Feed of exogenous events (attacker probes, sensors, telemetry, ...)."""

    def poll(self, tick: int) -> list[SimEvent]: ...


class Agent(Protocol):
    """A rule-driven participant (defender or attacker) in the scenario."""

    def decide(
        self, tick: int, events: list[SimEvent], state: ScenarioState
    ) -> list[ResponseSpec]: ...


# --- Null environment (records intent, does nothing) ---------------------------


class NullEnvironmentController:
    """No-op ``EnvironmentController``: records intended actions, does nothing.

    For dry runs and tests where there is no real infrastructure to mutate.
    """

    def __init__(self) -> None:
        self.recorded: list[tuple[str, str, dict]] = []

    def rotate_credential(self, target: str, params: dict) -> SimEvent:
        return self._record("rotate_credential", target, params)

    def patch_route(self, target: str, params: dict) -> SimEvent:
        return self._record("patch_route", target, params)

    def quarantine_host(self, target: str, params: dict) -> SimEvent:
        return self._record("quarantine_host", target, params)

    def inject_noise(self, target: str, params: dict) -> SimEvent:
        return self._record("inject_noise", target, params)

    def _record(self, action: str, target: str, params: dict) -> SimEvent:
        self.recorded.append((action, target, dict(params)))
        # tick=0 is a placeholder; run_scenario always re-stamps it with the
        # actual current tick before publishing.
        return SimEvent(tick=0, source="environment", kind=action, target=target, payload=dict(params))


# --- Scripted event source -------------------------------------------------------


class ReplayEventSource:
    """Deterministic, pre-scripted feed of events keyed by tick.

    ``script`` maps a tick number to the ``SimEvent``s that "arrive" at that
    tick (e.g. attacker probes discovered by a sensor, or externally observed
    telemetry). Ticks absent from the script yield an empty list. Polling the
    same tick repeatedly returns equal results every time.
    """

    def __init__(self, script: dict[int, list[SimEvent]]) -> None:
        self._script: dict[int, list[SimEvent]] = {
            tick: list(events) for tick, events in script.items()
        }

    def poll(self, tick: int) -> list[SimEvent]:
        return list(self._script.get(tick, []))


# --- Scripted agents --------------------------------------------------------------


@dataclass(frozen=True)
class AttackerMove:
    """One scripted step of a ``ScriptedAttacker``'s plan.

    ``response`` is proposed at exactly ``tick``. If ``precondition`` is set
    and evaluates false against the accumulated events/state, the move is
    blocked: a synthetic ``ResponseSpec`` with ``action="blocked"`` is
    proposed instead (carrying the intended action and the failed
    precondition in its payload), so a disruption is directly observable in
    the resulting timeline without special-casing in ``run_scenario``.
    """

    tick: int
    response: ResponseSpec
    precondition: str = ""


class ScriptedAttacker:
    """Rule-driven attacker: a fixed, deterministic plan of ``AttackerMove``s."""

    def __init__(self, moves: list[AttackerMove]) -> None:
        self._moves = sorted(moves, key=lambda move: move.tick)

    def decide(
        self, tick: int, events: list[SimEvent], state: ScenarioState
    ) -> list[ResponseSpec]:
        decisions: list[ResponseSpec] = []
        for move in self._moves:
            if move.tick != tick:
                continue
            if move.precondition and not evaluate_condition(
                move.precondition, tick, events, state
            ):
                # Deliberately do NOT copy the intended response's full
                # payload: "checkpoint"/"sets" describe effects of the move
                # actually happening, and a blocked move must not apply them.
                blocked_payload = {
                    "target": move.response.payload.get("target", ""),
                    "intended_action": move.response.action,
                    "reason": move.precondition,
                }
                decisions.append(
                    ResponseSpec(
                        response_id=f"{move.response.response_id}-blocked",
                        description=f"blocked: {move.response.description}",
                        action="blocked",
                        payload=blocked_payload,
                    )
                )
                continue
            decisions.append(move.response)
        return decisions


class ScriptedDefender:
    """Rule-driven defender: evaluates ``TriggerSpec`` conditions each tick.

    ``trigger_responses`` maps a ``trigger_id`` to the ``ResponseSpec``s it
    fires. A trigger already recorded in ``state.fired_triggers`` is not
    re-evaluated (each trigger fires at most once per run). Every returned
    ``ResponseSpec`` has its originating ``trigger_id`` stamped into a copy of
    its payload, so ``run_scenario`` can update ``state.fired_triggers`` and
    ``ScenarioRunReport.triggers_fired`` without duplicating condition logic.
    """

    def __init__(
        self,
        triggers: list[TriggerSpec],
        trigger_responses: dict[str, list[ResponseSpec]],
    ) -> None:
        self._triggers = list(triggers)
        self._trigger_responses = {
            trigger_id: list(responses) for trigger_id, responses in trigger_responses.items()
        }

    def decide(
        self, tick: int, events: list[SimEvent], state: ScenarioState
    ) -> list[ResponseSpec]:
        decisions: list[ResponseSpec] = []
        for trigger in self._triggers:
            if trigger.trigger_id in state.fired_triggers:
                continue
            if not evaluate_condition(trigger.condition, tick, events, state):
                continue
            for response in self._trigger_responses.get(trigger.trigger_id, []):
                payload = dict(response.payload)
                payload["trigger_id"] = trigger.trigger_id
                decisions.append(dataclasses.replace(response, payload=payload))
        return decisions


# --- Condition DSL -----------------------------------------------------------------

_TIME_RE = re.compile(r"^(?P<op>\+|>=|<=|==|<|>)(?P<num>\d+)s?$")
_STATE_RE = re.compile(r"^(?P<key>[^=!]+?)(?P<op>!=|=)(?P<value>.*)$")
_COUNT_RE = re.compile(r"^(?P<kind>[^><=!]+?)(?P<op>>=|<=|==|!=|>|<)(?P<num>\d+)$")


def evaluate_condition(
    condition: str, tick: int, events: list[SimEvent], state: ScenarioState
) -> bool:
    """Evaluate a ``TriggerSpec.condition`` (or attacker precondition) string.

    See the module docstring for the supported clause grammar. Raises
    ``ValueError`` for an unrecognized clause so a scripted scenario fails
    loudly (at run time) rather than silently never firing.
    """
    condition = condition.strip()
    if not condition:
        return True
    return all(
        _evaluate_clause(clause, tick, events, state) for clause in condition.split("&&")
    )


def _evaluate_clause(
    clause: str, tick: int, events: list[SimEvent], state: ScenarioState
) -> bool:
    clause = clause.strip()
    if not clause:
        return True
    prefix, sep, rest = clause.partition(":")
    if not sep:
        raise ValueError(f"unrecognized condition clause: {clause!r}")
    if prefix == "time":
        return _evaluate_time(rest, tick)
    if prefix == "event":
        return _evaluate_event(rest, events)
    if prefix == "checkpoint":
        return rest.strip() in state.checkpoints
    if prefix == "state":
        return _evaluate_state(rest, state)
    if prefix == "count":
        return _evaluate_count(rest, events)
    raise ValueError(f"unrecognized condition clause: {clause!r}")


def _evaluate_time(expr: str, tick: int) -> bool:
    match = _TIME_RE.match(expr.strip())
    if not match:
        raise ValueError(f"invalid time condition: 'time:{expr}'")
    op = match.group("op")
    num = int(match.group("num"))
    if op in ("+", ">="):
        return tick >= num
    if op == "<=":
        return tick <= num
    if op == "==":
        return tick == num
    if op == "<":
        return tick < num
    return tick > num  # op == ">"


def _evaluate_event(expr: str, events: list[SimEvent]) -> bool:
    parts = expr.split(":")
    if len(parts) == 1:
        kind = parts[0].strip()
        return any(event.kind == kind for event in events)
    if len(parts) == 2:
        source, kind = (part.strip() for part in parts)
        return any(event.source == source and event.kind == kind for event in events)
    raise ValueError(f"invalid event condition: 'event:{expr}'")


def _evaluate_state(expr: str, state: ScenarioState) -> bool:
    match = _STATE_RE.match(expr)
    if not match:
        raise ValueError(f"invalid state condition: 'state:{expr}'")
    key = match.group("key").strip()
    op = match.group("op")
    value = match.group("value").strip()
    actual = state.flags.get(key)
    if op == "!=":
        return actual != value
    return actual == value


def _evaluate_count(expr: str, events: list[SimEvent]) -> bool:
    match = _COUNT_RE.match(expr)
    if not match:
        raise ValueError(f"invalid count condition: 'count:{expr}'")
    kind = match.group("kind").strip()
    op = match.group("op")
    num = int(match.group("num"))
    actual = sum(1 for event in events if event.kind == kind)
    if op == ">=":
        return actual >= num
    if op == "<=":
        return actual <= num
    if op == "==":
        return actual == num
    if op == "!=":
        return actual != num
    if op == ">":
        return actual > num
    return actual < num  # op == "<"


def _parse_sets(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        key, sep, value = pair.partition("=")
        if not sep:
            continue
        result[key.strip()] = value.strip()
    return result


# --- Run report ---------------------------------------------------------------------


@dataclass(frozen=True)
class ScenarioResponseRecord:
    """One applied ``ResponseSpec``, stamped with when/who applied it."""

    tick: int
    role: str
    response_id: str
    action: str
    target: str


@dataclass
class ScenarioRunReport:
    """Result of one ``run_scenario`` call."""

    challenge_path: str
    ticks_run: int = 0
    timeline: list[SimEvent] = field(default_factory=list)
    triggers_fired: list[str] = field(default_factory=list)
    responses_applied: list[ScenarioResponseRecord] = field(default_factory=list)
    attacker_blocked: list[str] = field(default_factory=list)
    final_state: ScenarioState | None = None

    @property
    def defender_disrupted_attacker(self) -> bool:
        """Whether any scripted attacker move was blocked during this run."""
        return bool(self.attacker_blocked)


# --- Environment-action bookkeeping --------------------------------------------

_ENV_ACTIONS = {"rotate_credential", "patch_route", "quarantine_host", "inject_noise"}
_ENV_FLAG_PREFIX = {
    "rotate_credential": "cred",
    "patch_route": "route",
    "quarantine_host": "host",
    "inject_noise": "noise",
}
_ENV_FLAG_STATUS = {
    "rotate_credential": "rotated",
    "patch_route": "patched",
    "quarantine_host": "quarantined",
}


def _apply_responses(
    responses: list[ResponseSpec],
    role: str,
    tick: int,
    bus: SimEventBus,
    state: ScenarioState,
    environment: EnvironmentController,
    report: ScenarioRunReport,
) -> None:
    for response in responses:
        target = response.payload.get("target", "")
        if response.action in _ENV_ACTIONS:
            method = getattr(environment, response.action)
            event = method(target, dict(response.payload))
            event = dataclasses.replace(event, tick=tick)
            if response.action == "inject_noise":
                state.noise_count += 1
                state.flags[f"{_ENV_FLAG_PREFIX[response.action]}:{target}"] = str(
                    state.noise_count
                )
            else:
                state.flags[f"{_ENV_FLAG_PREFIX[response.action]}:{target}"] = _ENV_FLAG_STATUS[
                    response.action
                ]
        else:
            event = SimEvent(
                tick=tick,
                source=role,
                kind=response.action,
                target=target,
                payload=dict(response.payload),
            )

        bus.publish(event)
        report.timeline.append(event)
        report.responses_applied.append(
            ScenarioResponseRecord(
                tick=tick,
                role=role,
                response_id=response.response_id,
                action=response.action,
                target=target,
            )
        )

        for key, value in _parse_sets(response.payload.get("sets", "")).items():
            state.flags[key] = value

        checkpoint = response.payload.get("checkpoint", "")
        if checkpoint:
            state.checkpoints.add(checkpoint)

        trigger_id = response.payload.get("trigger_id", "")
        if trigger_id and trigger_id not in state.fired_triggers:
            state.fired_triggers.add(trigger_id)
            report.triggers_fired.append(trigger_id)

        if response.action == "blocked":
            report.attacker_blocked.append(response.response_id)


def _default_defender_from_spec(spec: ScenarioSpec) -> Agent | None:
    """Best-effort ``ScriptedDefender`` built from a flat ``ScenarioSpec``.

    ``ScenarioSpec`` stores ``triggers`` and ``responses`` as two parallel
    lists with no explicit trigger->response mapping. When their lengths
    match, we pair them by index (``triggers[i]`` fires ``responses[i]``).
    Otherwise the mapping is ambiguous and no default defender is built --
    callers with a richer mapping should construct a ``ScriptedDefender``
    directly and pass it as ``defender``.
    """
    if not spec.enabled or not spec.triggers:
        return None
    if len(spec.triggers) != len(spec.responses):
        return None
    mapping: dict[str, list[ResponseSpec]] = {
        trigger.trigger_id: [response]
        for trigger, response in zip(spec.triggers, spec.responses)
    }
    return ScriptedDefender(spec.triggers, mapping)


# --- Entry point -----------------------------------------------------------------


def run_scenario(
    challenge_path: Path | str,
    environment: EnvironmentController,
    events: EventSource,
    defender: Agent | None = None,
    attacker: Agent | None = None,
    spec: ScenarioSpec | None = None,
    max_ticks: int | None = None,
) -> ScenarioRunReport:
    """Run a scripted, deterministic scenario timeline.

    Each tick, in order:

    1. ``events.poll(tick)`` supplies exogenous events (sensor telemetry,
       scripted attacker probes, ...), published to the run's event bus.
    2. ``attacker.decide(...)`` (if provided) proposes this tick's attacker
       actions; they are applied immediately (so an attacker action is
       visible to the defender within the same tick).
    3. ``defender.decide(...)`` (if provided) proposes this tick's defender
       actions, evaluated against everything published so far this tick
       (including the attacker's own actions); they are applied immediately.

    If ``defender`` is omitted and ``spec`` describes an unambiguous
    trigger->response pairing (see ``_default_defender_from_spec``), a
    ``ScriptedDefender`` is built from it automatically. ``attacker`` has no
    such default: ``ScenarioSpec`` has no notion of an attacker plan, so a
    caller wanting scripted attacker behavior must construct a
    ``ScriptedAttacker`` (or other ``Agent``) explicitly.

    Runs for exactly ``max_ticks`` ticks (default ``DEFAULT_MAX_TICKS``) --
    fully deterministic, no early-exit heuristics, so the same inputs always
    produce the same number of ticks and a byte-identical timeline.
    """
    resolved_spec = spec if spec is not None else ScenarioSpec()
    ticks = max_ticks if max_ticks is not None else DEFAULT_MAX_TICKS
    if defender is None:
        defender = _default_defender_from_spec(resolved_spec)

    bus = SimEventBus()
    state = ScenarioState()
    report = ScenarioRunReport(challenge_path=str(challenge_path))

    for tick in range(ticks):
        state.tick = tick

        for polled in events.poll(tick):
            stamped = polled if polled.tick == tick else dataclasses.replace(polled, tick=tick)
            bus.publish(stamped)
            report.timeline.append(stamped)

        if attacker is not None:
            attacker_responses = attacker.decide(tick, bus.all(), state)
            _apply_responses(attacker_responses, "attacker", tick, bus, state, environment, report)

        if defender is not None:
            defender_responses = defender.decide(tick, bus.all(), state)
            _apply_responses(defender_responses, "defender", tick, bus, state, environment, report)

    report.ticks_run = ticks
    report.final_state = state
    return report
