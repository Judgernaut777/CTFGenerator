"""AI-agent evaluation harness.

Measures how an AI agent fares against a *generated* challenge -- using only
the challenge's public surface (``public/description.md``, ``public/hints.yaml``
and live HTTP access to the running app), never ``private/`` -- and how much
the live-adversarial scenario engine (``scenario.py``) degrades that success.
This is the empirical AI-resistance signal: a challenge with a large
"solved without defense" vs "solved with defense" gap is meaningfully
resistant to a scripted/live-reacting adversary, not just to a static
writeup.

CLI-ONLY / SECURITY: this module drives Docker and subprocess (through the
same injectable ``CommandRunner`` used by ``runtime_validator.py``) and MUST
NEVER be imported from ``mcp_server.py`` -- a Phase-4/5 regression test in
``tests/test_mcp_server.py`` enforces this.

Every external effect (Docker/subprocess, HTTP, the wall clock, randomness)
sits behind an injectable Protocol or callable with a deterministic fake
available for tests:

* Docker/subprocess -- ``runtime_validator.CommandRunner`` (reused, not
  redefined).
* HTTP -- :class:`HTTPClient` (default: stdlib ``urllib``).
* Agent decision-making -- :class:`SolverAgent` (default:
  :class:`ScriptedSolverAgent`, a deterministic baseline; an optional
  :class:`LlmSolverAgent` stub lazily imports the ``anthropic``/``openai``
  SDKs and is never required at import time).
* The live-adversarial condition -- ``scenario.run_scenario`` (already
  fully offline/deterministic; see ``scenario.py``).

Nothing in this module uses the ``random`` module's global state or the
wall clock to make *decisions*: ``ScriptedSolverAgent`` is a pure function of
(the public challenge files, the HTTP responses it receives). Wall-clock
reads (``time.monotonic``) are used only for Docker orchestration timeouts
and the reported ``elapsed_wall_seconds``, mirroring ``runtime_validator.py``
-- never for control flow that would make a report non-reproducible under a
fake ``HTTPClient``/``CommandRunner``.
"""

from __future__ import annotations

import json
import random
import re
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from .models import ScenarioSpec
from .runtime_validator import CommandRunner, RuntimeValidationReport, _record, _run, _wait_for_health
from .scenario import (
    Agent as ScenarioAgent,
    EnvironmentController,
    EventSource,
    NullEnvironmentController,
    ReplayEventSource,
    ScenarioRunReport,
    run_scenario,
)
from .validator import validate_challenge

# A ``ctf{...}`` flag literal, the convention shared by every template in
# ``templates/`` (see e.g. ``templates/tenant_export.py``'s
# ``f"ctf{{tenant_worker_trust_{...}}}"``).
FLAG_PATTERN = re.compile(r"ctf\{[^{}\s]{1,160}\}")


# --- HTTP client ------------------------------------------------------------------


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    body: str
    headers: dict[str, str] = field(default_factory=dict)


class HTTPClient(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> HTTPResponse: ...


class UrllibHTTPClient:
    """Default ``HTTPClient``: stdlib ``urllib`` only, no third-party deps."""

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> HTTPResponse:
        data = None
        req_headers = dict(headers or {})
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        request = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                return HTTPResponse(
                    status=response.status, body=body, headers=dict(response.headers)
                )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            return HTTPResponse(status=exc.code, body=body, headers=dict(exc.headers or {}))
        except urllib.error.URLError as exc:
            return HTTPResponse(status=0, body=str(exc.reason), headers={})


def _default_http() -> HTTPClient:
    return UrllibHTTPClient()


# --- Solver agents ------------------------------------------------------------------


@dataclass
class AgentTranscript:
    solved: bool
    steps: int
    flag: str | None
    log: list[str] = field(default_factory=list)


class SolverAgent(Protocol):
    name: str

    def solve(
        self,
        *,
        base_url: str,
        public_dir: Path,
        http: HTTPClient,
        rng: random.Random,
        max_steps: int,
        deadline: float,
    ) -> AgentTranscript: ...


# Backtick-quoted "METHOD /path" and "Header-Name: literal-value" hints, the
# convention used across ``public/description.md`` (see e.g.
# ``templates/tenant_export.py``'s ``_description``: "- `GET /api/profile`",
# "Use the `X-User: {v.attacker_user}` request header."). Reading only
# ``public/`` (never ``private/solution.md``) is what makes this an honest
# "agent that hasn't seen the answer" baseline.
_METHOD_PATH_RE = re.compile(r"`(GET|POST|PUT|PATCH|DELETE)\s+([^`\s]+)`")
_HEADER_RE = re.compile(r"`([A-Za-z][A-Za-z0-9-]*):\s*([^`<>]+)`")

_DEFAULT_CANDIDATE_PATHS: tuple[str, ...] = ("/", "/healthz", "/api/health", "/flag", "/api/flag")


def _extract_plan(text: str) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Best-effort extraction of (method, path) candidates and headers.

    Pure function of ``text`` -- no filesystem/network access -- so it is
    trivially unit-testable and deterministic.
    """
    candidates: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for method, path in _METHOD_PATH_RE.findall(text):
        pair = (method, path)
        if pair not in seen:
            seen.add(pair)
            candidates.append(pair)

    headers: dict[str, str] = {}
    for name, value in _HEADER_RE.findall(text):
        if name in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            continue
        headers[name] = value.strip()

    if not candidates:
        candidates = [("GET", path) for path in _DEFAULT_CANDIDATE_PATHS]

    return candidates, headers


class ScriptedSolverAgent:
    """Deterministic baseline agent: follows a fixed plan read from ``public/``.

    Reads ``public/description.md`` and ``public/hints.yaml`` (whichever
    exist), extracts a small, ordered list of ``(method, path)`` candidates
    and literal header hints via :func:`_extract_plan`, then tries each
    candidate (bounded by ``max_steps``) against the live app, attaching
    every discovered header to every request. The first response whose body
    contains a :data:`FLAG_PATTERN` match ends the run successfully.

    This deliberately does *not* adapt to responses (no chained/multi-hop
    exploitation) -- it models a "read the writeup once, replay it" agent,
    which is exactly the baseline the live-adversarial engine is meant to
    beat: a scenario that rotates a credential or patches a route out from
    under a fixed plan should measurably reduce this agent's success (see
    :func:`run_adversarial_delta`).
    """

    name = "scripted"

    def solve(
        self,
        *,
        base_url: str,
        public_dir: Path,
        http: HTTPClient,
        rng: random.Random,
        max_steps: int,
        deadline: float,
    ) -> AgentTranscript:
        text = ""
        for relative in ("description.md", "hints.yaml"):
            candidate = public_dir / relative
            if candidate.exists():
                text += candidate.read_text(encoding="utf-8") + "\n"

        candidates, headers = _extract_plan(text)

        log: list[str] = []
        steps = 0
        for method, path in candidates:
            if steps >= max_steps:
                break
            if time.monotonic() > deadline:
                log.append("deadline exceeded")
                break
            steps += 1
            url = base_url.rstrip("/") + path
            response = http.request(method, url, headers=dict(headers))
            log.append(f"{method} {path} -> {response.status}")
            match = FLAG_PATTERN.search(response.body)
            if match:
                log.append(f"flag found: {match.group(0)}")
                return AgentTranscript(solved=True, steps=steps, flag=match.group(0), log=log)

        return AgentTranscript(solved=False, steps=steps, flag=None, log=log)


class LlmSolverAgent:
    """Optional LLM-driven agent. Lazily imports ``anthropic``/``openai``.

    Never imported/required by the rest of this module or by
    :data:`EVAL_PROFILES` -- constructing this class does not require either
    SDK to be installed; only calling :meth:`solve` does, at which point a
    missing extra fails loudly with a clear message instead of a bare
    ``ModuleNotFoundError`` deep in ``sys.path`` resolution.
    """

    name = "llm"

    def __init__(self, provider: str = "anthropic", model: str = "") -> None:
        if provider not in ("anthropic", "openai"):
            raise ValueError(f"unsupported provider: {provider!r}")
        self.provider = provider
        self.model = model

    def _client(self):
        if self.provider == "anthropic":
            try:
                import anthropic  # type: ignore
            except ImportError as exc:  # pragma: no cover - exercised only with extra installed
                raise ImportError(
                    "LlmSolverAgent(provider='anthropic') requires the 'anthropic' package; "
                    "install the ctf_generator[llm-anthropic] extra"
                ) from exc
            return anthropic.Anthropic()
        try:
            import openai  # type: ignore
        except ImportError as exc:  # pragma: no cover - exercised only with extra installed
            raise ImportError(
                "LlmSolverAgent(provider='openai') requires the 'openai' package; "
                "install the ctf_generator[llm-openai] extra"
            ) from exc
        return openai.OpenAI()

    def solve(
        self,
        *,
        base_url: str,
        public_dir: Path,
        http: HTTPClient,
        rng: random.Random,
        max_steps: int,
        deadline: float,
    ) -> AgentTranscript:
        # A real implementation would drive a multi-turn tool-use loop
        # (propose an HTTP request, execute it via ``http``, feed the
        # response back). Left intentionally minimal: this stub exists so
        # ``EVAL_PROFILES``/callers have a documented extension point without
        # forcing every install to carry an LLM SDK dependency.
        self._client()
        raise NotImplementedError("LlmSolverAgent.solve is a stub; supply a custom SolverAgent")


# --- Eval profiles --------------------------------------------------------------------


@dataclass(frozen=True)
class EvalProfile:
    """A named agent-eval configuration: which agent, how much budget."""

    name: str
    agent_factory: Callable[[], SolverAgent]
    max_steps: int
    timeout_seconds: float
    description: str = ""


EVAL_PROFILES: dict[str, EvalProfile] = {
    "one_shot_prompt": EvalProfile(
        name="one_shot_prompt",
        agent_factory=ScriptedSolverAgent,
        max_steps=1,
        timeout_seconds=30.0,
        description="Single best-guess request, no iteration -- models a one-shot LLM prompt.",
    ),
    "writeup_replay": EvalProfile(
        name="writeup_replay",
        agent_factory=ScriptedSolverAgent,
        max_steps=8,
        timeout_seconds=60.0,
        description="Replays the fixed plan extracted from public/ without adapting to responses.",
    ),
    "tool_using_agent": EvalProfile(
        name="tool_using_agent",
        agent_factory=ScriptedSolverAgent,
        max_steps=20,
        timeout_seconds=90.0,
        description="Larger step budget, models an iterative tool-calling agent.",
    ),
}

# Docker-compose project-name suffix for the "defense on" leg of
# ``run_adversarial_delta``, so its container stack never collides with the
# baseline ("defense off") leg's project name when both could in principle
# run concurrently.
ADVERSARIAL_COMPOSE_PROFILE = "adversarial"


def list_eval_profiles() -> list[str]:
    return sorted(EVAL_PROFILES)


# --- Report types -----------------------------------------------------------------


@dataclass
class AgentEvalReport:
    profile: str
    solved: bool = False
    steps: int = 0
    elapsed_ticks: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class AdversarialDeltaReport:
    """Result of comparing an eval with the scenario engine off vs on."""

    challenge_path: str
    profile: str
    baseline: AgentEvalReport
    adversarial: AgentEvalReport
    scenario_report: ScenarioRunReport
    notes: list[str] = field(default_factory=list)

    @property
    def success_dropped(self) -> bool:
        """Whether live defense flipped a solve into a non-solve."""
        return self.baseline.solved and not self.adversarial.solved

    @property
    def step_delta(self) -> int:
        """Extra steps the agent burned under live defense (can be negative)."""
        return self.adversarial.steps - self.baseline.steps


# --- run_agent_eval -----------------------------------------------------------------


def _project_name(challenge_path: Path, suffix: str = "") -> str:
    base = f"ctfgen-eval-{challenge_path.name}"
    if suffix:
        base += f"-{suffix}"
    return base.replace("_", "-").lower()


def run_agent_eval(
    challenge_path: Path,
    profile: str,
    base_url: str = "http://127.0.0.1:8080",
    timeout_seconds: int = 90,
    keep_running: bool = False,
    runner: CommandRunner | None = None,
    http: HTTPClient | None = None,
    rng: random.Random | None = None,
    agent: SolverAgent | None = None,
    already_running: bool = False,
    compose_suffix: str = "",
) -> AgentEvalReport:
    """Run one agent against one generated, live challenge instance.

    When ``already_running`` is ``False`` (the default), this builds/launches
    the challenge's Docker stack via ``runner`` (an injectable
    ``runtime_validator.CommandRunner``, reused verbatim -- never
    reimplemented) exactly like ``runtime_validator.validate_runtime``, waits
    for its health check, runs the agent, then tears the stack down (unless
    ``keep_running``). When ``already_running`` is ``True``, all of that is
    skipped and the agent is simply pointed at ``base_url`` -- the mode used
    by the (offline, Docker-free) test suite and by :func:`run_adversarial_delta`,
    which drives two agent runs against one already-running fixture.
    """
    if profile not in EVAL_PROFILES:
        raise ValueError(f"unknown eval profile: {profile!r}; choices: {list_eval_profiles()}")

    eval_profile = EVAL_PROFILES[profile]
    resolved_agent = agent or eval_profile.agent_factory()
    resolved_http = http or _default_http()
    resolved_rng = rng if rng is not None else random.Random(0)
    resolved_runner = runner or _run

    report = AgentEvalReport(profile=profile)

    static_report = validate_challenge(challenge_path)
    if static_report.errors:
        report.notes.extend(f"static validation error: {error}" for error in static_report.errors)
        return report

    project_name = _project_name(challenge_path, compose_suffix)
    started = False
    try:
        if not already_running:
            shim = RuntimeValidationReport(logs=report.notes)
            _record(
                shim,
                resolved_runner(
                    ["docker", "compose", "-p", project_name, "build"], challenge_path, timeout_seconds
                ),
            )
            _record(
                shim,
                resolved_runner(
                    ["docker", "compose", "-p", project_name, "up", "-d"], challenge_path, timeout_seconds
                ),
            )
            started = True
            _wait_for_health(challenge_path, base_url, timeout_seconds, resolved_runner, shim)

        deadline = time.monotonic() + eval_profile.timeout_seconds
        transcript = resolved_agent.solve(
            base_url=base_url,
            public_dir=challenge_path / "public",
            http=resolved_http,
            rng=resolved_rng,
            max_steps=eval_profile.max_steps,
            deadline=deadline,
        )
        report.solved = transcript.solved
        report.steps = transcript.steps
        report.elapsed_ticks = transcript.steps
        report.notes.extend(transcript.log)
    except subprocess.CalledProcessError as exc:
        report.notes.append(f"command failed: {' '.join(exc.cmd)}")
    except TimeoutError as exc:
        report.notes.append(str(exc))
    finally:
        if started and not keep_running:
            try:
                shim = RuntimeValidationReport(logs=report.notes)
                _record(
                    shim,
                    resolved_runner(
                        ["docker", "compose", "-p", project_name, "down", "--volumes", "--remove-orphans"],
                        challenge_path,
                        timeout_seconds,
                    ),
                )
            except subprocess.CalledProcessError as exc:
                report.notes.append(f"cleanup failed: {' '.join(exc.cmd)}")

    return report


# --- run_adversarial_delta -----------------------------------------------------------


class _ScenarioDefendedHTTPClient:
    """Wraps an ``HTTPClient``, applying a precomputed scenario's effects.

    ``scenario_report.responses_applied`` records every ``rotate_credential``
    / ``patch_route`` / ``quarantine_host`` the defender fired, each stamped
    with the tick it fired at and a ``target``. This wrapper advances one
    internal "tick" per ``.request()`` call (so a fixed agent plan against a
    fixed scenario always produces the same outcome -- no wall clock
    involved) and, from the tick a target was first broken onward, any
    request whose URL or header values mention that target is short-circuited
    to a ``403`` instead of reaching the real app: the credential/route the
    agent's fixed plan relies on has gone stale mid-solve, exactly the
    "static writeup goes stale" effect the live-adversarial engine is meant
    to produce (see ``scenario.py`` module docstring).
    """

    def __init__(self, inner: HTTPClient, scenario_report: ScenarioRunReport) -> None:
        self._inner = inner
        self._tick = 0
        self._broken_at: dict[str, int] = {}
        for record in scenario_report.responses_applied:
            if record.action in ("rotate_credential", "patch_route", "quarantine_host") and record.target:
                self._broken_at.setdefault(record.target, record.tick)

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> HTTPResponse:
        tick = self._tick
        self._tick += 1
        resolved_headers = headers or {}
        for target, broken_tick in self._broken_at.items():
            if tick < broken_tick:
                continue
            if target in url or any(target in str(value) for value in resolved_headers.values()):
                return HTTPResponse(
                    status=403, body=f"defense active: {target} rotated/patched", headers={}
                )
        return self._inner.request(method, url, json_body=json_body, headers=headers, timeout=timeout)


def run_adversarial_delta(
    challenge_path: Path,
    profile: str,
    base_url: str = "http://127.0.0.1:8080",
    timeout_seconds: int = 90,
    keep_running: bool = False,
    runner: CommandRunner | None = None,
    http: HTTPClient | None = None,
    rng: random.Random | None = None,
    agent: SolverAgent | None = None,
    already_running: bool = False,
    environment: EnvironmentController | None = None,
    events: EventSource | None = None,
    defender: ScenarioAgent | None = None,
    attacker: ScenarioAgent | None = None,
    scenario_spec: ScenarioSpec | None = None,
    max_ticks: int | None = None,
) -> AdversarialDeltaReport:
    """Run ``profile`` twice -- scenario engine off, then on -- and diff them.

    The "off" (baseline) leg is a plain :func:`run_agent_eval`. The "on"
    (adversarial) leg first computes a deterministic ``ScenarioRunReport``
    via ``scenario.run_scenario`` (offline, no Docker/HTTP/wall clock of its
    own) using ``environment``/``events``/``defender``/``attacker``/``scenario_spec``,
    then re-runs the agent with its ``http`` wrapped in
    :class:`_ScenarioDefendedHTTPClient` so the scenario's credential
    rotations/route patches/host quarantines can actually break the agent's
    plan mid-solve. Both legs share ``already_running``/``runner`` so the
    same fixture (real Docker stack, or an already-running one in tests) is
    reused for both.
    """
    resolved_http = http or _default_http()

    baseline = run_agent_eval(
        challenge_path,
        profile,
        base_url=base_url,
        timeout_seconds=timeout_seconds,
        keep_running=keep_running,
        runner=runner,
        http=resolved_http,
        rng=rng,
        agent=agent,
        already_running=already_running,
        compose_suffix="baseline",
    )

    resolved_environment = environment or NullEnvironmentController()
    resolved_events = events or ReplayEventSource({})
    scenario_report = run_scenario(
        challenge_path,
        resolved_environment,
        resolved_events,
        defender=defender,
        attacker=attacker,
        spec=scenario_spec,
        max_ticks=max_ticks,
    )

    defended_http = _ScenarioDefendedHTTPClient(resolved_http, scenario_report)
    adversarial = run_agent_eval(
        challenge_path,
        profile,
        base_url=base_url,
        timeout_seconds=timeout_seconds,
        keep_running=keep_running,
        runner=runner,
        http=defended_http,
        rng=rng,
        agent=agent,
        already_running=already_running,
        compose_suffix=ADVERSARIAL_COMPOSE_PROFILE,
    )

    report = AdversarialDeltaReport(
        challenge_path=str(challenge_path),
        profile=profile,
        baseline=baseline,
        adversarial=adversarial,
        scenario_report=scenario_report,
        notes=[
            f"scenario ticks_run={scenario_report.ticks_run}",
            f"triggers_fired={scenario_report.triggers_fired}",
            f"attacker_blocked={scenario_report.attacker_blocked}",
        ],
    )
    return report
