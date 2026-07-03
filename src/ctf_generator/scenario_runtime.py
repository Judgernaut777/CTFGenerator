"""Docker/HTTP-backed glue for the live-adversarial scenario engine.

CLI-only, effectful module: this is the part of the Phase-5 live-adversarial
engine that actually shells out to Docker and makes real HTTP requests
against a running challenge. ``scenario.py`` stays pure/offline; this module
supplies the real ``EnvironmentController`` / ``EventSource`` implementations
that ``scenario.run_scenario`` accepts.

Security note: this module (like ``runtime_validator.py`` and the future
``agent_eval.py``) drives Docker/subprocess directly and MUST NEVER be
imported from ``mcp_server.py`` -- a regression test in
``tests/test_mcp_server.py`` enforces this. Import it only from CLI code.

Every external effect is behind an injectable callable, mirroring
``runtime_validator.CommandRunner`` exactly:

* ``DockerEnvironmentController`` implements ``scenario.EnvironmentController``
  by running ``docker compose`` commands against a project via an injected
  ``runtime_validator.CommandRunner`` (default: the real ``runtime_validator._run``).
* ``HttpEventSource`` implements ``scenario.EventSource`` by polling a live
  challenge endpoint via an injected fetcher callable (default: stdlib
  ``urllib.request``).
* ``run_live_scenario`` wires both into ``scenario.run_scenario`` and returns
  its ``ScenarioRunReport``.

Tests supply a fake ``CommandRunner`` (records commands, returns scripted
``subprocess.CompletedProcess`` results) and a fake fetcher (returns scripted
JSON strings) -- no real Docker, network, or sockets are ever touched by the
test suite.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .runtime_validator import CommandRunner, _run
from .scenario import (
    Agent,
    ScenarioRunReport,
    ScenarioSpec,
    SimEvent,
    run_scenario,
)

DEFAULT_STATE_PATH = "/scenario/state"
DEFAULT_TIMEOUT_SECONDS = 30

Fetcher = Callable[[str, int], str]


def _urllib_fetch(url: str, timeout: int) -> str:
    """Default ``Fetcher``: a plain stdlib GET, returned as decoded text."""
    with urlopen(Request(url), timeout=timeout) as response:  # noqa: S310 - CLI-only, intended effect
        return response.read().decode("utf-8", errors="replace")


def _project_name(challenge_path: Path) -> str:
    """Same naming convention as ``runtime_validator.validate_runtime``."""
    return f"ctfgen-{challenge_path.name}".replace("_", "-").lower()


class DockerEnvironmentController:
    """``scenario.EnvironmentController`` backed by a real ``docker compose`` project.

    Each method runs one real command against ``project_name`` via an
    injected ``CommandRunner`` (see ``runtime_validator.CommandRunner``;
    default is ``runtime_validator._run``, the same default the runtime
    validator uses) and returns a ``SimEvent`` describing what happened.
    ``tick`` is left at 0 in the returned event -- ``run_scenario`` always
    re-stamps it with the actual current tick before publishing, the same
    convention ``scenario.NullEnvironmentController`` uses.

    A failing command (non-zero exit with ``check=True``, as the real
    ``_run`` uses) raises ``subprocess.CalledProcessError`` up through the
    caller, same as ``runtime_validator.validate_runtime``'s command calls --
    this module does not swallow real Docker failures.
    """

    def __init__(
        self,
        challenge_path: Path | str,
        project_name: str | None = None,
        runner: CommandRunner | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.challenge_path = Path(challenge_path)
        self.project_name = project_name or _project_name(self.challenge_path)
        self._runner = runner or _run
        self._timeout = timeout
        # Bookkeeping for tests/inspection, mirrors NullEnvironmentController.
        self.recorded: list[tuple[str, str, dict]] = []

    def rotate_credential(self, target: str, params: dict) -> SimEvent:
        script = params.get("command", "echo rotated-$(date +%s) > /tmp/ctfgen-credential")
        command = self._compose(["exec", "-T", target, "sh", "-c", script])
        return self._run_and_record("rotate_credential", target, params, command)

    def patch_route(self, target: str, params: dict) -> SimEvent:
        script = params.get("command", f"echo patched > /tmp/ctfgen-route-{target}")
        command = self._compose(["exec", "-T", target, "sh", "-c", script])
        return self._run_and_record("patch_route", target, params, command)

    def quarantine_host(self, target: str, params: dict) -> SimEvent:
        command = self._compose(["stop", target])
        return self._run_and_record("quarantine_host", target, params, command)

    def inject_noise(self, target: str, params: dict) -> SimEvent:
        script = params.get("command", "yes noise 2>/dev/null | head -n 100 >/dev/null")
        command = self._compose(["exec", "-T", target, "sh", "-c", script])
        return self._run_and_record("inject_noise", target, params, command)

    def _compose(self, args: list[str]) -> list[str]:
        return ["docker", "compose", "-p", self.project_name, *args]

    def _run_and_record(
        self, action: str, target: str, params: dict, command: list[str]
    ) -> SimEvent:
        self.recorded.append((action, target, dict(params)))
        result = self._runner(command, self.challenge_path, self._timeout)
        payload = dict(params)
        payload["command"] = " ".join(command)
        payload["returncode"] = str(result.returncode)
        if result.stdout:
            payload["stdout"] = result.stdout
        if result.stderr:
            payload["stderr"] = result.stderr
        return SimEvent(tick=0, source="environment", kind=action, target=target, payload=payload)


class HttpEventSource:
    """``scenario.EventSource`` backed by a live challenge HTTP endpoint.

    ``poll(tick)`` fetches ``base_url + path`` via an injected fetcher
    callable (default: stdlib ``urllib``), parses the response body as JSON,
    and turns observed state into ``SimEvent``s:

    * a top-level ``"checkpoint"`` string -> one ``checkpoint_reached`` event
      the first time that checkpoint name is observed (repeat polls of an
      unchanged checkpoint are not re-emitted, so a slow-changing endpoint
      doesn't flood the timeline).
    * a top-level ``"events"`` list of ``{"source", "kind", "target",
      "payload"}`` mappings -> one ``SimEvent`` each, e.g. an attacker
      request the challenge itself observed.

    A fetch or parse failure never raises: it becomes a single
    ``poll_error`` ``SimEvent`` so a flaky/unreachable endpoint shows up in
    the scenario timeline instead of aborting the whole run.
    """

    def __init__(
        self,
        base_url: str,
        path: str = DEFAULT_STATE_PATH,
        fetcher: Fetcher | None = None,
        timeout: int = 10,
        source: str = "http",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.path = path if path.startswith("/") else f"/{path}"
        self._fetcher = fetcher or _urllib_fetch
        self._timeout = timeout
        self._source = source
        self._seen_checkpoints: set[str] = set()

    def poll(self, tick: int) -> list[SimEvent]:
        url = f"{self.base_url}{self.path}"
        try:
            raw = self._fetcher(url, self._timeout)
            data = json.loads(raw)
        except (URLError, HTTPError, TimeoutError, OSError, ValueError) as exc:
            return [
                SimEvent(
                    tick=tick,
                    source=self._source,
                    kind="poll_error",
                    target=url,
                    payload={"error": str(exc)},
                )
            ]

        events: list[SimEvent] = []
        checkpoint = data.get("checkpoint") if isinstance(data, dict) else None
        if checkpoint and checkpoint not in self._seen_checkpoints:
            self._seen_checkpoints.add(str(checkpoint))
            events.append(
                SimEvent(
                    tick=tick,
                    source=self._source,
                    kind="checkpoint_reached",
                    target=str(checkpoint),
                    payload={"checkpoint": str(checkpoint)},
                )
            )

        raw_events = data.get("events") if isinstance(data, dict) else None
        if isinstance(raw_events, list):
            for item in raw_events:
                if not isinstance(item, dict):
                    continue
                raw_payload = item.get("payload", {})
                payload = (
                    {str(key): str(value) for key, value in raw_payload.items()}
                    if isinstance(raw_payload, dict)
                    else {}
                )
                events.append(
                    SimEvent(
                        tick=tick,
                        source=str(item.get("source", self._source)),
                        kind=str(item.get("kind", "observed")),
                        target=str(item.get("target", "")),
                        payload=payload,
                    )
                )
        return events


def run_live_scenario(
    challenge_path: Path | str,
    base_url: str,
    spec: ScenarioSpec | None = None,
    runner: CommandRunner | None = None,
    fetcher: Fetcher | None = None,
    project_name: str | None = None,
    state_path: str = DEFAULT_STATE_PATH,
    defender: Agent | None = None,
    attacker: Agent | None = None,
    max_ticks: int | None = None,
) -> ScenarioRunReport:
    """Run a live scenario against a real (or faked-for-tests) environment.

    Wires a ``DockerEnvironmentController`` (over ``runner``) and an
    ``HttpEventSource`` (over ``fetcher``, polling ``base_url + state_path``)
    into ``scenario.run_scenario`` and returns its ``ScenarioRunReport``.
    With deterministic fakes for both ``runner`` and ``fetcher`` this is
    fully offline and deterministic, same as ``run_scenario`` itself; with
    the real defaults it drives an actual Docker Compose project and a real
    HTTP endpoint.
    """
    resolved_path = Path(challenge_path)
    environment = DockerEnvironmentController(
        challenge_path=resolved_path,
        project_name=project_name,
        runner=runner,
    )
    events = HttpEventSource(
        base_url=base_url,
        path=state_path,
        fetcher=fetcher,
    )
    return run_scenario(
        challenge_path=resolved_path,
        environment=environment,
        events=events,
        defender=defender,
        attacker=attacker,
        spec=spec,
        max_ticks=max_ticks,
    )
