"""Pure unit tests for the run_agent_evaluation worker dispatch (M15b).

No Docker, no DB, no agent_eval import: an INJECTED fake EvalJobRunner returns a
scripted report and the worker projects it into the SECRET-FREE advisory result.
Covers:

* an eval job (payload has eval_run_id/definition_slug/version_no/profile/
  adversarial and NO instance_id) DISPATCHES to _do_agent_eval -- it does NOT
  raise "missing instance_id" (the eval branch precedes the instance_id
  extraction);
* the reported result is the ALLOWLISTED advisory subset keyed by eval_run_id and
  a planted ``ctf{...}`` flag in the report notes is ABSENT from every field of
  the result (the worker is the first secret-free guard);
* an adversarial payload routes to the delta path (baseline solved/steps +
  success_dropped/step_delta);
* a runner that raises -> an advisory FAILURE result (sanitized error), never an
  unhandled crash, and the JOB still completes (not fails);
* no injected runner -> an advisory failure documenting the distributed
  build_challenge dependency;
* a malformed eval payload (no eval_run_id) fails the job cleanly (internal).
"""

from __future__ import annotations

import json
import unittest
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace

from ctf_generator.domain.work.models import Job, JobLease
from ctf_generator.workers.worker import Worker, WorkerConfig

_NOW = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
_PLANTED_FLAG = "ctf{planted_secret_flag}"
_FAKE_KEY = "sk-ant-api03-DEADBEEFdeadbeef1234567890AbCdEf"  # noqa: S105 - fixture


class _FakeBackend:
    """A never-touched runtime backend (an eval job reaches no runtime verb)."""

    def reap_managed(self, worker=None):  # pragma: no cover - unused by eval path
        return 0


@dataclass
class _FakeClient:
    token: str = "ctfw1.cred.secret"
    completed: list = field(default_factory=list)
    failed: list = field(default_factory=list)
    claim_lease: JobLease | None = None

    def authenticate(self, now):
        return self.token

    def claim(self, token, lease_seconds, now):
        lease, self.claim_lease = self.claim_lease, None
        return lease

    def start(self, token, job_id, lease_token, now):
        pass

    def heartbeat(self, token, job_id, lease_token, lease_seconds, now):
        return False

    def complete(self, token, job_id, lease_token, result, now):
        self.completed.append((job_id, result))

    def fail(self, token, job_id, lease_token, error_class, error_detail, retryable, now):
        self.failed.append((job_id, error_class, retryable))


class _FakeEvalRunner:
    """Records the run() call args; returns a scripted report or raises."""

    def __init__(self, report=None, *, raises: Exception | None = None) -> None:
        self.report = report
        self.raises = raises
        self.calls: list[tuple] = []

    def run(self, *, definition_slug, version_no, profile, adversarial, now):
        self.calls.append((definition_slug, version_no, profile, adversarial))
        if self.raises is not None:
            raise self.raises
        return self.report


def _eval_payload(**overrides) -> dict:
    payload = {
        "eval_run_id": "eval-1",
        "definition_slug": "sqli",
        "version_no": 1,
        "profile": "writeup_replay",
        "adversarial": False,
    }
    payload.update(overrides)
    return payload


def _eval_lease(payload: dict) -> JobLease:
    job = Job(
        job_id="job-eval-1",
        job_type="run_agent_evaluation",
        idempotency_key="eval:sqli:v1:writeup_replay:False",
        available_at=_NOW,
        required_capabilities=("run_agent_evaluation",),
        payload=payload,
    )
    return JobLease(job=job, lease_token="lease-1", lease_expires_at=_NOW)


def _worker(client, runner) -> Worker:
    return Worker(
        WorkerConfig(worker_name="w1", lease_seconds=60),
        client,
        _FakeBackend(),  # type: ignore[arg-type]
        eval_runner=runner,
        clock=lambda: _NOW,
    )


def _plain_report():
    # AgentEvalReport-shaped: the transcript notes carry a discovered flag, which
    # the worker MUST redact before it enters the result.
    return SimpleNamespace(
        profile="writeup_replay",
        solved=True,
        steps=3,
        elapsed_ticks=3,
        notes=["GET /flag -> 200", f"flag found: {_PLANTED_FLAG}"],
    )


class EvalDispatchTests(unittest.TestCase):
    def test_eval_job_dispatches_without_instance_id_and_is_secret_free(self) -> None:
        client = _FakeClient(claim_lease=_eval_lease(_eval_payload()))
        runner = _FakeEvalRunner(_plain_report())
        worked = _worker(client, runner).run_once()

        # Dispatched (not raised "missing instance_id"): the job COMPLETED, and
        # the runner was actually invoked with the payload references.
        self.assertTrue(worked)
        self.assertEqual(client.failed, [])
        self.assertEqual(runner.calls, [("sqli", 1, "writeup_replay", False)])
        self.assertEqual(len(client.completed), 1)

        _job_id, result = client.completed[0]
        self.assertEqual(result["eval_run_id"], "eval-1")
        self.assertTrue(result["solved"])
        self.assertEqual(result["steps"], 3)
        # Allowlist ONLY: no flag/base_url/candidate/credential field.
        self.assertEqual(
            set(result), {"eval_run_id", "solved", "steps", "notes"}
        )
        # The planted flag is ABSENT from EVERY field of the reported result
        # (serialise the whole dict and search) -- proven redacted, not merely
        # dropped from one field.
        blob = json.dumps(result)
        self.assertNotIn(_PLANTED_FLAG, blob)
        self.assertNotIn("planted_secret_flag", blob)
        self.assertIn("[redacted]", result["notes"][-1])

    def test_dispatch_does_not_raise_missing_instance_id(self) -> None:
        # Direct call: the eval branch precedes the instance_id extraction, so a
        # payload with NO instance_id returns an outcome instead of raising.
        runner = _FakeEvalRunner(_plain_report())
        worker = _worker(_FakeClient(), runner)
        outcome = worker._dispatch(
            "run_agent_evaluation", _eval_payload(), _NOW
        )
        self.assertIsNotNone(outcome.result)
        self.assertEqual(outcome.result["eval_run_id"], "eval-1")

    def test_adversarial_payload_routes_to_delta_path(self) -> None:
        delta = SimpleNamespace(
            baseline=SimpleNamespace(solved=True, steps=5, notes=["baseline"]),
            adversarial=SimpleNamespace(solved=False, steps=7, notes=["defended"]),
            success_dropped=True,
            step_delta=2,
            notes=["scenario ticks_run=3", f"note {_PLANTED_FLAG}"],
        )
        client = _FakeClient(
            claim_lease=_eval_lease(_eval_payload(adversarial=True))
        )
        runner = _FakeEvalRunner(delta)
        _worker(client, runner).run_once()

        self.assertEqual(runner.calls, [("sqli", 1, "writeup_replay", True)])
        _job_id, result = client.completed[0]
        # solved/steps reflect the undefended BASELINE; the delta is advisory.
        self.assertTrue(result["solved"])
        self.assertEqual(result["steps"], 5)
        self.assertTrue(result["success_dropped"])
        self.assertEqual(result["step_delta"], 2)
        self.assertNotIn(_PLANTED_FLAG, json.dumps(result))

    def test_runner_failure_yields_advisory_error_result_not_a_crash(self) -> None:
        client = _FakeClient(claim_lease=_eval_lease(_eval_payload()))
        runner = _FakeEvalRunner(
            raises=RuntimeError(f"boom leaked {_FAKE_KEY} and {_PLANTED_FLAG}")
        )
        worked = _worker(client, runner).run_once()

        self.assertTrue(worked)
        # An advisory FAILURE result -- the JOB completes, it does not fail.
        self.assertEqual(client.failed, [])
        _job_id, result = client.completed[0]
        self.assertEqual(result["eval_run_id"], "eval-1")
        self.assertIn("error", result)
        blob = json.dumps(result)
        self.assertNotIn(_FAKE_KEY, blob)
        self.assertNotIn(_PLANTED_FLAG, blob)

    def test_no_runner_reports_distributed_dependency(self) -> None:
        client = _FakeClient(claim_lease=_eval_lease(_eval_payload()))
        _worker(client, None).run_once()
        _job_id, result = client.completed[0]
        self.assertIn("error", result)
        self.assertIn("build_challenge", result["error"])
        self.assertEqual(client.failed, [])

    def test_malformed_eval_payload_fails_job_cleanly(self) -> None:
        payload = _eval_payload()
        del payload["eval_run_id"]
        client = _FakeClient(claim_lease=_eval_lease(payload))
        runner = _FakeEvalRunner(_plain_report())
        _worker(client, runner).run_once()

        self.assertEqual(client.completed, [])
        self.assertEqual(len(client.failed), 1)
        self.assertEqual(client.failed[0][1], "internal")


class ControlPlanePurityTests(unittest.TestCase):
    def test_worker_and_projector_do_not_load_agent_eval(self) -> None:
        # The effectful eval engine (Docker/subprocess/HTTP/LLM) must NEVER be
        # pulled onto the worker's OR the control-plane projector's import graph:
        # worker.py imports agent_eval only under TYPE_CHECKING, eval_runner imports
        # it lazily inside run(). Only actually RUNNING an eval loads it. Prove it
        # in a FRESH interpreter (this test process may have loaded it elsewhere).
        # The MCP firewall + domain-boundary tests do NOT cover workers/, so this is
        # the only guard against a regression to an eager import.
        import os
        import subprocess
        import sys
        from pathlib import Path

        src = str(Path(__file__).resolve().parent.parent / "src")
        code = (
            "import sys\n"
            "import ctf_generator.workers.worker\n"
            "import ctf_generator.application.evaluation.projector\n"
            "import ctf_generator.workers.eval_runner\n"  # even the runner MODULE
            "loaded = 'ctf_generator.agent_eval' in sys.modules\n"
            "sys.stderr.write('AGENT_EVAL_LOADED=%s\\n' % loaded)\n"
            "sys.exit(1 if loaded else 0)\n"
        )
        proc = subprocess.run(  # noqa: S603 - fixed snippet via sys.executable
            [sys.executable, "-c", code],
            env={"PYTHONPATH": src, "PATH": os.environ.get("PATH", "")},
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"agent_eval was loaded onto the worker/control-plane graph: {proc.stderr}",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
