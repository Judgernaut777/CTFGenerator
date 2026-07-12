"""Pure host unit tests for the instance-lifecycle domain (M8 slice 1b).

No database: state-machine legality, aggregate validation, and the corrective
idempotency contract (which is pure -- ``corrective.py`` imports only domain
value types). The Docker-gated repository/reconciler suites cover the SQL.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from ctf_generator.application.instances.corrective import (
    INSTANCE_ACTION_JOB_TYPES,
    build_corrective_job,
    corrective_idempotency_key,
)
from ctf_generator.domain.instances.models import (
    LEGAL_INSTANCE_TRANSITIONS,
    TERMINAL_INSTANCE_STATES,
    VALID_INSTANCE_STATES,
    VALID_OBSERVED_STATES,
    HealthObservation,
    Instance,
    InstanceCredential,
    InstanceEndpoint,
    InstanceEvent,
    RuntimeResource,
    is_legal_instance_transition,
)

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


def _instance(**kw) -> Instance:
    base = dict(
        instance_id="11111111-1111-1111-1111-111111111111",
        competition_id="comp",
        team_name="team",
        definition_slug="chal",
        version_no=1,
    )
    base.update(kw)
    return Instance(**base)


class InstanceValidationTests(unittest.TestCase):
    def test_defaults(self) -> None:
        inst = _instance()
        self.assertEqual(inst.state, "requested")
        self.assertEqual(inst.desired_state, "active")
        self.assertEqual(inst.generation, 1)
        self.assertIsNone(inst.assigned_worker)
        self.assertFalse(inst.is_terminal)

    def test_bad_state_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _instance(state="bogus")

    def test_bad_desired_state_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _instance(desired_state="running")

    def test_version_no_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            _instance(version_no=0)

    def test_generation_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            _instance(generation=0)

    def test_empty_business_keys_rejected(self) -> None:
        for field in ("competition_id", "team_name", "definition_slug"):
            with self.assertRaises(ValueError):
                _instance(**{field: "  "})

    def test_naive_expires_at_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _instance(expires_at=datetime(2026, 7, 12, 12, 0))

    def test_archived_is_terminal(self) -> None:
        self.assertTrue(_instance(state="archived").is_terminal)


class TransitionMatrixTests(unittest.TestCase):
    def test_matrix_keys_cover_all_states(self) -> None:
        self.assertEqual(set(LEGAL_INSTANCE_TRANSITIONS), set(VALID_INSTANCE_STATES))

    def test_archived_is_the_only_terminal(self) -> None:
        self.assertEqual(TERMINAL_INSTANCE_STATES, frozenset({"archived"}))
        self.assertEqual(LEGAL_INSTANCE_TRANSITIONS["archived"], frozenset())
        for state, targets in LEGAL_INSTANCE_TRANSITIONS.items():
            if state != "archived":
                self.assertTrue(targets, f"{state} has no outgoing transitions")

    def test_targets_are_valid_states(self) -> None:
        for targets in LEGAL_INSTANCE_TRANSITIONS.values():
            self.assertTrue(targets <= VALID_INSTANCE_STATES)

    def test_self_transition_always_legal(self) -> None:
        for state in VALID_INSTANCE_STATES:
            self.assertTrue(is_legal_instance_transition(state, state))

    def test_representative_legal_moves(self) -> None:
        for src, dst in [
            ("requested", "queued"),
            ("queued", "building"),
            ("building", "ready"),
            ("ready", "starting"),
            ("starting", "healthy"),
            ("healthy", "active"),
            ("active", "degraded"),
            ("degraded", "healthy"),
            ("active", "stopping"),
            ("stopping", "stopped"),
            ("stopped", "archived"),
            ("healthy", "expired"),
            ("expired", "archived"),
            ("failed", "starting"),
            ("quarantined", "archived"),
        ]:
            self.assertTrue(
                is_legal_instance_transition(src, dst), f"{src}->{dst} should be legal"
            )

    def test_representative_illegal_moves(self) -> None:
        for src, dst in [
            ("requested", "healthy"),
            ("requested", "active"),
            ("building", "active"),
            ("archived", "starting"),
            ("archived", "active"),
            ("stopped", "active"),
            ("stopping", "active"),
            ("healthy", "requested"),
            ("ready", "healthy"),
        ]:
            self.assertFalse(
                is_legal_instance_transition(src, dst), f"{src}->{dst} should be illegal"
            )


class ChildAggregateValidationTests(unittest.TestCase):
    def test_endpoint_ok_and_bad_port(self) -> None:
        InstanceEndpoint(
            instance_id="i", name="web", host="h", port=8080, protocol="tcp", url="u"
        )
        with self.assertRaises(ValueError):
            InstanceEndpoint(
                instance_id="i", name="web", host="h", port=0, protocol="tcp", url="u"
            )

    def test_runtime_resource_kind_and_state(self) -> None:
        RuntimeResource(
            instance_id="i", kind="container", external_ref="c1", worker="w"
        )
        with self.assertRaises(ValueError):
            RuntimeResource(
                instance_id="i", kind="pod", external_ref="c1", worker="w"
            )
        with self.assertRaises(ValueError):
            RuntimeResource(
                instance_id="i",
                kind="container",
                external_ref="c1",
                worker="w",
                state="gone",
            )

    def test_credential_is_a_handle(self) -> None:
        cred = InstanceCredential(
            instance_id="i",
            name="access",
            secret_ref="vault://k",  # noqa: S106 - a reference handle, not a secret
            scopes=("read",),
        )
        self.assertEqual(cred.secret_ref, "vault://k")
        with self.assertRaises(ValueError):
            InstanceCredential(
                instance_id="i",
                name="access",
                secret_ref="  ",  # noqa: S106 - a reference handle, not a secret
            )

    def test_observation_state_and_generation(self) -> None:
        obs = HealthObservation(
            instance_id="i",
            observed_state="absent",
            healthy=False,
            worker="w",
            generation=1,
            observed_at=_NOW,
        )
        self.assertTrue(obs.observed_absent)
        self.assertIn("absent", VALID_OBSERVED_STATES)
        with self.assertRaises(ValueError):
            HealthObservation(
                instance_id="i",
                observed_state="nope",
                healthy=True,
                worker="w",
                generation=1,
                observed_at=_NOW,
            )
        with self.assertRaises(ValueError):
            HealthObservation(
                instance_id="i",
                observed_state="healthy",
                healthy=True,
                worker="w",
                generation=0,
                observed_at=_NOW,
            )

    def test_event_actor_and_states(self) -> None:
        InstanceEvent(
            instance_id="i",
            from_state=None,
            to_state="requested",
            reason="created",
            actor="system",
            generation=1,
            occurred_at=_NOW,
        )
        with self.assertRaises(ValueError):
            InstanceEvent(
                instance_id="i",
                from_state=None,
                to_state="requested",
                reason="x",
                actor="hacker",
                generation=1,
                occurred_at=_NOW,
            )


class CorrectiveContractTests(unittest.TestCase):
    def test_idempotency_key_shape(self) -> None:
        key = corrective_idempotency_key("abc", 3, "launch")
        self.assertEqual(key, "instance:abc:gen3:launch")

    def test_idempotency_key_rejects_unknown_action(self) -> None:
        with self.assertRaises(ValueError):
            corrective_idempotency_key("abc", 1, "frobnicate")

    def test_every_action_maps_to_a_job_type(self) -> None:
        self.assertEqual(
            set(INSTANCE_ACTION_JOB_TYPES),
            {"launch", "stop", "reset", "expire", "delete"},
        )

    def test_build_job_is_reference_only(self) -> None:
        inst = _instance(image_ref="registry/img@sha256:deadbeef")
        job = build_corrective_job(inst, inst.generation, "launch", _NOW)
        self.assertEqual(job.job_type, "launch_instance")
        self.assertEqual(
            job.idempotency_key, f"instance:{inst.instance_id}:gen1:launch"
        )
        self.assertEqual(job.required_capabilities, ("launch_instance",))
        # Payload carries references only -- no flag/secret/credential material.
        self.assertEqual(
            dict(job.payload),
            {"instance_id": inst.instance_id, "generation": 1, "action": "launch"},
        )
        self.assertEqual(job.competition_id, "comp")
        self.assertEqual(job.definition_slug, "chal")
        self.assertEqual(job.version_no, 1)

    def test_different_generations_are_distinct_jobs(self) -> None:
        inst1 = _instance(generation=1)
        inst2 = _instance(generation=2)
        self.assertNotEqual(
            build_corrective_job(inst1, 1, "launch", _NOW).idempotency_key,
            build_corrective_job(inst2, 2, "launch", _NOW + timedelta(seconds=1)).idempotency_key,
        )


if __name__ == "__main__":
    unittest.main()
