"""Host-pure unit tests for the worker identity & trust domain (M7).

Stdlib only. Covers every construction invariant of Worker/WorkerCredential,
the repr-suppression of IssuedCredential's secret, and the token format
helpers. Store-side enforcement (partial UNIQUE, freeze trigger) is proven by
the Docker-gated integration suite.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from ctf_generator.domain.execution.models import (
    CREDENTIAL_TOKEN_PREFIX,
    VALID_CREDENTIAL_SCOPES,
    VALID_RUNTIME_TYPES,
    VALID_TRUST_STATES,
    IssuedCredential,
    Worker,
    WorkerCredential,
)

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)
_HASH = "a" * 64


def _worker(**overrides) -> Worker:
    base = dict(
        name="worker-1",
        runtime_type="docker-rootless",
        architectures=("arm64",),
        capabilities=("build_challenge", "launch_instance"),
        capacity=4,
        version="0.7.0",
    )
    base.update(overrides)
    return Worker(**base)


def _credential(**overrides) -> WorkerCredential:
    base = dict(
        credential_id="7d5f5df1-9556-4d76-8a3d-000000000002",
        worker_name="worker-1",
        token_hash=_HASH,
        scopes=("jobs:claim",),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(hours=24),
    )
    base.update(overrides)
    return WorkerCredential(**base)


class WorkerValidationTests(unittest.TestCase):
    def test_defaults_are_pending_and_unfenced(self) -> None:
        w = _worker()
        self.assertEqual(w.trust_state, "pending")
        self.assertIsNone(w.revoked_at)
        self.assertIsNone(w.quarantined_at)
        self.assertIsNone(w.drain_requested_at)

    def test_rejects_unknown_runtime_type(self) -> None:
        with self.assertRaises(ValueError):
            _worker(runtime_type="docker-rootful")  # rootful is banned (ADR-004)

    def test_rejects_empty_collections(self) -> None:
        with self.assertRaises(ValueError):
            _worker(architectures=())
        with self.assertRaises(ValueError):
            _worker(capabilities=())
        with self.assertRaises(ValueError):
            _worker(architectures=["arm64"])  # list, not tuple

    def test_rejects_nonpositive_capacity(self) -> None:
        for bad in (0, -1, "4"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _worker(capacity=bad)

    def test_rejects_unknown_trust_state(self) -> None:
        with self.assertRaises(ValueError):
            _worker(trust_state="probation")

    def test_revoked_requires_timestamp_and_vice_versa(self) -> None:
        with self.assertRaises(ValueError):
            _worker(trust_state="revoked")  # no revoked_at
        with self.assertRaises(ValueError):
            _worker(revoked_at=_NOW)  # not revoked
        w = _worker(trust_state="revoked", revoked_at=_NOW)
        self.assertEqual(w.trust_state, "revoked")

    def test_quarantine_fields_paired(self) -> None:
        with self.assertRaises(ValueError):
            _worker(quarantined_at=_NOW)  # no reason
        with self.assertRaises(ValueError):
            _worker(quarantine_reason="compromised")  # no timestamp
        w = _worker(quarantined_at=_NOW, quarantine_reason="compromised")
        self.assertEqual(w.quarantine_reason, "compromised")

    def test_three_trust_states_three_runtimes(self) -> None:
        self.assertEqual(VALID_TRUST_STATES, {"pending", "trusted", "revoked"})
        self.assertEqual(len(VALID_RUNTIME_TYPES), 3)
        for runtime in VALID_RUNTIME_TYPES:
            self.assertIn("rootless", runtime)  # ADR-004: rootless only


class WorkerCredentialValidationTests(unittest.TestCase):
    def test_valid_credential(self) -> None:
        c = _credential()
        self.assertIsNone(c.revoked_at)

    def test_rejects_plaintext_shaped_hash(self) -> None:
        # The ctfw1. prefix can never satisfy 64-lowercase-hex, so storing a
        # plaintext token is structurally impossible -- domain half of the
        # guarantee (the DB CHECK is the other half).
        for bad in (
            f"{CREDENTIAL_TOKEN_PREFIX}.id.secret",
            "A" * 64,  # uppercase
            "a" * 63,
            "a" * 65,
            "z" * 64,  # non-hex
            "",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _credential(token_hash=bad)

    def test_rejects_unknown_scope(self) -> None:
        with self.assertRaises(ValueError):
            _credential(scopes=("jobs:claim", "admin:everything"))

    def test_rejects_empty_scopes(self) -> None:
        with self.assertRaises(ValueError):
            _credential(scopes=())

    def test_rejects_expiry_before_issue(self) -> None:
        with self.assertRaises(ValueError):
            _credential(expires_at=_NOW - timedelta(seconds=1))
        with self.assertRaises(ValueError):
            _credential(expires_at=_NOW)  # equal is also invalid

    def test_rejects_naive_datetimes(self) -> None:
        with self.assertRaises(ValueError):
            _credential(issued_at=datetime(2026, 7, 12))

    def test_scope_vocabulary(self) -> None:
        self.assertEqual(
            VALID_CREDENTIAL_SCOPES,
            {"jobs:claim", "jobs:heartbeat", "jobs:complete", "artifacts:pull"},
        )


class IssuedCredentialTests(unittest.TestCase):
    def test_repr_hides_the_secret(self) -> None:
        issued = IssuedCredential(
            credential_id="cred-1",
            worker_name="worker-1",
            scopes=("jobs:claim",),
            expires_at=_NOW,
            secret="super-secret-value",  # noqa: S106 - test fixture
        )
        self.assertNotIn("super-secret-value", repr(issued))
        self.assertNotIn("super-secret-value", str(issued))

    def test_token_format(self) -> None:
        issued = IssuedCredential(
            credential_id="cred-1",
            worker_name="worker-1",
            scopes=("jobs:claim",),
            expires_at=_NOW,
            secret="deadbeef",  # noqa: S106 - test fixture
        )
        self.assertEqual(issued.token(), "ctfw1.cred-1.deadbeef")

    def test_rejects_empty_secret(self) -> None:
        with self.assertRaises(ValueError):
            IssuedCredential(
                credential_id="cred-1",
                worker_name="worker-1",
                scopes=("jobs:claim",),
                expires_at=_NOW,
                secret="",
            )


if __name__ == "__main__":
    unittest.main()
