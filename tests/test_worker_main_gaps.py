"""``ctfgen-worker`` entrypoint: operator runtime-gap acknowledgement (single-host).

The networked worker entrypoint (`workers.worker.main`) builds its
`DockerRuntimeBackend` with the SECURE default (`require_rootless=True`, no
acknowledged gaps) unless the operator explicitly sets
`CTFGEN_WORKER_ACKNOWLEDGED_GAPS` for a single-host demo. These tests pin that
contract WITHOUT a real docker CLI / network by patching the lazily-imported
collaborators and capturing the backend constructor kwargs.

    PYTHONPATH=src:tests python -m unittest test_worker_main_gaps
"""

from __future__ import annotations

import unittest
from unittest import mock

from ctf_generator.workers import worker as worker_mod

_BASE_ENV = {
    "CTFGEN_WORKER_TRANSPORT": "http",
    "CTFGEN_WORKER_CONTROL_PLANE_URL": "http://gw:8001",
    "CTFGEN_WORKER_TOKEN": "ctfw1.id.secret",
    "CTFGEN_WORKER_NAME": "worker-1",
}


def _run_main(env: dict[str, str]):
    """Run main() with a patched backend/client/worker; return (rc, backend_kwargs)."""
    captured: dict = {}

    def _fake_backend(*args, **kwargs):
        captured.update(kwargs)
        return mock.MagicMock(name="DockerRuntimeBackend")

    with (
        mock.patch.dict("os.environ", env, clear=True),
        mock.patch(
            "ctf_generator.infrastructure.runtime.docker_backend.DockerRuntimeBackend",
            side_effect=_fake_backend,
        ),
        mock.patch(
            "ctf_generator.workers.http_client.HttpControlPlaneClient",
            return_value=mock.MagicMock(name="HttpControlPlaneClient"),
        ),
        mock.patch.object(worker_mod, "Worker", return_value=mock.MagicMock()),
    ):
        rc = worker_mod.main([])
    return rc, captured


class WorkerMainGapsTest(unittest.TestCase):
    def test_default_is_secure_rootless_required(self) -> None:
        rc, kwargs = _run_main(dict(_BASE_ENV))
        self.assertEqual(rc, 0)
        # Secure default: rootless REQUIRED, no gaps acknowledged.
        self.assertTrue(kwargs["require_rootless"])
        self.assertEqual(kwargs["acknowledged_gaps"], frozenset())

    def test_acknowledged_gaps_relax_rootless_for_exactly_those_gaps(self) -> None:
        rc, kwargs = _run_main(
            {**_BASE_ENV, "CTFGEN_WORKER_ACKNOWLEDGED_GAPS": "rootless, user_namespace"}
        )
        self.assertEqual(rc, 0)
        # Explicit acknowledgement disables the rootless requirement and passes
        # exactly the named gaps (whitespace-tolerant).
        self.assertFalse(kwargs["require_rootless"])
        self.assertEqual(
            kwargs["acknowledged_gaps"], frozenset({"rootless", "user_namespace"})
        )

    def test_unknown_gap_is_refused(self) -> None:
        rc, kwargs = _run_main(
            {**_BASE_ENV, "CTFGEN_WORKER_ACKNOWLEDGED_GAPS": "rootless,seccomp"}
        )
        # seccomp is NOT acknowledgeable -> hard fail before building a backend.
        self.assertEqual(rc, 2)
        self.assertEqual(kwargs, {})


if __name__ == "__main__":
    unittest.main()
