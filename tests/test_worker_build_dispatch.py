"""Pure unit tests for the build_challenge worker dispatch
(docs/architecture/build-challenge-worker-pipeline.md).

No Docker, no DB, no real bundle renderer: an INJECTED fake
``WorkerControlPlaneClient.fetch_build_bundle`` returns scripted bundle bytes
and a fake ``BuildBackend`` records ``build_image`` calls instead of shelling to
``docker``. Covers:

* a build_challenge job (payload has definition_slug/version_no/spec_sha256 and
  NO instance_id) dispatches to ``_do_build_challenge`` -- it does NOT raise
  "missing instance_id" (the build branch precedes the instance_id extraction,
  same as the eval branch);
* the happy path: fetch -> both hash checks pass -> extract -> select build
  context -> build -> COMPLETE with a result carrying image_ref + digest (and
  nothing else -- no bundle bytes, no flag material);
* a bundle content-hash mismatch REFUSES with NO call into the build backend,
  and the job FAILS (never completes);
* a spec_sha256 drift (fetched version's current hash != the job's enqueue-time
  hash) REFUSES with NO call into the build backend, and the job FAILS;
* a malformed payload (missing definition_slug / version_no / spec_sha256)
  fails the job cleanly ('internal'), never reaching fetch_build_bundle;
* no build_backend configured on this worker fails cleanly ('internal'), never
  reaching fetch_build_bundle;
* an oversized-image refusal from the build backend (``UnsupportedRuntimeError``)
  is classified 'infrastructure'/non-retryable by the SAME branch
  ``_do_launch`` already exercises;
* the build context handed to the backend is a directory containing the
  bundle's Dockerfile (root-level preferred), never the raw tar bytes and never
  a path outside the confined temp dir;
* a planted flag string in the bundle content never appears in the completed
  job's result.
"""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import tempfile
import unittest
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

try:
    import yaml  # noqa: F401 -- the compose-manifest parser needs it

    _HAVE_YAML = True
except ImportError:  # pragma: no cover
    _HAVE_YAML = False

from ctf_generator.domain.execution.runtime import BuildBundle
from ctf_generator.domain.work.models import Job, JobLease
from ctf_generator.infrastructure.runtime.docker_backend import (
    DockerCommandError,
    UnsupportedRuntimeError,
)
from ctf_generator.workers.worker import Worker, WorkerConfig

_NOW = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)
_PLANTED_FLAG = "ctf{planted_build_dispatch_flag}"


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _tiny_bundle() -> bytes:
    return _tar_bytes(
        {
            "Dockerfile": b"FROM alpine:latest\nCMD [\"true\"]\n",
            "services/app/app.py": f"# {_PLANTED_FLAG}\n".encode(),
            "private/solution.md": f"the flag is {_PLANTED_FLAG}\n".encode(),
        }
    )


class _FakeRuntimeBackend:
    """A never-touched runtime backend (a build job reaches no launch verb)."""

    def reap_managed(self, worker=None):  # pragma: no cover - unused by build path
        return 0


class _FakeBuildBackend:
    """Records build_image calls; returns a scripted digest or raises."""

    def __init__(self, *, digest: str = "sha256:" + "ab" * 32, raises: Exception | None = None) -> None:
        self.digest = digest
        self.raises = raises
        self.calls: list[dict] = []

    def build_image(
        self,
        *,
        context_dir: str,
        tag: str,
        network: bool = False,
        allow_mirror: bool = False,
    ) -> str:
        # The temp dir is cleaned up once _do_build_challenge's `with` block
        # exits (before returning to the caller) -- snapshot what matters about
        # the context HERE, at call time, not after the fact.
        context_path = Path(context_dir)
        self.calls.append(
            {
                "context_dir": context_dir,
                "context_dir_name": context_path.name,
                "has_dockerfile": (context_path / "Dockerfile").is_file(),
                "tag": tag,
                "network": network,
                "allow_mirror": allow_mirror,
            }
        )
        if self.raises is not None:
            raise self.raises
        return self.digest

    def is_available(self) -> bool:  # pragma: no cover - not exercised by dispatch
        return True


@dataclass
class _FakeClient:
    bundle: BuildBundle | None
    token: str = "ctfw1.cred.secret"
    completed: list = field(default_factory=list)
    failed: list = field(default_factory=list)
    claim_lease: JobLease | None = None
    fetch_calls: list = field(default_factory=list)

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
        self.failed.append((job_id, error_class, error_detail, retryable))

    def fetch_build_bundle(self, definition_slug, version_no, job_id, lease_token, now):
        self.fetch_calls.append((definition_slug, version_no, job_id, lease_token))
        if self.bundle is None:
            raise LookupError(f"no bundle for {definition_slug!r} v{version_no}")
        return self.bundle


def _build_payload(**overrides) -> dict:
    payload = {
        "definition_slug": "sqli",
        "version_no": 1,
        "spec_sha256": "spec-hash-abc123",
    }
    payload.update(overrides)
    return payload


def _build_lease(payload: dict) -> JobLease:
    job = Job(
        job_id="job-build-1",
        job_type="build_challenge",
        idempotency_key="build:sqli:v1:spec-hash-abc123",
        available_at=_NOW,
        required_capabilities=("build_challenge",),
        payload=payload,
    )
    return JobLease(job=job, lease_token="lease-1", lease_expires_at=_NOW)


def _worker(client, build_backend) -> Worker:
    return Worker(
        WorkerConfig(worker_name="w1", lease_seconds=60),
        client,
        _FakeRuntimeBackend(),  # type: ignore[arg-type]
        build_backend=build_backend,
        clock=lambda: _NOW,
    )


def _valid_bundle(data: bytes, *, spec_sha256: str = "spec-hash-abc123") -> BuildBundle:
    return BuildBundle(
        data=data,
        bundle_sha256=hashlib.sha256(data).hexdigest(),
        spec_sha256=spec_sha256,
    )


class BuildChallengeDispatchTests(unittest.TestCase):
    def test_build_job_dispatches_without_instance_id(self) -> None:
        # No "instance_id" key anywhere in the payload -- if the build branch
        # did not precede the instance_id extraction this would raise
        # "build_challenge payload missing instance_id" instead.
        data = _tiny_bundle()
        client = _FakeClient(bundle=_valid_bundle(data), claim_lease=_build_lease(_build_payload()))
        backend = _FakeBuildBackend()
        worker = _worker(client, backend)

        worked = worker.run_once()

        self.assertTrue(worked)
        self.assertEqual(len(client.failed), 0, client.failed)
        self.assertEqual(len(client.completed), 1)

    def test_happy_path_reports_image_ref_and_digest(self) -> None:
        data = _tiny_bundle()
        digest = "sha256:" + "cd" * 32
        client = _FakeClient(bundle=_valid_bundle(data), claim_lease=_build_lease(_build_payload()))
        backend = _FakeBuildBackend(digest=digest)
        worker = _worker(client, backend)

        worker.run_once()

        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(backend.calls[0]["network"], False)
        # The worker opts each build into the (operator-configured) mirror; with
        # no mirror configured this is a no-op --network=none build.
        self.assertEqual(backend.calls[0]["allow_mirror"], True)
        # The build context is a REAL directory containing the extracted
        # Dockerfile -- never the raw tar bytes and never the temp root itself
        # (root-level Dockerfile in this fixture -> context IS the temp root's
        # "bundle" subdir).
        self.assertTrue(backend.calls[0]["has_dockerfile"])

        [(job_id, result)] = client.completed
        self.assertEqual(job_id, "job-build-1")
        self.assertEqual(result["digest"], digest)
        self.assertTrue(result["image_ref"].startswith("ctfgen-build/sqli:v1-"))
        self.assertEqual(result["definition_slug"], "sqli")
        self.assertEqual(result["version_no"], 1)
        self.assertEqual(result["bundle_sha256"], hashlib.sha256(data).hexdigest())
        # Never-log / never-leak rule: no bundle bytes and no flag material in
        # the reported result.
        self.assertNotIn("data", result)
        for value in result.values():
            self.assertNotIn(_PLANTED_FLAG, str(value))

    def test_bundle_hash_mismatch_refuses_before_any_build(self) -> None:
        data = _tiny_bundle()
        bundle = BuildBundle(
            data=data,
            bundle_sha256="0" * 64,  # deliberately wrong
            spec_sha256="spec-hash-abc123",
        )
        client = _FakeClient(bundle=bundle, claim_lease=_build_lease(_build_payload()))
        backend = _FakeBuildBackend()
        worker = _worker(client, backend)

        worker.run_once()

        self.assertEqual(backend.calls, [])
        self.assertEqual(len(client.completed), 0)
        self.assertEqual(len(client.failed), 1)
        job_id, error_class, error_detail, retryable = client.failed[0]
        self.assertEqual(job_id, "job-build-1")
        self.assertEqual(error_class, "internal")
        self.assertIn("hash mismatch", error_detail)

    def test_spec_sha256_drift_refuses_before_any_build(self) -> None:
        data = _tiny_bundle()
        # The version's CURRENT spec_sha256 (read at fetch time) differs from
        # the job's enqueue-time spec_sha256 -- the version changed underneath.
        bundle = _valid_bundle(data, spec_sha256="a-different-spec-hash")
        client = _FakeClient(bundle=bundle, claim_lease=_build_lease(_build_payload()))
        backend = _FakeBuildBackend()
        worker = _worker(client, backend)

        worker.run_once()

        self.assertEqual(backend.calls, [])
        self.assertEqual(len(client.completed), 0)
        self.assertEqual(len(client.failed), 1)
        _job_id, error_class, error_detail, _retryable = client.failed[0]
        self.assertEqual(error_class, "internal")
        self.assertIn("spec hash", error_detail)

    def test_malformed_payload_fails_cleanly_without_fetching(self) -> None:
        for missing in ("definition_slug", "version_no", "spec_sha256"):
            with self.subTest(missing=missing):
                payload = _build_payload()
                del payload[missing]
                client = _FakeClient(bundle=None, claim_lease=_build_lease(payload))
                backend = _FakeBuildBackend()
                worker = _worker(client, backend)

                worker.run_once()

                self.assertEqual(client.fetch_calls, [])
                self.assertEqual(backend.calls, [])
                self.assertEqual(len(client.completed), 0)
                self.assertEqual(len(client.failed), 1)
                self.assertEqual(client.failed[0][1], "internal")

    def test_no_build_backend_configured_fails_cleanly(self) -> None:
        data = _tiny_bundle()
        client = _FakeClient(bundle=_valid_bundle(data), claim_lease=_build_lease(_build_payload()))
        worker = Worker(
            WorkerConfig(worker_name="w1", lease_seconds=60),
            client,
            _FakeRuntimeBackend(),  # type: ignore[arg-type]
            build_backend=None,
            clock=lambda: _NOW,
        )

        worker.run_once()

        self.assertEqual(client.fetch_calls, [])
        self.assertEqual(len(client.completed), 0)
        self.assertEqual(len(client.failed), 1)
        self.assertEqual(client.failed[0][1], "internal")

    def test_oversized_image_is_infrastructure_non_retryable(self) -> None:
        data = _tiny_bundle()
        client = _FakeClient(bundle=_valid_bundle(data), claim_lease=_build_lease(_build_payload()))
        backend = _FakeBuildBackend(raises=UnsupportedRuntimeError("image too large"))
        worker = _worker(client, backend)

        worker.run_once()

        self.assertEqual(len(client.completed), 0)
        self.assertEqual(len(client.failed), 1)
        job_id, error_class, error_detail, retryable = client.failed[0]
        self.assertEqual(error_class, "infrastructure")
        self.assertFalse(retryable)
        self.assertIn("unsupported_runtime", error_detail)

    def test_services_subdir_dockerfile_is_used_when_no_root_dockerfile(self) -> None:
        data = _tar_bytes(
            {
                "services/edge/Dockerfile": b"FROM alpine:latest\n",
                "services/edge/app.py": b"print(1)\n",
                "services/internal/Dockerfile": b"FROM alpine:latest\n",
            }
        )
        client = _FakeClient(bundle=_valid_bundle(data), claim_lease=_build_lease(_build_payload()))
        backend = _FakeBuildBackend()
        worker = _worker(client, backend)

        worker.run_once()

        self.assertEqual(len(backend.calls), 1)
        # Lexicographically-first services/*/Dockerfile -> "edge" before
        # "internal".
        self.assertEqual(backend.calls[0]["context_dir_name"], "edge")
        self.assertTrue(backend.calls[0]["has_dockerfile"])
        self.assertEqual(len(client.completed), 1)

    def test_no_dockerfile_anywhere_fails_cleanly(self) -> None:
        data = _tar_bytes({"README.md": b"nothing buildable here\n"})
        client = _FakeClient(bundle=_valid_bundle(data), claim_lease=_build_lease(_build_payload()))
        backend = _FakeBuildBackend()
        worker = _worker(client, backend)

        worker.run_once()

        self.assertEqual(backend.calls, [])
        self.assertEqual(len(client.completed), 0)
        self.assertEqual(len(client.failed), 1)
        self.assertEqual(client.failed[0][1], "internal")

    def test_path_traversal_member_is_refused(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="../escape.txt")
            info.size = 3
            tar.addfile(info, io.BytesIO(b"bad"))
        data = buf.getvalue()
        client = _FakeClient(bundle=_valid_bundle(data), claim_lease=_build_lease(_build_payload()))
        backend = _FakeBuildBackend()
        worker = _worker(client, backend)

        worker.run_once()

        self.assertEqual(backend.calls, [])
        self.assertEqual(len(client.completed), 0)
        self.assertEqual(len(client.failed), 1)
        _job_id, error_class, error_detail, _retryable = client.failed[0]
        self.assertEqual(error_class, "internal")
        self.assertIn("unsafe path", error_detail)

    def test_absolute_path_member_is_refused(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="/etc/passwd")
            info.size = 3
            tar.addfile(info, io.BytesIO(b"bad"))
        data = buf.getvalue()
        client = _FakeClient(bundle=_valid_bundle(data), claim_lease=_build_lease(_build_payload()))
        backend = _FakeBuildBackend()
        worker = _worker(client, backend)

        worker.run_once()

        self.assertEqual(backend.calls, [])
        self.assertEqual(len(client.completed), 0)
        self.assertEqual(len(client.failed), 1)
        _job_id, error_class, error_detail, _retryable = client.failed[0]
        self.assertEqual(error_class, "internal")
        self.assertIn("unsafe path", error_detail)

    def test_symlink_member_is_refused(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="innocuous_link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
        data = buf.getvalue()
        client = _FakeClient(bundle=_valid_bundle(data), claim_lease=_build_lease(_build_payload()))
        backend = _FakeBuildBackend()
        worker = _worker(client, backend)

        worker.run_once()

        self.assertEqual(backend.calls, [])
        self.assertEqual(len(client.completed), 0)
        self.assertEqual(len(client.failed), 1)
        _job_id, error_class, error_detail, _retryable = client.failed[0]
        self.assertEqual(error_class, "internal")
        self.assertIn("not a regular file", error_detail)

    def test_docker_build_failure_redacts_stderr_from_error_detail(self) -> None:
        # A DockerCommandError's message embeds up to 400 chars of captured
        # `docker build` stderr -- since the build context is hostile-by-
        # construction generated content, that stderr can echo flag-adjacent
        # material. The persisted error_detail must NEVER forward it.
        data = _tiny_bundle()
        secret_stderr = (
            f"COPY failed: cat private/solution.md; the flag is {_PLANTED_FLAG}"
        )
        client = _FakeClient(bundle=_valid_bundle(data), claim_lease=_build_lease(_build_payload()))
        backend = _FakeBuildBackend(
            raises=DockerCommandError(("docker", "build", "."), 1, secret_stderr)
        )
        worker = _worker(client, backend)

        worker.run_once()

        self.assertEqual(len(client.completed), 0)
        self.assertEqual(len(client.failed), 1)
        job_id, error_class, error_detail, retryable = client.failed[0]
        self.assertEqual(job_id, "job-build-1")
        # Class/retryable semantics are UNCHANGED from the generic handler.
        self.assertEqual(error_class, "internal")
        self.assertTrue(retryable)
        self.assertNotIn(secret_stderr, error_detail)
        self.assertNotIn(_PLANTED_FLAG, error_detail)
        self.assertNotIn("solution.md", error_detail)
        # The sanitized argv + exit code still make it in, for diagnosis.
        self.assertIn("docker", error_detail)
        self.assertIn("exit 1", error_detail)


class DispatchableJobsTests(unittest.TestCase):
    def test_build_challenge_is_dispatchable(self) -> None:
        from ctf_generator.workers.worker import BUILD_JOBS, DISPATCHABLE_JOBS

        self.assertIn("build_challenge", BUILD_JOBS)
        self.assertTrue(BUILD_JOBS.issubset(DISPATCHABLE_JOBS))


class _SpyBuildBackend:
    """Records ``build_image`` args (no docker). Proves the build POLICY -- every
    build opts into the mirror and never takes general egress -- without shelling
    out to a real builder."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, bool, bool]] = []

    def build_image(self, *, context_dir, tag, network=False, allow_mirror=False):
        self.calls.append((tag, network, allow_mirror))
        return "sha256:" + "ab" * 32

    def is_available(self) -> bool:  # pragma: no cover - not exercised here
        return True


def _write_file(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


@unittest.skipUnless(_HAVE_YAML, "pyyaml required for the compose-manifest parser")
class BuildMirrorOptInTests(unittest.TestCase):
    """Every service build of an N-service (compose) bundle -- and the single-image
    path -- must opt into the operator mirror (``allow_mirror=True``) and never take
    general egress (``network=False``), so a pip/apk-installing family reaches the
    pre-warmed INTERNAL mirror and nothing else. Host-level (a spy backend), so the
    build-N + mirror POLICY is proven without a real per-service docker build."""

    def _worker(self, build) -> Worker:
        return Worker(
            WorkerConfig(worker_name="w1", lease_seconds=60),
            client=None,  # type: ignore[arg-type]
            backend=None,  # type: ignore[arg-type]
            build_backend=build,
        )

    def test_every_service_of_a_stack_opts_into_the_mirror(self) -> None:
        root = tempfile.mkdtemp(prefix="ctfgen-mirror-stack-")
        _write_file(
            os.path.join(root, "docker-compose.yml"),
            "services:\n"
            "  alpha:\n"
            "    build: ./services/alpha\n"
            '    expose: ["8000"]\n'
            "  beta:\n"
            "    build: ./services/beta\n"
            '    ports: ["8080:8080"]\n'
            "    depends_on: [alpha]\n",
        )
        _write_file(os.path.join(root, "services", "alpha", "Dockerfile"), "FROM x\n")
        _write_file(os.path.join(root, "services", "beta", "Dockerfile"), "FROM x\n")
        build = _SpyBuildBackend()
        self._worker(build)._build_from_bundle("demo", 1, "a" * 64, Path(root))
        self.assertEqual(len(build.calls), 2)  # one build per service
        for _tag, network, allow_mirror in build.calls:
            self.assertFalse(network)  # never general egress
            self.assertTrue(allow_mirror)  # always the INTERNAL mirror path

    def test_single_image_build_also_opts_into_the_mirror(self) -> None:
        root = tempfile.mkdtemp(prefix="ctfgen-mirror-single-")
        _write_file(os.path.join(root, "Dockerfile"), "FROM x\n")
        build = _SpyBuildBackend()
        self._worker(build)._build_from_bundle("demo", 1, "a" * 64, Path(root))
        self.assertEqual(len(build.calls), 1)
        _tag, network, allow_mirror = build.calls[0]
        self.assertFalse(network)
        self.assertTrue(allow_mirror)


class StackHelperTests(unittest.TestCase):
    """Pure helpers the compose-aware launch relies on (no docker, no DB)."""

    def test_expose_ports_tolerates_protocol_suffix_and_drops_junk(self) -> None:
        from ctf_generator.workers.worker import _expose_ports

        # "9443/tcp" -> 9443 (compose long-form); out-of-range / non-numeric drop.
        self.assertEqual(
            _expose_ports(("9443/tcp", "8080", "0", "70000", "http", "  443/udp ")),
            (9443, 8080, 443),
        )
        self.assertEqual(_expose_ports(()), ())

    def test_order_stack_places_dependencies_first(self) -> None:
        from ctf_generator.domain.execution.runtime import StackServiceImage
        from ctf_generator.workers.worker import _order_stack

        stack = (
            StackServiceImage(
                service_name="edge", image_ref="ir-edge",
                image_digest="sha256:" + "ee" * 32, depends_on=("internal",),
                is_primary=True,
            ),
            StackServiceImage(
                service_name="internal", image_ref="ir-internal",
                image_digest="sha256:" + "11" * 32,
            ),
        )
        ordered = [s.service_name for s in _order_stack(stack)]
        self.assertLess(ordered.index("internal"), ordered.index("edge"))

    def test_order_stack_is_stable_for_independent_services(self) -> None:
        from ctf_generator.domain.execution.runtime import StackServiceImage
        from ctf_generator.workers.worker import _order_stack

        stack = tuple(
            StackServiceImage(
                service_name=n, image_ref=f"ir-{n}",
                image_digest="sha256:" + "aa" * 32,
            )
            for n in ("beta", "alpha", "gamma")
        )
        # No deps -> name-sorted for determinism.
        self.assertEqual(
            [s.service_name for s in _order_stack(stack)],
            ["alpha", "beta", "gamma"],
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
