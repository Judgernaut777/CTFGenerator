"""M18 18a: static guards on the deploy/ packaging (HOST, stdlib-only).

These are STATIC/grep-level structural checks -- the REAL docker build + boot +
REQ-INV-010 proof is deploy/verify-deploy.sh (Docker-gated, run by the LEAD).
Here we lock the contract so it cannot silently regress:

* pyproject exposes [deploy] (the control-plane bundle referencing
  api/db/web/oidc/postgres) and [worker] (httpx only);
* .env.example carries PLACEHOLDER values (no real secret) for every deploy var;
* the Dockerfiles / compose / entrypoint exist and are structurally sane -- the
  API image installs [deploy] and carries NO docker CLI / NO socket mount, and the
  entrypoint runs `alembic upgrade` BEFORE uvicorn;
* the compose bakes no secret literal (env/${VAR} interpolation only).

    PYTHONPATH=src:tests python -m unittest test_deploy_packaging
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DEPLOY = _ROOT / "deploy"


def _pyproject() -> dict:
    return tomllib.loads((_ROOT / "pyproject.toml").read_text())


class DeployExtrasTest(unittest.TestCase):
    def setUp(self) -> None:
        self.extras = _pyproject()["project"]["optional-dependencies"]

    def test_deploy_extra_is_the_control_plane_bundle(self) -> None:
        self.assertIn("deploy", self.extras)
        deps = self.extras["deploy"]
        # Expressed by reference to the individual runtime extras so it cannot
        # drift; the union must cover api + db + web + oidc + postgres.
        joined = " ".join(deps)
        for extra in ("api", "db", "web", "oidc", "postgres"):
            self.assertIn(extra, joined, f"[deploy] must include the [{extra}] extra")
        self.assertIn("ctf-generator[", joined)

    def test_worker_extra_is_httpx_only_no_db_no_engine(self) -> None:
        self.assertIn("worker", self.extras)
        deps = self.extras["worker"]
        self.assertEqual(len(deps), 1, "the networked worker's ONLY py dep is httpx")
        self.assertTrue(deps[0].startswith("httpx"))
        joined = " ".join(deps)
        # No db / sqlalchemy / docker on the networked worker's python deps.
        for forbidden in ("sqlalchemy", "alembic", "psycopg", "docker"):
            self.assertNotIn(forbidden, joined)

    def test_entry_points_present(self) -> None:
        scripts = _pyproject()["project"]["scripts"]
        for name in ("ctfgen", "ctfgen-mcp", "ctfgen-worker", "ctfgen-admin"):
            self.assertIn(name, scripts)


class EnvExampleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.path = _DEPLOY / ".env.example"
        self.text = self.path.read_text()

    def test_exists_and_covers_core_vars(self) -> None:
        for var in (
            "POSTGRES_PASSWORD",
            "CTFGEN_ARTIFACT_ROOT",
            "CTFGEN_WEB_CSRF_SECRET",
            "CTFGEN_BOOTSTRAP_ADMIN_PASSWORD",
        ):
            self.assertIn(var, self.text)

    def test_secret_values_are_placeholders(self) -> None:
        # Every assignment to a secret-bearing key must be a PLACEHOLDER, never a
        # real-looking value.
        secret_keys = (
            "POSTGRES_PASSWORD",
            "CTFGEN_WEB_CSRF_SECRET",
            "CTFGEN_BOOTSTRAP_ADMIN_PASSWORD",
            "CTFGEN_OIDC_CLIENT_SECRET",
        )
        for line in self.text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            if key.strip() in secret_keys and value.strip():
                self.assertIn(
                    "CHANGE_ME",
                    value,
                    f"{key} in .env.example must be a CHANGE_ME placeholder, not {value!r}",
                )


class DeployFilesExistTest(unittest.TestCase):
    def test_all_deploy_files_present(self) -> None:
        for name in (
            "Dockerfile.api",
            "Dockerfile.worker",
            "entrypoint.sh",
            "docker-compose.yml",
            ".env.example",
            "verify-deploy.sh",
        ):
            self.assertTrue((_DEPLOY / name).is_file(), f"deploy/{name} missing")

    def test_dockerignore_is_at_the_build_context_root(self) -> None:
        # Both builds use the REPO ROOT as the docker context (compose `context: ..`,
        # verify-deploy.sh builds the repo root), and docker reads .dockerignore
        # ONLY from the context root -- a deploy/.dockerignore would be inert, so it
        # MUST live at the repo root to actually exclude .venv/.git/tests.
        root_ignore = _ROOT / ".dockerignore"
        self.assertTrue(root_ignore.is_file(), "repo-root .dockerignore missing")
        self.assertFalse(
            (_DEPLOY / ".dockerignore").exists(),
            "deploy/.dockerignore is inert (context is the repo root)",
        )
        text = root_ignore.read_text()
        for excluded in (".venv", ".git", "tests"):
            self.assertIn(excluded, text, f".dockerignore must exclude {excluded}")


class DockerfileApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (_DEPLOY / "Dockerfile.api").read_text()

    def test_installs_the_deploy_extra(self) -> None:
        self.assertIn("[deploy]", self.text)

    def test_control_plane_is_docker_free(self) -> None:
        # REQ-INV-010 as a static guard: no docker CLI package install, no socket.
        # (The verify harness proves it on the built image.) `docker.io` /
        # `docker-ce` are the apt package names; `docker.sock` is the socket path.
        self.assertNotIn("docker.io", self.text)
        self.assertNotIn("docker-ce", self.text)
        self.assertNotIn("docker.sock", self.text)

    def test_pinned_base_and_non_root(self) -> None:
        self.assertIn("FROM python:3.12-slim", self.text)
        self.assertIn("USER ctfgen", self.text)


class DockerfileWorkerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (_DEPLOY / "Dockerfile.worker").read_text()

    def test_installs_the_worker_extra_and_documents_runtime_reqs(self) -> None:
        self.assertIn("[worker]", self.text)
        # The rootless + NET_ADMIN runtime posture is documented honestly.
        self.assertIn("NET_ADMIN", self.text)
        self.assertIn("ROOTLESS", self.text.upper())


class EntrypointTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (_DEPLOY / "entrypoint.sh").read_text()

    def test_migrate_then_serve_order(self) -> None:
        self.assertIn("set -euo pipefail", self.text)
        alembic_at = self.text.find("alembic -c alembic.ini upgrade head")
        uvicorn_at = self.text.find("uvicorn ctf_generator.interfaces.api.app:app")
        self.assertGreater(alembic_at, -1, "entrypoint must run alembic upgrade")
        self.assertGreater(uvicorn_at, -1, "entrypoint must serve via uvicorn")
        self.assertLess(alembic_at, uvicorn_at, "migrate must run BEFORE serve")

    def test_no_auto_bootstrap_admin(self) -> None:
        # bootstrap-admin is a documented ONE-TIME manual step, never auto-run.
        for line in self.text.splitlines():
            code = line.split("#", 1)[0]
            self.assertNotIn("bootstrap-admin", code)

    def test_serves_worker_gateway_mode(self) -> None:
        self.assertIn(
            "uvicorn ctf_generator.interfaces.api.worker_app:worker_app", self.text
        )


class ComposeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (_DEPLOY / "docker-compose.yml").read_text()

    def test_no_baked_secret(self) -> None:
        # No placeholder/secret literal is baked; secrets come via ${VAR}.
        self.assertNotIn("CHANGE_ME", self.text)
        self.assertIn("${POSTGRES_PASSWORD}", self.text)

    def test_no_docker_socket_on_control_plane(self) -> None:
        # The control-plane compose never mounts the docker socket.
        self.assertNotIn("docker.sock", self.text)

    def test_documents_worker_separation(self) -> None:
        upper = self.text.upper()
        self.assertIn("SEPARATE HOST", upper)
        self.assertIn("REQ-INV-010", self.text)

    def test_ready_healthcheck_and_migrate_on_start(self) -> None:
        # The system router is mounted under /api/v1, so the readiness probe MUST
        # use the prefixed path (a bare /system/ready 404s).
        self.assertIn("/api/v1/system/ready", self.text)
        self.assertIn("service_healthy", self.text)


if __name__ == "__main__":
    unittest.main()
