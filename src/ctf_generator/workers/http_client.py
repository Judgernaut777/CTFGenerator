"""Networked control-plane client for the worker run loop (M9 slice d).

:class:`HttpControlPlaneClient` implements
:class:`~ctf_generator.workers.worker.WorkerControlPlaneClient` over HTTP against
the worker gateway (``interfaces/api/worker_gateway``). It is the NETWORKED
counterpart to the in-process :class:`~ctf_generator.workers.local_client.LocalControlPlaneClient`:
behavior-equivalent for the worker loop (same inputs -> same domain objects / same
exception types), differing only in transport.

Security boundary (docs/security/runtime-isolation.md, ADR-001):

* The client is constructed with the control-plane base URL and the worker's OWN
  scoped bearer token (from worker config / enrollment) -- NEVER a control-plane DB
  credential and NEVER a signing key. It sends the bearer on every call.
* It maps each HTTP error response BACK to the SAME exception type the run loop
  expects, so ``run_once`` behaves identically to the Local path:

    401 -> WorkerAuthenticationError   (rejected / rotated / expired credential)
    403 forbidden_ownership -> InstanceOwnershipError
    403 (other)             -> ScopeError
    409 worker_draining     -> WorkerDrainingError
    409 worker_stale        -> WorkerStaleError
    404                     -> LookupError (get_instance maps 404 -> None first)
    400 / 422               -> ValueError
    other 4xx/5xx           -> RuntimeError (never leaks the response internals)

The credential token is never logged; error text is never derived from response
bodies that could carry a name we did not put there.
"""

from __future__ import annotations

from datetime import datetime

import httpx

from ctf_generator.application.execution.worker_instance_service import (
    InstanceOwnershipError,
)
from ctf_generator.application.execution.worker_job_service import (
    WorkerAuthenticationError,
    WorkerDrainingError,
    WorkerStaleError,
)
from ctf_generator.application.worker_enrollment import ScopeError
from ctf_generator.domain.execution.runtime import BuildBundle, MAX_BUILD_BUNDLE_BYTES
from ctf_generator.domain.instances.models import (
    HealthObservation,
    Instance,
    InstanceEndpoint,
    RuntimeResource,
)
from ctf_generator.domain.work.models import Job, JobLease

_DEFAULT_TIMEOUT = 30.0


class HttpControlPlaneClient:
    """HTTP ``WorkerControlPlaneClient`` over the worker gateway.

    Accepts either a ready :class:`httpx.Client` (tests inject the FastAPI
    ``TestClient``, whose transport speaks the ASGI app directly) or builds one
    from ``base_url``. The bearer token is the ONLY credential it holds."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        token: str,
        prefix: str = "/api/v1",
        client: httpx.Client | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        if client is None and not base_url:
            raise ValueError("either base_url or an httpx client must be given")
        self._client = client or httpx.Client(base_url=base_url, timeout=timeout)
        self._token = token
        self._prefix = prefix.rstrip("/")

    # -- transport -------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    def _post(self, path: str, json: dict | None = None) -> httpx.Response:
        return self._client.post(
            f"{self._prefix}{path}", json=json or {}, headers=self._headers()
        )

    def _get(self, path: str) -> httpx.Response:
        return self._client.get(f"{self._prefix}{path}", headers=self._headers())

    @staticmethod
    def _error_code(response: httpx.Response) -> str:
        try:
            return response.json().get("error", {}).get("code", "")
        except (ValueError, AttributeError):  # pragma: no cover - non-JSON error body
            return ""

    def _raise_for_status(self, response: httpx.Response) -> None:
        """Map a non-2xx worker-gateway response onto the loop's exception types.
        A 2xx returns cleanly. Never surfaces the raw response body."""
        status = response.status_code
        if status < 400:
            return
        code = self._error_code(response)
        if status == 401:
            raise WorkerAuthenticationError("worker credential rejected")
        if status == 404:
            raise LookupError("resource not found")
        if status == 403:
            if code == "forbidden_ownership":
                raise InstanceOwnershipError("worker does not own this instance")
            raise ScopeError("credential lacks the required scope")
        if status == 409:
            if code == "worker_draining":
                raise WorkerDrainingError("worker is draining; cannot claim new work")
            if code == "worker_stale":
                raise WorkerStaleError("worker liveness heartbeat is stale")
            raise RuntimeError("worker gateway conflict")
        if status in (400, 422):
            raise ValueError("worker gateway rejected the request")
        raise RuntimeError(f"worker gateway error (status {status})")

    # -- credential ------------------------------------------------------------

    def authenticate(self, now: datetime) -> str:
        """Validate the credential against ``POST /worker/auth`` and return the
        live bearer token. A rejected (rotated / expired / revoked) credential
        surfaces as :class:`WorkerAuthenticationError` -- the same signal the loop
        already handles when a credential goes bad on the Local path."""
        response = self._post("/worker/auth")
        self._raise_for_status(response)
        return self._token

    # -- queue verbs -----------------------------------------------------------

    def claim(self, token: str, lease_seconds: int, now: datetime) -> JobLease | None:
        response = self._post(
            "/worker/jobs/claim", {"lease_seconds": lease_seconds}
        )
        if response.status_code == 204:
            return None
        self._raise_for_status(response)
        return _job_lease_from_wire(response.json())

    def start(self, token: str, job_id: str, lease_token: str, now: datetime) -> None:
        response = self._post(
            f"/worker/jobs/{job_id}/start", {"lease_token": lease_token}
        )
        self._raise_for_status(response)

    def heartbeat(
        self, token: str, job_id: str, lease_token: str, lease_seconds: int, now: datetime
    ) -> bool:
        response = self._post(
            f"/worker/jobs/{job_id}/heartbeat",
            {"lease_token": lease_token, "lease_seconds": lease_seconds},
        )
        self._raise_for_status(response)
        return bool(response.json()["cancel_requested"])

    def complete(
        self, token: str, job_id: str, lease_token: str, result: dict | None, now: datetime
    ) -> None:
        response = self._post(
            f"/worker/jobs/{job_id}/complete",
            {"lease_token": lease_token, "result": result},
        )
        self._raise_for_status(response)

    def fail(
        self,
        token: str,
        job_id: str,
        lease_token: str,
        error_class: str,
        error_detail: str | None,
        retryable: bool,
        now: datetime,
    ) -> None:
        response = self._post(
            f"/worker/jobs/{job_id}/fail",
            {
                "lease_token": lease_token,
                "error_class": error_class,
                "error_detail": error_detail,
                "retryable": retryable,
            },
        )
        self._raise_for_status(response)

    # -- instance facts --------------------------------------------------------

    def get_instance(self, instance_id: str) -> Instance | None:
        response = self._get(f"/worker/instances/{instance_id}")
        if response.status_code == 404:
            # Behavior-equivalent with the Local path (a missing instance is None,
            # which the loop turns into a LookupError itself).
            return None
        self._raise_for_status(response)
        return _instance_from_wire(response.json())

    def replace_instance(self, instance_id: str, now: datetime) -> Instance:
        response = self._post(f"/worker/instances/{instance_id}/replace")
        self._raise_for_status(response)
        return _instance_from_wire(response.json())

    def report_health(self, observation: HealthObservation, now: datetime) -> None:
        # The worker field is NOT sent -- the gateway stamps it from the credential.
        response = self._post(
            f"/worker/instances/{observation.instance_id}/health",
            {
                "observed_state": observation.observed_state,
                "healthy": observation.healthy,
                "generation": observation.generation,
                "observed_at": observation.observed_at.isoformat(),
                "detail": dict(observation.detail),
            },
        )
        self._raise_for_status(response)

    def report_runtime_resource(self, resource: RuntimeResource, now: datetime) -> None:
        response = self._post(
            f"/worker/instances/{resource.instance_id}/resource",
            {
                "kind": resource.kind,
                "external_ref": resource.external_ref,
                "generation": resource.generation,
                "state": resource.state,
            },
        )
        self._raise_for_status(response)

    def report_endpoint(self, endpoint: InstanceEndpoint, now: datetime) -> None:
        response = self._post(
            f"/worker/instances/{endpoint.instance_id}/endpoint",
            {
                "name": endpoint.name,
                "host": endpoint.host,
                "port": endpoint.port,
                "protocol": endpoint.protocol,
                "url": endpoint.url,
                "internal": endpoint.internal,
            },
        )
        self._raise_for_status(response)

    def transition_instance(
        self, instance_id: str, to_state: str, *, reason: str, now: datetime
    ) -> None:
        response = self._post(
            f"/worker/instances/{instance_id}/transition",
            {"to_state": to_state, "reason": reason},
        )
        self._raise_for_status(response)

    # -- build bundle (build_challenge) -----------------------------------------

    def fetch_build_bundle(
        self,
        definition_slug: str,
        version_no: int,
        job_id: str,
        lease_token: str,
        now: datetime,
    ) -> BuildBundle:
        """Fetch the FULL bundle, proving via ``job_id``/``lease_token`` query
        params that this worker holds a live lease on a matching
        build_challenge job (the lease-fence BLOCKER fix -- see
        ``WorkerBuildService``). Streamed rather than buffered by ``httpx`` in
        one shot, so the body is bounded against ``MAX_BUILD_BUNDLE_BYTES`` as
        it arrives -- both via an early ``Content-Length`` check and a running
        total across ``iter_bytes`` -- rather than trusting an unbounded
        response to fit in memory."""
        url = f"{self._prefix}/worker/builds/{definition_slug}/{version_no}/bundle"
        with self._client.stream(
            "GET",
            url,
            params={"job_id": job_id, "lease_token": lease_token},
            headers=self._headers(),
        ) as response:
            if response.status_code >= 400:
                response.read()  # a small JSON error envelope -- safe to buffer
                self._raise_for_status(response)
            content_length = response.headers.get("content-length")
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError:
                    declared = None
                if declared is not None and declared > MAX_BUILD_BUNDLE_BYTES:
                    raise ValueError(
                        f"build bundle Content-Length {declared} exceeds the "
                        f"{MAX_BUILD_BUNDLE_BYTES}-byte ceiling; refusing to fetch"
                    )
            chunks = bytearray()
            for chunk in response.iter_bytes():
                chunks += chunk
                if len(chunks) > MAX_BUILD_BUNDLE_BYTES:
                    raise ValueError(
                        f"build bundle body exceeds the {MAX_BUILD_BUNDLE_BYTES}-byte "
                        "ceiling; refusing to fetch"
                    )
            bundle_sha256 = response.headers.get("x-bundle-sha256", "")
            spec_sha256 = response.headers.get("x-spec-sha256", "")
        return BuildBundle(
            data=bytes(chunks), bundle_sha256=bundle_sha256, spec_sha256=spec_sha256
        )

    def close(self) -> None:  # pragma: no cover - lifecycle convenience
        self._client.close()


def _job_lease_from_wire(data: dict) -> JobLease:
    job = Job(
        job_id=data["job_id"],
        job_type=data["job_type"],
        idempotency_key=data["idempotency_key"],
        available_at=datetime.fromisoformat(data["available_at"]),
        status=data["status"],
        priority=data["priority"],
        payload=dict(data.get("payload") or {}),
        required_capabilities=tuple(data.get("required_capabilities") or ()),
        attempt_count=data["attempt_count"],
        max_attempts=data["max_attempts"],
        claimed_by=data.get("claimed_by"),
        competition_id=data.get("competition_id"),
        definition_slug=data.get("definition_slug"),
        version_no=data.get("version_no"),
    )
    return JobLease(
        job=job,
        lease_token=data["lease_token"],
        lease_expires_at=datetime.fromisoformat(data["lease_expires_at"]),
    )


def _instance_from_wire(data: dict) -> Instance:
    expires_at = data.get("expires_at")
    return Instance(
        instance_id=data["instance_id"],
        competition_id=data["competition_id"],
        team_name=data["team"],
        definition_slug=data["definition_slug"],
        version_no=data["version_no"],
        state=data["state"],
        desired_state=data["desired_state"],
        assigned_worker=data.get("assigned_worker"),
        generation=data["generation"],
        image_ref=data.get("image_ref"),
        expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
    )
