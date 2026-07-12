"""OpenAPI contract tests for the M9 API ([api] extra; no database required).

Structural assertions that the generated schema exposes the slice-a resource
paths under ``/api/v1`` and that error responses reference the ``ctfgen.error``
envelope. Establishes the contract slice-b/c extend. SKIPS cleanly without the
``[api]`` extra.
"""

from __future__ import annotations

import json
import unittest

try:
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.settings import ApiSettings
    from ctf_generator.schema import ERROR_SCHEMA

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - only without the extra
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_SKIP = _IMPORT_ERROR is not None
_REASON = f"[api] extra not importable ({_IMPORT_ERROR})" if _SKIP else ""


@unittest.skipIf(_SKIP, _REASON)
class OpenApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = create_app(ApiSettings()).openapi()

    def test_openapi_served_under_api_v1(self) -> None:
        app = create_app(ApiSettings())
        self.assertEqual(app.openapi_url, "/api/v1/openapi.json")

    def test_slice_a_resource_paths_present(self) -> None:
        paths = self.spec["paths"]
        for expected in (
            "/api/v1/competitions",
            "/api/v1/competitions/{competition_id}",
            "/api/v1/teams",
            "/api/v1/teams/{competition_id}/{name}",
            "/api/v1/challenge-definitions",
            "/api/v1/challenge-definitions/{slug}",
            "/api/v1/challenge-versions",
            "/api/v1/challenge-versions/{definition_slug}/{version_no}",
            "/api/v1/challenge-versions/{definition_slug}/{version_no}/publish",
            "/api/v1/users",
            "/api/v1/users/{user_id}",
            "/api/v1/competitions/{competition_id}/submissions",
            "/api/v1/submissions/{submission_id}",
            "/api/v1/competitions/{competition_id}/scoreboard",
            "/api/v1/competitions/{competition_id}/scoreboard/lag",
        ):
            self.assertIn(expected, paths, f"missing path {expected}")

    def test_slice_b_verbs(self) -> None:
        paths = self.spec["paths"]
        self.assertEqual(set(paths["/api/v1/users"].keys()), {"get", "post"})
        self.assertEqual(
            set(paths["/api/v1/competitions/{competition_id}/submissions"].keys()),
            {"get", "post"},
        )
        self.assertEqual(
            set(paths["/api/v1/submissions/{submission_id}"].keys()), {"get"}
        )
        self.assertEqual(
            set(paths["/api/v1/competitions/{competition_id}/scoreboard"].keys()),
            {"get"},
        )

    def test_slice_c_resource_paths_present(self) -> None:
        paths = self.spec["paths"]
        for expected in (
            "/api/v1/instances",
            "/api/v1/instances/{instance_id}",
            "/api/v1/competitions/{competition_id}/instances",
            "/api/v1/instances/{instance_id}/stop",
            "/api/v1/instances/{instance_id}/reset",
            "/api/v1/instances/{instance_id}/delete",
            "/api/v1/challenge-definitions/{slug}/builds",
            "/api/v1/builds/{build_id}",
            "/api/v1/competitions/{competition_id}/publications",
            "/api/v1/competitions/{competition_id}/publications/"
            "{definition_slug}/{version_no}",
            "/api/v1/jobs/{job_id}",
            "/api/v1/jobs/dead-letter",
            "/api/v1/jobs/{job_id}/cancel",
            "/api/v1/jobs/{job_id}/retry",
            "/api/v1/system/health",
            "/api/v1/system/ready",
            "/api/v1/system/version",
        ):
            self.assertIn(expected, paths, f"missing path {expected}")

    def test_slice_c_verbs(self) -> None:
        paths = self.spec["paths"]
        self.assertEqual(set(paths["/api/v1/instances"].keys()), {"get", "post"})
        self.assertEqual(
            set(paths["/api/v1/instances/{instance_id}"].keys()), {"get"}
        )
        self.assertEqual(
            set(
                paths[
                    "/api/v1/competitions/{competition_id}/publications"
                ].keys()
            ),
            {"get", "post"},
        )
        self.assertEqual(
            set(
                paths[
                    "/api/v1/competitions/{competition_id}/publications/"
                    "{definition_slug}/{version_no}"
                ].keys()
            ),
            {"delete"},
        )
        self.assertEqual(
            set(paths["/api/v1/challenge-definitions/{slug}/builds"].keys()),
            {"get", "post"},
        )

    def test_system_probes_are_unauthenticated_in_spec(self) -> None:
        # The unauthenticated probes carry no security requirement and are not
        # documented with auth-related error codes.
        paths = self.spec["paths"]
        health = paths["/api/v1/system/health"]["get"]["responses"]
        self.assertIn("200", health)
        self.assertNotIn("401", health)

    def test_trigger_build_documents_202(self) -> None:
        responses = self.spec["paths"][
            "/api/v1/challenge-definitions/{slug}/builds"
        ]["post"]["responses"]
        self.assertIn("202", responses)
        for code in ("401", "403", "404", "409"):
            self.assertIn(code, responses)

    def test_submit_documents_201_and_error_codes(self) -> None:
        responses = self.spec["paths"][
            "/api/v1/competitions/{competition_id}/submissions"
        ]["post"]["responses"]
        self.assertIn("201", responses)
        for code in ("400", "401", "403", "404", "409", "422", "429"):
            self.assertIn(code, responses)

    def test_competitions_expose_full_crud_verbs(self) -> None:
        paths = self.spec["paths"]
        self.assertEqual(
            set(paths["/api/v1/competitions"].keys()), {"get", "post"}
        )
        self.assertEqual(
            set(paths["/api/v1/competitions/{competition_id}"].keys()),
            {"get", "patch"},
        )

    def test_error_envelope_schema_is_ctfgen_error(self) -> None:
        envelope = self.spec["components"]["schemas"]["ErrorEnvelope"]
        self.assertIn("error", envelope["properties"])
        self.assertEqual(
            envelope["properties"]["schema"]["default"], ERROR_SCHEMA
        )
        self.assertIn(ERROR_SCHEMA, json.dumps(envelope))

    def test_error_responses_reference_the_envelope(self) -> None:
        # Every documented non-2xx response across slice-a routes must point at
        # the shared ErrorEnvelope, not an ad-hoc shape.
        paths = self.spec["paths"]
        checked = 0
        for path, operations in paths.items():
            if not path.startswith("/api/v1/"):
                continue
            # The readiness probe legitimately returns its readiness body (not the
            # error envelope) on 503 when a dependency is down -- it is not an
            # error response, so it is exempt from the envelope invariant.
            if path == "/api/v1/system/ready":
                continue
            for operation in operations.values():
                for status, response in operation.get("responses", {}).items():
                    if not str(status).startswith(("4", "5")):
                        continue
                    schema = (
                        response.get("content", {})
                        .get("application/json", {})
                        .get("schema", {})
                    )
                    self.assertEqual(
                        schema.get("$ref"),
                        "#/components/schemas/ErrorEnvelope",
                        f"{path} {status} does not reference ErrorEnvelope",
                    )
                    checked += 1
        self.assertGreater(checked, 0)

    def test_create_competition_documents_201_and_error_codes(self) -> None:
        responses = self.spec["paths"]["/api/v1/competitions"]["post"]["responses"]
        self.assertIn("201", responses)
        for code in ("400", "401", "403", "409", "422", "429"):
            self.assertIn(code, responses)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
