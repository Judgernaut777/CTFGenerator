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
        ):
            self.assertIn(expected, paths, f"missing path {expected}")

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
