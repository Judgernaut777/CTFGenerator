"""Host tests for the compose-as-manifest parser (build_challenge tail slice C).

Stdlib + PyYAML; no Docker. Proves the strict allowlist, path safety, ordering,
and the single-image fallthrough.
"""

from __future__ import annotations

import unittest

from ctf_generator.application.execution.compose_manifest import (
    MAX_STACK_SERVICES,
    ComposeManifestError,
    parse_compose_manifest,
)

# A two-service compose shaped like the network_lateral_pivot family's output.
_NET_COMPOSE = """
services:
  internal:
    build: ./services/internal
    expose: ["9443"]
    networks: [backend]
    read_only: true
    cap_drop: [ALL]
  edge:
    build: ./services/edge
    ports: ["8080:8080"]
    depends_on: [internal]
    networks: [frontend, backend]
networks:
  frontend: {}
  backend: {internal: true}
"""


class ComposeManifestTests(unittest.TestCase):
    def test_single_image_shapes_return_none(self) -> None:
        self.assertIsNone(parse_compose_manifest(None))
        self.assertIsNone(parse_compose_manifest(""))
        self.assertIsNone(parse_compose_manifest("   "))
        self.assertIsNone(parse_compose_manifest("services: {}"))
        self.assertIsNone(parse_compose_manifest("not_a_services_doc: 1"))

    def test_parses_the_network_family_shape(self) -> None:
        manifest = parse_compose_manifest(_NET_COMPOSE)
        assert manifest is not None
        names = [s.name for s in manifest.services]
        self.assertEqual(set(names), {"internal", "edge"})
        # depends_on order: internal before edge.
        self.assertLess(names.index("internal"), names.index("edge"))
        edge = next(s for s in manifest.services if s.name == "edge")
        internal = next(s for s in manifest.services if s.name == "internal")
        self.assertEqual(edge.build_context, "services/edge")
        self.assertEqual(edge.depends_on, ("internal",))
        self.assertEqual(internal.expose, ("9443",))
        # Primary = the service with host `ports:` (the ingress).
        self.assertTrue(edge.is_primary)
        self.assertFalse(internal.is_primary)
        self.assertIs(manifest.primary, edge)

    def test_runtime_directives_are_ignored_not_honored(self) -> None:
        # cap_drop/networks/read_only/ports never surface -- ContainerPolicy is
        # authoritative; only build/expose/depends_on are read.
        manifest = parse_compose_manifest(_NET_COMPOSE)
        assert manifest is not None
        for svc in manifest.services:
            self.assertFalse(hasattr(svc, "cap_drop"))
            self.assertFalse(hasattr(svc, "networks"))

    def test_primary_defaults_to_first_when_no_ports(self) -> None:
        manifest = parse_compose_manifest(
            "services:\n"
            "  bbb: {build: ./services/bbb}\n"
            "  aaa: {build: ./services/aaa, depends_on: [bbb]}\n"
        )
        assert manifest is not None
        # No `ports` anywhere -> lexicographically-first (aaa) is primary.
        self.assertEqual(manifest.primary.name, "aaa")

    def test_absolute_build_context_is_refused(self) -> None:
        with self.assertRaises(ComposeManifestError):
            parse_compose_manifest("services:\n  x: {build: /etc}\n")

    def test_parent_escape_build_context_is_refused(self) -> None:
        with self.assertRaises(ComposeManifestError):
            parse_compose_manifest("services:\n  x: {build: ../../etc}\n")

    def test_image_only_service_is_refused(self) -> None:
        with self.assertRaises(ComposeManifestError):
            parse_compose_manifest("services:\n  x: {image: alpine}\n")

    def test_depends_on_cycle_is_refused(self) -> None:
        with self.assertRaises(ComposeManifestError):
            parse_compose_manifest(
                "services:\n"
                "  a: {build: ./a, depends_on: [b]}\n"
                "  b: {build: ./b, depends_on: [a]}\n"
            )

    def test_unknown_dependency_is_refused(self) -> None:
        with self.assertRaises(ComposeManifestError):
            parse_compose_manifest(
                "services:\n  a: {build: ./a, depends_on: [ghost]}\n"
            )

    def test_too_many_services_is_refused(self) -> None:
        svcs = "".join(
            f"  s{i}: {{build: ./s{i}}}\n" for i in range(MAX_STACK_SERVICES + 1)
        )
        with self.assertRaises(ComposeManifestError):
            parse_compose_manifest("services:\n" + svcs)

    def test_long_form_build_and_depends_on(self) -> None:
        manifest = parse_compose_manifest(
            "services:\n"
            "  a: {build: {context: ./services/a}}\n"
            "  b: {build: ./services/b, depends_on: {a: {condition: started}}}\n"
        )
        assert manifest is not None
        a = next(s for s in manifest.services if s.name == "a")
        b = next(s for s in manifest.services if s.name == "b")
        self.assertEqual(a.build_context, "services/a")
        self.assertEqual(b.depends_on, ("a",))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
