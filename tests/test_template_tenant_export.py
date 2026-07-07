from __future__ import annotations

import json
import random
import unittest

from ctf_generator.models import ChallengeSpec
from ctf_generator.templates import tenant_export


def _spec(**overrides: object) -> ChallengeSpec:
    defaults = dict(
        title="Invoice Drift",
        category="web",
        difficulty="medium",
        family="web_business_logic_tenant_export",
        seed="web-seed-1",
        learning_objectives=["Trace an authorization boundary across services"],
        checkpoints=[
            "discovers profile and notice endpoints",
            "identifies the export workflow",
            "finds cross-tenant invoice metadata",
            "queues or enumerates an export it should not reach",
            "retrieves the generated export and extracts the flag",
        ],
    )
    defaults.update(overrides)
    return ChallengeSpec(**defaults)  # type: ignore[arg-type]


class ModuleInterfaceTests(unittest.TestCase):
    def test_vuln_classes_exposed(self) -> None:
        self.assertEqual(
            set(tenant_export.VULN_CLASSES), {"field_trust", "predictable_job_id"}
        )


class VariantJsonTests(unittest.TestCase):
    def test_variant_carries_vuln_class_and_stable_token_shape(self) -> None:
        spec = _spec()
        files = tenant_export.render_tenant_export(spec, random.Random(spec.seed))
        variant = json.loads(files["private/variant.json"])
        self.assertIn(variant["vuln_class"], tenant_export.VULN_CLASSES)
        # Token/route shape is class-independent (keeps variant-uniqueness scoring
        # stable regardless of the drawn class): 2 routes + 9 tokens.
        self.assertEqual(len(variant["routes"]), 2)
        self.assertEqual(len(variant["tokens"]), 9)

    def test_flag_is_consistent_and_not_in_public_prose(self) -> None:
        spec = _spec()
        files = tenant_export.render_tenant_export(spec, random.Random(spec.seed))
        # The flag lives in the runtime service source + .env, never in public prose.
        env_flag = files[".env.example"].split("CTFGEN_FLAG=", 1)[1].strip()
        self.assertTrue(env_flag.startswith("ctf{"))
        self.assertIn(env_flag, files["services/api/app.py"])
        self.assertIn(env_flag, files["services/worker/worker.py"])
        self.assertNotIn(env_flag, files["public/description.md"])
        self.assertNotIn(env_flag, files["public/hints.yaml"])


class AdaptiveSolverTests(unittest.TestCase):
    def test_solver_ships_both_techniques_and_compiles(self) -> None:
        # One adaptive, class-agnostic solver ships BOTH techniques, so it solves
        # any instance and any differently-classed sibling (validate-runtime +
        # cross-replay hold).
        spec = _spec()
        files = tenant_export.render_tenant_export(spec, random.Random(spec.seed))
        solver = files["private/solver.py"]
        self.assertIn("_try_field_trust", solver)
        self.assertIn("_try_predictable_job_id", solver)
        compile(solver, "solver.py", "exec")

    def test_solver_is_byte_identical_across_classes(self) -> None:
        # The solver carries no per-instance interpolation, so it is identical
        # for both classes -- the adaptation happens at runtime.
        ft = PerInstanceVulnClassTests()._render_class("field_trust")["private/solver.py"]
        pj = PerInstanceVulnClassTests()._render_class("predictable_job_id")["private/solver.py"]
        self.assertEqual(ft, pj)


class PerInstanceVulnClassTests(unittest.TestCase):
    """Front C: the vulnerability CLASS varies per instance, so a technique tied
    to one class does not generalise to a differently-classed sibling."""

    _OWNERSHIP_CHECK = 'job.get("created_by") != user'

    def _render_class(self, target: str):
        for i in range(200):
            spec = _spec(seed=f"vc-seed-{i}")
            files = tenant_export.render_tenant_export(spec, random.Random(spec.seed))
            if json.loads(files["private/variant.json"])["vuln_class"] == target:
                return files
        self.fail(f"no seed produced vuln_class={target}")

    def test_both_classes_are_reachable(self) -> None:
        for cls in tenant_export.VULN_CLASSES:
            with self.subTest(vuln_class=cls):
                self._render_class(cls)

    def test_field_trust_has_legacy_bypass_predictable_does_not(self) -> None:
        ft_app = self._render_class("field_trust")["services/api/app.py"]
        pj_app = self._render_class("predictable_job_id")["services/api/app.py"]
        # The legacy-tenant-field bypass exists ONLY in field_trust: forging the
        # field is exactly what fails on a predictable_job_id sibling.
        self.assertIn("not in body and INVOICES", ft_app)
        self.assertNotIn("not in body and INVOICES", pj_app)

    def test_predictable_uses_sequential_ids_and_idor_download(self) -> None:
        pj_app = self._render_class("predictable_job_id")["services/api/app.py"]
        ft_app = self._render_class("field_trust")["services/api/app.py"]
        # Sequential IDs + pre-seeded victim export exist only in predictable.
        self.assertIn('redis_client.incr("job_seq")', pj_app)
        self.assertIn("_ensure_seeded", pj_app)
        self.assertNotIn('redis_client.incr("job_seq")', ft_app)
        # IDOR: predictable's download drops the ownership check (present in
        # status only -> 1 occurrence); field_trust keeps it on both status and
        # download -> 2 occurrences. Enumeration on a field_trust sibling gets a
        # 403, so that technique does not transfer.
        self.assertEqual(pj_app.count(self._OWNERSHIP_CHECK), 1)
        self.assertEqual(ft_app.count(self._OWNERSHIP_CHECK), 2)

    def test_solution_prose_is_class_specific(self) -> None:
        ft_sol = self._render_class("field_trust")["private/solution.md"]
        pj_sol = self._render_class("predictable_job_id")["private/solution.md"]
        self.assertIn("field_trust", ft_sol)
        self.assertIn("predictable_job_id", pj_sol)


class DeterminismTests(unittest.TestCase):
    def test_same_seed_is_byte_identical(self) -> None:
        a = tenant_export.render_tenant_export(_spec(), random.Random("seed-x"))
        b = tenant_export.render_tenant_export(_spec(), random.Random("seed-x"))
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
