from __future__ import annotations

import random
import re
import unittest

from ctf_generator.cve_source import CveRecord
from ctf_generator.models import ChallengeSpec
from ctf_generator.templates import forensics


def _spec(**overrides: object) -> ChallengeSpec:
    defaults: dict[str, object] = dict(
        title="Incident Triage: Edge Gateway Compromise",
        category="forensics",
        difficulty="medium",
        family=forensics.FAMILY_NAME,
        seed="forensics-seed-1",
        learning_objectives=["obj-1", "obj-2"],
        checkpoints=[
            "identifies exploited CVE via corroborated waf-alert",
            "extracts attacker source IP from access.log",
            "correlates process execution in auth.log",
            "extracts dropped-file sha256 from strings dump",
            "assembles the flag from IOCs",
        ],
        mode="blue",
    )
    defaults.update(overrides)
    return ChallengeSpec(**defaults)  # type: ignore[arg-type]


def _cve_record(**overrides: object) -> CveRecord:
    defaults: dict[str, object] = dict(
        cve_id="CVE-2020-13379",
        published="2020-06-04",
        cvss_version="3.1",
        cvss_score=7.5,
        cvss_severity="HIGH",
        cwe_ids=["CWE-918"],
        category="forensics",
        affected_products=["Grafana before 6.7.4"],
        description="Grafana allows unauthenticated SSRF via the avatar proxy endpoint.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-13379"],
    )
    defaults.update(overrides)
    return CveRecord(**defaults)  # type: ignore[arg-type]


FLAG_RE = re.compile(r"^ctf\{[a-z0-9\-_]+\}$")


class ForensicsInterfaceTests(unittest.TestCase):
    def test_module_constants(self) -> None:
        self.assertEqual(forensics.FAMILY_NAME, "forensics_incident_triage")
        self.assertEqual(forensics.CATEGORY, "forensics")
        self.assertEqual(forensics.MODES, ("blue",))
        self.assertEqual(forensics.DIFFICULTIES, ("easy", "medium", "hard"))
        self.assertTrue(forensics.CVE_DRIVEN)
        self.assertTrue(forensics.LLM_BRIEF)
        self.assertEqual(forensics.COMPOSE_MARKERS, ())
        self.assertIn("has_worker", forensics.SCORING_HINTS)
        self.assertIn("has_queue", forensics.SCORING_HINTS)
        self.assertIn("live_interaction", forensics.SCORING_HINTS)
        self.assertIn("decoy_density", forensics.SCORING_HINTS)
        self.assertFalse(forensics.SCORING_HINTS["has_worker"])
        self.assertFalse(forensics.SCORING_HINTS["has_queue"])
        self.assertFalse(forensics.SCORING_HINTS["live_interaction"])
        self.assertIn("challenge.yaml", forensics.REQUIRED_FILES)


class ForensicsRenderTests(unittest.TestCase):
    def test_render_emits_every_required_file_except_challenge_yaml(self) -> None:
        spec = _spec()
        rng = random.Random(spec.seed)
        files = forensics.render(spec, rng, _cve_record())

        expected = set(forensics.REQUIRED_FILES) - {"challenge.yaml"}
        self.assertEqual(set(files.keys()), expected)
        for relative_path, content in files.items():
            self.assertIsInstance(content, str)
            self.assertTrue(content.strip(), f"{relative_path} must not be empty")

    def test_no_extra_files_beyond_required_files(self) -> None:
        spec = _spec()
        rng = random.Random(spec.seed)
        files = forensics.render(spec, rng, _cve_record())
        for relative_path in files:
            self.assertIn(relative_path, forensics.REQUIRED_FILES)

    def test_deterministic_with_cve_record(self) -> None:
        spec = _spec()
        rng1 = random.Random(spec.seed)
        rng2 = random.Random(spec.seed)
        files1 = forensics.render(spec, rng1, _cve_record())
        files2 = forensics.render(spec, rng2, _cve_record())
        self.assertEqual(files1, files2)

    def test_deterministic_without_cve_record(self) -> None:
        spec = _spec(seed="no-cve-seed")
        rng1 = random.Random(spec.seed)
        rng2 = random.Random(spec.seed)
        files1 = forensics.render(spec, rng1, None)
        files2 = forensics.render(spec, rng2, None)
        self.assertEqual(files1, files2)

    def test_deterministic_for_each_supported_mode(self) -> None:
        for mode in forensics.MODES:
            spec = _spec(mode=mode, seed=f"mode-seed-{mode}")
            rng1 = random.Random(spec.seed)
            rng2 = random.Random(spec.seed)
            files1 = forensics.render(spec, rng1, _cve_record())
            files2 = forensics.render(spec, rng2, _cve_record())
            self.assertEqual(files1, files2, f"render() not deterministic for mode={mode!r}")

    def test_different_seeds_produce_different_output(self) -> None:
        spec_a = _spec(seed="seed-alpha")
        spec_b = _spec(seed="seed-beta")
        files_a = forensics.render(spec_a, random.Random(spec_a.seed), _cve_record())
        files_b = forensics.render(spec_b, random.Random(spec_b.seed), _cve_record())
        self.assertNotEqual(files_a, files_b)

    def test_variant_json_contains_flag(self) -> None:
        spec = _spec()
        rng = random.Random(spec.seed)
        files = forensics.render(spec, rng, _cve_record())
        variant_text = files["private/variant.json"]
        self.assertIn('"flag"', variant_text)
        match = re.search(r'"flag":\s*"(ctf\{[^"]+\})"', variant_text)
        self.assertIsNotNone(match, "private/variant.json must contain a flag")
        flag = match.group(1)
        self.assertRegex(flag, FLAG_RE)

    def test_flag_uses_the_real_cve_not_the_decoy(self) -> None:
        record = _cve_record(cve_id="CVE-2018-13379", cwe_ids=["CWE-22"])
        spec = _spec()
        rng = random.Random(spec.seed)
        files = forensics.render(spec, rng, record)
        variant_text = files["private/variant.json"]
        match = re.search(r'"flag":\s*"(ctf\{[^"]+\})"', variant_text)
        flag = match.group(1)
        self.assertIn("cve-2018-13379", flag)

    def test_access_log_has_corroborated_and_decoy_waf_alerts(self) -> None:
        spec = _spec()
        rng = random.Random(spec.seed)
        files = forensics.render(spec, rng, _cve_record())
        access_log = files["public/artifacts/access.log"]
        alerts = re.findall(r'signature="(CVE-\d{4}-\d{4,})"', access_log)
        self.assertEqual(len(alerts), 2, "expected exactly one real + one decoy waf-alert")
        self.assertEqual(len(set(alerts)), 2, "real and decoy CVE ids must differ")

    def test_auth_log_references_dropped_filename(self) -> None:
        spec = _spec()
        rng = random.Random(spec.seed)
        files = forensics.render(spec, rng, _cve_record())
        variant_text = files["private/variant.json"]
        dropped_filename_match = re.search(r'"dropped_filename":\s*"([^"]+)"', variant_text)
        self.assertIsNotNone(dropped_filename_match)
        dropped_filename = dropped_filename_match.group(1)
        self.assertIn(dropped_filename, files["public/artifacts/auth.log"])
        self.assertIn(dropped_filename, files["public/artifacts/dropped_strings.txt"])

    def test_dropped_strings_contains_sha256_matching_variant(self) -> None:
        spec = _spec()
        rng = random.Random(spec.seed)
        files = forensics.render(spec, rng, _cve_record())
        variant_text = files["private/variant.json"]
        hash_match = re.search(r'"dropped_hash":\s*"([0-9a-f]{64})"', variant_text)
        self.assertIsNotNone(hash_match)
        dropped_hash = hash_match.group(1)
        self.assertIn(f"sha256:{dropped_hash}", files["public/artifacts/dropped_strings.txt"])

    def test_solver_derives_the_same_flag_as_variant_json(self) -> None:
        """End-to-end: run the private solver's own logic against the public
        artifacts and confirm it derives the same flag stamped in variant.json.

        This exercises the solver's *analysis logic* directly (imported from
        its rendered source via exec in an isolated namespace) rather than
        spawning a subprocess, keeping the test hermetic and network-free.
        """
        spec = _spec()
        rng = random.Random(spec.seed)
        files = forensics.render(spec, rng, _cve_record())

        namespace: dict[str, object] = {}
        solver_source = files["private/solver.py"]
        exec(compile(solver_source, "<solver>", "exec"), namespace)  # noqa: S102

        with _TempArtifacts(files) as artifacts_dir:
            flag = namespace["analyze"](artifacts_dir)

        variant_text = files["private/variant.json"]
        match = re.search(r'"flag":\s*"(ctf\{[^"]+\})"', variant_text)
        self.assertEqual(flag, match.group(1))

    def test_healthcheck_passes_against_rendered_artifacts(self) -> None:
        spec = _spec()
        rng = random.Random(spec.seed)
        files = forensics.render(spec, rng, _cve_record())

        namespace: dict[str, object] = {}
        healthcheck_source = files["tests/healthcheck.py"]
        exec(compile(healthcheck_source, "<healthcheck>", "exec"), namespace)  # noqa: S102

        with _TempArtifacts(files) as artifacts_dir:
            for filename, marker in namespace["REQUIRED_MARKERS"].items():
                text = (artifacts_dir / filename).read_text(encoding="utf-8")
                self.assertIn(marker, text)


class _TempArtifacts:
    """Materializes the ``public/artifacts/*`` files from a render() dict
    into a temporary directory, for exercising solver.py / healthcheck.py
    logic against real files without touching the network or Docker.
    """

    def __init__(self, files: dict[str, str]) -> None:
        self._files = files
        self._tmpdir = None

    def __enter__(self):
        import tempfile
        from pathlib import Path

        self._tmpdir = tempfile.TemporaryDirectory()
        artifacts_dir = Path(self._tmpdir.name)
        for relative_path, content in self._files.items():
            if not relative_path.startswith("public/artifacts/"):
                continue
            filename = relative_path.rsplit("/", 1)[-1]
            (artifacts_dir / filename).write_text(content, encoding="utf-8")
        return artifacts_dir

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
        return False


if __name__ == "__main__":
    unittest.main()
