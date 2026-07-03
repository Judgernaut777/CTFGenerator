from __future__ import annotations

import base64
import json
import random
import unittest
import xml.etree.ElementTree as ET

from ctf_generator.models import ChallengeSpec
from ctf_generator.templates import mobile


def _spec(**overrides: object) -> ChallengeSpec:
    defaults = dict(
        title="Vault Prefs",
        category="mobile",
        difficulty="medium",
        family=mobile.FAMILY_NAME,
        seed="mobile-seed-1",
        learning_objectives=["Understand insecure on-device storage (CWE-312/CWE-798)"],
        checkpoints=[
            "locates the hardcoded XOR key in CryptoVault.java",
            "locates the encrypted value in shared_prefs",
            "recognizes the debug credentials in LoginActivity as a decoy",
            "decrypts the shared_prefs value with the hardcoded key",
            "extracts the flag",
        ],
    )
    defaults.update(overrides)
    return ChallengeSpec(**defaults)  # type: ignore[arg-type]


class ModuleInterfaceTests(unittest.TestCase):
    def test_exports(self) -> None:
        self.assertEqual(mobile.FAMILY_NAME, "mobile_insecure_storage")
        self.assertEqual(mobile.CATEGORY, "mobile")
        self.assertEqual(mobile.MODES, ("red", "blue"))
        self.assertEqual(mobile.DIFFICULTIES, ("easy", "medium", "hard"))
        self.assertTrue(mobile.CVE_DRIVEN)
        self.assertTrue(mobile.LLM_BRIEF)
        self.assertEqual(mobile.COMPOSE_MARKERS, ())
        self.assertIn("challenge.yaml", mobile.REQUIRED_FILES)
        self.assertIsInstance(mobile.SCORING_HINTS, dict)
        for key in ("has_worker", "has_queue", "live_interaction", "decoy_density"):
            self.assertIn(key, mobile.SCORING_HINTS)


class RenderShapeTests(unittest.TestCase):
    def test_render_emits_every_required_file_except_challenge_yaml(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        expected = set(mobile.REQUIRED_FILES) - {"challenge.yaml"}
        self.assertEqual(set(files), expected)
        for relative, content in files.items():
            self.assertTrue(content, f"{relative} must not be empty")

    def test_render_supports_every_declared_mode(self) -> None:
        for mode in mobile.MODES:
            spec = _spec(mode=mode)
            files = mobile.render(spec, random.Random(spec.seed))
            expected = set(mobile.REQUIRED_FILES) - {"challenge.yaml"}
            self.assertEqual(set(files), expected, msg=f"mode={mode}")

    def test_no_compose_file_emitted(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        self.assertNotIn("docker-compose.yml", files)


class DeterminismTests(unittest.TestCase):
    def test_same_spec_and_rng_seed_is_byte_identical(self) -> None:
        spec = _spec()
        first = mobile.render(spec, random.Random("shared-seed"))
        second = mobile.render(spec, random.Random("shared-seed"))
        self.assertEqual(first, second)

    def test_same_spec_and_rng_seed_is_byte_identical_per_mode(self) -> None:
        for mode in mobile.MODES:
            spec = _spec(mode=mode)
            first = mobile.render(spec, random.Random("shared-seed"))
            second = mobile.render(spec, random.Random("shared-seed"))
            self.assertEqual(first, second, msg=f"mode={mode}")

    def test_different_rng_seed_changes_output(self) -> None:
        spec = _spec()
        first = mobile.render(spec, random.Random("seed-a"))
        second = mobile.render(spec, random.Random("seed-b"))
        self.assertNotEqual(first, second)

    def test_red_and_blue_rendered_with_same_rng_differ_only_in_framing(self) -> None:
        red = mobile.render(_spec(mode="red"), random.Random("shared-seed"))
        blue = mobile.render(_spec(mode="blue"), random.Random("shared-seed"))
        self.assertNotEqual(red["public/description.md"], blue["public/description.md"])
        # Underlying bundle (key material, ciphertext) is identical between
        # framings for the same rng -- only narrative framing differs.
        self.assertEqual(
            red[f"public/app/src/main/java/com/acmemobile/vault/CryptoVault.java"],
            blue[f"public/app/src/main/java/com/acmemobile/vault/CryptoVault.java"],
        )
        red_variant = json.loads(red["private/variant.json"])
        blue_variant = json.loads(blue["private/variant.json"])
        self.assertEqual(red_variant["flag"], blue_variant["flag"])

    def test_cve_record_is_accepted_and_stays_deterministic(self) -> None:
        from ctf_generator.cve_source import SnapshotCveSource

        record = SnapshotCveSource().get("CVE-2015-3860")
        self.assertIsNotNone(record)
        spec = _spec()
        first = mobile.render(spec, random.Random("shared-seed"), cve_record=record)
        second = mobile.render(spec, random.Random("shared-seed"), cve_record=record)
        self.assertEqual(first, second)
        self.assertIn(record.cve_id, first["public/description.md"])


class VariantJsonTests(unittest.TestCase):
    def test_variant_json_contains_flag_and_is_valid_json(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        variant = json.loads(files["private/variant.json"])
        self.assertIn("flag", variant)
        self.assertTrue(variant["flag"].startswith("ctf{"))
        self.assertEqual(variant["family"], mobile.FAMILY_NAME)
        self.assertIn("credentials", variant)
        self.assertIn("app", variant)
        self.assertIn("findings", variant)

    def test_flag_is_consistent_across_files(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        variant = json.loads(files["private/variant.json"])
        flag = variant["flag"]
        self.assertIn(flag, files["private/solution.md"])
        # The flag itself is never echoed in the public-facing bundle --
        # only the (encrypted-at-rest) shared_prefs/backup, the private
        # solution, and variant.json carry it.
        self.assertNotIn(flag, files["public/description.md"])
        self.assertNotIn(flag, files["public/app/shared_prefs/vault_prefs.xml"])
        self.assertNotIn(
            flag,
            files["public/app/src/main/java/com/acmemobile/vault/CryptoVault.java"],
        )


class BundleContentTests(unittest.TestCase):
    def test_hardcoded_key_present_in_crypto_vault(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        variant = json.loads(files["private/variant.json"])
        key_hex = variant["credentials"]["hardcoded_xor_key_hex"]
        source = files[
            "public/app/src/main/java/com/acmemobile/vault/CryptoVault.java"
        ]
        self.assertIn(key_hex, source)

    def test_shared_prefs_is_valid_xml_and_decrypts_to_flag(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        variant = json.loads(files["private/variant.json"])
        key = bytes.fromhex(variant["credentials"]["hardcoded_xor_key_hex"])

        prefs_xml = files["public/app/shared_prefs/vault_prefs.xml"]
        root = ET.fromstring(prefs_xml)
        pref_key = variant["storage"]["pref_key"]
        value = None
        for elem in root.findall("string"):
            if elem.get("name") == pref_key:
                value = elem.text
        self.assertIsNotNone(value)

        raw = base64.b64decode(value)
        decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)).decode("utf-8")
        envelope = json.loads(decrypted)
        self.assertEqual(envelope["value"], variant["flag"])

    def test_manifest_declares_backup_enabled(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        manifest = files["public/app/AndroidManifest.xml"]
        self.assertIn('android:allowBackup="true"', manifest)
        self.assertIn("backup_rules", manifest)

    def test_backup_rules_references_shared_prefs(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        rules = files["public/app/res/xml/backup_rules.xml"]
        self.assertIn("vault_prefs.xml", rules)

    def test_login_activity_contains_decoy_hardcoded_credentials(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        variant = json.loads(files["private/variant.json"])
        source = files[
            "public/app/src/main/java/com/acmemobile/vault/LoginActivity.java"
        ]
        self.assertIn(variant["credentials"]["debug_user"], source)
        self.assertIn(variant["credentials"]["debug_password"], source)

    def test_solver_source_is_syntactically_valid_python(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        solver_source = files["private/solver.py"]
        compile(solver_source, "solver.py", "exec")
        self.assertIn("XOR_KEY_HEX", solver_source)

    def test_healthcheck_source_is_syntactically_valid_python(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        compile(files["tests/healthcheck.py"], "healthcheck.py", "exec")


class CheckpointsTests(unittest.TestCase):
    def test_checkpoints_come_from_spec(self) -> None:
        spec = _spec()
        files = mobile.render(spec, random.Random(spec.seed))
        checkpoints_yaml = files["private/checkpoints.yaml"]
        for name in spec.checkpoints:
            self.assertIn(name, checkpoints_yaml)


if __name__ == "__main__":
    unittest.main()
