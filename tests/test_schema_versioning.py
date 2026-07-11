"""Tests for Milestone 4 schema/versioning + family capability contracts."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ctf_generator import families, generator, schema
from ctf_generator.spec_generator import (
    default_spec,
    load_spec_document,
    spec_from_dict,
    spec_to_dict,
)


class SemverTests(unittest.TestCase):
    def test_parse(self) -> None:
        self.assertEqual(schema.parse_semver("1"), (1, 0, 0))
        self.assertEqual(schema.parse_semver("1.2"), (1, 2, 0))
        self.assertEqual(schema.parse_semver("1.2.3"), (1, 2, 3))

    def test_malformed(self) -> None:
        for bad in ("", "x", "1.2.3.4", "1.a"):
            with self.assertRaises(schema.SchemaError):
                schema.parse_semver(bad)


class CompatibilityTests(unittest.TestCase):
    def test_rejects_incompatible_major(self) -> None:
        with self.assertRaises(schema.IncompatibleSchemaError):
            schema.check_compatible(schema.SPEC_SCHEMA, "2.0")

    def test_accepts_newer_minor_forward_compatible(self) -> None:
        # current spec is 1.1; a same-major 1.9 document is additive -> accepted
        schema.check_compatible(schema.SPEC_SCHEMA, "1.9")

    def test_accepts_current_and_older_minor(self) -> None:
        schema.check_compatible(schema.SPEC_SCHEMA, "1.0")
        schema.check_compatible(schema.SPEC_SCHEMA, "1.1")

    def test_newer_minor_document_keeps_its_stamp(self) -> None:
        # a forward-compatible doc must NOT be downgraded to current
        out = schema.migrate(schema.SPEC_SCHEMA, {"schema_version": "1.5", "title": "x"})
        self.assertEqual(out["schema_version"], "1.5")
        self.assertEqual(out["schema"], schema.SPEC_SCHEMA)


class MigrationTests(unittest.TestCase):
    def test_unstamped_document_assumed_earliest(self) -> None:
        out = schema.migrate(schema.SPEC_SCHEMA, {"title": "x"})
        self.assertEqual(out["schema"], schema.SPEC_SCHEMA)
        self.assertEqual(out["schema_version"], schema.current_version(schema.SPEC_SCHEMA))

    def test_migrates_1_0_to_current(self) -> None:
        out = schema.migrate(schema.SPEC_SCHEMA, {"schema_version": "1.0", "title": "x"})
        self.assertEqual(out["schema_version"], "1.1")
        self.assertEqual(out["title"], "x")

    def test_rejects_wrong_schema_id(self) -> None:
        with self.assertRaises(schema.UnknownSchemaError):
            schema.migrate(schema.SPEC_SCHEMA, {"schema": "ctfgen.report", "schema_version": "1.0"})

    def test_rejects_incompatible_major(self) -> None:
        with self.assertRaises(schema.IncompatibleSchemaError):
            schema.migrate(schema.SPEC_SCHEMA, {"schema_version": "2.0"})

    def test_broken_chain_raises_not_silently_stamps(self) -> None:
        # A gap in the migration chain must raise, never stamp an un-upgraded
        # doc as current. Register a temporary schema with a missing link.
        sid = "ctfgen.test-broken-chain"
        schema.CURRENT_VERSIONS[sid] = "1.2"
        schema.register_migration(sid, "1.0", "1.1", lambda d: d)  # 1.1->1.2 missing
        try:
            with self.assertRaises(schema.SchemaError):
                schema.migrate(sid, {"schema_version": "1.0"})
        finally:
            schema.CURRENT_VERSIONS.pop(sid, None)
            schema._MIGRATIONS.pop((sid, "1.0"), None)


class SpecStampTests(unittest.TestCase):
    def test_spec_to_dict_is_stamped(self) -> None:
        d = spec_to_dict(default_spec(seed="s", title="T", difficulty="medium", family="crypto_token_forgery"))
        self.assertEqual(d["schema"], schema.SPEC_SCHEMA)
        self.assertEqual(d["schema_version"], "1.1")

    def test_spec_from_dict_accepts_unstamped(self) -> None:
        spec = default_spec(seed="s", title="T", difficulty="medium", family="crypto_token_forgery")
        raw = spec_to_dict(spec)
        del raw["schema"], raw["schema_version"]  # simulate a pre-M4 spec.json
        self.assertEqual(spec_from_dict(raw), spec)

    def test_spec_from_dict_rejects_future_major(self) -> None:
        spec = default_spec(seed="s", title="T", difficulty="medium", family="crypto_token_forgery")
        raw = spec_to_dict(spec)
        raw["schema_version"] = "2.0"
        with self.assertRaises(schema.IncompatibleSchemaError):
            spec_from_dict(raw)

    def test_load_spec_document_preserves_original(self) -> None:
        spec = default_spec(seed="s", title="T", difficulty="medium", family="crypto_token_forgery")
        raw = spec_to_dict(spec)
        raw["x_custom_field"] = {"kept": True}  # a key this version does not model
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "spec.json"
            p.write_text(json.dumps(raw), encoding="utf-8")
            parsed, original = load_spec_document(p)
        self.assertEqual(parsed, spec)  # parsed ignores the unknown key
        self.assertEqual(original["x_custom_field"], {"kept": True})  # original retains it


class FamilyMetadataTests(unittest.TestCase):
    def test_every_family_has_version_and_metadata(self) -> None:
        for name in families.family_names():
            fam = families.get(name)
            self.assertRegex(fam.version, r"^\d+\.\d+\.\d+$")
            meta = fam.metadata()
            self.assertEqual(meta["schema"], schema.FAMILY_METADATA_SCHEMA)
            self.assertEqual(meta["family"], name)
            self.assertEqual(meta["family_version"], fam.version)
            self.assertIn(meta["isolation_level"], {"container", "raw_tcp", "artifact"})
            self.assertIn(meta["maintenance_status"], {"stable", "beta", "experimental", "deprecated"})

    def test_known_capability_values(self) -> None:
        self.assertEqual(families.get("binary_heap_exploit").isolation_level, "raw_tcp")
        self.assertEqual(families.get("forensics_incident_triage").isolation_level, "artifact")
        self.assertEqual(families.get("cloud_metadata_ssrf").required_ports, (8080, 9000))
        # production-track categories are beta; the rest experimental
        self.assertEqual(families.get("web_business_logic_tenant_export").maintenance_status, "beta")
        self.assertEqual(families.get("crypto_token_forgery").maintenance_status, "experimental")

    def test_seed_varied_port_families_declare_no_fixed_ports(self) -> None:
        # scada/binary publish seed-randomized ports, so required_ports is empty
        # (a scheduler must discover them, not trust a fixed value).
        self.assertEqual(families.get("scada_ics_modbus_takeover").required_ports, ())
        self.assertEqual(families.get("binary_heap_exploit").required_ports, ())


class McpSchemaErrorHandlingTests(unittest.TestCase):
    def test_validate_spec_folds_schema_error_into_errors(self) -> None:
        from ctf_generator import mcp_server

        # a future-major spec must return a structured error, not raise
        result = mcp_server.validate_spec({"schema_version": "2.0", "title": "x"})
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])

    def test_create_from_spec_folds_schema_error_into_errors(self) -> None:
        from ctf_generator import mcp_server

        with tempfile.TemporaryDirectory() as tmp:
            mcp_server.set_workspace_root(tmp)
            result = mcp_server.create_from_spec(
                {"schema_version": "2.0", "title": "x"}, output_dir="chal"
            )
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])

    def test_manifest_records_family_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            generator.create_challenge(
                output_dir=out, seed="s1", title="T", difficulty="medium",
                family="crypto_token_forgery",
            )
            priv = json.loads((out / "private/manifest.json").read_text())
            self.assertEqual(priv["family_version"], families.get("crypto_token_forgery").version)


if __name__ == "__main__":
    unittest.main()
