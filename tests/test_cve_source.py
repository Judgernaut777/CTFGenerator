from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ctf_generator.cve_source import (
    CATEGORIES,
    CachingCveSource,
    CveRecord,
    NvdCveSource,
    SnapshotCveSource,
    get_source,
)


def _canned_nvd_response() -> bytes:
    """A realistic (trimmed) NVD 2.0 API response shape for one CVE."""
    payload = {
        "resultsPerPage": 1,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "published": "2021-12-10T10:15:00.000",
                    "lastModified": "2021-12-14T00:00:00.000",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": (
                                "Apache Log4j2 JNDI features do not protect against "
                                "attacker-controlled LDAP endpoints, allowing remote "
                                "code execution via crafted log messages."
                            ),
                        },
                        {"lang": "es", "value": "Descripcion en espanol."},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": "CWE-502"}],
                        },
                        {
                            "source": "nvd@nist.gov",
                            "type": "Secondary",
                            "description": [{"lang": "en", "value": "CWE-400"}],
                        },
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
                        {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                    ],
                }
            }
        ],
    }
    return json.dumps(payload).encode("utf-8")


class SnapshotCveSourceTests(unittest.TestCase):
    def test_bundled_fixture_spans_required_categories(self) -> None:
        source = SnapshotCveSource()
        records = source.fetch(limit=100)
        self.assertGreaterEqual(len(records), 8)
        categories = {r.category for r in records}
        required = {"web", "scada_ics", "network", "crypto", "forensics", "cloud"}
        self.assertTrue(required.issubset(categories), categories)
        for record in records:
            self.assertIn(record.category, CATEGORIES)

    def test_fetch_filters_by_category(self) -> None:
        source = SnapshotCveSource()
        records = source.fetch(category="crypto")
        self.assertTrue(records)
        for record in records:
            self.assertEqual(record.category, "crypto")

    def test_fetch_filters_by_min_cvss(self) -> None:
        source = SnapshotCveSource()
        records = source.fetch(min_cvss=9.5)
        self.assertTrue(records)
        for record in records:
            self.assertGreaterEqual(record.cvss_score, 9.5)

    def test_fetch_filters_by_published_after(self) -> None:
        source = SnapshotCveSource()
        records = source.fetch(published_after="2020-01-01")
        self.assertTrue(records)
        for record in records:
            self.assertGreaterEqual(record.published, "2020-01-01")

    def test_fetch_filters_by_keyword(self) -> None:
        source = SnapshotCveSource()
        records = source.fetch(keyword="log4j")
        self.assertTrue(records)
        self.assertTrue(any("Log4j" in r.description or "Log4j" in " ".join(r.affected_products) for r in records))

    def test_fetch_respects_limit(self) -> None:
        source = SnapshotCveSource()
        records = source.fetch(limit=2)
        self.assertEqual(len(records), 2)

    def test_get_returns_matching_record(self) -> None:
        source = SnapshotCveSource()
        record = source.get("CVE-2021-44228")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.cve_id, "CVE-2021-44228")
        self.assertEqual(record.category, "web")

    def test_get_returns_none_for_unknown_id(self) -> None:
        source = SnapshotCveSource()
        self.assertIsNone(source.get("CVE-0000-00000"))

    def test_custom_records_override_bundled_fixture(self) -> None:
        custom = CveRecord(
            cve_id="CVE-9999-00001",
            published="2024-01-01",
            cvss_version="3.1",
            cvss_score=5.0,
            cvss_severity="MEDIUM",
            cwe_ids=["CWE-79"],
            category="web",
            affected_products=["Example App 1.0"],
            description="Example custom record.",
            references=[],
        )
        source = SnapshotCveSource(records=[custom])
        self.assertEqual(source.fetch(limit=100), [custom])
        self.assertIsNone(source.get("CVE-2021-44228"))

    def test_to_mapping_round_trips(self) -> None:
        source = SnapshotCveSource()
        record = source.get("CVE-2021-44228")
        assert record is not None
        mapping = record.to_mapping()
        self.assertEqual(mapping["cve_id"], "CVE-2021-44228")
        rebuilt = CveRecord(**mapping)
        self.assertEqual(rebuilt, record)

    def test_get_source_factory_default_is_snapshot(self) -> None:
        source = get_source()
        self.assertIsInstance(source, SnapshotCveSource)

    def test_get_source_factory_unknown_name_raises(self) -> None:
        with self.assertRaises(ValueError):
            get_source("bogus")


class NvdCveSourceTests(unittest.TestCase):
    def test_fetch_parses_nvd_json_shape(self) -> None:
        captured: dict = {}

        def fake_fetcher(url: str, headers: dict, timeout: int) -> bytes:
            captured["url"] = url
            captured["headers"] = headers
            captured["timeout"] = timeout
            return _canned_nvd_response()

        source = NvdCveSource(fetcher=fake_fetcher, timeout=5)
        records = source.fetch(limit=10)

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.cve_id, "CVE-2021-44228")
        self.assertEqual(record.published, "2021-12-10T10:15:00.000")
        self.assertEqual(record.cvss_version, "3.1")
        self.assertEqual(record.cvss_score, 10.0)
        self.assertEqual(record.cvss_severity, "CRITICAL")
        self.assertIn("CWE-502", record.cwe_ids)
        self.assertIn("CWE-400", record.cwe_ids)
        self.assertIn("log4j", record.description.lower())
        self.assertEqual(
            record.affected_products, ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"]
        )
        self.assertIn(
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", record.references
        )
        # CWE-400 maps to "network" before CWE-502 (no hint) is consulted --
        # classification takes the first CWE with a known hint.
        self.assertIn(record.category, CATEGORIES)
        self.assertEqual(captured["timeout"], 5)
        self.assertIn("resultsPerPage=10", captured["url"])

    def test_get_returns_matching_record_from_canned_response(self) -> None:
        def fake_fetcher(url: str, headers: dict, timeout: int) -> bytes:
            return _canned_nvd_response()

        source = NvdCveSource(fetcher=fake_fetcher)
        record = source.get("CVE-2021-44228")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.cve_id, "CVE-2021-44228")

    def test_get_returns_none_when_no_matching_id(self) -> None:
        def fake_fetcher(url: str, headers: dict, timeout: int) -> bytes:
            payload = {"vulnerabilities": []}
            return json.dumps(payload).encode("utf-8")

        source = NvdCveSource(fetcher=fake_fetcher)
        self.assertIsNone(source.get("CVE-0000-00000"))

    def test_api_key_included_in_headers_when_set(self) -> None:
        captured: dict = {}

        def fake_fetcher(url: str, headers: dict, timeout: int) -> bytes:
            captured["headers"] = headers
            return _canned_nvd_response()

        source = NvdCveSource(api_key="secret-key", fetcher=fake_fetcher)
        source.fetch()
        self.assertEqual(captured["headers"]["apiKey"], "secret-key")

    def test_get_source_factory_builds_nvd_source(self) -> None:
        def fake_fetcher(url: str, headers: dict, timeout: int) -> bytes:
            return _canned_nvd_response()

        source = get_source("nvd", fetcher=fake_fetcher)
        self.assertIsInstance(source, NvdCveSource)
        records = source.fetch()
        self.assertEqual(records[0].cve_id, "CVE-2021-44228")


class _FakeClock:
    def __init__(self, times: list[float]) -> None:
        self._times = list(times)

    def __call__(self) -> float:
        if len(self._times) > 1:
            return self._times.pop(0)
        return self._times[0]


class CachingCveSourceTests(unittest.TestCase):
    def test_cache_hit_avoids_second_backend_call(self) -> None:
        calls = {"count": 0}

        class _CountingSource:
            def fetch(self, **kwargs):
                calls["count"] += 1
                return [
                    CveRecord(
                        cve_id="CVE-2021-44228",
                        published="2021-12-10",
                        cvss_version="3.1",
                        cvss_score=10.0,
                        cvss_severity="CRITICAL",
                        cwe_ids=["CWE-502"],
                        category="web",
                        affected_products=["Apache Log4j2"],
                        description="desc",
                        references=[],
                    )
                ]

            def get(self, cve_id):
                calls["count"] += 1
                return None

        with tempfile.TemporaryDirectory() as tmp:
            clock = _FakeClock([100.0, 100.0, 100.0])
            source = CachingCveSource(
                _CountingSource(), cache_dir=Path(tmp), ttl_seconds=60.0, clock=clock
            )
            first = source.fetch(category="web")
            second = source.fetch(category="web")

        self.assertEqual(calls["count"], 1)
        self.assertEqual(first, second)

    def test_cache_expires_after_ttl(self) -> None:
        calls = {"count": 0}

        class _CountingSource:
            def fetch(self, **kwargs):
                calls["count"] += 1
                return [
                    CveRecord(
                        cve_id="CVE-2021-44228",
                        published="2021-12-10",
                        cvss_version="3.1",
                        cvss_score=10.0,
                        cvss_severity="CRITICAL",
                        cwe_ids=["CWE-502"],
                        category="web",
                        affected_products=["Apache Log4j2"],
                        description="desc",
                        references=[],
                    )
                ]

            def get(self, cve_id):
                return None

        with tempfile.TemporaryDirectory() as tmp:
            # First fetch writes cache at t=0 with ttl=60 -> expires_at=60.
            # Second fetch reads cache at t=200, well past expiry.
            clock = _FakeClock([0.0, 200.0])
            source = CachingCveSource(
                _CountingSource(), cache_dir=Path(tmp), ttl_seconds=60.0, clock=clock
            )
            source.fetch(category="web")
            source.fetch(category="web")

        self.assertEqual(calls["count"], 2)

    def test_get_caches_none_result(self) -> None:
        calls = {"count": 0}

        class _CountingSource:
            def fetch(self, **kwargs):
                return []

            def get(self, cve_id):
                calls["count"] += 1
                return None

        with tempfile.TemporaryDirectory() as tmp:
            clock = _FakeClock([50.0, 50.0])
            source = CachingCveSource(
                _CountingSource(), cache_dir=Path(tmp), ttl_seconds=60.0, clock=clock
            )
            first = source.get("CVE-0000-00000")
            second = source.get("CVE-0000-00000")

        self.assertIsNone(first)
        self.assertIsNone(second)
        self.assertEqual(calls["count"], 1)

    def test_cache_persists_across_instances_in_same_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            clock = _FakeClock([10.0, 10.0])
            snapshot = SnapshotCveSource()
            source_a = CachingCveSource(
                snapshot, cache_dir=Path(tmp), ttl_seconds=60.0, clock=clock
            )
            first = source_a.fetch(category="crypto")

            # A fresh instance pointed at the same cache dir should read the
            # cached JSON rather than recomputing from a (possibly different)
            # backend.
            class _ExplodingSource:
                def fetch(self, **kwargs):
                    raise AssertionError("backend should not be called on cache hit")

                def get(self, cve_id):
                    raise AssertionError("backend should not be called on cache hit")

            source_b = CachingCveSource(
                _ExplodingSource(), cache_dir=Path(tmp), ttl_seconds=60.0, clock=clock
            )
            second = source_b.fetch(category="crypto")

        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
