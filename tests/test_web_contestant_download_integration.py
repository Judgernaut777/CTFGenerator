"""PostgreSQL integration tests for the M14 slice 14c-2 CONTESTANT public-artifact
download (web surface).

Closes the M12 deferral: a contestant can download a published challenge's PUBLIC
artifact bundle. The invariants under test mirror the contestant catalog reads:

* a contestant who can read COMP_A downloads the MATERIALIZED public artifact of a
  challenge published in A -> 200, ``Content-Type: application/x-tar``,
  ``Content-Disposition: attachment`` with the sanitized filename, and the body is
  EXACTLY the materialized tar bytes;
* R-22 at the DELIVERY boundary: the downloaded bytes carry ONLY ``public/`` paths
  and NOT the real generated flag / any private marker;
* a contestant of A gets an existence-hiding 404 on COMP_B's download;
* a published-but-UNMATERIALIZED challenge -> a friendly 404 (never a 500);
* an unpublished ``(slug, version)`` -> 404;
* an UNCONFIGURED store (``artifact_store=None``) -> a clean 404, never a 500.

The artifact is produced by the REAL
:class:`~ctf_generator.application.authoring.materialization.BuildMaterializationService`
over a REAL :class:`LocalFilesystemArtifactStore`, wired into the mounted web app.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_contestant_download_integration
"""

from __future__ import annotations

import io
import os
import re
import tarfile
import tempfile
import unittest
from pathlib import Path

try:
    import web_support as ws

    from ctf_generator import generator as _generator_module
    from ctf_generator.application.authoring.materialization import (
        BuildMaterializationService,
    )
    from ctf_generator.infrastructure.artifacts.local_store import (
        LocalFilesystemArtifactStore,
    )
    from ctf_generator.spec_generator import default_spec, spec_from_dict, spec_to_dict

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_SKIP_REASON = (
    f"[api]/[web]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_FAMILY = "web_business_logic_tenant_export"
_SLUG = "tenant-export"
_SEED = "download-seed-1"


def _renderable_spec() -> dict:
    """A full, renderable spec (spec_to_dict form) so materialization can render +
    strip a real public bundle -- not a bare ``{"title": ...}`` stub."""
    spec = default_spec(seed=_SEED, title="Tenant Export", difficulty="medium", family=_FAMILY)
    return spec_to_dict(spec)


def _rendered_flag(spec_dict: dict) -> str:
    """Render the FULL bundle out-of-band and extract the ACTUAL generated flag, so
    the delivery-boundary R-22 assertion checks the real secret token (not a generic
    ``ctf{`` format hint that the public description legitimately contains)."""
    spec = spec_from_dict(dict(spec_dict))
    with tempfile.TemporaryDirectory(prefix="download-flag-") as tmp:
        out = Path(tmp) / "bundle"
        _generator_module.create_challenge(
            output_dir=out,
            seed=spec.seed,
            title=spec.title,
            difficulty=spec.difficulty,
            family=spec.family,
            force=True,
            spec=spec,
        )
        env_text = (out / ".env.example").read_text(encoding="utf-8")
    match = re.search(r"ctf\{[^}]*\}", env_text)
    assert match is not None, "expected a generated flag in .env.example"
    return match.group(0)


def _seed_published(db, cid: str, slug: str) -> tuple[int, dict]:
    """Publish a renderable challenge attached to ``cid``; return (version_no, spec)."""
    spec_dict = _renderable_spec()
    _slug, ver = ws.seed_published_version(
        db, slug, "Tenant Export", family=_FAMILY, spec=spec_dict
    )
    ws.attach_publication(db, cid, slug, ver)
    return ver, spec_dict


def _materialize(db, store, slug: str, ver: int) -> bytes:
    """Materialize the public artifact and return its exact stored tar bytes."""
    build = BuildMaterializationService(db, store).materialize(slug, ver)
    data = store.get(build.storage_uri)
    assert data is not None
    return data


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ContestantDownloadWebTests(unittest.TestCase):
    def test_contestant_downloads_materialized_public_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dl-store-") as tmp:
            store = LocalFilesystemArtifactStore(Path(tmp) / "artifacts")
            with ws.web_client(artifact_store=store) as (client, db, _svc):
                ver, spec_dict = _seed_published(db, ws.COMP_A, _SLUG)
                tar_bytes = _materialize(db, store, _SLUG, ver)
                flag = _rendered_flag(spec_dict)

                ws.login(client, ws.EVE)  # player in COMP_A (competition:read)
                resp = client.get(
                    f"/app/competitions/{ws.COMP_A}/challenges/{_SLUG}/{ver}/download"
                )

                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertEqual(
                    resp.headers["content-type"], "application/x-tar"
                )
                self.assertEqual(
                    resp.headers["content-disposition"],
                    f'attachment; filename="{_SLUG}-v{ver}.tar"',
                )
                self.assertEqual(resp.headers["cache-control"], "no-store")
                # The body is EXACTLY the materialized tar bytes.
                self.assertEqual(resp.content, tar_bytes)

                # R-22 at the DELIVERY boundary: only public/ paths, no flag/private.
                names = tarfile.open(fileobj=io.BytesIO(resp.content)).getnames()
                self.assertTrue(names, "artifact tar is empty")
                self.assertTrue(
                    all(n.startswith("public/") for n in names),
                    f"non-public entry delivered: {names}",
                )
                self.assertNotIn(flag.encode("utf-8"), resp.content)
                self.assertNotIn(b"private/", resp.content)
                self.assertNotIn(b"solver.py", resp.content)
                self.assertNotIn(b"solution", resp.content)

    def test_cross_competition_download_is_existence_hiding_404(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dl-store-") as tmp:
            store = LocalFilesystemArtifactStore(Path(tmp) / "artifacts")
            with ws.web_client(artifact_store=store) as (client, db, _svc):
                # Published + materialized in COMP_B, where EVE has NO membership.
                ver, _spec = _seed_published(db, ws.COMP_B, _SLUG)
                _materialize(db, store, _SLUG, ver)

                ws.login(client, ws.EVE)  # member of COMP_A only
                resp = client.get(
                    f"/app/competitions/{ws.COMP_B}/challenges/{_SLUG}/{ver}/download"
                )
                self.assertEqual(resp.status_code, 404, resp.text)
                self.assertNotIn(ws.COMP_B, resp.text)  # never confirm existence

    def test_published_elsewhere_not_here_is_404_no_cross_tenant_leak(self) -> None:
        # The load-bearing tenancy guard: the resolver is competition-AGNOSTIC
        # (slug+version only), so the ONLY cross-tenant gate is the handler's
        # published-in-THIS-competition check. Prove it: EVE can read COMP_A, but
        # the (slug,ver) is published + materialized ONLY in COMP_B. A request via
        # the COMP_A path must 404 and NEVER stream COMP_B's materialized bytes --
        # if the published-here gate were removed, this would leak (200).
        with tempfile.TemporaryDirectory(prefix="dl-store-") as tmp:
            store = LocalFilesystemArtifactStore(Path(tmp) / "artifacts")
            with ws.web_client(artifact_store=store) as (client, db, _svc):
                ver, spec_dict = _seed_published(db, ws.COMP_B, _SLUG)  # COMP_B only
                tar_bytes = _materialize(db, store, _SLUG, ver)  # bytes DO exist
                flag = _rendered_flag(spec_dict)

                ws.login(client, ws.EVE)  # reader of COMP_A (passes authz), NOT B
                resp = client.get(
                    f"/app/competitions/{ws.COMP_A}/challenges/{_SLUG}/{ver}/download"
                )
                self.assertEqual(resp.status_code, 404, resp.text)
                # COMP_B's materialized artifact is NEVER served through COMP_A.
                self.assertNotEqual(resp.content, tar_bytes)
                self.assertNotIn(flag.encode("utf-8"), resp.content)

    def test_published_but_unmaterialized_is_friendly_404_not_500(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dl-store-") as tmp:
            store = LocalFilesystemArtifactStore(Path(tmp) / "artifacts")
            with ws.web_client(artifact_store=store) as (client, db, _svc):
                ver, _spec = _seed_published(db, ws.COMP_A, _SLUG)
                # Deliberately DO NOT materialize -> no build/bytes.
                ws.login(client, ws.EVE)
                resp = client.get(
                    f"/app/competitions/{ws.COMP_A}/challenges/{_SLUG}/{ver}/download"
                )
                self.assertEqual(resp.status_code, 404, resp.text)
                self.assertNotIn("Traceback", resp.text)

    def test_unpublished_version_is_404(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dl-store-") as tmp:
            store = LocalFilesystemArtifactStore(Path(tmp) / "artifacts")
            with ws.web_client(artifact_store=store) as (client, db, _svc):
                # A published+materialized v1, but request an unpublished v2.
                ver, _spec = _seed_published(db, ws.COMP_A, _SLUG)
                _materialize(db, store, _SLUG, ver)
                ws.login(client, ws.EVE)
                resp = client.get(
                    f"/app/competitions/{ws.COMP_A}/challenges/{_SLUG}/{ver + 1}/download"
                )
                self.assertEqual(resp.status_code, 404, resp.text)

    def test_unconfigured_store_is_clean_404_not_500(self) -> None:
        # artifact_store=None (CTFGEN_ARTIFACT_ROOT unset): the download service
        # resolves to None -> a friendly 404, never a 500.
        with ws.web_client(artifact_store=None) as (client, db, _svc):
            ver, _spec = _seed_published(db, ws.COMP_A, _SLUG)
            ws.login(client, ws.EVE)
            resp = client.get(
                f"/app/competitions/{ws.COMP_A}/challenges/{_SLUG}/{ver}/download"
            )
            self.assertEqual(resp.status_code, 404, resp.text)
            self.assertNotIn("Traceback", resp.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
