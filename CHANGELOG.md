# Changelog

All notable changes to CTFGenerator are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release CI enforces that every tagged version has an entry here (see
`.github/workflows/release.yml`).

## [Unreleased]

### Added — Milestone 4: schema & family contracts

- New `ctf_generator.schema` module centralizes schema **identity, semantic
  versioning, compatibility, and migration**. Replaces three independent
  hard-coded `"1.0"` stamps that no consumer read (risk R-03) with real
  contracts: `check_compatible` rejects an incompatible major (or a
  newer-than-supported minor), and `migrate` upgrades older documents through a
  registered chain.
- Challenge specs are now **stamped and versioned** (`ctfgen.challenge-spec`
  1.1): `spec_to_dict` stamps, `spec_from_dict` migrates + rejects an unknown
  major (also at the MCP `build_spec`/`validate_spec` boundary). A pre-M4,
  unstamped `spec.json` still loads (assumed 1.0). New `load_spec_document`
  returns the parsed spec **and the verbatim original** so a caller can retain
  exactly what a user submitted (preserve-original-spec requirement).
- **Family capability contract**: `Family` gained a per-family `version`
  (independent of the generator version — closes the R-12 residual) plus a
  capability declaration (maintenance tier, supported modes/difficulties/
  architectures, isolation level, required ports, memory/cpu/build estimates,
  internet requirement, CVE-fidelity support) and a schema-stamped
  `metadata()`. Values grounded in each family's rendered compose. The build
  manifest now records `family_version`.
- Tests: `tests/test_schema_versioning.py` (semver, compatibility, migration,
  spec stamping/round-trip/reject-future-major, preserve-original, per-family
  metadata, manifest family_version). Golden fixtures regenerated; all families
  remain deterministic.
- Scope note: the execution-plane interface contracts the plan also lists under
  M4 (runtime-backend, artifact-store, job, and worker-result protocols) are
  deferred to land **with their consumers** in M7/M8, per the "no isolated
  framework code without a complete workflow" rule.

### Added — Milestone 3: filesystem & generation hardening

- New `ctf_generator.build` module is the single choke point that turns a
  family's rendered `{path: content}` mapping into an on-disk bundle safely.
  `generator.create_challenge` now routes through it, so **every** entry point
  (CLI `create`/`create-from-cve`, MCP tools) is hardened uniformly — not just
  the MCP workspace seam.
- **Path safety**: renderer paths are validated (no absolute, no `..`, no
  control/bidi-confusable chars, no reserved names, bounded length) and rejected
  case-insensitively if they would forge the build marker or a manifest;
  duplicate normalized paths (case-insensitive) are rejected.
- **Atomic publish**: builds are written to a temporary sibling directory and
  published with a move-aside + `os.replace`, so a failed or interrupted build
  can never replace or destroy a valid one; failed builds are retained under a
  unique `*.ctfgen-failed-*` directory for diagnosis.
- **Managed-deletion guard**: a `.ctfgen-build` ownership marker is written into
  every build; `--force` regeneration refuses to delete any non-empty directory
  that is not a CTFGenerator-managed build, a symlink, or a dangerous root
  (`/`, `$HOME`, cwd, shallow system paths).
- **Limits**: aggregate size (64 MiB) and file count (2000) are enforced.
- **Cryptographic manifests**: every build emits a `private/manifest.json`
  (SHA-256 of every file, seed, spec hash, generator/spec versions) and, when a
  public surface exists, a `public/manifest.json` containing **only** public
  file hashes — the seed (which deterministically derives the flag) and spec
  hash are never placed in a player-facing artifact.
- Adversarial test suite `tests/test_build_hardening.py` covering traversal,
  absolute paths, symlink escape, dangerous force targets, unmarked-directory
  deletion, duplicate/case-collision paths, oversized/over-count output,
  interrupted builds, partial-publish restore, and Unicode-confusable paths.
  Golden baseline fixtures regenerated to include the manifests; all 8 families
  remain deterministic. An adversarial security review of the module was run and
  its findings (incl. a seed-in-public-manifest leak) fixed before landing.

### Added — productization foundation (Milestones 0–2, security & ADRs)

- **Baseline golden fixtures** for all 8 challenge families across 2 seeds
  (`tests/fixtures/baseline/`) plus a regression test
  (`tests/test_baseline_fixtures.py`) that rebuilds each challenge in-process and
  asserts byte-for-byte agreement — enforcing the deterministic-rebuild invariant
  and the no-private-content-in-public invariant. Determinism confirmed for every
  family.
- **Current-system documentation** (Milestone 0): `docs/current-system.md`,
  `docs/current-cli.md`, `docs/current-schemas.md`, `docs/architecture/current.md`,
  `docs/risk-register.md`, and an ADR template `docs/adr/000-template.md`.
- **Product scope documentation** (Milestone 1): `docs/PRODUCT.md`,
  `docs/REQUIREMENTS.md`, `docs/SUPPORT_MATRIX.md`, `docs/RELEASE_CRITERIA.md`,
  `docs/MATURITY.md`.
- **Security workstream** (plan §7): `SECURITY.md` and
  `docs/security/{threat-model,runtime-isolation,secret-management,incident-response,responsible-disclosure}.md`.
- **Architecture Decision Records** for the load-bearing decisions:
  control/execution-plane boundary (ADR-001), PostgreSQL persistence (ADR-002),
  PostgreSQL-backed job queue (ADR-003), rootless container runtime (ADR-004),
  and package dependency boundaries (ADR-005), plus `docs/architecture/dependency-rules.md`.
- **CI foundation** (Milestone 2): `.github/workflows/{pr,nightly,release}.yml`
  with required gates (unit tests on 3.11/3.12, compileall, package build,
  deterministic-generation golden check, secret scan) and informational gates
  (ruff lint/format, mypy, bandit, pip-audit) that are promoted to required as
  the code is cleaned during the M5 refactor. Release builds produce checksums
  and a CycloneDX SBOM.
- Tooling config for ruff, mypy, and pytest in `pyproject.toml`, and a `ci`
  optional-dependency group.

### Notes

- No changes to the generator, families, or any runtime behavior in this
  foundation increment — the existing test suite remains green (712 tests).

## [0.1.0]

- Initial deterministic CTF generator/validator with 8 challenge families,
  static + Docker runtime validation, scoring, scenario engine, agent-eval
  harness, CVE sourcing, stdlib dashboard, and MCP server. See `README.md` and
  `docs/ARCHITECTURE.md` for the as-built system.
