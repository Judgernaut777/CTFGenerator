# Generator determinism-conformance suite (M20)

Single, **named** entry point for the CTFGenerator determinism/conformance
guarantees: `tests/test_conformance_suite.py`. This is evidence, not a claim —
it runs in the default host suite (no PostgreSQL, Docker, or network needed) and
asserts the invariants directly.

Today conformance was real but scattered across five modules. This suite
**aggregates** them (via the unittest `load_tests` protocol — no logic is
duplicated) and **adds** two direct, run-to-run assertions that had no explicit
home before: byte-identical rebuild and *no wall-clock in provenance*.

## What it proves

### New assertions (this module)

`DeterminismNoWallClockConformanceTests` regenerates one representative family
with a public surface (`web_business_logic_tenant_export`, the fixed spec a bare
`ctfgen create` uses) **twice** into disjoint temp dirs and asserts:

- **Determinism.** `test_same_seed_produces_byte_identical_tree_and_provenance`
  — the same `(family, spec, seed)` produces a byte-identical file tree (equal
  file set, equal SHA-256 per file), provenance stamps included. Unlike
  `test_baseline_fixtures` (which compares against a *committed* golden), this
  compares two live runs to each other.
- **No wall-clock in provenance.** `test_provenance_carries_no_wall_clock` reads
  the generator's real provenance stamps — the `.ctfgen-build` ownership marker
  and `private/manifest.json` / `public/manifest.json` (field names read from
  `src/ctf_generator/build.py`: `_build_manifests` / `write_build`, not
  invented) — and asserts:
  - no stamp value differs between the two runs (nothing time- or
    random-derived), and
  - no scalar value in any stamp parses as a timestamp of "now" (numeric epoch
    in seconds or ms, or an ISO-8601 datetime, within a 24 h window of the run).
  The one legitimately content-derived field, `spec_sha256`, is asserted present,
  identical across both runs (deterministic by construction), and shaped as a
  SHA-256 digest.
- **Non-vacuity guard.** `test_detector_fires_on_planted_now` proves the
  wall-clock detector actually fires on a real `now` (epoch seconds, epoch ms,
  ISO-8601 with `+00:00` and with `Z`) and does **not** false-positive on the
  provenance-shaped values (versions, family names, seeds, hex digests, counts).
  Without this, the negative assertion above could pass simply because the
  detector never triggers.

Provenance is **observed, never mutated** — the suite regenerates into temp dirs
and reads the emitted files; it does not touch scoring math, generator
determinism, golden fixtures, schemas, or migrations (charter §5).

### Aggregated (constituent) suites

Loaded into this module so one run executes the whole conformance set. Each
remains the source of truth for its own logic:

| Module | Invariant |
|---|---|
| `tests/test_baseline_fixtures.py` | Byte-stable golden manifests per (family, seed); no private-file content under `public/` |
| `tests/test_replay_validator.py` | Cross-seed replay — a sibling's solver must not solve a differently-seeded sibling's instance |
| `tests/test_sibling_validator.py` | Cross-sibling token uniqueness across generated variants |
| `tests/test_schema_versioning.py` | Spec/manifest schema compatibility + family capability contracts |
| `tests/test_models_golden.py` | Golden default `ChallengeSpec.to_mapping()` serialization shape |

## How to run

One command runs the full conformance set (new assertions + all five
constituents), on the host — no external services required:

```
PYTHONPATH=src:tests .venv/bin/python3 -m unittest test_conformance_suite
```

Verbose (to confirm the new no-wall-clock assertion executes and is not
skipped):

```
PYTHONPATH=src:tests .venv/bin/python3 -m unittest -v test_conformance_suite
```

Expected: **52 tests, OK**, with
`DeterminismNoWallClockConformanceTests.test_provenance_carries_no_wall_clock`
and `.test_detector_fires_on_planted_now` shown as `ok` (not skipped).

## Scope / honesty (charter §5)

- **host** — the entire suite runs and asserts on the host; nothing here is
  PG-gated, Docker-gated, or network-gated, so there is no skipped path to
  document.
- The determinism assertion covers one representative public-surface family for
  the run-to-run byte comparison; the *full* family × seed matrix is covered by
  the aggregated `test_baseline_fixtures` against committed goldens. The
  no-wall-clock assertion inspects that family's marker + both manifests, which
  share the provenance schema emitted for every family by `build.py`.
