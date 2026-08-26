# OSINT Artifact Integration Implementation Plan

> **For Hermes:** Implement task-by-task with isolated Ox Alpha/OpenRouter coding agents, strict TDD, independent review, and parent-side verification.

**Goal:** Extend CTFGenerator with binary-safe deterministic artifact generation and OSINT-suitable answer verification, then add a separately packaged OSINT investigation family that CEI-Labs can consume without mixing project lore or ownership.

**Architecture:** CTFGenerator remains the platform and deterministic build engine. The core gains a binary-safe renderer value and pluggable typed answer-verifier dispatch. A separate `ctfgen-family-osint` package owns curated OSINT dossiers and seeded variants; CEI-Labs owns event content and may depend on/export from that plugin without copying CTFGenerator internals. Decima concepts and lore are excluded.

**Tech Stack:** Python 3.11+, frozen dataclasses/protocols, stdlib hashing/tarfile/mimetypes/json, pytest/unittest, CTFGenerator SDK entry points, FastAPI/PostgreSQL platform surfaces where already present.

---

## Delivery strategy

Deliver as reviewable vertical PRs rather than one risky cross-repository change:

1. **PR A — Binary-safe generated files** (implement now)
2. **PR B — Typed answer verifier strategies**
3. **PR C — Authoritative team-seed answer derivation**
4. **PR D — External OSINT artifact family and three curated templates**
5. **PR E — CEI-Labs adapter/export and pilot content migration**
6. **PR F — Judged analytical products** (optional after pilot)

Each PR must preserve deterministic builds, contestant/private separation, public API compatibility, and existing test behavior.

---

## PR A: Binary-safe generated files

### Task A1: Introduce the public rendered-file value

**Objective:** Let SDK families return text or exact binary bytes while retaining a stable public authoring type.

**Files:**
- Create: `src/ctf_generator/rendered_file.py`
- Modify: `src/ctf_generator/families.py`
- Modify: `src/ctf_generator/sdk/__init__.py`
- Modify: `docs/CHALLENGE_SDK.md`
- Test: `tests/test_binary_rendered_files.py`

**TDD steps:**
1. Add failing tests proving `RenderedFile.from_value()` or the selected minimal normalizer preserves bytes and UTF-8 encodes strings.
2. Run the focused test and confirm failure due to the missing API.
3. Add a frozen `RenderedFile` dataclass or narrow `str | bytes` normalization helper; avoid MIME/storage features not required by this PR.
4. Run focused tests and the SDK tests.
5. Commit.

### Task A2: Make hardened build publishing binary-safe

**Objective:** Preserve byte-identical binary payloads through validation, writing, manifests, and atomic publication.

**Files:**
- Modify: `src/ctf_generator/build.py`
- Test: `tests/test_build_hardening.py`
- Test: `tests/test_binary_rendered_files.py`

**TDD steps:**
1. Add a failing test with non-UTF-8 bytes under `public/evidence/sample.bin`.
2. Assert exact on-disk bytes and manifest SHA-256/size.
3. Confirm the old writer fails when attempting `.encode()` on bytes.
4. Implement one normalization seam; do not duplicate conversion in generator/materialization.
5. Run focused and build-hardening suites.
6. Commit.

### Task A3: Propagate the renderer contract through SDK lint/testing/generation

**Objective:** Ensure binary-returning external families lint, generate, rebuild deterministically, and remain private-leak safe.

**Files:**
- Modify: `src/ctf_generator/families.py`
- Modify: `src/ctf_generator/sdk/lint.py`
- Modify: `src/ctf_generator/testing.py` if required
- Modify: `docs/CHALLENGE_SDK.md`
- Test: `tests/test_sdk_lint.py`
- Test: `tests/test_sdk_author_testing.py`
- Test: `tests/test_families_integration.py`

**TDD steps:**
1. Add a binary family fixture that returns public and private byte files.
2. Confirm lint and determinism tests fail against the old assumptions.
3. Update type aliases and byte comparisons without weakening private-content detection.
4. Verify text-only families remain byte-identical.
5. Run full host test suite.
6. Commit.

### Task A4: Independent review and PR

**Objective:** Prove no leak, determinism, size-limit, or compatibility regression.

**Validation:**
- `PYTHONPATH=src python3 -m pytest tests/test_binary_rendered_files.py tests/test_build_hardening.py tests/test_sdk_lint.py tests/test_sdk_author_testing.py -q`
- `PYTHONPATH=src python3 -m unittest discover -s tests`
- `python3 -m compileall -q src tests`
- Independent Ox Alpha spec review.
- Independent Ox Alpha security/code-quality review.
- Push branch and open PR; report live CI honestly.

---

## PR B: Typed answer verifier strategies

### Task B1: Define answer specification types

**Objective:** Add immutable exact, alias, coordinate-tolerance, identifier, and multipart answer specifications without changing existing `spec['flag']` behavior.

**Likely files:**
- Create: `src/ctf_generator/domain/answers/models.py`
- Create: `src/ctf_generator/domain/answers/normalization.py`
- Modify: `src/ctf_generator/spec_generator.py`
- Modify: `src/ctf_generator/schema.py`
- Test: `tests/test_answer_spec.py`

### Task B2: Add verifier dispatch

**Objective:** Select a verifier from immutable published spec data and preserve constant-time exact comparison where applicable.

**Likely files:**
- Modify: `src/ctf_generator/application/submissions/verifier.py`
- Test: `tests/test_submission_verifier.py`

**Required cases:**
- Existing exact flags unchanged.
- Aliases support configured case/punctuation normalization.
- Coordinates use haversine distance and explicit meter tolerance.
- Identifiers support canonical prefix/separator normalization only when configured.
- Multipart submissions have an unambiguous serialized format or structured API input.
- Candidate values remain absent from logs, persistence, and score events.

### Task B3: API/schema compatibility

**Objective:** Expose answer-kind validation to authors without exposing private expected answers to contestants.

**Validation:** Full submission integration and API redaction suites.

---

## PR C: Authoritative team-seed derivation

### Task C1: Resolve the issued seed internally

**Objective:** Never trust `instance_seed` supplied by a contestant request.

**Likely files:**
- Modify: `src/ctf_generator/application/submissions/service.py`
- Modify: instance/artifact assignment repositories
- Modify: submission API schemas
- Test: new integration tests for seed spoofing and team isolation

### Task C2: Add family answer derivation hook

**Objective:** Let a deterministic family derive the canonical answer from the immutable version spec plus the server-resolved team seed.

**Constraints:**
- Hook is trusted installed family code.
- No expected answer is persisted in public artifacts.
- Same version+seed always yields the same answer.
- Cross-team seed replay fails.

---

## PR D: External OSINT investigation family

### Task D1: Scaffold private plugin package

**Files:**
- Create separate repository/package: `ctfgen-family-osint`
- Entry point: `ctf_generator.families`

**Family metadata:**
- `name='osint_investigation'`
- `category='osint'`
- initial `modes=('blue',)` until an investigative mode is justified
- `isolation_level='artifact'`
- no ports; no runtime container

### Task D2: Define dossier and curated variant schemas

**Required dossier fields:**
- Learning objective and primary method
- Player briefing
- Public evidence assets
- Private ground truth and solution
- Answer verifier specification
- Safety/privacy review
- Licensing/provenance
- Live source retrieval date and archived fallback
- Playtest state and timing
- Compatible curated variants/decoys

### Task D3: Implement three vertical templates

1. Image provenance/geolocation
2. Vessel or aircraft movement corroboration
3. Public-record/entity corroboration

Each template uses reviewed variant pools—not arbitrary generated facts.

### Task D4: Prove deterministic sibling behavior

**Required tests:**
- Same seed produces byte-identical bundle.
- Different seeds produce different reviewed cases.
- Every selected combination is compatible.
- Private answer never appears in public bytes.
- All evidence assets are present and hashed.
- Artifact family launches no runtime instance.

---

## PR E: CEI-Labs adapter and pilot migration

### Task E1: Remove cross-project contamination before migration

Audit CEI-Labs OSINT docs and generator for Decima-only concepts, especially “The Loom.” Replace with neutral, evidence-driven case framing; do not invent replacement canon without owner approval.

### Task E2: Select a pilot bank

Select approximately 12 evidence-complete leads from the current idea bank. Archive rather than delete the remaining ideas.

### Task E3: Export through CTFGenerator

Replace monolithic placeholder generation with either:
- OSINT plugin dossier inputs, or
- an explicit export adapter to CTFd during transition.

Do not duplicate canonical answers and writeups across files; generate derived docs from dossiers.

---

## PR F: Judged analytical products (post-pilot)

Add protected participant artifact submission, judge assignment, rubric dimensions, comments, multi-judge reconciliation, and score events. Keep ordinary deterministic solves separate so subjective grading cannot block core competition progress.

---

## Risks and controls

- **Binary private leaks:** retain and extend byte-level public/private leak tests.
- **Memory/disk abuse:** preserve file-count and aggregate-byte limits; test bytes at boundaries.
- **Seed spoofing:** server resolves assignment seed; contestant value is never authoritative.
- **Live-source drift:** require fallback captures and source provenance in OSINT dossiers.
- **Licensing:** keep CEI-Labs content, CTFGenerator core, OSINT plugin, and Decima separate; document permissions.
- **AI-resistance overclaim:** measure deterministic variation and verification burden; do not claim guaranteed AI resistance.
- **Plugin trust:** external family remains trusted installed code and must pass lint/tests before deployment.

## Completion criteria for the immediate implementation

PR A is complete only when binary public/private files survive generation exactly, manifests hash their real bytes, text-only family output is unchanged, SDK tests pass, independent reviewers approve, and a GitHub PR is open with verified CI state.
