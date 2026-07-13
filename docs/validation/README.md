# Validation program (M20)

The M20 validation program produces **executed evidence** for the product's
release criteria — not claims. Each document below is backed by a runnable
artifact (a test module or a script) that anyone can re-run; where a path cannot
be exercised on the validation host (no WAL/PITR, no LLM key, no real
multi-host worker fleet, no production-scale corpus) it is documented as
**UNVERIFIED** with the reason, never silently softened.

Executed-evidence artifacts, and what each proves:

| Area | Doc | Runnable artifact | Status |
|---|---|---|---|
| Deterministic-generator conformance | [conformance.md](conformance.md) | `tests/test_conformance_suite.py` (byte-stability + a **no-wall-clock-in-provenance** assertion) | executed, host-passing |
| Backup / restore DR (RTO) | [../operations/backup-recovery-upgrade.md §5](../operations/backup-recovery-upgrade.md) | `scripts/recovery_drill.sh` + `tests/test_recovery_drill_integration.py` (measures RTO wall-clock vs the ≤30 min SLO; negative controls) | executed vs live PG; **RPO (≤5 min continuous) UNVERIFIED — needs WAL/PITR**; production-volume RTO UNVERIFIED |
| Security gates S1–S9 | [security-checklist.md](security-checklist.md) | `tests/test_security_validation_meta.py` (maps each gate → its executed test, guards the mapping) | mapping executed; isolation/authz/immutability gates are **PG/Docker-gated** (run in integration env, not host `pr.yml`) |
| Full-stack e2e flow | [e2e.md](e2e.md) | `tests/test_e2e_flow_integration.py` (organizer→publish→contestant-submit→scoreboard over real PG) | executed vs live PG; real TLS socket + distributed-worker instance launch UNVERIFIED |
| Coverage measurement | [coverage.md](coverage.md) | `scripts/coverage.sh` + `.github/workflows/coverage.yml` (informational) | executed; informational floor, not a hard gate |
| Capacity / load (NFR-001..005) | [capacity.md](capacity.md) | `scripts/loadtest.py` + `tests/test_capacity_smoke_integration.py` (measured p50/p95 at smoke scale) | smoke executed; **production-scale 25-team run UNVERIFIED → M21/M22** |
| AI-resistance (flagship claim) | [ai-resistance.md](ai-resistance.md) | grounded report over `score.py`, `families.py` scenarios, the Evaluation Lab | honest: live scenario engine + integrity gate + measured single-host substrate are real; static-dimension gameability, generalization, and distributed/LLM eval remain UNVERIFIED |
| Internal-alpha gate dry-run (M21) | [internal-alpha-report.md](internal-alpha-report.md) | the alpha entry/exit checklist replayed as a single-host simulation over real PG + Docker | MET-by-simulation with one PARTIAL (named-operators/rollback is a process artifact, not a test); distributed-worker launch UNVERIFIED |
| Closed-beta gate dry-run (M21) | [closed-beta-report.md](closed-beta-report.md) | the beta entry/exit checklist replayed as a simulation; reuses the S1–S9 + DR + capacity-smoke artifacts | PARTIAL — security/isolation/determinism/uniqueness backed by executed tests; TLS deploy, production scale, real external beta, continuous RPO UNVERIFIED |
| Consolidated gate-status matrix (M21) | [gate-status.md](gate-status.md) | roll-up of `test_security_validation_meta` + the S1–S9 modules + the alpha/beta reports | executed on this host: S4/S5/S6/S9(static) PASS, S1/S2/S3/S7/S8/S9(runtime) GATED-PASS; v1.0 blockers listed honestly — evidence for M22, ticks no box |

**Release-gate sign-off is M22's job, not M20's.** This program supplies the
evidence; `../RELEASE_CRITERIA.md` gates stay unchecked until the M22
qualification pass adjudicates them against this evidence.
