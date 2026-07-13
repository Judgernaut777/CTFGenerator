# Security validation checklist (M20)

Maps each standing security release gate **S1–S9** (`docs/RELEASE_CRITERIA.md`,
"Security release gates") to the **executed** test(s) that validate it. This is
evidence, not a claim: each cited path is a real test module, and
`tests/test_security_validation_meta.py` is a host guard that fails if any cited
module disappears, stops importing, or if a gate falls out of this table.

**Honesty about where each gate actually runs** (charter §5 — no silent
limitations):

- **host** — runs and asserts in the default host suite (`pr.yml`,
  `python -m unittest`); no PostgreSQL, Docker, or network needed.
- **PG-gated** — real assertions, but they `skipUnless(CTFGEN_TEST_DATABASE_URL)`
  so they only execute against the integration PostgreSQL, **not** in the host
  `pr.yml` run. They pass in the integration env; on the host they SKIP.
- **Docker-gated** — real assertions that launch containers; `skipUnless` docker
  CLI/daemon (and, for isolation, the host-block firewall capability). Not run in
  `pr.yml`.
- **documented-unverified** — a requirement no executed test covers here, or a
  path this host cannot exercise; called out explicitly, never redefined to pass.

| # | What it guarantees | Executed test(s) — real file paths | Where it runs | Status |
|---|---|---|---|---|
| **S1** | No unresolved critical/high **authz** failures: role checks on every privileged action; one team cannot act in another's competition | `tests/test_api_authz_scoping_integration.py` (`test_organizer_of_a_is_denied_every_scoped_write_in_b` → every scoped write in B is 403; `test_organizer_of_a_still_authorized_in_a` is the positive control), `tests/test_api_instances_integration.py` (`test_contestant_is_forbidden_everywhere` → player is 403 on every instance endpoint) | PG-gated | PASS in integration env; SKIPS on host |
| **S2** | No **container escape** from a challenge workload to the worker host or beyond | `tests/test_team_isolation_integration.py` (`test_isolated_container_cannot_reach_host_bound_service`, `test_metadata_and_internet_egress_is_denied`; positive controls `test_reach_probe_returns_true_for_open_colocated_target` / `test_reach_exec_probe_returns_true_...` prove the probe is not vacuous), `tests/test_docker_backend_integration.py` (`test_strict_policy_hardening_takes_effect` all caps dropped, `test_writable_tmpfs_is_noexec`) | Docker-gated (isolation also needs host-block firewall capability) | PASS in Docker+firewall env; SKIPS on host |
| **S3** | No **cross-team access** — instance/submission/data of one team reachable by another | `tests/test_api_authz_scoping_integration.py` (`test_red_a_confined_to_red_in_a_and_absent_in_b` → Red cannot submit for Blue (403) nor list Blue), `tests/test_team_isolation_integration.py` (`test_cross_team_isolation_with_positive_control` → colocated other-team container is unreachable while the positive control is reachable) | PG-gated (API scoping) + Docker-gated (network) | PASS in integration env; SKIPS on host |
| **S4** | No **flag leakage** — flags never in public artifacts, never served to contestants; only reachable by exploiting the service | `tests/test_public_flag_leak.py` (`test_no_family_mode_leaks_its_flag_into_public` → every family/mode built, flag string absent from `public/`), `tests/test_score.py` (`test_flag_leaked_into_public_is_demoted`, `test_stub_solver_that_embeds_flag_is_demoted` → integrity gate forces `band == "weak"`) | host | PASS |
| **S5** | No **secret leakage** — flags, session tokens, provider/API keys never logged or emitted in reports/artifacts | `tests/test_logging_redaction.py` (`test_no_secret_class_reaches_the_emitted_output`, `test_exception_traceback_is_redacted`, `test_shapeless_secrets_in_message_text_are_redacted`, `test_secret_redacted_on_the_real_worker_logger`) | host | PASS |
| **S6** | **Destructive path handling** safe — generated paths cannot escape the build dir; `force`/recursive delete constrained to the sandbox root | `tests/test_build_hardening.py` (`PathValidationTests` parent-traversal/absolute/symlink rejects, `DeletionGuardTests` refuses non-empty unmarked dir / symlink output / dangerous roots, `SymlinkEscapeTests.test_assert_within_blocks_symlinked_component`), `tests/test_mcp_server.py` (`test_create_challenge_rejects_parent_traversal`, `test_create_challenge_rejects_absolute_outside_root`) | host | PASS |
| **S7** | No **unauthenticated admin endpoints** — every admin/control-plane mutation requires authn + authz | `tests/test_api_auth_integration.py` (`test_missing_bearer_on_me_is_401`, `test_wrong_password_and_unknown_email_are_indistinguishable` → 401), `tests/test_api_instances_integration.py` (`test_contestant_is_forbidden_everywhere` → privileged instance mutations 403 without the role), `tests/test_web_security.py` (`WebLoginCsrfTests`, `WebCsrfTests` → state-changing POST rejected without a valid CSRF token) | PG-gated | PASS in integration env; SKIPS on host |
| **S8** | No **unrecoverable DB corruption** — migrations reversible/tested; scoreboards reconstructable from persisted score events; backup/restore verified; ledgers append-only | `tests/test_ledger_repository_integration.py` (`test_append_only_trigger_blocks_update_delete_truncate`, `test_append_only_trigger_blocks_mutation`), `tests/test_restore_verify_integration.py` (`test_backup_restore_verify_round_trip_passes` incl. scoreboard parity, `test_restore_preserves_append_only_immutability`, negative controls `test_negative_wrong_migration_head_fails` / `test_negative_ledger_seq_gap_fails`), `tests/test_migration_drift_integration.py` (`test_head_has_no_autogenerate_drift`, `test_full_downgrade_leaves_clean_database`) | PG-gated (restore round-trip also needs `pg_dump`/`pg_restore`, host or via `docker exec`) | PASS in integration env; SKIPS on host |
| **S9** | Control plane **never executes generated challenge code and never mounts the Docker socket** (highest-priority boundary) | `tests/test_mcp_server.py` (`test_source_imports_no_effectful_or_platform_module`, `test_source_calls_no_shell_exec_primitive`, `test_fresh_import_pulls_no_forbidden_module` → no `subprocess`/`docker`/`runtime_validator`/`scenario_runtime`/`agent_eval`; `test_no_docker_tool_exposed`), `tests/test_architecture_boundaries.py` (`test_domain_has_no_forbidden_imports`) | host | PASS |

## The meta-guard

`tests/test_security_validation_meta.py` is a **host** test (needs no PostgreSQL,
Docker, or network). For every gate S1–S9 it asserts each cited test **module
exists on disk** and is **importable/collectable** (via `importlib` +
`unittest.TestLoader.loadTestsFromModule`), and it asserts this document lists all
of S1–S9 and names every cited module. It does **not** run the PG/Docker-gated
tests — it only proves they exist and can be collected, so the mapping above
cannot silently rot.

Run:

```
PYTHONPATH=src:tests .venv/bin/python3 -m unittest test_security_validation_meta
```

## Explicitly UNVERIFIED here (charter §5)

- **S1/S3/S7/S8** carry `PASS in integration env`, not host. The default
  `pr.yml` host run **skips** them (no `CTFGEN_TEST_DATABASE_URL`). Their
  release-gate evidence must be produced by running the suite against the
  integration PostgreSQL; this doc does not assert they ran in CI.
- **S2 / S3 (network)** require Docker **and** the host-block firewall
  capability. On a host without that capability the isolated launch refuses (by
  design) and these tests SKIP — the escape guarantee is unverified there.
  Rootless/userns hardening remains capability-gated on this rootful arm64 host
  (`docs/security/runtime-isolation.md`); the rootless variant is
  documented-unverified.
- **S8 backup/restore** additionally needs `pg_dump`/`pg_restore` (host binary or
  `docker exec` into the PG container); absent both, `test_restore_verify_integration.py`
  SKIPS and the round-trip is unverified.
- No standing gate is left without an executed test. If a future gate is added to
  `RELEASE_CRITERIA.md` with no test, it MUST appear here flagged **MISSING**
  rather than omitted.
