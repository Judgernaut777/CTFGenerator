# AI-resistance: honest validation report (M20)

This is the grounded validation record for the product's flagship "AI-resistance"
claim. Every statement below is tied to code/tests read at the cited line. The
report deliberately separates what is **MEASURED / PROVABLE HERE** from what is
**UNPROVEN / THEATER-RISK**. Where a path cannot be executed on this host it is
marked **UNVERIFIED** with the reason — the requirement is never weakened to make
it pass (charter §5).

## Scope of the claim

"AI-resistance" spans three distinct mechanisms, each with a different level of
evidence:

1. the static `score` heuristic (`src/ctf_generator/score.py`),
2. the live-adversarial **scenario engine** (`src/ctf_generator/families.py`,
   `scenario.py`), and
3. the **Evaluation Lab** empirical delta (`src/ctf_generator/agent_eval.py`,
   `domain/evaluation/models.py`).

They must be claimed separately. Collapsing them into one "resistance score" is
exactly the overclaim R-10 was opened against.

## WHAT IS NOW REAL (measured / provable here)

### 1. The static score is explicitly ADVISORY, and its own docstring says so
`score.score_challenge` (`score.py:46-55`) is documented as *"the ADVISORY
AI-resistance heuristic … a static quality signal derived from bundle heuristics
(string counts and self-reported flags), NOT a measured or guaranteed
resistance."* The docstring itself directs callers to the Evaluation Lab for the
empirical signal. This is the R-10 reframe landed in code, not just docs.

### 2. An INTEGRITY GATE catches the two unambiguous "not a real challenge" cases
`score.py:96-104` runs `_integrity_gate` (`score.py:136-172`) *after* computing
the declared total and **forces `band = "weak"`** when either:
- the solver embeds the literal concrete flag (`score.py:149-153`) — a stub
  "solver" that prints the answer rather than deriving it; or
- the concrete flag leaks into a player-facing `public/` file (`score.py:159-171`),
  outside a `blue` defensive mode whose task is analysing a provided artifact
  (`score.py:157`).

The concrete flag is resolved from `variant.json` or private/services source via
the seed-derived `_CONCRETE_FLAG` regex (`score.py:108-133`), which excludes
placeholders. So the old failure mode "a broken challenge scores 100/100" is
**caught for these two specific cases**: such a bundle can no longer read as
`strong`/`good`. (Note the narrowness — see UNPROVEN §1.)

### 3. The scenario engine is LIVE for 4 families and genuinely blocks the real attack surface
`_FAMILY_SCENARIOS` (`families.py:236-269`) ships an enabled two-stage blue-team
scenario for four families: `crypto_token_forgery` (`target=/api/admin/`),
`cloud_metadata_ssrf` (`/internal/objects`), `network_lateral_pivot`
(`/internal/flag`), and `web_business_logic_tenant_export` (`/download/`). Each is
built by `_http_defense_scenario` (`families.py:193-211`) with `enabled=True`
(`families.py:211`) — the previously-inert (`enabled=False`) engine is now wired.
The `target` is a **stable substring of the challenge's own attack surface** that
every solver of that family must touch, not a hand-matched test literal
(`families.py:203-205`, and the `/download/` rationale at `families.py:263-267`).

This is **proven by `tests/test_family_scenarios.py`** (passes: `Ran 2 tests …
OK`). The test, for every family that ships a scenario, (1) generates a real
bundle and asserts `scenario_timeline.json` was written and `spec.enabled`
(lines 59-66); (2) runs `scenario.run_scenario` offline and asserts **all**
triggers fire and a `patch_route` response is applied (lines 68-80); (3) drives
`_ScenarioDefendedHTTPClient` and asserts a request to the family's real target
substring flips to **403 mid-solve** while an earlier benign call is 200
(lines 82-97). The target is read back from the family's own scenario, not
hard-coded in the test (`_scenario_target`, lines 24-30).

**Honesty bound:** this proof is **offline and unit-level**. `run_scenario` is
deterministic with no Docker/HTTP/wall-clock of its own, and the "block" is
demonstrated against `_ScenarioDefendedHTTPClient` wrapping a `_FakeInner`
(`test_family_scenarios.py:33-35, 89`). It proves the timeline fires and the
defense *would* refuse the target request; it is **not** a live autonomous agent
being defeated by a running instance.

### 4. The Evaluation Lab can compute an empirical single-host delta
`agent_eval.run_adversarial_delta` (`agent_eval.py:805-891`) runs a profile twice
— scenario engine off (baseline) then on (adversarial, with `http` wrapped in
`_ScenarioDefendedHTTPClient`, `agent_eval.py:864`) — and diffs them.
`AdversarialDeltaReport` (`agent_eval.py:629-647`) exposes `success_dropped`
(baseline solved ∧ adversarial not, line 640-642) and `step_delta`
(line 644-647). The advisory subset `solved`/`steps`/`success_dropped`/
`step_delta` is the allowlisted, secret-free result carried through
`domain/evaluation/models.py:107-108,148-149,163-166`. The single-host runner
`workers.eval_runner.SingleHostEvalJobRunner` (`eval_runner.py:46-`) renders the
full bundle in-process and runs `agent_eval` against a real Docker image on this
host for the scripted (no-LLM) profiles.

So the machinery to produce a real solved-with-vs-without-defense number for the
four scenario families **exists and is exercisable** on this host.

## WHAT REMAINS UNPROVEN / THEATER-RISK

### 1. The static dimensions are still DECLARED, gameable proxies
The five scoring dimensions (`_variant_uniqueness`/`_statefulness`/`_solver_depth`/
`_live_interaction`/`_scanner_resistance`, `score.py:196-321`) are string counts
and self-reported spec flags — e.g. `scanner_resistance` is a direct lookup of the
spec's own `generic_scanner_usefulness` value (`score.py:305-312`). The integrity
comment says so explicitly: *"the five dimensions above are DECLARED signals …
so a broken or gamed challenge can score highly on them"* (`score.py:96-100`). The
gate only catches an embedded flag or a leaked flag; a **non-broken but
low-effort** challenge that sets favourable spec flags can still inflate its
number and pass the gate. **The heuristic band is NOT a resistance guarantee.**

### 2. Only 4 of the registered families have a live scenario; cross-family generalization is unproven
`_FAMILY_SCENARIOS` covers four families (`families.py:236-269`). Families without
a live HTTP attack surface ship no scenario, so `run_adversarial_delta` for them
has nothing to break. There is no evidence that the delta measured on the four
scenario families transfers to any other family.

### 3. The measured delta test itself uses injected doubles, not a live agent vs a running instance
The adversarial-delta unit tests (`tests/test_agent_eval.py:318-359`) call
`run_adversarial_delta` with an **injected agent and HTTP client**
(`already_running`-style doubles), and `test_eval_runner_integration.py`
**patches the Docker leg out entirely** (its own header, lines 5-6: *"the Docker
leg … is patched out here"*). These prove wiring and the off/on diff logic; they
do **not** produce a resistance number from a real LLM agent against a real
running challenge. The real Docker scripted run is documented as **lead-run**
(`docs/evaluation/eval-worker-limitations.md:35-37`), not part of the automated
gate.

### 4. The DISTRIBUTED-worker eval path is NOT built
A networked worker with no control-plane DB credential cannot run an eval: it
would need the full bundle delivered and the image built via the
`build_challenge` worker pipeline, **which is not yet built**
(`docs/evaluation/eval-worker-limitations.md:38-53`; `eval_runner.py:16-23`).
Until then a networked worker leaves `eval_runner` unset and the dispatch reports
a sanitized advisory *"eval runner not configured on this worker: a distributed
…"* failure (`workers/worker.py:605`). **UNVERIFIED — distributed eval, blocked
on an unbuilt pipeline.**

### 5. The LLM adversarial profile is credential-blocked here
The `llm_agent` profile needs the `[anthropic]`/`[openai]` extra plus a provider
key; it is contract-tested with a fake client only and is not in the automated
gate (`docs/evaluation/eval-worker-limitations.md:55-60`). **UNVERIFIED — no
provider key on this host.** The strongest adversary (a real tool-using LLM) has
therefore not been run against any challenge here.

### 6. No CI evidence produces resistance numbers today
The eval integration tests are PG/Docker-gated (`skipUnless` on
`CTFGEN_TEST_DATABASE_URL`, `test_eval_runner_integration.py:57-63,137`) and the
real Docker leg is lead-run. **There is no continuous, automated artifact that
emits an empirical resistance delta.** The only always-on automated evidence is
`test_family_scenarios.py` (the offline scenario-fires-and-blocks proof, §3 above).

## VERDICT

### What M20 can honestly assert
- The `score` output is an **advisory bundle-quality heuristic**, and the code
  now says so and enforces two integrity gates that stop a stub-solver or
  flag-leak bundle from reading as strong.
- The live-adversarial **scenario engine is real and deterministic** for four
  families, and it **provably disrupts each family's own attack surface** in an
  offline unit proof (`test_family_scenarios.py`).
- The Evaluation Lab **can** compute a single-host empirical solved-with-vs-
  without-defense delta for those families (lead-run, scripted profiles).

### What the product must NOT claim
- Do **not** call the `score` band a "measured" or "guaranteed" AI-resistance
  level — it is a gameable proxy for all but the two gated failure cases.
- Do **not** claim a live autonomous LLM agent has been defeated by a running
  instance: not run here (§5), and the scenario proof is offline (§3).
- Do **not** imply distributed/at-scale adversarial evaluation exists — the
  distributed path is unbuilt (§4).

### Recommended wording for the docs
> "AI-resistance" combines an **advisory static heuristic** (`score`, a quality
> signal, not a guarantee), a **deterministic live-adversarial scenario engine**
> for four families (proven to fire and block the real attack surface offline),
> and an **Evaluation Lab** that measures a single-host solved-with-vs-without-
> defense delta for scripted (non-LLM) profiles on this host. Real-LLM and
> distributed at-scale adversarial evaluation are **not yet validated**.

### Risk-register reconciliation (`docs/risk-register.md`)
- **R-10** ("AI-resistance metric currently overclaims", Open) can move toward
  **mitigated, not closed**: the reframe-to-advisory + integrity gate land the
  documented mitigation for the *broken-bundle* overclaim, but the residual
  gameable-proxy risk (UNPROVEN §1) keeps it from full closure. Recommend status
  **Open→Mitigated (residual: static dimensions remain gameable; band is advisory
  only)**.
- **R-20** ("live_adversarial_engine advertised but unwired", Accepted) is
  **substantially addressed**: the engine is now wired and enabled for four
  families (`families.py:211,236-269`) and proven to fire (§3). It cannot be
  called fully closed because coverage is four families and the measured delta is
  lead-run/offline-proven, not continuously validated. Recommend status
  **Accepted→Mitigated (scoped: four families, single-host; distributed unbuilt)**.

## Verification note

Each cited file was opened and the referenced lines confirmed:
`src/ctf_generator/score.py` (whole file: 46-55, 96-104, 108-133, 136-172,
196-321), `src/ctf_generator/families.py` (193-211, 236-269),
`src/ctf_generator/agent_eval.py` (629-647, 805-891),
`src/ctf_generator/domain/evaluation/models.py` (16-17, 107-108, 148-149,
163-166), `src/ctf_generator/workers/eval_runner.py` (1-60),
`src/ctf_generator/workers/worker.py` (605),
`tests/test_family_scenarios.py` (whole file),
`tests/test_agent_eval.py` (23, 210-211, 318-359),
`tests/test_eval_runner_integration.py` (5-18, 57-63, 137),
`docs/evaluation/eval-worker-limitations.md` (whole file),
`docs/risk-register.md` (R-10 line 30, R-20 line 40, mapping line 57).
`tests/test_family_scenarios.py` was executed here:
`PYTHONPATH=src:tests .venv/bin/python3 -m unittest test_family_scenarios` →
`Ran 2 tests … OK`.
