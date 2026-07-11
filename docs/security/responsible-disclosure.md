# Responsible Disclosure Policy

CTFGenerator is a proprietary, for-profit product (owner: Matthew Judge / Judgernaut777).
We welcome good-faith security research and will work with researchers who report
vulnerabilities responsibly. This document is the coordinated-disclosure policy referenced
by [`SECURITY.md`](../../SECURITY.md); `SECURITY.md` is the entry point, this page is the
detailed policy.

> **Status note.** CTFGenerator today (v0.1.0) is a self-hosted, pure-Python generator/validator
> plus a stdlib `http.server` dashboard (`ctfgen serve`) and an MCP server (`mcp_server.py`).
> The multi-plane control/execution platform described in the productization plan is **planned**,
> not shipped. Sections below label planned surfaces explicitly. There is **no hosted service**
> to test against; all testing happens on your own deployment.

---

## 1. Scope

### 1.1 In scope (current codebase)

| Area | Component(s) | Notes |
|---|---|---|
| Generator / spec pipeline | `generator.py`, `spec_generator.py`, `families.py`, `templates/*` | Determinism/isolation defects: generated paths escaping the build dir, private files leaking into public artifacts, embedded/leaked flags. |
| Static + runtime validation | `validator.py`, `runtime_validator.py`, `replay_validator.py`, `sibling_validator.py` | Untrusted-bundle code execution boundary (see §5). |
| MCP server | `mcp_server.py` | Workspace-sandbox escape via `output_dir` (`_resolve_in_workspace` / `CTFGEN_MCP_WORKSPACE`); any path that reaches Docker/`subprocess` through MCP (should be impossible by design). |
| Dashboard / scoreboard server | `dashboard_server.py`, `dashboard_ui.py` | Auth/session/token handling (`serve --admin-user/--admin-password/--public-token`), public-vs-admin data separation, injection in served HTML. |
| Scoring / events | `score.py`, `scoring_engine.py`, `scoreboard.py`, `events.py`, `postgres_events.py`, `competition_service.py` | Score/event integrity, one-solve-per-`(team,challenge)` invariant, scoreboard reconstructability. |
| CVE sourcing | `cve_source.py` | Cache-poisoning of `CachingCveSource`, unsafe parsing of remote NVD JSON. |
| Reporting | `report_writer.py`, `report_index.py` | Injection into generated HTML report index. |
| Supply chain | Packaging (`ctf-generator` / `ctfgen`), optional extras (`[mcp]`, LLM, `psycopg`) | Dependency/build integrity. |

### 1.2 In scope (planned platform — report if you find it early)

The four-plane target (Author Studio, Competition Control Plane, Execution Plane, Evaluation Lab)
introduces higher-severity classes we care about most:

- Generated vulnerable workloads executing on the **control plane** (must never happen).
- Control plane obtaining **Docker socket** access (must never happen).
- One team accessing **another team's instance** or data.
- **Flag / session-token / provider-key leakage** into logs, public artifacts, or the contestant portal.
- **Private solvers** served to contestants.
- Auth/authz bypass across the eight roles (Platform owner, Operator, Event administrator,
  Challenge author, Reviewer, Team captain, Contestant, Observer).
- Deterministic-rebuild failures or published-artifact mutability.

### 1.3 Out of scope

- **The intentional vulnerabilities inside generated challenges.** Challenge bundles are
  *vulnerable by construction* (that is the product). A bug in generated `services/*/app.py`
  is a feature, not a finding — unless it lets challenge code escape its intended sandbox or
  reach the control/host beyond the documented trust boundary.
- Findings that require running bundle code you generated yourself on your own host without
  `--sandbox` — this is documented behavior (see §5), not a vulnerability.
- Self-DoS of a deployment you fully control (e.g. resource exhaustion by an admin against
  their own server) absent a cross-tenant or unauthenticated vector.
- Missing hardening headers, TLS config, or rate limits on a **deployer-operated** reverse
  proxy (that is the operator's responsibility per the V1 deployment model), unless the core
  app ships an exploitable default.
- Vulnerabilities in third-party dependencies with no demonstrated impact on CTFGenerator —
  report those upstream (feel free to CC us).
- Reports generated solely by automated scanners with no verified, reproducible impact.
- Social engineering, physical attacks, or attacks against the owner's personal accounts/infra.
- Anything requiring compromised credentials the operator themselves configured
  (`--admin-password`, `--public-token`) unless you can obtain them without authorization.

---

## 2. How to report

Send reports to the security contact listed in `SECURITY.md`. If encryption is offered there,
use it — always for reports containing exploit code, credentials, or captured data.

A good report includes:

- Affected component/module and version (`ctfgen --version`, or git commit).
- Deployment context (CLI-only, `ctfgen serve`, MCP host, or a planned-plane prototype).
- Reproduction steps, a minimal PoC, and the observed vs. expected behavior.
- Impact assessment and, if known, a suggested severity.
- Your name/handle for attribution (optional).

Do **not** open a public GitHub issue for a suspected vulnerability. Use the private channel
in `SECURITY.md` and give us a chance to fix it first.

---

## 3. Our commitments and timelines

These are **target** service levels for a solo-maintained proprietary project; they are goals,
not contractual guarantees, and may flex for complex issues. We will keep you informed either way.

| Stage | Target |
|---|---|
| Acknowledge receipt | Within **3 business days** |
| Initial triage + severity assessment | Within **10 business days** |
| Status updates | At least every **2 weeks** while the report is open |
| Fix / mitigation for Critical–High | Target **30 days** from triage |
| Fix / mitigation for Medium–Low | Target **90 days** from triage |
| Coordinated public disclosure | By mutual agreement, typically after a fix ships |

We will tell you when a fix is released and, with your permission, credit you in the release
notes or a security advisory. We do not currently run a paid bug-bounty program; recognition
is at our discretion.

---

## 4. Safe harbor

If you make a **good-faith** effort to comply with this policy, we will consider your research
authorized, will not pursue or support legal action against you for it, and will not report you
to law enforcement. Specifically, for activity that:

- stays within the scope in §1 and respects the prohibitions in §5;
- targets **only** infrastructure you own or are explicitly authorized to test;
- avoids privacy violations, data destruction, and service degradation for others;
- stops as soon as you confirm a vulnerability, and reports it promptly and confidentially;
- gives us reasonable time to remediate before any public disclosure.

Safe harbor does not waive third parties' rights: if your testing touches infrastructure,
data, or events belonging to someone else, this authorization does not cover it, and you are
responsible for obtaining their permission. If in doubt about whether an action is authorized,
ask us first at the contact in `SECURITY.md`.

This is not a license to access data or systems you are not entitled to, and it does not
override the product's proprietary license terms for use of the software itself.

---

## 5. What researchers must NOT do

- **Do not test against live events, competitions, or deployments you do not own or operate.**
  A running CTF may have contestants, scores, and flags belonging to third parties. Test only
  on an isolated deployment you control.
- **Do not access, modify, or exfiltrate data that is not yours** — no dumping other operators'
  event logs (`events.py` JSONL / `postgres_events.py`), scoreboards, admin credentials, public
  tokens, provider API keys, or contestant data.
- **Do not exfiltrate or publish flags, session tokens, or provider keys.** Report their exposure;
  do not collect or retain them.
- **Do not run generated challenge bundles' `tests/healthcheck.py` / `private/solver.py` on a host
  you do not own.** `validate-runtime` and `replay` execute bundle-shipped code **on the host with
  your privileges by default** — the CLI warns about this. Use `--sandbox` and disposable hosts.
- **Do not perform destructive testing**: no data deletion (note `force=True` triggers
  `shutil.rmtree`), no ransomware, no persistent backdoors, no `serve_forever` resource-exhaustion
  against shared instances.
- **Do not pivot** from a generated challenge or a compromised component into unrelated systems,
  networks, or accounts.
- **Do not use vulnerabilities beyond what is minimally necessary** to confirm the issue, and do
  not maintain access after confirming it.
- **Do not publicly disclose** before coordinated release, and do not share details or PoCs with
  third parties in the interim.
- **Do not violate any law** or the product's proprietary license in the course of research.

Violating these prohibitions removes safe-harbor protection (§4) and may be treated as
unauthorized access.

---

*This policy may be updated as the platform evolves toward the multi-plane target architecture.
The version in the repository's default branch is authoritative.*
