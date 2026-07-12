# Contestant portal (M12) — scope, security model, and documented limitations

The contestant portal is the server-rendered, contestant-facing half of the web
sub-app (`src/ctf_generator/interfaces/web/`, mounted at `/app`). It mirrors the
existing JSON contestant loop (M9b) as HTML. It shares the M11 stack: cookie
session bridge over the M10 `AuthService`, per-response CSP nonce, session-bound
double-submit CSRF, `Cache-Control: no-store`, jinja2 autoescape, no CDN, no JS.

## Surface (routes under `/app`)

Reads (slice 12a):
- `GET /play` — the caller's competitions (`authorized_competitions`, `competition:read`).
- `GET /competitions/{id}/play` — per-competition landing: window, own-team context, published catalog, links.
- `GET /competitions/{id}/challenges` — the published-challenge catalog (public metadata only).
- `GET /competitions/{id}/roster` — the caller's OWN-team roster.

Writes (slice 12b):
- `GET /competitions/{id}/challenges/{slug}/{version_no}/submit` — the flag submit form.
- `POST /competitions/{id}/challenges/{slug}/{version_no}/submit` — record one attempt.
- `GET /competitions/{id}/submissions` — the caller's OWN-team submission history.

## Authorization & tenancy

Every route requires the cookie principal and is gated ONLY by permissions a
contestant role (`player`/`captain`) already holds: `competition:read`,
`team:read`, `challenge:read`, `scoreboard:read`, `submission:create`,
`submission:read`. Tenancy is confined by the SAME `submission_team_scope` the
JSON API uses:

- The submission/history/roster **team is derived server-side from membership**,
  NEVER from a request field or path. There is no team parameter to tamper.
- A team-scoped contestant sees and acts on ONLY their own team; a **teamless**
  contestant fails closed (a friendly "not on a team" page, empty history, no
  submit form) — never another team's data, never a 500.
- A tenancy-**unrestricted** caller (organizer/admin/staff) has no single team on
  this contestant surface, so they are treated identically to teamless here and
  use the organizer/JSON surfaces instead.
- Cross-competition access is an **existence-hiding 404** (via
  `assert_competition_permission_or_404`), never a 403 that confirms existence.
- The candidate answer is **inbound-only**: it is verified and discarded, never
  persisted (the `LedgerSubmission` stores only `correct: bool`), never echoed in
  a re-render, never logged.
- Double-submit is **idempotent**: a per-render nonce is folded into a
  deterministic `submission_id` (`uuid5(_SUBMISSION_NS,
  "{subject}:{competition}:{nonce}")`, single-sourced with the API's namespace),
  so re-POSTing the same rendered form replays onto the same submission.
- The catalog shows public metadata only (slug/title/version/mode/family); the
  version spec (flag/solution/private fields) is never read.

## Documented limitations (per charter §24 "no silent limitations")

These are deliberate scoping decisions grounded in the current architecture, not
oversights. Each has a clear future home.

1. **No challenge-artifact download.** No artifact/file-serving path exists in any
   layer today (builds persist references + content hashes only, never bytes).
   Delivering downloadable challenge artifacts to contestants requires an
   artifact-store delivery path — deferred to the artifact/SDK and deployment
   milestones (M14/M18). The catalog links to the submit form, not to files.

2. **No contestant self-service instance launch/stop.** Contestant roles do not
   hold any `instance:*` permission; the platform model is that instances are
   organizer-operated. Contestant per-team instance self-service would require a
   NEW scoped permission plus a per-team tenancy design (a team may operate only
   its own instance) and is out of M12. Consequently submissions verify against
   the published version's base flag (`instance_seed=None`); per-instance-seeded
   verification is a future slice tied to that permission.

3. **No team self-join.** Membership is seeded by an organizer / the admin CLI,
   by design. Contestants view their roster; they do not self-join a team.

4. **No app-level submit rate limit.** The submit POST is CSRF-protected and
   tenancy-confined, and flag values are high-entropy, so a flooded session cannot
   brute-force a flag. There is no per-principal/per-team submit throttle at the
   application layer — this is at PARITY with the JSON API, whose
   `RateLimitMiddleware` is IP-keyed (pre-auth) only. Abuse throttling belongs at
   the deployment edge (reverse proxy) and is an M18 concern; a per-team submit
   rate limit is a future enhancement. The residual risk is availability
   amplification (each attempt takes the per-competition submission advisory
   lock), not flag secrecy.
