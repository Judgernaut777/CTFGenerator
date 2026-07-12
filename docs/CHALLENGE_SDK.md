# Challenge Family SDK (`ctf_generator.sdk`)

The **supported, semver-stable authoring surface** for CTFGenerator challenge
families. This closes REQ-GEN-011: families register through an explicit
SDK/plugin boundary instead of editing a central hub.

## The authoring facade

Author against `ctf_generator.sdk` — never internal modules. The facade
**re-exports the real implementations** (`sdk.Family is
ctf_generator.families.Family`), so authoring against it is authoring against
the real types, with no shim drift. Internal modules may change between
releases; the `sdk` facade is the contract.

```python
from ctf_generator.sdk import Family, ScoringHints, register

def render(spec, rng, cve_record=None):
    # Return {relative_path: text}. Emit only under public/ private/ services/
    # tests/ detection/ or the top-level docker-compose.yml / .env.example.
    # challenge.yaml is injected by the generator -- do NOT emit it.
    return {
        "public/description.md": "...",
        "private/solution.md": "...",
        "docker-compose.yml": "...",
    }

register(Family(
    name="my_family", category="web", modes=("red",),
    render=render, required_files=("challenge.yaml", "public/description.md", ...),
))
```

Exported: the registry + family record (`Family`, `FamilyRenderer`,
`ScoringHints`, `DefaultSpecBuilder`, `register`/`get`/`is_registered`/
`family_names`/`families_for_mode`/`families_for_category`); the spec value types
authors compose (`ChallengeSpec`, `ScenarioSpec`, `TriggerSpec`, `ResponseSpec`,
`AIResistance`, `DynamicVariation`); spec construction/validation (`default_spec`,
`validate_spec`, `spec_to_dict`, `spec_from_dict`, `DIFFICULTIES`); helpers
(`validate_relative_path`, `parse_semver`, `SchemaError`); the module adapter
(`family_from_module`, `is_renderer_module`); the linter and the loader (below).

## Structural linter

`lint_family(family) -> list[LintIssue]` renders the family for a representative
default spec (offline, in-memory, no Docker) and checks:

| code | check |
|------|-------|
| `MISSING_REQUIRED_FILE` | render output (+ generator-injected `challenge.yaml`) is a superset of `required_files` |
| `UNSAFE_PATH` | every path passes `build.validate_relative_path` (no abs/traversal/control/bidi/reserved) |
| `PATH_OUTSIDE_ROOT` | every path lives under `public/ private/ services/ tests/ detection/` or a top-level `docker-compose.yml` / `.env.example` / `challenge.yaml` |
| `PRIVATE_CONTENT_IN_PUBLIC` | no `private/` bytes appear under `public/` (byte-identical file **or** a private flag token) |
| `BAD_VERSION` | `version` is valid semver |
| `BAD_MAINTENANCE_STATUS` | `maintenance_status` in `{stable, beta, experimental}` |
| `BAD_ISOLATION_LEVEL` | `isolation_level` in `{container, raw_tcp, artifact}` |
| `BAD_MODES` | `modes` non-empty subset of `{red, blue, purple}` |
| `EMPTY_CATEGORY` | `category` non-empty |
| `RENDER_FAILED` | `render()` raised (reported, never propagated) |
| `MODULE_IMPORTS_FAMILIES` | (module lint) a renderer module must not import `ctf_generator.families` |

`assert_family_ok(family)` raises `FamilyLintError` on any error-severity issue —
call it in your family's own test suite. `lint_renderer_module(module)` adds the
AST circular-import check for renderer-module plugins.

## Distributing an external family (entry points)

Ship your family in a package that declares a `ctf_generator.families` entry
point, resolving to a `Family`, a zero-arg callable returning one, or a renderer
module (adapted exactly like the built-in template modules):

```toml
[project.entry-points."ctf_generator.families"]
my_family = "my_pkg.my_family:FAMILY"   # or a factory, or a renderer module
```

`load_entry_point_families()` discovers, **lints**, and registers each valid
external family. It is **fail-safe**: a plugin that raises on load, resolves to a
non-`Family`, or fails the linter is skipped with a logged warning — it never
crashes discovery of the others or the app. Loading is idempotent.

### Trust boundary (read this)

Loading an entry point **executes third-party code** (`EntryPoint.load()` imports
the plugin). **A family plugin is operator-installed, trusted code — exactly like
any other dependency in the environment.** The loader validates *shape* (the
family lints clean); it is **not a sandbox** and cannot contain a malicious
plugin that runs code at import. Install only family plugins you trust.

### Where loading happens (and where it does not)

Entry-point loading is **explicit**: it runs only via
`sdk.plugins.bootstrap_family_plugins()`, wired into the legacy generator CLI
(`ctf_generator.cli.main`), guarded to run at most once per process. It is
**never** invoked at `families` import time and is **never reachable from
`mcp_server`** — a model driving the MCP server only ever sees the built-in
families, never arbitrary installed plugins (enforced by
`tests/test_mcp_server.py::MCPImportFirewallTests` and
`tests/test_sdk_plugins.py`).
