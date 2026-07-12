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

## Scaffold and test a family

`ctfgen new-family` writes a **minimal, lint-clean, immediately generatable**
starting point so you begin from a working family, not a blank file:

```console
$ ctfgen new-family my_family --category web --dest ./my_family
Scaffolded family 'my_family' into my_family:
  my_family/my_family.py
  my_family/test_my_family.py
  my_family/ENTRY_POINT.md
```

Flags: `--category <c>` (required), `--dest DIR` (default `./<name>/`),
`--modes red,blue,purple` (default `red`), `--force` (overwrite existing files).
The `name` must be a Python identifier — a bad name (path separator, `..`,
non-identifier, keyword), a bad category, or an unknown mode is a clean nonzero
exit that writes nothing; existing files are never overwritten without `--force`.

Three files are written:

| File | What it is |
| --- | --- |
| `my_family.py` | The renderer module: the interface constants (`FAMILY_NAME`/`CATEGORY`/`MODES`/`DIFFICULTIES`/`CVE_DRIVEN`/`LLM_BRIEF`/`COMPOSE_MARKERS`/`SCORING_HINTS`/`REQUIRED_FILES`) + a minimal deterministic `render`. It does **not** import `ctf_generator.families`. |
| `test_my_family.py` | A runnable author test using `ctf_generator.testing`. |
| `ENTRY_POINT.md` | The `[project.entry-points."ctf_generator.families"]` snippet. |

**1. Edit `render`.** Emit each file your `REQUIRED_FILES` declares. Derive every
per-instance value from `rng` (never the clock or global state) so the family
stays deterministic. `challenge.yaml` is injected by the generator.

**2. Test with the supported facade.** The scaffolded `test_my_family.py` uses
`ctf_generator.testing` — the **supported author-testing surface**, a thin facade
over `sdk.lint` + the generator + `build` (it never re-implements a check):

```python
from ctf_generator import sdk, testing
import my_family as family_module

fam = sdk.family_from_module(family_module)

testing.assert_family_ok(fam)                  # structural lint (== sdk.assert_family_ok)
testing.assert_deterministic(fam)              # renders twice, asserts byte-identical
testing.assert_no_private_leak(fam)            # sdk.lint PRIVATE_CONTENT_IN_PUBLIC invariant
path = testing.build_family_in(fam, "/tmp/out")  # real generator.create_challenge -> validate it
testing.assert_rebuild_is_byte_identical(fam)  # golden-manifest determinism, on disk
```

```console
$ cd my_family && python -m pytest test_my_family.py     # or: python -m unittest
```

`assert_deterministic` renders through the *same* RNG derivation the generator
uses (`random.Random(generator.seed_to_int(spec.seed))`), so a pass means a
byte-identical real build. `build_family_in` publishes through the hardened,
path-safe `build.write_build`, so you can `ctfgen validate <path>` the result.

**3. Register it.** Declare the entry point from `ENTRY_POINT.md` (next section).
Once your package is installed, `ctfgen` discovers, **lints**, and registers the
family automatically at CLI startup via `bootstrap_family_plugins`.

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
