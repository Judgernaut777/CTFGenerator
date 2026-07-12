"""External family registration via Python entry points.

A third-party challenge family is distributed as an installable package that
declares an entry point in the ``ctf_generator.families`` group. Each entry
point resolves to one of:

* a :class:`~ctf_generator.families.Family` instance,
* a zero-argument callable returning a ``Family``, or
* a renderer *module* exposing the module-interface constants + ``render``
  (adapted exactly as ``families.py`` adapts its built-in template modules).

:func:`load_entry_point_families` discovers every such entry point, LINTS each
candidate with :func:`sdk.lint.assert_family_ok`, and ``register()``s the ones
that pass.

Trust boundary (READ THIS):
    Loading an entry point EXECUTES third-party code (``EntryPoint.load()`` imports
    the plugin package). A family plugin is therefore **operator-installed,
    trusted code -- exactly like any other dependency in the environment**. This
    loader is a convenience/robustness layer, NOT a sandbox: it validates SHAPE
    (the family lints clean) but cannot contain a malicious plugin that runs code
    at import. Only install family plugins you trust.

    What the loader DOES guarantee is fail-SAFE discovery: a plugin that raises on
    import/resolve, resolves to a non-``Family``, or fails the linter is SKIPPED
    with a logged warning -- it can never crash discovery of the other plugins or
    the application.

MCP purity:
    This module is NEVER imported by ``mcp_server`` and MUST NOT be invoked at
    ``families`` import time. Entry-point loading is EXPLICIT: it happens only via
    :func:`bootstrap_family_plugins`, wired into the legacy generator CLI's
    ``main`` (``ctf_generator.cli``). A model driving the MCP server therefore
    only ever sees the built-in families; it cannot trigger loading of arbitrary
    installed plugins.
"""

from __future__ import annotations

import logging
from importlib import metadata
from typing import Any

from ..families import Family, is_registered, register
from .adapter import is_renderer_module
from .lint import FamilyLintError, assert_family_ok, lint_renderer_module

logger = logging.getLogger("ctf_generator.sdk.plugins")

ENTRY_POINT_GROUP = "ctf_generator.families"

# Entry points already processed (keyed by a stable identity), so repeated
# calls are idempotent: a plugin is discovered/registered at most once per
# process even if load_entry_point_families is called again.
_LOADED_EP_KEYS: set[tuple[str, str, str]] = set()

# Guards bootstrap_family_plugins so the CLI can call it unconditionally.
_BOOTSTRAPPED = False


class PluginResolutionError(TypeError):
    """An entry point did not resolve to a Family, factory, or renderer module."""


def _ep_key(ep: Any) -> tuple[str, str, str]:
    return (getattr(ep, "group", ""), getattr(ep, "name", ""), getattr(ep, "value", ""))


def _coerce_to_family(obj: Any) -> Family:
    """Resolve a loaded entry-point object into a ``Family``.

    Accepts a ``Family`` directly, a renderer module (adapted), or a zero-arg
    callable returning one of those. Raises :class:`PluginResolutionError`
    otherwise.
    """
    if isinstance(obj, Family):
        return obj
    if is_renderer_module(obj):
        from .adapter import family_from_module

        return family_from_module(obj)
    if callable(obj):
        produced = obj()
        if isinstance(produced, Family):
            return produced
        if is_renderer_module(produced):
            from .adapter import family_from_module

            return family_from_module(produced)
        raise PluginResolutionError(
            f"entry-point callable returned {type(produced).__name__}, not a Family"
        )
    raise PluginResolutionError(
        f"entry point resolved to {type(obj).__name__}, not a Family/factory/module"
    )


def _discover_entry_points() -> list[Any]:
    """Return the entry points in :data:`ENTRY_POINT_GROUP` (empty on any error)."""
    try:
        eps = metadata.entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:
        # Extremely old importlib.metadata without the group= kwarg. requires-
        # python is >=3.11 so this is only defensive.
        eps = metadata.entry_points().get(ENTRY_POINT_GROUP, [])  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 - discovery must never crash the app
        logger.warning("family-plugin discovery failed: %s", exc)
        return []
    return list(eps)


def load_entry_point_families(*, on_error: str = "skip") -> list[str]:
    """Discover, lint, and register external families from entry points.

    Returns the list of family names newly registered by THIS call (empty if none
    or if every plugin was already loaded).

    ``on_error``:
      * ``"skip"`` (default): a plugin that raises on load/resolve, resolves to a
        non-``Family``, or fails the linter is skipped with a logged warning and
        does not affect the others.
      * ``"raise"``: re-raise the first such error (for strict author CI). The
        skip semantics are the production default -- the app must never crash on a
        third-party plugin.

    Idempotent: an entry point already processed in this process is not
    re-registered on a subsequent call.
    """
    registered: list[str] = []
    for ep in _discover_entry_points():
        key = _ep_key(ep)
        if key in _LOADED_EP_KEYS:
            continue
        name = getattr(ep, "name", "<unknown>")
        try:
            obj = ep.load()
            family = _coerce_to_family(obj)
            assert_family_ok(family)
            # Also enforce the circular-import contract when the plugin ships as a
            # renderer module (the family-level lint above cannot see the source).
            if is_renderer_module(obj):
                module_errors = [
                    i
                    for i in lint_renderer_module(obj)
                    if i.severity == "error" and i.code == "MODULE_IMPORTS_FAMILIES"
                ]
                if module_errors:
                    raise FamilyLintError(module_errors)
        except Exception as exc:  # noqa: BLE001 - fail-safe: never crash discovery
            _LOADED_EP_KEYS.add(key)  # do not retry a known-bad plugin every call
            logger.warning(
                "skipping family plugin %r (%s): %s",
                name,
                getattr(ep, "value", "?"),
                exc,
            )
            if on_error == "raise":
                raise
            continue
        # SECURITY: never let a plugin CLOBBER an already-registered family. A
        # plugin whose family.name collides with a built-in (or an earlier plugin)
        # would otherwise silently REPLACE trusted deterministic-core render code
        # with third-party code under a known name. Refuse + warn; the incumbent
        # wins. (`register()` overwrites by name, so the guard lives here.)
        if is_registered(family.name):
            _LOADED_EP_KEYS.add(key)
            logger.warning(
                "skipping family plugin %r: name %r is already registered "
                "(a built-in or another plugin) -- refusing to override it",
                name,
                family.name,
            )
            if on_error == "raise":
                raise PluginResolutionError(
                    f"family name {family.name!r} is already registered"
                )
            continue
        _LOADED_EP_KEYS.add(key)
        register(family)
        registered.append(family.name)
        logger.info("registered family plugin %r -> %s", name, family.name)
    return registered


def bootstrap_family_plugins() -> list[str]:
    """Load external family plugins exactly once per process (fail-safe).

    The single, EXPLICIT entry-point-loading hook. Called from the legacy
    generator CLI bootstrap (``ctf_generator.cli.main``). Guarded so repeated CLI
    dispatches in one process do not re-discover. Never raises: this is the
    application bootstrap path.
    """
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return []
    _BOOTSTRAPPED = True
    return load_entry_point_families(on_error="skip")


def _reset_for_tests() -> None:
    """Clear the idempotency/bootstrap guards (test-only helper)."""
    _LOADED_EP_KEYS.clear()
    global _BOOTSTRAPPED
    _BOOTSTRAPPED = False


def registered_plugin_family(name: str) -> bool:
    """True if a family ``name`` is registered (built-in or plugin)."""
    return is_registered(name)
