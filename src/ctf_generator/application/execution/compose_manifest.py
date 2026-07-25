"""Parse a generated ``docker-compose.yml`` as a MANIFEST (never an engine).

A multi-service challenge family renders several ``services/<name>/Dockerfile``
trees plus a ``docker-compose.yml`` that wires them together. The worker builds
each service's image and launches each as its own policy-constrained container on
the instance's per-instance network -- it does **NOT** run ``docker compose up``.
The generated compose is hostile input by construction (ADR-001) and its runtime
directives (``ports:`` host-publish, ``mem_limit``, ``cap_drop``, ``networks``,
``security_opt``) directly contradict the platform's secure floor; honoring them
would bypass ``ContainerPolicy``, the ``--internal`` per-instance network, and the
host-block firewall. So this reads the compose ONLY as a service graph.

Strict allowlist: for each service it reads ``build`` (the relative context dir),
``image`` (optional), ``expose`` (advertised ports), and ``depends_on`` (start
order). Every other directive is ignored -- our launch applies its own policy
regardless, so a service's ``privileged``/``cap_add``/``ports`` is inert here. The
build-context path is validated to stay strictly inside the bundle (no absolute
paths, no ``..``). A service count ceiling and depends_on cycle detection bound
the fan-out and refuse a malformed graph.

Pure + host-testable: parses text, touches no Docker, resolves paths lexically.
Returns ``None`` for a single-image bundle (no compose / a single serviceless
shape), so the existing single-image path is unaffected.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Bound the per-instance container fan-out. A stack larger than this is refused
# rather than silently launching an unbounded number of containers.
MAX_STACK_SERVICES = 8


class ComposeManifestError(ValueError):
    """The compose file is present but malformed/unsafe as a build manifest
    (bad build path, too many services, a depends_on cycle, an unknown service in
    depends_on). Fail loud -- a malformed multi-service graph must not build."""


@dataclass(frozen=True)
class ServiceSpec:
    """One service in the stack manifest (references only -- no secrets)."""

    name: str
    build_context: str  # bundle-relative dir, validated in-bundle
    expose: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    is_primary: bool = False


@dataclass(frozen=True)
class StackManifest:
    """An ordered, validated multi-service manifest. ``services`` is in a
    deterministic START order (topological over depends_on, ties broken by name)."""

    services: tuple[ServiceSpec, ...] = field(default_factory=tuple)

    @property
    def primary(self) -> ServiceSpec:
        for svc in self.services:
            if svc.is_primary:
                return svc
        return self.services[0]


def _as_str_tuple(value: object) -> tuple[str, ...]:
    """Coerce a compose scalar/list into a tuple of strings; ignore non-scalars."""
    if value is None:
        return ()
    if isinstance(value, (str, int)):
        return (str(value),)
    if isinstance(value, dict):  # depends_on: {svc: {condition: ...}} long form
        return tuple(str(k) for k in value)
    if isinstance(value, list):
        return tuple(str(v) for v in value if isinstance(v, (str, int)))
    return ()


def _safe_build_context(raw: object, service: str) -> str:
    """Validate a service ``build`` value into a safe bundle-relative dir. Accepts
    the short form (a string dir) or the long form (``{context: dir}``). Refuses
    absolute paths and any ``..`` escape."""
    context = raw.get("context") if isinstance(raw, dict) else raw
    if not isinstance(context, str) or not context.strip():
        raise ComposeManifestError(
            f"service {service!r} has no usable build context"
        )
    context = context.strip()
    # Strip a SINGLE leading "./" only (not every leading dot/slash -- that would
    # collapse "../../x" to "x" and defeat the escape check below).
    norm = context[2:] if context.startswith("./") else context
    if context.startswith("/") or ".." in norm.split("/"):
        raise ComposeManifestError(
            f"service {service!r} build context {context!r} escapes the bundle"
        )
    return norm


def _topological_order(
    specs: dict[str, ServiceSpec],
) -> tuple[ServiceSpec, ...]:
    """Kahn's algorithm over depends_on, name-sorted for determinism. Raises on an
    unknown dependency or a cycle."""
    for name, spec in specs.items():
        for dep in spec.depends_on:
            if dep not in specs:
                raise ComposeManifestError(
                    f"service {name!r} depends_on unknown service {dep!r}"
                )
    # in-degree = number of a node's own dependencies still unplaced
    remaining = {name: set(spec.depends_on) for name, spec in specs.items()}
    order: list[ServiceSpec] = []
    while remaining:
        ready = sorted(n for n, deps in remaining.items() if not deps)
        if not ready:
            raise ComposeManifestError(
                f"depends_on cycle among services {sorted(remaining)}"
            )
        for name in ready:
            order.append(specs[name])
            del remaining[name]
            for deps in remaining.values():
                deps.discard(name)
    return tuple(order)


def parse_compose_manifest(compose_text: str | None) -> StackManifest | None:
    """Parse a compose document into a validated :class:`StackManifest`, or
    ``None`` when there is no multi-service stack to build (absent/empty compose,
    or a compose whose ``services`` maps zero services). NEVER executes the
    compose. Raises :class:`ComposeManifestError` on a malformed/unsafe graph."""
    if not compose_text or not compose_text.strip():
        return None
    import yaml  # lazy: only the worker's build path needs it

    try:
        doc = yaml.safe_load(compose_text)
    except yaml.YAMLError as exc:
        raise ComposeManifestError(f"compose is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        return None
    services = doc.get("services")
    if not isinstance(services, dict) or not services:
        return None
    if len(services) > MAX_STACK_SERVICES:
        raise ComposeManifestError(
            f"stack has {len(services)} services, over the {MAX_STACK_SERVICES} "
            "ceiling"
        )

    specs: dict[str, ServiceSpec] = {}
    for name, body in services.items():
        if not isinstance(body, dict):
            raise ComposeManifestError(f"service {name!r} is not a mapping")
        service = str(name)
        # A service must build from the bundle (we do not pull arbitrary images):
        # an `image:`-only service with no `build:` is refused for this MVP.
        if "build" not in body:
            raise ComposeManifestError(
                f"service {service!r} has no build: (image-only services are not "
                "supported yet)"
            )
        specs[service] = ServiceSpec(
            name=service,
            build_context=_safe_build_context(body["build"], service),
            expose=_as_str_tuple(body.get("expose")),
            depends_on=_as_str_tuple(body.get("depends_on")),
            # Primary = the ingress service (declares host `ports:`), else the
            # lexicographically-first (resolved after ordering below).
            is_primary=bool(body.get("ports")),
        )

    ordered = _topological_order(specs)
    # If no service declared `ports`, mark the lexicographically-first as primary
    # so top-level image_ref/digest back-compat has a deterministic anchor.
    if not any(s.is_primary for s in ordered):
        first = min(specs, key=str)
        ordered = tuple(
            ServiceSpec(
                name=s.name, build_context=s.build_context, expose=s.expose,
                depends_on=s.depends_on, is_primary=(s.name == first),
            )
            for s in ordered
        )
    return StackManifest(services=ordered)
