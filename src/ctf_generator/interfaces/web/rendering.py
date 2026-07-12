"""Server-side template rendering with autoescape ON (M11 slice a).

A thin wrapper over a Jinja2 ``Environment`` whose ``autoescape`` is
unconditionally TRUE (the secure default): every ``{{ value }}`` is HTML-escaped,
so a competition name of ``<script>alert(1)</script>`` renders as inert text. No
template ever uses ``|safe`` on data-derived content, and NO secret (flag / token
/ hash / credential) is placed in a context (REQ-INV-011).

:func:`render` injects the per-response CSP nonce and the signed CSRF token into
every context so templates can stamp inline ``<style nonce>`` / ``<script nonce>``
tags and hidden CSRF fields without each handler re-deriving them.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import Request
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.responses import HTMLResponse

from ctf_generator.interfaces.api.deps import Principal

from .csrf import csrf_token_for_request
from .deps import get_web_settings

_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


def build_environment() -> Environment:
    """The shared Jinja2 environment. ``autoescape=True`` is forced (not merely
    ``select_autoescape`` by extension) so there is no filename by which an
    unescaped template could slip in."""
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(default=True, default_for_string=True),
        auto_reload=False,
    )
    # Belt-and-suspenders: assert the secure default actually took effect.
    assert env.autoescape is not False  # noqa: S101
    return env


class TemplateRenderer:
    """Renders a named template to a hardened :class:`HTMLResponse`."""

    def __init__(self, environment: Environment | None = None) -> None:
        self._env = environment or build_environment()

    def render(
        self,
        request: Request,
        template_name: str,
        context: dict[str, Any] | None = None,
        *,
        status_code: int = 200,
        principal: Principal | None = None,
    ) -> HTMLResponse:
        settings = get_web_settings(request)
        ctx: dict[str, Any] = dict(context or {})
        ctx["request"] = request
        ctx["csp_nonce"] = getattr(request.state, "csp_nonce", "")
        ctx["csrf_token"] = csrf_token_for_request(request, settings)
        ctx["mount_path"] = settings.mount_path
        ctx["principal_subject"] = principal.subject if principal is not None else None
        ctx["is_system_admin"] = (
            "admin" in principal.system_roles if principal is not None else False
        )
        template = self._env.get_template(template_name)
        html = template.render(**ctx)
        return HTMLResponse(content=html, status_code=status_code)


def get_renderer(request: Request) -> TemplateRenderer:
    renderer = getattr(request.app.state, "web_renderer", None)
    if renderer is None:  # pragma: no cover - misconfiguration guard
        raise RuntimeError("no template renderer configured on the web app")
    return renderer
