"""Minimal ``application/x-www-form-urlencoded`` body parsing (M11 slice a).

HTML ``<form method="post">`` submissions are urlencoded. Starlette's
``request.form()`` requires the optional ``python-multipart`` library even for the
urlencoded case, so -- to keep the ``[web]`` extra to jinja2 alone -- the web app
parses the urlencoded body with the standard library. Starlette caches the raw
body on the request, so a CSRF dependency and its handler can both read it.

This parser handles ONLY urlencoded bodies; it never touches multipart uploads
(the organizer read/write slices submit simple text forms). A non-urlencoded
content type yields an empty mapping (the handler then treats required fields as
missing -- fail closed).
"""

from __future__ import annotations

from urllib.parse import parse_qsl

from fastapi import Request

_URLENCODED = "application/x-www-form-urlencoded"


async def read_form(request: Request) -> dict[str, str]:
    """Return the urlencoded form fields as a flat ``{name: value}`` mapping (the
    last value wins on a repeated key). Reads (and caches) the request body."""
    content_type = request.headers.get("content-type", "")
    if _URLENCODED not in content_type.lower():
        return {}
    raw = await request.body()
    pairs = parse_qsl(raw.decode("utf-8"), keep_blank_values=True)
    return {key: value for key, value in pairs}
