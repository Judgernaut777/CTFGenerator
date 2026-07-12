"""Versioned resource routers (mounted under ``/api/v1``). Each is a thin adapter:
typed request DTO -> application service -> response DTO envelope, permission-gated
and error-enveloped. No business logic or session/commit logic lives here."""

from __future__ import annotations
