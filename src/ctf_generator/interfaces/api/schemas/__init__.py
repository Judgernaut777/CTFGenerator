"""Pydantic v2 request/response DTOs + domain<->DTO mappers.

These DTOs are the API's wire contract and are SEPARATE from the domain
dataclasses: surrogate uuids, ORM lifecycle columns, and any private/solver
content never appear here. Each resource module provides request models
(validated by FastAPI -> automatic ``422``) and response models plus explicit
``*_to_response`` / request-to-domain mappers. Response bodies are stamped into
the ``schema``/``schema_version`` envelope by the routers, not by these models.
"""

from __future__ import annotations
