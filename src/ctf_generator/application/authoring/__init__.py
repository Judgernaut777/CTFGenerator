"""Authoring application services: build inspection + build-job triggering.

The control plane NEVER builds a challenge in-process (ADR-001): triggering a
build enqueues a durable ``build_challenge`` job that a worker claims with scoped
credentials. This package hosts the thin, unit-of-work-owning facade the API
calls to read content-addressed build artifacts and to enqueue that job.
"""

from __future__ import annotations

from .build_service import BuildService

__all__ = ["BuildService"]
