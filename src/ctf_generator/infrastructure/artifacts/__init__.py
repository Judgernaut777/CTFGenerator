"""Concrete artifact-store backends (M14 slice 14c-1).

Implements the domain
:class:`ctf_generator.domain.repositories.ArtifactStore` forward contract with a
content-addressed, immutable, path-safe local-filesystem store plus an in-memory
double for unit tests. Object-store (S3/GCS) backends are the SAME Protocol and
are credential-blocked here (see :mod:`.local_store`).
"""

from __future__ import annotations

from .config import (
    ArtifactStoreConfig,
    ArtifactStoreConfigError,
    artifact_store_from_env,
)
from .local_store import (
    ArtifactStoreError,
    InMemoryArtifactStore,
    LocalFilesystemArtifactStore,
)

__all__ = [
    "ArtifactStoreConfig",
    "ArtifactStoreConfigError",
    "ArtifactStoreError",
    "InMemoryArtifactStore",
    "LocalFilesystemArtifactStore",
    "artifact_store_from_env",
]
