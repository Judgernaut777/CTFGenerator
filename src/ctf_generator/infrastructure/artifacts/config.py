"""Artifact-store configuration, sourced from the environment.

Mirrors :class:`ctf_generator.infrastructure.database.config.DatabaseConfig`:
the storage root comes from an env var so a later API slice (the contestant
download endpoint, 14c-2) can construct the store without hard-coding a path.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .local_store import LocalFilesystemArtifactStore

DEFAULT_ROOT_ENV = "CTFGEN_ARTIFACT_ROOT"


class ArtifactStoreConfigError(RuntimeError):
    """Raised when required artifact-store configuration is missing."""


@dataclass(frozen=True)
class ArtifactStoreConfig:
    """Location settings for the local-filesystem artifact store."""

    root: str

    @classmethod
    def from_env(cls, env_var: str = DEFAULT_ROOT_ENV) -> ArtifactStoreConfig:
        root = os.environ.get(env_var)
        if not root:
            raise ArtifactStoreConfigError(
                f"{env_var} is not set; artifact materialization requires a storage root"
            )
        return cls(root=root)


def artifact_store_from_env(
    env_var: str = DEFAULT_ROOT_ENV,
) -> LocalFilesystemArtifactStore:
    """Construct a :class:`LocalFilesystemArtifactStore` from the environment.

    The single wiring point a later slice calls to obtain a configured store; an
    object-store backend would slot in behind the same
    :class:`~ctf_generator.domain.repositories.ArtifactStore` Protocol here.
    """
    return LocalFilesystemArtifactStore(ArtifactStoreConfig.from_env(env_var).root)
