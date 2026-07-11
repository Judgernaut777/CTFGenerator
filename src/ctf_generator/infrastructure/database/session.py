"""Engine + session lifecycle: the unit-of-work boundary for the control plane.

``Database.session_scope()`` is the transaction boundary application services
use -- commit on success, rollback on any exception, always close. Business
logic never manages sessions directly.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import DatabaseConfig


class Database:
    """Owns the SQLAlchemy engine and hands out transactional sessions."""

    def __init__(self, config: DatabaseConfig) -> None:
        self._engine: Engine = create_engine(
            config.url,
            echo=config.echo,
            pool_pre_ping=config.pool_pre_ping,
            future=True,
        )
        self._session_factory = sessionmaker(
            bind=self._engine, expire_on_commit=False, future=True
        )

    @property
    def engine(self) -> Engine:
        return self._engine

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        """Transactional unit of work: commit on success, rollback on error."""
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:
        self._engine.dispose()
