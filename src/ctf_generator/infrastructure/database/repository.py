"""Generic SQLAlchemy repository base.

Concrete repositories (implementing the domain repository protocols in
ctf_generator.domain.repositories) subclass this per aggregate, starting with
Competition in the next step. Repositories operate on a caller-provided
``Session`` so they participate in the caller's unit of work / transaction --
they never open or commit their own.
"""

from __future__ import annotations

from typing import Generic, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from .base import Base

T = TypeVar("T", bound=Base)


class SqlAlchemyRepository(Generic[T]):
    """Minimal add/get/list over one mapped model within a session/transaction."""

    #: Subclasses set this to their mapped model class.
    model: type[T]

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, entity: T) -> T:
        self._session.add(entity)
        self._session.flush()  # assign PKs / surface constraint errors now
        return entity

    def get(self, entity_id: object) -> T | None:
        return self._session.get(self.model, entity_id)

    def list(self) -> list[T]:
        return list(self._session.scalars(select(self.model)))
