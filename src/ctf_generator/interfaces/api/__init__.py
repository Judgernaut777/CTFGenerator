"""HTTP interface (M9): a thin FastAPI adapter over the application services.

This is the ONLY package permitted to import a web framework (FastAPI / Starlette
/ Pydantic / uvicorn) -- the architecture-boundary test forbids the domain layer
from importing frameworks but explicitly allows ``interfaces/api``. Handlers hold
NO business logic and NO session/commit logic: every request maps a typed request
DTO, calls an application service (which owns the unit of work), and maps the
domain result to a response DTO. ORM/domain internals and secrets never appear in
a response.

The package is import-safe without the ``[api]`` extra installed only insofar as
callers guard the import (the app factory needs FastAPI); the test suites gate on
the extra and skip cleanly, exactly like the ``[db]`` integration suites.
"""

from __future__ import annotations
