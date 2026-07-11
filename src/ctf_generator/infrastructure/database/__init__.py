"""Database infrastructure (M6): SQLAlchemy engine/session management, the
declarative Base, and repository base classes. Concrete implementations of the
domain repository protocols (ctf_generator.domain.repositories) live here.

Importing this package pulls in SQLAlchemy, so it is only imported by DB-backed
code paths (integration tests, the future API) -- never by the stdlib-only
generator core or the unit suite. Install the ``db`` extra to use it.
"""
