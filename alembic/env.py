"""Alembic migration environment for the CTFGenerator control plane (M6).

Reads the database URL from the environment (CTFGEN_DATABASE_URL) via the app's
DatabaseConfig, and targets ctf_generator's declarative metadata so autogenerate
sees every ORM model as aggregates are added.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from ctf_generator.infrastructure.database.base import Base
from ctf_generator.infrastructure.database.config import DatabaseConfig

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Resolve the DSN from the environment (never from alembic.ini) unless a caller
# has explicitly injected one (e.g. an isolated test database).
if not config.get_main_option("sqlalchemy.url"):
    config.set_main_option("sqlalchemy.url", DatabaseConfig.from_env().url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
