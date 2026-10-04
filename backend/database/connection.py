"""
Async PostgreSQL connection pool and session factory.
Uses SQLAlchemy 2.x async engine with asyncpg driver.
DATABASE_URL must be set as an environment variable.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.sql.ddl import CreateColumn

from backend.database.models import Base

logger = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _get_database_url() -> str:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        raise RuntimeError("DATABASE_URL environment variable is not set")
    # SQLAlchemy async requires postgresql+asyncpg:// scheme
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


async def init_db() -> None:
    """Initialise engine, create all tables, and verify connectivity (Req 16.6)."""
    global _engine, _session_factory

    url = _get_database_url()
    _engine = create_async_engine(
        url,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        echo=False,
    )
    _session_factory = async_sessionmaker(
        _engine, expire_on_commit=False, class_=AsyncSession
    )

    # Create tables if they don't exist and repair any missing columns.
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with _engine.begin() as conn:
        await conn.run_sync(_ensure_missing_columns)

    # Health check
    async with _engine.connect() as conn:
        await conn.execute(__import__("sqlalchemy").text("SELECT 1"))

    logger.info("Database connection pool initialised")


def _ensure_missing_columns(sync_conn) -> None:
    """Add missing nullable or defaultable columns to existing tables."""
    inspector = inspect(sync_conn)
    for table_name, table in Base.metadata.tables.items():
        if not inspector.has_table(table_name):
            continue

        existing_columns = {col["name"] for col in inspector.get_columns(table_name)}

        # Legacy migration: if a legacy supervised score column exists, copy it into lightgbm_score.
        if table_name in ("attack_events", "risk_score_log") and "supervised_score" in existing_columns:
            logger.warning(
                "Migrating legacy %s.supervised_score -> %s.lightgbm_score", table_name, table_name
            )
            if "lightgbm_score" not in existing_columns:
                missing_col = table.columns.get("lightgbm_score")
                if missing_col is not None:
                    try:
                        rendered = str(CreateColumn(missing_col).compile(dialect=sync_conn.dialect))
                    except Exception:
                        rendered = f"{missing_col.name} {missing_col.type.compile(dialect=sync_conn.dialect)}"
                        if missing_col.server_default is not None:
                            rendered += f" DEFAULT {missing_col.server_default.arg}"
                        elif missing_col.default is not None and missing_col.default.arg is not None:
                            rendered += f" DEFAULT {missing_col.default.arg}"
                    sync_conn.execute(
                        text(
                            f"ALTER TABLE {table_name} ADD COLUMN {rendered}"
                        )
                    )
                    existing_columns.add("lightgbm_score")

            sync_conn.execute(
                text(
                    f"UPDATE {table_name} SET lightgbm_score = COALESCE(lightgbm_score, supervised_score)"
                )
            )
            sync_conn.execute(
                text(
                    f"ALTER TABLE {table_name} DROP COLUMN IF EXISTS supervised_score"
                )
            )
            existing_columns.discard("supervised_score")

        for column in table.columns:
            if column.name in existing_columns:
                continue

            if column.primary_key:
                logger.warning(
                    "Skipping missing primary key column %s.%s during schema repair",
                    table_name,
                    column.name,
                )
                continue

            if column.nullable or column.server_default is not None or column.default is not None:
                logger.warning(
                    "Adding missing column %s.%s to existing table %s",
                    table_name,
                    column.name,
                    table_name,
                )
                try:
                    rendered = str(CreateColumn(column).compile(dialect=sync_conn.dialect))
                except Exception:
                    rendered = f"{column.name} {column.type.compile(dialect=sync_conn.dialect)}"
                    if column.server_default is not None:
                        rendered += f" DEFAULT {column.server_default.arg}"
                    elif column.default is not None and column.default.arg is not None:
                        rendered += f" DEFAULT {column.default.arg}"
                sync_conn.execute(
                    text(f"ALTER TABLE {table_name} ADD COLUMN {rendered}")
                )
            else:
                logger.error(
                    "Cannot auto-add non-nullable column %s.%s without a default;"
                    " please migrate the database schema manually.",
                    table_name,
                    column.name,
                )


async def close_db() -> None:
    """Dispose the engine on shutdown."""
    global _engine
    if _engine:
        await _engine.dispose()
        logger.info("Database connection pool closed")



async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager yielding a database session."""
    if _session_factory is None:
        raise RuntimeError("Database not initialised — call init_db() first")
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def session_context():
    """
    Context manager for agents, loggers and startup code.
    """

    if _session_factory is None:
        raise RuntimeError("Database not initialised")

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def health_check() -> bool:
    """Return True if the database is reachable."""
    try:
        if _engine is None:
            return False
        async with _engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning("Database health check failed: %s", exc)
        return False
