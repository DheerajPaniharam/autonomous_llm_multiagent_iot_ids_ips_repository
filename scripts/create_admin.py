"""
Create or update the initial admin user in the database.

Usage:
    python scripts/create_admin.py
    python scripts/create_admin.py --username admin --password secret --role admin

Environment:
    DATABASE_URL must be set (same as the main application).
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.database.models import Base, UserModel
from backend.api.auth import AuthService


def _get_database_url() -> str:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        print("ERROR: DATABASE_URL environment variable is not set.")
        sys.exit(1)
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


async def create_user(username: str, password: str, role: str) -> None:
    url = _get_database_url()
    engine = create_async_engine(url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    # Ensure tables exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        # Check if user already exists
        result = await session.execute(
            select(UserModel).where(UserModel.username == username)
        )
        existing = result.scalar_one_or_none()

        password_hash = AuthService.hash_password(password)

        if existing:
            existing.password_hash = password_hash
            existing.role = role
            await session.commit()
            print(f"✓ Updated user '{username}' (role={role})")
        else:
            user = UserModel(
                username=username,
                password_hash=password_hash,
                role=role,
            )
            session.add(user)
            await session.commit()
            print(f"✓ Created user '{username}' (role={role})")

    await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or update an IDS/IPS user")
    parser.add_argument("--username", default="admin", help="Username (default: admin)")
    parser.add_argument("--password", default="admin123", help="Password (default: admin123)")
    parser.add_argument(
        "--role",
        default="admin",
        choices=["admin", "analyst", "viewer"],
        help="Role (default: admin)",
    )
    args = parser.parse_args()

    print(f"Creating user: {args.username} / role={args.role}")
    asyncio.run(create_user(args.username, args.password, args.role))
    print("\nDone. You can now log in at http://localhost:5173")


if __name__ == "__main__":
    main()
