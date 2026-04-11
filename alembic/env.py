# alembic/env.py
import sys
import os
from logging.config import fileConfig

from sqlalchemy import create_engine, pool
from alembic import context

# -----------------------------
# Add project folder to path
# -----------------------------
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# -----------------------------
# Import your project settings
# -----------------------------
from app.core.config import settings  # reads from .env
from app.db.models import SQLModel     # all your SQLModel tables

# -----------------------------
# Alembic Config
# -----------------------------
config = context.config

# Set up Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Metadata for 'autogenerate'
target_metadata = SQLModel.metadata

# -----------------------------
# Offline migrations
# -----------------------------
def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (generates SQL scripts)."""
    url = settings.DATABASE_URL  # read from .env
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

# -----------------------------
# Online migrations
# -----------------------------
def run_migrations_online() -> None:
    """Run migrations in 'online' mode (executes against DB)."""
    connectable = create_engine(
        settings.DATABASE_URL,
        poolclass=pool.NullPool,
        echo=True,  # Optional: logs all SQL statements during migration
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

# -----------------------------
# Run offline or online
# -----------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()