# File: backend/app/migrations/env.py
"""
Alembic migration environment configuration for CAP Platform.

This module handles the migration environment setup including:
- Database connection management
- Migration context configuration
- Offline and online migration modes
- Multi-tenant schema support
"""

import asyncio
import os
import sys
from logging.config import fileConfig
from typing import Any

from sqlalchemy import engine_from_config, pool
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from alembic import context

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Import the Base and settings after path modification
from app.core.config import settings
from app.core.database import Base

# Import all models to ensure they're registered with metadata
from app.models import user, organization, auth  # noqa

# This is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Add your model's MetaData object here for 'autogenerate' support
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def get_database_url() -> str:
    """
    Get the database URL for migrations.
    
    Uses the synchronous PostgreSQL URL from settings.
    
    Returns:
        str: Database connection URL
    """
    # Override the sqlalchemy.url from alembic.ini with our settings
    return settings.postgres_sync_url


def process_revision_directives(context: Any, revision: Any, directives: Any) -> None:
    """
    Process revision directives to customize migration generation.
    
    This function allows us to modify the migration before it's written.
    We can add custom logic, modify operations, or add additional commands.
    
    Args:
        context: Migration context
        revision: Revision information
        directives: Migration directives
    """
    # Skip empty migrations
    if getattr(config.cmd_opts, 'autogenerate', False):
        script = directives[0]
        if script.upgrade_ops.is_empty():
            directives[:] = []
            print("No changes detected, skipping migration generation.")
            return


def render_item(type_: str, obj: Any, autogen_context: Any) -> str:
    """
    Custom rendering for migration items.
    
    This allows us to customize how certain database objects are rendered
    in the migration files.
    
    Args:
        type_: Type of object being rendered
        obj: The object to render
        autogen_context: Autogeneration context
        
    Returns:
        str: Rendered representation of the object
    """
    # Custom rendering for specific types
    if type_ == "type" and hasattr(obj, "python_type"):
        # Handle custom types
        if obj.python_type.__name__ == "UUID":
            return "sa.UUID()"
    
    # Use default rendering for other types
    return False


def include_name(name: str, type_: str, parent_names: dict) -> bool:
    """
    Determine whether to include a name in the migration.
    
    This function allows us to filter what gets included in migrations.
    Useful for excluding certain tables, indexes, or constraints.
    
    Args:
        name: Name of the object
        type_: Type of object (table, index, constraint, etc.)
        parent_names: Dictionary of parent object names
        
    Returns:
        bool: Whether to include this object in the migration
    """
    # Skip alembic version table
    if type_ == "table" and name == "alembic_version":
        return False
    
    # Skip certain temporary or system tables
    if type_ == "table" and name.startswith("_"):
        return False
    
    # Include everything else
    return True


def compare_type(context: Any, inspected_column: Any, metadata_column: Any, inspected_type: Any, metadata_type: Any) -> bool:
    """
    Custom type comparison for migrations.
    
    This function allows us to customize how column types are compared
    to determine if a migration is needed.
    
    Args:
        context: Migration context
        inspected_column: Column from database inspection
        metadata_column: Column from SQLAlchemy metadata
        inspected_type: Type from database inspection
        metadata_type: Type from SQLAlchemy metadata
        
    Returns:
        bool: Whether the types are different and need migration
    """
    # Handle UUID type comparison
    if hasattr(metadata_type, "python_type") and metadata_type.python_type.__name__ == "UUID":
        if str(inspected_type).upper().startswith("UUID"):
            return False
    
    # Handle JSONB vs JSON comparison
    if str(metadata_type).upper() == "JSONB" and str(inspected_type).upper() in ["JSON", "JSONB"]:
        return False
    
    # Use default comparison
    return None


def compare_server_default(context: Any, inspected_column: Any, metadata_column: Any, inspected_default: Any, metadata_default: Any, rendered_metadata_default: Any) -> bool:
    """
    Custom server default comparison for migrations.
    
    This function allows us to customize how server defaults are compared.
    
    Args:
        context: Migration context
        inspected_column: Column from database inspection
        metadata_column: Column from SQLAlchemy metadata
        inspected_default: Default from database inspection
        metadata_default: Default from SQLAlchemy metadata
        rendered_metadata_default: Rendered version of metadata default
        
    Returns:
        bool: Whether the defaults are different and need migration
    """
    # Handle UUID generation functions
    if rendered_metadata_default and "uuid_generate_v4()" in rendered_metadata_default:
        if inspected_default and "uuid_generate_v4()" in str(inspected_default):
            return False
    
    # Handle NOW() vs CURRENT_TIMESTAMP
    if rendered_metadata_default and rendered_metadata_default.strip() == "now()":
        if inspected_default and str(inspected_default).upper() in ["NOW()", "CURRENT_TIMESTAMP"]:
            return False
    
    # Use default comparison
    return None


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well. By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Additional configuration for better migrations
        compare_type=compare_type,  # Compare column types
        compare_server_default=compare_server_default,  # Compare server defaults
        render_as_batch=False,  # Don't use batch mode by default
        # Include object name in constraints for better naming
        include_name=include_name,
        include_schemas=True,
        # Custom naming convention
        process_revision_directives=process_revision_directives,
        render_item=render_item,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Any) -> None:
    """
    Run migrations with the given connection.
    
    Args:
        connection: Database connection
    """
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Enhanced configuration for better migrations
        compare_type=compare_type,  # Detect column type changes
        compare_server_default=compare_server_default,  # Detect default value changes
        render_as_batch=False,  # Use regular ALTER statements
        include_name=include_name,  # Include names in generated constraints
        include_schemas=True,  # Include schema information
        # Custom naming convention for constraints
        process_revision_directives=process_revision_directives,
        # User functions for custom comparisons
        user_module_prefix="cap_",  # Prefix for user-defined types
        # Include comments in generated SQL
        render_item=render_item,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    # Get database URL
    database_url = get_database_url()
    
    # Update the alembic configuration with our database URL
    config.set_main_option("sqlalchemy.url", database_url)
    
    # Create engine with connection pooling
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # Use NullPool for migrations
        future=True,  # Use SQLAlchemy 2.0 style
    )

    with connectable.connect() as connection:
        do_run_migrations(connection)


async def run_async_migrations() -> None:
    """
    Run migrations asynchronously.
    
    This is used when we need async database operations during migration.
    """
    database_url = get_database_url()
    
    # Convert sync URL to async URL for async engine
    async_url = database_url.replace("postgresql://", "postgresql+asyncpg://")
    
    # Create async engine
    connectable = create_async_engine(
        async_url,
        poolclass=pool.NullPool,  # Use NullPool for migrations
        future=True,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


# Run migrations based on mode
if context.is_offline_mode():
    print("Running migrations in offline mode...")
    run_migrations_offline()
else:
    print("Running migrations in online mode...")
    # Use sync migrations for better compatibility
    run_migrations_online()