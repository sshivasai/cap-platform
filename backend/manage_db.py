# File: backend/manage_db.py
"""
Database migration management script for CAP Platform.

This script provides utilities for managing database migrations including:
- Running migrations (upgrade/downgrade)
- Creating new migrations
- Database initialization
- Development utilities

Usage:
    python manage_db.py init          # Initialize database
    python manage_db.py migrate       # Run pending migrations
    python manage_db.py upgrade       # Alias for migrate
    python manage_db.py downgrade     # Downgrade one migration
    python manage_db.py revision      # Create new migration
    python manage_db.py history       # Show migration history
    python manage_db.py current       # Show current migration
    python manage_db.py reset         # Reset database (development only)
    python manage_db.py seed          # Seed database with test data
"""

import asyncio
import os
import sys
import subprocess
import argparse
from pathlib import Path
from typing import Optional

# Add the app directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from app.core.config import settings


def setup_logging():
    """Setup basic logging for the script."""
    import logging
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)


logger = setup_logging()


class DatabaseManager:
    """Database management utilities."""
    
    def __init__(self):
        self.alembic_cfg_path = Path(__file__).parent / "alembic.ini"
        
    def run_alembic_command(self, command: str, *args) -> int:
        """
        Run an Alembic command.
        
        Args:
            command: Alembic command to run
            *args: Additional arguments
            
        Returns:
            int: Exit code
        """
        cmd = [
            sys.executable, "-m", "alembic",
            "-c", str(self.alembic_cfg_path),
            command
        ] + list(args)
        
        logger.info(f"Running command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            if result.stdout:
                print(result.stdout)
            return 0
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with exit code {e.returncode}")
            if e.stdout:
                print("STDOUT:", e.stdout)
            if e.stderr:
                print("STDERR:", e.stderr)
            return e.returncode
    
    async def init_database(self) -> bool:
        """
        Initialize the database.
        
        Returns:
            bool: True if successful
        """
        try:
            logger.info("Initializing database connections...")
            
            # Import here to avoid circular imports
            from app.core.database import db_manager
            
            # Initialize database manager
            await db_manager.initialize()
            
            # Check if we need to create the database
            logger.info("Database connections initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            return False
    
    async def check_database_connection(self) -> bool:
        """
        Check database connection.
        
        Returns:
            bool: True if connection is successful
        """
        try:
            from app.core.database import db_manager
            
            await db_manager.initialize()
            health = await db_manager.health_check()
            postgres_status = health.get("postgresql", {}).get("status", "unhealthy")
            
            if postgres_status == "healthy":
                logger.info("✅ Database connection successful")
                return True
            else:
                logger.error(f"❌ Database connection failed: {health}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to check database connection: {e}")
            return False
    
    def upgrade_database(self, revision: str = "head") -> int:
        """
        Upgrade database to a specific revision.
        
        Args:
            revision: Target revision (default: head)
            
        Returns:
            int: Exit code
        """
        logger.info(f"Upgrading database to revision: {revision}")
        return self.run_alembic_command("upgrade", revision)
    
    def downgrade_database(self, revision: str = "-1") -> int:
        """
        Downgrade database by one revision or to a specific revision.
        
        Args:
            revision: Target revision (default: -1 for one step back)
            
        Returns:
            int: Exit code
        """
        logger.info(f"Downgrading database to revision: {revision}")
        return self.run_alembic_command("downgrade", revision)
    
    def create_revision(self, message: str, autogenerate: bool = True) -> int:
        """
        Create a new migration revision.
        
        Args:
            message: Migration message
            autogenerate: Whether to use autogenerate
            
        Returns:
            int: Exit code
        """
        logger.info(f"Creating new revision: {message}")
        
        args = ["revision"]
        if autogenerate:
            args.append("--autogenerate")
        args.extend(["-m", message])
        
        return self.run_alembic_command(*args)
    
    def show_history(self) -> int:
        """
        Show migration history.
        
        Returns:
            int: Exit code
        """
        return self.run_alembic_command("history")
    
    def show_current(self) -> int:
        """
        Show current migration.
        
        Returns:
            int: Exit code
        """
        return self.run_alembic_command("current")
    
    def show_heads(self) -> int:
        """
        Show head revisions.
        
        Returns:
            int: Exit code
        """
        return self.run_alembic_command("heads")
    
    async def reset_database(self) -> bool:
        """
        Reset database (development only).
        
        WARNING: This will drop all tables and data!
        
        Returns:
            bool: True if successful
        """
        if settings.is_production():
            logger.error("Database reset is not allowed in production!")
            return False
        
        try:
            logger.warning("⚠️  RESETTING DATABASE - ALL DATA WILL BE LOST!")
            
            # Import here to avoid circular imports
            from app.core.database import db_manager, Base
            
            # Initialize database connection
            await db_manager.initialize()
            
            # Get sync engine for raw SQL
            sync_engine = db_manager.sync_engine
            
            # Drop all tables
            with sync_engine.begin() as conn:
                # Drop all tables
                Base.metadata.drop_all(conn)
                logger.info("All tables dropped")
                
                # Drop alembic version table if it exists
                conn.execute("DROP TABLE IF EXISTS alembic_version CASCADE")
                logger.info("Alembic version table dropped")
            
            logger.info("Database reset completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reset database: {e}")
            return False
    
    async def seed_database(self) -> bool:
        """
        Seed database with test data (development only).
        
        Returns:
            bool: True if successful
        """
        if settings.is_production():
            logger.error("Database seeding is not allowed in production!")
            return False
        
        try:
            logger.info("Seeding database with test data...")
            
            # Import here to avoid circular imports
            from app.core.database import db_manager
            from app.models.organization import Organization
            from app.models.user import User
            from app.models.auth import SecuritySettings
            
            # Initialize database
            await db_manager.initialize()
            
            # Check if password utility exists, if not create a simple version
            try:
                from app.utils.password import get_password_hash
            except ImportError:
                import bcrypt
                def get_password_hash(password: str) -> str:
                    password_bytes = password.encode('utf-8')
                    salt = bcrypt.gensalt(rounds=12)
                    hashed = bcrypt.hashpw(password_bytes, salt)
                    return hashed.decode('utf-8')
            
            import uuid
            from datetime import datetime, timedelta
            
            async with db_manager.get_async_session() as session:
                # Create default organization if it doesn't exist
                from sqlalchemy import select
                result = await session.execute(
                    select(Organization).where(Organization.slug == "default")
                )
                default_org = result.scalar_one_or_none()
                
                if not default_org:
                    default_org = Organization(
                        name="Default Organization",
                        slug="default",
                        subscription_tier="pro",
                        settings={
                            "theme": "light",
                            "timezone": "UTC",
                            "language": "en"
                        },
                        usage_limits={
                            "max_users": 100,
                            "max_agents": 50,
                            "max_conversations_per_month": 10000
                        },
                        credit_balance=1000.00
                    )
                    session.add(default_org)
                    await session.flush()
                    logger.info("Created default organization")
                
                # Create admin user if it doesn't exist
                result = await session.execute(
                    select(User).where(User.email == "admin@capplatform.dev")
                )
                admin_user = result.scalar_one_or_none()
                
                if not admin_user:
                    admin_user = User(
                        organization_id=default_org.id,
                        email="admin@capplatform.dev",
                        password_hash=get_password_hash("admin123!"),
                        first_name="Admin",
                        last_name="User",
                        role="owner",
                        is_email_verified=True,
                        is_active=True,
                        account_status="active",
                        terms_accepted_at=datetime.utcnow(),
                        privacy_policy_accepted_at=datetime.utcnow(),
                        onboarding_completed=True
                    )
                    session.add(admin_user)
                    await session.flush()
                    logger.info("Created admin user (admin@capplatform.dev / admin123!)")
                
                # Create test user if it doesn't exist
                result = await session.execute(
                    select(User).where(User.email == "user@capplatform.dev")
                )
                test_user = result.scalar_one_or_none()
                
                if not test_user:
                    test_user = User(
                        organization_id=default_org.id,
                        email="user@capplatform.dev",
                        password_hash=get_password_hash("user123!"),
                        first_name="Test",
                        last_name="User",
                        role="member",
                        is_email_verified=True,
                        is_active=True,
                        account_status="active",
                        terms_accepted_at=datetime.utcnow(),
                        privacy_policy_accepted_at=datetime.utcnow(),
                        onboarding_completed=True
                    )
                    session.add(test_user)
                    await session.flush()
                    logger.info("Created test user (user@capplatform.dev / user123!)")
                
                # Create security settings if they don't exist
                result = await session.execute(
                    select(SecuritySettings).where(
                        SecuritySettings.organization_id == default_org.id
                    )
                )
                security_settings = result.scalar_one_or_none()
                
                if not security_settings:
                    security_settings = SecuritySettings(
                        organization_id=default_org.id
                    )
                    session.add(security_settings)
                    logger.info("Created default security settings")
                
                await session.commit()
            
            logger.info("✅ Database seeding completed successfully")
            logger.info("Test accounts created:")
            logger.info("  Admin: admin@capplatform.dev / admin123!")
            logger.info("  User:  user@capplatform.dev / user123!")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to seed database: {e}")
            return False
    
    async def validate_migrations(self) -> bool:
        """
        Validate that migrations are up to date.
        
        Returns:
            bool: True if migrations are current
        """
        try:
            # Check if there are pending migrations
            result = subprocess.run([
                sys.executable, "-m", "alembic",
                "-c", str(self.alembic_cfg_path),
                "current"
            ], capture_output=True, text=True, check=True)
            
            current_output = result.stdout.strip()
            
            result = subprocess.run([
                sys.executable, "-m", "alembic",
                "-c", str(self.alembic_cfg_path),
                "heads"
            ], capture_output=True, text=True, check=True)
            
            heads_output = result.stdout.strip()
            
            if "head" in current_output or current_output in heads_output:
                logger.info("Database migrations are up to date")
                return True
            else:
                logger.warning("Database migrations are not up to date")
                return False
                
        except Exception as e:
            logger.error(f"Failed to validate migrations: {e}")
            return False


async def main():
    """Main entry point for the database management script."""
    parser = argparse.ArgumentParser(description="CAP Platform Database Management")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Init command
    subparsers.add_parser("init", help="Initialize database")
    
    # Migration commands
    migrate_parser = subparsers.add_parser("migrate", help="Run pending migrations")
    migrate_parser.add_argument("--revision", default="head", help="Target revision")
    
    upgrade_parser = subparsers.add_parser("upgrade", help="Upgrade database (alias for migrate)")
    upgrade_parser.add_argument("--revision", default="head", help="Target revision")
    
    downgrade_parser = subparsers.add_parser("downgrade", help="Downgrade database")
    downgrade_parser.add_argument("--revision", default="-1", help="Target revision")
    
    # Revision commands
    revision_parser = subparsers.add_parser("revision", help="Create new migration")
    revision_parser.add_argument("-m", "--message", required=True, help="Migration message")
    revision_parser.add_argument("--autogenerate", action="store_true", default=True, help="Use autogenerate")
    revision_parser.add_argument("--no-autogenerate", action="store_true", help="Don't use autogenerate")
    
    # Info commands
    subparsers.add_parser("history", help="Show migration history")
    subparsers.add_parser("current", help="Show current migration")
    subparsers.add_parser("heads", help="Show head revisions")
    
    # Development commands
    subparsers.add_parser("reset", help="Reset database (development only)")
    subparsers.add_parser("seed", help="Seed database with test data (development only)")
    subparsers.add_parser("check", help="Check database connection")
    subparsers.add_parser("validate", help="Validate migrations are current")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    db_mgr = DatabaseManager()
    exit_code = 0
    
    try:
        if args.command == "init":
            logger.info("Initializing database...")
            success = await db_mgr.init_database()
            if success:
                # Also run migrations after initialization
                exit_code = db_mgr.upgrade_database()
                if exit_code == 0:
                    logger.info("✅ Database initialization completed")
                else:
                    logger.error("❌ Database initialization failed")
            else:
                exit_code = 1
        
        elif args.command in ("migrate", "upgrade"):
            revision = getattr(args, "revision", "head")
            exit_code = db_mgr.upgrade_database(revision)
        
        elif args.command == "downgrade":
            revision = getattr(args, "revision", "-1")
            exit_code = db_mgr.downgrade_database(revision)
        
        elif args.command == "revision":
            autogenerate = args.autogenerate and not args.no_autogenerate
            exit_code = db_mgr.create_revision(args.message, autogenerate)
        
        elif args.command == "history":
            exit_code = db_mgr.show_history()
        
        elif args.command == "current":
            exit_code = db_mgr.show_current()
        
        elif args.command == "heads":
            exit_code = db_mgr.show_heads()
        
        elif args.command == "reset":
            if input("⚠️  This will DELETE ALL DATA! Type 'yes' to continue: ") == "yes":
                success = await db_mgr.reset_database()
                exit_code = 0 if success else 1
            else:
                logger.info("Database reset cancelled")
                exit_code = 0
        
        elif args.command == "seed":
            success = await db_mgr.seed_database()
            exit_code = 0 if success else 1
        
        elif args.command == "check":
            success = await db_mgr.check_database_connection()
            exit_code = 0 if success else 1
        
        elif args.command == "validate":
            success = await db_mgr.validate_migrations()
            exit_code = 0 if success else 1
        
        else:
            logger.error(f"Unknown command: {args.command}")
            exit_code = 1
    
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        exit_code = 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        exit_code = 1
    finally:
        # Clean up database connections
        try:
            from app.core.database import db_manager
            await db_manager.close()
        except Exception as e:
            logger.debug(f"Error closing database connections: {e}")
    
    return exit_code


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)