# File: backend/app/core/database.py
"""
Database configuration and connection management for CAP Platform.

This module handles:
- PostgreSQL connection with SQLAlchemy (async + sync)
- MongoDB connection with Motor
- Qdrant vector database connection
- Connection pooling and session management
- Database health checks and monitoring

Designed for production scalability with proper connection pooling,
health monitoring, and error handling.
"""

import asyncio
import logging
from typing import AsyncGenerator, Optional, Dict, Any
from contextlib import asynccontextmanager
from sqlalchemy import create_engine, text, MetaData, event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
    AsyncEngine
)
from sqlalchemy.orm import DeclarativeBase, declared_attr, sessionmaker, Session
from sqlalchemy.pool import NullPool, StaticPool
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from qdrant_client import QdrantClient
from qdrant_client.http import models as qdrant_models
from pymongo.errors import ConnectionFailure
import redis.asyncio as redis

from app.core.config import settings
from app.utils.logging import get_logger

logger = get_logger(__name__)


# ================================
# SQLAlchemy Base and Configuration
# ================================

class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy models.
    
    Provides common functionality and naming conventions for all database models.
    """
    
    # Generate table names automatically from class names
    @declared_attr
    def __tablename__(cls) -> str:
        """Generate table name from class name (lowercase with underscores)."""
        import re
        # Convert CamelCase to snake_case
        name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', cls.__name__)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()
    
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s"
        }
    )


# ================================
# PostgreSQL Configuration
# ================================

class DatabaseManager:
    """
    Centralized database connection manager.
    
    Handles PostgreSQL (async + sync), MongoDB, Qdrant, and Redis connections
    with proper connection pooling, health checks, and error handling.
    """
    
    def __init__(self):
        self._async_engine: Optional[AsyncEngine] = None
        self._sync_engine = None
        self._async_session_factory = None
        self._sync_session_factory = None
        self._mongo_client: Optional[AsyncIOMotorClient] = None
        self._mongo_db: Optional[AsyncIOMotorDatabase] = None
        self._qdrant_client: Optional[QdrantClient] = None
        self._redis_client: Optional[redis.Redis] = None
        self._initialized = False
    
    async def initialize(self):
        """Initialize all database connections."""
        if self._initialized:
            return
        
        logger.info("Initializing database connections...")
        
        try:
            # Initialize PostgreSQL
            await self._initialize_postgresql()
            
            # Initialize MongoDB (optional)
            try:
                await self._initialize_mongodb()
            except Exception as e:
                logger.warning(f"MongoDB initialization failed (optional): {e}")
            
            # Initialize Qdrant (optional)
            try:
                await self._initialize_qdrant()
            except Exception as e:
                logger.warning(f"Qdrant initialization failed (optional): {e}")
            
            # Initialize Redis (optional)
            try:
                await self._initialize_redis()
            except Exception as e:
                logger.warning(f"Redis initialization failed (optional): {e}")
            
            self._initialized = True
            logger.info("Database connections initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize databases: {e}")
            await self.close()
            raise
    
    async def _initialize_postgresql(self):
        """Initialize PostgreSQL connections (async and sync)."""
        logger.info("Initializing PostgreSQL connections...")
        
        # Async Engine Configuration - FIXED for asyncio
        async_engine_config = {
            "url": settings.postgres_url,
            "poolclass": NullPool,  # Use NullPool for async engines
            "echo": settings.DEBUG,  # Log SQL queries in debug mode
            "future": True,  # Use SQLAlchemy 2.0 style
        }
        
        # Create async engine
        self._async_engine = create_async_engine(**async_engine_config)
        
        # Create async session factory
        self._async_session_factory = async_sessionmaker(
            bind=self._async_engine,
            class_=AsyncSession,
            expire_on_commit=False,  # Don't expire objects after commit
            autoflush=True,  # Auto-flush before queries
            autocommit=False,  # Manual transaction control
        )
        
        # Sync Engine Configuration (for Alembic migrations)
        sync_engine_config = {
            "url": settings.postgres_sync_url,
            "poolclass": StaticPool,  # Use StaticPool for sync engine in async context
            "pool_pre_ping": True,
            "echo": settings.DEBUG,
            "future": True,
        }
        
        # Create sync engine
        self._sync_engine = create_engine(**sync_engine_config)
        
        # Create sync session factory
        self._sync_session_factory = sessionmaker(
            bind=self._sync_engine,
            autoflush=True,
            autocommit=False,
        )
        
        # Test connection
        await self._test_postgresql_connection()
        
        logger.info("PostgreSQL connections initialized successfully")
    
    async def _test_postgresql_connection(self):
        """Test PostgreSQL connection."""
        try:
            async with self._async_engine.begin() as conn:
                result = await conn.execute(text("SELECT 1"))
                result.fetchone()
            logger.debug("PostgreSQL connection test successful")
        except Exception as e:
            logger.error(f"PostgreSQL connection test failed: {e}")
            raise
    
    async def _initialize_mongodb(self):
        """Initialize MongoDB connection."""
        logger.info("Initializing MongoDB connection...")
        
        try:
            # Create MongoDB client with connection pooling
            self._mongo_client = AsyncIOMotorClient(
                settings.MONGODB_URL,
                maxPoolSize=20,  # Maximum connections in pool
                minPoolSize=5,   # Minimum connections in pool
                maxIdleTimeMS=30000,  # Max idle time for connections
                waitQueueTimeoutMS=5000,  # Timeout when waiting for connection
                retryWrites=True,  # Retry writes on network errors
                serverSelectionTimeoutMS=5000,  # Server selection timeout
            )
            
            # Get database reference
            self._mongo_db = self._mongo_client[settings.MONGODB_DB_NAME]
            
            # Test connection
            await self._test_mongodb_connection()
            
            logger.info("MongoDB connection initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize MongoDB: {e}")
            raise
    
    async def _test_mongodb_connection(self):
        """Test MongoDB connection."""
        try:
            # Ping the database
            await self._mongo_client.admin.command('ping')
            logger.debug("MongoDB connection test successful")
        except ConnectionFailure as e:
            logger.error(f"MongoDB connection test failed: {e}")
            raise
    
    async def _initialize_qdrant(self):
        """Initialize Qdrant vector database connection."""
        logger.info("Initializing Qdrant connection...")
        
        try:
            # Create Qdrant client
            client_config = {
                "host": settings.QDRANT_HOST,
                "port": settings.QDRANT_PORT,
                "timeout": 10,  # Request timeout in seconds
            }
            
            # Add API key if provided
            if settings.QDRANT_API_KEY:
                client_config["api_key"] = settings.QDRANT_API_KEY
            
            self._qdrant_client = QdrantClient(**client_config)
            
            # Test connection
            await self._test_qdrant_connection()
            
            logger.info("Qdrant connection initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Qdrant: {e}")
            raise
    
    async def _test_qdrant_connection(self):
        """Test Qdrant connection."""
        try:
            # Get cluster info to test connection
            cluster_info = self._qdrant_client.get_cluster_info()
            logger.debug(f"Qdrant connection test successful. Cluster info: {cluster_info}")
        except Exception as e:
            logger.error(f"Qdrant connection test failed: {e}")
            raise
    
    async def _initialize_redis(self):
        """Initialize Redis connection."""
        logger.info("Initializing Redis connection...")
        
        try:
            # Create Redis client with connection pooling
            redis_config = {
                "host": settings.REDIS_HOST,
                "port": settings.REDIS_PORT,
                "db": settings.REDIS_DB,
                "decode_responses": True,  # Automatically decode byte responses to strings
                "max_connections": settings.REDIS_POOL_SIZE,
                "retry_on_timeout": True,
                "socket_connect_timeout": 5,
                "socket_timeout": 5,
                "health_check_interval": 30,  # Health check every 30 seconds
            }
            
            # Add password if provided
            if settings.REDIS_PASSWORD:
                redis_config["password"] = settings.REDIS_PASSWORD
            
            # Create connection pool
            connection_pool = redis.ConnectionPool(**redis_config)
            self._redis_client = redis.Redis(connection_pool=connection_pool)
            
            # Test connection
            await self._test_redis_connection()
            
            logger.info("Redis connection initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {e}")
            raise
    
    async def _test_redis_connection(self):
        """Test Redis connection."""
        try:
            # Ping Redis server
            pong = await self._redis_client.ping()
            if pong:
                logger.debug("Redis connection test successful")
            else:
                raise Exception("Redis ping returned False")
        except Exception as e:
            logger.error(f"Redis connection test failed: {e}")
            raise
    
    # ================================
    # Connection Getters
    # ================================
    
    @property
    def async_engine(self) -> AsyncEngine:
        """Get async PostgreSQL engine."""
        if not self._async_engine:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._async_engine
    
    @property
    def sync_engine(self):
        """Get sync PostgreSQL engine."""
        if not self._sync_engine:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._sync_engine
    
    @property
    def mongo_db(self) -> AsyncIOMotorDatabase:
        """Get MongoDB database."""
        if not self._mongo_db:
            raise RuntimeError("MongoDB not initialized. Call initialize() first.")
        return self._mongo_db
    
    @property
    def qdrant_client(self) -> QdrantClient:
        """Get Qdrant client."""
        if not self._qdrant_client:
            raise RuntimeError("Qdrant not initialized. Call initialize() first.")
        return self._qdrant_client
    
    @property
    def redis_client(self) -> redis.Redis:
        """Get Redis client."""
        if not self._redis_client:
            raise RuntimeError("Redis not initialized. Call initialize() first.")
        return self._redis_client
    
    # ================================
    # Session Management
    # ================================
    
    @asynccontextmanager
    async def get_async_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get async database session with automatic cleanup.
        
        Usage:
            async with db_manager.get_async_session() as session:
                # Use session for database operations
                result = await session.execute(select(User))
        """
        if not self._async_session_factory:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        async with self._async_session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    def get_sync_session(self) -> Session:
        """
        Get sync database session for Alembic migrations.
        
        Returns:
            Session: Synchronous database session
        """
        if not self._sync_session_factory:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        return self._sync_session_factory()
    
    # ================================
    # Health Checks
    # ================================
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on all database connections.
        
        Returns:
            Dict containing health status of all database connections
        """
        health_status = {
            "postgresql": {"status": "unknown", "error": None},
            "mongodb": {"status": "unknown", "error": None},
            "qdrant": {"status": "unknown", "error": None},
            "redis": {"status": "unknown", "error": None},
        }
        
        # Check PostgreSQL
        try:
            async with self.get_async_session() as session:
                await session.execute(text("SELECT 1"))
            health_status["postgresql"]["status"] = "healthy"
        except Exception as e:
            health_status["postgresql"]["status"] = "unhealthy"
            health_status["postgresql"]["error"] = str(e)
            logger.error(f"PostgreSQL health check failed: {e}")
        
        # Check MongoDB
        try:
            if self._mongo_client:
                await self._mongo_client.admin.command('ping')
                health_status["mongodb"]["status"] = "healthy"
            else:
                health_status["mongodb"]["status"] = "not_configured"
        except Exception as e:
            health_status["mongodb"]["status"] = "unhealthy"
            health_status["mongodb"]["error"] = str(e)
            logger.error(f"MongoDB health check failed: {e}")
        
        # Check Qdrant
        try:
            if self._qdrant_client:
                self._qdrant_client.get_cluster_info()
                health_status["qdrant"]["status"] = "healthy"
            else:
                health_status["qdrant"]["status"] = "not_configured"
        except Exception as e:
            health_status["qdrant"]["status"] = "unhealthy"
            health_status["qdrant"]["error"] = str(e)
            logger.error(f"Qdrant health check failed: {e}")
        
        # Check Redis
        try:
            if self._redis_client:
                await self._redis_client.ping()
                health_status["redis"]["status"] = "healthy"
            else:
                health_status["redis"]["status"] = "not_configured"
        except Exception as e:
            health_status["redis"]["status"] = "unhealthy"
            health_status["redis"]["error"] = str(e)
            logger.error(f"Redis health check failed: {e}")
        
        return health_status
    
    # ================================
    # Connection Statistics
    # ================================
    
    async def get_connection_stats(self) -> Dict[str, Any]:
        """
        Get connection pool statistics.
        
        Returns:
            Dict containing connection pool statistics
        """
        stats = {}
        
        # PostgreSQL stats
        if self._async_engine:
            stats["postgresql"] = {
                "engine_type": "async",
                "pool_class": str(type(self._async_engine.pool)),
                "url": str(self._async_engine.url).replace(self._async_engine.url.password or "", "***")
            }
        
        # Redis stats
        try:
            if self._redis_client:
                redis_info = await self._redis_client.info()
                stats["redis"] = {
                    "connected_clients": redis_info.get("connected_clients", 0),
                    "used_memory": redis_info.get("used_memory_human", "0B"),
                    "total_commands_processed": redis_info.get("total_commands_processed", 0),
                }
        except Exception as e:
            stats["redis"] = {"error": str(e)}
        
        # MongoDB stats
        try:
            if self._mongo_client:
                # Get server status (requires admin privileges)
                server_status = await self._mongo_client.admin.command("serverStatus")
                stats["mongodb"] = {
                    "connections": server_status.get("connections", {}),
                    "network": server_status.get("network", {}),
                }
        except Exception as e:
            stats["mongodb"] = {"error": f"Unable to get stats: {e}"}
        
        return stats
    
    # ================================
    # Cleanup and Shutdown
    # ================================
    
    async def close(self):
        """Close all database connections."""
        logger.info("Closing database connections...")
        
        # Close PostgreSQL connections
        if self._async_engine:
            await self._async_engine.dispose()
            logger.debug("PostgreSQL async engine disposed")
        
        if self._sync_engine:
            self._sync_engine.dispose()
            logger.debug("PostgreSQL sync engine disposed")
        
        # Close MongoDB connection
        if self._mongo_client:
            self._mongo_client.close()
            logger.debug("MongoDB client closed")
        
        # Close Qdrant connection
        if self._qdrant_client:
            self._qdrant_client.close()
            logger.debug("Qdrant client closed")
        
        # Close Redis connection
        if self._redis_client:
            await self._redis_client.aclose()
            logger.debug("Redis client closed")
        
        self._initialized = False
        logger.info("All database connections closed")


# ================================
# Global Database Manager Instance
# ================================

# Global database manager instance
db_manager = DatabaseManager()


# ================================
# Convenience Functions
# ================================

async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency function for FastAPI to get async database session.
    
    Usage in FastAPI endpoints:
        @app.get("/users/")
        async def get_users(db: AsyncSession = Depends(get_async_db)):
            # Use db session
    """
    async with db_manager.get_async_session() as session:
        yield session


def get_sync_db() -> Session:
    """
    Get synchronous database session.
    
    Primarily used for Alembic migrations and testing.
    """
    return db_manager.get_sync_session()


async def get_mongo_db() -> AsyncIOMotorDatabase:
    """Get MongoDB database instance."""
    return db_manager.mongo_db


async def get_qdrant_client() -> QdrantClient:
    """Get Qdrant client instance."""
    return db_manager.qdrant_client


async def get_redis_client() -> redis.Redis:
    """Get Redis client instance."""
    return db_manager.redis_client


# ================================
# Database Initialization
# ================================

async def init_db():
    """Initialize database connections and create tables if needed."""
    logger.info("Initializing database...")
    
    # Initialize all connections
    await db_manager.initialize()
    
    # Create tables if they don't exist (for development)
    if settings.is_development():
        logger.info("Creating database tables...")
        async with db_manager.async_engine.begin() as conn:
            # Import all models to ensure they're registered
            try:
                from app.models import user, organization, auth  # noqa
            except ImportError as e:
                logger.warning(f"Could not import models (may not exist yet): {e}")
            
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database tables created successfully")
    
    # Initialize Qdrant collections if needed
    try:
        await init_qdrant_collections()
    except Exception as e:
        logger.warning(f"Could not initialize Qdrant collections: {e}")
    
    logger.info("Database initialization completed")


async def init_qdrant_collections():
    """Initialize Qdrant collections for vector storage."""
    logger.info("Initializing Qdrant collections...")
    
    try:
        qdrant = db_manager.qdrant_client
        
        # Define collections for different vector types
        collections_config = [
            {
                "name": "knowledge_base_chunks",
                "vector_size": 1536,  # OpenAI embedding size
                "distance": qdrant_models.Distance.COSINE,
                "description": "Knowledge base document chunks"
            },
            {
                "name": "conversation_embeddings",
                "vector_size": 1536,
                "distance": qdrant_models.Distance.COSINE,
                "description": "Conversation embeddings for similarity search"
            }
        ]
        
        # Create collections if they don't exist
        existing_collections = qdrant.get_collections().collections
        existing_names = {col.name for col in existing_collections}
        
        for config in collections_config:
            if config["name"] not in existing_names:
                logger.info(f"Creating Qdrant collection: {config['name']}")
                
                qdrant.create_collection(
                    collection_name=config["name"],
                    vectors_config=qdrant_models.VectorParams(
                        size=config["vector_size"],
                        distance=config["distance"]
                    ),
                    optimizers_config=qdrant_models.OptimizersConfig(
                        default_segment_number=2,
                        max_segment_size=None,
                        memmap_threshold=None,
                        indexing_threshold=20000,
                        flush_interval_sec=5,
                        max_optimization_threads=1
                    ),
                    hnsw_config=qdrant_models.HnswConfig(
                        m=16,
                        ef_construct=100,
                        full_scan_threshold=10000,
                        max_indexing_threads=0,
                        on_disk=False
                    )
                )
                
                logger.info(f"Created Qdrant collection: {config['name']}")
            else:
                logger.debug(f"Qdrant collection already exists: {config['name']}")
        
        logger.info("Qdrant collections initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize Qdrant collections: {e}")
        # Don't raise error as Qdrant might not be critical for basic functionality
        logger.warning("Continuing without Qdrant collections")


# ================================
# Database Utilities
# ================================

class DatabaseTransaction:
    """
    Context manager for database transactions with proper error handling.
    
    Usage:
        async with DatabaseTransaction() as tx:
            # Perform database operations
            await tx.session.execute(...)
            # Transaction is automatically committed or rolled back
    """
    
    def __init__(self):
        self.session: Optional[AsyncSession] = None
    
    async def __aenter__(self) -> 'DatabaseTransaction':
        self.session = db_manager._async_session_factory()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            await self.session.rollback()
            logger.error(f"Transaction rolled back due to error: {exc_val}")
        else:
            await self.session.commit()
            logger.debug("Transaction committed successfully")
        
        await self.session.close()


# ================================
# Connection Monitoring
# ================================

async def monitor_connections():
    """
    Monitor database connections and log statistics.
    
    This function can be called periodically to monitor connection health.
    """
    try:
        # Get health status
        health = await db_manager.health_check()
        
        # Get connection stats
        stats = await db_manager.get_connection_stats()
        
        # Log summary
        healthy_services = sum(1 for service in health.values() if service["status"] == "healthy")
        total_services = len([s for s in health.values() if s["status"] != "not_configured"])
        
        logger.info(
            f"Database health: {healthy_services}/{total_services} services healthy"
        )
        
        # Log detailed stats if in debug mode
        if settings.DEBUG:
            logger.debug(f"Connection stats: {stats}")
        
        return {"health": health, "stats": stats}
        
    except Exception as e:
        logger.error(f"Failed to monitor connections: {e}")
        return None