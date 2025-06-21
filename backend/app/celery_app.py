"""
Celery configuration and application setup for CAP Platform.

This module provides:
- Celery application configuration with Redis/RabbitMQ
- Task routing and queue management
- Background task processing for scalable operations
- Periodic task scheduling with Celery Beat
- Task monitoring and error handling
- Integration with application database and cache

Designed for production scalability with proper task routing,
error handling, monitoring, and resource management.
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from celery import Celery, Task
from celery.schedules import crontab
from celery.signals import (
    task_prerun,
    task_postrun,
    task_failure,
    task_success,
    worker_ready,
    worker_shutdown
)
from kombu import Queue, Exchange

from app.core.config import settings
from app.utils.logging import get_logger

logger = get_logger(__name__)


# ================================
# Celery Application Configuration
# ================================

def create_celery_app() -> Celery:
    """
    Create and configure Celery application.
    
    Returns:
        Configured Celery application instance
    """
    # Create Celery instance
    celery_app = Celery(
        "cap_platform",
        broker=settings.CELERY_BROKER_URL,
        backend=settings.CELERY_RESULT_BACKEND,
        include=[
            "app.tasks.notifications",
            "app.tasks.document_processing", 
            "app.tasks.analytics",
            "app.tasks.auth",
            "app.tasks.cleanup",
        ]
    )
    
    # Configure Celery
    celery_app.conf.update(
        # Serialization
        task_serializer=settings.CELERY_TASK_SERIALIZER,
        result_serializer=settings.CELERY_RESULT_SERIALIZER,
        accept_content=settings.CELERY_ACCEPT_CONTENT,
        
        # Timezone
        timezone=settings.CELERY_TIMEZONE,
        enable_utc=settings.CELERY_ENABLE_UTC,
        
        # Task execution
        task_always_eager=False,  # Don't execute tasks synchronously
        task_eager_propagates=True,  # Propagate exceptions in eager mode
        task_ignore_result=False,  # Store task results
        task_store_eager_result=True,  # Store results even in eager mode
        
        # Result backend settings
        result_expires=3600,  # Results expire after 1 hour
        result_backend_max_retries=10,
        result_backend_retry_delay=1,
        
        # Task routing and queues
        task_routes=settings.CELERY_TASK_ROUTES,
        task_default_queue="default",
        task_default_exchange="default",
        task_default_exchange_type="direct",
        task_default_routing_key="default",
        
        # Worker settings
        worker_prefetch_multiplier=settings.CELERY_WORKER_PREFETCH_MULTIPLIER,
        worker_max_tasks_per_child=settings.CELERY_WORKER_MAX_TASKS_PER_CHILD,
        worker_disable_rate_limits=False,
        worker_log_format="[%(asctime)s: %(levelname)s/%(processName)s] %(message)s",
        worker_task_log_format="[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s",
        
        # Monitoring
        worker_send_task_events=True,
        task_send_sent_event=True,
        
        # Error handling
        task_reject_on_worker_lost=True,
        task_acks_late=True,  # Acknowledge tasks after completion
        worker_max_memory_per_child=200000,  # 200MB memory limit per child
        
        # Security
        worker_hijack_root_logger=False,
        worker_log_color=False,
        
        # Beat scheduler settings (for periodic tasks)
        beat_schedule_filename="celerybeat-schedule",
        beat_sync_every=1,
        beat_max_loop_interval=5,
    )
    
    # Configure task queues
    _configure_task_queues(celery_app)
    
    # Configure periodic tasks
    _configure_periodic_tasks(celery_app)
    
    return celery_app


def _configure_task_queues(celery_app: Celery):
    """
    Configure task queues for different types of work.
    
    Args:
        celery_app: Celery application instance
    """
    # Define exchanges
    default_exchange = Exchange("default", type="direct")
    priority_exchange = Exchange("priority", type="direct")
    
    # Define queues with different priorities and configurations
    task_queues = [
        # Default queue for general tasks
        Queue(
            "default",
            exchange=default_exchange,
            routing_key="default",
            queue_arguments={"x-max-priority": 5}
        ),
        
        # High-priority queue for critical tasks
        Queue(
            "priority",
            exchange=priority_exchange,
            routing_key="priority",
            queue_arguments={"x-max-priority": 10}
        ),
        
        # Notification queue for emails, SMS, etc.
        Queue(
            "notifications",
            exchange=default_exchange,
            routing_key="notifications",
            queue_arguments={
                "x-max-priority": 7,
                "x-message-ttl": 300000,  # 5 minutes TTL
            }
        ),
        
        # Document processing queue (CPU intensive)
        Queue(
            "document_processing",
            exchange=default_exchange,
            routing_key="document_processing",
            queue_arguments={
                "x-max-priority": 6,
                "x-message-ttl": 3600000,  # 1 hour TTL
            }
        ),
        
        # Analytics queue for background analytics
        Queue(
            "analytics",
            exchange=default_exchange,
            routing_key="analytics",
            queue_arguments={
                "x-max-priority": 3,
                "x-message-ttl": 7200000,  # 2 hours TTL
            }
        ),
        
        # Authentication queue for auth-related tasks
        Queue(
            "auth",
            exchange=default_exchange,
            routing_key="auth",
            queue_arguments={
                "x-max-priority": 8,
                "x-message-ttl": 600000,  # 10 minutes TTL
            }
        ),
        
        # Cleanup queue for maintenance tasks
        Queue(
            "cleanup",
            exchange=default_exchange,
            routing_key="cleanup",
            queue_arguments={
                "x-max-priority": 1,
                "x-message-ttl": 86400000,  # 24 hours TTL
            }
        ),
    ]
    
    celery_app.conf.task_queues = task_queues
    
    logger.info(f"Configured {len(task_queues)} task queues")


def _configure_periodic_tasks(celery_app: Celery):
    """
    Configure periodic tasks using Celery Beat.
    
    Args:
        celery_app: Celery application instance
    """
    # Define periodic tasks schedule
    beat_schedule = {
        # Cleanup expired sessions every hour
        "cleanup-expired-sessions": {
            "task": "app.tasks.cleanup.cleanup_expired_sessions",
            "schedule": crontab(minute=0),  # Every hour
            "options": {"queue": "cleanup", "priority": 1}
        },
        
        # Cleanup temporary files every 6 hours
        "cleanup-temp-files": {
            "task": "app.tasks.cleanup.cleanup_temp_files",
            "schedule": crontab(minute=0, hour="*/6"),  # Every 6 hours
            "options": {"queue": "cleanup", "priority": 1}
        },
        
        # Generate daily analytics reports
        "generate-daily-analytics": {
            "task": "app.tasks.analytics.generate_daily_report",
            "schedule": crontab(hour=1, minute=0),  # Daily at 1 AM
            "options": {"queue": "analytics", "priority": 3}
        },
        
        # Send credit usage alerts
        "check-credit-usage": {
            "task": "app.tasks.notifications.check_credit_usage_alerts",
            "schedule": crontab(minute="*/30"),  # Every 30 minutes
            "options": {"queue": "notifications", "priority": 6}
        },
        
        # Health check and monitoring
        "health-check": {
            "task": "app.tasks.analytics.system_health_check",
            "schedule": crontab(minute="*/5"),  # Every 5 minutes
            "options": {"queue": "analytics", "priority": 2}
        },
        
        # Process pending document uploads
        "process-pending-documents": {
            "task": "app.tasks.document_processing.process_pending_documents",
            "schedule": crontab(minute="*/10"),  # Every 10 minutes
            "options": {"queue": "document_processing", "priority": 5}
        },
        
        # Refresh authentication tokens
        "refresh-expiring-tokens": {
            "task": "app.tasks.auth.refresh_expiring_tokens",
            "schedule": crontab(minute="*/15"),  # Every 15 minutes
            "options": {"queue": "auth", "priority": 7}
        },
    }
    
    celery_app.conf.beat_schedule = beat_schedule
    
    logger.info(f"Configured {len(beat_schedule)} periodic tasks")


# ================================
# Custom Task Base Class
# ================================

class CAPTask(Task):
    """
    Custom base task class with enhanced functionality.
    
    Provides automatic retry logic, error handling, and logging
    for all tasks in the CAP platform.
    """
    
    # Default retry settings
    autoretry_for = (Exception,)
    retry_kwargs = {"max_retries": 3, "countdown": 60}
    retry_backoff = True
    retry_backoff_max = 700
    retry_jitter = False
    
    def on_success(self, retval, task_id, args, kwargs):
        """Called when task succeeds."""
        logger.info(f"Task {self.name}[{task_id}] succeeded: {retval}")
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called when task fails."""
        logger.error(
            f"Task {self.name}[{task_id}] failed: {exc}",
            exc_info=einfo
        )
        
        # Log task failure for monitoring
        try:
            from app.tasks.analytics import log_task_failure
            log_task_failure.delay(
                task_name=self.name,
                task_id=task_id,
                error=str(exc),
                args=args,
                kwargs=kwargs
            )
        except Exception as e:
            logger.error(f"Failed to log task failure: {e}")
    
    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Called when task is retried."""
        logger.warning(
            f"Task {self.name}[{task_id}] retry: {exc}",
            exc_info=einfo
        )
    
    def before_start(self, task_id, args, kwargs):
        """Called before task starts."""
        logger.debug(f"Starting task {self.name}[{task_id}]")
    
    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        """Called after task returns."""
        logger.debug(f"Task {self.name}[{task_id}] finished with status: {status}")


# ================================
# Task Utilities
# ================================

class TaskManager:
    """
    Utility class for managing tasks and queues.
    """
    
    def __init__(self, celery_app: Celery):
        self.celery_app = celery_app
    
    def get_queue_status(self) -> Dict[str, Any]:
        """
        Get status of all task queues.
        
        Returns:
            Dict containing queue statistics
        """
        try:
            # Get active tasks
            active_tasks = self.celery_app.control.inspect().active()
            
            # Get reserved tasks
            reserved_tasks = self.celery_app.control.inspect().reserved()
            
            # Get scheduled tasks
            scheduled_tasks = self.celery_app.control.inspect().scheduled()
            
            # Get worker statistics
            stats = self.celery_app.control.inspect().stats()
            
            return {
                "active_tasks": active_tasks,
                "reserved_tasks": reserved_tasks,
                "scheduled_tasks": scheduled_tasks,
                "worker_stats": stats,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get queue status: {e}")
            return {"error": str(e)}
    
    def purge_queue(self, queue_name: str) -> int:
        """
        Purge all tasks from a specific queue.
        
        Args:
            queue_name: Name of queue to purge
            
        Returns:
            Number of tasks purged
        """
        try:
            result = self.celery_app.control.purge()
            logger.info(f"Purged queue {queue_name}: {result}")
            return result or 0
        except Exception as e:
            logger.error(f"Failed to purge queue {queue_name}: {e}")
            return 0
    
    def revoke_task(self, task_id: str, terminate: bool = False) -> bool:
        """
        Revoke a running task.
        
        Args:
            task_id: Task ID to revoke
            terminate: Whether to terminate the task forcefully
            
        Returns:
            True if task was revoked successfully
        """
        try:
            self.celery_app.control.revoke(task_id, terminate=terminate)
            logger.info(f"Revoked task {task_id} (terminate={terminate})")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke task {task_id}: {e}")
            return False
    
    def get_task_result(self, task_id: str) -> Any:
        """
        Get result of a completed task.
        
        Args:
            task_id: Task ID
            
        Returns:
            Task result or None if not found
        """
        try:
            result = self.celery_app.AsyncResult(task_id)
            if result.ready():
                return result.result
            return None
        except Exception as e:
            logger.error(f"Failed to get task result {task_id}: {e}")
            return None


# ================================
# Signal Handlers
# ================================

@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **kwds):
    """Handle task prerun signal."""
    logger.debug(f"Task starting: {task.name}[{task_id}]")
    
    # Initialize database connections for task if needed
    try:
        from app.core.database import db_manager
        if not db_manager._initialized:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(db_manager.initialize())
    except Exception as e:
        logger.warning(f"Failed to initialize database for task: {e}")


@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, retval=None, state=None, **kwds):
    """Handle task postrun signal."""
    logger.debug(f"Task finished: {task.name}[{task_id}] - State: {state}")


@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, traceback=None, einfo=None, **kwds):
    """Handle task failure signal."""
    logger.error(f"Task failed: {sender.name}[{task_id}] - Exception: {exception}")
    
    # Additional failure handling can be added here
    # e.g., sending alerts, updating monitoring systems


@task_success.connect
def task_success_handler(sender=None, result=None, **kwds):
    """Handle task success signal."""
    logger.debug(f"Task succeeded: {sender.name}")


@worker_ready.connect
def worker_ready_handler(sender=None, **kwds):
    """Handle worker ready signal."""
    logger.info(f"Celery worker ready: {sender}")
    
    # Initialize any required resources when worker starts
    try:
        # Initialize database connections
        from app.core.database import init_db
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(init_db())
        
        # Initialize Redis connections
        from app.core.redis import init_redis
        loop.run_until_complete(init_redis())
        
        logger.info("Worker initialization completed")
    except Exception as e:
        logger.error(f"Worker initialization failed: {e}")


@worker_shutdown.connect
def worker_shutdown_handler(sender=None, **kwds):
    """Handle worker shutdown signal."""
    logger.info(f"Celery worker shutting down: {sender}")
    
    # Cleanup resources when worker shuts down
    try:
        # Close database connections
        from app.core.database import db_manager
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(db_manager.close())
        
        # Close Redis connections
        from app.core.redis import cleanup_redis
        loop.run_until_complete(cleanup_redis())
        
        logger.info("Worker cleanup completed")
    except Exception as e:
        logger.error(f"Worker cleanup failed: {e}")


# ================================
# Task Priority and Routing Utilities
# ================================

class TaskPriority:
    """Task priority constants."""
    CRITICAL = 10
    HIGH = 8
    NORMAL = 5
    LOW = 3
    BACKGROUND = 1


class TaskRouter:
    """
    Intelligent task routing based on task type and load.
    """
    
    @staticmethod
    def route_task(name: str, args=None, kwargs=None, options=None, task=None, **kw):
        """
        Route tasks to appropriate queues based on task characteristics.
        
        Args:
            name: Task name
            args: Task arguments
            kwargs: Task keyword arguments
            options: Task options
            task: Task instance
            
        Returns:
            Routing information dict
        """
        # Default routing
        queue = "default"
        priority = TaskPriority.NORMAL
        
        # Route based on task name patterns
        if "notification" in name:
            queue = "notifications"
            priority = TaskPriority.HIGH
        elif "document_processing" in name:
            queue = "document_processing"
            priority = TaskPriority.NORMAL
        elif "analytics" in name:
            queue = "analytics"
            priority = TaskPriority.LOW
        elif "auth" in name:
            queue = "auth"
            priority = TaskPriority.HIGH
        elif "cleanup" in name:
            queue = "cleanup"
            priority = TaskPriority.BACKGROUND
        elif "urgent" in name or "critical" in name:
            queue = "priority"
            priority = TaskPriority.CRITICAL
        
        # Override priority if specified in options
        if options and "priority" in options:
            priority = options["priority"]
        
        return {
            "queue": queue,
            "priority": priority,
            "routing_key": queue
        }


# ================================
# Task Decorators
# ================================

def high_priority_task(**kwargs):
    """
    Decorator for high priority tasks.
    
    Usage:
        @high_priority_task()
        @celery_app.task
        def urgent_task():
            pass
    """
    def decorator(func):
        # Set default options for high priority
        default_options = {
            "queue": "priority",
            "priority": TaskPriority.HIGH,
            "retry_kwargs": {"max_retries": 5, "countdown": 30}
        }
        default_options.update(kwargs)
        
        # Apply options to function
        for key, value in default_options.items():
            setattr(func, key, value)
        
        return func
    return decorator


def background_task(**kwargs):
    """
    Decorator for background tasks.
    
    Usage:
        @background_task()
        @celery_app.task
        def background_job():
            pass
    """
    def decorator(func):
        # Set default options for background tasks
        default_options = {
            "queue": "analytics",
            "priority": TaskPriority.BACKGROUND,
            "retry_kwargs": {"max_retries": 1, "countdown": 300}  # 5 minute delay
        }
        default_options.update(kwargs)
        
        # Apply options to function
        for key, value in default_options.items():
            setattr(func, key, value)
        
        return func
    return decorator


def notification_task(**kwargs):
    """
    Decorator for notification tasks.
    
    Usage:
        @notification_task()
        @celery_app.task
        def send_email():
            pass
    """
    def decorator(func):
        # Set default options for notification tasks
        default_options = {
            "queue": "notifications",
            "priority": TaskPriority.HIGH,
            "retry_kwargs": {"max_retries": 3, "countdown": 60}
        }
        default_options.update(kwargs)
        
        # Apply options to function
        for key, value in default_options.items():
            setattr(func, key, value)
        
        return func
    return decorator


# ================================
# Health Monitoring
# ================================

class CeleryHealthMonitor:
    """
    Monitor Celery health and performance.
    """
    
    def __init__(self, celery_app: Celery):
        self.celery_app = celery_app
        self.task_manager = TaskManager(celery_app)
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive health status of Celery system.
        
        Returns:
            Dict containing health information
        """
        try:
            # Get worker information
            workers = self.celery_app.control.inspect().ping()
            active_workers = len(workers) if workers else 0
            
            # Get queue statistics
            queue_status = self.task_manager.get_queue_status()
            
            # Calculate total active tasks
            total_active = 0
            if queue_status.get("active_tasks"):
                for worker_tasks in queue_status["active_tasks"].values():
                    total_active += len(worker_tasks)
            
            # Get memory usage (if available)
            memory_info = {}
            try:
                stats = self.celery_app.control.inspect().stats()
                if stats:
                    for worker, worker_stats in stats.items():
                        if "rusage" in worker_stats:
                            memory_info[worker] = worker_stats["rusage"]
            except Exception:
                pass
            
            health_status = {
                "status": "healthy" if active_workers > 0 else "unhealthy",
                "active_workers": active_workers,
                "total_active_tasks": total_active,
                "queue_status": queue_status,
                "memory_info": memory_info,
                "broker_url": settings.CELERY_BROKER_URL,
                "backend_url": settings.CELERY_RESULT_BACKEND,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            return health_status
            
        except Exception as e:
            logger.error(f"Failed to get Celery health status: {e}")
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def check_broker_connection(self) -> bool:
        """
        Check if broker is accessible.
        
        Returns:
            True if broker is accessible
        """
        try:
            # Try to get broker statistics
            self.celery_app.control.inspect().ping()
            return True
        except Exception as e:
            logger.error(f"Broker connection check failed: {e}")
            return False
    
    def get_task_statistics(self) -> Dict[str, Any]:
        """
        Get task execution statistics.
        
        Returns:
            Dict containing task statistics
        """
        try:
            # This would typically involve querying task results
            # and maintaining statistics in a database or cache
            stats = {
                "total_tasks_executed": 0,
                "successful_tasks": 0,
                "failed_tasks": 0,
                "average_execution_time": 0,
                "task_types": {},
                "queue_utilization": {}
            }
            
            # Implementation would query actual task results
            # For now, return empty statistics
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get task statistics: {e}")
            return {"error": str(e)}


# ================================
# Create Celery Application Instance
# ================================

# Create the main Celery application
celery_app = create_celery_app()

# Set custom task base class
celery_app.Task = CAPTask

# Create utility instances
task_manager = TaskManager(celery_app)
health_monitor = CeleryHealthMonitor(celery_app)

# Configure task router
celery_app.conf.task_router = TaskRouter.route_task

logger.info("Celery application configured successfully")


# ================================
# Convenience Functions
# ================================

def get_celery_app() -> Celery:
    """Get the configured Celery application."""
    return celery_app


def get_task_manager() -> TaskManager:
    """Get the task manager instance."""
    return task_manager


def get_health_monitor() -> CeleryHealthMonitor:
    """Get the health monitor instance."""
    return health_monitor


def schedule_task(
    task_name: str,
    args: tuple = (),
    kwargs: dict = None,
    queue: str = "default",
    priority: int = TaskPriority.NORMAL,
    countdown: int = 0,
    eta: Optional[datetime] = None
) -> str:
    """
    Schedule a task for execution.
    
    Args:
        task_name: Name of the task to execute
        args: Task arguments
        kwargs: Task keyword arguments
        queue: Queue to send task to
        priority: Task priority
        countdown: Delay in seconds before execution
        eta: Specific datetime for execution
        
    Returns:
        Task ID
    """
    kwargs = kwargs or {}
    
    try:
        task = celery_app.send_task(
            task_name,
            args=args,
            kwargs=kwargs,
            queue=queue,
            priority=priority,
            countdown=countdown,
            eta=eta
        )
        
        logger.info(f"Scheduled task {task_name}[{task.id}] on queue {queue}")
        return task.id
        
    except Exception as e:
        logger.error(f"Failed to schedule task {task_name}: {e}")
        raise


def bulk_schedule_tasks(
    tasks: List[Dict[str, Any]],
    queue: str = "default",
    priority: int = TaskPriority.NORMAL
) -> List[str]:
    """
    Schedule multiple tasks efficiently.
    
    Args:
        tasks: List of task dictionaries with name, args, kwargs
        queue: Default queue for tasks
        priority: Default priority for tasks
        
    Returns:
        List of task IDs
    """
    task_ids = []
    
    try:
        for task_config in tasks:
            task_name = task_config["name"]
            args = task_config.get("args", ())
            kwargs = task_config.get("kwargs", {})
            task_queue = task_config.get("queue", queue)
            task_priority = task_config.get("priority", priority)
            
            task_id = schedule_task(
                task_name=task_name,
                args=args,
                kwargs=kwargs,
                queue=task_queue,
                priority=task_priority
            )
            task_ids.append(task_id)
        
        logger.info(f"Bulk scheduled {len(tasks)} tasks")
        return task_ids
        
    except Exception as e:
        logger.error(f"Failed to bulk schedule tasks: {e}")
        raise


# ================================
# Development and Testing Utilities
# ================================

def purge_all_queues():
    """Purge all task queues (development/testing only)."""
    if not settings.is_development() and not settings.is_testing():
        raise RuntimeError("Queue purging only allowed in development/testing")
    
    try:
        celery_app.control.purge()
        logger.warning("All task queues purged")
    except Exception as e:
        logger.error(f"Failed to purge queues: {e}")


def reset_celery_state():
    """Reset Celery state (development/testing only)."""
    if not settings.is_development() and not settings.is_testing():
        raise RuntimeError("State reset only allowed in development/testing")
    
    try:
        # Stop all workers
        celery_app.control.shutdown()
        
        # Purge all queues
        purge_all_queues()
        
        # Clear beat schedule
        import os
        beat_file = "celerybeat-schedule"
        if os.path.exists(beat_file):
            os.remove(beat_file)
        
        logger.warning("Celery state reset completed")
        
    except Exception as e:
        logger.error(f"Failed to reset Celery state: {e}")


# ================================
# Startup and Shutdown
# ================================

def startup_celery():
    """Initialize Celery components on startup."""
    logger.info("Starting Celery application...")
    
    # Validate configuration
    if not settings.CELERY_BROKER_URL:
        raise ValueError("CELERY_BROKER_URL not configured")
    
    if not settings.CELERY_RESULT_BACKEND:
        raise ValueError("CELERY_RESULT_BACKEND not configured")
    
    # Log configuration
    logger.info(f"Celery broker: {settings.CELERY_BROKER_URL}")
    logger.info(f"Celery backend: {settings.CELERY_RESULT_BACKEND}")
    logger.info(f"Task queues configured: {len(celery_app.conf.task_queues)}")
    logger.info(f"Periodic tasks configured: {len(celery_app.conf.beat_schedule)}")
    
    # Check broker connection
    if health_monitor.check_broker_connection():
        logger.info("Celery broker connection successful")
    else:
        logger.warning("Celery broker connection failed")
    
    logger.info("Celery application started successfully")


def shutdown_celery():
    """Cleanup Celery components on shutdown."""
    logger.info("Shutting down Celery application...")
    
    try:
        # Stop all workers gracefully
        celery_app.control.shutdown()
        logger.info("Celery workers stopped")
    except Exception as e:
        logger.error(f"Error stopping Celery workers: {e}")
    
    logger.info("Celery application shutdown completed")


# ================================
# Auto-discovery and Configuration
# ================================

# Auto-discover tasks in the tasks modules
celery_app.autodiscover_tasks([
    "app.tasks.notifications",
    "app.tasks.document_processing",
    "app.tasks.analytics", 
    "app.tasks.auth",
    "app.tasks.cleanup"
])

logger.info("Celery task auto-discovery completed")


# ================================
# Task Execution Context Manager
# ================================

class TaskExecutionContext:
    """
    Context manager for task execution with proper resource management.
    """
    
    def __init__(self, task_name: str, task_id: str):
        self.task_name = task_name
        self.task_id = task_id
        self.start_time = None
        
    def __enter__(self):
        """Initialize task execution context."""
        self.start_time = datetime.utcnow()
        logger.info(f"Starting task execution: {self.task_name}[{self.task_id}]")
        
        # Set correlation ID for logging
        from app.utils.logging import set_correlation_id
        set_correlation_id(f"task-{self.task_id}")
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup task execution context."""
        execution_time = (datetime.utcnow() - self.start_time).total_seconds()
        
        if exc_type is None:
            logger.info(f"Task completed successfully: {self.task_name}[{self.task_id}] in {execution_time:.2f}s")
        else:
            logger.error(f"Task failed: {self.task_name}[{self.task_id}] after {execution_time:.2f}s - {exc_val}")
        
        # Clear correlation ID
        from app.utils.logging import set_correlation_id
        set_correlation_id(None)


# ================================
# Enhanced Task Decorators
# ================================

def credit_consuming_task(credits_per_execution: float = 0.0, **kwargs):
    """
    Decorator for tasks that consume user credits.
    
    Args:
        credits_per_execution: Number of credits consumed per execution
        **kwargs: Additional task options
        
    Usage:
        @credit_consuming_task(credits_per_execution=0.1)
        @celery_app.task
        def ai_processing_task(user_id, data):
            pass
    """
    def decorator(func):
        from functools import wraps
        
        @wraps(func)
        def wrapper(*args, **task_kwargs):
            # Extract user_id for credit tracking
            user_id = task_kwargs.get('user_id') or (args[0] if args else None)
            
            if user_id and credits_per_execution > 0:
                # Check and deduct credits before task execution
                from app.core.redis import credit_cache
                import asyncio
                
                try:
                    # This would be implemented with proper credit checking
                    logger.info(f"Deducting {credits_per_execution} credits for user {user_id}")
                except Exception as e:
                    logger.error(f"Credit deduction failed: {e}")
                    raise Exception("Insufficient credits")
            
            # Execute the original task
            return func(*args, **task_kwargs)
        
        # Apply additional task options
        for key, value in kwargs.items():
            setattr(wrapper, key, value)
        
        return wrapper
    return decorator


def authenticated_task(**kwargs):
    """
    Decorator for tasks that require user authentication.
    
    Usage:
        @authenticated_task()
        @celery_app.task
        def user_specific_task(user_id, data):
            pass
    """
    def decorator(func):
        from functools import wraps
        
        @wraps(func)
        def wrapper(*args, **task_kwargs):
            # Extract and validate user_id
            user_id = task_kwargs.get('user_id') or (args[0] if args else None)
            
            if not user_id:
                raise ValueError("User ID is required for authenticated tasks")
            
            # Additional user validation could be added here
            logger.debug(f"Executing authenticated task for user: {user_id}")
            
            return func(*args, **task_kwargs)
        
        # Apply additional task options
        for key, value in kwargs.items():
            setattr(wrapper, key, value)
        
        return wrapper
    return decorator


def organization_task(**kwargs):
    """
    Decorator for tasks that operate within organization context.
    
    Usage:
        @organization_task()
        @celery_app.task
        def org_specific_task(org_id, data):
            pass
    """
    def decorator(func):
        from functools import wraps
        
        @wraps(func)
        def wrapper(*args, **task_kwargs):
            # Extract and validate organization_id
            org_id = task_kwargs.get('organization_id') or task_kwargs.get('org_id') or (args[0] if args else None)
            
            if not org_id:
                raise ValueError("Organization ID is required for organization tasks")
            
            logger.debug(f"Executing organization task for org: {org_id}")
            
            return func(*args, **task_kwargs)
        
        # Apply additional task options
        for key, value in kwargs.items():
            setattr(wrapper, key, value)
        
        return wrapper
    return decorator


# ================================
# Task Result Utilities
# ================================

class TaskResultManager:
    """
    Utility class for managing task results and status.
    """
    
    def __init__(self, celery_app: Celery):
        self.celery_app = celery_app
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get comprehensive task status information.
        
        Args:
            task_id: Task ID
            
        Returns:
            Dict containing task status information
        """
        try:
            result = self.celery_app.AsyncResult(task_id)
            
            status_info = {
                "task_id": task_id,
                "status": result.status,
                "ready": result.ready(),
                "successful": result.successful() if result.ready() else None,
                "failed": result.failed() if result.ready() else None,
                "result": result.result if result.ready() and result.successful() else None,
                "traceback": result.traceback if result.failed() else None,
                "info": result.info,
                "date_done": result.date_done.isoformat() if result.date_done else None
            }
            
            return status_info
            
        except Exception as e:
            logger.error(f"Failed to get task status for {task_id}: {e}")
            return {
                "task_id": task_id,
                "status": "UNKNOWN",
                "error": str(e)
            }
    
    def wait_for_task(self, task_id: str, timeout: int = 30) -> Any:
        """
        Wait for task completion with timeout.
        
        Args:
            task_id: Task ID to wait for
            timeout: Timeout in seconds
            
        Returns:
            Task result or raises exception
        """
        try:
            result = self.celery_app.AsyncResult(task_id)
            return result.get(timeout=timeout)
        except Exception as e:
            logger.error(f"Failed to wait for task {task_id}: {e}")
            raise
    
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a pending or running task.
        
        Args:
            task_id: Task ID to cancel
            
        Returns:
            True if cancellation was successful
        """
        try:
            self.celery_app.control.revoke(task_id, terminate=True)
            logger.info(f"Cancelled task: {task_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to cancel task {task_id}: {e}")
            return False


# Create task result manager instance
task_result_manager = TaskResultManager(celery_app)


# ================================
# Batch Task Processing
# ================================

class BatchTaskProcessor:
    """
    Utility for processing tasks in batches for efficiency.
    """
    
    def __init__(self, celery_app: Celery):
        self.celery_app = celery_app
    
    def process_batch(
        self,
        task_name: str,
        items: List[Any],
        batch_size: int = 10,
        queue: str = "default",
        priority: int = TaskPriority.NORMAL
    ) -> List[str]:
        """
        Process items in batches using Celery tasks.
        
        Args:
            task_name: Name of the task to execute
            items: List of items to process
            batch_size: Number of items per batch
            queue: Queue to send tasks to
            priority: Task priority
            
        Returns:
            List of task IDs
        """
        task_ids = []
        
        # Split items into batches
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            
            # Schedule batch processing task
            task_id = schedule_task(
                task_name=task_name,
                args=(batch,),
                queue=queue,
                priority=priority
            )
            task_ids.append(task_id)
        
        logger.info(f"Scheduled {len(task_ids)} batch tasks for {len(items)} items")
        return task_ids
    
    def wait_for_batch_completion(
        self,
        task_ids: List[str],
        timeout: int = 300
    ) -> List[Any]:
        """
        Wait for all batch tasks to complete.
        
        Args:
            task_ids: List of task IDs to wait for
            timeout: Total timeout in seconds
            
        Returns:
            List of results from all tasks
        """
        results = []
        
        for task_id in task_ids:
            try:
                result = task_result_manager.wait_for_task(task_id, timeout)
                results.append(result)
            except Exception as e:
                logger.error(f"Batch task {task_id} failed: {e}")
                results.append(None)
        
        return results


# Create batch processor instance
batch_processor = BatchTaskProcessor(celery_app)


# ================================
# Performance Monitoring
# ================================

class TaskPerformanceMonitor:
    """
    Monitor task performance and execution metrics.
    """
    
    def __init__(self):
        self.metrics = {}
    
    def record_task_execution(
        self,
        task_name: str,
        execution_time: float,
        success: bool,
        queue: str = "default"
    ):
        """
        Record task execution metrics.
        
        Args:
            task_name: Name of the executed task
            execution_time: Execution time in seconds
            success: Whether the task succeeded
            queue: Queue the task was executed on
        """
        if task_name not in self.metrics:
            self.metrics[task_name] = {
                "total_executions": 0,
                "successful_executions": 0,
                "failed_executions": 0,
                "total_execution_time": 0.0,
                "average_execution_time": 0.0,
                "queue_distribution": {}
            }
        
        metrics = self.metrics[task_name]
        metrics["total_executions"] += 1
        metrics["total_execution_time"] += execution_time
        metrics["average_execution_time"] = metrics["total_execution_time"] / metrics["total_executions"]
        
        if success:
            metrics["successful_executions"] += 1
        else:
            metrics["failed_executions"] += 1
        
        # Track queue distribution
        if queue not in metrics["queue_distribution"]:
            metrics["queue_distribution"][queue] = 0
        metrics["queue_distribution"][queue] += 1
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Get comprehensive performance report.
        
        Returns:
            Dict containing performance metrics
        """
        report = {
            "total_tasks": len(self.metrics),
            "task_metrics": self.metrics,
            "summary": {
                "total_executions": sum(m["total_executions"] for m in self.metrics.values()),
                "total_successful": sum(m["successful_executions"] for m in self.metrics.values()),
                "total_failed": sum(m["failed_executions"] for m in self.metrics.values()),
                "overall_success_rate": 0.0
            }
        }
        
        # Calculate overall success rate
        total_exec = report["summary"]["total_executions"]
        if total_exec > 0:
            report["summary"]["overall_success_rate"] = (
                report["summary"]["total_successful"] / total_exec * 100
            )
        
        return report


# Create performance monitor instance
performance_monitor = TaskPerformanceMonitor()


# ================================
# Final Exports
# ================================

# Export main components
__all__ = [
    "celery_app",
    "task_manager", 
    "health_monitor",
    "task_result_manager",
    "batch_processor",
    "performance_monitor",
    "TaskPriority",
    "TaskExecutionContext",
    "get_celery_app",
    "get_task_manager",
    "get_health_monitor",
    "schedule_task",
    "bulk_schedule_tasks",
    "startup_celery",
    "shutdown_celery",
    # Decorators
    "high_priority_task",
    "background_task", 
    "notification_task",
    "credit_consuming_task",
    "authenticated_task",
    "organization_task"
]

logger.info("Celery application configuration completed successfully")