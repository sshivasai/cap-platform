import os
from celery import Celery

# Create Celery instance
celery = Celery(
    "cap_platform",
    broker=os.getenv("RABBITMQ_URL", "redis://redis:6379/0"),
    backend=os.getenv("REDIS_URL", "redis://redis:6379/0"),
    include=["app.tasks.example_tasks"]
)

# Configure Celery
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "app.tasks.example_tasks.*": {"queue": "default"},
    },
    # Beat schedule file location
    beat_schedule_filename="beat/celerybeat-schedule.db",
    beat_scheduler="celery.beat:PersistentScheduler",
)

# Auto-discover tasks
celery.autodiscover_tasks()

# Optional: Add some periodic tasks for testing
from celery.schedules import crontab

celery.conf.beat_schedule = {
    'test-every-minute': {
        'task': 'app.tasks.example_tasks.add_numbers',
        'schedule': crontab(minute='*'),  # Every minute
        'args': (10, 20)
    },
}

if __name__ == "__main__":
    celery.start()
