from app.celery_app import celery
import time

@celery.task
def add_numbers(x: int, y: int) -> int:
    """Example task that adds two numbers."""
    time.sleep(2)  # Simulate some work
    return x + y

@celery.task
def process_document(doc_id: str) -> dict:
    """Example document processing task."""
    time.sleep(5)  # Simulate document processing
    return {"doc_id": doc_id, "status": "processed", "timestamp": time.time()}
