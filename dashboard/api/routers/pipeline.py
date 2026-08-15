"""
Pipeline health and statistics endpoints.
"""

import logging
from fastapi import APIRouter, Request

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/health")
async def health_check(request: Request):
    """Check connectivity to all infrastructure components."""
    neo4j = request.app.state.neo4j
    redis = request.app.state.redis

    neo4j_ok = neo4j.health_check()
    redis_ok = await redis.health_check()

    # Simple Kafka check — try to import and connect
    kafka_ok = False
    try:
        from confluent_kafka.admin import AdminClient
        admin = AdminClient({"bootstrap.servers": "localhost:9092"})
        metadata = admin.list_topics(timeout=3)
        kafka_ok = metadata is not None
    except Exception:
        kafka_ok = False

    all_ok = neo4j_ok and redis_ok and kafka_ok
    return {
        "status": "healthy" if all_ok else "degraded",
        "services": {
            "neo4j": "up" if neo4j_ok else "down",
            "redis": "up" if redis_ok else "down",
            "kafka": "up" if kafka_ok else "down",
        },
    }


@router.get("/stats")
async def get_pipeline_stats(request: Request):
    """Get pipeline processing statistics from Redis cache."""
    redis = request.app.state.redis
    stats = await redis.get_pipeline_stats()
    if stats:
        return stats
    return {
        "events_processed": 0,
        "events_enriched": 0,
        "alerts_generated": 0,
        "ml_dga_detections": 0,
        "ml_anomaly_detections": 0,
        "errors": 0,
        "source": "default",
    }
