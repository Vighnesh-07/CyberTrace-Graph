"""
Redis client for the CyberTrace-Graph Dashboard API.

Provides caching for alerts and pipeline statistics.
Also maintains a list of recent alerts for the SSE stream.
"""

import json
import logging
from typing import Optional
import redis.asyncio as aioredis

logger = logging.getLogger(__name__)


class RedisClient:
    def __init__(self, url: str = "redis://localhost:6379/0"):
        self._url = url
        self._redis: Optional[aioredis.Redis] = None

    async def connect(self):
        self._redis = aioredis.from_url(self._url, decode_responses=True)
        logger.info(f"Redis client connected to {self._url}")

    async def close(self):
        if self._redis:
            await self._redis.close()

    async def health_check(self) -> bool:
        try:
            if self._redis:
                await self._redis.ping()
                return True
            return False
        except Exception:
            return False

    # ── Pipeline Stats ─────────────────────────────────────────────

    async def set_pipeline_stats(self, stats: dict):
        if self._redis:
            await self._redis.set("pipeline:stats", json.dumps(stats), ex=30)

    async def get_pipeline_stats(self) -> Optional[dict]:
        if self._redis:
            data = await self._redis.get("pipeline:stats")
            if data:
                return json.loads(data)
        return None

    # ── Recent Alerts (for SSE) ────────────────────────────────────

    async def push_alert(self, alert: dict):
        """Push an alert to the recent alerts list (max 200)."""
        if self._redis:
            await self._redis.lpush("alerts:recent", json.dumps(alert))
            await self._redis.ltrim("alerts:recent", 0, 199)

    async def get_recent_alerts(self, count: int = 50) -> list[dict]:
        """Get the most recent alerts."""
        if self._redis:
            items = await self._redis.lrange("alerts:recent", 0, count - 1)
            return [json.loads(item) for item in items]
        return []

    async def get_alert_count(self) -> int:
        if self._redis:
            return await self._redis.llen("alerts:recent")
        return 0
