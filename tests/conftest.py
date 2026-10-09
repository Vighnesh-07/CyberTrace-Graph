"""
CyberTrace-Graph Test Suite — Shared Fixtures & Configuration.

Provides reusable mock objects for Redis, Neo4j, and Kafka
to enable fast, isolated unit testing without external dependencies.
"""

import pytest
from unittest.mock import MagicMock, patch


# ── Mock Redis Sliding Window ──────────────────────────────────────

class MockSlidingWindow:
    """In-memory replacement for RedisSlidingWindow for unit testing."""

    def __init__(self, **kwargs):
        self._data = {}  # key -> set of (member, timestamp)

    def add(self, name: str, member: str, timestamp: float):
        if name not in self._data:
            self._data[name] = set()
        self._data[name].add((member, timestamp))

    def count(self, name: str, now: float) -> int:
        if name not in self._data:
            return 0
        return len(self._data[name])

    def clear(self, name: str):
        self._data.pop(name, None)


class MockRedisClient:
    """In-memory replacement for redis.Redis for unit testing."""

    def __init__(self):
        self._store = {}

    def get(self, key):
        return self._store.get(key)

    def setex(self, key, ttl, value):
        self._store[key] = value

    def delete(self, key):
        self._store.pop(key, None)

    def zadd(self, key, mapping):
        pass

    def zremrangebyscore(self, key, min_val, max_val):
        pass

    def zcard(self, key):
        return 0

    def expire(self, key, seconds):
        pass


@pytest.fixture
def mock_sliding_window():
    """Returns a fresh MockSlidingWindow instance."""
    return MockSlidingWindow()


@pytest.fixture
def mock_redis_client():
    """Returns a fresh MockRedisClient instance."""
    return MockRedisClient()


@pytest.fixture
def mock_neo4j():
    """Returns a MagicMock Neo4j client."""
    client = MagicMock()
    client._run_query.return_value = []
    client.update_alert_status.return_value = None
    client.get_alerts.return_value = []
    return client
