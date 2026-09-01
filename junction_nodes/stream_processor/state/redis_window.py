import redis
from typing import List, Tuple
import time

class RedisSlidingWindow:
    """
    A sliding window state tracker backed by Redis Sorted Sets (ZSET).
    This ensures that state (e.g. tracking beaconing intervals, port scan rates)
    persists across restarts of the stream processor and is horizontally scalable.
    """
    def __init__(self, redis_url: str = "redis://localhost:6379/0", namespace: str = "window"):
        self.client = redis.from_url(redis_url, decode_responses=True)
        self.namespace = namespace

    def add_event(self, key: str, event_id: str, timestamp: float, ttl_seconds: int = 600):
        """
        Adds an event to the sliding window for the given key.
        Uses the timestamp as the score.
        Sets a TTL on the key so it cleans itself up if there's no activity.
        """
        full_key = f"{self.namespace}:{key}"
        # ZADD: add event_id with score=timestamp
        self.client.zadd(full_key, {event_id: timestamp})
        # Extend TTL
        self.client.expire(full_key, ttl_seconds)

    def count_events(self, key: str, window_seconds: float) -> int:
        """
        Counts the number of events for the given key within the last `window_seconds`.
        Also lazily prunes expired events from the set.
        """
        full_key = f"{self.namespace}:{key}"
        now = time.time()
        min_score = now - window_seconds

        # Prune older events
        self.client.zremrangebyscore(full_key, "-inf", min_score)
        
        # Count remaining
        return self.client.zcard(full_key)

    def get_events(self, key: str, window_seconds: float) -> List[Tuple[str, float]]:
        """
        Returns all events (event_id, timestamp) in the window.
        """
        full_key = f"{self.namespace}:{key}"
        now = time.time()
        min_score = now - window_seconds
        
        # Prune older events
        self.client.zremrangebyscore(full_key, "-inf", min_score)
        
        # Return remaining events with their scores
        results = self.client.zrangebyscore(full_key, min_score, "+inf", withscores=True)
        return results

    def clear(self, key: str):
        full_key = f"{self.namespace}:{key}"
        self.client.delete(full_key)
