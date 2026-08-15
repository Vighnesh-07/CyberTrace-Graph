"""
Server-Sent Events (SSE) endpoint for real-time alert streaming.
"""

import asyncio
import json
import logging
from fastapi import APIRouter, Request
from sse_starlette.sse import EventSourceResponse

logger = logging.getLogger(__name__)
router = APIRouter()


async def alert_event_generator(request: Request):
    """Generator that yields new alerts from Redis as SSE events."""
    redis = request.app.state.redis
    last_count = 0

    while True:
        if await request.is_disconnected():
            break

        try:
            current_count = await redis.get_alert_count()
            if current_count > last_count:
                # New alerts arrived
                new_alerts = await redis.get_recent_alerts(current_count - last_count)
                for alert in new_alerts:
                    yield {
                        "event": "alert",
                        "data": json.dumps(alert) if isinstance(alert, dict) else alert,
                    }
                last_count = current_count
            else:
                # Send heartbeat to keep connection alive
                yield {"event": "heartbeat", "data": ""}
        except Exception as e:
            logger.error(f"SSE stream error: {e}")
            yield {"event": "error", "data": str(e)}

        await asyncio.sleep(3)


@router.get("/alerts")
async def stream_alerts(request: Request):
    """Stream real-time alerts via Server-Sent Events."""
    return EventSourceResponse(alert_event_generator(request))
