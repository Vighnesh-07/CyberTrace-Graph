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


from fastapi import Query, HTTPException, status
from dashboard.api.core.security import SECRET_KEY, ALGORITHM
from jose import jwt, JWTError

@router.get("/alerts")
async def stream_alerts(request: Request, token: str = Query(None)):
    """Stream real-time alerts via Server-Sent Events."""
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        
    return EventSourceResponse(alert_event_generator(request))
