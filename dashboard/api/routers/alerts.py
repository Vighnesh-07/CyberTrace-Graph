"""
Alert endpoints for the CyberTrace-Graph Dashboard.

Provides CRUD operations for security alerts and SOAR
(Security Orchestration, Automation, Response) actions.
"""

import logging
from fastapi import APIRouter, Request, HTTPException, Query
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger(__name__)
router = APIRouter()


class StatusUpdate(BaseModel):
    status: str  # OPEN, ACKNOWLEDGED, INVESTIGATING, CLOSED


@router.get("")
async def get_alerts(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """Fetch alerts. Tries Redis cache first, falls back to Neo4j."""
    neo4j = request.app.state.neo4j
    redis = request.app.state.redis

    # Try Redis cache first
    if not severity and not status:
        cached = await redis.get_recent_alerts(limit)
        if cached:
            return {"alerts": cached, "total": len(cached), "source": "cache"}

    # Fall back to Neo4j
    alerts = neo4j.get_alerts(limit=limit, severity=severity, status=status)
    return {"alerts": alerts, "total": len(alerts), "source": "neo4j"}


@router.get("/{alert_id}")
async def get_alert(request: Request, alert_id: str):
    """Get a single alert with full details."""
    neo4j = request.app.state.neo4j
    alert = neo4j.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert


@router.post("/{alert_id}/status")
async def update_alert_status(request: Request, alert_id: str, body: StatusUpdate):
    """Update alert status (SOAR action)."""
    valid_statuses = {"OPEN", "ACKNOWLEDGED", "INVESTIGATING", "CLOSED"}
    if body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    neo4j = request.app.state.neo4j
    success = neo4j.update_alert_status(alert_id, body.status)
    if not success:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    logger.info(f"Alert {alert_id} status updated to {body.status}")
    return {"alert_id": alert_id, "status": body.status, "updated": True}
