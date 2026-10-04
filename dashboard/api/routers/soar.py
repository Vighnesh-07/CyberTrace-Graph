"""
SOAR (Security Orchestration, Automation & Response) Router.

Provides endpoints for executing automated response actions
(Block IP, Isolate Host, Kill Process) and querying audit logs.

All actions are:
1. Logged to an immutable audit trail in Neo4j
2. Reflected in the attack graph (ResponseAction nodes)
3. Simulated via webhook stubs (ready for real EDR/Firewall integration)
"""

import logging
import uuid
import asyncio
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, Depends, Query
from pydantic import BaseModel

from dashboard.api.core.security import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Request Models ──────────────────────────────────────────────────

class BlockIPRequest(BaseModel):
    ip: str
    alert_id: Optional[str] = None
    reason: str = ""

class IsolateHostRequest(BaseModel):
    hostname: str
    alert_id: Optional[str] = None
    reason: str = ""

class KillProcessRequest(BaseModel):
    hostname: str
    process_name: str
    alert_id: Optional[str] = None
    reason: str = ""


# ── Webhook Simulators (Replace with real integrations) ─────────────

async def _simulate_firewall_block(ip: str) -> dict:
    """Simulates calling an external firewall API (e.g., Palo Alto, AWS WAF, Cloudflare)."""
    await asyncio.sleep(0.8)  # Simulate network latency
    return {
        "integration": "PaloAlto-Firewall-Sim",
        "rule_id": f"BLOCK-{uuid.uuid4().hex[:8].upper()}",
        "status": "APPLIED",
        "message": f"Inbound/outbound traffic for {ip} blocked on all zones.",
    }

async def _simulate_edr_isolate(hostname: str) -> dict:
    """Simulates calling an EDR API (e.g., CrowdStrike, Microsoft Defender)."""
    await asyncio.sleep(1.0)
    return {
        "integration": "CrowdStrike-EDR-Sim",
        "containment_id": f"CS-{uuid.uuid4().hex[:8].upper()}",
        "status": "ISOLATED",
        "message": f"Host {hostname} network-isolated. Only CrowdStrike cloud connection retained.",
    }

async def _simulate_edr_kill_process(hostname: str, process_name: str) -> dict:
    """Simulates calling an EDR API to terminate a process."""
    await asyncio.sleep(0.6)
    return {
        "integration": "CrowdStrike-EDR-Sim",
        "kill_id": f"KILL-{uuid.uuid4().hex[:8].upper()}",
        "status": "TERMINATED",
        "message": f"Process '{process_name}' on {hostname} terminated successfully.",
    }


# ── Audit Trail Helper ─────────────────────────────────────────────

def _write_audit_log(neo4j, action_type: str, target: str, user: str,
                     alert_id: str = None, reason: str = "",
                     details: str = "", webhook_response: dict = None):
    """Write an immutable audit log entry and ResponseAction node to Neo4j."""
    action_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Create ResponseAction node
    neo4j._run_query(
        "CREATE (ra:ResponseAction {"
        "  action_id: $action_id,"
        "  action_type: $action_type,"
        "  target: $target,"
        "  status: 'COMPLETED',"
        "  executed_by: $user,"
        "  executed_at: datetime($ts),"
        "  reason: $reason,"
        "  details: $details,"
        "  webhook_integration: $webhook_integration,"
        "  webhook_status: $webhook_status"
        "})",
        {
            "action_id": action_id,
            "action_type": action_type,
            "target": target,
            "user": user,
            "ts": timestamp,
            "reason": reason,
            "details": details,
            "webhook_integration": (webhook_response or {}).get("integration", ""),
            "webhook_status": (webhook_response or {}).get("status", ""),
        },
    )

    # Link to Alert if provided
    if alert_id:
        neo4j._run_query(
            "MATCH (ra:ResponseAction {action_id: $action_id}), (a:Alert {alert_id: $alert_id}) "
            "MERGE (a)-[:RESPONDED_WITH]->(ra)",
            {"action_id": action_id, "alert_id": alert_id},
        )

    # Link to target entity (IP or Host)
    if action_type == "BLOCK_IP":
        neo4j._run_query(
            "MATCH (ra:ResponseAction {action_id: $action_id}), (ip:IPAddress {ip: $target}) "
            "MERGE (ra)-[:BLOCKED]->(ip)",
            {"action_id": action_id, "target": target},
        )
    elif action_type in ("ISOLATE_HOST", "KILL_PROCESS"):
        neo4j._run_query(
            "MATCH (ra:ResponseAction {action_id: $action_id}), (h:Host {hostname: $target}) "
            "MERGE (ra)-[:ACTED_ON]->(h)",
            {"action_id": action_id, "target": target},
        )

    # Create immutable AuditLog node
    neo4j._run_query(
        "CREATE (al:AuditLog {"
        "  log_id: $log_id,"
        "  timestamp: datetime($ts),"
        "  user: $user,"
        "  action: $action_type,"
        "  target: $target,"
        "  alert_id: $alert_id,"
        "  reason: $reason,"
        "  details: $details"
        "})",
        {
            "log_id": str(uuid.uuid4()),
            "ts": timestamp,
            "user": user,
            "action_type": action_type,
            "target": target,
            "alert_id": alert_id or "",
            "reason": reason,
            "details": details,
        },
    )

    return action_id


# ── SOAR Action Endpoints ───────────────────────────────────────────

@router.post("/block-ip")
async def block_ip(request: Request, body: BlockIPRequest,
                   current_user: str = Depends(get_current_user)):
    """Block an IP address via firewall integration."""
    neo4j = request.app.state.neo4j

    logger.info(f"🛡️ SOAR: User '{current_user}' blocking IP {body.ip}")

    # Execute the simulated firewall webhook
    webhook_result = await _simulate_firewall_block(body.ip)

    # Write audit trail and graph nodes
    action_id = _write_audit_log(
        neo4j,
        action_type="BLOCK_IP",
        target=body.ip,
        user=current_user,
        alert_id=body.alert_id,
        reason=body.reason,
        details=webhook_result.get("message", ""),
        webhook_response=webhook_result,
    )

    # Update the alert status to INVESTIGATING if linked
    if body.alert_id:
        neo4j.update_alert_status(body.alert_id, "INVESTIGATING")

    return {
        "action_id": action_id,
        "action_type": "BLOCK_IP",
        "target": body.ip,
        "status": "COMPLETED",
        "webhook_result": webhook_result,
        "executed_by": current_user,
    }


@router.post("/isolate-host")
async def isolate_host(request: Request, body: IsolateHostRequest,
                       current_user: str = Depends(get_current_user)):
    """Isolate a compromised host via EDR integration."""
    neo4j = request.app.state.neo4j

    logger.info(f"🔒 SOAR: User '{current_user}' isolating host {body.hostname}")

    webhook_result = await _simulate_edr_isolate(body.hostname)

    action_id = _write_audit_log(
        neo4j,
        action_type="ISOLATE_HOST",
        target=body.hostname,
        user=current_user,
        alert_id=body.alert_id,
        reason=body.reason,
        details=webhook_result.get("message", ""),
        webhook_response=webhook_result,
    )

    if body.alert_id:
        neo4j.update_alert_status(body.alert_id, "INVESTIGATING")

    return {
        "action_id": action_id,
        "action_type": "ISOLATE_HOST",
        "target": body.hostname,
        "status": "COMPLETED",
        "webhook_result": webhook_result,
        "executed_by": current_user,
    }


@router.post("/kill-process")
async def kill_process(request: Request, body: KillProcessRequest,
                       current_user: str = Depends(get_current_user)):
    """Terminate a malicious process via EDR integration."""
    neo4j = request.app.state.neo4j

    logger.info(f"⚡ SOAR: User '{current_user}' killing process {body.process_name} on {body.hostname}")

    webhook_result = await _simulate_edr_kill_process(body.hostname, body.process_name)

    action_id = _write_audit_log(
        neo4j,
        action_type="KILL_PROCESS",
        target=body.hostname,
        user=current_user,
        alert_id=body.alert_id,
        reason=body.reason,
        details=f"Killed process: {body.process_name}. {webhook_result.get('message', '')}",
        webhook_response=webhook_result,
    )

    if body.alert_id:
        neo4j.update_alert_status(body.alert_id, "INVESTIGATING")

    return {
        "action_id": action_id,
        "action_type": "KILL_PROCESS",
        "target": f"{body.hostname}:{body.process_name}",
        "status": "COMPLETED",
        "webhook_result": webhook_result,
        "executed_by": current_user,
    }


# ── Query Endpoints ─────────────────────────────────────────────────

@router.get("/actions")
async def get_soar_actions(request: Request, alert_id: Optional[str] = Query(None),
                           limit: int = Query(50, ge=1, le=200),
                           current_user: str = Depends(get_current_user)):
    """Get SOAR response actions, optionally filtered by alert_id."""
    neo4j = request.app.state.neo4j

    if alert_id:
        results = neo4j._run_query(
            "MATCH (a:Alert {alert_id: $alert_id})-[:RESPONDED_WITH]->(ra:ResponseAction) "
            "RETURN ra ORDER BY ra.executed_at DESC LIMIT $limit",
            {"alert_id": alert_id, "limit": limit},
        )
    else:
        results = neo4j._run_query(
            "MATCH (ra:ResponseAction) "
            "RETURN ra ORDER BY ra.executed_at DESC LIMIT $limit",
            {"limit": limit},
        )

    actions = [dict(r["ra"]) for r in results]
    return {"actions": actions, "total": len(actions)}


@router.get("/audit-log")
async def get_audit_log(request: Request,
                        limit: int = Query(50, ge=1, le=500),
                        user_filter: Optional[str] = Query(None),
                        action_filter: Optional[str] = Query(None),
                        current_user: str = Depends(get_current_user)):
    """Get the immutable audit trail of all SOAR actions."""
    neo4j = request.app.state.neo4j

    conditions = []
    params = {"limit": limit}

    if user_filter:
        conditions.append("al.user = $user_filter")
        params["user_filter"] = user_filter
    if action_filter:
        conditions.append("al.action = $action_filter")
        params["action_filter"] = action_filter

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    results = neo4j._run_query(
        f"MATCH (al:AuditLog) {where_clause} "
        "RETURN al ORDER BY al.timestamp DESC LIMIT $limit",
        params,
    )

    entries = [dict(r["al"]) for r in results]
    return {"entries": entries, "total": len(entries)}
