"""
Graph endpoints for the CyberTrace-Graph Dashboard.

Provides graph topology data, statistics, detections,
and timeline views from the Neo4j attack graph.
"""

import logging
from fastapi import APIRouter, Request, Query

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/stats")
async def get_graph_stats(request: Request):
    """Get node and relationship count statistics."""
    neo4j = request.app.state.neo4j
    stats = neo4j.get_stats()
    return stats


@router.get("/topology")
async def get_topology(request: Request, limit: int = Query(200, ge=10, le=500)):
    """Get the graph topology as nodes and edges for visualization."""
    neo4j = request.app.state.neo4j
    topology = neo4j.get_topology(limit=limit)
    return topology


@router.get("/detections")
async def run_detections(request: Request):
    """Run all graph-based detection queries."""
    neo4j = request.app.state.neo4j
    results = neo4j.run_detections()
    return results


@router.get("/timeline/{ip}")
async def get_timeline(request: Request, ip: str):
    """Get the attack timeline for a specific IP address."""
    neo4j = request.app.state.neo4j
    timeline = neo4j.get_timeline(ip)
    return {"ip": ip, "events": timeline, "total": len(timeline)}

@router.get("/analytics/severity-distribution")
async def get_severity_distribution(request: Request):
    neo4j = request.app.state.neo4j
    return neo4j.get_severity_distribution()

@router.get("/analytics/alert-timeline")
async def get_alert_timeline(request: Request):
    neo4j = request.app.state.neo4j
    return neo4j.get_alert_timeline()

@router.get("/analytics/top-techniques")
async def get_top_mitre_techniques(request: Request):
    neo4j = request.app.state.neo4j
    return neo4j.get_top_mitre_techniques()
