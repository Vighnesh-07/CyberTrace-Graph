"""
CyberTrace-Graph — SOC Dashboard API

FastAPI backend that serves real-time security data from Neo4j,
Redis, and Kafka to the React dashboard frontend.

Endpoints:
- /api/alerts — Alert CRUD and SOAR actions
- /api/graph — Graph topology, stats, and detections
- /api/pipeline — Pipeline health and processing stats
- /api/stream — Server-Sent Events for real-time alerts
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import os
from dashboard.api.services.neo4j_client import Neo4jClient
from dashboard.api.services.redis_client import RedisClient
from dashboard.api.routers import alerts, graph, pipeline, stream, auth
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle for the API."""
    logger.info("🚀 Starting CyberTrace-Graph Dashboard API...")

    # Connect to Neo4j securely
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_pass = os.getenv("NEO4J_PASSWORD")
    
    if not neo4j_pass:
        logger.error("NEO4J_PASSWORD environment variable not set. Exiting.")
        raise RuntimeError("Missing NEO4J_PASSWORD")

    app.state.neo4j = Neo4jClient(
        uri="bolt://localhost:7687",
        user=neo4j_user,
        password=neo4j_pass,
    )
    logger.info("✅ Connected to Neo4j")

    # Connect to Redis
    app.state.redis = RedisClient(url="redis://localhost:6379/0")
    await app.state.redis.connect()
    logger.info("✅ Connected to Redis")

    yield

    # Shutdown
    logger.info("Shutting down Dashboard API...")
    app.state.neo4j.close()
    await app.state.redis.close()
    logger.info("Dashboard API stopped.")


app = FastAPI(
    title="CyberTrace-Graph Dashboard API",
    description="Real-time SOC dashboard backend for the CyberTrace-Graph SIEM pipeline",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow the React dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from dashboard.api.core.security import get_current_user
from fastapi import Depends

# Mount routers
app.include_router(auth.router)
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"], dependencies=[Depends(get_current_user)])
app.include_router(graph.router, prefix="/api/graph", tags=["Graph"], dependencies=[Depends(get_current_user)])
app.include_router(pipeline.router, prefix="/api/pipeline", tags=["Pipeline"], dependencies=[Depends(get_current_user)])
app.include_router(stream.router, prefix="/api/stream", tags=["Stream"]) # SSE stream might need token in query param instead of header


@app.get("/")
async def root():
    return {
        "service": "CyberTrace-Graph Dashboard API",
        "version": "1.0.0",
        "docs": "/docs",
    }
