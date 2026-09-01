from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
import json
import logging
from datetime import datetime
from junction_nodes.common.kafka_producer import KafkaEventProducer
from junction_nodes.common.config import KafkaConfig
from junction_nodes.ingestion_gateway.parsers.sysmon import parse_sysmon_event

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="CyberTrace-Graph Ingestion Gateway")
security = HTTPBearer()
API_KEY = os.getenv("INGESTION_API_KEY", "super_secret_ingest_key")

kafka_producer = KafkaEventProducer(KafkaConfig())

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return credentials.credentials

@app.post("/api/v1/ingest/sysmon", dependencies=[Depends(verify_api_key)])
async def ingest_sysmon(request: Request):
    try:
        data = await request.json()
        if isinstance(data, dict):
            events = [data]
        else:
            events = data
            
        success_count = 0
        for event in events:
            parsed_event, topic_suffix = parse_sysmon_event(event)
            if parsed_event:
                topic = f"apt.events.{topic_suffix}"
                # In a real app we'd batch this async
                kafka_producer.produce_event(topic, parsed_event)
                success_count += 1
                
        return {"status": "success", "ingested": success_count}
    except Exception as e:
        logger.error(f"Ingestion error: {e}")
        raise HTTPException(status_code=400, detail="Invalid payload")

@app.post("/api/v1/ingest/generic", dependencies=[Depends(verify_api_key)])
async def ingest_generic(request: Request):
    """Fallback for generic JSON arrays that are already in our internal schema"""
    try:
        events = await request.json()
        if isinstance(events, dict):
            events = [events]
            
        success_count = 0
        for event in events:
            if "event_type" in event:
                # determine topic routing based on event_type prefix
                event_type = event["event_type"]
                topic_suffix = "endpoint"
                if "NETWORK" in event_type or "DNS" in event_type:
                    topic_suffix = "network"
                elif "AUTH" in event_type:
                    topic_suffix = "auth"
                
                topic = f"apt.events.{topic_suffix}"
                kafka_producer.produce_event(topic, event)
                success_count += 1
                
        return {"status": "success", "ingested": success_count}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid payload")
