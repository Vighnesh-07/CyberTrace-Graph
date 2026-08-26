from enum import Enum
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

class SensorType(str, Enum):
    DNS = "DNS"
    NETWORK = "NETWORK"
    ENDPOINT = "ENDPOINT"
    AUTH = "AUTH"
    CLOUD = "CLOUD"

class KafkaConfig(BaseModel):
    bootstrap_servers: str = "localhost:9092"
    client_id: str = "junction_node"
    compression_type: str = "lz4"
    batch_size: int = 16384
    linger_ms: int = 50
    acks: str = "all"

class SensorConfig(BaseModel):
    sensor_id: str
    sensor_type: SensorType
    heartbeat_interval_sec: int = 60
    log_level: str = "INFO"
    buffer_max_size: int = 10000

import os

class Neo4jConfig(BaseModel):
    uri: str = "bolt://localhost:7687"
    user: str = os.getenv("NEO4J_USER", "neo4j")
    password: str = Field(default_factory=lambda: os.getenv("NEO4J_PASSWORD", ""))

class RedisConfig(BaseModel):
    url: str = "redis://localhost:6379/0"

class AppConfig(BaseSettings):
    kafka: KafkaConfig = Field(default_factory=KafkaConfig)
    sensor: SensorConfig
    neo4j: Neo4jConfig = Field(default_factory=Neo4jConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    
    model_config = SettingsConfigDict(
        env_prefix="APT_HUNTER_",
        env_nested_delimiter="__",
        env_file=".env",
        extra="ignore"
    )

def load_config(config_path: Optional[str] = None) -> AppConfig:
    import yaml
    import os
    
    yaml_data = {}
    if config_path and os.path.exists(config_path):
        with open(config_path, "r") as f:
            yaml_data = yaml.safe_load(f) or {}
            
    return AppConfig(**yaml_data)
