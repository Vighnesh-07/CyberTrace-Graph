import os
import logging
from confluent_kafka.admin import AdminClient, NewTopic

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_kafka_topics():
    """
    Creates the necessary Kafka topics for the CyberTrace-Graph.
    """
    bootstrap_servers = os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
    
    admin_client = AdminClient({
        'bootstrap.servers': bootstrap_servers
    })
    
    # Define topics based on requirements
    topic_configs = [
        {"name": "apt.events.dns", "partitions": 6, "replication": 1},
        {"name": "apt.events.network", "partitions": 6, "replication": 1},
        {"name": "apt.events.endpoint", "partitions": 6, "replication": 1},
        {"name": "apt.events.auth", "partitions": 3, "replication": 1},
        {"name": "apt.events.cloud", "partitions": 3, "replication": 1},
        {"name": "apt.alerts.raw", "partitions": 3, "replication": 1},
        {"name": "apt.alerts.correlated", "partitions": 3, "replication": 1},
        {"name": "apt.system.heartbeat", "partitions": 1, "replication": 1},
    ]
    
    new_topics = [
        NewTopic(
            topic=tc["name"],
            num_partitions=tc["partitions"],
            replication_factor=tc["replication"]
        ) for tc in topic_configs
    ]
    
    logger.info(f"Connecting to Kafka at {bootstrap_servers}")
    logger.info("Attempting to create topics...")
    
    # Call create_topics to asynchronously create topics
    futures = admin_client.create_topics(new_topics)
    
    # Wait for each operation to finish
    for topic, future in futures.items():
        try:
            future.result()  # The result itself is None
            logger.info(f"Topic created successfully: {topic}")
        except Exception as e:
            if 'TOPIC_ALREADY_EXISTS' in str(e):
                logger.info(f"Topic already exists: {topic}")
            else:
                logger.error(f"Failed to create topic {topic}: {e}")

if __name__ == "__main__":
    logger.info("Starting topic creation script")
    create_kafka_topics()
    logger.info("Topic creation script finished")
