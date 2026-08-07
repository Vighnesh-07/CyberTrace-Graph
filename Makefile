.PHONY: help up down down-clean logs logs-kafka create-topics run-dns-sensor run-processor run-ingestor run-simulator run-detections test lint clean status

help:
	@echo "CyberTrace-Graph Makefile"
	@echo ""
	@echo "Infrastructure:"
	@echo "  up               - Start docker compose infrastructure"
	@echo "  down             - Stop docker compose infrastructure"
	@echo "  down-clean       - Stop infrastructure and remove volumes"
	@echo "  logs             - Follow all service logs"
	@echo "  logs-kafka       - Follow Kafka logs"
	@echo "  status           - Show service status"
	@echo "  create-topics    - Create Kafka topics"
	@echo ""
	@echo "Services:"
	@echo "  run-dns-sensor   - Run the DNS sensor junction node"
	@echo "  run-processor    - Run the stream processor pipeline"
	@echo "  run-ingestor     - Run the graph correlation ingestor"
	@echo "  run-simulator    - Run the APT attack simulator"
	@echo "  run-detections   - Run graph detection queries once"
	@echo ""
	@echo "Development:"
	@echo "  test             - Run pytest suite"
	@echo "  lint             - Run flake8 and mypy"
	@echo "  clean            - Remove cache directories"

up:
	docker compose up -d

down:
	docker compose down

down-clean:
	docker compose down -v

logs:
	docker compose logs -f

logs-kafka:
	docker compose logs -f kafka

create-topics:
	python scripts/create_topics.py

run-dns-sensor:
	python -m junction_nodes.dns_sensor.main

run-processor:
	python -m junction_nodes.stream_processor.main

run-ingestor:
	python -m junction_nodes.correlation_engine.main

run-simulator:
	cd attack_simulator && python simulate_apt.py

run-detections:
	python -c "from junction_nodes.common.config import Neo4jConfig; from junction_nodes.correlation_engine.graph_service import GraphService; from junction_nodes.correlation_engine.detectors import GraphDetector; import json; gs = GraphService(Neo4jConfig()); gd = GraphDetector(gs); print(json.dumps(gd.run_all_detections(), indent=2, default=str)); print(json.dumps(gs.get_stats(), indent=2, default=str)); gs.close()"

test:
	pytest tests/ -v

lint:
	flake8 .
	mypy .

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

status:
	docker compose ps
