.PHONY: help up down down-clean logs logs-kafka create-topics run-dns-sensor run-simulator test lint clean status

# Default target
help:
	@echo "CyberTrace-Graph Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  up               - Start docker compose infrastructure in detached mode"
	@echo "  down             - Stop docker compose infrastructure"
	@echo "  down-clean       - Stop docker compose infrastructure and remove volumes"
	@echo "  logs             - Follow docker compose logs"
	@echo "  logs-kafka       - Follow docker compose logs for kafka service"
	@echo "  create-topics    - Run script to create Kafka topics"
	@echo "  run-dns-sensor   - Run the DNS sensor junction node"
	@echo "  run-simulator    - Run the APT attack simulator"
	@echo "  test             - Run pytest"
	@echo "  lint             - Run flake8 and mypy"
	@echo "  clean            - Remove __pycache__ and .pytest_cache directories"
	@echo "  status           - Show docker compose status"

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
	cd junction_nodes/dns_sensor && python main.py

run-simulator:
	cd attack_simulator && python simulate_apt.py

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
