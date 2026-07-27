FROM python:3.11-slim

WORKDIR /app

COPY junction_nodes/stream_processor/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app

CMD ["python", "-m", "junction_nodes.stream_processor.main", "--config", "junction_nodes/stream_processor/config.yaml"]
