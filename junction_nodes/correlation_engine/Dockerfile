FROM python:3.11-slim

WORKDIR /app

COPY junction_nodes/correlation_engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-m", "junction_nodes.correlation_engine.main"]
