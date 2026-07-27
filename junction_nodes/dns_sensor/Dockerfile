FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    librdkafka-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
# Since this sensor relies on common/, we'll assume the context is the project root
# Or we'll copy things relative to where we run it.
COPY junction_nodes/common /app/junction_nodes/common
COPY junction_nodes/dns_sensor /app/junction_nodes/dns_sensor

ENV PYTHONPATH=/app

LABEL maintainer="CyberTrace-Graph"
LABEL component="dns-sensor"

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ps aux | grep "python main.py" | grep -v grep || exit 1

WORKDIR /app/junction_nodes/dns_sensor
CMD ["python", "main.py", "--config", "config.yaml"]
