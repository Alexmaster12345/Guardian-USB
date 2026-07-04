FROM python:3.12-slim

# nmap is required for network discovery
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY guardian/ ./guardian/
COPY data/       ./data/
COPY pyproject.toml .

RUN pip install --no-cache-dir -e .

# Persistent volumes for DB and reports
VOLUME ["/app/data"]

EXPOSE 8000

ENV GUARDIAN_HOST=0.0.0.0
ENV GUARDIAN_PORT=8000

ENTRYPOINT ["guardian"]
CMD ["serve"]
