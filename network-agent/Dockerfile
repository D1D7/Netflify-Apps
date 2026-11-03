FROM python:3.12-slim

# ping / traceroute for the diagnostics tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping traceroute \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY netagent ./netagent
COPY inventory/devices.example.yaml ./inventory/devices.example.yaml

RUN mkdir -p logs backups exports

CMD ["python", "-m", "netagent.telegram_bot"]
