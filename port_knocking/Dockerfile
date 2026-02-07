FROM python:3.11-slim

WORKDIR /app

RUN apt-get update -o Acquire::ForceIPv4=true \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iptables iproute2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY knock_server.py knock_client.py ./

CMD ["python3", "knock_server.py"]

