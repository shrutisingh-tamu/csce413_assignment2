FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir paramiko

COPY honeypot.py logger.py ./
RUN mkdir -p logs

CMD ["python3", "honeypot.py"]
