# SSH Honeypot Implementation

## Overview

This honeypot simulates a realistic SSH service using **Paramiko** and logs unauthorized access attempts for detection and analysis. It runs inside a Docker container and exposes an SSH-like interface that appears legitimate to attackers, while never granting real access.

The honeypot captures authentication attempts, connection metadata, and suspicious behavior, providing visibility into attack patterns such as brute-force login attempts.

---

## Features (Assignment Requirements)

The honeypot logs:

- Timestamp (UTC)
- Source IP address and port
- Connection duration
- Username/password authentication attempts
- Basic interaction data (best effort)
- Suspicious activity alerts (bonus feature)

All logs are written in structured JSON format.

---

## How It Works

1. The honeypot listens on container port **22** (mapped to host port **2222**).
2. A convincing OpenSSH-style banner is presented.
3. All authentication attempts are rejected — credentials are logged.
4. Repeated failures trigger a brute-force alert.
5. No real shell access is ever granted.

---

## Bonus Feature — Brute-force Detection

The logger monitors failed authentication attempts.

If **5 or more failures occur within 60 seconds** from the same IP:

```
event = alert
type = bruteforce_suspected
```

This demonstrates active attack detection capability.

---

## Architecture

```
Attacker → SSH Client → Honeypot Container → Logger → JSON Logs
```

```
Host: localhost:2222
   ↓
Docker honeypot: port 22
   ↓
Paramiko SSH simulation
   ↓
Structured logging + alert detection
```

---

## Files

- `honeypot.py` — SSH honeypot server implementation
- `logger.py` — JSON logging + alert detection
- `analysis.md` — Attack testing analysis
- `Dockerfile` — Container configuration
- `logs/` — Log directory (kept empty in submission)

---

## Running the Honeypot

Start container:

```bash
docker compose up -d honeypot
```

Simulate attacker login:

```bash
ssh admin@127.0.0.1 -p 2222
```

View logs:

```bash
docker exec -it 2_network_honeypot sh -lc "tail -n 50 logs/honeypot.log"
```

Check alerts:

```bash
docker exec -it 2_network_honeypot sh -lc "grep -i alert logs/honeypot.log || true"
```

---

## Security Value

This honeypot provides:

- Visibility into unauthorized login attempts
- Evidence of brute-force behavior
- Attack telemetry useful for detection engineering
- Deception layer that wastes attacker time

---

## Limitations

- Not a full SSH environment
- Command capture is best-effort only
- No encryption of logs
- Intended for lab/testing use

Real deployments should isolate honeypots and forward logs to SIEM systems.

---

## Conclusion

The honeypot successfully simulates a believable SSH service, logs attacker behavior, and detects brute-force activity — fulfilling assignment requirements and demonstrating practical defensive security monitoring.
