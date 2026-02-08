# Honeypot Attack Analysis

## Test Environment

- Honeypot container: `2_network_honeypot`
- Host port: **2222**
- Container port: **22**
- SSH banner spoofed to appear as OpenSSH
- Logs stored in JSON format

---

## Attack Simulation

### Test 1 — Unauthorized Login Attempt

Command:

```bash
ssh admin@127.0.0.1 -p 2222
```

Observation:

- SSH banner displayed successfully
- Authentication rejected
- Username/password attempt logged

Captured log event:

```json
{
  "event": "auth_attempt",
  "username": "admin",
  "success": false
}
```

This confirms credential logging functionality.

---

### Test 2 — Brute-force Simulation (Bonus Feature)

Action:

Multiple rapid incorrect passwords entered.

Observation:

- Logger tracked failed attempts
- Alert triggered after threshold reached

Example alert log:

```json
{
  "event": "alert",
  "type": "bruteforce_suspected",
  "failed_attempts": 5
}
```

This confirms automated attack detection.

---

## Logged Data Categories

The honeypot captured:

- Connection start/end timestamps
- Source IP and port
- Authentication attempts
- Session duration
- Alert events

Structured logs enable easy forensic analysis.

---

## Security Insights

Observed behavior demonstrates:

- Credential stuffing attempts
- Repeated authentication failures
- Attack timing patterns

Such telemetry is valuable for intrusion detection and response.

---

## Defensive Value

The honeypot:

- Detects unauthorized access attempts
- Generates actionable alerts
- Provides attacker intelligence
- Supports incident analysis

This aligns with deception-based defensive security principles.

---

## Conclusion

Testing confirms the honeypot effectively simulates an SSH service, captures attacker activity, and detects brute-force behavior. The implementation satisfies assignment requirements and demonstrates practical defensive monitoring capabilities.
