#!/usr/bin/env python3
"""
Honeypot logger + simple alerting.

Logs JSON lines to: honeypot/logs/honeypot.log
Alert (bonus): prints to stdout when an IP exceeds N failed auth attempts within a window.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from typing import Any, Dict, List


def _utc_ts() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


class HoneypotLogger:
    def __init__(
        self,
        log_dir: str = "logs",
        log_file: str = "honeypot.log",
        alert_threshold: int = 5,
        alert_window_sec: int = 60,
    ) -> None:
        self.log_dir = log_dir
        self.log_path = os.path.join(log_dir, log_file)

        # Ensure log_dir exists and is a directory (fixes your FileExistsError case)
        if os.path.exists(self.log_dir) and not os.path.isdir(self.log_dir):
            os.remove(self.log_dir)
        os.makedirs(self.log_dir, exist_ok=True)

        self.alert_threshold = int(alert_threshold)
        self.alert_window_sec = int(alert_window_sec)

        self._lock = threading.Lock()
        self._failed_by_ip: Dict[str, List[float]] = {}

    def _write_line(self, obj: Dict[str, Any]) -> None:
        obj.setdefault("ts", _utc_ts())
        line = json.dumps(obj, ensure_ascii=False)
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def log_connection_start(self, src_ip: str, src_port: int, service: str) -> None:
        self._write_line(
            {
                "event": "connection_start",
                "service": service,
                "src_ip": src_ip,
                "src_port": int(src_port),
            }
        )

    def log_connection_end(self, src_ip: str, src_port: int, duration_sec: float) -> None:
        self._write_line(
            {
                "event": "connection_end",
                "src_ip": src_ip,
                "src_port": int(src_port),
                "duration_sec": round(float(duration_sec), 3),
            }
        )

    def log_auth_attempt(
        self,
        src_ip: str,
        src_port: int,
        username: str,
        password: str,
        success: bool,
    ) -> None:
        self._write_line(
            {
                "event": "auth_attempt",
                "src_ip": src_ip,
                "src_port": int(src_port),
                "username": username,
                "password": password,
                "success": bool(success),
            }
        )

        if not success:
            now = time.time()
            with self._lock:
                bucket = self._failed_by_ip.setdefault(src_ip, [])
                bucket.append(now)
                cutoff = now - self.alert_window_sec
                # keep only recent
                self._failed_by_ip[src_ip] = [t for t in bucket if t >= cutoff]
                count = len(self._failed_by_ip[src_ip])

            if count >= self.alert_threshold:
                # Bonus feature: alert
                alert = {
                    "event": "alert",
                    "type": "bruteforce_suspected",
                    "src_ip": src_ip,
                    "failed_attempts": count,
                    "window_sec": self.alert_window_sec,
                }
                self._write_line(alert)
                print(f"[ALERT] Possible brute-force from {src_ip} ({count} fails/{self.alert_window_sec}s)")

    def log_command(self, src_ip: str, src_port: int, command: str) -> None:
        self._write_line(
            {
                "event": "command",
                "src_ip": src_ip,
                "src_port": int(src_port),
                "command": command,
            }
        )
