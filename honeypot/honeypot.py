#!/usr/bin/env python3
"""
SSH Honeypot (Paramiko-based)

Requirements met:
- Simulates real SSH service banner
- Logs: timestamp, src ip/port, duration, usernames/passwords, typed input (best-effort)
- Convincing enough: OpenSSH-like banner + basic messages
- Never grants real access

Bonus:
- Brute-force alerting via HoneypotLogger (threshold within window)
"""

from __future__ import annotations

import argparse
import socket
import threading
import time
from typing import Optional, Tuple

import paramiko

from logger import HoneypotLogger


DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_PORT = 22
DEFAULT_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13"


class HoneySSHServer(paramiko.ServerInterface):
    def __init__(self, hp_logger: HoneypotLogger, client_addr: Tuple[str, int]) -> None:
        self.log = hp_logger
        self.client_ip, self.client_port = client_addr
        self._shell_requested = threading.Event()

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        # Always fail but log creds
        self.log.log_auth_attempt(
            src_ip=self.client_ip,
            src_port=self.client_port,
            username=username,
            password=password,
            success=False,
        )
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self._shell_requested.set()
        return True


def _load_or_create_host_key(path: str) -> paramiko.PKey:
    # Generate once so the "host fingerprint" stays stable across restarts (more convincing)
    try:
        return paramiko.RSAKey(filename=path)
    except Exception:
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(path)
        return key


def _drain_and_log_input(chan: paramiko.Channel, hp_logger: HoneypotLogger, src_ip: str, src_port: int) -> None:
    """
    Best-effort: capture anything the client sends after a shell request.
    Many SSH clients won't reach this without successful auth; still ok.
    """
    chan.settimeout(2.0)
    while True:
        try:
            data = chan.recv(4096)
            if not data:
                break
            text = data.decode(errors="replace").strip()
            if text:
                hp_logger.log_command(src_ip, src_port, text)
        except socket.timeout:
            # idle
            continue
        except Exception:
            break


def handle_client(
    client_sock: socket.socket,
    client_addr: Tuple[str, int],
    host_key: paramiko.PKey,
    banner: str,
    hp_logger: HoneypotLogger,
) -> None:
    start = time.time()
    src_ip, src_port = client_addr
    hp_logger.log_connection_start(src_ip=src_ip, src_port=src_port, service="ssh-honeypot")

    transport: Optional[paramiko.Transport] = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = banner
        transport.add_server_key(host_key)

        server = HoneySSHServer(hp_logger, (src_ip, src_port))
        transport.start_server(server=server)

        chan = transport.accept(timeout=12)
        if chan is None:
            return

        # If a shell is requested, show realistic-ish denial and capture any typing
        server._shell_requested.wait(timeout=4)

        try:
            chan.send(b"Ubuntu 22.04.3 LTS\n")
            chan.send(b"Permission denied, please try again.\n")
        except Exception:
            pass

        _drain_and_log_input(chan, hp_logger, src_ip, src_port)

        try:
            chan.close()
        except Exception:
            pass

    except paramiko.ssh_exception.SSHException:
        # Common when someone connects with netcat/tcp check instead of real SSH
        # Still counts as a connection attempt; we don't crash the container.
        pass
    except Exception:
        pass
    finally:
        dur = time.time() - start
        hp_logger.log_connection_end(src_ip=src_ip, src_port=src_port, duration_sec=dur)
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH honeypot")
    parser.add_argument("--host", default=DEFAULT_LISTEN_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument("--banner", default=DEFAULT_BANNER)
    parser.add_argument("--log-dir", default="logs")
    parser.add_argument("--log-file", default="honeypot.log")
    parser.add_argument("--alert-threshold", type=int, default=5)
    parser.add_argument("--alert-window", type=int, default=60)
    parser.add_argument("--host-key", default="host_key.pem")
    args = parser.parse_args()

    logger = HoneypotLogger(
        log_dir=args.log_dir,
        log_file=args.log_file,
        alert_threshold=args.alert_threshold,
        alert_window_sec=args.alert_window,
    )

    host_key = _load_or_create_host_key(args.host_key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(100)

    print(f"[+] SSH honeypot listening on {args.host}:{args.port}")
    print(f"[+] Banner: {args.banner}")

    while True:
        client, addr = sock.accept()
        t = threading.Thread(
            target=handle_client,
            args=(client, addr, host_key, args.banner, logger),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    main()
