#!/usr/bin/env python3
import argparse
import socket
from typing import List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(ip: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        s.close()

def grab_banner(ip: str, port: int, timeout: float) -> str:
    """
    Very simple banner grab.
    For HTTP-like services, send GET to trigger response.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))

        # Trigger HTTP response on common ports
        if port in (80, 8080, 8000, 5000, 8888):
            try:
                s.sendall(b"GET / HTTP/1.0\r\nHost: test\r\n\r\n")
            except OSError:
                pass

        try:
            data = s.recv(400)
        except socket.timeout:
            return ""

        banner = data.decode(errors="replace").strip()
        return banner.replace("\r", "\\r").replace("\n", "\\n")
    except OSError:
        return ""
    finally:
        s.close()

def parse_ports(ports_str: str) -> List[int]:
    """
    Supports:
      - "22,80,5000"
      - "1-1024"
      - "22,80,5000-5010"
    """
    ports = set()
    for token in ports_str.split(","):
        token = token.strip()
        if not token:
            continue

        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start = int(start_s.strip())
            end = int(end_s.strip())
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                ports.add(p)
        else:
            ports.add(int(token))

    return sorted(ports)

def scan_worker(ip: str, port: int, timeout: float) -> Tuple[int, bool, str]:
    is_open = scan_port(ip, port, timeout)
    banner = grab_banner(ip, port, timeout) if is_open else ""
    return port, is_open, banner

def main():
    ap = argparse.ArgumentParser(description="Custom TCP port scanner (threaded)")
    ap.add_argument("--target", required=True, help="Target IP (e.g., 172.20.0.10)")
    ap.add_argument("--ports", required=True, help='Ports (e.g. "22,80,5000-5010")')
    ap.add_argument("--timeout", type=float, default=0.5, help="Socket timeout seconds")
    ap.add_argument("--threads", type=int, default=100, help="Number of worker threads")
    args = ap.parse_args()

    ports = parse_ports(args.ports)

    print(f"Target: {args.target}")
    print(f"Ports: {ports[:20]}{' ...' if len(ports) > 20 else ''} (total={len(ports)})")
    print(f"Timeout: {args.timeout}s | Threads: {args.threads}")
    print("PORT\tSTATE\tBANNER")

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_map = {executor.submit(scan_worker, args.target, p, args.timeout): p for p in ports}
        for fut in as_completed(future_map):
            results.append(fut.result())

    # Print in port order (cleaner output)
    results.sort(key=lambda x: x[0])
    for port, is_open, banner in results:
        state = "open" if is_open else "closed"
        print(f"{port}\t{state}\t{banner}")

if __name__ == "__main__":
    main()

