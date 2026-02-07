#!/usr/bin/env python3
"""
Port knocking using iptables 'recent' (Option C).

This script installs firewall rules on the HOST (EC2) to:
- Block secret_ssh (172.20.0.20:2222) by default for container-to-container traffic
- Require a knock sequence against the port_knocking container (172.20.0.40):
  1234 -> 5678 -> 9012 within 10 seconds each
- After correct sequence, allow the source IP to reach 172.20.0.20:2222 for 30 seconds

Run on the host (not inside a container):
  sudo python3 port_knocking/knock_server.py --install
"""

import argparse
import subprocess

DEFAULT_PROTECTED_IP = "172.20.0.20"
DEFAULT_KNOCK_IP = "172.20.0.40"
DEFAULT_TTL = 30
DEFAULT_WINDOW = 10

def run(cmd):
    return subprocess.run(cmd, check=True)

def install_rules(protected_ip, knock_ip, window, ttl):
    # Ensure DOCKER-USER exists
    subprocess.run(["sudo", "iptables", "-N", "DOCKER-USER"], stderr=subprocess.DEVNULL)

    # Flush to avoid duplicates
    run(["sudo", "iptables", "-F", "DOCKER-USER"])

    # Default drop protected port
    run(["sudo", "iptables", "-A", "DOCKER-USER", "-d", f"{protected_ip}/32", "-p", "tcp", "--dport", "2222", "-j", "DROP"])

    # Knock1
    run(["sudo", "iptables", "-I", "DOCKER-USER", "1", "-d", f"{knock_ip}/32", "-p", "tcp", "--dport", "1234",
         "-m", "recent", "--set", "--name", "KNOCK1", "--rsource", "-j", "DROP"])

    # Knock2
    run(["sudo", "iptables", "-I", "DOCKER-USER", "1", "-d", f"{knock_ip}/32", "-p", "tcp", "--dport", "5678",
         "-m", "recent", "--rcheck", "--seconds", str(window), "--name", "KNOCK1", "--rsource",
         "-m", "recent", "--set", "--name", "KNOCK2", "--rsource", "-j", "DROP"])

    # Knock3
    run(["sudo", "iptables", "-I", "DOCKER-USER", "1", "-d", f"{knock_ip}/32", "-p", "tcp", "--dport", "9012",
         "-m", "recent", "--rcheck", "--seconds", str(window), "--name", "KNOCK2", "--rsource",
         "-m", "recent", "--set", "--name", "KNOCK3", "--rsource", "-j", "DROP"])

    # Allow after final knock
    run(["sudo", "iptables", "-I", "DOCKER-USER", "1", "-d", f"{protected_ip}/32", "-p", "tcp", "--dport", "2222",
         "-m", "recent", "--rcheck", "--seconds", str(ttl), "--name", "KNOCK3", "--rsource", "-j", "ACCEPT"])

def show_rules():
    subprocess.run(["sudo", "iptables", "-S", "DOCKER-USER"], check=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--protected-ip", default=DEFAULT_PROTECTED_IP)
    ap.add_argument("--knock-ip", default=DEFAULT_KNOCK_IP)
    ap.add_argument("--window", type=int, default=DEFAULT_WINDOW)
    ap.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--show", action="store_true")
    args = ap.parse_args()

    if args.install:
        install_rules(args.protected_ip, args.knock_ip, args.window, args.ttl)
        show_rules()
    elif args.show:
        show_rules()
    else:
        ap.print_help()

if __name__ == "__main__":
    main()
