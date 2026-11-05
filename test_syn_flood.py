#!/usr/bin/env python3
"""
Lightweight Network Intrusion Detection System (L-IDS)
======================================================
Module: test_syn_flood.py
Description:
    Test script to simulate a SYN flood / port scan attack by generating
    bursts of TCP SYN packets towards a target host. Used to verify L-IDS
    Phase 4 rate-limiting and threshold alerting.
"""

import argparse
import sys
import time
from scapy.all import IP, TCP, send


def simulate_syn_burst(target_ip: str, count: int = 55, delay: float = 0.02) -> None:
    """
    Transmit a burst of TCP SYN packets to simulate a port scan or SYN flood.

    Args:
        target_ip: Destination IP address to target.
        count: Total number of SYN packets to generate.
        delay: Delay in seconds between successive packets.
    """
    print(f"[*] Simulating SYN burst: Sending {count} SYN packets to {target_ip}...")
    start_port = 10000

    for i in range(1, count + 1):
        target_port = start_port + i
        packet = IP(dst=target_ip) / TCP(
            sport=50000 + (i % 1000), dport=target_port, flags="S"
        )
        send(packet, verbose=False)
        if delay > 0:
            time.sleep(delay)

    print(f"[+] Successfully transmitted {count} SYN packets.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate SYN flood / port scan for L-IDS verification"
    )
    parser.add_argument(
        "--target", type=str, default="127.0.0.1", help="Target IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--count", type=int, default=55, help="Number of SYN packets (default: 55)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.01,
        help="Delay between packets (default: 0.01s)",
    )
    args = parser.parse_args()

    simulate_syn_burst(args.target, args.count, args.delay)


if __name__ == "__main__":
    main()
