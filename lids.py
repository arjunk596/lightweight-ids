#!/usr/bin/env python3
"""
Lightweight Network Intrusion Detection System (L-IDS)
======================================================
Module: lids.py
Description:
    Core engine and CLI orchestrator for the Lightweight Network Intrusion
    Detection System (L-IDS). Sniffs network traffic in real-time, verifies
    administrative/BPF privileges, detects cleartext credential leaks
    (signature-based) and SYN flood / port scans (anomaly-based), logs alerts
    to a persistent CSV file, and gracefully displays session statistics upon
    shutdown.

Project Rules:
    - Clean, modern, idiomatic Python 3 (PEP 8 compliant)
    - Comprehensive comments and docstrings
    - Strict error handling with defensive execution
"""

import argparse
import csv
from datetime import datetime
import os
import sys
import threading
import time
from typing import Dict, Optional, Set

# Scapy packet manipulation & capture primitives
try:
    from scapy.all import sniff, IP, TCP, Raw
except ImportError as err:
    sys.stderr.write("\n" + "=" * 65 + "\n")
    sys.stderr.write("[!] ERROR: Missing Dependency\n")
    sys.stderr.write("=" * 65 + "\n")
    sys.stderr.write(f"[-] Could not import required Scapy modules: {err}\n")
    sys.stderr.write("[+] Please install requirements:\n")
    sys.stderr.write("    pip install -r requirements.txt\n")
    sys.stderr.write("=" * 65 + "\n\n")
    sys.exit(1)

# ANSI terminal formatting codes
ANSI_RED_BOLD: str = "\033[1;91m"
ANSI_YELLOW_BOLD: str = "\033[1;93m"
ANSI_CYAN_BOLD: str = "\033[1;96m"
ANSI_RESET: str = "\033[0m"

# Phase 3: Signature Detection Patterns
SENSITIVE_KEYWORDS: list[str] = ["user=", "pass=", "password=", "login="]

# Phase 4: Anomaly Detection Configuration
SYN_THRESHOLD: int = 50  # Max permitted SYN packets per Source IP in window
WINDOW_DURATION: float = 10.0  # Sliding time window length in seconds

# Phase 5: CSV Logging & Session Metrics
CSV_LOG_FILE: str = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "ids_alerts.csv"
)
csv_lock: threading.Lock = threading.Lock()
stats_lock: threading.Lock = threading.Lock()

# Global state dictionaries and metrics
syn_tracker: Dict[str, list[float]] = {}
alerted_ips: Set[str] = set()
last_cleanup_time: float = time.time()
tracker_lock: threading.Lock = threading.Lock()

session_start_time: float = 0.0
total_packets_analyzed: int = 0
total_alerts_triggered: int = 0


def log_alert_to_csv(src_ip: str, dst_ip: str, alert_type: str) -> None:
    """
    Append an intrusion detection alert record to the CSV log file in a thread-safe manner.

    Opens the file in append mode ('a') and closes it immediately after writing
    to prevent file locking and ensure live data availability for the web dashboard.

    Format (4 columns):
        [Timestamp, Source IP, Destination IP, Alert Type]

    Args:
        src_ip: Source IP address of the offending host/packet.
        dst_ip: Destination IP address.
        alert_type: Alert classification ('Cleartext Leak' or 'Port Scan').
    """
    with csv_lock:
        file_exists: bool = (
            os.path.isfile(CSV_LOG_FILE) and os.path.getsize(CSV_LOG_FILE) > 0
        )
        timestamp: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            # Open in append mode ('a') and close immediately after writing via context manager
            with open(CSV_LOG_FILE, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(
                        [
                            "Timestamp",
                            "Source IP",
                            "Destination IP",
                            "Alert Type",
                        ]
                    )
                writer.writerow([timestamp, src_ip, dst_ip, alert_type])
        except OSError as log_err:
            sys.stderr.write(f"[!] Failed to write alert to CSV: {log_err}\n")


def cleanup_stale_trackers(now: float) -> None:
    """
    Purge expired timestamp records and dead IP keys from the tracking state.
    Runs periodically to prevent memory exhaustion during long-term monitoring.
    """
    global last_cleanup_time, syn_tracker, alerted_ips
    if now - last_cleanup_time >= 30.0:
        for ip in list(syn_tracker.keys()):
            syn_tracker[ip] = [t for t in syn_tracker[ip] if now - t <= WINDOW_DURATION]
            if not syn_tracker[ip]:
                del syn_tracker[ip]
                alerted_ips.discard(ip)
        last_cleanup_time = now


def is_admin() -> bool:
    """
    Verify whether the script possesses sufficient privileges for raw packet sniffing.

    Detection requirements:
      - Linux / macOS (POSIX): UID / EUID == 0 (root).
      - macOS Berkeley Packet Filter: Read/write permission on /dev/bpf*
        (e.g., access_bpf group).
      - Windows: Administrator token verified via shell32.IsUserAnAdmin.

    Returns:
        bool: True if elevated privileges or raw socket capabilities are granted.
    """
    try:
        # Standard POSIX root check
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True

        # macOS: Check direct read/write access to Berkeley Packet Filter devices
        if sys.platform == "darwin":
            import glob

            bpf_devices = glob.glob("/dev/bpf*")
            if bpf_devices and os.access(bpf_devices[0], os.R_OK | os.W_OK):
                return True

        # Windows administrator check
        if os.name == "nt":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())

        return False
    except (AttributeError, ImportError, OSError) as err:
        sys.stderr.write(
            f"[!] Warning: Exception encountered while verifying privileges: {err}\n"
        )
        return False


def verify_privileges() -> None:
    """
    Enforce administrative or packet capture privileges before initializing capture.

    If required privileges are absent, prints a descriptive error banner with
    remediation commands and terminates execution with status code 1.
    """
    if not is_admin():
        sys.stderr.write("\n" + "=" * 65 + "\n")
        sys.stderr.write(
            "[!] ERROR: Elevated Privileges Required (Root / Admin / BPF Access)\n"
        )
        sys.stderr.write("=" * 65 + "\n")
        sys.stderr.write(
            "[-] Raw socket packet capture requires elevated/BPF rights.\n"
        )
        sys.stderr.write(
            "[-] Current process lacks required packet capture permissions.\n\n"
        )
        sys.stderr.write("[+] Remediation:\n")
        if os.name == "nt":
            sys.stderr.write("    Run command prompt or PowerShell as Administrator.\n")
        else:
            script_path: str = os.path.abspath(sys.argv[0])
            sys.stderr.write(f"    sudo python3 {script_path}\n")
            sys.stderr.write("    or using the project virtualenv:\n")
            sys.stderr.write(f"    sudo ./.venv/bin/python {script_path}\n")
        sys.stderr.write("=" * 65 + "\n\n")
        sys.exit(1)


def analyze_packet(packet) -> None:
    """
    Packet analysis callback invoked by scapy.sniff for each captured frame.

    Execution Flow:
      1. Validates presence of IPv4 (IP) and TCP headers.
      2. Updates session packet counter.
      3. Anomaly Engine: Evaluates TCP SYN flags, tracks counts per Source IP,
         flushes state every 10s window, and logs/alerts if threshold (>50) is breached.
      4. Signature Engine: Decodes Raw payload, scans for cleartext credentials
         ('user=', 'pass=', 'password=', 'login='), and logs/alerts on match.
      5. Telemetry: Emits standard flow telemetry for benign traffic.

    Args:
        packet: Scapy frame captured from the network interface.
    """
    global total_packets_analyzed, total_alerts_triggered

    try:
        # Step 1: Validate IP and TCP headers
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        with stats_lock:
            total_packets_analyzed += 1

        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        src_ip: str = ip_layer.src
        dst_ip: str = ip_layer.dst
        dst_port: int = tcp_layer.dport
        src_port: int = tcp_layer.sport

        # Step 2: Anomaly Engine (SYN Flood / Port Scan detection)
        with tracker_lock:
            now = time.time()
            cleanup_stale_trackers(now)

            # Inspect if the 'S' (SYN) flag is set
            if "S" in tcp_layer.flags:
                # Retain only timestamps within the sliding window duration (10s)
                ip_timestamps = syn_tracker.get(src_ip, [])
                ip_timestamps = [t for t in ip_timestamps if now - t <= WINDOW_DURATION]
                ip_timestamps.append(now)
                syn_tracker[src_ip] = ip_timestamps
                current_syn_count: int = len(ip_timestamps)

                # Trigger alert if SYN frequency threshold is breached
                if current_syn_count > SYN_THRESHOLD and src_ip not in alerted_ips:
                    alerted_ips.add(src_ip)
                    with stats_lock:
                        total_alerts_triggered += 1

                    # Phase 6 Task 2: Log Anomaly alert (Port Scan) to CSV
                    log_alert_to_csv(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        alert_type="Port Scan",
                    )

                    syn_alert = (
                        f"\n{ANSI_YELLOW_BOLD}"
                        f"=================================================================\n"
                        f"[!] WARNING: Potential Port Scan or SYN Flood!\n"
                        f"=================================================================\n"
                        f"[-] Source IP        : {src_ip}\n"
                        f"[-] SYN Packet Count : {current_syn_count} (Threshold: >{SYN_THRESHOLD} in {int(WINDOW_DURATION)}s)\n"
                        f"[-] Target Host/Port : {dst_ip}:{dst_port}\n"
                        f"[-] Action           : Recorded in {CSV_LOG_FILE}\n"
                        f"================================================================={ANSI_RESET}\n"
                    )
                    print(syn_alert)

        # Step 3: Signature Engine (Cleartext Credential Leak Detection)
        if packet.haslayer(Raw):
            raw_bytes: bytes = bytes(packet[Raw].load)
            payload_text: str = raw_bytes.decode("utf-8", errors="ignore")
            payload_lower: str = payload_text.lower()

            matched_keywords: list[str] = [
                kw for kw in SENSITIVE_KEYWORDS if kw in payload_lower
            ]
            if "password=" in matched_keywords and "pass=" in matched_keywords:
                matched_keywords.remove("pass=")

            if matched_keywords:
                with stats_lock:
                    total_alerts_triggered += 1

                # Focus snippet around the matched keyword
                primary_kw: str = matched_keywords[0]
                kw_pos: int = payload_lower.find(primary_kw)
                start_idx: int = max(0, kw_pos - 35)
                end_idx: int = min(len(payload_text), kw_pos + 120)

                snippet: str = " ".join(payload_text[start_idx:end_idx].strip().split())
                if start_idx > 0:
                    snippet = "..." + snippet
                if end_idx < len(payload_text):
                    snippet = snippet + "..."

                # Phase 6 Task 2: Log Signature alert (Cleartext Leak) to CSV
                log_alert_to_csv(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    alert_type="Cleartext Leak",
                )

                cred_alert = (
                    f"\n{ANSI_RED_BOLD}"
                    f"=================================================================\n"
                    f"[!] CRITICAL ALERT: Sensitive Credential Leak Detected!\n"
                    f"=================================================================\n"
                    f"[-] Source IP        : {src_ip}:{src_port}\n"
                    f"[-] Destination IP   : {dst_ip}:{dst_port}\n"
                    f"[-] Trigger Pattern  : {', '.join(matched_keywords)}\n"
                    f"[-] Leaked Snippet   : {snippet}\n"
                    f"[-] Action           : Recorded in {CSV_LOG_FILE}\n"
                    f"================================================================={ANSI_RESET}\n"
                )
                print(cred_alert)
                return

        # Step 4: Default TCP flow telemetry
        print(
            f"[TCP] Source IP: {src_ip:<15} ({src_port}) -> "
            f"Destination IP: {dst_ip:<15} | Destination Port: {dst_port}"
        )
    except Exception as err:
        sys.stderr.write(f"[!] Error analyzing packet: {err}\n")


def print_session_summary() -> None:
    """
    Display a structured shutdown summary showing total session runtime,
    total packets inspected, and total security alerts raised.
    """
    runtime_seconds: float = (
        max(0.0, time.time() - session_start_time) if session_start_time > 0 else 0.0
    )
    mins, secs = divmod(int(runtime_seconds), 60)
    runtime_formatted: str = f"{mins:02d}m {secs:02d}s ({runtime_seconds:.2f}s)"

    csv_path: str = os.path.abspath(CSV_LOG_FILE)

    print("\n" + ANSI_CYAN_BOLD + "=" * 65)
    print("             L-IDS SESSION SHUTDOWN SUMMARY")
    print("=" * 65 + ANSI_RESET)
    print(f" [+] Total Runtime          : {runtime_formatted}")
    print(f" [+] Total Packets Analyzed : {total_packets_analyzed}")
    print(f" [+] Total Alerts Triggered : {total_alerts_triggered}")
    print(f" [+] Persistent Alert Log   : {csv_path}")
    print(ANSI_CYAN_BOLD + "=" * 65 + ANSI_RESET + "\n")


def start_sniffing(
    interface: Optional[str] = None, timeout: Optional[int] = None
) -> None:
    """
    Launch packet sniffing and route frames into the analysis pipeline.

    Wraps scapy.sniff inside a KeyboardInterrupt handler to ensure graceful
    shutdown with runtime telemetry and statistics reporting.

    Args:
        interface: Specific network interface to monitor (None selects Scapy default).
        timeout: Sniff duration in seconds (None monitors continuously until stopped).
    """
    global session_start_time
    session_start_time = time.time()

    print("[*] Starting live packet capture (store=False)...")
    if interface:
        print(f"[*] Bound to interface: {interface}")
    if timeout:
        print(f"[*] Sniff duration limited to {timeout} seconds.")
    print("[*] Press Ctrl+C at any time to halt inspection.\n" + "-" * 70)

    try:
        sniff(prn=analyze_packet, store=False, iface=interface, timeout=timeout)
    except KeyboardInterrupt:
        print("\n[*] Interruption signal received (SIGINT). Shutting down L-IDS...")
    except PermissionError as perm_err:
        sys.stderr.write(f"\n[!] Socket Permission Error: {perm_err}\n")
        sys.stderr.write("[!] Please execute with root / sudo privileges.\n")
        sys.exit(1)
    except Exception as exc:
        sys.stderr.write(f"\n[!] Unexpected error during packet capture: {exc}\n")
        sys.exit(1)
    finally:
        print_session_summary()


def main() -> None:
    """
    Main application entrypoint for L-IDS.
    Validates execution privileges, parses CLI options, and initiates sniffing.
    """
    parser = argparse.ArgumentParser(
        description="Lightweight Network Intrusion Detection System (L-IDS)"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=None,
        help="Capture timeout in seconds (default: continuous monitoring)",
    )
    default_iface = "lo0" if sys.platform == "darwin" else None
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=default_iface,
        help=f"Network interface to monitor (default: '{default_iface or 'Scapy default'}')",
    )
    args = parser.parse_args()

    print("[*] Initializing Lightweight Network Intrusion Detection System (L-IDS)...")

    # Step 1: Privilege validation
    verify_privileges()
    print("[+] Privilege verification passed (Packet sniffing authorized).")

    # Step 2: Start capture engine
    start_sniffing(interface=args.interface, timeout=args.timeout)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] L-IDS stopped by user. Exiting cleanly.")
        sys.exit(0)
    except Exception as fatal_err:
        sys.stderr.write(f"\n[!] Fatal unhandled exception in L-IDS: {fatal_err}\n")
        sys.exit(1)
