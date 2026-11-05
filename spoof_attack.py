#!/usr/bin/env python3
"""
Lightweight Network Intrusion Detection System (L-IDS) - Test Attack Simulator
==============================================================================
Module: spoof_attack.py
Description:
    Adversary simulation harness utilizing Scapy to craft and inject realistic
    spoofed international IP network packets (UK, EU, etc.) across the local
    interface.

    Simulates two primary attack vectors:
      1. Signature-Based Vector: Cleartext Credential Exfiltration
         Crafts unencrypted HTTP/TCP packets containing sensitive credential
         parameters ('user=', 'password=', 'login=').
      2. Anomaly-Based Vector: Rapid Port Scan / SYN Flood
         Transmits a high-velocity burst of TCP SYN packets (>50 packets in <1s)
         targeting a range of destination ports.

Usage:
    python spoof_attack.py --mode all
    python spoof_attack.py --mode leak --src-country UK
    python spoof_attack.py --mode scan --src-country EU --count 60
"""

import argparse
import random
import sys
import time
from typing import Dict, List, Optional

# Scapy primitives for raw packet fabrication and transmission
try:
    from scapy.all import IP, TCP, Raw, conf, send
except ImportError as imp_err:
    sys.stderr.write(
        f"\n[!] ERROR: Scapy is required for raw packet crafting: {imp_err}\n"
        f"    Install via: pip install scapy>=2.5.0\n\n"
    )
    sys.exit(1)

# Suppress verbose Scapy runtime output by default
conf.verb = 0

# ANSI color codes for terminal presentation
ANSI_RED: str = "\033[1;91m"
ANSI_YELLOW: str = "\033[1;93m"
ANSI_GREEN: str = "\033[1;92m"
ANSI_CYAN: str = "\033[1;96m"
ANSI_WHITE: str = "\033[1;97m"
ANSI_GRAY: str = "\033[0;90m"
ANSI_RESET: str = "\033[0m"

# Catalog of realistic international IP profiles for threat actor simulation
INTERNATIONAL_THREAT_PROFILES: Dict[str, Dict[str, str]] = {
    "UK": {
        "country": "United Kingdom (London)",
        "flag": "🇬🇧",
        "ip": "82.165.197.1",
        "asn": "AS8560 (IONOS SE / UK Hub)",
    },
    "EU_GERMANY": {
        "country": "European Union (Frankfurt, Germany)",
        "flag": "🇩🇪",
        "ip": "194.26.29.112",
        "asn": "AS200019 (Alexhost SRL / Frankfurt)",
    },
    "EU_NETHERLANDS": {
        "country": "European Union (Amsterdam, Netherlands)",
        "flag": "🇳🇱",
        "ip": "185.220.101.5",
        "asn": "AS208294 (Tor Exit Node / Amsterdam)",
    },
    "EU_ROMANIA": {
        "country": "European Union (Bucharest, Romania)",
        "flag": "🇷🇴",
        "ip": "89.38.97.10",
        "asn": "AS43949 (M247 Europe)",
    },
    "APAC_SINGAPORE": {
        "country": "Asia-Pacific (Singapore)",
        "flag": "🇸🇬",
        "ip": "103.253.144.10",
        "asn": "AS133117 (Equinix SG)",
    },
}


def print_banner() -> None:
    """Display cyber adversary simulator banner."""
    print(
        f"{ANSI_RED}"
        r"""
  ███████╗██████╗  ██████╗  ██████╗ ███████╗    ███████╗██╗███╗   ███╗
  ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝    ██╔════╝██║████╗ ████║
  ███████╗██████╔╝██║   ██║██║   ██║█████╗      ███████╗██║██╔████╔██║
  ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝      ╚════██║██║██║╚██╔╝██║
  ███████║██║     ╚██████╔╝╚██████╔╝██║         ███████║██║██║ ╚═╝ ██║
  ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝         ╚══════╝╚═╝╚═╝     ╚═╝
"""
        f"{ANSI_RESET}"
        f"  {ANSI_GRAY}[+] Lightweight Network Intrusion Detection System (L-IDS) Test Harness{ANSI_RESET}\n"
        f"  {ANSI_GRAY}[+] Advanced Adversary Emulation & International Packet Spoofing{ANSI_RESET}\n"
    )


def simulate_credential_leak(
    target_ip: str = "127.0.0.1",
    target_port: int = 8080,
    spoofed_ip: str = "194.26.29.112",
    profile_info: Optional[Dict[str, str]] = None,
    interface: str = "lo0",
) -> None:
    """
    Simulate signature attack: Cleartext credential exfiltration with spoofed IP.

    Crafts a raw TCP packet containing an unencrypted HTTP POST payload with
    sensitive keywords ('user=', 'password=', 'login=').

    Args:
        target_ip: Destination host IP (default 127.0.0.1).
        target_port: Target destination TCP port.
        spoofed_ip: Fake international source IP address.
        profile_info: Metadata dictionary describing spoofed actor origin.
        interface: Network interface to inject raw packet onto.
    """
    country_desc = profile_info["country"] if profile_info else "International"
    flag = profile_info["flag"] if profile_info else "🌐"
    asn = profile_info.get("asn", "Unknown ASN") if profile_info else ""

    print(f"{ANSI_CYAN}{'=' * 72}{ANSI_RESET}")
    print(
        f"{ANSI_WHITE}[1/2] SIMULATING CLEARTEXT CREDENTIAL EXFILTRATION (SIGNATURE-BASED){ANSI_RESET}"
    )
    print(f"{ANSI_CYAN}{'=' * 72}{ANSI_RESET}")
    print(f"  [-] Spoofed Origin : {flag} {ANSI_GREEN}{spoofed_ip}{ANSI_RESET} ({country_desc})")
    print(f"  [-] Origin Network : {ANSI_GRAY}{asn}{ANSI_RESET}")
    print(f"  [-] Target Host    : {ANSI_YELLOW}{target_ip}:{target_port}{ANSI_RESET}")
    print(f"  [-] Injection Iface: {ANSI_WHITE}{interface}{ANSI_RESET}")

    # Construct realistic unencrypted HTTP authentication payload
    sensitive_payload: str = (
        f"POST /api/v2/corporate/auth/login HTTP/1.1\r\n"
        f"Host: login.enterprise-internal.corp\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatActor/4.2\r\n"
        f"Accept: application/json\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 68\r\n"
        f"Connection: close\r\n\r\n"
        f"user=chief_security_officer&password=ClassifiedPass2026!&login=true\r\n"
    )

    sport = random.randint(49152, 65535)

    # Scapy packet construction: IP / TCP (PUSH/ACK) / Raw Payload
    packet = (
        IP(src=spoofed_ip, dst=target_ip)
        / TCP(sport=sport, dport=target_port, flags="PA", seq=1000, ack=1)
        / Raw(load=sensitive_payload.encode("utf-8"))
    )

    try:
        # Inject packet onto specified interface (store=0)
        send(packet, iface=interface, verbose=False)
        print(f"  {ANSI_GREEN}[+] Packet dispatched successfully!{ANSI_RESET}")
        print(
            f"  {ANSI_GRAY}[+] Expected Alert: [Cleartext Leak] from {spoofed_ip} on L-IDS & Dashboard.{ANSI_RESET}\n"
        )
    except Exception as exc:
        sys.stderr.write(
            f"  {ANSI_RED}[!] Error injecting spoofed credential packet: {exc}{ANSI_RESET}\n"
        )


def simulate_syn_flood(
    target_ip: str = "127.0.0.1",
    base_port: int = 10000,
    count: int = 60,
    delay: float = 0.01,
    spoofed_ip: str = "82.165.197.1",
    profile_info: Optional[Dict[str, str]] = None,
    interface: str = "lo0",
) -> None:
    """
    Simulate anomaly attack: Rapid TCP SYN flood / port scan with spoofed IP.

    Transmits a high-velocity burst of TCP SYN packets exceeding the detection
    threshold (>50 packets within the 10-second sliding window).

    Args:
        target_ip: Destination host IP (default 127.0.0.1).
        base_port: Starting destination TCP port for scan.
        count: Total number of SYN packets to fire (threshold is 50).
        delay: Sleep interval between packets in seconds.
        spoofed_ip: Fake international source IP address.
        profile_info: Metadata dictionary describing spoofed actor origin.
        interface: Network interface to inject raw packets onto.
    """
    country_desc = profile_info["country"] if profile_info else "International"
    flag = profile_info["flag"] if profile_info else "🌐"
    asn = profile_info.get("asn", "Unknown ASN") if profile_info else ""

    print(f"{ANSI_YELLOW}{'=' * 72}{ANSI_RESET}")
    print(
        f"{ANSI_WHITE}[2/2] SIMULATING RAPID PORT SCAN / SYN FLOOD (ANOMALY-BASED){ANSI_RESET}"
    )
    print(f"{ANSI_YELLOW}{'=' * 72}{ANSI_RESET}")
    print(f"  [-] Spoofed Origin : {flag} {ANSI_GREEN}{spoofed_ip}{ANSI_RESET} ({country_desc})")
    print(f"  [-] Origin Network : {ANSI_GRAY}{asn}{ANSI_RESET}")
    print(f"  [-] Target Host    : {ANSI_YELLOW}{target_ip}{ANSI_RESET}")
    print(f"  [-] Packet Target  : Ports {base_port} -> {base_port + count}")
    print(f"  [-] Volume / Delay : {count} SYN packets @ {delay}s interval")
    print(f"  [-] Injection Iface: {ANSI_WHITE}{interface}{ANSI_RESET}")

    sys.stdout.write("  [-] Progress       : [")
    sys.stdout.flush()

    for idx in range(1, count + 1):
        target_dport: int = base_port + idx
        sport: int = random.randint(30000, 60000)

        # Scapy packet construction: IP / TCP with pure SYN flag ('S')
        packet = IP(src=spoofed_ip, dst=target_ip) / TCP(
            sport=sport, dport=target_dport, flags="S", seq=2000 + idx
        )

        try:
            send(packet, iface=interface, verbose=False)
        except Exception as exc:
            sys.stderr.write(f"\n  {ANSI_RED}[!] Packet injection error: {exc}{ANSI_RESET}\n")
            break

        # Progress bar animation
        if count <= 20 or idx % (count // 20) == 0:
            sys.stdout.write("█")
            sys.stdout.flush()

        if delay > 0:
            time.sleep(delay)

    sys.stdout.write("] Done!\n")
    print(
        f"  {ANSI_GREEN}[+] Transmitted {count} SYN packets from {spoofed_ip}!{ANSI_RESET}"
    )
    print(
        f"  {ANSI_GRAY}[+] Expected Alert: [Port Scan] triggered after 50th SYN packet.{ANSI_RESET}\n"
    )


def resolve_profile(country_key: str) -> Dict[str, str]:
    """
    Resolve profile key to threat metadata.

    Args:
        country_key: Profile identifier (e.g., 'UK', 'EU', 'DE', 'NL', 'SG').

    Returns:
        Dict[str, str]: Threat profile specification.
    """
    key_upper = country_key.upper()
    if key_upper in ("UK", "GB"):
        return INTERNATIONAL_THREAT_PROFILES["UK"]
    elif key_upper in ("DE", "GERMANY"):
        return INTERNATIONAL_THREAT_PROFILES["EU_GERMANY"]
    elif key_upper in ("NL", "NETHERLANDS"):
        return INTERNATIONAL_THREAT_PROFILES["EU_NETHERLANDS"]
    elif key_upper in ("RO", "ROMANIA"):
        return INTERNATIONAL_THREAT_PROFILES["EU_ROMANIA"]
    elif key_upper in ("SG", "APAC", "SINGAPORE"):
        return INTERNATIONAL_THREAT_PROFILES["APAC_SINGAPORE"]
    elif key_upper in ("EU", "EUROPE"):
        return random.choice(
            [
                INTERNATIONAL_THREAT_PROFILES["EU_GERMANY"],
                INTERNATIONAL_THREAT_PROFILES["EU_NETHERLANDS"],
                INTERNATIONAL_THREAT_PROFILES["EU_ROMANIA"],
            ]
        )
    # Default fallback
    return INTERNATIONAL_THREAT_PROFILES["EU_GERMANY"]


def main() -> None:
    """CLI orchestrator for spoofed adversary simulation."""
    parser = argparse.ArgumentParser(
        description="L-IDS Adversary Simulation Harness - International Packet Spoofing"
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["all", "leak", "scan"],
        default="all",
        help="Attack scenario to execute: 'all' (default), 'leak', or 'scan'",
    )
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        default="127.0.0.1",
        help="Target IP address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8080,
        help="Target port for credential leak (default: 8080)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=60,
        help="Total SYN packets to send for port scan (default: 60, threshold is 50)",
    )
    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=0.01,
        help="Delay in seconds between successive SYN packets (default: 0.01)",
    )
    parser.add_argument(
        "--src-country",
        type=str,
        default="random",
        choices=["random", "UK", "EU", "DE", "NL", "RO", "SG"],
        help="Origin of spoofed adversary (default: random international profile)",
    )
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default="lo0" if sys.platform == "darwin" else None,
        help="Network interface to inject packets onto (default: 'lo0' on macOS)",
    )

    args = parser.parse_args()

    # Determine default interface if not resolved
    iface: str = args.interface or ("lo0" if sys.platform == "darwin" else conf.iface)

    print_banner()

    # Resolve threat profiles for leak and scan vectors
    if args.src_country == "random":
        leak_profile = INTERNATIONAL_THREAT_PROFILES["EU_GERMANY"]
        scan_profile = INTERNATIONAL_THREAT_PROFILES["UK"]
    else:
        leak_profile = resolve_profile(args.src_country)
        scan_profile = resolve_profile(args.src_country)

    start_time: float = time.time()

    if args.mode in ("all", "leak"):
        simulate_credential_leak(
            target_ip=args.target,
            target_port=args.port,
            spoofed_ip=leak_profile["ip"],
            profile_info=leak_profile,
            interface=iface,
        )
        if args.mode == "all":
            time.sleep(1.0)  # Brief pause between scenarios for clean SOC visualization

    if args.mode in ("all", "scan"):
        simulate_syn_flood(
            target_ip=args.target,
            base_port=10000,
            count=args.count,
            delay=args.delay,
            spoofed_ip=scan_profile["ip"],
            profile_info=scan_profile,
            interface=iface,
        )

    elapsed: float = time.time() - start_time
    print(f"{ANSI_GREEN}{'=' * 72}{ANSI_RESET}")
    print(
        f"{ANSI_WHITE}[✓] Adversary simulation completed in {elapsed:.2f} seconds.{ANSI_RESET}"
    )
    print(
        f"    Check your SOC Dashboard at {ANSI_CYAN}http://localhost:5000{ANSI_RESET} (or :5001) for live alerts!"
    )
    print(f"{ANSI_GREEN}{'=' * 72}{ANSI_RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{ANSI_YELLOW}[*] Simulation interrupted by user. Exiting.{ANSI_RESET}")
        sys.exit(0)

