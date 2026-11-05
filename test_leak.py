#!/usr/bin/env python3
"""
Lightweight Network Intrusion Detection System (L-IDS)
======================================================
Module: test_leak.py
Description:
    Verification test harness that transmits an unencrypted HTTP POST request
    containing sensitive credentials ("password=test") over a local TCP socket.
    Used to validate that the L-IDS payload inspection and alerting rules trigger.

Project Rules:
    - Clean, modern, idiomatic Python 3 (PEP 8 compliant)
    - Comprehensive comments and docstrings
    - Strict error handling with defensive execution
"""

import argparse
import socket
import sys
import threading
import time
from typing import Tuple


def start_dummy_receiver(host: str, port: int, ready_event: threading.Event) -> None:
    """
    Lightweight temporary TCP receiver running in a daemon thread.
    Accepts an incoming TCP connection, consumes the payload, sends an HTTP 200,
    and terminates.

    Args:
        host: IP address to bind receiver.
        port: Port number to bind receiver.
        ready_event: Threading event signaled once socket is listening.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((host, port))
        server_sock.listen(1)
        ready_event.set()

        server_sock.settimeout(5.0)
        conn, _ = server_sock.accept()
        with conn:
            # Drain request bytes
            _ = conn.recv(4096)
            # Send HTTP response
            response = (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            )
            conn.sendall(response)
    except socket.timeout:
        # Expected if timeout expires without connection
        pass
    except Exception as err:
        sys.stderr.write(f"[!] Receiver socket notice: {err}\n")
    finally:
        server_sock.close()


def send_leaked_payload(host: str, port: int, payload_data: str) -> None:
    """
    Connect to the target host:port and send an unencrypted HTTP POST request
    containing cleartext credentials.

    Args:
        host: Target IP address.
        port: Target TCP port.
        payload_data: String payload body (e.g. 'user=admin&password=test').
    """
    http_request = (
        f"POST /login HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"User-Agent: L-IDS-TestClient/1.0\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(payload_data)}\r\n"
        f"Connection: close\r\n\r\n"
        f"{payload_data}"
    )

    print(f"[*] Connecting to {host}:{port}...")
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.settimeout(5.0)

    try:
        client_sock.connect((host, port))
        print(f"[+] Connected. Sending dummy unencrypted HTTP POST request:")
        print(f"    Payload: {payload_data}")
        client_sock.sendall(http_request.encode("utf-8"))

        # Read response
        try:
            response = client_sock.recv(1024)
            print(f"[+] Received server response ({len(response)} bytes).")
        except socket.timeout:
            pass

        print("[+] Test payload transmission completed successfully.")
    except ConnectionRefusedError:
        sys.stderr.write(f"[!] Connection refused on {host}:{port}.\n")
        sys.stderr.write(
            "[-] Ensure a receiver is running or omit --no-server to auto-start one.\n"
        )
        sys.exit(1)
    except Exception as err:
        sys.stderr.write(f"[!] Error transmitting test packet: {err}\n")
        sys.exit(1)
    finally:
        client_sock.close()


def main() -> None:
    """
    Entrypoint for test_leak harness.
    """
    parser = argparse.ArgumentParser(
        description="L-IDS Test Harness: Transmit cleartext credential payload to local socket"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Target IP address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int, default=9999, help="Target TCP port (default: 9999)"
    )
    parser.add_argument(
        "--payload",
        type=str,
        default="user=admin&password=test",
        help="Sensitive payload to transmit (default: 'user=admin&password=test')",
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Do not auto-spawn a local receiver (use when a server is already listening)",
    )
    args = parser.parse_args()

    print("[*] L-IDS Test Harness Initialized.")

    # Spawn local listener if needed
    if not args.no_server:
        ready_event = threading.Event()
        receiver_thread = threading.Thread(
            target=start_dummy_receiver,
            args=(args.host, args.port, ready_event),
            daemon=True,
        )
        receiver_thread.start()
        # Wait for receiver to bind
        ready_event.wait(timeout=2.0)
        time.sleep(0.1)

    # Transmit test payload
    send_leaked_payload(args.host, args.port, args.payload)


if __name__ == "__main__":
    main()
