"""
NetLab ServiceScout

Concurrent TCP service discovery and lightweight service fingerprinting.

Use only against systems you own or have explicit permission to test.
"""

import argparse
import errno
import json
import socket
import ssl
import time

from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# Port scanning
# ============================================================

def scan_port(ip, port, timeout=1):
    """
    Attempt a TCP connection to one port.

    Returns structured information about the connection attempt.
    """

    start = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((ip, port))

    except socket.timeout:
        status = "timeout"
        result = None

    except OSError as error:
        return {
            "port": port,
            "status": "error",
            "latency_ms": round(
                (time.perf_counter() - start) * 1000,
                2
            ),
            "error": str(error)
        }

    elapsed = time.perf_counter() - start

    if result == 0:
        status = "open"

    elif result in {
        errno.ECONNREFUSED,
        10061,  # Windows WSAECONNREFUSED
    }:
        status = "closed"

    elif result in {
        errno.ETIMEDOUT,
        10060,  # Windows WSAETIMEDOUT
    }:
        status = "timeout"

    else:
        status = "unreachable"

    return {
        "port": port,
        "status": status,
        "latency_ms": round(elapsed * 1000, 2)
    }


def scan_ports(ip, ports, workers=50, timeout=1):
    """
    Scan multiple ports concurrently.
    """

    results = []
    futures = []

    with ThreadPoolExecutor(max_workers=workers) as executor:

        for port in ports:
            future = executor.submit(
                scan_port,
                ip,
                port,
                timeout
            )

            futures.append(future)

        for future in as_completed(futures):

            try:
                result = future.result()
                results.append(result)

            except Exception as error:
                results.append({
                    "port": None,
                    "status": "error",
                    "error": str(error)
                })

    return results


# ============================================================
# Passive banner detection
# ============================================================

def grab_banner(ip, port, timeout=1):
    """
    Connect and wait briefly to see whether the server speaks first.
    """

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            banner = sock.recv(1024)

            if not banner:
                return None

            return banner

    except (socket.timeout, OSError):
        return None


def identify_banner(banner):
    """
    Identify services that expose recognizable passive banners.
    """

    if not banner:
        return None

    fingerprints = {
        b"SSH-": "SSH",
    }

    for prefix, service in fingerprints.items():

        if banner.startswith(prefix):
            return {
                "service": service,
                "banner": banner.decode(
                    "utf-8",
                    errors="replace"
                ).strip(),
                "evidence": f"Banner begins with {prefix.decode()}"
            }

    return None


# ============================================================
# HTTP detection
# ============================================================

def probe_http(ip, port, host, timeout=1):
    """
    Send a minimal plaintext HTTP request.

    We only care whether the service behaves like HTTP.
    """

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            sock.sendall(request.encode("utf-8"))

            response = sock.recv(1024)

    except (socket.timeout, OSError):
        return None

    if not response.startswith(b"HTTP/"):
        return None

    status_line = response.split(b"\r\n", 1)[0]

    return {
        "service": "HTTP",
        "banner": None,
        "evidence": status_line.decode(
            "utf-8",
            errors="replace"
        )
    }


# ============================================================
# TLS / HTTPS detection
# ============================================================

def probe_tls(ip, port, host, timeout=2):
    """
    Attempt a TLS handshake.

    If TLS succeeds, send an HTTP request through the encrypted
    connection to determine whether the service is HTTPS.

    Certificate verification is deliberately disabled here because
    this function is performing service identification rather than
    certificate trust validation.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection(
            (ip, port),
            timeout=timeout
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=host
            ) as tls_socket:

                tls_version = tls_socket.version()

                cipher_info = tls_socket.cipher()

                cipher = (
                    cipher_info[0]
                    if cipher_info
                    else None
                )

                request = (
                    "GET / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )

                tls_socket.sendall(
                    request.encode("utf-8")
                )

                try:
                    response = tls_socket.recv(1024)

                except socket.timeout:
                    response = b""

                if response.startswith(b"HTTP/"):

                    status_line = response.split(
                        b"\r\n",
                        1
                    )[0]

                    return {
                        "service": "HTTPS",
                        "banner": None,
                        "tls_version": tls_version,
                        "cipher": cipher,
                        "evidence": status_line.decode(
                            "utf-8",
                            errors="replace"
                        )
                    }

                return {
                    "service": "TLS",
                    "banner": None,
                    "tls_version": tls_version,
                    "cipher": cipher,
                    "evidence": "TLS handshake succeeded"
                }

    except (
        ssl.SSLError,
        socket.timeout,
        ConnectionError,
        OSError
    ):
        return None


# ============================================================
# Service detection
# ============================================================

def detect_service(ip, port, host):
    """
    Attempt to identify the application protocol behind an open port.
    """

    # --------------------------------------------------------
    # 1. Passive banner
    # --------------------------------------------------------

    banner = grab_banner(ip, port)

    banner_result = identify_banner(banner)

    if banner_result:
        return banner_result

    # --------------------------------------------------------
    # 2. Likely TLS ports get TLS tested first
    # --------------------------------------------------------

    likely_tls_ports = {
        443,
        465,
        636,
        853,
        993,
        995,
        8443,
    }

    tls_already_checked = False

    if port in likely_tls_ports:

        tls_already_checked = True

        tls_result = probe_tls(
            ip,
            port,
            host
        )

        if tls_result:
            return tls_result

    # --------------------------------------------------------
    # 3. Plaintext HTTP
    # --------------------------------------------------------

    http_result = probe_http(
        ip,
        port,
        host
    )

    if http_result:
        return http_result

    # --------------------------------------------------------
    # 4. Generic TLS probe
    # --------------------------------------------------------

    if not tls_already_checked:

        tls_result = probe_tls(
            ip,
            port,
            host
        )

        if tls_result:
            return tls_result

    # --------------------------------------------------------
    # 5. Nothing matched
    # --------------------------------------------------------

    return {
        "service": "unknown",
        "banner": (
            banner.decode(
                "utf-8",
                errors="replace"
            ).strip()
            if banner
            else None
        ),
        "evidence": "No recognized service fingerprint"
    }


def enrich_open_ports(ip, host, results):
    """
    Run service detection only against open ports.
    """

    for result in results:

        if result["status"] != "open":
            continue

        service_result = detect_service(
            ip,
            result["port"],
            host
        )

        result.update(service_result)

    return results


# ============================================================
# User input
# ============================================================

def parse_ports(port_spec):
    """
    Convert strings such as:

        22,80,443
        1-1000
        22,80,443,8000-8010

    into a sorted list of port numbers.
    """

    ports = set()

    for section in port_spec.split(","):

        section = section.strip()

        if "-" in section:

            start_text, end_text = section.split("-", 1)

            start = int(start_text)
            end = int(end_text)

            if start > end:
                raise ValueError(
                    f"Invalid port range: {section}"
                )

            for port in range(start, end + 1):
                ports.add(port)

        else:
            ports.add(int(section))

    for port in ports:

        if not 1 <= port <= 65535:
            raise ValueError(
                f"Invalid TCP port: {port}"
            )

    return sorted(ports)


# ============================================================
# Reporting
# ============================================================

def print_report(host, ip, results):
    """
    Display open ports in a human-readable format.
    """

    open_results = [
        result
        for result in results
        if result["status"] == "open"
    ]

    print()
    print("NetLab ServiceScout")
    print("=" * 72)

    print(f"Target:      {host}")
    print(f"Resolved IP: {ip}")
    print()

    if not open_results:
        print("No open ports detected.")
        return

    print(
        f"{'PORT':<8}"
        f"{'STATE':<10}"
        f"{'SERVICE':<12}"
        f"{'LATENCY':<12}"
        f"EVIDENCE"
    )

    print("-" * 72)

    for result in open_results:

        latency = f"{result['latency_ms']} ms"

        print(
            f"{result['port']:<8}"
            f"{result['status']:<10}"
            f"{result.get('service', 'unknown'):<12}"
            f"{latency:<12}"
            f"{result.get('evidence', '')}"
        )

        if result.get("banner"):
            print(
                f"{'':<42}"
                f"Banner: {result['banner']}"
            )

        if result.get("tls_version"):
            print(
                f"{'':<42}"
                f"TLS: {result['tls_version']}"
            )

        if result.get("cipher"):
            print(
                f"{'':<42}"
                f"Cipher: {result['cipher']}"
            )

    print()
    print(
        f"{len(open_results)} open port(s) detected."
    )


def save_json_report(filename, host, ip, results):
    report = {
        "target": host,
        "ip": ip,
        "results": results
    }

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )


# ============================================================
# Main CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "NetLab ServiceScout - "
            "Concurrent TCP service discovery"
        )
    )

    parser.add_argument(
        "target",
        help="Hostname or IPv4 address to scan"
    )

    parser.add_argument(
        "--ports",
        default="22,80,443,8080",
        help=(
            "Ports to scan. Examples: "
            "22,80,443 or 1-1000"
        )
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Maximum concurrent scan workers"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1,
        help="TCP connection timeout in seconds"
    )

    parser.add_argument(
        "--json",
        dest="json_file",
        help="Save complete results as JSON"
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)

    except ValueError as error:
        parser.error(str(error))

    try:
        ip = socket.gethostbyname(args.target)

    except socket.gaierror:
        parser.error(
            f"Unable to resolve target: {args.target}"
        )

    print(
        f"Scanning {args.target} ({ip}) "
        f"across {len(ports)} port(s)..."
    )

    results = scan_ports(
        ip,
        ports,
        workers=args.workers,
        timeout=args.timeout
    )

    results = enrich_open_ports(
        ip,
        args.target,
        results
    )

    results.sort(
        key=lambda result: (
            result["port"]
            if result["port"] is not None
            else 65536
        )
    )

    print_report(
        args.target,
        ip,
        results
    )

    if args.json_file:

        save_json_report(
            args.json_file,
            args.target,
            ip,
            results
        )

        print(
            f"\nJSON report saved to "
            f"{args.json_file}"
        )


if __name__ == "__main__":
    main()