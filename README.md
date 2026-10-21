# Network Lab

A collection of Python networking experiments focused on learning how network protocols and services work beneath high-level libraries.

This project explores TCP connections, HTTP message parsing, DNS packet construction, port scanning, service identification, and basic network-event analysis through hands-on implementation.

## Projects

### `service_scout.py` — TCP Service Discovery

A concurrent TCP port scanner with lightweight service fingerprinting.

Features:
- Scan specified TCP ports or port ranges.
- Configure connection timeouts and worker concurrency.
- Identify some services using banners, HTTP responses, and TLS handshakes.
- Display detected open ports and supporting evidence.
- Export scan results to JSON.

Example:

```bash
python service_scout.py example.com --ports 22,80,443
```

Scan a range of ports:

```bash
python service_scout.py example.com --ports 1-1000
```

Save results to JSON:

```bash
python service_scout.py example.com --ports 22,80,443 --json results.json
```

### `http_parser.py` — Manual HTTP Client

A low-level HTTP client implemented using Python sockets. It supports plain HTTP only; HTTPS is intentionally unsupported.

Concepts explored:
- TCP socket connections and HTTP requests.
- HTTP status lines and response headers.
- Reading responses across multiple socket operations.
- `Content-Length` and chunked transfer encoding.
- Following HTTP redirects.

Run:

```bash
python http_parser.py
```

The current example requests `http://example.com/`.

### `dns_packet.py` — DNS Query and Response Parsing

A testable DNS client that builds query packets, sends them over UDP, and parses response records.

Concepts explored:
- DNS message headers and flags.
- Binary encoding with `struct`.
- Domain-name label encoding.
- DNS question and resource-record fields.
- Parsing DNS names, including compression pointers.
- Checking transaction IDs and validating packet boundaries.

This remains an educational subset of DNS, not a complete production resolver.

Run:

```bash
python dns_packet.py
```

The current implementation queries `www.example.com` using Cloudflare's public DNS resolver.


### `pcap_reader.py` and `pcap_analyzer.py` — Classic PCAP Analysis

The reader uses the Python standard library to extract timestamped metadata from classic PCAP captures containing Ethernet-framed IPv4 TCP or UDP packets. It reads packet records incrementally rather than loading the full capture bytes into memory; extracted metadata is still collected for analysis.

Run a summary:

```bash
python pcap_analyzer.py capture.pcap
```

Flag destination bursts within a five-second window and save JSON:

```bash
python pcap_analyzer.py capture.pcap --threshold 5 --window 5 --json report.json
```

Scope and limitations:
- Supports classic PCAP files with Ethernet link-layer headers, optional VLAN tags, and IPv4 TCP/UDP packets.
- Does not support PCAPNG, IPv6, IP fragment reassembly, TCP stream reassembly, or application-layer decoding.
- The destination-count heuristic is only a basic signal; it is not proof of scanning or malicious activity.
- Only analyze captures you are authorized to inspect.

### `network_event_analyzer.py` — Network Event Analysis

A small experiment using simulated connection-event data to explore:
- Dictionaries and sets for tracking network activity.
- Counting connections and unique destinations.
- Identifying possible scanning patterns.

This script currently analyzes hard-coded sample events; it does not read or decode PCAP files. It can count unique destinations across the full input or flag unique-destination bursts within a configurable time window. Window mode requires numeric event timestamps.

## Tests

Run the unit tests from the repository root with:

```bash
python -m unittest discover -s tests -v
```

The tests cover DNS packet encoding/parsing, HTTP parsing and framing, network-event analysis, and port-specification validation. They do not require internet access.

## Requirements

- Python 3
- Network connectivity for the DNS, HTTP, and TCP scanning experiments
- Permission to test the target systems used for scanning

The current scripts primarily use Python's standard library, so no third-party package installation is documented as necessary.

## Learning Goals

This repository is a practical exploration of:

- TCP and UDP socket programming.
- DNS message structure and binary data.
- HTTP request and response parsing.
- Concurrent network operations.
- Service identification and basic network reconnaissance.
- Dictionaries, sets, byte arrays, and structured data.
- Error handling and protocol edge cases.

## Safety and Responsible Use

Only scan systems you own or have explicit permission to test. Network scanning can trigger security monitoring or violate a target's acceptable-use policies.

These scripts are educational implementations, not replacements for mature networking tools or production-grade protocol parsers.

## Project Status

This repository is a work in progress. Features, protocol handling, error cases, and testing will continue to evolve as I develop my understanding of networking and Python.

## License

No license information is currently documented in this README. Add the license you intend to use before presenting the repository as an open-source project.
