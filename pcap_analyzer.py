"""Analyze classic PCAP captures with NetLab's event analyzer."""

import argparse
import json
from collections import Counter

from network_event_analyzer import analyze_events
from pcap_reader import read_pcap
from dns_payload import parse_dns_payload


def main():
    parser = argparse.ArgumentParser(
        description="Summarize TCP/UDP IPv4 traffic from a classic Ethernet PCAP"
    )
    parser.add_argument("capture", help="Path to a classic .pcap file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Unique destinations needed to flag a source")
    parser.add_argument("--window", type=float,
                        help="Optional sliding time window in seconds")
    parser.add_argument("--port-threshold", type=int,
                        help="Flag sources contacting this many unique destination ports")
    parser.add_argument("--json", dest="json_file",
                        help="Optional path to save the report as JSON")
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.window is not None and args.window <= 0:
        parser.error("--window must be greater than zero")
    if args.port_threshold is not None and args.port_threshold < 1:
        parser.error("--port-threshold must be at least 1")

    try:
        events = read_pcap(args.capture)
        dns_messages = []
        for event in events:
            if (
                event["protocol"] == "UDP"
                and (event["src_port"] in (53, 5353) or event["dst_port"] in (53, 5353))
            ):
                try:
                    dns = parse_dns_payload(bytes.fromhex(event["payload_hex"]))
                except ValueError as error:
                    event["dns_parse_error"] = str(error)
                else:
                    event["dns"] = dns
                    dns_messages.append(dns)

        # For TCP, count initial SYN packets as connection attempts, not replies
        # or subsequent packets. UDP has no handshake, so UDP events remain candidates.
        scan_events = [
            event for event in events
            if event["protocol"] == "UDP"
            or (event["protocol"] == "TCP" and event["tcp_syn"] and not event["tcp_ack"])
        ]
        report = analyze_events(
            scan_events,
            threshold=args.threshold,
            window_seconds=args.window,
            port_threshold=args.port_threshold,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))

    report["capture"] = args.capture
    report["packet_count"] = len(events)
    report["scan_candidate_count"] = len(scan_events)
    report["dns_message_count"] = len(dns_messages)
    report["dns_parse_error_count"] = sum("dns_parse_error" in event for event in events)
    report["dns_questions"] = [
        {"time": event["time"], "src_ip": event["src_ip"], "dst_ip": event["dst_ip"],
         "questions": event["dns"]["questions"], "is_response": event["dns"]["is_response"],
         "rcode": event["dns"]["rcode"]}
        for event in events if "dns" in event
    ]
    queried_names = Counter(
        question["name"].lower()
        for event in events
        if "dns" in event and not event["dns"]["is_response"]
        for question in event["dns"]["questions"]
    )
    report["top_dns_queries"] = dict(queried_names.most_common(20))
    report["dns_response_rcodes"] = dict(Counter(
        event["dns"]["rcode"]
        for event in events if "dns" in event and event["dns"]["is_response"]
    ))
    report["tcp_flag_counts"] = {
        "syn": sum(event["tcp_syn"] for event in events if event["protocol"] == "TCP"),
        "ack": sum(event["tcp_ack"] for event in events if event["protocol"] == "TCP"),
        "rst": sum(event["tcp_rst"] for event in events if event["protocol"] == "TCP"),
        "fin": sum(event["tcp_fin"] for event in events if event["protocol"] == "TCP"),
        "initial_syn_without_ack": sum(
            event["tcp_syn"] and not event["tcp_ack"]
            for event in events if event["protocol"] == "TCP"
        ),
    }
    report["protocol_counts"] = dict(Counter(event["protocol"] for event in events))
    report["top_destination_ports"] = dict(
        Counter(event["dst_port"] for event in events).most_common(10)
    )

    rendered_report = json.dumps(report, indent=2)
    print(rendered_report)
    if args.json_file:
        try:
            with open(args.json_file, "w", encoding="utf-8") as output:
                output.write(rendered_report + "\n")
        except OSError as error:
            parser.error(f"Could not write JSON report: {error}")


if __name__ == "__main__":
    main()
