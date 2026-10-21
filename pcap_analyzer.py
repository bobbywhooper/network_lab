"""Analyze classic PCAP captures with NetLab's event analyzer."""

import argparse
import json
from collections import Counter

from network_event_analyzer import analyze_events
from pcap_reader import read_pcap


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
        report = analyze_events(
            events,
            threshold=args.threshold,
            window_seconds=args.window,
            port_threshold=args.port_threshold,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))

    report["capture"] = args.capture
    report["packet_count"] = len(events)
    report["protocol_counts"] = dict(Counter(event["protocol"] for event in events))
    report["top_destination_ports"] = dict(
        Counter(event["dst_port"] for event in events).most_common(10)
    )

    print(json.dumps(report, indent=2))
    if args.json_file:
        with open(args.json_file, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2)


if __name__ == "__main__":
    main()
