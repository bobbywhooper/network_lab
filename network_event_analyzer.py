"""Analyze simulated network connection events.

This module does not read PCAP files. It analyzes event dictionaries supplied
by the caller and flags source IPs that contact many unique destinations.
"""

from collections import defaultdict


def analyze_events(events, threshold=5):
    """Summarize connection activity and flag possible destination scanning.

    Each event must contain src_ip and dst_ip fields. Other fields, such as
    time and dst_port, may be present but are not used yet.
    """
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError("threshold must be a positive integer")

    connection_counts = defaultdict(int)
    destinations = defaultdict(set)

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"Event at index {index} must be a dictionary")

        missing = {"src_ip", "dst_ip"} - event.keys()
        if missing:
            fields = ", ".join(sorted(missing))
            raise ValueError(f"Event at index {index} is missing required field(s): {fields}")

        src_ip = event["src_ip"]
        dst_ip = event["dst_ip"]
        if not isinstance(src_ip, str) or not src_ip.strip():
            raise ValueError(f"Event at index {index} has an invalid src_ip")
        if not isinstance(dst_ip, str) or not dst_ip.strip():
            raise ValueError(f"Event at index {index} has an invalid dst_ip")

        connection_counts[src_ip] += 1
        destinations[src_ip].add(dst_ip)

    sources = {}
    flagged_sources = []

    for src_ip, count in connection_counts.items():
        unique_destinations = len(destinations[src_ip])
        sources[src_ip] = {
            "connection_count": count,
            "unique_destination_count": unique_destinations,
        }

        if unique_destinations >= threshold:
            flagged_sources.append(
                {
                    "src_ip": src_ip,
                    "unique_destination_count": unique_destinations,
                }
            )

    return {"sources": sources, "flagged_sources": flagged_sources}


def main():
    # Illustrative data only; timestamps are not used for time-window analysis.
    events = [
        {"time": 1, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.10", "dst_port": 22},
        {"time": 2, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.11", "dst_port": 22},
        {"time": 3, "src_ip": "10.0.0.8", "dst_ip": "10.0.0.20", "dst_port": 443},
        {"time": 3, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.12", "dst_port": 22},
        {"time": 4, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.13", "dst_port": 22},
        {"time": 5, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.14", "dst_port": 22},
        {"time": 20, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.30", "dst_port": 22},
    ]

    report = analyze_events(events, threshold=5)

    for src_ip, stats in report["sources"].items():
        print(
            f"{src_ip}: {stats['connection_count']} connections, "
            f"{stats['unique_destination_count']} unique destinations"
        )

    for finding in report["flagged_sources"]:
        print(
            f"Possible scanning activity: {finding['src_ip']} contacted "
            f"{finding['unique_destination_count']} unique destinations"
        )


if __name__ == "__main__":
    main()
