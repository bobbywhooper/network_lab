"""Analyze connection events for destination and port-scanning patterns.

Events are dictionaries, typically produced by pcap_reader.py. The analyzer
uses simple heuristics; a finding is a lead for investigation, not proof of
malicious activity.
"""

from collections import Counter, defaultdict


def analyze_events(events, threshold=5, window_seconds=None, port_threshold=None):
    """Summarize events and optionally flag host or port scans.

    Required fields: src_ip, dst_ip. If window_seconds is set, each event
    also requires a numeric time. A supplied port_threshold enables detection
    of sources contacting many unique destination ports. In window mode,
    both rules are evaluated over inclusive sliding windows.
    """
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    if window_seconds is not None and (
        not isinstance(window_seconds, (int, float))
        or isinstance(window_seconds, bool)
        or window_seconds <= 0
    ):
        raise ValueError("window_seconds must be a positive number")
    if port_threshold is not None and (
        not isinstance(port_threshold, int)
        or isinstance(port_threshold, bool)
        or port_threshold < 1
    ):
        raise ValueError("port_threshold must be a positive integer")

    normalized = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"Event at index {index} must be a dictionary")
        missing = {"src_ip", "dst_ip"} - event.keys()
        if window_seconds is not None:
            missing.add("time")
        if missing:
            fields = ", ".join(sorted(missing))
            raise ValueError(f"Event at index {index} is missing required field(s): {fields}")

        src_ip, dst_ip = event["src_ip"], event["dst_ip"]
        if not isinstance(src_ip, str) or not src_ip.strip():
            raise ValueError(f"Event at index {index} has an invalid src_ip")
        if not isinstance(dst_ip, str) or not dst_ip.strip():
            raise ValueError(f"Event at index {index} has an invalid dst_ip")

        timestamp = event.get("time")
        if window_seconds is not None and (
            not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool)
        ):
            raise ValueError(f"Event at index {index} has an invalid time")

        dst_port = event.get("dst_port")
        if dst_port is not None and (
            not isinstance(dst_port, int)
            or isinstance(dst_port, bool)
            or not 1 <= dst_port <= 65535
        ):
            raise ValueError(f"Event at index {index} has an invalid dst_port")

        normalized.append((src_ip, dst_ip, dst_port, timestamp, index))

    connection_counts = Counter()
    destinations = defaultdict(set)
    destination_ports = defaultdict(set)
    events_by_source = defaultdict(list)

    for src_ip, dst_ip, dst_port, timestamp, index in normalized:
        connection_counts[src_ip] += 1
        destinations[src_ip].add(dst_ip)
        if dst_port is not None:
            destination_ports[src_ip].add(dst_port)
        events_by_source[src_ip].append((timestamp, dst_ip, dst_port, index))

    sources = {}
    flagged_sources = []
    for src_ip, count in connection_counts.items():
        unique_count = len(destinations[src_ip])
        unique_ports = len(destination_ports[src_ip])
        source_stats = {
            "connection_count": count,
            "unique_destination_count": unique_count,
            "unique_destination_port_count": unique_ports,
        }

        if window_seconds is None:
            if unique_count >= threshold:
                flagged_sources.append({
                    "src_ip": src_ip,
                    "reason": "many_unique_destinations",
                    "unique_destination_count": unique_count,
                    "window_start": None,
                    "window_end": None,
                })
            if port_threshold is not None and unique_ports >= port_threshold:
                flagged_sources.append({
                    "src_ip": src_ip,
                    "reason": "many_unique_destination_ports",
                    "unique_destination_port_count": unique_ports,
                    "window_start": None,
                    "window_end": None,
                })
        else:
            ordered = sorted(events_by_source[src_ip], key=lambda item: item[0])
            left = 0
            window_destinations = Counter()
            window_ports = Counter()
            emitted_destination_finding = False
            emitted_port_finding = False
            max_destinations = 0
            max_ports = 0

            for right, (timestamp, dst_ip, dst_port, _) in enumerate(ordered):
                window_destinations[dst_ip] += 1
                if dst_port is not None:
                    window_ports[dst_port] += 1

                while timestamp - ordered[left][0] > window_seconds:
                    old_dst = ordered[left][1]
                    old_port = ordered[left][2]
                    window_destinations[old_dst] -= 1
                    if window_destinations[old_dst] == 0:
                        del window_destinations[old_dst]
                    if old_port is not None:
                        window_ports[old_port] -= 1
                        if window_ports[old_port] == 0:
                            del window_ports[old_port]
                    left += 1

                max_destinations = max(max_destinations, len(window_destinations))
                max_ports = max(max_ports, len(window_ports))

                if not emitted_destination_finding and len(window_destinations) >= threshold:
                    flagged_sources.append({
                        "src_ip": src_ip,
                        "reason": "many_unique_destinations",
                        "unique_destination_count": len(window_destinations),
                        "window_start": ordered[left][0],
                        "window_end": timestamp,
                    })
                    emitted_destination_finding = True

                if (
                    port_threshold is not None
                    and not emitted_port_finding
                    and len(window_ports) >= port_threshold
                ):
                    flagged_sources.append({
                        "src_ip": src_ip,
                        "reason": "many_unique_destination_ports",
                        "unique_destination_port_count": len(window_ports),
                        "window_start": ordered[left][0],
                        "window_end": timestamp,
                    })
                    emitted_port_finding = True

            source_stats["max_unique_destinations_in_window"] = max_destinations
            source_stats["max_unique_destination_ports_in_window"] = max_ports

        sources[src_ip] = source_stats

    return {
        "sources": sources,
        "flagged_sources": flagged_sources,
        "window_seconds": window_seconds,
        "threshold": threshold,
        "port_threshold": port_threshold,
    }


def main():
    events = [
        {"time": 1, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.10", "dst_port": 22},
        {"time": 2, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.11", "dst_port": 22},
        {"time": 3, "src_ip": "10.0.0.8", "dst_ip": "10.0.0.20", "dst_port": 443},
        {"time": 3, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.12", "dst_port": 22},
        {"time": 4, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.13", "dst_port": 22},
        {"time": 5, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.14", "dst_port": 22},
        {"time": 20, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.30", "dst_port": 22},
    ]

    report = analyze_events(events, threshold=5, window_seconds=5)
    for src_ip, stats in report["sources"].items():
        print(f"{src_ip}: {stats['connection_count']} connections, "
              f"{stats['unique_destination_count']} unique destinations overall")

    for finding in report["flagged_sources"]:
        print(f"Possible scanning activity: {finding['src_ip']} ({finding['reason']}) "
              f"from t={finding['window_start']} to t={finding['window_end']}")


if __name__ == "__main__":
    main()
