"""Analyze simulated network connection events.

This module currently consumes event dictionaries, not PCAP files. It can
flag sources contacting many unique destinations overall or within a time
window when each event includes a numeric timestamp.
"""

from collections import defaultdict


def analyze_events(events, threshold=5, window_seconds=None):
    """Summarize events and flag sources contacting many unique destinations.

    Required fields: src_ip, dst_ip. If window_seconds is supplied, each event
    must also contain a numeric time. Events are sorted by time per source and
    evaluated using a sliding window. The window's endpoints are inclusive.
    """
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    if window_seconds is not None and (
        not isinstance(window_seconds, (int, float))
        or isinstance(window_seconds, bool)
        or window_seconds <= 0
    ):
        raise ValueError("window_seconds must be a positive number")

    normalized = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"Event at index {index} must be a dictionary")
        missing = {"src_ip", "dst_ip"} - event.keys()
        if window_seconds is not None:
            missing |= {"time"} - event.keys()
        if missing:
            fields = ", ".join(sorted(missing))
            raise ValueError(f"Event at index {index} is missing required field(s): {fields}")

        src_ip, dst_ip = event["src_ip"], event["dst_ip"]
        if not isinstance(src_ip, str) or not src_ip.strip():
            raise ValueError(f"Event at index {index} has an invalid src_ip")
        if not isinstance(dst_ip, str) or not dst_ip.strip():
            raise ValueError(f"Event at index {index} has an invalid dst_ip")

        timestamp = event.get("time")
        if window_seconds is not None:
            if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
                raise ValueError(f"Event at index {index} has an invalid time")
        normalized.append((src_ip, dst_ip, timestamp, index))

    connection_counts = defaultdict(int)
    destinations = defaultdict(set)
    events_by_source = defaultdict(list)

    for src_ip, dst_ip, timestamp, index in normalized:
        connection_counts[src_ip] += 1
        destinations[src_ip].add(dst_ip)
        events_by_source[src_ip].append((timestamp, dst_ip, index))

    sources = {}
    flagged_sources = []
    for src_ip, count in connection_counts.items():
        unique_count = len(destinations[src_ip])
        source_stats = {
            "connection_count": count,
            "unique_destination_count": unique_count,
        }

        if window_seconds is None:
            if unique_count >= threshold:
                flagged_sources.append({
                    "src_ip": src_ip,
                    "unique_destination_count": unique_count,
                    "window_start": None,
                    "window_end": None,
                })
        else:
            ordered = sorted(events_by_source[src_ip], key=lambda item: item[0])
            left = 0
            window_destinations = defaultdict(int)
            finding = None

            for right, (timestamp, dst_ip, _) in enumerate(ordered):
                window_destinations[dst_ip] += 1
                while timestamp - ordered[left][0] > window_seconds:
                    old_dst = ordered[left][1]
                    window_destinations[old_dst] -= 1
                    if window_destinations[old_dst] == 0:
                        del window_destinations[old_dst]
                    left += 1

                if len(window_destinations) >= threshold:
                    finding = {
                        "src_ip": src_ip,
                        "unique_destination_count": len(window_destinations),
                        "window_start": ordered[left][0],
                        "window_end": timestamp,
                    }
                    break

            if finding:
                flagged_sources.append(finding)
                source_stats["max_unique_destinations_in_window"] = max(
                    len(set(item[1] for item in ordered[left:right + 1])),
                    threshold,
                )

        sources[src_ip] = source_stats

    return {
        "sources": sources,
        "flagged_sources": flagged_sources,
        "window_seconds": window_seconds,
        "threshold": threshold,
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
        print(f"Possible scanning activity: {finding['src_ip']} contacted "
              f"{finding['unique_destination_count']} unique destinations "
              f"from t={finding['window_start']} to t={finding['window_end']}")


if __name__ == "__main__":
    main()
