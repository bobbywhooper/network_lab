"""Correlate TCP SYN attempts with replies in packet-capture metadata.

This is a lightweight, packet-level heuristic. It does not reassemble TCP
streams, validate sequence numbers, or prove that an unanswered SYN was
malicious; capture loss and asymmetric routing can hide replies.
"""


def analyze_tcp_connections(events, response_window=3.0):
    """Classify initial SYN attempts as established, refused, or unanswered.

    A SYN-ACK is evidence that the destination replied to the connection
    attempt. A reverse-direction RST is treated as a refusal. Retransmitted
    SYNs for the same four-tuple inside the response window are grouped into
    one attempt. Only packets present in the supplied capture can be matched.
    """
    if (
        not isinstance(response_window, (int, float))
        or isinstance(response_window, bool)
        or response_window <= 0
    ):
        raise ValueError("response_window must be a positive number")

    tcp_packets = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"Event at index {index} must be a dictionary")
        if event.get("protocol") != "TCP":
            continue
        required = {"time", "src_ip", "dst_ip", "src_port", "dst_port",
                    "tcp_syn", "tcp_ack", "tcp_rst"}
        missing = required - event.keys()
        if missing:
            raise ValueError(
                f"TCP event at index {index} is missing required field(s): "
                + ", ".join(sorted(missing))
            )
        timestamp = event["time"]
        if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
            raise ValueError(f"TCP event at index {index} has an invalid time")
        for field in ("src_port", "dst_port"):
            port = event[field]
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise ValueError(f"TCP event at index {index} has an invalid {field}")
        for field in ("tcp_syn", "tcp_ack", "tcp_rst"):
            if not isinstance(event[field], bool):
                raise ValueError(f"TCP event at index {index} has an invalid {field}")
        tcp_packets.append((timestamp, index, event))

    tcp_packets.sort(key=lambda item: (item[0], item[1]))
    attempts = []
    active_by_tuple = {}

    for timestamp, index, event in tcp_packets:
        flow = (
            event["src_ip"], event["src_port"],
            event["dst_ip"], event["dst_port"],
        )
        if event["tcp_syn"] and not event["tcp_ack"]:
            previous = active_by_tuple.get(flow)
            if previous is not None and timestamp - previous["time"] <= response_window:
                previous["retransmissions"] += 1
                continue
            attempt = {
                "src_ip": flow[0],
                "dst_ip": flow[2],
                "src_port": flow[1],
                "dst_port": flow[3],
                "time": timestamp,
                "response_time": None,
                "outcome": "unanswered",
                "retransmissions": 0,
            }
            attempts.append(attempt)
            active_by_tuple[flow] = attempt
            continue

        if not event["tcp_rst"] and not (event["tcp_syn"] and event["tcp_ack"]):
            continue

        reverse_flow = (
            event["dst_ip"], event["dst_port"],
            event["src_ip"], event["src_port"],
        )
        attempt = active_by_tuple.get(reverse_flow)
        if attempt is None or timestamp < attempt["time"]:
            continue
        if timestamp - attempt["time"] > response_window:
            continue
        if attempt["outcome"] != "unanswered":
            continue

        attempt["response_time"] = timestamp
        attempt["outcome"] = "refused" if event["tcp_rst"] else "syn_ack"

    by_source = {}
    for attempt in attempts:
        stats = by_source.setdefault(attempt["src_ip"], {
            "attempts": 0, "syn_ack": 0, "refused": 0, "unanswered": 0,
            "unique_destinations": set(), "unique_destination_ports": set(),
        })
        stats["attempts"] += 1
        stats[attempt["outcome"]] += 1
        if attempt["outcome"] == "unanswered":
            stats["unique_destinations"].add(attempt["dst_ip"])
            stats["unique_destination_ports"].add(attempt["dst_port"])

    for stats in by_source.values():
        stats["unique_unanswered_destinations"] = len(stats.pop("unique_destinations"))
        stats["unique_unanswered_destination_ports"] = len(
            stats.pop("unique_destination_ports")
        )

    return {
        "response_window": response_window,
        "attempt_count": len(attempts),
        "outcome_counts": {
            outcome: sum(item["outcome"] == outcome for item in attempts)
            for outcome in ("syn_ack", "refused", "unanswered")
        },
        "sources": by_source,
        "attempts": attempts,
    }
