import unittest

from tcp_scan_detector import analyze_tcp_connections


def packet(time, src, dst, src_port, dst_port, *, syn=False, ack=False, rst=False):
    return {
        "time": time, "protocol": "TCP", "src_ip": src, "dst_ip": dst,
        "src_port": src_port, "dst_port": dst_port,
        "tcp_syn": syn, "tcp_ack": ack, "tcp_rst": rst,
    }


class TcpScanDetectorTests(unittest.TestCase):
    def test_correlates_syn_ack_response(self):
        events = [
            packet(1, "10.0.0.5", "10.0.0.10", 50000, 443, syn=True),
            packet(1.1, "10.0.0.10", "10.0.0.5", 443, 50000, syn=True, ack=True),
        ]
        report = analyze_tcp_connections(events)
        self.assertEqual(report["outcome_counts"]["syn_ack"], 1)
        self.assertEqual(report["attempts"][0]["outcome"], "syn_ack")

    def test_correlates_reset_as_refused(self):
        events = [
            packet(1, "10.0.0.5", "10.0.0.10", 50000, 22, syn=True),
            packet(1.1, "10.0.0.10", "10.0.0.5", 22, 50000, rst=True, ack=True),
        ]
        report = analyze_tcp_connections(events)
        self.assertEqual(report["outcome_counts"]["refused"], 1)

    def test_unanswered_syn_is_reported(self):
        report = analyze_tcp_connections([
            packet(1, "10.0.0.5", "10.0.0.10", 50000, 8080, syn=True)
        ])
        source = report["sources"]["10.0.0.5"]
        self.assertEqual(source["unanswered"], 1)
        self.assertEqual(source["unique_unanswered_destination_ports"], 1)

    def test_retransmitted_syns_are_grouped(self):
        report = analyze_tcp_connections([
            packet(1, "10.0.0.5", "10.0.0.10", 50000, 443, syn=True),
            packet(1.5, "10.0.0.5", "10.0.0.10", 50000, 443, syn=True),
            packet(2, "10.0.0.10", "10.0.0.5", 443, 50000, syn=True, ack=True),
        ])
        self.assertEqual(report["attempt_count"], 1)
        self.assertEqual(report["attempts"][0]["retransmissions"], 1)
        self.assertEqual(report["outcome_counts"]["syn_ack"], 1)

    def test_reply_outside_window_does_not_match(self):
        report = analyze_tcp_connections([
            packet(1, "10.0.0.5", "10.0.0.10", 50000, 443, syn=True),
            packet(5, "10.0.0.10", "10.0.0.5", 443, 50000, syn=True, ack=True),
        ], response_window=3)
        self.assertEqual(report["outcome_counts"]["unanswered"], 1)

    def test_ignores_non_tcp_events(self):
        report = analyze_tcp_connections([{"protocol": "UDP"}])
        self.assertEqual(report["attempt_count"], 0)

    def test_rejects_invalid_response_window(self):
        for value in (0, -1, "3", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                analyze_tcp_connections([], response_window=value)

    def test_rejects_incomplete_tcp_metadata(self):
        with self.assertRaisesRegex(ValueError, "missing required"):
            analyze_tcp_connections([{"protocol": "TCP"}])


if __name__ == "__main__":
    unittest.main()
