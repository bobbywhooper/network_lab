import unittest

from network_event_analyzer import analyze_events


class AnalyzeEventsTests(unittest.TestCase):
    def test_counts_connections_and_unique_destinations(self):
        events = [
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 22},
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "dst_port": 22},
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80},
        ]
        report = analyze_events(events, threshold=2)
        self.assertEqual(report["sources"]["10.0.0.1"]["connection_count"], 3)
        self.assertEqual(report["sources"]["10.0.0.1"]["unique_destination_count"], 2)
        self.assertEqual(report["flagged_sources"][0]["src_ip"], "10.0.0.1")

    def test_window_flags_burst_but_not_spread_out_events(self):
        events = [
            {"time": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
            {"time": 2, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3"},
            {"time": 3, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.4"},
            {"time": 20, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.5"},
        ]
        report = analyze_events(events, threshold=3, window_seconds=5)
        self.assertEqual(len(report["flagged_sources"]), 1)
        finding = report["flagged_sources"][0]
        self.assertEqual(finding["window_start"], 1)
        self.assertEqual(finding["window_end"], 3)
        self.assertEqual(finding["unique_destination_count"], 3)

    def test_duplicate_destination_does_not_inflate_window_count(self):
        events = [
            {"time": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
            {"time": 2, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
            {"time": 3, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3"},
        ]
        self.assertEqual(
            analyze_events(events, threshold=3, window_seconds=5)["flagged_sources"],
            [],
        )

    def test_window_requires_timestamp(self):
        with self.assertRaisesRegex(ValueError, "time"):
            analyze_events([{"src_ip": "a", "dst_ip": "b"}], window_seconds=5)

    def test_rejects_invalid_threshold_and_window(self):
        for threshold in (0, -1, 1.5, True):
            with self.subTest(threshold=threshold), self.assertRaises(ValueError):
                analyze_events([], threshold=threshold)
        for window in (0, -1, "5", True):
            with self.subTest(window=window), self.assertRaises(ValueError):
                analyze_events([], window_seconds=window)

    def test_empty_events_returns_empty_report(self):
        self.assertEqual(analyze_events([])["sources"], {})
        self.assertEqual(analyze_events([])["flagged_sources"], [])

    def test_missing_event_field_has_clear_error(self):
        with self.assertRaisesRegex(ValueError, "dst_ip"):
            analyze_events([{"src_ip": "10.0.0.1"}])


if __name__ == "__main__":
    unittest.main()
