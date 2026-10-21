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

        self.assertEqual(
            report["sources"]["10.0.0.1"],
            {"connection_count": 3, "unique_destination_count": 2},
        )
        self.assertEqual(
            report["flagged_sources"],
            [{"src_ip": "10.0.0.1", "unique_destination_count": 2}],
        )

    def test_source_below_threshold_is_not_flagged(self):
        events = [
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 22},
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "dst_port": 22},
        ]
        self.assertEqual(analyze_events(events, threshold=3)["flagged_sources"], [])

    def test_sources_are_counted_independently(self):
        events = [
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "dst_port": 22},
            {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3", "dst_port": 22},
        ]
        report = analyze_events(events, threshold=1)
        self.assertEqual(report["sources"]["10.0.0.1"]["connection_count"], 1)
        self.assertEqual(report["sources"]["10.0.0.2"]["connection_count"], 1)
        self.assertEqual(len(report["flagged_sources"]), 2)

    def test_empty_events_returns_empty_report(self):
        self.assertEqual(analyze_events([]), {"sources": {}, "flagged_sources": []})

    def test_threshold_must_be_at_least_one(self):
        for threshold in (0, -1):
            with self.subTest(threshold=threshold), self.assertRaises(ValueError):
                analyze_events([], threshold=threshold)

    def test_missing_event_field_has_clear_error(self):
        with self.assertRaisesRegex(ValueError, "dst_ip"):
            analyze_events([{"src_ip": "10.0.0.1"}])

    def test_threshold_must_be_integer(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            analyze_events([], threshold=1.5)

    def test_rejects_blank_ip(self):
        with self.assertRaisesRegex(ValueError, "invalid src_ip"):
            analyze_events([{"src_ip": " ", "dst_ip": "10.0.0.2"}])


if __name__ == "__main__":
    unittest.main()
